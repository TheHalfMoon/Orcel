//! SG-000108 product caller, slice 1b: orceld drives the live browser host
//! under the approval broker (test builds only: the `live-browser-test`
//! feature, which release builds never enable).
//!
//! Decision 3 of docs/security/SG-000108_PRODUCT_CALLER.md, the two-part
//! binding:
//! 1. the host computes its binding for the intended action (`bind`);
//! 2. orceld prompts for, and the broker mints and consumes, an approval
//!    whose digest covers orceld's own material (workspace, policy
//!    revision, the lifetime, the action) and the host binding;
//! 3. orceld sends the action with the broker's record id and the host
//!    binding, and the host re-derives its binding before acting.
//!
//! The broker is the single source of approvals: a denied, unavailable or
//! mismatched approval never reaches the host.
//!
//! Slice 1b has no envelope dispatch into this module yet: the native tests
//! drive it directly. Exposure through the `browser_structured` profile and
//! the live-backed page store arrive together in slice 3.
// The fixture paths serve only the test-feature native tests and the
// product paths only live-browser-dev dispatch: each is unused without the other.
#![cfg_attr(
    not(all(test, feature = "live-browser-test", feature = "live-browser-dev")),
    allow(dead_code)
)]

use crate::browser_broker::NeedsYou;
use crate::browser_lease::{
    FillValue, FullAccess, LeaseDecision, LeaseMoment, LeaseQuery, LeaseUse,
};
use crate::takeover_gate::TakeoverGate;
use orcel_approval::{now_ms, ApprovalBroker, ApprovalPrompt, ApprovedToken, ConsumeExpectation};
use orcel_browser_host::worker_host::{
    BindAction, BoundForm, FormNavigation, WireCheck, WireNode, WorkerHostReply, WorkerHostRequest,
};
use orcel_browser_host::{Supervisor, WorkerHostLaunch};
use orcel_browser_session::{ActionClass, ChallengeKind, WriteTicket};
use orcel_contracts::browser_impact::{self, Impact};
use orcel_contracts::FailureCode;
use orcel_policy::browser_lease::BrowserFamily;
use orcel_policy::{Workspace, POLICY_REVISION};
use orcel_provider_browser::{PageRecord, PageState, PageStore};
use orcel_provider_fs::ProviderError;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Domain separation for the combined approval digest. Version 2 binds
/// the page store's page id, generation and origin (slice 2b); version 3
/// (SG-000122 slice A2) also binds what a form prompt names about its field:
/// the role, the digest of the name the host observed, whether the prompt's
/// name was cut, and the ordinal (`-` for every other action).
const LIVE_APPROVAL_DOMAIN: &str = "orcel-sg108-live-approval/3";

/// Schema of one intent journal line.
const INTENT_SCHEMA: &str = "orcel-sg108-intent/1";

/// Where a live browser keeps its durable state: the page registry and the
/// download intent journal (both under orceld's protected local state in
/// a product build; a test scene's own directory in tests).
#[derive(Debug, Clone)]
pub struct LiveState {
    pub pages: PathBuf,
    pub intents: PathBuf,
}

/// The host lifetime's numeric policy revision. orceld's own revision (a
/// string) is bound into orceld's half of every digest.
const LIFETIME_POLICY_REVISION: u64 = 1;

/// SG-000135 OB-01 end-to-end harness: the loopback fixture host
/// (apps/orcel-browser-worker/scripts/https-fixture.mjs).
#[cfg(feature = "live-browser-test")]
const E2E_FIXTURE_HOST: &str = "fixture.test";

/// SG-000135 OB-01 end-to-end harness, builds with the test-only
/// `live-browser-test` feature only: the fixture certificate's SPKI hash the
/// harness gives in `ORCEL_E2E_FIXTURE_SPKI`, when `origin` is exactly the
/// fixture origin. Any other origin, or no variable, is `None`, and the
/// navigation takes the public path (which refuses the fixture host).
#[cfg(feature = "live-browser-test")]
fn e2e_fixture_spki(origin: &str) -> Option<String> {
    if origin != format!("https://{E2E_FIXTURE_HOST}:443") {
        return None;
    }
    std::env::var("ORCEL_E2E_FIXTURE_SPKI")
        .ok()
        .filter(|spki| !spki.is_empty())
}

/// A committed download, as the host reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveDownload {
    pub relative: String,
    pub sha256: String,
    pub bytes: u64,
    pub source_url: String,
    /// The broker record the approval was consumed under.
    pub record_id: String,
}

/// SG-000135 OB-02: the host's extraction of the committed document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveExtraction {
    pub url: String,
    pub document_generation: u64,
    pub truncated: bool,
    /// The page's own text: untrusted, never an instruction.
    pub text: String,
}

/// SG-000122 slice A2: the verifier's report, as the host gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveVerification {
    pub url: String,
    pub document_generation: u64,
    pub results: Vec<WireCheck>,
    pub verified: bool,
    pub evidence_sha256: String,
}

/// SG-000135 OB-06: whether a person answered an approval prompt: it was
/// approved, or denied by the person. A prompt that timed out unanswered
/// (`UNANSWERED_DENIAL`), or failed for any other reason, was not.
fn prompt_answered<T>(result: &Result<T, orcel_approval::ApprovalError>) -> bool {
    match result {
        Ok(_) => true,
        Err(error) => {
            error.code == FailureCode::ApprovalDenied
                && !error.message.starts_with(orcel_approval::UNANSWERED_DENIAL)
        }
    }
}

/// SG-000135 OB-06: the refusal code of a frame the takeover gate stopped
/// right before it was sent (nothing reached the host).
pub(crate) const GATE_REFUSED: &str = "orceld:human_takeover";

/// What became of a consumed approval (slice 2: the "consumed, not
/// dispatched" record of decision 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// The host carried the action out.
    Executed,
    /// The host refused the action after the approval was spent (closed code).
    Refused(String),
    /// The reply never came (timeout, a dead or broken host): the approval
    /// was spent and the outcome is unknown until reconciled.
    Lost,
}

/// One consumed approval and its outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalOutcome {
    pub record_id: String,
    pub outcome: DispatchOutcome,
    /// SG-000135 OB-08: the Full Access lease that authorized the frame
    /// instead of an approval (its record id is then the lease's one-shot
    /// use id, never an approval record).
    pub lease_id: Option<String>,
    /// SG-000135 OB-05: the authority service's epoch that lease was
    /// checked at.
    pub lease_epoch: Option<u64>,
}

/// SG-000135 OB-08: what authorizes one consequential frame.
enum Authority {
    /// A SOFT approval, spent (consumed) right before dispatch.
    Approval {
        token: ApprovedToken,
        digest: String,
    },
    /// A Full Access lease, checked once more right before dispatch.
    Lease(LeaseUse),
}

/// A download sent to the host whose reply has not arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadIntent {
    pub record_id: String,
    pub folder: PathBuf,
    pub relative: String,
}

/// What a lost download left at its destination. orceld cannot tell the
/// host's committed file from one a same-user process placed at that name,
/// so a present file is reported, never adopted as a committed download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconciled {
    PresentUnverified { sha256: String, bytes: u64 },
    Absent,
}

/// One intent recovered from an earlier run and what reconciling it found.
pub type Recovered = (DownloadIntent, Result<Reconciled, ProviderError>);

/// What is at `relative` inside `folder` now. `relative` must pass the
/// host's own destination rules (no root, traversal, streams, trailing
/// dots or spaces, reserved names); no segment below `folder` may be a
/// reparse point, and anything but a regular file at the name is refused
/// rather than reported. The file is hashed through the handle that was
/// checked, and never beyond the transfer limit.
pub fn reconcile_destination(folder: &Path, relative: &str) -> Result<Reconciled, ProviderError> {
    let relative = orcel_browser_host::validate_relative_destination(relative).map_err(|_| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "the destination name is not a plain relative path",
        )
    })?;
    let segments: Vec<&str> = relative.split(['/', '\\']).collect();
    let mut path = folder.to_path_buf();
    for (index, segment) in segments.iter().enumerate() {
        path.push(segment);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Reconciled::Absent)
            }
            Err(_) => return Err(uninspectable()),
        };
        let last = index + 1 == segments.len();
        if is_reparse_point(&metadata)
            || (last && !metadata.is_file())
            || (!last && !metadata.is_dir())
        {
            return Err(not_a_regular_file());
        }
    }
    let file = open_no_reparse(&path).map_err(|_| uninspectable())?;
    // The handle's own metadata: what was opened is still a plain file.
    let metadata = file.metadata().map_err(|_| uninspectable())?;
    if is_reparse_point(&metadata) || !metadata.is_file() {
        return Err(not_a_regular_file());
    }
    let limit = orcel_browser_host::MAX_TRANSFER_BYTES;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut reader = std::io::Read::take(file, limit + 1);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = std::io::Read::read(&mut reader, &mut buffer).map_err(|_| {
            ProviderError::new(
                FailureCode::ProviderUnavailable,
                "the destination could not be read",
            )
        })?;
        if read == 0 {
            break;
        }
        bytes += read as u64;
        hasher.update(&buffer[..read]);
    }
    if bytes > limit {
        return Err(ProviderError::new(
            FailureCode::PostconditionFailed,
            "the destination is larger than any transfer",
        ));
    }
    Ok(Reconciled::PresentUnverified {
        sha256: hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        bytes,
    })
}

fn uninspectable() -> ProviderError {
    ProviderError::new(
        FailureCode::ProviderUnavailable,
        "the destination could not be inspected",
    )
}

fn not_a_regular_file() -> ProviderError {
    ProviderError::new(
        FailureCode::PostconditionFailed,
        "the destination is not a regular file",
    )
}

fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Open for reading without following a reparse point at the final name.
fn open_no_reparse(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// One line of the intent journal. A download's `pending` line is written
/// and synced before its approval is consumed; `settled` follows a reply
/// (success or refusal), `abandoned` an approval that was never consumed,
/// and `reconciled` a report of the destination after a lost reply.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct JournalLine {
    schema: String,
    event: String,
    record_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    folder: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    relative: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host_started: Option<u64>,
}

impl JournalLine {
    fn event(event: &str, record_id: &str) -> Self {
        Self {
            schema: INTENT_SCHEMA.into(),
            event: event.into(),
            record_id: record_id.into(),
            folder: None,
            relative: None,
            host_pid: None,
            host_started: None,
        }
    }
}

/// A download intent the journal still holds open, with the host that
/// was asked to carry it out (pid and creation time, so a reused pid is
/// never mistaken for it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournaledIntent {
    pub intent: DownloadIntent,
    pub host_pid: u32,
    pub host_started: u64,
}

fn journal_unavailable() -> ProviderError {
    ProviderError::new(
        FailureCode::ProviderUnavailable,
        "the download intent journal could not be written",
    )
}

/// Append one line and sync it to disk before returning (the shared
/// kernel journal, SG-000120 RJ-01; the bytes are unchanged).
fn journal_append(path: &Path, line: &JournalLine) -> Result<(), ProviderError> {
    orcel_journal::append_line(path, line).map_err(|_| journal_unavailable())
}

/// The `pending` line that opens a download intent: refused while too
/// little room would remain for its closing line.
fn journal_append_opening(path: &Path, line: &JournalLine) -> Result<(), ProviderError> {
    orcel_journal::append_opening_line(path, line).map_err(|_| journal_unavailable())
}

/// The intents still open in the journal, in order. A torn line (a crash
/// mid-append, before the approval was consumed: a strict prefix of a
/// line, so its JSON ends early) is skipped wherever a later append sealed
/// it; any other unreadable line fails closed.
pub fn journal_open_intents(path: &Path) -> Result<Vec<JournaledIntent>, ProviderError> {
    let unreadable = || {
        ProviderError::new(
            FailureCode::ProviderUnavailable,
            "the download intent journal is unreadable",
        )
    };
    let lines = match orcel_journal::read_lines::<JournalLine>(path) {
        Ok(lines) => lines.lines,
        Err(orcel_journal::JournalError::Read) => {
            return Err(ProviderError::new(
                FailureCode::ProviderUnavailable,
                "the download intent journal could not be read",
            ))
        }
        Err(_) => return Err(unreadable()),
    };
    let mut open: Vec<JournaledIntent> = Vec::new();
    for line in lines {
        if line.schema != INTENT_SCHEMA {
            return Err(unreadable());
        }
        match line.event.as_str() {
            "pending" => match (line.folder, line.relative, line.host_pid, line.host_started) {
                (Some(folder), Some(relative), Some(host_pid), Some(host_started)) => {
                    open.push(JournaledIntent {
                        intent: DownloadIntent {
                            record_id: line.record_id,
                            folder,
                            relative,
                        },
                        host_pid,
                        host_started,
                    })
                }
                _ => return Err(unreadable()),
            },
            "settled" | "abandoned" | "reconciled" => {
                open.retain(|entry| entry.intent.record_id != line.record_id)
            }
            _ => return Err(unreadable()),
        }
    }
    Ok(open)
}

/// What the OS says about a process id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Liveness {
    /// Running, with this creation time.
    Running(u64),
    /// No such process (or it has exited).
    Gone,
    /// The OS would not say (access refused): never taken as gone.
    Unknown,
}

fn liveness(pid: u32) -> Liveness {
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_INVALID_PARAMETER, FILETIME, STILL_ACTIVE,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // SAFETY: a plain query-only open of a pid; the handle is closed below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process == 0 {
        // SAFETY: reads the calling thread's last error.
        return match unsafe { GetLastError() } {
            ERROR_INVALID_PARAMETER => Liveness::Gone,
            _ => Liveness::Unknown,
        };
    }
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    let mut code: u32 = 0;
    // SAFETY: a valid handle and out-pointers to locals.
    let state = unsafe {
        if GetExitCodeProcess(process, &mut code) == 0
            || GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) == 0
        {
            Liveness::Unknown
        } else if code != STILL_ACTIVE as u32 {
            Liveness::Gone
        } else {
            Liveness::Running(
                (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime),
            )
        }
    };
    // SAFETY: closing the handle opened above, once.
    unsafe { CloseHandle(process) };
    state
}

/// Whether the host an intent named may still be running. A reused pid
/// (another creation time) means that host is gone; an unanswerable query
/// counts as running, so nothing it could still commit is reported.
fn host_may_run(host_pid: u32, host_started: u64) -> bool {
    match liveness(host_pid) {
        Liveness::Running(started) => started == host_started,
        Liveness::Gone => false,
        Liveness::Unknown => true,
    }
}

/// Reconcile, once, every open intent whose host is gone: after a orceld
/// restart (orceld's job kills the host family when orceld ends) or a host
/// that died. An intent whose host may still run belongs to a live lifetime
/// (possibly another orceld's) and is left untouched. A report that could
/// not be made (the destination unreadable for now) stays open.
pub fn recover_intents(journal: &Path) -> Result<Vec<Recovered>, ProviderError> {
    let mut recovered = Vec::new();
    for open in journal_open_intents(journal)? {
        if host_may_run(open.host_pid, open.host_started) {
            continue;
        }
        let found = reconcile_destination(&open.intent.folder, &open.intent.relative);
        let settled =
            !matches!(&found, Err(error) if error.code == FailureCode::ProviderUnavailable);
        if settled {
            journal_append(
                journal,
                &JournalLine::event("reconciled", &open.intent.record_id),
            )?;
        }
        recovered.push((open.intent, found));
    }
    Ok(recovered)
}

/// SG-000135 OB-03: a bounded, masked page screenshot as orceld checked it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveScreenshot {
    pub png: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub truncated: bool,
    pub sha256: String,
}

/// SG-000135 OB-03: one tab as a tab report shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TabView {
    pub page_id: String,
    pub generation: u64,
    /// The tab's committed URL (orceld's record), if it has one.
    pub url: Option<String>,
    pub active: bool,
}

/// SG-000135 OB-03: a tab of the lifetime other than the active one: its
/// own page-store page (own id and generation) and its worker tab id.
#[derive(Debug, Clone)]
struct BackgroundTab {
    page: PageRecord,
    worker_tab: u32,
    url: Option<String>,
}

/// SG-000135 OB-03: the most tabs one session holds.
pub const MAX_TABS: usize = orcel_browser_host::page_capture::MAX_TABS;

/// One supervised worker-mode host and at most one lifetime.
pub struct LiveBrowser {
    supervisor: Supervisor,
    lifetime: Option<String>,
    /// The origin the current lifetime admitted (slice 3c).
    lifetime_origin: Option<String>,
    /// The workspace the live page belongs to (slice 3c).
    page_workspace: Option<String>,
    /// The page-store record of the lifetime's page (slice 2b).
    page: Option<PageRecord>,
    pages: PageStore,
    intents: PathBuf,
    /// The host's pid and creation time, written into every intent.
    host_pid: u32,
    host_started: u64,
    /// What `start` reconciled from earlier runs.
    recovered: Vec<Recovered>,
    outcomes: Vec<ApprovalOutcome>,
    pending_download: Option<DownloadIntent>,
    /// WI-05: the downloads the host committed in this lifetime, the only
    /// files `parse_download` will hand to the confined document parser.
    committed: Vec<crate::document_parse::CommittedDownload>,
    /// SG-000122 slice A2: each node of the latest observation and its role
    /// (the role a form action binds; the host checks it again).
    observed_roles: std::collections::HashMap<String, String>,
    /// None while the host is (or may be) running; once ended, whether the
    /// whole family was confirmed gone. Set once, never revised: a later
    /// shutdown finds no host and would report a vacuous success.
    host_ended: Option<bool>,
    /// Orcel Browser B1: the human-intervention gate, asked before every
    /// agent action on the page (off until SG-000135; it can only refuse).
    takeover: TakeoverGate,
    /// SG-000135 OB-04: the persistent Orcel-managed profile this browser
    /// runs in, named in every approval prompt it asks; `None` for an
    /// ephemeral profile.
    profile_label: Option<String>,
    /// The gate's ticket for the write in progress, if it admitted one.
    gate_ticket: Option<WriteTicket>,
    /// The page's latest committed URL (B1: the path in an action's
    /// stable key).
    page_url: Option<String>,
    /// SG-000135 OB-03 (browser_full only; always empty for
    /// browser_structured): the lifetime's other tabs, and the worker tab
    /// id of `page`, once a tab request learned it.
    background: Vec<BackgroundTab>,
    active_tab: Option<u32>,
    /// SG-000135 OB-08 (browser_full only; always `None` for
    /// browser_structured): the session's Full Access lease cache.
    full_access: Option<FullAccess>,
    /// SG-000135 OB-08: the family a navigation also needs (`tabs` while a
    /// new tab opens its URL).
    navigation_also: Option<BrowserFamily>,
    /// SG-000135 OB-07 (browser_full only): what the challenge detector
    /// last reported for each page that waits for the person, by page id.
    challenges: std::collections::HashMap<String, ChallengeNote>,
    /// SG-000135 OB-07b: a page of this session was detected as a sign-in
    /// page. From then on every agent-facing URL of the session shows no
    /// query or fragment value (`agent_url`): a later URL may carry what the
    /// person typed (a GET sign-in form). Never cleared.
    sign_in_seen: bool,
    /// SG-000135 OB-07: the HTTP status of each page's latest committed
    /// navigation that orceld dispatched, with the URL it committed (the
    /// detector counts a status only while the page still shows that URL).
    page_status: std::collections::HashMap<String, (String, u16)>,
    /// SG-000135 OB-07: the page the detector last ran on, and when.
    last_challenge_check: Option<(String, std::time::Instant)>,
    /// Test builds only: a shorter reply budget for dispatched frames.
    #[cfg(test)]
    reply_timeout: Option<std::time::Duration>,
    /// Test builds only: runs once, between a consume and its dispatch,
    /// with the host's pid (to make the host die there).
    #[cfg(test)]
    after_consume: Option<Box<dyn FnMut(u32)>>,
}

/// The failure code for a host refusal (design open question 4), from the
/// closed code only: no host text crosses.
pub fn failure_for(code: &str) -> FailureCode {
    match code {
        "binding_mismatch" | "no_lifetime" | "no_observation" => FailureCode::TargetStale,
        "approval_replay" => FailureCode::ApprovalDenied,
        "invalid" => FailureCode::InvalidRequest,
        "download" => FailureCode::PostconditionFailed,
        "unavailable:timedout" => FailureCode::ProcessTimeout,
        // BR-01: the approved element is gone and nothing replaced it.
        "unavailable:targetstale" => FailureCode::TargetStale,
        // BR-04: another element covers it; nothing was clicked. Like a
        // stale target, the page must be observed again.
        "unavailable:targetoccluded" => FailureCode::TargetStale,
        // SG-000122: the lifetime's cap on distinct awaited texts; the page
        // was not probed.
        "unavailable:textlimitreached" => FailureCode::OutputLimit,
        // SG-000122 slice A6: before anything opened, an Enter's page tried
        // to open a document off the Enter route rule (another origin,
        // another method, a frame or a popup); the route rule refused it
        // before it left. (A refusal after the admitted document opened is
        // `unavailable:outcomeunknown`.)
        "unavailable:submissionrefused" => FailureCode::CapabilityDenied,
        // SG-000135 OB-03: a navigation was in flight (nothing captured or
        // changed; observe again), a screenshot past its bounds, or the
        // lifetime's tab cap.
        "unavailable:navigationinflight" => FailureCode::TargetStale,
        "unavailable:captureoversized" | "unavailable:tablimitreached" => FailureCode::OutputLimit,
        code if code.starts_with("unavailable:") => FailureCode::ProviderUnavailable,
        _ => FailureCode::InternalError,
    }
}

fn host_error(error: orcel_browser_host::HostError) -> ProviderError {
    let code = orcel_browser_host::worker_host::error_code(&error);
    // A failed pipe or platform call is the provider being unavailable (a
    // dead or broken host), not an internal fault.
    let failure = match error {
        orcel_browser_host::HostError::Io(_) | orcel_browser_host::HostError::Platform(_) => {
            FailureCode::ProviderUnavailable
        }
        _ => failure_for(&code),
    };
    ProviderError::new(failure, format!("browser host: {code}"))
}

/// The page store's errors, as orceld's (same code and message).
fn from_page(error: orcel_provider_browser::ProviderError) -> ProviderError {
    ProviderError::new(error.code, error.message)
}

/// SG-000135 OB-07: how often a page that waits for the person is checked
/// again (on the agent's next request or status read).
pub(crate) const CHALLENGE_RECHECK: std::time::Duration = std::time::Duration::from_millis(1_000);

/// SG-000135 OB-07: the signal a page is held with when the detector could
/// not answer for it (fail closed).
pub(crate) const DETECTOR_UNAVAILABLE: &str = "detector_unavailable";

/// SG-000135 OB-07: what the detector last reported for a waiting page.
#[derive(Debug, Clone)]
struct ChallengeNote {
    signals: Vec<String>,
    /// The detector has since reported it gone (the quiet period runs).
    gone: bool,
}

/// SG-000135 OB-07: the host's closed code for a page between documents.
const NAVIGATION_IN_FLIGHT: &str = "unavailable:navigationinflight";

/// SG-000135 OB-07: what one detector run said about the active page.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Detection {
    /// A challenge of this kind, with the detector's signals.
    Seen(ChallengeKind, Vec<String>),
    /// Nothing that asks for a person.
    Clear,
    /// The page was between documents: nothing was classified.
    Busy,
    /// The detector could not answer.
    Unavailable,
}

/// SG-000135 OB-07: what the live browser does about a detection.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ChallengeStep {
    /// The page waits for the person (or keeps waiting).
    Hold(ChallengeKind, Vec<String>),
    /// Tell the gate, once, that the challenge is gone.
    ReportGone,
    /// Already reported gone: the quiet period runs on.
    StillGone,
    /// Nothing waits: drop any note.
    Forget,
    /// Nothing learned: check again later (a held page stays held).
    Later,
}

/// SG-000135 OB-07: the decision for one detection, given whether the page
/// already waits and whether its disappearance was already reported. A
/// page between documents (a navigation in flight, or a document that
/// changed during the capture) is never held for that alone: it is checked
/// again on the next action or status read. Any other detector failure
/// holds the page (fail closed). The gate is told a challenge is gone once
/// per disappearance, so repeated checks cannot push the quiet period back.
fn challenge_step(detection: Detection, waiting: bool, reported_gone: bool) -> ChallengeStep {
    match detection {
        Detection::Seen(kind, signals) => ChallengeStep::Hold(kind, signals),
        Detection::Clear if !waiting => ChallengeStep::Forget,
        Detection::Clear if reported_gone => ChallengeStep::StillGone,
        Detection::Clear => ChallengeStep::ReportGone,
        Detection::Busy => ChallengeStep::Later,
        Detection::Unavailable => {
            ChallengeStep::Hold(ChallengeKind::Other, vec![DETECTOR_UNAVAILABLE.to_owned()])
        }
    }
}

/// SG-000135 OB-07: the gate's kind for the detector's word (None for
/// `none`; an unknown word never arrives: the host checks the vocabulary).
fn challenge_kind(kind: &str) -> Option<ChallengeKind> {
    match kind {
        "captcha" => Some(ChallengeKind::Captcha),
        "mfa" => Some(ChallengeKind::Mfa),
        "sign_in" => Some(ChallengeKind::SignIn),
        "passkey" => Some(ChallengeKind::Passkey),
        "none" => None,
        _ => Some(ChallengeKind::Other),
    }
}

/// SG-000135 OB-07: a challenge kind's wire name.
pub(crate) fn challenge_name(kind: ChallengeKind) -> &'static str {
    match kind {
        ChallengeKind::SignIn => "sign_in",
        ChallengeKind::Mfa => "mfa",
        ChallengeKind::Passkey => "passkey",
        ChallengeKind::Captcha => "captcha",
        ChallengeKind::Other => "other",
    }
}

/// SG-000135 OB-03: a tab id the session does not hold.
fn unknown_tab() -> ProviderError {
    ProviderError::new(
        FailureCode::TargetStale,
        "the browser session has no such tab; list its tabs again",
    )
}

fn refused(code: &str) -> ProviderError {
    ProviderError::new(failure_for(code), format!("browser host refused: {code}"))
}

pub(crate) fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The combined approval digest: orceld's material (workspace, policy
/// revision, lifetime, the page store's page id, generation and origin,
/// the action with its node, value, option, state or key, and for a form
/// action the field facts its prompt shows) and the host binding.
pub(crate) fn approval_digest(
    workspace_id: &str,
    lifetime: &str,
    page: &PageRecord,
    action: &BindAction,
    form: Option<&BoundForm>,
    host_binding: &str,
) -> String {
    // A bind action is plain strings and booleans, so it always serializes;
    // an empty material would still differ from every real one.
    let action = serde_json::to_string(action).unwrap_or_default();
    let form = match form {
        None => "-".to_owned(),
        Some(form) => format!(
            "{}\n{}\n{}\n{}",
            form.role,
            sha256_hex(&form.name),
            form.name_cut,
            form.ordinal
                .map(|ordinal| format!("{}/{}", ordinal.position, ordinal.count))
                .unwrap_or_else(|| "-".to_owned())
        ),
    };
    sha256_hex(&format!(
        "{LIVE_APPROVAL_DOMAIN}\n{workspace_id}\n{POLICY_REVISION}\n{lifetime}\n{}\n{}\n{}\n{action}\n{form}\n{host_binding}",
        page.page_id, page.generation, page.current_origin
    ))
}

/// The host's binding for one action and the prompt a person would see.
struct Bound {
    prompt: ApprovalPrompt,
    digest: String,
    binding: String,
    target: String,
    /// SG-000135 OB-08: the host's classification of a link; unknown for
    /// every other action.
    impact: Impact,
}

/// SG-000135 OB-08: the origin of `url` as the page store names origins,
/// or empty (which no lease covers).
fn origin_of(url: &str) -> String {
    orcel_provider_browser::parse_destination_url(url)
        .map(|parsed| parsed.origin)
        .unwrap_or_default()
}

/// SG-000135 OB-04: `prompt` with the persistent profile `profile` named,
/// as the first preview line and (when `in_summary`, for a prompt whose
/// summary is not a shown value) in the summary. With no profile the prompt
/// is unchanged.
pub(crate) fn profile_prompt(
    profile: Option<&str>,
    prompt: ApprovalPrompt,
    in_summary: bool,
) -> ApprovalPrompt {
    let Some(name) = profile else {
        return prompt;
    };
    let line =
        format!("Profile: the Orcel-managed browser profile {name}; it may be signed in to sites");
    let mut prompt = prompt;
    if in_summary {
        prompt.summary = format!("{} profile={name}", prompt.summary);
    }
    prompt.preview = Some(match prompt.preview.take() {
        Some(orcel_approval::Preview::Content {
            mut lines,
            more_lines,
        }) => {
            lines.insert(0, ('>', line));
            let mut more_lines = more_lines;
            while lines.len() > orcel_approval::PREVIEW_LINES {
                lines.pop();
                more_lines += 1;
            }
            orcel_approval::Preview::Content { lines, more_lines }
        }
        Some(other) => other,
        None => orcel_approval::Preview::Content {
            lines: vec![('>', line)],
            more_lines: 0,
        },
    });
    prompt
}

/// SG-000122 slice A2: the approval prompt of one live form action, from
/// the host's facts about its field. Refused, before anything is asked, when
/// the field's name looks secret (fill and Enter), when the bind facts are
/// for another role, or when a fill value or option label is one the prompt
/// would cut or escape: the person sees the value exactly and in full, or no
/// prompt at all.
///
/// The value (or option label) is the whole summary line, so its bound is
/// the summary's own (`MAX_SUMMARY_CHARS` displayed characters). The field's
/// role and name are preview lines labelled as page-supplied; when another
/// field of its role would draw the same name line, its ordinal ("2 of 3")
/// too. Enter says that the page may submit or send what it holds. When an
/// earlier approved action on this page has an unknown outcome
/// (`earlier_unknown`, its operation), the first preview line says so,
/// leaving the value's summary line and bound untouched. At most
/// `PREVIEW_LINES` preview lines.
pub(crate) fn form_prompt(
    workspace_id: &str,
    target: &str,
    action: &BindAction,
    form: &BoundForm,
    digest: &str,
    earlier_unknown: Option<&str>,
) -> Result<ApprovalPrompt, ProviderError> {
    let refused = |message: &str| ProviderError::new(FailureCode::InvalidRequest, message);
    let role = match action {
        BindAction::Fill { role, .. }
        | BindAction::Select { role, .. }
        | BindAction::Check { role, .. }
        | BindAction::PressEnter { role, .. } => role,
        _ => return Err(refused("not a live form action")),
    };
    if *role != form.role {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "the browser host bound another field; observe the page again",
        ));
    }
    if matches!(
        action,
        BindAction::Fill { .. } | BindAction::PressEnter { .. }
    ) && orcel_browser_host::name_looks_secret(&form.name)
    {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "the field looks like a password, PIN or other secret; it is never filled or typed into",
        ));
    }
    // A radio can only be selected (the browser engine refuses to uncheck
    // one only after the approval is spent). The host refuses this before
    // binding; refused here again so no prompt can ever ask for it.
    if matches!(action, BindAction::Check { checked: false, .. }) && form.role == "radio" {
        return Err(refused(orcel_browser_host::RADIO_UNCHECK_REFUSED));
    }
    let shown = |text: &str, field: &str| {
        orcel_policy::live_browser::shown_in_full(text, field)
            .map_err(|error| ProviderError::new(error.code, error.message))
    };
    let mut lines = Vec::new();
    if let Some(operation) = earlier_unknown {
        // Kept short, so the prompt never cuts it.
        let operation: String = operation
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(16)
            .collect();
        lines.push(format!(
            "UNKNOWN EARLIER OUTCOME: an approved {operation} on this page may or may not have happened"
        ));
    }
    lines.push(format!("Field role (page-supplied): {}", form.role));
    // The host already bounded the name and said whether it cut it: the
    // same line the host keyed the ordinal on.
    let (name, cut) = orcel_contracts::prompt_display::bounded_field_name(&form.name);
    lines.push(orcel_contracts::prompt_display::field_name_line(
        name,
        cut || form.name_cut,
    ));
    if let Some(ordinal) = form.ordinal {
        lines.push(format!(
            "Field position: {} of {} fields with this role and shown name, in page order",
            ordinal.position, ordinal.count
        ));
    }
    let (title, summary) = match action {
        BindAction::Fill { value, .. } => {
            shown(value, "value")?;
            lines.push(if value.is_empty() {
                "Value: empty (the line after Target is blank), so the field is cleared".into()
            } else {
                "Value: the line after Target, exactly (a backslash shows doubled)".into()
            });
            lines.push("A value typed into an ordinary field is not checked for secrets".into());
            (
                "type the value on the line after Target into a field of an isolated browser page",
                value.clone(),
            )
        }
        BindAction::Select { label, .. } => {
            shown(label, "option")?;
            lines.push("Option: the line after Target, exactly as the page labels it".into());
            (
                "choose the option on the line after Target in a list of an isolated browser page",
                label.clone(),
            )
        }
        BindAction::Check { checked, .. } => (
            if *checked {
                "check a box or option on an isolated browser page"
            } else {
                "uncheck a box or option on an isolated browser page"
            },
            format!("set to {}", if *checked { "checked" } else { "unchecked" }),
        ),
        BindAction::PressEnter { .. } => {
            lines.push(
                "Enter may submit or send what the page holds, to the page's admitted origin"
                    .into(),
            );
            (
                "press Enter in a field of an isolated browser page",
                "press Enter (the page may submit or send what it holds)".to_owned(),
            )
        }
        _ => return Err(refused("not a live form action")),
    };
    Ok(ApprovalPrompt::new(
        workspace_id.to_owned(),
        POLICY_REVISION,
        title,
        target.to_owned(),
        summary,
        digest.to_owned(),
    )
    .with_preview(orcel_approval::Preview::Content {
        lines: lines.into_iter().map(|line| ('>', line)).collect(),
        more_lines: 0,
    }))
}

/// SG-000120 RJ-02: how a dispatched form action's journal intent closes.
/// B1: what makes two form actions the same action for the idempotency
/// guard: its kind and value, and the field's role, name and ordinal as the
/// host bound them. Hashed by the gate, never kept or logged.
fn form_material(action: &BindAction, form: &BoundForm) -> String {
    let (kind, value) = match action {
        BindAction::Fill { value, .. } => ("fill", value.clone()),
        BindAction::Select { label, .. } => ("select", label.clone()),
        BindAction::Check { checked, .. } => ("check", checked.to_string()),
        BindAction::PressEnter { .. } => ("enter", String::new()),
        other => ("other", format!("{other:?}")),
    };
    // The position only: a new, unrelated field of the same name changes
    // the count, and must not make the same field look like a new action.
    let ordinal = form
        .ordinal
        .map(|ordinal| ordinal.position.to_string())
        .unwrap_or_default();
    [
        kind,
        form.role.as_str(),
        form.name.as_str(),
        ordinal.as_str(),
        value.as_str(),
    ]
    .join("\u{0}")
}

/// Executed is `done`; a refusal the host gives before the worker could act
/// (a changed binding, a replayed record, the wrong control, a stale or
/// covered target, a busy worker) is `failed`, nothing done; anything else
/// (a lost reply, a timeout, an outcome the worker could not confirm) is
/// `unknown`, and nothing is ever retried in its place.
pub(crate) fn form_outcome(outcome: &DispatchOutcome) -> &'static str {
    match outcome {
        DispatchOutcome::Executed => "done",
        DispatchOutcome::Refused(code)
            if matches!(
                code.as_str(),
                "binding_mismatch"
                    | "approval_replay"
                    | "no_lifetime"
                    | "no_observation"
                    | "invalid"
                    | "unavailable:targetstale"
                    | "unavailable:targetoccluded"
                    | "unavailable:actionfailed"
                    // SG-000122 slice A6: the submission's document was
                    // refused at the route before anything opened (the
                    // host answers outcomeunknown once it opened).
                    | "unavailable:submissionrefused"
                    // SG-000135 OB-06: orceld's gate refused it before send.
                    | GATE_REFUSED
            ) =>
        {
            "failed"
        }
        DispatchOutcome::Refused(_) | DispatchOutcome::Lost => "unknown",
    }
}

impl LiveBrowser {
    /// Reconcile what earlier runs left open, then supervise one
    /// worker-mode host.
    pub fn start(
        host_binary: &Path,
        launch: &WorkerHostLaunch,
        state: &LiveState,
    ) -> Result<Self, ProviderError> {
        let recovered = recover_intents(&state.intents)?;
        let mut supervisor = Supervisor::new();
        supervisor
            .launch_worker_host(host_binary, launch)
            .map_err(host_error)?;
        let host_pid = supervisor.worker_host().map(|host| host.pid()).unwrap_or(0);
        // The supervisor holds the host's process handle, so its pid cannot
        // be reused while this reads the creation time.
        let host_started = match liveness(host_pid) {
            Liveness::Running(started) => started,
            _ => {
                let _ = supervisor.shutdown_worker_host();
                return Err(ProviderError::new(
                    FailureCode::ProviderUnavailable,
                    "the browser host's identity could not be read",
                ));
            }
        };
        Ok(Self {
            supervisor,
            lifetime: None,
            lifetime_origin: None,
            page_workspace: None,
            page: None,
            pages: PageStore::load_or_create(state.pages.clone()),
            intents: state.intents.clone(),
            host_pid,
            host_started,
            recovered,
            outcomes: Vec::new(),
            pending_download: None,
            committed: Vec::new(),
            observed_roles: std::collections::HashMap::new(),
            host_ended: None,
            takeover: TakeoverGate::from_switch(),
            profile_label: None,
            gate_ticket: None,
            page_url: None,
            background: Vec::new(),
            active_tab: None,
            full_access: None,
            navigation_also: None,
            challenges: std::collections::HashMap::new(),
            sign_in_seen: false,
            page_status: std::collections::HashMap::new(),
            last_challenge_check: None,
            #[cfg(test)]
            reply_timeout: None,
            #[cfg(test)]
            after_consume: None,
        })
    }

    fn request(&mut self, request: &WorkerHostRequest) -> Result<WorkerHostReply, ProviderError> {
        let host = self.supervisor.worker_host().ok_or_else(|| {
            ProviderError::new(FailureCode::ProviderUnavailable, "no live browser host")
        })?;
        match host.request(request) {
            Ok(WorkerHostReply::Error { code }) => Err(refused(&code)),
            Ok(reply) => Ok(reply),
            Err(error) => {
                // A lost or broken channel: the lifetime is over for orceld
                // (decision 3: a dead lifetime makes its page stale).
                self.end_host();
                Err(host_error(error))
            }
        }
    }

    /// End the lifetime and the whole host family, once. A host whose
    /// reply is lost may still be acting (suspended, or slow): only a
    /// confirmed-gone family makes the destination safe to reconcile.
    fn end_host(&mut self) {
        self.lifetime = None;
        self.lifetime_origin = None;
        self.close_page();
        if self.host_ended.is_none() {
            self.host_ended = Some(self.supervisor.shutdown_worker_host().unwrap_or(false));
        }
    }

    /// Send a consequential frame whose approval was just consumed, and
    /// record what became of that approval.
    fn dispatch(
        &mut self,
        record_id: &str,
        request: &WorkerHostRequest,
    ) -> Result<WorkerHostReply, ProviderError> {
        // SG-000135 OB-06: the takeover gate's last word, right before the
        // frame goes (spending the approval or checking the lease can take
        // seconds). A person who took the page over meanwhile stops it: the
        // approval is spent, nothing is sent, and the write ends `failed`.
        if let Err(error) = self.takeover.before_dispatch(self.gate_ticket.as_ref()) {
            self.note_gate_refusal(&error);
            self.outcomes.push(ApprovalOutcome {
                record_id: record_id.to_owned(),
                outcome: DispatchOutcome::Refused(GATE_REFUSED.to_owned()),
                lease_id: None,
                lease_epoch: None,
            });
            return Err(error);
        }
        #[cfg(test)]
        if let Some(mut hook) = self.after_consume.take() {
            if let Some(pid) = self.supervisor.worker_host().map(|host| host.pid()) {
                hook(pid);
            }
        }
        #[cfg(test)]
        let reply_timeout = self.reply_timeout;
        let reply = match self.supervisor.worker_host() {
            None => Err(ProviderError::new(
                FailureCode::ProviderUnavailable,
                "no live browser host",
            )),
            #[cfg(test)]
            Some(host) if reply_timeout.is_some() => host
                .request_within(request, reply_timeout.unwrap_or_default())
                .map_err(host_error),
            Some(host) => host.request(request).map_err(host_error),
        };
        let (outcome, result) = match reply {
            Ok(WorkerHostReply::Error { code }) => {
                let error = refused(&code);
                (DispatchOutcome::Refused(code), Err(error))
            }
            Ok(reply) => (DispatchOutcome::Executed, Ok(reply)),
            // Every other path leaves the consumed approval's outcome
            // unknown: record it lost, and end the host before anything
            // reads the destination.
            Err(error) => {
                // B1: settle the write as uncertain while its page's
                // session still exists; end_host closes the page.
                self.takeover
                    .after_write(self.gate_ticket.take(), "unknown");
                self.end_host();
                (DispatchOutcome::Lost, Err(error))
            }
        };
        self.outcomes.push(ApprovalOutcome {
            record_id: record_id.to_owned(),
            outcome,
            lease_id: None,
            lease_epoch: None,
        });
        result
    }

    /// SG-000135 OB-08: the frame dispatched under `record_id` was
    /// authorized by `authority`: its outcome names the lease, if one.
    fn note_authority(&mut self, record_id: &str, authority: &Authority) {
        if let Authority::Lease(used) = authority {
            if let Some(last) = self
                .outcomes
                .last_mut()
                .filter(|last| last.record_id == record_id)
            {
                last.lease_id = Some(used.lease_id.clone());
                last.lease_epoch = Some(used.authority_epoch);
            }
        }
    }

    /// SG-000135 OB-08: give this browser (a broker session's) its Full
    /// Access lease cache. browser_structured never has one.
    pub(crate) fn set_full_access(&mut self, access: FullAccess) {
        self.full_access = Some(access);
    }

    /// SG-000135 OB-08: the session's lease status, read-only (scope and
    /// expiry), for `browser_task_status`.
    pub(crate) fn full_access_status(&self) -> Option<serde_json::Value> {
        self.full_access
            .as_ref()
            .map(|access| access.status(now_ms()))
    }

    /// SG-000135 OB-08: what is true now for a lease decision on `page_id`.
    fn lease_moment(&self, approval: &impl ApprovalBroker) -> LeaseMoment {
        LeaseMoment {
            approval_epoch: approval.verified_revoke_epoch(),
            now_ms: now_ms(),
            interventions: self.takeover.interventions(),
        }
    }

    /// A page opened: the takeover gate claims it, and (OB-08 review) the
    /// session's lease takes its intervention mark now, not at first use.
    fn page_claimed(&mut self, page_id: &str) {
        self.takeover.page_opened(page_id);
        let epoch = self.takeover.intervention_epoch(page_id);
        if let Some(access) = self.full_access.as_mut() {
            access.page_opened(page_id, epoch);
        }
    }

    /// SG-000135 OB-08: authorize one consequential frame. A session with
    /// a Full Access lease that covers `query` needs no prompt; otherwise
    /// (no lease, a query that is not covered, or no query) the person is
    /// asked as before. A lease that just became invalid refuses.
    fn authorize(
        &mut self,
        approval: &impl ApprovalBroker,
        prompt: &ApprovalPrompt,
        query: Option<LeaseQuery<'_>>,
    ) -> Result<Authority, ProviderError> {
        if let Some(query) = query {
            let moment = self.lease_moment(approval);
            if let Some(access) = self.full_access.as_mut() {
                match access.decide(&query, &moment) {
                    LeaseDecision::Covered(used) => return Ok(Authority::Lease(used)),
                    LeaseDecision::Refuse(error) => return Err(error),
                    LeaseDecision::Ask => {}
                }
            }
        }
        let token = self
            .request_token(approval, prompt)
            .map_err(|error| ProviderError::new(error.code, error.message))?;
        Ok(Authority::Approval {
            token,
            digest: prompt.digest.clone(),
        })
    }

    /// SG-000135 OB-08: right before dispatch, spend the approval (exact
    /// digest, single use) or check the lease once more (one fresh read).
    /// Returns the record id the frame carries.
    fn spend(
        &mut self,
        workspace: &Workspace,
        approval: &impl ApprovalBroker,
        authority: &Authority,
    ) -> Result<String, ProviderError> {
        match authority {
            Authority::Approval { token, digest } => {
                Self::consume(workspace, approval, token, digest.clone())?;
                Ok(token.record_id.clone())
            }
            Authority::Lease(used) => {
                // OB-08 review: from the first lease use on, the host refuses
                // every page request but a GET for this lifetime (page
                // scripts, fetch, XHR, form posts, beacons). Nothing is sent
                // unless the host confirms the guard.
                match self.request(&WorkerHostRequest::LeaseGuard {})? {
                    WorkerHostReply::Guarded {} => {}
                    _ => {
                        return Err(ProviderError::new(
                            FailureCode::InternalError,
                            "unexpected browser host reply",
                        ))
                    }
                }
                let moment = self.lease_moment(approval);
                let _ = used.page_id();
                let access = self.full_access.as_mut().ok_or_else(|| {
                    ProviderError::new(
                        FailureCode::CapabilityDenied,
                        "lease_invalid: this browser has no Full Access lease; nothing was sent",
                    )
                })?;
                access.confirm(used, &moment)?;
                Ok(used.record_id.clone())
            }
        }
    }

    /// SG-000135 OB-08: a person took the page over (the takeover gate
    /// refused as paused): Full Access stops for the session.
    fn note_gate_refusal(&mut self, error: &ProviderError) {
        if error.message.starts_with("browser session paused") {
            if let Some(access) = self.full_access.as_mut() {
                access.invalidate("a person interrupted this browser session");
            }
        }
    }

    /// A dead lifetime makes its page stale for good (decision 3). If the
    /// registry cannot record it, the page is still dropped here, so this
    /// browser never acts on it again.
    fn close_page(&mut self) {
        self.observed_roles.clear();
        self.close_background();
        if let Some(page) = self.page.take() {
            let _ = self.pages.close_page(&page.page_id);
            self.takeover.page_closed(&page.page_id);
            self.page_url = None;
        }
    }

    /// SG-000122 slice A2: the role the latest observation reported for
    /// `node_id`, if it holds that node.
    pub fn observed_role(&self, node_id: &str) -> Option<String> {
        self.observed_roles.get(node_id).cloned()
    }

    /// The page-store record of the lifetime's page, if a lifetime is open.
    pub fn page(&self) -> Option<&PageRecord> {
        self.page.as_ref()
    }

    /// What `start` reconciled from earlier runs (each reported once).
    pub fn recovered(&self) -> &[Recovered] {
        &self.recovered
    }

    /// What `start` reconciled from earlier runs, handed out once (slice
    /// 3c: the first live response after a start reports it).
    pub fn take_recovered(&mut self) -> Vec<Recovered> {
        std::mem::take(&mut self.recovered)
    }

    /// Every consumed approval of this browser and its outcome, in order.
    pub fn outcomes(&self) -> &[ApprovalOutcome] {
        &self.outcomes
    }

    /// Whether a lifetime is live (false after open, before open, or once a
    /// lost reply ended it).
    pub fn has_lifetime(&self) -> bool {
        self.lifetime.is_some()
    }

    /// Whether the host family was ended and confirmed gone (None while
    /// it may still be running).
    pub fn host_ended(&self) -> Option<bool> {
        self.host_ended
    }

    /// Reconcile the download whose reply was lost, if any: report what is
    /// at its destination now. Never re-downloads. Refused, keeping the
    /// intent, unless the host family is confirmed gone: a host still
    /// running could commit after the report.
    pub fn reconcile(&mut self) -> Option<Result<(DownloadIntent, Reconciled), ProviderError>> {
        self.pending_download.as_ref()?;
        if self.host_ended != Some(true) {
            return Some(Err(ProviderError::new(
                FailureCode::ProviderUnavailable,
                "the browser host is not confirmed gone; the destination cannot be reconciled",
            )));
        }
        let intent = self.pending_download.take()?;
        let found = match reconcile_destination(&intent.folder, &intent.relative) {
            Ok(found) => found,
            Err(error) => return Some(Err(error)),
        };
        if let Err(error) = journal_append(
            &self.intents,
            &JournalLine::event("reconciled", &intent.record_id),
        ) {
            return Some(Err(error));
        }
        Some(Ok((intent, found)))
    }

    /// Open a lifetime for the fixture destination (test builds only).
    #[cfg(feature = "live-browser-test")]
    pub fn open_fixture(
        &mut self,
        workspace: &Workspace,
        host: &str,
        fixture_spki: &str,
    ) -> Result<String, ProviderError> {
        match self.request(&WorkerHostRequest::Open {
            workspace: workspace.id.clone(),
            policy_revision: LIFETIME_POLICY_REVISION,
            host: host.into(),
            fixture_spki: fixture_spki.into(),
        })? {
            WorkerHostReply::Opened { lifetime, .. } => {
                // The lifetime's page, server-allocated in the page store
                // and bound to the workspace and this lifetime.
                match self.pages.open_page(
                    &workspace.id,
                    &format!("live-lifetime:{lifetime}"),
                    POLICY_REVISION,
                ) {
                    Ok(page) => {
                        self.page_claimed(&page.page_id);
                        self.page = Some(page);
                    }
                    Err(error) => {
                        self.end_host();
                        return Err(from_page(error));
                    }
                }
                // The page belongs to the workspace that opened it, as an
                // `open_page` page does (the form actions check it).
                self.page_workspace = Some(workspace.id.clone());
                self.lifetime = Some(lifetime.clone());
                Ok(lifetime)
            }
            _ => Err(ProviderError::new(
                FailureCode::InternalError,
                "unexpected browser host reply",
            )),
        }
    }

    /// Slice 3c: allocate the live page in the page store, bound to the
    /// workspace and to this host (no lifetime yet: the first navigation
    /// opens one for its origin). One page at a time: a page already open
    /// ends, with its lifetime, and is stale for good.
    pub fn open_page(&mut self, workspace: &Workspace) -> Result<PageRecord, ProviderError> {
        self.end_lifetime();
        self.close_page();
        let page = self
            .pages
            .open_page(
                &workspace.id,
                &format!("live-host:{}-{}", self.host_pid, self.host_started),
                POLICY_REVISION,
            )
            .map_err(from_page)?;
        self.page = Some(page.clone());
        self.page_workspace = Some(workspace.id.clone());
        self.page_claimed(&page.page_id);
        Ok(page)
    }

    /// The live page, if `page_id` names it, it belongs to `workspace`, it
    /// is not closed, and the caller saw its current generation.
    pub fn live_page(
        &self,
        workspace: &Workspace,
        page_id: &str,
        expected_generation: u64,
    ) -> Result<PageRecord, ProviderError> {
        let page = self
            .page
            .clone()
            .filter(|page| page.page_id == page_id && page.state != PageState::Closed)
            .filter(|_| self.page_workspace.as_deref() == Some(workspace.id.as_str()))
            .ok_or_else(|| {
                ProviderError::new(
                    FailureCode::TargetStale,
                    "the live page is unknown, closed or another workspace's; open a page first",
                )
            })?;
        if page.generation != expected_generation {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "the live page moved on since that generation; observe it again",
            ));
        }
        Ok(page)
    }

    /// End the current lifetime on purpose (a navigation to another
    /// origin): the host closes it and removes its profile; the page stays,
    /// and its next navigation advances its generation, so every node id
    /// and approval of the old lifetime is stale for good.
    fn end_lifetime(&mut self) {
        self.observed_roles.clear();
        // SG-000135 OB-03: the other tabs die with the lifetime.
        self.close_background();
        if self.lifetime.take().is_some() {
            self.lifetime_origin = None;
            let closed = self.request(&WorkerHostRequest::Close {});
            if !matches!(closed, Ok(WorkerHostReply::Closed { .. })) {
                // A host that cannot close cleanly is ended entirely.
                self.end_host();
            }
        }
    }

    /// Open a lifetime for `url`'s origin (development builds): orceld
    /// validates the destination under SG-000075 first, then the host
    /// resolves, admits and pins it itself (decision 2).
    #[cfg(feature = "live-browser-dev")]
    fn open_public(&mut self, workspace: &Workspace, url: &str) -> Result<(), ProviderError> {
        let resolver = orcel_provider_browser::SystemResolver;
        let validated =
            orcel_provider_browser::validate_destination(url, &resolver).map_err(from_page)?;
        match self.request(&WorkerHostRequest::OpenPublic {
            workspace: workspace.id.clone(),
            policy_revision: LIFETIME_POLICY_REVISION,
            url: url.into(),
        })? {
            WorkerHostReply::Opened { lifetime, .. } => {
                self.lifetime = Some(lifetime);
                self.lifetime_origin = Some(validated.origin.clone());
                Ok(())
            }
            _ => Err(ProviderError::new(
                FailureCode::InternalError,
                "unexpected browser host reply",
            )),
        }
    }

    /// SG-000135 OB-01 end-to-end harness (a build with both live browser
    /// features, which only tests make): a lifetime for the loopback
    /// fixture origin, trusting exactly its certificate, for the session's
    /// existing page. The host admits only the fixture host on 127.0.0.1.
    #[cfg(feature = "live-browser-test")]
    fn open_fixture_lifetime(
        &mut self,
        workspace: &Workspace,
        fixture_spki: &str,
        origin: &str,
    ) -> Result<(), ProviderError> {
        match self.request(&WorkerHostRequest::Open {
            workspace: workspace.id.clone(),
            policy_revision: LIFETIME_POLICY_REVISION,
            host: E2E_FIXTURE_HOST.into(),
            fixture_spki: fixture_spki.into(),
        })? {
            WorkerHostReply::Opened { lifetime, .. } => {
                self.lifetime = Some(lifetime);
                self.lifetime_origin = Some(origin.to_owned());
                Ok(())
            }
            _ => Err(ProviderError::new(
                FailureCode::InternalError,
                "unexpected browser host reply",
            )),
        }
    }

    /// Slice 3c: an approved navigation of the live page. A page with no
    /// lifetime, or one on another origin, first gets a lifetime for the
    /// URL's origin (the old one ends); the approval then binds the new
    /// lifetime's host pin (decision 2).
    #[cfg(feature = "live-browser-dev")]
    pub fn navigate_live(
        &mut self,
        workspace: &Workspace,
        approval: &impl ApprovalBroker,
        page_id: &str,
        expected_generation: u64,
        url: &str,
    ) -> Result<(String, u16), ProviderError> {
        self.live_page(workspace, page_id, expected_generation)?;
        self.gate_write(page_id, "navigate", url, ActionClass::Repeatable)?;
        // SG-000135 OB-08: the origin of the document the page holds now,
        // read before a switch ends its lifetime.
        let committed = self.page_url.as_deref().map(origin_of);
        let origin = orcel_provider_browser::parse_destination_url(url)
            .map_err(from_page)?
            .origin;
        let switched =
            self.lifetime.is_none() || self.lifetime_origin.as_deref() != Some(origin.as_str());
        if switched && !self.background.is_empty() {
            // SG-000135 OB-03: another site needs a new lifetime, which
            // would end the other tabs; nothing is ended silently.
            return Err(ProviderError::new(
                FailureCode::CapabilityDenied,
                "other tabs of this session are open on its current site; close them before opening another site",
            ));
        }
        if switched {
            // The old lifetime ends before the prompt, so the approval binds
            // the new lifetime and its host pin. The page's generation moves
            // only when a navigation commits (navigate's follow), once: the
            // caller's generation stays valid across a denial, and every
            // node id and approval of the old lifetime is stale by lifetime
            // (the host never resolves them; the digest binds the lifetime).
            self.end_lifetime();
            #[cfg(feature = "live-browser-test")]
            match e2e_fixture_spki(&origin) {
                Some(spki) => self.open_fixture_lifetime(workspace, &spki, &origin)?,
                None => self.open_public(workspace, url)?,
            }
            #[cfg(not(feature = "live-browser-test"))]
            self.open_public(workspace, url)?;
        }
        let navigated = self.navigate_approved(workspace, approval, url, committed.as_deref());
        if navigated.is_err() && switched {
            // A denied or failed switch leaves no lifetime, as decision 2
            // says: the fresh one never held a document of this page.
            self.end_lifetime();
        }
        navigated
    }

    /// Slice 3c: a bounded observation of the live page, with the host's
    /// typed selection of its latest dated link, if it has one.
    pub fn observe_live(
        &mut self,
        workspace: &Workspace,
        page_id: &str,
        expected_generation: u64,
    ) -> Result<(PageRecord, Vec<WireNode>, Option<String>), ProviderError> {
        let page = self.live_page(workspace, page_id, expected_generation)?;
        let read = self.takeover.before_read(page_id)?;
        if self.lifetime.is_none() {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "the live page has no document yet; navigate it first",
            ));
        }
        let nodes = self.observe()?;
        // No dated link, or a tie, is not an error: there is no selection.
        let latest = match self.request(&WorkerHostRequest::SelectLatestDatedLink {}) {
            Ok(WorkerHostReply::Selected { node_id }) => Some(node_id),
            Ok(_) => {
                return Err(ProviderError::new(
                    FailureCode::InternalError,
                    "unexpected browser host reply",
                ))
            }
            // A refusal (no dated link, a tie) leaves the lifetime; a lost
            // channel ends it, and that is an error.
            Err(error) => {
                if self.lifetime.is_none() {
                    return Err(error);
                }
                None
            }
        };
        // B1: a fresh observation is what the agent's next write is
        // planned on (and, after a person's intervention, what ends it).
        self.takeover.observed(read);
        Ok((page, nodes, latest))
    }

    /// Slice 3c: an approved activation of one observed link (the only
    /// live click). The page store follows the opened document.
    pub fn click(
        &mut self,
        workspace: &Workspace,
        approval: &impl ApprovalBroker,
        page_id: &str,
        expected_generation: u64,
        node_id: &str,
    ) -> Result<(String, u16), ProviderError> {
        let page = self.live_page(workspace, page_id, expected_generation)?;
        self.gate_write(page_id, "click", node_id, ActionClass::Repeatable)?;
        let action = BindAction::Click {
            node_id: node_id.into(),
            role: "link".into(),
        };
        let bound = self.bind_prompt(
            workspace,
            &action,
            "open a link on an isolated browser page",
        )?;
        // SG-000135 OB-08: a link to the page's own origin, which the host
        // classified routine from its name and destination.
        let effect = origin_of(&bound.target);
        let authority = self.authorize(
            approval,
            &bound.prompt,
            Some(LeaseQuery {
                family: BrowserFamily::Click,
                also: None,
                effect_origin: &effect,
                committed_origin: Some(&page.current_origin),
                impact: bound.impact,
                page_id,
            }),
        )?;
        // OB-08 review: under a lease the link is never clicked: the host
        // navigates (a GET) to the destination it bound, so no click
        // listener, `href="#"` or `javascript:` handler of the page runs.
        let frame = match &authority {
            Authority::Lease(_) => {
                let navigation = BindAction::Navigate {
                    url: bound.target.clone(),
                };
                let binding = match self.request(&WorkerHostRequest::Bind { action: navigation })? {
                    WorkerHostReply::Bound { binding, .. } => binding,
                    _ => {
                        return Err(ProviderError::new(
                            FailureCode::InternalError,
                            "unexpected browser host reply",
                        ))
                    }
                };
                (true, binding)
            }
            Authority::Approval { .. } => (false, bound.binding.clone()),
        };
        self.gate_confirm()?;
        let record_id = self.spend(workspace, approval, &authority)?;
        let request = if frame.0 {
            WorkerHostRequest::Navigate {
                url: bound.target.clone(),
                record_id: record_id.clone(),
                binding: frame.1,
            }
        } else {
            WorkerHostRequest::Activate {
                node_id: node_id.into(),
                role: "link".into(),
                record_id: record_id.clone(),
                binding: frame.1,
            }
        };
        let reply = self.dispatch(&record_id, &request);
        self.note_authority(&record_id, &authority);
        self.gate_finish(&record_id);
        match reply? {
            WorkerHostReply::Activated { url, status }
            | WorkerHostReply::Navigated { url, status } => {
                self.follow(&url)?;
                self.note_status(&url, status);
                Ok((url, status))
            }
            _ => Err(ProviderError::new(
                FailureCode::InternalError,
                "unexpected browser host reply",
            )),
        }
    }

    /// Slice 3c: what a download would do, for its prompt: the host's
    /// binding and the link it reads. Writes nothing and consumes nothing.
    pub fn preview_download(
        &mut self,
        workspace: &Workspace,
        page_id: &str,
        expected_generation: u64,
        node_id: &str,
        folder: &Path,
        relative: &str,
    ) -> Result<(String, String), ProviderError> {
        self.live_page(workspace, page_id, expected_generation)?;
        self.takeover.before_read(page_id)?;
        match self.request(&WorkerHostRequest::Bind {
            action: BindAction::Download {
                node_id: node_id.into(),
                role: "link".into(),
                folder: folder.to_string_lossy().into_owned(),
                relative: relative.into(),
            },
        })? {
            WorkerHostReply::Bound {
                binding, target, ..
            } => Ok((binding, target)),
            _ => Err(ProviderError::new(
                FailureCode::InternalError,
                "unexpected browser host reply",
            )),
        }
    }

    /// Record a committed document on the page (navigation or activation):
    /// a new generation, so earlier approvals and observations go stale. If
    /// the store cannot follow the host, the lifetime ends.
    pub(crate) fn follow(&mut self, url: &str) -> Result<PageRecord, ProviderError> {
        let moved = orcel_provider_browser::parse_destination_url(url)
            .map_err(from_page)
            .and_then(|origin| {
                let page = self.page.clone().ok_or_else(|| {
                    ProviderError::new(FailureCode::TargetStale, "no live browser page")
                })?;
                self.pages
                    .apply_navigation(
                        &page.page_id,
                        &page.current_origin,
                        page.generation,
                        &origin.origin,
                    )
                    .map(|(next, _, _)| next)
                    .map_err(from_page)
            });
        match moved {
            Ok(next) => {
                self.page_url = Some(url.to_owned());
                self.page = Some(next.clone());
                Ok(next)
            }
            Err(error) => {
                self.end_host();
                Err(error)
            }
        }
    }

    /// The two-part approval for `action`: the host's binding, then the
    /// broker's approval over orceld's material and that binding. Returns
    /// the approved, not yet consumed token, its digest and the host
    /// binding to present.
    fn ask(
        &mut self,
        workspace: &Workspace,
        approval: &impl ApprovalBroker,
        action: &BindAction,
        title: &str,
    ) -> Result<(ApprovedToken, String, String, String), ProviderError> {
        let bound = self.bind_prompt(workspace, action, title)?;
        let token = self
            .request_token(approval, &bound.prompt)
            .map_err(|error| ProviderError::new(error.code, error.message))?;
        Ok((token, bound.digest, bound.binding, bound.target))
    }

    /// Ask the owner's approval for `prompt`. SG-000135 OB-06: the takeover
    /// gate is told the prompt is up, so the click or key that answers it
    /// is not taken for a person on a Visible session's browser window.
    fn request_token(
        &mut self,
        approval: &impl ApprovalBroker,
        prompt: &ApprovalPrompt,
    ) -> Result<ApprovedToken, orcel_approval::ApprovalError> {
        self.takeover.prompt_started();
        let token = approval.request_token(prompt);
        // Only a prompt a person answered (approved or denied) excuses the
        // input around its end; one that timed out unanswered does not.
        let answered = prompt_answered(&token);
        self.takeover.prompt_ended(answered);
        token
    }

    /// The host's binding for `action` and the prompt a person would see
    /// for it (nothing asked yet), with the host's routine classification
    /// of a link (SG-000135 OB-08; unknown for anything else).
    fn bind_prompt(
        &mut self,
        workspace: &Workspace,
        action: &BindAction,
        title: &str,
    ) -> Result<Bound, ProviderError> {
        // What the prompt shows: where the action goes, and for a download
        // also where the file lands (all of it bound into the digest).
        let lifetime = self.lifetime.clone().ok_or_else(|| {
            ProviderError::new(FailureCode::TargetStale, "no live browser lifetime")
        })?;
        let page = self
            .page
            .clone()
            .filter(|page| page.state != PageState::Closed)
            .ok_or_else(|| ProviderError::new(FailureCode::TargetStale, "no live browser page"))?;
        let (binding, target, impact) = match self.request(&WorkerHostRequest::Bind {
            action: action.clone(),
        })? {
            WorkerHostReply::Bound {
                binding,
                target,
                impact,
                ..
            } => (binding, target, impact),
            _ => {
                return Err(ProviderError::new(
                    FailureCode::InternalError,
                    "unexpected browser host reply",
                ))
            }
        };
        let digest = approval_digest(&workspace.id, &lifetime, &page, action, None, &binding);
        let summary = match action {
            BindAction::Download {
                folder, relative, ..
            } => {
                format!("lifetime={lifetime} source={target} destination={folder} file={relative}")
            }
            _ => format!("lifetime={lifetime} target={target}"),
        };
        let prompt = ApprovalPrompt::new(
            workspace.id.clone(),
            POLICY_REVISION,
            title,
            target.clone(),
            summary,
            digest.clone(),
        );
        // A download's file gets its own Destination line and type, where a long source can't
        // push it out of view.
        let prompt = match action {
            BindAction::Download {
                folder, relative, ..
            } => prompt.downloading_to(format!("{folder}/{relative}")),
            _ => prompt,
        };
        let prompt = self.with_profile(prompt, true);
        // Only a link's classification is the host's to give; anything it
        // does not name exactly `routine` is not routine.
        let impact = match (action, impact) {
            (BindAction::Click { .. }, Some(impact)) => impact,
            _ => Impact::Unknown,
        };
        Ok(Bound {
            prompt,
            digest,
            binding,
            target,
            impact,
        })
    }

    /// B1: ask the takeover gate before an agent write on `page_id`. It
    /// can only refuse. A ticket an earlier write left (it failed before
    /// dispatch, so nothing was sent) is released first.
    fn gate_write(
        &mut self,
        page_id: &str,
        kind: &str,
        material: &str,
        class: ActionClass,
    ) -> Result<(), ProviderError> {
        self.takeover.after_write(self.gate_ticket.take(), "failed");
        match self.takeover.before_write(page_id, kind, material, class) {
            Ok(ticket) => {
                self.gate_ticket = ticket;
                Ok(())
            }
            Err(error) => {
                self.note_gate_refusal(&error);
                Err(error)
            }
        }
    }

    /// B1: give the write in progress the key of its stable material: the
    /// page's origin and URL path, the action's kind and `material` (a
    /// stable description of its target, never a node id).
    fn gate_rekey(&mut self, kind: &str, material: &str) -> Result<(), ProviderError> {
        let origin = self
            .page
            .as_ref()
            .map(|page| page.current_origin.clone())
            .unwrap_or_default();
        let rekeyed = self.takeover.rekey(
            self.gate_ticket.as_ref(),
            &origin,
            self.page_url.as_deref(),
            kind,
            material,
        );
        if rekeyed.is_err() {
            self.gate_ticket = None;
        }
        rekeyed
    }

    /// B1: ask the gate again right before the approval is spent: a person
    /// may have taken the page over while the prompt was up.
    fn gate_confirm(&mut self) -> Result<(), ProviderError> {
        let confirmed = self.takeover.before_dispatch(self.gate_ticket.as_ref());
        if let Err(error) = &confirmed {
            self.gate_ticket = None;
            self.note_gate_refusal(error);
        }
        confirmed
    }

    /// B1: tell the gate what became of the write dispatched under
    /// `record_id`, in the journal's words (`done`, `failed`, `unknown`).
    fn gate_finish(&mut self, record_id: &str) {
        let outcome = self
            .outcomes
            .last()
            .filter(|last| last.record_id == record_id)
            .map(|last| form_outcome(&last.outcome))
            .unwrap_or("unknown");
        self.takeover.after_write(self.gate_ticket.take(), outcome);
    }

    /// Spend the approval: exact digest, workspace and policy revision.
    fn consume(
        workspace: &Workspace,
        approval: &impl ApprovalBroker,
        token: &ApprovedToken,
        digest: String,
    ) -> Result<(), ProviderError> {
        approval
            .consume(
                token,
                &ConsumeExpectation::new(digest, workspace.id.clone(), POLICY_REVISION),
                now_ms(),
            )
            .map_err(|error| ProviderError::new(error.code, error.message))
    }

    /// An approved navigation of the lifetime's page. B1: asks the
    /// takeover gate first, as every agent write does.
    pub fn navigate(
        &mut self,
        workspace: &Workspace,
        approval: &impl ApprovalBroker,
        url: &str,
    ) -> Result<(String, u16), ProviderError> {
        let page_id = self
            .page
            .as_ref()
            .map(|page| page.page_id.clone())
            .unwrap_or_default();
        self.gate_write(&page_id, "navigate", url, ActionClass::Repeatable)?;
        let committed = self.page_url.as_deref().map(origin_of);
        self.navigate_approved(workspace, approval, url, committed.as_deref())
    }

    /// The approved navigation itself, once the gate admitted it.
    /// `committed` is the origin of the document the page held before this
    /// navigation (none for a page with no document yet): SG-000135 OB-08
    /// covers a navigation on that origin, or a page's first one, never a
    /// move to another origin.
    fn navigate_approved(
        &mut self,
        workspace: &Workspace,
        approval: &impl ApprovalBroker,
        url: &str,
        committed: Option<&str>,
    ) -> Result<(String, u16), ProviderError> {
        let bound = self.bind_prompt(
            workspace,
            &BindAction::Navigate { url: url.into() },
            "navigate isolated browser page",
        )?;
        let page_id = self
            .page
            .as_ref()
            .map(|page| page.page_id.clone())
            .unwrap_or_default();
        let effect = origin_of(url);
        let also = self.navigation_also;
        let authority = self.authorize(
            approval,
            &bound.prompt,
            Some(LeaseQuery {
                family: BrowserFamily::Navigate,
                also,
                effect_origin: &effect,
                committed_origin: committed,
                impact: browser_impact::classify_destination(url),
                page_id: &page_id,
            }),
        )?;
        self.gate_confirm()?;
        let record_id = self.spend(workspace, approval, &authority)?;
        let reply = self.dispatch(
            &record_id,
            &WorkerHostRequest::Navigate {
                url: url.into(),
                record_id: record_id.clone(),
                binding: bound.binding,
            },
        );
        self.note_authority(&record_id, &authority);
        self.gate_finish(&record_id);
        match reply? {
            WorkerHostReply::Navigated { url, status } => {
                // The page store follows the committed document: a new
                // origin and generation, so every earlier approval and
                // observation of this page goes stale. If the store cannot
                // follow, the lifetime ends rather than act on either.
                self.follow(&url)?;
                self.note_status(&url, status);
                Ok((url, status))
            }
            _ => Err(ProviderError::new(
                FailureCode::InternalError,
                "unexpected browser host reply",
            )),
        }
    }

    /// SG-000122 slice A2: one approved form action (fill, select, check or
    /// Enter) on an observed node of the live page. The host binds it from
    /// its own observation (refusing the wrong kind of control or a secret
    /// field before any prompt); orceld prompts with the value, the field's
    /// page-supplied role and name and, when shared, its ordinal, all bound
    /// into one single-use digest with the page, its generation, the
    /// lifetime and the host binding; the step is journaled before the
    /// prompt and closed `done`, `failed` or `unknown`, never retried.
    /// Returns the committed URL, the broker record and what happened to
    /// the document: the same document, or (slice A6, Enter only) the one
    /// same-origin document its submission committed, which the page store
    /// follows as a new generation.
    pub fn form_action(
        &mut self,
        workspace: &Workspace,
        approval: &impl ApprovalBroker,
        request: &orcel_contracts::RequestEnvelope,
        page_id: &str,
        expected_generation: u64,
        action: BindAction,
    ) -> Result<(String, String, FormNavigation), ProviderError> {
        self.live_page(workspace, page_id, expected_generation)?;
        // B1: Enter may submit or send what the page holds, so an Enter
        // whose outcome is unknown is never admitted again on this page.
        let class = if matches!(action, BindAction::PressEnter { .. }) {
            ActionClass::Consequential
        } else {
            ActionClass::Repeatable
        };
        self.gate_write(page_id, "form", &format!("{action:?}"), class)?;
        let lifetime = self.lifetime.clone().ok_or_else(|| {
            ProviderError::new(
                FailureCode::TargetStale,
                "the live page has no document yet; navigate it first",
            )
        })?;
        let page = self
            .page
            .clone()
            .filter(|page| page.state != PageState::Closed)
            .ok_or_else(|| ProviderError::new(FailureCode::TargetStale, "no live browser page"))?;
        let (binding, target, form) = match self.request(&WorkerHostRequest::Bind {
            action: action.clone(),
        })? {
            WorkerHostReply::Bound {
                binding,
                target,
                form: Some(form),
                ..
            } => (binding, target, form),
            _ => {
                return Err(ProviderError::new(
                    FailureCode::InternalError,
                    "unexpected browser host reply",
                ))
            }
        };
        // B1: the stable key names the field by its role, name and ordinal
        // (never its node id), so a renumbered observation still finds an
        // Enter whose outcome is unknown.
        self.gate_rekey("form", &form_material(&action, &form))?;
        let digest = approval_digest(
            &workspace.id,
            &lifetime,
            &page,
            &action,
            Some(&form),
            &binding,
        );
        // SG-000120 RJ-02: journaled against the page (Enter's effect is the
        // page's): an effect orceld cannot read back. A page whose latest
        // step has an unknown outcome refuses the first request after it
        // (in `pending`); the next one's prompt names the unknown first.
        let sink = crate::mutation_journal::global();
        let journal_target = format!("{}{page_id}", crate::mutation_journal::BROWSER_PAGE_TARGET);
        let earlier =
            crate::mutation_journal::surfaced_unknown(sink, &workspace.id, &journal_target);
        let prompt = form_prompt(
            &workspace.id,
            &target,
            &action,
            &form,
            &digest,
            earlier.as_deref(),
        )?;
        // The form prompt's summary is the value shown exactly: the profile
        // goes in the preview only.
        let prompt = self.with_profile(prompt, false);
        let mut intent = crate::mutation_journal::pending(
            sink,
            crate::mutation_journal::opaque(workspace, request, &digest, &journal_target),
        )?;
        let mut gate_refused = false;
        // SG-000135 OB-08: a fill (the `type` family) or a select of an
        // ordinary, named field on the page's own origin may be covered by
        // the session's lease; a check, an Enter (which may submit) and
        // anything secret, payment- or effect-named ask as before.
        let family = match &action {
            BindAction::Fill { .. } => Some(BrowserFamily::Type),
            BindAction::Select { .. } => Some(BrowserFamily::Select),
            _ => None,
        };
        let impact = if orcel_browser_host::name_looks_secret(&form.name) || form.name_cut {
            Impact::HighImpact
        } else {
            browser_impact::classify_field(&form.role, &form.name)
        };
        // OB-08 review: a value that looks secret or holds a stored secret
        // is never typed under a lease (refused below); one the secret
        // store could not check is left to the person (it asks).
        let fill_value = match (&action, self.full_access.as_ref()) {
            (BindAction::Fill { value, .. }, Some(access)) => access.fill_value(value),
            _ => FillValue::Ordinary,
        };
        let family = if fill_value == FillValue::Unverified {
            None
        } else {
            family
        };
        let query = family.map(|family| LeaseQuery {
            family,
            also: None,
            effect_origin: &page.current_origin,
            committed_origin: Some(&page.current_origin),
            impact,
            page_id,
        });
        let approved = self
            .authorize(approval, &prompt, query)
            .and_then(|authority| match authority {
                Authority::Lease(_) if fill_value == FillValue::Secret => Err(ProviderError::new(
                    FailureCode::CapabilityDenied,
                    "the value looks like a secret or holds a stored secret; Full Access never types it and nothing was sent",
                )),
                other => Ok(other),
            })
            .and_then(|authority| {
                self.gate_confirm()
                    .inspect_err(|_| gate_refused = true)
                    .map(|()| authority)
            });
        let approved = approved.and_then(|authority| {
            self.spend(workspace, approval, &authority)
                .map(|record_id| (record_id, authority))
        });
        let (record_id, authority) = match approved {
            Ok(done) => done,
            Err(refusal) => {
                intent.abandon(match refusal.code {
                    // B1: a person took the page over during the prompt.
                    // Only the gate's own refusal is named so; with the
                    // gate off this never happens.
                    _ if gate_refused => "target_stale",
                    _ if refusal
                        .message
                        .starts_with(crate::browser_lease::LEASE_INVALID) =>
                    {
                        "lease_invalid"
                    }
                    FailureCode::ApprovalDenied => "approval_denied",
                    _ => "approval_unavailable",
                });
                return Err(refusal);
            }
        };
        // If this line cannot be written, nothing is sent: the approval is
        // spent (or the lease use checked) and the step closes
        // `not_dispatched`.
        intent.dispatched()?;
        let reply = self.dispatch(
            &record_id,
            &WorkerHostRequest::FormAction {
                action,
                record_id: record_id.clone(),
                binding,
            },
        );
        self.note_authority(&record_id, &authority);
        let outcome = self
            .outcomes
            .last()
            .filter(|last| last.record_id == record_id)
            .map(|last| form_outcome(&last.outcome))
            .unwrap_or("unknown");
        intent.settle(outcome);
        self.takeover.after_write(self.gate_ticket.take(), outcome);
        let reply = match reply {
            Ok(reply) => reply,
            Err(error) => {
                // A refused or unknown step leaves nothing observed to act on.
                self.observed_roles.clear();
                return Err(error);
            }
        };
        match reply {
            WorkerHostReply::FormDone {
                url,
                navigation: FormNavigation::None,
            } => Ok((url, record_id, FormNavigation::None)),
            WorkerHostReply::FormDone {
                url,
                navigation: FormNavigation::DocumentCommitted,
            } => {
                // SG-000122 slice A6: the page store follows the committed
                // document (a new generation), so every earlier approval and
                // observation of the page goes stale.
                self.observed_roles.clear();
                self.follow(&url)?;
                Ok((url, record_id, FormNavigation::DocumentCommitted))
            }
            _ => Err(ProviderError::new(
                FailureCode::InternalError,
                "unexpected browser host reply",
            )),
        }
    }

    /// SG-000122 slice A2: wait, read-only and without approval, until
    /// `text` appears (or no copy is left) in the live page's committed main
    /// document, for at most `timeout_ms`. The host counts distinct awaited
    /// texts per lifetime and refuses a new one past its cap unprobed.
    pub fn wait_text(
        &mut self,
        workspace: &Workspace,
        page_id: &str,
        expected_generation: u64,
        text: &str,
        appear: bool,
        timeout_ms: u64,
    ) -> Result<bool, ProviderError> {
        self.live_page(workspace, page_id, expected_generation)?;
        self.takeover.before_read(page_id)?;
        self.require_lifetime()?;
        match self.request(&WorkerHostRequest::WaitText {
            text: text.into(),
            appear,
            timeout_ms,
        })? {
            WorkerHostReply::Waited { met } => Ok(met),
            _ => Err(ProviderError::new(
                FailureCode::InternalError,
                "unexpected browser host reply",
            )),
        }
    }

    /// SG-000122 slice A2: the BR-07 verifier, read-only and without
    /// approval, over the live page's committed main document. Its text
    /// checks share the waits' cap; its evidence is a fixed vocabulary and
    /// counts, never page text, a name or a value.
    pub fn verify(
        &mut self,
        workspace: &Workspace,
        page_id: &str,
        expected_generation: u64,
        checks: Vec<orcel_browser_host::Postcondition>,
    ) -> Result<LiveVerification, ProviderError> {
        self.live_page(workspace, page_id, expected_generation)?;
        self.takeover.before_read(page_id)?;
        self.require_lifetime()?;
        orcel_browser_host::check_postconditions(&checks)
            .map_err(|_| ProviderError::new(FailureCode::InvalidRequest, "malformed checks"))?;
        match self.request(&WorkerHostRequest::Verify { checks })? {
            WorkerHostReply::Verified {
                url,
                document_generation,
                results,
                verified,
                evidence_sha256,
            } => Ok(LiveVerification {
                url,
                document_generation,
                results,
                verified,
                evidence_sha256,
            }),
            _ => Err(ProviderError::new(
                FailureCode::InternalError,
                "unexpected browser host reply",
            )),
        }
    }

    /// SG-000135 OB-02: the committed main document's rendered content as
    /// bounded, untrusted page text (the host's `extract`), read-only and
    /// without approval, after the takeover gate admits a read.
    pub fn extract(
        &mut self,
        workspace: &Workspace,
        page_id: &str,
        expected_generation: u64,
    ) -> Result<LiveExtraction, ProviderError> {
        self.live_page(workspace, page_id, expected_generation)?;
        self.takeover.before_read(page_id)?;
        self.require_lifetime()?;
        match self.request(&WorkerHostRequest::Extract {})? {
            WorkerHostReply::Extracted {
                url,
                document_generation,
                truncated,
                text,
            } => Ok(LiveExtraction {
                url,
                document_generation,
                truncated,
                text,
            }),
            _ => Err(ProviderError::new(
                FailureCode::InternalError,
                "unexpected browser host reply",
            )),
        }
    }

    /// SG-000135 OB-03: drop every background tab (its page is stale for
    /// good and the takeover gate releases it).
    fn close_background(&mut self) {
        for tab in std::mem::take(&mut self.background) {
            let _ = self.pages.close_page(&tab.page.page_id);
            self.takeover.page_closed(&tab.page.page_id);
        }
        self.active_tab = None;
    }

    /// SG-000135 OB-03: a bounded PNG of the live page (the viewport, or
    /// with `full_page` the page from its top within the bounds), every
    /// secret field masked by the worker; read-only and without approval,
    /// after the takeover gate admits a read. The pieces are checked here
    /// again (order, size, byte count, PNG size, digest).
    pub fn screenshot(
        &mut self,
        workspace: &Workspace,
        page_id: &str,
        expected_generation: u64,
        full_page: bool,
    ) -> Result<LiveScreenshot, ProviderError> {
        use orcel_browser_host::page_capture::{PieceHeader, ScreenshotAssembly};
        self.live_page(workspace, page_id, expected_generation)?;
        self.takeover.before_read(page_id)?;
        self.require_lifetime()?;
        let malformed = |_| {
            ProviderError::new(
                FailureCode::InternalError,
                "the browser host's screenshot is malformed",
            )
        };
        let piece_of = |reply: WorkerHostReply, expected: u32| match reply {
            WorkerHostReply::Screenshot {
                piece,
                total,
                width,
                height,
                bytes,
                sha256,
                truncated,
                data,
            } if piece == expected => Ok((
                PieceHeader {
                    total,
                    width,
                    height,
                    bytes,
                    truncated,
                },
                sha256,
                data,
            )),
            _ => Err(ProviderError::new(
                FailureCode::InternalError,
                "unexpected browser host reply",
            )),
        };
        let first = self.request(&WorkerHostRequest::Screenshot { full_page })?;
        let (header, digest, data) = piece_of(first, 0)?;
        let mut assembly = ScreenshotAssembly::start(header, 0, &data).map_err(malformed)?;
        while let Some(piece) = assembly.next() {
            let reply = self.request(&WorkerHostRequest::ScreenshotMore { piece })?;
            let (next, again, data) = piece_of(reply, piece)?;
            if again != digest {
                return Err(malformed("digest"));
            }
            assembly.push(next, piece, &data).map_err(malformed)?;
        }
        let shot = assembly.finish().map_err(malformed)?;
        let sha256: String = Sha256::digest(&shot.png)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if sha256 != digest {
            return Err(malformed("digest"));
        }
        Ok(LiveScreenshot {
            png: shot.png,
            width: shot.width,
            height: shot.height,
            truncated: shot.truncated,
            sha256,
        })
    }

    /// SG-000135 OB-03: send one tab frame and check the host's report.
    fn tab_frame(
        &mut self,
        request: &WorkerHostRequest,
    ) -> Result<orcel_browser_host::page_capture::TabsState, ProviderError> {
        match self.request(request)? {
            WorkerHostReply::Tabs { active, tabs } => {
                orcel_browser_host::page_capture::TabsState::checked(active, tabs).map_err(|_| {
                    ProviderError::new(
                        FailureCode::InternalError,
                        "the browser host's tab report is malformed",
                    )
                })
            }
            _ => Err(ProviderError::new(
                FailureCode::InternalError,
                "unexpected browser host reply",
            )),
        }
    }

    /// SG-000135 OB-03: bring orceld's tabs in line with the worker's:
    /// a tab that is gone is closed for good; a tab the page opened that the
    /// host admitted (a popup, on the lifetime's site) gets its own page;
    /// and the active page is the worker's active tab.
    fn reconcile_tabs(
        &mut self,
        workspace: &Workspace,
        state: &orcel_browser_host::page_capture::TabsState,
    ) -> Result<(), ProviderError> {
        let present = |id: u32| state.tabs.iter().any(|tab| tab.tab == id);
        if self.active_tab.is_none() && self.page.is_some() && state.active != 0 {
            self.active_tab = Some(state.active);
        }
        let gone: Vec<BackgroundTab> = self
            .background
            .iter()
            .filter(|tab| !present(tab.worker_tab))
            .cloned()
            .collect();
        self.background.retain(|tab| present(tab.worker_tab));
        for tab in gone {
            let _ = self.pages.close_page(&tab.page.page_id);
            self.takeover.page_closed(&tab.page.page_id);
        }
        if let Some(active) = self.active_tab {
            if !present(active) {
                // The active tab's page went away (it closed itself).
                self.observed_roles.clear();
                if let Some(page) = self.page.take() {
                    let _ = self.pages.close_page(&page.page_id);
                    self.takeover.page_closed(&page.page_id);
                }
                self.page_url = None;
                self.active_tab = None;
            }
        }
        let known: Vec<u32> = self
            .background
            .iter()
            .map(|tab| tab.worker_tab)
            .chain(self.active_tab)
            .collect();
        for tab in &state.tabs {
            if known.contains(&tab.tab) {
                continue;
            }
            // A tab orceld never opened: adopted only on the lifetime's
            // site (the host already mediated it under SG-000075).
            let origin = orcel_provider_browser::parse_destination_url(&tab.url)
                .ok()
                .map(|target| target.origin)
                .filter(|origin| self.lifetime_origin.as_deref() == Some(origin.as_str()));
            let Some(origin) = origin else {
                continue;
            };
            let opened = self
                .pages
                .open_page(
                    &workspace.id,
                    &format!("live-host:{}-{}", self.host_pid, self.host_started),
                    POLICY_REVISION,
                )
                .map_err(from_page)?;
            let page = self
                .pages
                .apply_navigation(
                    &opened.page_id,
                    &opened.current_origin,
                    opened.generation,
                    &origin,
                )
                .map(|(next, _, _)| next)
                .map_err(from_page)?;
            self.page_claimed(&page.page_id);
            self.background.push(BackgroundTab {
                page,
                worker_tab: tab.tab,
                url: Some(tab.url.clone()),
            });
        }
        if state.active != 0 && self.active_tab != Some(state.active) {
            if let Some(index) = self
                .background
                .iter()
                .position(|tab| tab.worker_tab == state.active)
            {
                let target = self.background.remove(index);
                self.make_active(target);
            }
        }
        Ok(())
    }

    /// SG-000135 OB-03: `target` becomes the active tab; the active one, if
    /// any, goes to the background. Nothing observed holds afterwards.
    fn make_active(&mut self, target: BackgroundTab) {
        self.observed_roles.clear();
        if let (Some(page), Some(worker_tab)) = (self.page.take(), self.active_tab) {
            self.background.push(BackgroundTab {
                page,
                worker_tab,
                url: self.page_url.take(),
            });
        }
        self.page = Some(target.page);
        self.page_url = target.url;
        self.active_tab = Some(target.worker_tab);
    }

    /// SG-000135 OB-03: every tab, read-only (the worker's tab list, which
    /// also adopts admitted popups and drops tabs that closed themselves).
    pub fn tabs(&mut self, workspace: &Workspace) -> Result<Vec<TabView>, ProviderError> {
        if self.lifetime.is_some() {
            let state = self.tab_frame(&WorkerHostRequest::Tabs {})?;
            self.reconcile_tabs(workspace, &state)?;
        }
        Ok(self.tab_views())
    }

    pub fn tab_views(&self) -> Vec<TabView> {
        let mut views: Vec<(u32, TabView)> = Vec::new();
        if let Some(page) = &self.page {
            views.push((
                self.active_tab.unwrap_or(0),
                TabView {
                    page_id: page.page_id.clone(),
                    generation: page.generation,
                    url: self.page_url.clone(),
                    active: true,
                },
            ));
        }
        for tab in &self.background {
            views.push((
                tab.worker_tab,
                TabView {
                    page_id: tab.page.page_id.clone(),
                    generation: tab.page.generation,
                    url: tab.url.clone(),
                    active: false,
                },
            ));
        }
        views.sort_by_key(|(id, _)| *id);
        views.into_iter().map(|(_, view)| view).collect()
    }

    /// SG-000135 OB-03: open a new tab, active and blank, on the open
    /// lifetime (at most `MAX_TABS`), then, with `url`, navigate it there
    /// through the ordinary approved navigation (a new tab to a URL is a
    /// navigation: same SOFT approval, same host checks). `url` must be on
    /// the lifetime's site. If the navigation is refused or fails, the new
    /// tab is closed and the previous one is active again.
    #[cfg(feature = "live-browser-dev")]
    pub fn tab_new(
        &mut self,
        workspace: &Workspace,
        approval: &impl ApprovalBroker,
        url: Option<&str>,
    ) -> Result<(PageRecord, Option<(String, u16)>), ProviderError> {
        self.require_lifetime()?;
        // SG-000135 OB-06: no new tab opens in a window a person is using.
        self.takeover.hold_session()?;
        if let Some(url) = url {
            let origin = orcel_provider_browser::parse_destination_url(url)
                .map_err(from_page)?
                .origin;
            if self.lifetime_origin.as_deref() != Some(origin.as_str()) {
                return Err(ProviderError::new(
                    FailureCode::CapabilityDenied,
                    "a new tab opens only on the session's current site; open another site with browser_open in a session with one tab",
                ));
            }
        }
        let state = self.tab_frame(&WorkerHostRequest::Tabs {})?;
        self.reconcile_tabs(workspace, &state)?;
        if usize::from(self.page.is_some()) + self.background.len() >= MAX_TABS {
            return Err(ProviderError::new(
                FailureCode::OutputLimit,
                format!("the browser session already holds {MAX_TABS} tabs; close one first"),
            ));
        }
        let previous = self.active_tab;
        let state = self.tab_frame(&WorkerHostRequest::TabNew {})?;
        let known = self
            .background
            .iter()
            .any(|tab| tab.worker_tab == state.active)
            || self.active_tab == Some(state.active);
        if state.active == 0 || known {
            return Err(ProviderError::new(
                FailureCode::InternalError,
                "the browser host did not report the new tab",
            ));
        }
        let page = self
            .pages
            .open_page(
                &workspace.id,
                &format!("live-host:{}-{}", self.host_pid, self.host_started),
                POLICY_REVISION,
            )
            .map_err(from_page)?;
        self.page_claimed(&page.page_id);
        self.make_active(BackgroundTab {
            page: page.clone(),
            worker_tab: state.active,
            url: None,
        });
        self.reconcile_tabs(workspace, &state)?;
        let Some(url) = url else {
            return Ok((page, None));
        };
        self.navigation_also = Some(BrowserFamily::Tabs);
        let navigated =
            self.navigate_live(workspace, approval, &page.page_id, page.generation, url);
        self.navigation_also = None;
        match navigated {
            Ok(done) => {
                let page = self.page.clone().ok_or_else(|| {
                    ProviderError::new(FailureCode::TargetStale, "no live browser page")
                })?;
                Ok((page, Some(done)))
            }
            Err(error) => {
                // The new tab never held a document of its own: it closes,
                // and the tab before it is active again.
                if self.lifetime.is_some() {
                    let _ = self.close_tab_inner(workspace, &page.page_id, previous);
                }
                Err(error)
            }
        }
    }

    /// SG-000135 OB-03: make the tab with `page_id` active (after the
    /// takeover gate admits a read of it). Its generation is unchanged;
    /// nothing observed on any tab holds afterwards, so take a snapshot.
    pub fn tab_switch(
        &mut self,
        workspace: &Workspace,
        page_id: &str,
    ) -> Result<PageRecord, ProviderError> {
        self.require_lifetime()?;
        let state = self.tab_frame(&WorkerHostRequest::Tabs {})?;
        self.reconcile_tabs(workspace, &state)?;
        if let Some(page) = self.page.clone().filter(|page| page.page_id == page_id) {
            return Ok(page);
        }
        let index = self
            .background
            .iter()
            .position(|tab| tab.page.page_id == page_id)
            .ok_or_else(unknown_tab)?;
        self.takeover.before_read(page_id)?;
        // SG-000135 OB-06: the active tab never changes under a person.
        self.takeover.hold_session()?;
        let worker_tab = self.background[index].worker_tab;
        let state = self.tab_frame(&WorkerHostRequest::TabSwitch { tab: worker_tab })?;
        if state.active != worker_tab {
            return Err(ProviderError::new(
                FailureCode::InternalError,
                "the browser host did not switch to the tab",
            ));
        }
        let target = self.background.remove(index);
        self.make_active(target);
        self.reconcile_tabs(workspace, &state)?;
        self.page.clone().ok_or_else(unknown_tab)
    }

    /// SG-000135 OB-03: close the tab with `page_id` (after the takeover
    /// gate admits a write on it). Closing the active tab makes the most
    /// recently opened other tab active; closing the last tab ends the
    /// lifetime and leaves the session open with no page (browser_open
    /// opens a new one).
    pub fn tab_close(
        &mut self,
        workspace: &Workspace,
        page_id: &str,
    ) -> Result<Vec<TabView>, ProviderError> {
        let is_page = self
            .page
            .as_ref()
            .is_some_and(|page| page.page_id == page_id);
        if self.lifetime.is_none() {
            // A page with no document yet: closing it needs no host.
            if !is_page {
                return Err(unknown_tab());
            }
            self.gate_write(page_id, "tab_close", "tab", ActionClass::Repeatable)?;
            self.close_page();
            self.takeover.after_write(self.gate_ticket.take(), "done");
            return Ok(Vec::new());
        }
        let state = self.tab_frame(&WorkerHostRequest::Tabs {})?;
        self.reconcile_tabs(workspace, &state)?;
        let known = self
            .page
            .as_ref()
            .is_some_and(|page| page.page_id == page_id)
            || self
                .background
                .iter()
                .any(|tab| tab.page.page_id == page_id);
        if !known {
            return Err(unknown_tab());
        }
        self.gate_write(page_id, "tab_close", "tab", ActionClass::Repeatable)?;
        let closed = self.close_tab_inner(workspace, page_id, None);
        let outcome = if closed.is_ok() { "done" } else { "failed" };
        self.takeover.after_write(self.gate_ticket.take(), outcome);
        closed?;
        Ok(self.tab_views())
    }

    /// Close one known tab; `prefer` names the worker tab to make active
    /// when the active one closes (else the most recently opened other).
    fn close_tab_inner(
        &mut self,
        workspace: &Workspace,
        page_id: &str,
        prefer: Option<u32>,
    ) -> Result<(), ProviderError> {
        // SG-000135 OB-06: no tab closes, and no other becomes active, while
        // a person holds the session (a new tab whose navigation was
        // refused stays open until then).
        self.takeover.hold_session()?;
        let active = self
            .page
            .as_ref()
            .is_some_and(|page| page.page_id == page_id);
        if active {
            if self.background.is_empty() {
                // The last tab: the lifetime ends with it; the session stays.
                self.end_lifetime();
                self.close_page();
                return Ok(());
            }
            let next = prefer
                .filter(|id| self.background.iter().any(|tab| tab.worker_tab == *id))
                .or_else(|| self.background.iter().map(|tab| tab.worker_tab).max())
                .ok_or_else(unknown_tab)?;
            let state = self.tab_frame(&WorkerHostRequest::TabSwitch { tab: next })?;
            if let Some(index) = self
                .background
                .iter()
                .position(|tab| tab.worker_tab == next)
            {
                let target = self.background.remove(index);
                self.make_active(target);
            }
            self.reconcile_tabs(workspace, &state)?;
        }
        let index = self
            .background
            .iter()
            .position(|tab| tab.page.page_id == page_id)
            .ok_or_else(unknown_tab)?;
        let worker_tab = self.background[index].worker_tab;
        let state = self.tab_frame(&WorkerHostRequest::TabClose { tab: worker_tab })?;
        if let Some(index) = self
            .background
            .iter()
            .position(|tab| tab.worker_tab == worker_tab)
        {
            let tab = self.background.remove(index);
            let _ = self.pages.close_page(&tab.page.page_id);
            self.takeover.page_closed(&tab.page.page_id);
        }
        self.reconcile_tabs(workspace, &state)
    }

    /// SG-000135 OB-01: the broker session this browser serves; the
    /// takeover gate claims its pages for that session.
    pub fn set_task(&mut self, task: &str) {
        self.takeover.set_task(task);
    }

    /// SG-000135 OB-04: the persistent profile this browser runs in; every
    /// prompt it asks names it.
    pub fn set_profile(&mut self, name: &str) {
        self.profile_label = Some(name.to_owned());
    }

    /// SG-000135 OB-04: `prompt` with the persistent profile named, as the
    /// first preview line and (for a prompt whose summary is not a shown
    /// value) in the summary. An ephemeral browser's prompt is unchanged.
    fn with_profile(&self, prompt: ApprovalPrompt, in_summary: bool) -> ApprovalPrompt {
        profile_prompt(self.profile_label.as_deref(), prompt, in_summary)
    }

    /// SG-000135 OB-01: the MCP client the broker session belongs to; the
    /// takeover gate keeps its uncertain consequential actions per client
    /// too.
    pub fn set_client(&mut self, client: &str) {
        self.takeover.set_client(client);
    }

    /// SG-000135 OB-07: every page of this browser goes through the
    /// takeover gate, whatever the build's switch (browser_full broker
    /// sessions; `browser_structured` keeps the switch). Called before any
    /// page is opened.
    pub fn enable_takeover_gate(&mut self) {
        self.takeover.enable();
    }

    /// SG-000135 OB-06: a Visible session's window is watched for a
    /// person's input (the engine's windows are this browser host's
    /// descendants). Called after `enable_takeover_gate`, before any page
    /// opens.
    ///
    /// # Errors
    /// `PROVIDER_UNAVAILABLE` when no input source exists here; the caller
    /// must then not run the Visible session.
    pub fn watch_visible_window(&mut self) -> Result<(), ProviderError> {
        let probe = self
            .supervisor
            .worker_host()
            .and_then(|host| host.job_handle())
            .map(crate::human_input::for_job);
        self.takeover.watch_visible_window(probe)
    }

    /// SG-000135 OB-05 (FA-J): the peak memory the session's browser family
    /// (host, worker runtime and engine, all in one job) has committed, as
    /// the job reports it; `None` when it cannot be asked. Read-only.
    pub fn peak_memory_bytes(&mut self) -> Option<u64> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::{
            JobObjectExtendedLimitInformation, QueryInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        };
        let job = self.supervisor.worker_host()?.job_handle()?;
        // SAFETY: a plain-data structure, valid when zeroed.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        let mut returned = 0u32;
        // SAFETY: a valid job handle, an out-buffer of exactly the class's
        // size, and an out-pointer to a local.
        let ok = unsafe {
            QueryInformationJobObject(
                job.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
                JobObjectExtendedLimitInformation,
                (&mut info as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                &mut returned,
            )
        };
        (ok != 0).then_some(info.PeakJobMemoryUsed as u64)
    }

    /// SG-000135 OB-06: refuse to close the session while a person holds
    /// its window (`HUMAN_TAKEOVER`); an emergency stop, the end of the MCP
    /// session and orceld's own shutdown still end it.
    pub fn check_not_held(&mut self) -> Result<(), ProviderError> {
        self.takeover.hold_session()
    }

    /// SG-000135 OB-06: where a person's input comes from (`visible_window`
    /// or `none`), for the session status.
    pub fn takeover_input_source(&self) -> &'static str {
        self.takeover.input_source()
    }

    /// SG-000135 OB-07: the status of the active page's navigation that
    /// just committed `url`.
    fn note_status(&mut self, url: &str, status: u16) {
        if let Some(page) = &self.page {
            self.page_status
                .insert(page.page_id.clone(), (url.to_owned(), status));
        }
    }

    /// SG-000135 OB-07: run the engine's read-only challenge detector on
    /// the active page and tell the takeover gate what it saw (see
    /// `challenge_step`). A page that shows a sign-in, one-time code,
    /// passkey or CAPTCHA check waits for the person; a page that waits and
    /// no longer shows one is reported gone (the gate then holds it for the
    /// quiet period and asks for a fresh observation). While a page waits,
    /// the detector runs at most once per `CHALLENGE_RECHECK`. A page
    /// between documents (a navigation in flight) is checked again later; a
    /// detector that cannot answer otherwise holds the page (fail closed:
    /// "Needs you").
    ///
    /// This is orceld's own read, never the agent's: it bypasses the gate's
    /// read refusal because nothing of the page crosses (a closed kind and
    /// closed signal names), and it never types, clicks, submits or solves.
    /// Nothing happens with the gate off or without a committed document.
    pub fn check_challenge(&mut self) {
        self.run_challenge_check(false);
    }

    /// As [`Self::check_challenge`], but at most once per
    /// `CHALLENGE_RECHECK` for the active page whether or not it waits: for
    /// status reads, which an agent may repeat as fast as it likes.
    pub fn check_challenge_throttled(&mut self) {
        self.run_challenge_check(true);
    }

    fn run_challenge_check(&mut self, throttled: bool) {
        if !self.takeover.is_on() || self.lifetime.is_none() || self.page_url.is_none() {
            return;
        }
        let Some(page_id) = self.page.as_ref().map(|page| page.page_id.clone()) else {
            return;
        };
        let waiting = self.takeover.awaiting(&page_id).is_some();
        let recent = self
            .last_challenge_check
            .as_ref()
            .is_some_and(|(page, at)| *page == page_id && at.elapsed() < CHALLENGE_RECHECK);
        if recent && (waiting || throttled) {
            return;
        }
        let status = match (self.page_status.get(&page_id), self.page_url.as_deref()) {
            (Some((url, status)), Some(now)) if url == now => *status,
            _ => 0,
        };
        let busy = refused(NAVIGATION_IN_FLIGHT).message;
        let detection = match self.request(&WorkerHostRequest::DetectChallenge { status }) {
            Ok(WorkerHostReply::Challenge { kind, signals, .. }) => match challenge_kind(&kind) {
                Some(kind) => Detection::Seen(kind, signals),
                None => Detection::Clear,
            },
            Err(error) if error.message == busy => Detection::Busy,
            Ok(_) | Err(_) => Detection::Unavailable,
        };
        // A lost host closed the page: nothing is left to hold.
        if self.page.as_ref().map(|page| page.page_id.as_str()) != Some(page_id.as_str()) {
            return;
        }
        let checked = std::time::Instant::now();
        self.last_challenge_check = Some((page_id.clone(), checked));
        let reported = self.challenges.get(&page_id).is_some_and(|note| note.gone);
        match challenge_step(detection, waiting, reported) {
            ChallengeStep::Hold(kind, signals) => {
                if kind == ChallengeKind::SignIn {
                    self.sign_in_seen = true;
                }
                if self.takeover.challenge_detected(&page_id, kind) {
                    self.challenges.insert(
                        page_id,
                        ChallengeNote {
                            signals,
                            gone: false,
                        },
                    );
                }
            }
            ChallengeStep::ReportGone => {
                if self.takeover.challenge_gone(&page_id) {
                    if let Some(note) = self.challenges.get_mut(&page_id) {
                        note.gone = true;
                    }
                }
            }
            ChallengeStep::Forget => {
                self.challenges.remove(&page_id);
            }
            ChallengeStep::StillGone | ChallengeStep::Later => {}
        }
    }

    /// SG-000135 OB-07b: a page URL as the agent may read it: every reply
    /// field that carries a page URL goes through here (the vault scan
    /// checks it). See `agent_url.rs`.
    pub fn agent_url(&self, url: &str) -> String {
        crate::agent_url::agent_url(url, self.sign_in_seen)
    }

    /// SG-000135 OB-07b: whether a page of this session was a sign-in page.
    pub fn sign_in_seen(&self) -> bool {
        self.sign_in_seen
    }

    /// SG-000135 OB-07: the pages that wait for the person now ("Needs
    /// you"), with what the detector saw: a closed kind and closed signal
    /// names, never page text. Notes of pages that no longer wait are
    /// dropped.
    pub fn needs_you(&mut self) -> Vec<NeedsYou> {
        let pages: Vec<String> = self.challenges.keys().cloned().collect();
        let mut out = Vec::new();
        for page_id in pages {
            match self.takeover.awaiting(&page_id) {
                Some(kind) => {
                    if let Some(note) = self.challenges.get(&page_id) {
                        out.push(NeedsYou {
                            page_id,
                            kind: challenge_name(kind),
                            signals: note.signals.clone(),
                            clearing: note.gone,
                        });
                    }
                }
                None => {
                    self.challenges.remove(&page_id);
                }
            }
        }
        out.sort_by(|a, b| a.page_id.cmp(&b.page_id));
        out
    }

    /// SG-000135 OB-07: the active page's takeover-gate state, by the
    /// design's name (None with the gate off or no page).
    pub fn page_state(&mut self) -> Option<&'static str> {
        let page_id = self.page.as_ref()?.page_id.clone();
        self.takeover.page_state(&page_id).map(|state| state.name())
    }

    fn require_lifetime(&self) -> Result<(), ProviderError> {
        if self.lifetime.is_none() {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "the live page has no document yet; navigate it first",
            ));
        }
        Ok(())
    }

    /// A bounded observation: identities and digests, and (SG-000122 slice
    /// A5) the untrusted names of main-frame form controls.
    pub fn observe(&mut self) -> Result<Vec<WireNode>, ProviderError> {
        match self.request(&WorkerHostRequest::Observe {})? {
            WorkerHostReply::Observed { nodes, .. } => {
                // SG-000122: the roles a form action may bind, from this
                // observation only.
                self.observed_roles.clear();
                let mut stack: Vec<&WireNode> = nodes.iter().collect();
                while let Some(node) = stack.pop() {
                    self.observed_roles
                        .insert(node.node_id.clone(), node.role.clone());
                    stack.extend(node.children.iter());
                }
                Ok(nodes)
            }
            _ => Err(ProviderError::new(
                FailureCode::InternalError,
                "unexpected browser host reply",
            )),
        }
    }

    /// The host's typed selection of the latest dated link.
    pub fn select_latest_dated_link(&mut self) -> Result<String, ProviderError> {
        match self.request(&WorkerHostRequest::SelectLatestDatedLink {})? {
            WorkerHostReply::Selected { node_id } => Ok(node_id),
            _ => Err(ProviderError::new(
                FailureCode::InternalError,
                "unexpected browser host reply",
            )),
        }
    }

    /// An approved, create-only download of an observed link into
    /// `folder` (the approved workspace destination) as `relative`.
    pub fn download(
        &mut self,
        workspace: &Workspace,
        approval: &impl ApprovalBroker,
        node_id: &str,
        folder: &Path,
        relative: &str,
    ) -> Result<LiveDownload, ProviderError> {
        let page_id = self
            .page
            .as_ref()
            .map(|page| page.page_id.clone())
            .unwrap_or_default();
        self.gate_write(
            &page_id,
            "download",
            &format!("{node_id}\u{0}{relative}"),
            ActionClass::Consequential,
        )?;
        let folder = folder.to_string_lossy().into_owned();
        let folder_for_record = folder.clone();
        let (token, digest, binding, target) = self.ask(
            workspace,
            approval,
            &BindAction::Download {
                node_id: node_id.into(),
                role: "link".into(),
                folder: folder.clone(),
                relative: relative.into(),
            },
            "download from isolated browser page",
        )?;
        // B1: nothing is journaled or spent while a person holds the page,
        // nor for a download of the same link to the same name whose
        // earlier outcome is unknown.
        self.gate_rekey(
            "download",
            &format!(
                "{}\u{0}{relative}",
                crate::takeover_gate::link_identity(&target)
            ),
        )?;
        self.gate_confirm()?;
        let record_id = token.record_id.clone();
        // The intent is durable before the approval is spent: if orceld
        // dies anywhere after this, a restart finds it and reconciles the
        // destination. If it cannot be written, nothing is spent or sent.
        // Opening lines leave room for the line that closes them.
        journal_append_opening(
            &self.intents,
            &JournalLine {
                folder: Some(PathBuf::from(&folder)),
                relative: Some(relative.into()),
                host_pid: Some(self.host_pid),
                host_started: Some(self.host_started),
                ..JournalLine::event("pending", &record_id)
            },
        )?;
        if let Err(error) = Self::consume(workspace, approval, &token, digest) {
            // Never spent, never sent. If even this line is lost, a restart
            // reports the (untouched) destination, which is still safe.
            let _ = journal_append(&self.intents, &JournalLine::event("abandoned", &record_id));
            return Err(error);
        }
        self.pending_download = Some(DownloadIntent {
            record_id: record_id.clone(),
            folder: PathBuf::from(&folder),
            relative: relative.into(),
        });
        let reply = self.dispatch(
            &record_id,
            &WorkerHostRequest::Download {
                node_id: node_id.into(),
                role: "link".into(),
                folder,
                relative: relative.into(),
                record_id: record_id.clone(),
                binding,
            },
        );
        self.gate_finish(&record_id);
        // A reply, refusal or success, settles it; only a lost one stays.
        // If the settled line cannot be written, a restart reports the
        // destination as present, unverified: never adopted, so still safe.
        if !matches!(self.outcomes.last(), Some(o) if o.outcome == DispatchOutcome::Lost) {
            self.pending_download = None;
            let _ = journal_append(&self.intents, &JournalLine::event("settled", &record_id));
        }
        // A download the host refused after dispatch may already have
        // followed the link (the worker clicks before it checks the bytes),
        // so the page may no longer be the one observed: the lifetime ends
        // rather than let the store disagree with it (judge, slice 3c). A
        // lost host was already ended; refusals before dispatch (a denial,
        // a failed consume) never reach here.
        if matches!(
            self.outcomes.last(),
            Some(o) if o.record_id == record_id
                && matches!(&o.outcome, DispatchOutcome::Refused(code) if code != GATE_REFUSED)
        ) {
            self.end_lifetime();
        }
        match reply? {
            WorkerHostReply::Downloaded {
                relative,
                sha256,
                bytes,
                source_url,
            } => {
                self.committed
                    .push(crate::document_parse::CommittedDownload::new(
                        record_id.clone(),
                        PathBuf::from(&folder_for_record),
                        relative.clone(),
                        sha256.clone(),
                        bytes,
                        source_url.clone(),
                    ));
                Ok(LiveDownload {
                    relative,
                    sha256,
                    bytes,
                    source_url,
                    record_id,
                })
            }
            _ => Err(ProviderError::new(
                FailureCode::InternalError,
                "unexpected browser host reply",
            )),
        }
    }

    /// WI-05: convert a download this lifetime committed to Markdown in the
    /// confined document parser, under its own approval
    /// (`document_parse::parse_download`). Any other record is refused
    /// before anything is read or asked.
    pub fn parse_download(
        &self,
        workspace: &Workspace,
        approval: &impl ApprovalBroker,
        record_id: &str,
    ) -> Result<serde_json::Value, ProviderError> {
        let download = self
            .committed
            .iter()
            .find(|download| download.record_id() == record_id)
            .ok_or_else(|| {
                ProviderError::new(
                    FailureCode::InvalidRequest,
                    "no download with that record was committed in this browser lifetime",
                )
            })?;
        crate::document_parse::parse_download(workspace, approval, download)
    }

    /// Whether the host still answers in step.
    pub fn is_usable(&mut self) -> bool {
        self.supervisor
            .worker_host()
            .is_some_and(|host| host.is_usable())
    }

    /// Shut the host family down; true when confirmed empty. The page is
    /// closed with the lifetime.
    pub fn shutdown(mut self) -> bool {
        // SG-000135 OB-08: the session's lease ends with it.
        if let Some(mut access) = self.full_access.take() {
            access.session_ended();
        }
        self.lifetime = None;
        self.close_page();
        self.supervisor.shutdown().unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ob06_only_a_prompt_a_person_answered_counts_as_answered() {
        use orcel_approval::ApprovalError;
        let error = |code, message: &str| -> Result<(), ApprovalError> {
            Err(ApprovalError {
                code,
                message: message.to_owned(),
            })
        };
        assert!(prompt_answered(&Ok::<(), ApprovalError>(())));
        assert!(prompt_answered(&error(
            FailureCode::ApprovalDenied,
            "local user denied the operation"
        )));
        assert!(!prompt_answered(&error(
            FailureCode::ApprovalDenied,
            orcel_approval::UNANSWERED_DENIAL
        )));
        assert!(!prompt_answered(&error(
            FailureCode::ApprovalDenied,
            &format!(
                "{}; the decision was not recorded: x",
                orcel_approval::UNANSWERED_DENIAL
            )
        )));
        assert!(!prompt_answered(&error(
            FailureCode::ApprovalUnavailable,
            "approval ledger is unavailable"
        )));
    }

    use super::*;

    /// B1: a form action's stable material names the field by its position,
    /// never the count of same-named fields, nor its node id.
    /// SG-000135 OB-07: a page between documents is checked again later,
    /// never held for that alone; a held page stays held; other detector
    /// failures hold the page; a disappearance is reported once.
    #[test]
    fn ob07_a_navigation_in_flight_is_checked_again_later_not_held() {
        assert_eq!(
            challenge_step(Detection::Busy, false, false),
            ChallengeStep::Later
        );
        assert_eq!(
            challenge_step(Detection::Busy, true, false),
            ChallengeStep::Later
        );
        assert_eq!(
            challenge_step(Detection::Busy, true, true),
            ChallengeStep::Later
        );
        assert_eq!(
            challenge_step(Detection::Unavailable, false, false),
            ChallengeStep::Hold(ChallengeKind::Other, vec![DETECTOR_UNAVAILABLE.to_owned()])
        );
        assert_eq!(
            challenge_step(
                Detection::Seen(ChallengeKind::Mfa, vec!["otp_field".into()]),
                false,
                false
            ),
            ChallengeStep::Hold(ChallengeKind::Mfa, vec!["otp_field".into()])
        );
        assert_eq!(
            challenge_step(Detection::Clear, false, false),
            ChallengeStep::Forget
        );
        assert_eq!(
            challenge_step(Detection::Clear, true, false),
            ChallengeStep::ReportGone
        );
        assert_eq!(
            challenge_step(Detection::Clear, true, true),
            ChallengeStep::StillGone
        );
        // The host's busy code is the one the live browser recognises.
        assert_eq!(
            refused(NAVIGATION_IN_FLIGHT).code,
            FailureCode::TargetStale,
            "a navigation in flight is never a held page"
        );
        assert_ne!(
            refused(NAVIGATION_IN_FLIGHT).message,
            refused("unavailable:actionfailed").message
        );
    }

    #[test]
    fn b1_form_material_keys_on_the_position_not_the_count() {
        let field = |count: usize| BoundForm {
            role: "textbox".into(),
            name: "Search".into(),
            name_cut: false,
            ordinal: Some(orcel_browser_host::worker_host::FieldOrdinal { position: 1, count }),
        };
        let enter = |node: &str| BindAction::PressEnter {
            node_id: node.into(),
            role: "textbox".into(),
        };
        assert_eq!(
            form_material(&enter("n7"), &field(2)),
            form_material(&enter("n42"), &field(3)),
            "an unrelated new field of the same name, and renumbered nodes, change nothing"
        );
        let second = BoundForm {
            ordinal: Some(orcel_browser_host::worker_host::FieldOrdinal {
                position: 2,
                count: 3,
            }),
            ..field(3)
        };
        assert_ne!(
            form_material(&enter("n7"), &field(3)),
            form_material(&enter("n7"), &second)
        );
    }

    #[test]
    fn reconciliation_reports_what_is_at_the_destination_and_nothing_else() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let folder =
            std::env::temp_dir().join(format!("orcel-reconcile-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(folder.join("sub")).unwrap();
        assert_eq!(
            reconcile_destination(&folder, "a.pdf").unwrap(),
            Reconciled::Absent
        );
        std::fs::write(folder.join("a.pdf"), b"%PDF-1.4").unwrap();
        assert_eq!(
            reconcile_destination(&folder, "a.pdf").unwrap(),
            Reconciled::PresentUnverified {
                sha256: sha256_hex("%PDF-1.4"),
                bytes: 8
            }
        );
        for bad in [
            "",
            "../a.pdf",
            "sub/../../a.pdf",
            "C:\\a.pdf",
            "/a.pdf",
            "a.pdf:stream",
            "a.pdf.",
            "a.pdf ",
            "NUL",
            "nul.pdf",
            "sub//a.pdf",
        ] {
            assert_eq!(
                reconcile_destination(&folder, bad).unwrap_err().code,
                FailureCode::InvalidRequest,
                "{bad}"
            );
        }
        // A directory at the name is refused, not reported.
        assert_eq!(
            reconcile_destination(&folder, "sub").unwrap_err().code,
            FailureCode::PostconditionFailed
        );
        // A junction on the way is not followed, even to a real file.
        std::fs::write(folder.join("sub").join("b.pdf"), b"%PDF-1.4").unwrap();
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(folder.join("via"))
            .arg(folder.join("sub"))
            .output()
            .expect("mklink");
        assert!(made.status.success(), "{made:?}");
        assert!(folder.join("via").join("b.pdf").is_file());
        assert_eq!(
            reconcile_destination(&folder, "via/b.pdf")
                .unwrap_err()
                .code,
            FailureCode::PostconditionFailed
        );
        assert_eq!(
            reconcile_destination(&folder, "via").unwrap_err().code,
            FailureCode::PostconditionFailed
        );
        // Nothing larger than a transfer is hashed or reported.
        let limit = orcel_browser_host::MAX_TRANSFER_BYTES;
        std::fs::write(folder.join("big.pdf"), vec![b' '; limit as usize + 1]).unwrap();
        assert_eq!(
            reconcile_destination(&folder, "big.pdf").unwrap_err().code,
            FailureCode::PostconditionFailed
        );
        std::fs::write(folder.join("big.pdf"), vec![b' '; limit as usize]).unwrap();
        assert!(matches!(
            reconcile_destination(&folder, "big.pdf").unwrap(),
            Reconciled::PresentUnverified { bytes, .. } if bytes == limit
        ));
        std::fs::remove_dir(folder.join("via")).unwrap();
        std::fs::remove_dir_all(&folder).unwrap();
    }

    fn hostless(pending: bool, host_ended: Option<bool>, folder: &Path) -> LiveBrowser {
        LiveBrowser {
            supervisor: Supervisor::new(),
            lifetime: None,
            lifetime_origin: None,
            page_workspace: None,
            page: None,
            pages: PageStore::load_or_create(folder.join("pages.jsonl")),
            intents: folder.join("intents.jsonl"),
            host_pid: 0,
            host_started: 0,
            recovered: Vec::new(),
            outcomes: Vec::new(),
            pending_download: pending.then(|| DownloadIntent {
                record_id: "r1".into(),
                folder: folder.to_path_buf(),
                relative: "a.pdf".into(),
            }),
            committed: Vec::new(),
            observed_roles: std::collections::HashMap::new(),
            host_ended,
            takeover: TakeoverGate::from_switch(),
            profile_label: None,
            gate_ticket: None,
            page_url: None,
            background: Vec::new(),
            active_tab: None,
            full_access: None,
            navigation_also: None,
            challenges: std::collections::HashMap::new(),
            sign_in_seen: false,
            page_status: std::collections::HashMap::new(),
            last_challenge_check: None,
            reply_timeout: None,
            after_consume: None,
        }
    }

    /// SG-000135 OB-03: orceld's tabs follow the worker's report: an
    /// admitted popup on the lifetime's site gets its own page (own id and
    /// generation), one on another site is never adopted, a tab that closed
    /// itself is closed for good, and the active page is the worker's
    /// active tab.
    /// SG-000135 OB-07b: once a page of the session was a sign-in page,
    /// every agent-facing URL loses its query and fragment values (a GET
    /// sign-in form puts the password in the query).
    #[test]
    fn ob07b_agent_urls_are_redacted_and_strict_after_a_sign_in() {
        let dir = scratch("ob07b-agent-url");
        let mut browser = hostless(false, None, &dir);
        let after_get_sign_in = "https://user:pw@fixture.test/home?user=ann&pw2=hunter2&lang=en";
        assert!(!browser.sign_in_seen());
        assert_eq!(
            browser.agent_url(after_get_sign_in),
            "https://fixture.test/home?user=ann&pw2=[redacted]&lang=en"
        );
        assert_eq!(
            browser.agent_url("https://fixture.test/a?password=hunter2"),
            "https://fixture.test/a?password=[redacted]"
        );
        browser.sign_in_seen = true;
        let shown = browser.agent_url(after_get_sign_in);
        assert_eq!(
            shown,
            "https://fixture.test/home?user=[redacted]&pw2=[redacted]&lang=[redacted]"
        );
        assert!(!shown.contains("hunter2") && !shown.contains("ann"));
    }

    #[test]
    fn ob03_tabs_follow_the_workers_report() {
        use orcel_browser_host::page_capture::{TabsState, WorkerTab};
        let dir = scratch("ob03-tabs");
        let workspace = Workspace {
            id: "default".into(),
            root: dir.clone(),
        };
        let mut browser = hostless(false, None, &dir);
        let opened = browser
            .pages
            .open_page("default", "live-host:0-0", POLICY_REVISION)
            .unwrap();
        let origin = orcel_provider_browser::parse_destination_url("https://fixture.test/a")
            .unwrap()
            .origin;
        let (page, _, _) = browser
            .pages
            .apply_navigation(&opened.page_id, "", opened.generation, &origin)
            .unwrap();
        browser.page = Some(page.clone());
        browser.page_workspace = Some("default".into());
        browser.page_url = Some("https://fixture.test/a?token=x".into());
        browser.lifetime = Some("l1".into());
        browser.lifetime_origin = Some(origin.clone());
        let tab = |tab: u32, url: &str| WorkerTab {
            tab,
            url: url.into(),
        };
        let state = TabsState::checked(
            1,
            vec![
                tab(1, "https://fixture.test/a?token=x"),
                tab(2, "https://fixture.test/popup"),
                tab(3, "https://other.test/x"),
                tab(4, "about:blank"),
            ],
        )
        .unwrap();
        browser.reconcile_tabs(&workspace, &state).unwrap();
        let views = browser.tab_views();
        assert_eq!(views.len(), 2, "{views:?}");
        assert!(views[0].active && views[0].page_id == page.page_id);
        assert!(!views[1].active && views[1].page_id != page.page_id);
        assert_eq!(views[1].url.as_deref(), Some("https://fixture.test/popup"));
        let popup = views[1].page_id.clone();
        // Listing again adopts nothing twice.
        browser.reconcile_tabs(&workspace, &state).unwrap();
        assert_eq!(browser.tab_views().len(), 2);
        // Tab 1 closed itself: its page is stale for good, tab 2 is active.
        let state = TabsState::checked(2, vec![tab(2, "https://fixture.test/popup")]).unwrap();
        browser.reconcile_tabs(&workspace, &state).unwrap();
        let views = browser.tab_views();
        assert_eq!(views.len(), 1);
        assert!(views[0].active && views[0].page_id == popup);
        assert!(browser
            .live_page(&workspace, &page.page_id, page.generation)
            .is_err());
        assert!(browser.background.is_empty());
        // Every tab gone: no page is left, and nothing is active.
        browser
            .reconcile_tabs(&workspace, &TabsState::checked(0, vec![]).unwrap())
            .unwrap();
        assert!(browser.page().is_none() && browser.tab_views().is_empty());
        // A page with no document yet closes without a host; an unknown tab
        // is refused.
        browser.lifetime = None;
        let blank = browser.open_page(&workspace).unwrap();
        assert_eq!(
            browser
                .tab_close(&workspace, "pg-0123456789abcdef0123456789abcdef")
                .unwrap_err()
                .code,
            FailureCode::TargetStale
        );
        assert!(browser
            .tab_close(&workspace, &blank.page_id)
            .unwrap()
            .is_empty());
        assert!(browser.page().is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    fn scratch(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "orcel-intents-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// WI-05: only a download this lifetime committed reaches the document
    /// parser, and an uninstalled parser fails before any approval.
    #[test]
    fn wi05_only_a_committed_download_is_handed_to_the_document_parser() {
        let folder = scratch("wi05-parse");
        std::fs::write(folder.join("a.pdf"), b"%PDF-1.4 committed").unwrap();
        let mut browser = hostless(false, Some(true), &folder);
        let workspace = Workspace {
            id: "default".into(),
            root: folder.clone(),
        };
        let approve = orcel_approval::test_support::FixedApprovalBroker(
            orcel_approval::ApprovalDecision::Approved,
        );
        let error = browser
            .parse_download(&workspace, &approve, "never-committed")
            .unwrap_err();
        assert_eq!(error.code, FailureCode::InvalidRequest, "{}", error.message);
        browser
            .committed
            .push(crate::document_parse::CommittedDownload::new(
                "r1",
                folder.clone(),
                "a.pdf",
                orcel_provider_process::contained::sha256_hex(b"%PDF-1.4 committed"),
                18,
                "https://example.test/a.pdf",
            ));
        // No helper or parser is installed beside the test binary.
        let error = browser
            .parse_download(&workspace, &approve, "r1")
            .unwrap_err();
        assert_eq!(
            error.code,
            FailureCode::ProviderUnavailable,
            "{}",
            error.message
        );
        let _ = std::fs::remove_dir_all(folder);
    }

    fn pending(record_id: &str, folder: &Path, relative: &str, pid: u32, started: u64) -> String {
        serde_json::to_string(&JournalLine {
            folder: Some(folder.to_path_buf()),
            relative: Some(relative.into()),
            host_pid: Some(pid),
            host_started: Some(started),
            ..JournalLine::event("pending", record_id)
        })
        .unwrap()
    }

    fn event(event: &str, record_id: &str) -> String {
        serde_json::to_string(&JournalLine::event(event, record_id)).unwrap()
    }

    /// The creation time of a process that runs now.
    fn running(pid: u32) -> u64 {
        match liveness(pid) {
            Liveness::Running(started) => Some(started),
            _ => None,
        }
        .expect("a running process")
    }

    #[test]
    fn the_journal_keeps_open_only_unsettled_intents_and_fails_closed() {
        let dir = scratch("fold");
        let journal = dir.join("intents.jsonl");
        assert!(journal_open_intents(&journal).unwrap().is_empty());
        let body = [
            pending("r1", &dir, "a.pdf", 1, 2),
            pending("r2", &dir, "b.pdf", 1, 2),
            pending("r3", &dir, "c.pdf", 1, 2),
            pending("r4", &dir, "d.pdf", 1, 2),
            event("settled", "r1"),
            event("abandoned", "r3"),
            event("reconciled", "r4"),
        ]
        .join("\n");
        // A torn final line (a crash mid-append) is skipped.
        std::fs::write(&journal, format!("{body}\n{{\"schema\":\"orcel-sg")).unwrap();
        let open = journal_open_intents(&journal).unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].intent.record_id, "r2");
        // The next run's append seals it rather than fusing with it, and
        // the sealed torn line is skipped mid-file too.
        journal_append(&journal, &JournalLine::event("settled", "r2")).unwrap();
        assert!(journal_open_intents(&journal).unwrap().is_empty());
        let sealed = std::fs::read_to_string(&journal).unwrap();
        assert!(sealed.contains("\"orcel-sg\n{"), "{sealed}");
        // A zero-filled tail (a power loss) is not a line, sealed or not.
        let mut zeroed = format!("{body}\n").into_bytes();
        zeroed.extend_from_slice(&[0u8; 16]);
        std::fs::write(&journal, &zeroed).unwrap();
        assert_eq!(journal_open_intents(&journal).unwrap().len(), 1);
        journal_append(&journal, &JournalLine::event("settled", "r2")).unwrap();
        assert!(journal_open_intents(&journal).unwrap().is_empty());
        // A torn prefix followed by zeros on the same line is still torn,
        // and the next append seals it.
        let mut torn_zeroed = format!("{body}\n{{\"schema\":\"orcel-sg").into_bytes();
        torn_zeroed.extend_from_slice(&[0u8; 16]);
        std::fs::write(&journal, &torn_zeroed).unwrap();
        assert_eq!(journal_open_intents(&journal).unwrap().len(), 1);
        journal_append(&journal, &JournalLine::event("settled", "r2")).unwrap();
        assert!(journal_open_intents(&journal).unwrap().is_empty());
        // A zero byte inside an otherwise complete line is corruption.
        let mut inner_zero = format!("{body}\n").into_bytes();
        inner_zero.extend_from_slice(b"{\"schema\":\0}\n");
        std::fs::write(&journal, &inner_zero).unwrap();
        assert_eq!(
            journal_open_intents(&journal).unwrap_err().code,
            FailureCode::ProviderUnavailable
        );
        // A torn line that split a multi-byte path character is still torn.
        let torn = pending("r7", &dir.join("bericht-\u{e4}"), "a.pdf", 1, 2);
        let cut = torn.find('\u{e4}').unwrap() + 1;
        let mut bytes = format!("{body}\n").into_bytes();
        bytes.extend_from_slice(&torn.as_bytes()[..cut]);
        std::fs::write(&journal, &bytes).unwrap();
        assert_eq!(journal_open_intents(&journal).unwrap().len(), 1);
        assert_eq!(open[0].intent.relative, "b.pdf");
        assert_eq!((open[0].host_pid, open[0].host_started), (1, 2));
        // Anything else unreadable fails closed: a bad line mid-file, a
        // complete bad final line, a pending without its destination, an
        // unknown event or schema.
        let no_destination = event("pending", "r5");
        let other_schema = pending("r6", &dir, "e.pdf", 1, 2).replace(INTENT_SCHEMA, "other/1");
        for bad in [
            format!("garbage\n{body}\n"),
            format!("{body}\ngarbage\n"),
            format!("{body}\n{no_destination}\n"),
            format!("{body}\n{}\n", event("forgotten", "r2")),
            format!("{body}\n{other_schema}\n"),
        ] {
            std::fs::write(&journal, bad).unwrap();
            assert_eq!(
                journal_open_intents(&journal).unwrap_err().code,
                FailureCode::ProviderUnavailable
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn liveness_tells_a_running_process_from_an_exited_one() {
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "pause"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let started = running(child.id());
        assert!(host_may_run(child.id(), started));
        // Another creation time at the same pid is another process.
        assert!(!host_may_run(child.id(), started + 1));
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(liveness(child.id()), Liveness::Gone);
        assert!(!host_may_run(child.id(), started));
        let own = running(std::process::id());
        assert!(host_may_run(std::process::id(), own));
    }

    #[test]
    fn recovery_reconciles_once_and_only_intents_whose_host_is_gone() {
        let dir = scratch("recover");
        let folder = dir.join("approved");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("left.pdf"), b"%PDF-1.4").unwrap();
        let journal = dir.join("intents.jsonl");
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "pause"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let dead_started = running(child.id());
        let dead = child.id();
        child.kill().unwrap();
        child.wait().unwrap();
        let own = running(std::process::id());
        let me = std::process::id();
        std::fs::write(
            &journal,
            [
                // Its host died after committing: present, unverified.
                pending("gone-present", &folder, "left.pdf", dead, dead_started),
                // Its host died before acting: absent.
                pending("gone-absent", &folder, "none.pdf", dead, dead_started),
                // Its pid now names another process: that host is gone.
                pending("reused", &folder, "none.pdf", me, own + 1),
                // Its host runs (another orceld's lifetime): untouched.
                pending("live", &folder, "left.pdf", me, own),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        let recovered = recover_intents(&journal).unwrap();
        let found: Vec<(&str, &Result<Reconciled, ProviderError>)> = recovered
            .iter()
            .map(|(intent, found)| (intent.record_id.as_str(), found))
            .collect();
        assert_eq!(found.len(), 3, "{found:?}");
        assert_eq!(found[0].0, "gone-present");
        assert_eq!(
            found[0].1.as_ref().unwrap(),
            &Reconciled::PresentUnverified {
                sha256: sha256_hex("%PDF-1.4"),
                bytes: 8
            }
        );
        assert_eq!(found[1].0, "gone-absent");
        assert_eq!(found[1].1.as_ref().ok(), Some(&Reconciled::Absent));
        assert_eq!(found[2].0, "reused");
        assert_eq!(found[2].1.as_ref().ok(), Some(&Reconciled::Absent));
        // Each is reported once; the live one stays open.
        let open = journal_open_intents(&journal).unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].intent.record_id, "live");
        assert!(recover_intents(&journal).unwrap().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reconciliation_waits_for_a_confirmed_end_of_the_host() {
        let folder =
            std::env::temp_dir().join(format!("orcel-reconcile-gate-{}", std::process::id()));
        assert!(hostless(false, Some(true), &folder).reconcile().is_none());
        // Running, or ended without confirmation: refused, and the intent
        // is kept (never silently dropped).
        for ended in [None, Some(false)] {
            let mut browser = hostless(true, ended, &folder);
            let refused = browser.reconcile().expect("pending").unwrap_err();
            assert_eq!(refused.code, FailureCode::ProviderUnavailable);
            assert!(browser.pending_download.is_some(), "{ended:?}");
        }
        let mut browser = hostless(true, Some(true), &folder);
        let (intent, found) = browser.reconcile().expect("pending").expect("reconciled");
        assert_eq!(intent.record_id, "r1");
        assert_eq!(found, Reconciled::Absent);
        assert!(browser.reconcile().is_none());
        // The report is journaled, so a restart does not repeat it.
        let journal = std::fs::read_to_string(folder.join("intents.jsonl")).unwrap();
        assert!(journal.contains("\"reconciled\""), "{journal}");
        let _ = std::fs::remove_dir_all(&folder);
    }

    #[test]
    fn a_dispatch_without_a_host_is_recorded_lost() {
        let folder = std::env::temp_dir();
        let mut browser = hostless(false, None, &folder);
        let error = browser
            .dispatch("r9", &WorkerHostRequest::Observe {})
            .unwrap_err();
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
        assert_eq!(
            browser.outcomes(),
            &[ApprovalOutcome {
                record_id: "r9".into(),
                outcome: DispatchOutcome::Lost,
                lease_id: None,
                lease_epoch: None,
            }]
        );
        // No host existed, so its end is (trivially) confirmed.
        assert_eq!(browser.host_ended(), Some(true));
    }

    #[test]
    fn broken_pipes_and_platform_faults_are_the_provider_unavailable() {
        use orcel_browser_host::HostError;
        let io = HostError::Io(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        assert_eq!(host_error(io).code, FailureCode::ProviderUnavailable);
        let platform = HostError::Platform("job".into());
        assert_eq!(host_error(platform).code, FailureCode::ProviderUnavailable);
        let invalid = HostError::Invalid("x".into());
        assert_eq!(host_error(invalid).code, FailureCode::InvalidRequest);
    }

    #[test]
    fn host_refusals_map_onto_closed_failure_codes() {
        for (code, expected) in [
            ("binding_mismatch", FailureCode::TargetStale),
            ("no_lifetime", FailureCode::TargetStale),
            ("approval_replay", FailureCode::ApprovalDenied),
            ("invalid", FailureCode::InvalidRequest),
            ("download", FailureCode::PostconditionFailed),
            ("unavailable:timedout", FailureCode::ProcessTimeout),
            ("unavailable:targetstale", FailureCode::TargetStale),
            ("unavailable:targetoccluded", FailureCode::TargetStale),
            ("unavailable:textlimitreached", FailureCode::OutputLimit),
            (
                "unavailable:submissionrefused",
                FailureCode::CapabilityDenied,
            ),
            (
                "unavailable:managedpolicy",
                FailureCode::ProviderUnavailable,
            ),
            ("anything else", FailureCode::InternalError),
        ] {
            assert_eq!(failure_for(code), expected, "{code}");
        }
    }

    fn page(page_id: &str, generation: u64, origin: &str) -> PageRecord {
        PageRecord {
            page_id: page_id.into(),
            workspace_id: "w".into(),
            profile_identity: "live-lifetime:l1".into(),
            current_origin: origin.into(),
            generation,
            state: PageState::Open,
            policy_revision: POLICY_REVISION.into(),
        }
    }

    #[test]
    fn the_approval_digest_covers_both_halves() {
        let action = BindAction::Navigate {
            url: "https://fixture.test/".into(),
        };
        let fresh = page("page-1", 0, "");
        let base = approval_digest("w", "l1", &fresh, &action, None, "h1");
        for other in [
            approval_digest("v", "l1", &fresh, &action, None, "h1"),
            approval_digest("w", "l2", &fresh, &action, None, "h1"),
            approval_digest("w", "l1", &fresh, &action, None, "h2"),
            // The page store's half: another page, generation or origin.
            approval_digest("w", "l1", &page("page-2", 0, ""), &action, None, "h1"),
            approval_digest("w", "l1", &page("page-1", 1, ""), &action, None, "h1"),
            approval_digest(
                "w",
                "l1",
                &page("page-1", 0, "https://fixture.test:443"),
                &action,
                None,
                "h1",
            ),
            approval_digest(
                "w",
                "l1",
                &fresh,
                &BindAction::Navigate {
                    url: "https://fixture.test/x".into(),
                },
                None,
                "h1",
            ),
        ] {
            assert_ne!(base, other);
        }
        assert_eq!(base.len(), 64);
        // Fixed vector, computed independently (Python sha256) over the
        // documented framing (version 3: a `-` line where a form action's
        // field facts go), with the live policy revision sg-000040-v1.
        assert_eq!(
            base,
            "94364788a9592592fd82c79a94199b2b82cbb9a13448d48e7916ba8a34dd7232"
        );
    }

    fn fill(value: &str) -> BindAction {
        BindAction::Fill {
            node_id: "d3-e7".into(),
            role: "textbox".into(),
            value: value.into(),
        }
    }

    fn field(name: &str, ordinal: Option<(usize, usize)>) -> BoundForm {
        let (bounded, name_cut) = orcel_contracts::prompt_display::bounded_field_name(name);
        BoundForm {
            role: "textbox".into(),
            name: bounded.into(),
            name_cut,
            ordinal: ordinal.map(|(position, count)| {
                orcel_browser_host::worker_host::FieldOrdinal { position, count }
            }),
        }
    }

    /// The dialog text every OS shows for `prompt`, one line each.
    fn shown(prompt: &ApprovalPrompt) -> Vec<String> {
        orcel_approval::soft_dialog_text(prompt)
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// The line the prompt shows right after its Target line.
    fn after_target(lines: &[String]) -> String {
        let at = lines
            .iter()
            .position(|line| line.starts_with("Target: "))
            .expect("a Target line");
        lines[at + 1].clone()
    }

    /// SG-000135 OB-04: a prompt in a persistent profile names it (first
    /// preview line, and in a navigation's summary); a form value's summary
    /// is never changed; an ephemeral prompt is unchanged; the preview bound
    /// holds.
    #[test]
    fn ob04_every_prompt_in_a_persistent_profile_names_it() -> Result<(), String> {
        let base = || {
            ApprovalPrompt::new(
                "default",
                "rev",
                "navigate isolated browser page",
                "https://fixture.test/",
                "lifetime=l target=t",
                "d",
            )
        };
        let plain = base();
        let same = profile_prompt(None, plain.clone(), true);
        assert_eq!(same, plain);
        let named = profile_prompt(Some("work"), base(), true);
        assert!(named.summary.ends_with(" profile=work"));
        let text = orcel_approval::soft_dialog_text(&named);
        assert!(
            text.contains("Orcel-managed browser profile work"),
            "{text}"
        );
        assert!(text.contains("may be signed in"), "{text}");
        let full = base().with_preview(orcel_approval::Preview::Content {
            lines: (0..orcel_approval::PREVIEW_LINES)
                .map(|n| ('>', format!("line {n}")))
                .collect(),
            more_lines: 0,
        });
        let value = profile_prompt(Some("work"), full, false);
        assert_eq!(
            value.summary, "lifetime=l target=t",
            "a shown value is untouched"
        );
        let Some(orcel_approval::Preview::Content { lines, more_lines }) = &value.preview else {
            return Err(format!("not a content preview: {:?}", value.preview));
        };
        assert_eq!(lines.len(), orcel_approval::PREVIEW_LINES);
        assert!(lines
            .first()
            .is_some_and(|(_, line)| line.contains("profile work")));
        assert_eq!(*more_lines, 1);
        Ok(())
    }

    /// SG-000122 slice A2: a fill prompt shows exactly the bound value at
    /// the bound: every character as itself, each backslash doubled, nothing
    /// changed, cut or omitted; and the value is the approval's.
    #[test]
    fn sg122_a_fill_prompt_shows_exactly_the_bound_value_at_the_bound() {
        use orcel_contracts::prompt_display::MAX_SUMMARY_CHARS;
        // 100 backslashes count 200; the rest fills the bound exactly.
        let value = format!(
            "{}{}Zoë 日本 e\u{301}\u{302}",
            "\\".repeat(100),
            "a".repeat(MAX_SUMMARY_CHARS - 200 - 10)
        );
        assert_eq!(
            orcel_contracts::prompt_display::shown_exactly(&value, MAX_SUMMARY_CHARS),
            Ok(MAX_SUMMARY_CHARS)
        );
        let prompt = form_prompt(
            "default",
            "https://fixture.test:443",
            &fill(&value),
            &field("Full name", None),
            "d",
            None,
        )
        .expect("a value at the bound is shown");
        assert_eq!(prompt.summary, value);
        let lines = shown(&prompt);
        let line = after_target(&lines);
        assert_eq!(line, value.replace('\\', "\\\\"));
        assert_eq!(line.chars().count(), MAX_SUMMARY_CHARS);
        assert!(!line.contains("not shown"));
        // An ordinary value and an empty one (which clears the field).
        for value in ["Ada Lovelace", "C:\\temp\\x", ""] {
            let prompt = form_prompt(
                "default",
                "https://fixture.test:443",
                &fill(value),
                &field("Full name", None),
                "d",
                None,
            )
            .unwrap();
            assert_eq!(after_target(&shown(&prompt)), value.replace('\\', "\\\\"));
        }
        // A select shows its option label the same way.
        let select = BindAction::Select {
            node_id: "d3-e8".into(),
            role: "combobox".into(),
            label: "Porto \\ Norte".into(),
        };
        let mut city = field("City", None);
        city.role = "combobox".into();
        let prompt = form_prompt(
            "default",
            "https://fixture.test:443",
            &select,
            &city,
            "d",
            None,
        )
        .unwrap();
        assert_eq!(after_target(&shown(&prompt)), "Porto \\\\ Norte");
    }

    /// SG-000122 slice A2: one displayed character past the bound, and each
    /// character class the prompt would escape, is refused before any prompt
    /// exists; never cut, never shown altered.
    #[test]
    fn sg122_a_value_past_the_bound_or_with_an_escaped_character_gets_no_prompt() {
        use orcel_contracts::prompt_display::MAX_SUMMARY_CHARS;
        let ask = |value: &str| {
            form_prompt(
                "default",
                "https://fixture.test:443",
                &fill(value),
                &field("Full name", None),
                "d",
                None,
            )
        };
        let past = [
            "a".repeat(MAX_SUMMARY_CHARS + 1),
            format!("{}a", "\\".repeat(MAX_SUMMARY_CHARS / 2)),
            format!("{}\\", "a".repeat(MAX_SUMMARY_CHARS - 1)),
        ];
        for value in &past {
            assert_eq!(ask(value).unwrap_err().code, FailureCode::InvalidRequest);
        }
        // One of each escaped class: C0 and C1 controls, line and paragraph
        // separators, bidi embeddings, overrides, isolates and marks, format
        // and zero-width, default-ignorable, variation selectors, tags,
        // interlinear annotations, fillers and blank-looking spaces, and a
        // third combining mark in a row.
        for ch in [
            '\u{0}',
            '\u{9}',
            '\u{a}',
            '\u{d}',
            '\u{1b}',
            '\u{7f}',
            '\u{85}',
            '\u{9f}',
            '\u{2028}',
            '\u{2029}',
            '\u{202a}',
            '\u{202e}',
            '\u{2066}',
            '\u{2069}',
            '\u{200e}',
            '\u{200f}',
            '\u{061c}',
            '\u{200b}',
            '\u{200d}',
            '\u{2060}',
            '\u{2064}',
            '\u{206f}',
            '\u{feff}',
            '\u{00ad}',
            '\u{034f}',
            '\u{17b4}',
            '\u{180b}',
            '\u{fe00}',
            '\u{e0100}',
            '\u{1bca0}',
            '\u{13430}',
            '\u{1d173}',
            '\u{fff9}',
            '\u{e0001}',
            '\u{e007f}',
            '\u{115f}',
            '\u{1160}',
            '\u{3164}',
            '\u{ffa0}',
            '\u{00a0}',
            '\u{1680}',
            '\u{2000}',
            '\u{200a}',
            '\u{202f}',
            '\u{205f}',
            '\u{2800}',
            '\u{3000}',
        ] {
            let refused = ask(&format!("a{ch}b")).unwrap_err();
            assert_eq!(
                refused.code,
                FailureCode::InvalidRequest,
                "U+{:04X}",
                ch as u32
            );
        }
        assert!(ask("e\u{301}\u{302}\u{303}").is_err());
        // The value line has no label: a space it starts or ends with, two
        // in a row, or a value of spaces only (which would draw a blank
        // line) gets no prompt.
        for spaced in [" ", "    ", " Ada", "Ada ", "Ada  Lovelace", "Digest:  0"] {
            assert_eq!(
                ask(spaced).unwrap_err().code,
                FailureCode::InvalidRequest,
                "{spaced:?}"
            );
        }
        // The same rule for an option label.
        let mut city = field("City", None);
        city.role = "combobox".into();
        let select = BindAction::Select {
            node_id: "d3-e8".into(),
            role: "combobox".into(),
            label: "Porto\u{202e}".into(),
        };
        assert!(form_prompt("default", "t", &select, &city, "d", None).is_err());
    }

    /// SG-000122 slice A2: the prompt labels the field's role and name as
    /// page-supplied (a cut name says so), shows the ordinal only when it is
    /// shared, says that Enter may submit, and that values are not checked
    /// for secrets.
    #[test]
    fn sg122_the_prompt_labels_the_field_and_shows_a_shared_ordinal() {
        let lines = shown(
            &form_prompt(
                "default",
                "https://fixture.test:443",
                &fill("Ada"),
                &field("Full name", None),
                "d",
                None,
            )
            .unwrap(),
        );
        assert!(lines.contains(&"> │ Field role (page-supplied): textbox".to_owned()));
        assert!(lines.contains(&"> │ Field name (page-supplied): Full name".to_owned()));
        assert!(!lines.iter().any(|line| line.contains("Field position")));
        assert!(lines
            .iter()
            .any(|line| line.contains("not checked for secrets")));
        let lines = shown(
            &form_prompt(
                "default",
                "https://fixture.test:443",
                &fill("Ada"),
                &field("Email", Some((2, 3))),
                "d",
                None,
            )
            .unwrap(),
        );
        assert!(lines.contains(
            &"> │ Field position: 2 of 3 fields with this role and shown name, in page order"
                .to_owned()
        ));
        // A name past 256 bytes is labelled as cut; a hostile one is escaped.
        let lines = shown(
            &form_prompt(
                "default",
                "t",
                &fill("Ada"),
                &field(&"n".repeat(300), None),
                "d",
                None,
            )
            .unwrap(),
        );
        assert!(
            lines
                .iter()
                .any(|line| line
                    .starts_with("> │ Field name (page-supplied, longer than shown): nnn"))
        );
        let lines = shown(
            &form_prompt(
                "default",
                "t",
                &fill("Ada"),
                &field("Name\nApproval: STRONG", None),
                "d",
                None,
            )
            .unwrap(),
        );
        assert!(lines
            .contains(&"> │ Field name (page-supplied): Name\\u{a}Approval: STRONG".to_owned()));
        // Enter says what it may do.
        let enter = BindAction::PressEnter {
            node_id: "d3-e7".into(),
            role: "textbox".into(),
        };
        let lines =
            shown(&form_prompt("default", "t", &enter, &field("Search", None), "d", None).unwrap());
        assert!(lines
            .iter()
            .any(|line| line.contains("may submit or send what the page holds")));
        let check = BindAction::Check {
            node_id: "d3-e9".into(),
            role: "checkbox".into(),
            checked: false,
        };
        let mut terms = field("Terms", None);
        terms.role = "checkbox".into();
        let prompt = form_prompt("default", "t", &check, &terms, "d", None).unwrap();
        assert_eq!(prompt.summary, "set to unchecked");
    }

    /// SG-000120 RJ-02 for form actions: after an Enter whose outcome is
    /// unknown, the next request on that page is refused once (saying how to
    /// go on), and the request after it asks the person with the unknown
    /// named on the prompt's first preview line, the value line untouched.
    #[test]
    fn sg122_after_an_unknown_enter_the_next_prompt_names_it_first() {
        use crate::mutation_journal::{
            opaque, pending, surfaced_unknown, test_support, Sink, BROWSER_PAGE_TARGET,
        };
        let dir = scratch("sg122-unknown");
        let journal: &'static _ = Box::leak(Box::new(test_support::journal(
            dir.join("mutations.jsonl"),
            "sg122",
        )));
        test_support::restore(journal);
        let sink = Sink::Journal(journal);
        let workspace = Workspace {
            id: "default".into(),
            root: dir.clone(),
        };
        let request = |operation: &str| orcel_contracts::RequestEnvelope {
            version: orcel_contracts::INTERNAL_PROTOCOL_VERSION,
            request_id: "r".into(),
            client_session_id: "s".into(),
            workspace_id: "default".into(),
            capability: if operation == "fill" {
                "browser.dom".into()
            } else {
                "browser.form".into()
            },
            operation: operation.into(),
            target: None,
            arguments: serde_json::json!({}),
        };
        let target = format!("{BROWSER_PAGE_TARGET}pg-1");
        // An approved Enter whose reply was lost.
        let mut enter =
            pending(sink, opaque(&workspace, &request("enter"), "d1", &target)).expect("journaled");
        enter.dispatched().expect("dispatched");
        enter.settle(form_outcome(&DispatchOutcome::Lost));
        assert_eq!(surfaced_unknown(sink, "default", &target), None);
        // The next request is refused before any prompt, and says why.
        let refused = pending(sink, opaque(&workspace, &request("fill"), "d2", &target))
            .err()
            .expect("refused once");
        assert_eq!(refused.code, FailureCode::TargetStale);
        assert!(
            refused.message.contains("browser enter on live page pg-1")
                && refused.message.contains("observe the page"),
            "{}",
            refused.message
        );
        // The one after it: the person is told first.
        let earlier = surfaced_unknown(sink, "default", &target);
        assert_eq!(earlier.as_deref(), Some("enter"));
        let prompt = form_prompt(
            "default",
            "https://fixture.test:443",
            &fill("Ada"),
            &field("Full name", None),
            "d",
            earlier.as_deref(),
        )
        .unwrap();
        assert_eq!(prompt.summary, "Ada");
        let lines = shown(&prompt);
        let preview = lines
            .iter()
            .position(|line| line == "Preview:")
            .expect("a preview");
        assert_eq!(
            lines[preview + 1],
            "> │ UNKNOWN EARLIER OUTCOME: an approved enter on this page may or may not have happened"
        );
        assert!(pending(sink, opaque(&workspace, &request("fill"), "d3", &target)).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// SG-000122 slice A2: a field whose name looks like a credential is
    /// refused before any prompt (fill and Enter), as is a host binding for
    /// another role.
    #[test]
    fn sg122_a_credential_field_gets_no_prompt() {
        for name in ["Password", "PIN", "One-time code", "Card number", "CVV2"] {
            for action in [
                fill("x"),
                BindAction::PressEnter {
                    node_id: "d3-e7".into(),
                    role: "textbox".into(),
                },
            ] {
                let refused = form_prompt("default", "t", &action, &field(name, None), "d", None)
                    .unwrap_err();
                assert_eq!(refused.code, FailureCode::CapabilityDenied, "{name}");
            }
        }
        let mut other = field("Full name", None);
        other.role = "searchbox".into();
        assert_eq!(
            form_prompt("default", "t", &fill("x"), &other, "d", None)
                .unwrap_err()
                .code,
            FailureCode::TargetStale
        );
        // Not a form action at all.
        let navigate = BindAction::Navigate {
            url: "https://fixture.test/".into(),
        };
        assert!(form_prompt("default", "t", &navigate, &field("x", None), "d", None).is_err());
    }

    /// SG-000122 slice A4: `checked: false` on a radio is refused before any
    /// prompt (a radio can only be selected); a checkbox may still be
    /// cleared, and a radio still selected.
    #[test]
    fn sg122_unchecking_a_radio_gets_no_prompt() {
        let check = |role: &str, checked: bool| BindAction::Check {
            node_id: "d3-e9".into(),
            role: role.into(),
            checked,
        };
        let bound = |role: &str| {
            let mut form = field("Express delivery", None);
            form.role = role.into();
            form
        };
        let refused = form_prompt(
            "default",
            "t",
            &check("radio", false),
            &bound("radio"),
            "d",
            None,
        )
        .unwrap_err();
        assert_eq!(refused.code, FailureCode::InvalidRequest);
        assert_eq!(refused.message, orcel_browser_host::RADIO_UNCHECK_REFUSED);
        let selected = form_prompt(
            "default",
            "t",
            &check("radio", true),
            &bound("radio"),
            "d",
            None,
        )
        .unwrap();
        assert_eq!(selected.summary, "set to checked");
        let cleared = form_prompt(
            "default",
            "t",
            &check("checkbox", false),
            &bound("checkbox"),
            "d",
            None,
        )
        .unwrap();
        assert_eq!(cleared.summary, "set to unchecked");
    }

    /// SG-000122 slice A2: the approval digest binds the page, its
    /// generation, the element (node, role, name), the ordinal and the
    /// value, option, state or key; through the real broker, an approval
    /// replayed for any other one is refused, and an approval is single use
    /// and expires.
    #[test]
    fn sg122_an_approval_is_bound_single_use_and_never_replayed() {
        let fresh = page("page-1", 4, "https://fixture.test:443");
        let form = field("Email", Some((2, 3)));
        let digest = |page: &PageRecord, action: &BindAction, form: &BoundForm| {
            approval_digest("default", "l1", page, action, Some(form), "h1")
        };
        let base = digest(&fresh, &fill("Ada"), &form);
        let mut renamed = form.clone();
        renamed.name = "Email address".into();
        let mut cut = form.clone();
        cut.name_cut = true;
        let mut alone = form.clone();
        alone.ordinal = None;
        let mut moved = form.clone();
        moved.ordinal = Some(orcel_browser_host::worker_host::FieldOrdinal {
            position: 3,
            count: 3,
        });
        let mut role = form.clone();
        role.role = "searchbox".into();
        let others = [
            (
                "page",
                digest(
                    &page("page-2", 4, "https://fixture.test:443"),
                    &fill("Ada"),
                    &form,
                ),
            ),
            (
                "generation",
                digest(
                    &page("page-1", 5, "https://fixture.test:443"),
                    &fill("Ada"),
                    &form,
                ),
            ),
            ("value", digest(&fresh, &fill("Ada "), &form)),
            (
                "element",
                digest(
                    &fresh,
                    &BindAction::Fill {
                        node_id: "d3-e8".into(),
                        role: "textbox".into(),
                        value: "Ada".into(),
                    },
                    &form,
                ),
            ),
            ("name", digest(&fresh, &fill("Ada"), &renamed)),
            ("cut", digest(&fresh, &fill("Ada"), &cut)),
            ("ordinal", digest(&fresh, &fill("Ada"), &moved)),
            ("no ordinal", digest(&fresh, &fill("Ada"), &alone)),
            ("role", digest(&fresh, &fill("Ada"), &role)),
            (
                "key",
                digest(
                    &fresh,
                    &BindAction::PressEnter {
                        node_id: "d3-e7".into(),
                        role: "textbox".into(),
                    },
                    &form,
                ),
            ),
            (
                "host",
                approval_digest("default", "l1", &fresh, &fill("Ada"), Some(&form), "h2"),
            ),
            (
                "lifetime",
                approval_digest("default", "l2", &fresh, &fill("Ada"), Some(&form), "h1"),
            ),
            (
                "no facts",
                approval_digest("default", "l1", &fresh, &fill("Ada"), None, "h1"),
            ),
        ];
        let select = |label: &str| BindAction::Select {
            node_id: "d3-e8".into(),
            role: "combobox".into(),
            label: label.into(),
        };
        let check = |checked: bool| BindAction::Check {
            node_id: "d3-e9".into(),
            role: "checkbox".into(),
            checked,
        };
        assert_ne!(
            digest(&fresh, &select("Porto"), &form),
            digest(&fresh, &select("Lisbon"), &form)
        );
        assert_ne!(
            digest(&fresh, &check(true), &form),
            digest(&fresh, &check(false), &form)
        );
        for (what, other) in &others {
            assert_ne!(&base, other, "{what}");
        }
        // The real broker: the approval is minted for `base` only.
        let dir = scratch("sg122-broker");
        let broker = orcel_approval::LocalApprovalBroker::with_path_and_soft_decider(
            dir.join("approvals.json"),
            std::sync::Arc::new(orcel_approval::NoPresenceVerifier),
            std::sync::Arc::new(|_| orcel_approval::ApprovalDecision::Approved),
        );
        let prompt = form_prompt(
            "default",
            "https://fixture.test:443",
            &fill("Ada"),
            &form,
            &base,
            None,
        )
        .unwrap();
        let token = broker.request_token(&prompt).expect("approved");
        let expect = |digest: &str| ConsumeExpectation::new(digest, "default", POLICY_REVISION);
        for (what, other) in &others {
            assert!(
                broker.consume(&token, &expect(other), now_ms()).is_err(),
                "a replay on another {what} is refused"
            );
        }
        // Expired: refused, whatever the digest.
        assert!(broker
            .consume(&token, &expect(&base), now_ms() + 24 * 60 * 60 * 1000)
            .is_err());
        broker
            .consume(&token, &expect(&base), now_ms())
            .expect("the bound approval is consumed once");
        assert!(
            broker.consume(&token, &expect(&base), now_ms()).is_err(),
            "single use"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// SG-000120 RJ-02 for form actions: a refusal before the worker could
    /// act closes `failed`; a lost reply or an unconfirmed outcome closes
    /// `unknown` (never retried).
    #[test]
    fn sg122_a_form_action_closes_its_journal_intent_by_what_is_known() {
        assert_eq!(form_outcome(&DispatchOutcome::Executed), "done");
        for code in [
            "binding_mismatch",
            "approval_replay",
            "no_lifetime",
            "no_observation",
            "invalid",
            "unavailable:targetstale",
            "unavailable:targetoccluded",
            "unavailable:actionfailed",
            "unavailable:submissionrefused",
        ] {
            assert_eq!(
                form_outcome(&DispatchOutcome::Refused(code.into())),
                "failed",
                "{code}"
            );
        }
        for code in [
            "unavailable:outcomeunknown",
            "unavailable:timedout",
            "anything",
        ] {
            assert_eq!(
                form_outcome(&DispatchOutcome::Refused(code.into())),
                "unknown",
                "{code}"
            );
        }
        assert_eq!(form_outcome(&DispatchOutcome::Lost), "unknown");
    }

    /// SG-000122 slice A6: an Enter the host answers from its route record
    /// journals by what left. A submission refused before anything opened
    /// (SubmissionRefused) closes `failed`; one whose admitted document
    /// opened and then had a redirect off the origin refused (the request
    /// was delivered, the server may have acted) is OutcomeUnknown and
    /// closes `unknown`, never `failed`.
    #[test]
    fn sg122_an_enter_journals_unknown_once_its_document_opened() {
        use orcel_browser_host::worker_host::error_code;
        use orcel_browser_host::{HostError, UnavailableReason};
        let refused_before_open = error_code(&HostError::Unavailable(
            UnavailableReason::SubmissionRefused,
        ));
        let redirect_after_open =
            error_code(&HostError::Unavailable(UnavailableReason::OutcomeUnknown));
        assert_eq!(
            form_outcome(&DispatchOutcome::Refused(refused_before_open)),
            "failed"
        );
        assert_eq!(
            form_outcome(&DispatchOutcome::Refused(redirect_after_open)),
            "unknown"
        );
    }
}

/// Native tests: the real `orcel-browser-host --worker` binary (built with
/// the feature; its path from the test harness), the loopback fixture, and
/// the test approval broker, which mints and consumes like the ledger
/// (exact digest, scope and expiry). Run by `npm run browser-launcher:native`.
#[cfg(all(test, feature = "live-browser-test"))]
mod native {
    use super::*;
    use orcel_approval::test_support::FixedApprovalBroker;
    use orcel_approval::{
        ApprovalDecision, ApprovalError, ApprovedToken, LocalApprovalBroker, NoPresenceVerifier,
        RecordedDecision,
    };
    use std::io::BufRead;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    fn env_path(name: &str) -> PathBuf {
        let value = std::env::var_os(name);
        assert!(value.is_some(), "{name} is not set");
        PathBuf::from(value.unwrap_or_default())
    }

    struct Fixture {
        child: std::process::Child,
        spki: String,
    }

    impl Fixture {
        fn start() -> Self {
            let node = env_path("ORCEL_SG108_NODE");
            let main = env_path("ORCEL_SG108_WORKER_MAIN");
            let app = main.parent().and_then(Path::parent).expect("worker app");
            let mut child = std::process::Command::new(node)
                .arg(app.join("scripts").join("https-fixture.mjs"))
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit())
                .spawn()
                .expect("start the HTTPS fixture");
            let stdout = child.stdout.take().expect("fixture stdout");
            let (ready, spki) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                for line in std::io::BufReader::new(stdout)
                    .lines()
                    .map_while(Result::ok)
                {
                    if let Some(value) = line.strip_prefix("READY ") {
                        let _ = ready.send(value.to_owned());
                    }
                }
            });
            let spki = spki
                .recv_timeout(Duration::from_secs(30))
                .expect("fixture ready");
            Self { child, spki }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    struct Scene {
        root: PathBuf,
        approved: PathBuf,
        workspace: Workspace,
    }

    impl Scene {
        fn new(label: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let root = std::env::temp_dir().join(format!(
                "sg108-orceld-live-{label}-{}-{nanos}",
                std::process::id()
            ));
            let approved = root.join("approved");
            for dir in ["profiles", "staging", "state", "approved"] {
                std::fs::create_dir_all(root.join(dir)).expect("dirs");
            }
            Self {
                workspace: Workspace {
                    id: "ws-sg108-live".into(),
                    root: approved.clone(),
                },
                approved,
                root,
            }
        }

        fn browser(&self) -> LiveBrowser {
            LiveBrowser::start(
                &env_path("ORCEL_SG108_HOST_BINARY"),
                &WorkerHostLaunch {
                    node: Some(env_path("ORCEL_SG108_NODE")),
                    worker_main: Some(env_path("ORCEL_SG108_WORKER_MAIN")),
                    profile_root: self.root.join("profiles"),
                    temp_dir: self.root.join("staging"),
                    state_root: self.root.join("state"),
                    mode: orcel_browser_host::EngineMode::Shadow,
                    persistent_profile: None,
                },
                &self.state(),
            )
            .expect("supervise the worker-mode host")
        }

        fn state(&self) -> LiveState {
            LiveState {
                pages: self.root.join("state").join("pages.jsonl"),
                intents: self.root.join("state").join("intents.jsonl"),
            }
        }
    }

    impl Drop for Scene {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// Open the fixture lifetime; None when the host's real managed-policy
    /// precondition refused it (CI's runner has such a policy), which is
    /// then required to be exactly that refusal.
    fn open(browser: &mut LiveBrowser, scene: &Scene, fixture: &Fixture) -> Option<String> {
        let opened = browser.open_fixture(&scene.workspace, "fixture.test", &fixture.spki);
        if let Err(error) = &opened {
            if error.message.contains("unavailable:managedpolicy") {
                assert_eq!(error.code, FailureCode::ProviderUnavailable);
                println!("SG108-EVIDENCE orceld live: managed policy present; open refused typed");
                return None;
            }
        }
        Some(opened.expect("open refused"))
    }

    fn report(path: &str) -> Vec<u8> {
        format!(
            "%PDF-1.4\n% {path}\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"
        )
        .into_bytes()
    }

    /// A hook that kills the host (and its tree) and confirms the host
    /// process itself exited.
    fn kill_host() -> Box<dyn FnMut(u32)> {
        Box::new(|pid: u32| {
            use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
            use windows_sys::Win32::System::Threading::{
                OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
            };
            // SAFETY: a plain Win32 open of this test's host pid; the handle
            // pins the process object so the wait below observes this host.
            let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            assert_ne!(process, 0, "open the host process");
            // The tree kill may race children that exit on their own (its
            // exit status then reports them); what matters is the host died.
            let _ = std::process::Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/T", "/F"])
                .output()
                .expect("taskkill");
            // SAFETY: the handle opened above, still open.
            let waited = unsafe { WaitForSingleObject(process, 10_000) };
            // SAFETY: closing the handle opened above, once.
            unsafe { CloseHandle(process) };
            assert_eq!(waited, WAIT_OBJECT_0, "the host did not die");
        })
    }

    fn files(dir: &Path) -> usize {
        std::fs::read_dir(dir).map(|read| read.count()).unwrap_or(0)
    }

    #[test]
    #[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
    fn the_journey_runs_under_the_broker_and_commits_the_verified_report() {
        let fixture = Fixture::start();
        let scene = Scene::new("journey");
        let mut browser = scene.browser();
        if open(&mut browser, &scene, &fixture).is_none() {
            assert!(browser.shutdown());
            return;
        }
        // The real broker over its own ledger; only the SOFT consent (the
        // system dialog) is scripted, as approval.
        let ledger = scene.root.join("approvals.json");
        let approve = LocalApprovalBroker::with_path_and_soft_decider(
            &ledger,
            Arc::new(NoPresenceVerifier),
            Arc::new(|_| ApprovalDecision::Approved),
        );
        let opened = browser.page().expect("the lifetime's page").clone();
        assert_eq!((opened.generation, opened.current_origin.as_str()), (0, ""));
        let (url, status) = browser
            .navigate(&scene.workspace, &approve, "https://fixture.test/reports")
            .expect("approved navigation");
        assert_eq!(
            (url.as_str(), status),
            ("https://fixture.test/reports", 200)
        );
        // The page store followed the committed document.
        let page = browser.page().expect("page").clone();
        assert_eq!(page.page_id, opened.page_id);
        assert_eq!(page.generation, 1);
        assert_eq!(page.current_origin, "https://fixture.test:443");
        assert_eq!(page.state, PageState::Active);
        assert!(!browser.observe().expect("observe").is_empty());
        let latest = browser.select_latest_dated_link().expect("latest report");
        // An intent that cannot be journaled spends nothing and sends
        // nothing: the approval is left unconsumed.
        let journal = browser.intents.clone();
        browser.intents = scene.root.join("state");
        let unjournaled = browser
            .download(
                &scene.workspace,
                &approve,
                &latest,
                &scene.approved,
                "latest.pdf",
            )
            .expect_err("no journal");
        assert_eq!(unjournaled.code, FailureCode::ProviderUnavailable);
        assert_eq!(browser.outcomes().len(), 1, "a frame was sent");
        assert_eq!(files(&scene.approved), 0);
        let unspent = approve.history(10);
        assert_eq!(unspent.len(), 2, "{unspent:?}");
        assert_eq!(unspent.iter().filter(|record| !record.consumed).count(), 1);
        browser.intents = journal;
        let committed = browser
            .download(
                &scene.workspace,
                &approve,
                &latest,
                &scene.approved,
                "latest.pdf",
            )
            .expect("approved download");
        // The independent checker.
        let bytes = std::fs::read(scene.approved.join("latest.pdf")).expect("committed file");
        let expected = report("/reports/2026-09-30.pdf");
        assert_eq!(bytes, expected);
        assert_eq!(committed.sha256, sha256_bytes(&expected));
        assert_eq!(committed.bytes, expected.len() as u64);
        assert_eq!(
            committed.source_url,
            "https://fixture.test/reports/2026-09-30.pdf"
        );
        // The ledger recorded these approvals: the two carried out, each
        // consumed, and the one the journal refused, never consumed.
        let records: Vec<_> = approve
            .history(10)
            .into_iter()
            .filter(|record| record.consumed)
            .collect();
        assert_eq!(records.len(), 2, "{records:?}");
        assert!(records
            .iter()
            .all(|record| record.decision == RecordedDecision::Approved));
        let ids: Vec<&str> = browser
            .outcomes()
            .iter()
            .map(|o| o.record_id.as_str())
            .collect();
        assert!(records
            .iter()
            .all(|record| ids.contains(&record.id.as_str())));
        assert!(browser
            .outcomes()
            .iter()
            .all(|o| o.outcome == DispatchOutcome::Executed));
        // Reconciling the committed name reports exactly the committed file.
        assert_eq!(
            reconcile_destination(&scene.approved, "latest.pdf").expect("reconcile"),
            Reconciled::PresentUnverified {
                sha256: committed.sha256.clone(),
                bytes: committed.bytes
            }
        );
        assert!(
            browser.reconcile().is_none(),
            "no download was left pending"
        );
        // The journal holds the download's intent, settled, and nothing open.
        let download_record = &browser.outcomes().last().expect("outcome").record_id;
        let lines = std::fs::read_to_string(&scene.state().intents).expect("journal");
        let events: Vec<JournalLine> = lines
            .lines()
            .map(|line| serde_json::from_str(line).expect("line"))
            .collect();
        let mine: Vec<&str> = events
            .iter()
            .filter(|line| &line.record_id == download_record)
            .map(|line| line.event.as_str())
            .collect();
        assert_eq!(mine, ["pending", "settled"]);
        assert!(journal_open_intents(&scene.state().intents)
            .expect("journal")
            .is_empty());
        println!(
            "SG108-EVIDENCE orceld live journey: real-ledger approved navigation and download, page store bound, intent journaled and settled, sha256 {}",
            committed.sha256
        );
        assert!(browser.shutdown(), "the host family stayed");
        // The lifetime's page is closed with it, on disk.
        let stored = PageStore::load_or_create(scene.state().pages);
        assert_eq!(
            stored.get(&page.page_id).map(|page| page.state),
            Some(PageState::Closed)
        );
    }

    /// The node of `role` whose untrusted name (observation contract 2) is
    /// exactly `name` (else a marker id no host knows, which the next
    /// action refuses as stale: the sweep keeps panics out of this module).
    fn form_node(nodes: &[WireNode], role: &str, name: &str) -> String {
        let mut stack: Vec<&WireNode> = nodes.iter().collect();
        let mut found = None;
        while let Some(node) = stack.pop() {
            let named = node
                .untrusted_name
                .as_ref()
                .is_some_and(|shown| shown.text == name);
            if node.role == role && named {
                found = Some(node.node_id.clone());
                break;
            }
            stack.extend(node.children.iter());
        }
        found.unwrap_or_else(|| format!("no {role} named {name}"))
    }

    fn form_request(operation: &str) -> orcel_contracts::RequestEnvelope {
        orcel_contracts::RequestEnvelope {
            version: 1,
            request_id: format!("sg122-native-{operation}"),
            client_session_id: "sg122-native".into(),
            workspace_id: "ws-sg108-live".into(),
            capability: if operation == "fill" {
                "browser.dom"
            } else {
                "browser.form"
            }
            .into(),
            operation: operation.into(),
            target: None,
            arguments: serde_json::Value::Null,
        }
    }

    /// SG-000122 slice A6, the native run: on the controlled HTTPS fixture,
    /// orceld drives the worker-mode host through observe (form-control
    /// names), fill, select, check and an Enter that submits the form to its
    /// own origin, then waits for and verifies the result page; a stale
    /// generation is refused before any prompt, a form whose action leaves
    /// the origin is refused typed (journaled `failed`), and a form whose
    /// delivered same-origin POST redirects off the origin answers outcome
    /// unknown (journaled `unknown`). Every action is approved through
    /// the real broker over its own ledger; the person's SOFT consent at the
    /// Windows prompt is SCRIPTED here (approve, and record what the prompt
    /// showed). The founder-present run with real prompts is separate
    /// (docs/orcel/implementation-readiness/prep/SG-000122.md, "Founder-present
    /// run"), pending.
    #[test]
    #[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
    fn sg122_the_form_journey_runs_under_the_broker_with_recorded_decisions() {
        let fixture = Fixture::start();
        let scene = Scene::new("form");
        let mut browser = scene.browser();
        if open(&mut browser, &scene, &fixture).is_none() {
            assert!(browser.shutdown());
            return;
        }
        let ledger = scene.root.join("approvals.json");
        let prompts: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let seen = prompts.clone();
        // SCRIPTED consent: every prompt approved, its dialog text kept.
        let approve = LocalApprovalBroker::with_path_and_soft_decider(
            &ledger,
            Arc::new(NoPresenceVerifier),
            Arc::new(move |prompt: &ApprovalPrompt| {
                if let Ok(mut seen) = seen.lock() {
                    seen.push(orcel_approval::soft_dialog_text(prompt));
                }
                ApprovalDecision::Approved
            }),
        );
        let form_url = "https://fixture.test/enter-form";
        browser
            .navigate(&scene.workspace, &approve, form_url)
            .expect("approved navigation");
        let page = browser.page().expect("page").clone();
        assert_eq!(page.generation, 1);
        let nodes = browser.observe().expect("observe");
        let full_name = form_node(&nodes, "textbox", "Full name");
        let city = form_node(&nodes, "combobox", "City");
        let gift = form_node(&nodes, "checkbox", "Gift wrap");
        let email = form_node(&nodes, "textbox", "Email");
        let act = |browser: &mut LiveBrowser, generation: u64, action: BindAction| {
            let operation = match &action {
                BindAction::Fill { .. } => "fill",
                BindAction::Select { .. } => "select",
                BindAction::Check { .. } => "check",
                _ => "enter",
            };
            browser.form_action(
                &scene.workspace,
                &approve,
                &form_request(operation),
                &page.page_id,
                generation,
                action,
            )
        };
        for action in [
            BindAction::Fill {
                node_id: full_name.clone(),
                role: "textbox".into(),
                value: "Ada Lovelace".into(),
            },
            BindAction::Select {
                node_id: city.clone(),
                role: "combobox".into(),
                label: "Porto".into(),
            },
            BindAction::Check {
                node_id: gift.clone(),
                role: "checkbox".into(),
                checked: true,
            },
            BindAction::Fill {
                node_id: email.clone(),
                role: "textbox".into(),
                value: "ada@example.test".into(),
            },
        ] {
            let (url, _, navigation) = act(&mut browser, 1, action).expect("form action");
            assert_eq!((url.as_str(), navigation), (form_url, FormNavigation::None));
        }
        assert_eq!(browser.page().expect("page").generation, 1);
        // Enter submits the order form to its own origin: the page store
        // follows the committed document.
        let (url, enter_record, navigation) = act(
            &mut browser,
            1,
            BindAction::PressEnter {
                node_id: email.clone(),
                role: "textbox".into(),
            },
        )
        .expect("approved Enter");
        assert_eq!(url, "https://fixture.test/order");
        assert_eq!(navigation, FormNavigation::DocumentCommitted);
        let placed = browser.page().expect("page").clone();
        assert_eq!(placed.generation, 2);
        assert_eq!(placed.current_origin, "https://fixture.test:443");
        // The old generation is stale: refused before any prompt.
        let asked = prompts.lock().expect("prompts").len();
        let stale = act(
            &mut browser,
            1,
            BindAction::Fill {
                node_id: full_name.clone(),
                role: "textbox".into(),
                value: "Eve".into(),
            },
        )
        .expect_err("stale generation");
        assert_eq!(stale.code, FailureCode::TargetStale);
        assert_eq!(prompts.lock().expect("prompts").len(), asked);
        // Wait for, then verify, the result page (read-only, no approval).
        let summary = "Order placed for Ada Lovelace in Porto, gift wrap yes";
        assert!(browser
            .wait_text(&scene.workspace, &page.page_id, 2, summary, true, 5_000)
            .expect("wait"));
        let verified = browser
            .verify(
                &scene.workspace,
                &page.page_id,
                2,
                vec![
                    orcel_browser_host::Postcondition::UrlIs {
                        url: "https://fixture.test/order".into(),
                    },
                    orcel_browser_host::Postcondition::TextVisible {
                        text: summary.into(),
                    },
                ],
            )
            .expect("verify");
        assert!(verified.verified, "{:?}", verified.results);
        // A form whose action is another origin: refused typed at the route.
        browser
            .navigate(&scene.workspace, &approve, form_url)
            .expect("approved navigation");
        assert_eq!(browser.page().expect("page").generation, 3);
        let nodes = browser.observe().expect("observe");
        let coupon = form_node(&nodes, "textbox", "Coupon");
        act(
            &mut browser,
            3,
            BindAction::Fill {
                node_id: coupon.clone(),
                role: "textbox".into(),
                value: "SAVE10".into(),
            },
        )
        .expect("fill");
        let refused = act(
            &mut browser,
            3,
            BindAction::PressEnter {
                node_id: coupon,
                role: "textbox".into(),
            },
        )
        .expect_err("a submission off the origin");
        assert_eq!(refused.code, FailureCode::CapabilityDenied);
        assert!(
            refused.message.contains("unavailable:submissionrefused"),
            "{}",
            refused.message
        );
        // A form whose same-origin POST is admitted and delivered, then
        // redirected off the origin: the redirect is refused, but the
        // request left, so the outcome is unknown (journaled `unknown`).
        browser
            .navigate(&scene.workspace, &approve, form_url)
            .expect("approved navigation");
        let voucher_generation = browser.page().expect("page").generation;
        let nodes = browser.observe().expect("observe");
        let voucher = form_node(&nodes, "textbox", "Voucher");
        act(
            &mut browser,
            voucher_generation,
            BindAction::Fill {
                node_id: voucher.clone(),
                role: "textbox".into(),
                value: "V-1".into(),
            },
        )
        .expect("fill");
        let unknown = act(
            &mut browser,
            voucher_generation,
            BindAction::PressEnter {
                node_id: voucher,
                role: "textbox".into(),
            },
        )
        .expect_err("a delivered submission redirected off the origin");
        assert!(
            unknown.message.contains("unavailable:outcomeunknown"),
            "{}",
            unknown.message
        );
        // What the person was shown: the values and the option exactly, the
        // field names labelled page-supplied, and Enter's warning.
        let prompts = prompts.lock().expect("prompts").clone();
        assert_eq!(prompts.len(), 12, "three navigations, nine form actions");
        let enter_prompts: Vec<&String> = prompts
            .iter()
            .filter(|text| text.contains("press Enter"))
            .collect();
        assert_eq!(enter_prompts.len(), 3);
        assert!(enter_prompts.iter().all(|text| text.contains(
            "Enter may submit or send what the page holds, to the page's admitted origin"
        )));
        for shown in ["Ada Lovelace", "Porto", "ada@example.test", "SAVE10"] {
            assert!(
                prompts
                    .iter()
                    .any(|text| text.lines().any(|line| line == shown)),
                "{shown} was not shown on its own line"
            );
        }
        assert!(prompts
            .iter()
            .any(|text| text.contains("(page-supplied)") && text.contains("Gift wrap")));
        // The ledger recorded each decision, each consumed once; the host
        // executed every one but the refused and the unknown submission.
        let records = approve.history(20);
        assert_eq!(records.len(), 12, "{records:?}");
        assert!(records
            .iter()
            .all(|record| record.consumed && record.decision == RecordedDecision::Approved));
        let outcomes = browser.outcomes();
        assert!(outcomes
            .iter()
            .any(|o| o.record_id == enter_record && o.outcome == DispatchOutcome::Executed));
        // Each Enter's journal intent closes by what left: `failed` for the
        // submission refused before it opened, `unknown` for the delivered
        // one whose redirect was refused.
        let closed = |code: &str| -> Vec<&'static str> {
            outcomes
                .iter()
                .filter(|o| matches!(&o.outcome, DispatchOutcome::Refused(c) if c == code))
                .map(|o| form_outcome(&o.outcome))
                .collect()
        };
        assert_eq!(closed("unavailable:submissionrefused"), vec!["failed"]);
        assert_eq!(closed("unavailable:outcomeunknown"), vec!["unknown"]);
        println!(
            "SG122-EVIDENCE orceld live form journey: observe, fill, select, check and Enter approved through the broker (consent scripted), submission committed generation 2 on the origin, waited and verified (evidence {}); stale generation and cross-origin action refused (journaled failed); a delivered submission redirected off the origin journaled unknown; {} decisions recorded",
            verified.evidence_sha256,
            records.len()
        );
        assert!(browser.shutdown(), "the host family stayed");
    }

    #[test]
    #[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
    fn a_host_lost_after_the_consume_is_recorded_reconciled_and_ends_the_lifetime() {
        let fixture = Fixture::start();
        let scene = Scene::new("lost");
        let mut browser = scene.browser();
        if open(&mut browser, &scene, &fixture).is_none() {
            assert!(browser.shutdown());
            return;
        }
        let ledger = scene.root.join("approvals.json");
        let approve = LocalApprovalBroker::with_path_and_soft_decider(
            &ledger,
            Arc::new(NoPresenceVerifier),
            Arc::new(|_| ApprovalDecision::Approved),
        );
        browser
            .navigate(&scene.workspace, &approve, "https://fixture.test/reports")
            .expect("approved navigation");
        browser.observe().expect("observe");
        let latest = browser.select_latest_dated_link().expect("latest report");
        // The host dies after the broker consumed the download's approval
        // and before the frame reaches it.
        browser.after_consume = Some(kill_host());
        let lost = browser
            .download(
                &scene.workspace,
                &approve,
                &latest,
                &scene.approved,
                "lost.pdf",
            )
            .expect_err("the host was gone");
        assert!(
            matches!(
                lost.code,
                FailureCode::ProviderUnavailable | FailureCode::ProcessTimeout
            ),
            "{lost:?}"
        );
        // The approval was spent, and the outcome says it was lost.
        let last = browser.outcomes().last().expect("an outcome").clone();
        assert_eq!(last.outcome, DispatchOutcome::Lost);
        assert!(approve
            .history(10)
            .iter()
            .any(|record| record.id == last.record_id && record.consumed));
        // The lifetime is over: the next action is stale, before any prompt.
        assert!(!browser.has_lifetime());
        let before = approve.history(10).len();
        let stale = browser
            .navigate(&scene.workspace, &approve, "https://fixture.test/reports")
            .expect_err("stale lifetime");
        assert_eq!(stale.code, FailureCode::TargetStale);
        assert_eq!(approve.history(10).len(), before, "a stale action prompted");
        // The family was ended and confirmed gone before anything reads
        // the destination.
        assert_eq!(browser.host_ended(), Some(true));
        // The page is stale for good, on disk; the intent is still open.
        assert!(browser.page().is_none());
        let stored = PageStore::load_or_create(scene.state().pages);
        assert!(stored.count_for_workspace(&scene.workspace.id) == 0);
        let open = journal_open_intents(&scene.state().intents).expect("journal");
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].intent.record_id, last.record_id);
        // Reconciliation: the host died before acting, so nothing is there.
        let (intent, found) = browser
            .reconcile()
            .expect("a pending download")
            .expect("reconciled");
        assert_eq!(intent.record_id, last.record_id);
        assert_eq!(found, Reconciled::Absent);
        assert_eq!(files(&scene.approved), 0);
        println!("SG108-EVIDENCE orceld live lost: consumed approval recorded lost, lifetime stale, destination reconciled absent");
        let _ = browser.shutdown();
    }

    #[test]
    #[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
    fn a_restart_reconciles_the_download_a_lost_host_left_open() {
        let fixture = Fixture::start();
        let scene = Scene::new("restart");
        let mut browser = scene.browser();
        if open(&mut browser, &scene, &fixture).is_none() {
            assert!(browser.shutdown());
            return;
        }
        let approve = LocalApprovalBroker::with_path_and_soft_decider(
            scene.root.join("approvals.json"),
            Arc::new(NoPresenceVerifier),
            Arc::new(|_| ApprovalDecision::Approved),
        );
        browser
            .navigate(&scene.workspace, &approve, "https://fixture.test/reports")
            .expect("approved navigation");
        browser.observe().expect("observe");
        let latest = browser.select_latest_dated_link().expect("latest report");
        browser.after_consume = Some(kill_host());
        browser
            .download(
                &scene.workspace,
                &approve,
                &latest,
                &scene.approved,
                "lost.pdf",
            )
            .expect_err("the host was gone");
        let lost = browser.outcomes().last().expect("an outcome").clone();
        assert_eq!(lost.outcome, DispatchOutcome::Lost);
        // orceld ends without reconciling: everything in memory is gone,
        // only the journal remains.
        let _ = browser.shutdown();
        let open = journal_open_intents(&scene.state().intents).expect("journal");
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].intent.record_id, lost.record_id);
        // The next run reconciles it before anything else, exactly once.
        let next = scene.browser();
        let recovered = next.recovered();
        assert_eq!(recovered.len(), 1, "{recovered:?}");
        assert_eq!(recovered[0].0.record_id, lost.record_id);
        assert_eq!(recovered[0].0.relative, "lost.pdf");
        assert_eq!(recovered[0].1.as_ref().ok(), Some(&Reconciled::Absent));
        assert!(journal_open_intents(&scene.state().intents)
            .expect("journal")
            .is_empty());
        assert!(next.shutdown());
        let again = scene.browser();
        assert!(again.recovered().is_empty(), "reported twice");
        assert!(again.shutdown());
        println!("SG108-EVIDENCE orceld live restart: a lost download's journaled intent was reconciled absent by the next run, once");
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtSuspendProcess(process: windows_sys::Win32::Foundation::HANDLE) -> i32;
    }

    #[test]
    #[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
    fn a_suspended_host_is_ended_before_its_lost_download_is_reconciled() {
        use std::sync::atomic::{AtomicIsize, Ordering};
        use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, WaitForSingleObject, PROCESS_SUSPEND_RESUME, PROCESS_SYNCHRONIZE,
        };
        let fixture = Fixture::start();
        let scene = Scene::new("suspended");
        let mut browser = scene.browser();
        if open(&mut browser, &scene, &fixture).is_none() {
            assert!(browser.shutdown());
            return;
        }
        let approve = LocalApprovalBroker::with_path_and_soft_decider(
            scene.root.join("approvals.json"),
            Arc::new(NoPresenceVerifier),
            Arc::new(|_| ApprovalDecision::Approved),
        );
        browser
            .navigate(&scene.workspace, &approve, "https://fixture.test/reports")
            .expect("approved navigation");
        browser.observe().expect("observe");
        let latest = browser.select_latest_dated_link().expect("latest report");
        // The host is alive but silent (suspended, not dead) when the
        // consumed download goes out: the reply is lost, yet the host could
        // still act once it resumed.
        let handle = Arc::new(AtomicIsize::new(0));
        let held = Arc::clone(&handle);
        browser.reply_timeout = Some(Duration::from_secs(5));
        browser.after_consume = Some(Box::new(move |pid: u32| {
            // SAFETY: plain Win32 calls on a pid this test's host owns; the
            // handle is kept (so the pid cannot be reused under it) and
            // closed below.
            let process =
                unsafe { OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_SYNCHRONIZE, 0, pid) };
            assert_ne!(process, 0, "open the host process");
            // SAFETY: a valid process handle with PROCESS_SUSPEND_RESUME.
            assert_eq!(unsafe { NtSuspendProcess(process) }, 0, "suspend the host");
            held.store(process, Ordering::SeqCst);
        }));
        let lost = browser
            .download(
                &scene.workspace,
                &approve,
                &latest,
                &scene.approved,
                "lost.pdf",
            )
            .expect_err("the reply never came");
        assert_eq!(lost.code, FailureCode::ProcessTimeout, "{lost:?}");
        let last = browser.outcomes().last().expect("an outcome").clone();
        assert_eq!(last.outcome, DispatchOutcome::Lost);
        // The host was ended and confirmed gone before reconciliation: the
        // suspended process itself has exited.
        assert_eq!(browser.host_ended(), Some(true));
        let process = handle.load(Ordering::SeqCst);
        // SAFETY: the handle opened above, still open.
        assert_eq!(unsafe { WaitForSingleObject(process, 0) }, WAIT_OBJECT_0);
        // SAFETY: closing the handle opened above, once.
        unsafe { CloseHandle(process) };
        let (intent, found) = browser
            .reconcile()
            .expect("a pending download")
            .expect("reconciled");
        assert_eq!(intent.record_id, last.record_id);
        assert_eq!(found, Reconciled::Absent);
        // And it stays absent: nothing is left that could commit later.
        std::thread::sleep(Duration::from_secs(3));
        assert_eq!(files(&scene.approved), 0);
        println!("SG108-EVIDENCE orceld live suspended: silent host ended and confirmed gone, lost download reconciled absent and stayed absent");
        let _ = browser.shutdown();
    }

    /// Approves, but presents a token whose digest is not the prompt's: the
    /// broker refuses the consume, so nothing may reach the host.
    struct TamperingBroker(FixedApprovalBroker);

    impl ApprovalBroker for TamperingBroker {
        fn request_token(&self, prompt: &ApprovalPrompt) -> Result<ApprovedToken, ApprovalError> {
            let mut token = self.0.request_token(prompt)?;
            token.digest = "0".repeat(64);
            Ok(token)
        }

        fn consume(
            &self,
            token: &ApprovedToken,
            expected: &ConsumeExpectation,
            now_ms: u64,
        ) -> Result<(), ApprovalError> {
            self.0.consume(token, expected, now_ms)
        }
    }

    #[test]
    #[ignore = "requires the built browser worker and Edge; run by npm run browser-launcher:native"]
    fn a_denied_or_mismatched_approval_never_reaches_the_host() {
        let fixture = Fixture::start();
        let scene = Scene::new("denied");
        let mut browser = scene.browser();
        if open(&mut browser, &scene, &fixture).is_none() {
            assert!(browser.shutdown());
            return;
        }
        let approve = FixedApprovalBroker(ApprovalDecision::Approved);
        let deny = FixedApprovalBroker(ApprovalDecision::Denied);
        let tamper = TamperingBroker(FixedApprovalBroker(ApprovalDecision::Approved));
        // A denied navigation: refused by the broker, the page stays blank
        // (selection has no observation to work from).
        let denied = browser
            .navigate(&scene.workspace, &deny, "https://fixture.test/reports")
            .expect_err("denied navigation");
        assert_eq!(denied.code, FailureCode::ApprovalDenied);
        browser
            .navigate(&scene.workspace, &approve, "https://fixture.test/reports")
            .expect("approved navigation");
        browser.observe().expect("observe");
        let latest = browser.select_latest_dated_link().expect("latest report");
        // A denied download, and one whose consume fails: nothing written.
        let denied = browser
            .download(&scene.workspace, &deny, &latest, &scene.approved, "a.pdf")
            .expect_err("denied download");
        assert_eq!(denied.code, FailureCode::ApprovalDenied);
        let tampered = browser
            .download(&scene.workspace, &tamper, &latest, &scene.approved, "b.pdf")
            .expect_err("mismatched approval");
        // The broker refused the consume (not the host): its own code and
        // message.
        assert_eq!(tampered.code, FailureCode::TargetStale, "{tampered:?}");
        assert!(
            tampered.message.contains("digest changed after approval"),
            "{tampered:?}"
        );
        assert_eq!(files(&scene.approved), 0, "a refused approval wrote a file");
        // The unspent approval's intent was closed as abandoned, so no
        // restart reports a lost download for it.
        let journal = std::fs::read_to_string(&scene.state().intents).expect("journal");
        assert!(journal.contains("\"abandoned\""), "{journal}");
        assert!(journal_open_intents(&scene.state().intents)
            .expect("journal")
            .is_empty());
        // The lifetime is still live and in step: an approved download runs.
        assert!(browser.is_usable());
        browser
            .download(
                &scene.workspace,
                &approve,
                &latest,
                &scene.approved,
                "c.pdf",
            )
            .expect("approved download after refusals");
        assert_eq!(files(&scene.approved), 1);
        println!("SG108-EVIDENCE orceld live denial: denied and mismatched approvals never reached the host");
        assert!(browser.shutdown(), "the host family stayed");
    }

    fn sha256_bytes(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}
