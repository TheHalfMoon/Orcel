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
#![cfg_attr(not(test), allow(dead_code))]

use orcel_approval::{now_ms, ApprovalBroker, ApprovalPrompt, ApprovedToken, ConsumeExpectation};
use orcel_browser_host::worker_host::{BindAction, WireNode, WorkerHostReply, WorkerHostRequest};
use orcel_browser_host::{Supervisor, WorkerHostLaunch};
use orcel_contracts::FailureCode;
use orcel_policy::{Workspace, POLICY_REVISION};
use orcel_provider_browser::{PageRecord, PageState, PageStore};
use orcel_provider_fs::ProviderError;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Domain separation for the combined approval digest. Version 2 binds
/// the page store's page id, generation and origin (slice 2b).
const LIVE_APPROVAL_DOMAIN: &str = "orcel-sg108-live-approval/2";

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

/// A committed download, as the host reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveDownload {
    pub relative: String,
    pub sha256: String,
    pub bytes: u64,
    pub source_url: String,
}

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

/// Append one line and sync it to disk before returning.
fn journal_append(path: &Path, line: &JournalLine) -> Result<(), ProviderError> {
    use std::io::Write as _;
    let mut bytes = serde_json::to_vec(line).map_err(|_| journal_unavailable())?;
    bytes.push(b'\n');
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| journal_unavailable())?;
    }
    // A torn tail (a crash mid-append) is sealed with a newline first, so
    // this line never fuses with it.
    if torn_tail(path)? {
        bytes.insert(0, b'\n');
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|_| journal_unavailable())?;
    file.write_all(&bytes).map_err(|_| journal_unavailable())?;
    file.sync_data().map_err(|_| journal_unavailable())
}

/// Whether the journal ends without a newline (a torn final line).
fn torn_tail(path: &Path) -> Result<bool, ProviderError> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(journal_unavailable()),
    };
    let length = file.metadata().map_err(|_| journal_unavailable())?.len();
    if length == 0 {
        return Ok(false);
    }
    let mut last = [0u8; 1];
    file.seek(SeekFrom::Start(length - 1))
        .and_then(|_| file.read_exact(&mut last))
        .map_err(|_| journal_unavailable())?;
    Ok(last[0] != b'\n')
}

/// The intents still open in the journal, in order. A torn line (a crash
/// mid-append, before the approval was consumed: a strict prefix of a
/// line, so its JSON ends early) is skipped wherever a later append sealed
/// it; any other unreadable line fails closed.
pub fn journal_open_intents(path: &Path) -> Result<Vec<JournaledIntent>, ProviderError> {
    let text = match std::fs::read(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => {
            return Err(ProviderError::new(
                FailureCode::ProviderUnavailable,
                "the download intent journal could not be read",
            ))
        }
    };
    let mut open: Vec<JournaledIntent> = Vec::new();
    for raw in text.split(|byte| *byte == b'\n') {
        // Zero bytes are never part of a written line (JSON escapes control
        // characters): a power loss can leave allocated but unwritten bytes,
        // alone or after a torn prefix. Drop them, so a torn prefix still
        // reads as torn and a zero-filled run as nothing.
        let end = raw
            .iter()
            .rposition(|byte| *byte != 0)
            .map_or(0, |last| last + 1);
        let raw = &raw[..end];
        if raw.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let line = match serde_json::from_slice::<JournalLine>(raw) {
            Ok(line) if line.schema == INTENT_SCHEMA => line,
            Err(error) if error.is_eof() => continue,
            _ => {
                return Err(ProviderError::new(
                    FailureCode::ProviderUnavailable,
                    "the download intent journal is unreadable",
                ))
            }
        };
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
                _ => {
                    return Err(ProviderError::new(
                        FailureCode::ProviderUnavailable,
                        "the download intent journal is unreadable",
                    ))
                }
            },
            "settled" | "abandoned" | "reconciled" => {
                open.retain(|entry| entry.intent.record_id != line.record_id)
            }
            _ => {
                return Err(ProviderError::new(
                    FailureCode::ProviderUnavailable,
                    "the download intent journal is unreadable",
                ))
            }
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

/// One supervised worker-mode host and at most one lifetime.
pub struct LiveBrowser {
    supervisor: Supervisor,
    lifetime: Option<String>,
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
    /// None while the host is (or may be) running; once ended, whether the
    /// whole family was confirmed gone. Set once, never revised: a later
    /// shutdown finds no host and would report a vacuous success.
    host_ended: Option<bool>,
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

fn refused(code: &str) -> ProviderError {
    ProviderError::new(failure_for(code), format!("browser host refused: {code}"))
}

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The combined approval digest: orceld's material (workspace, policy
/// revision, lifetime, the page store's page id, generation and origin,
/// the action) and the host binding.
pub(crate) fn approval_digest(
    workspace_id: &str,
    lifetime: &str,
    page: &PageRecord,
    action: &BindAction,
    host_binding: &str,
) -> String {
    let action = serde_json::to_string(action).expect("a bind action always serializes");
    sha256_hex(&format!(
        "{LIVE_APPROVAL_DOMAIN}\n{workspace_id}\n{POLICY_REVISION}\n{lifetime}\n{}\n{}\n{}\n{action}\n{host_binding}",
        page.page_id, page.generation, page.current_origin
    ))
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
            page: None,
            pages: PageStore::load_or_create(state.pages.clone()),
            intents: state.intents.clone(),
            host_pid,
            host_started,
            recovered,
            outcomes: Vec::new(),
            pending_download: None,
            committed: Vec::new(),
            host_ended: None,
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
                self.end_host();
                (DispatchOutcome::Lost, Err(error))
            }
        };
        self.outcomes.push(ApprovalOutcome {
            record_id: record_id.to_owned(),
            outcome,
        });
        result
    }

    /// A dead lifetime makes its page stale for good (decision 3). If the
    /// registry cannot record it, the page is still dropped here, so this
    /// browser never acts on it again.
    fn close_page(&mut self) {
        if let Some(page) = self.page.take() {
            let _ = self.pages.close_page(&page.page_id);
        }
    }

    /// The page-store record of the lifetime's page, if a lifetime is open.
    pub fn page(&self) -> Option<&PageRecord> {
        self.page.as_ref()
    }

    /// What `start` reconciled from earlier runs (each reported once).
    pub fn recovered(&self) -> &[Recovered] {
        &self.recovered
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
                    Ok(page) => self.page = Some(page),
                    Err(error) => {
                        self.end_host();
                        return Err(from_page(error));
                    }
                }
                self.lifetime = Some(lifetime.clone());
                Ok(lifetime)
            }
            _ => Err(ProviderError::new(
                FailureCode::InternalError,
                "unexpected browser host reply",
            )),
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
    ) -> Result<(ApprovedToken, String, String), ProviderError> {
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
        let (binding, target) = match self.request(&WorkerHostRequest::Bind {
            action: action.clone(),
        })? {
            WorkerHostReply::Bound { binding, target } => (binding, target),
            _ => {
                return Err(ProviderError::new(
                    FailureCode::InternalError,
                    "unexpected browser host reply",
                ))
            }
        };
        let digest = approval_digest(&workspace.id, &lifetime, &page, action, &binding);
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
        let token = approval
            .request_token(&prompt)
            .map_err(|error| ProviderError::new(error.code, error.message))?;
        Ok((token, digest, binding))
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

    /// An approved navigation of the lifetime's page.
    pub fn navigate(
        &mut self,
        workspace: &Workspace,
        approval: &impl ApprovalBroker,
        url: &str,
    ) -> Result<(String, u16), ProviderError> {
        let (token, digest, binding) = self.ask(
            workspace,
            approval,
            &BindAction::Navigate { url: url.into() },
            "navigate isolated browser page",
        )?;
        Self::consume(workspace, approval, &token, digest)?;
        let record_id = token.record_id;
        match self.dispatch(
            &record_id,
            &WorkerHostRequest::Navigate {
                url: url.into(),
                record_id: record_id.clone(),
                binding,
            },
        )? {
            WorkerHostReply::Navigated { url, status } => {
                // The page store follows the committed document: a new
                // origin and generation, so every earlier approval and
                // observation of this page goes stale.
                let moved = orcel_provider_browser::parse_destination_url(&url)
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
                    Ok(next) => self.page = Some(next),
                    // orceld's record no longer matches the host's page:
                    // end the lifetime rather than act on either.
                    Err(error) => {
                        self.end_host();
                        return Err(error);
                    }
                }
                Ok((url, status))
            }
            _ => Err(ProviderError::new(
                FailureCode::InternalError,
                "unexpected browser host reply",
            )),
        }
    }

    /// A bounded observation: identities and digests only.
    pub fn observe(&mut self) -> Result<Vec<WireNode>, ProviderError> {
        match self.request(&WorkerHostRequest::Observe {})? {
            WorkerHostReply::Observed { nodes, .. } => Ok(nodes),
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
        let folder = folder.to_string_lossy().into_owned();
        let folder_for_record = folder.clone();
        let (token, digest, binding) = self.ask(
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
        let record_id = token.record_id.clone();
        // The intent is durable before the approval is spent: if orceld
        // dies anywhere after this, a restart finds it and reconciles the
        // destination. If it cannot be written, nothing is spent or sent.
        journal_append(
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
        // A reply, refusal or success, settles it; only a lost one stays.
        // If the settled line cannot be written, a restart reports the
        // destination as present, unverified: never adopted, so still safe.
        if !matches!(self.outcomes.last(), Some(o) if o.outcome == DispatchOutcome::Lost) {
            self.pending_download = None;
            let _ = journal_append(&self.intents, &JournalLine::event("settled", &record_id));
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
        self.lifetime = None;
        self.close_page();
        self.supervisor.shutdown().unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            host_ended,
            reply_timeout: None,
            after_consume: None,
        }
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
                outcome: DispatchOutcome::Lost
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
        let base = approval_digest("w", "l1", &fresh, &action, "h1");
        for other in [
            approval_digest("v", "l1", &fresh, &action, "h1"),
            approval_digest("w", "l2", &fresh, &action, "h1"),
            approval_digest("w", "l1", &fresh, &action, "h2"),
            // The page store's half: another page, generation or origin.
            approval_digest("w", "l1", &page("page-2", 0, ""), &action, "h1"),
            approval_digest("w", "l1", &page("page-1", 1, ""), &action, "h1"),
            approval_digest(
                "w",
                "l1",
                &page("page-1", 0, "https://fixture.test:443"),
                &action,
                "h1",
            ),
            approval_digest(
                "w",
                "l1",
                &fresh,
                &BindAction::Navigate {
                    url: "https://fixture.test/x".into(),
                },
                "h1",
            ),
        ] {
            assert_ne!(base, other);
        }
        assert_eq!(base.len(), 64);
        // Fixed vector, computed independently (Python sha256) over the
        // documented framing, with the live policy revision sg-000040-v1.
        assert_eq!(
            base,
            "1a665c0c67139a674c19c41f7ab4282dee34706533c68bb185b690ce39672d9a"
        );
    }
}

/// Native tests: the real `orcel-browser-host --worker` binary (built with
/// the feature; its path from the test harness), the loopback fixture, and
/// the test approval broker, which mints and consumes like the ledger
/// (exact digest, scope and expiry). Run by `npm run browser-launcher:native`.
#[cfg(test)]
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
                    node: env_path("ORCEL_SG108_NODE"),
                    worker_main: env_path("ORCEL_SG108_WORKER_MAIN"),
                    profile_root: self.root.join("profiles"),
                    temp_dir: self.root.join("staging"),
                    state_root: self.root.join("state"),
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
