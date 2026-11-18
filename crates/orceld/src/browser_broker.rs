//! SG-000135 OB-01: the Orcel Browser Session Broker.
//!
//! The broker replaces the single thread-local live browser for the
//! `browser_full` profile only (`browser_structured` keeps its own slot in
//! `live_dispatch.rs`, unchanged). It holds a map of broker sessions:
//!
//! - Each session id is minted here, never by a caller, and carries this
//!   orceld's instance id (the `orcel_session_id`, random per process), so
//!   an id from an earlier orceld run is refused as stale and never reaches
//!   another session.
//! - Each session is bound to the MCP session that created it (the
//!   request's `client_session_id`); another client naming its id is
//!   refused.
//! - Each session owns one worker lifetime (its own supervised browser
//!   host) and one Orcel-managed profile directory under the broker's root
//!   in orceld's protected browser state, never a personal browser profile.
//!   A session's profile is ephemeral by default: the directory is removed
//!   when the session ends. SG-000135 OB-04 adds a persistent Orcel-managed
//!   profile a session may name (`browser_profiles.rs`): its data folder
//!   lives outside the session's directory, is held by one live session at
//!   a time and is kept when the session ends. Routing the
//!   `browser_structured` shapes through the broker stays deferred (see
//!   `docs/orcel/implementation-readiness/prep/OB04_MODES_PROFILES.md`).
//! - SG-000135 OB-04: each session has a mode, Shadow (the default:
//!   headless, never the person's desktop) or Visible (a headed window named
//!   as an Orcel agent session, which the caller chose). The broker records
//!   it; the host builds the matching argv. Only Shadow advertises
//!   no-interference.
//! - Budgets: a per-client cap on open sessions, a device-wide cap held as
//!   locked slot files (so every orceld on the device counts, and a crashed
//!   orceld's slot frees itself), and a per-session action budget with a
//!   bounded receipt list.
//! - Sessions end on `browser_close`, when the MCP session ends (orceld's
//!   input closes, on every exit path), and on emergency stop, in this
//!   orceld at once and in every other orceld before its next broker action
//!   (each checks the approval epoch first); every end shuts the worker down
//!   and removes the session's profile directory, retrying a removal that
//!   failed.
//! - Each orceld instance holds its own instance lock for its lifetime. At
//!   start, the broker removes the session folders of every other instance
//!   whose lock is free (a crashed or exited orceld), never following a
//!   junction or symbolic link, and refuses state directories that are one.
//!
//! Every action yields an evidence receipt (SG-000135 OB-05,
//! `browser_receipts.rs`): its intent is written to orceld's hash-chained
//! audit log before anything is sent, and its receipt (authority, session,
//! profile and mode, origin, URL digest, target, pre- and post-action
//! evidence digests, outcome and times) after. Receipts chain by digest
//! within the session and are returned by `browser_task_status`; each names
//! its intent's and its own place in the chain. The session's start and end
//! are chained too.
//!
//! The broker grants nothing: profile gate, policy, the takeover gate and
//! the approval broker still decide every action. It is generic over the
//! worker so its rules are tested without a browser.

pub(crate) use crate::browser_receipts::ReceiptAudit;
use crate::browser_receipts::{
    disposition, receipt_digest_of, Disposition, EvidenceFile, EvidenceKind, EvidenceStore, Intent,
    IntentDraft, PreEvidence, ReceiptTarget, RECEIPT_CONTRACT, SOURCE_RECEIPT, SOURCE_SESSION,
};
use orcel_contracts::FailureCode;
use orcel_provider_fs::ProviderError;
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::path::{Path, PathBuf};

/// The prefix of every broker session id.
pub(crate) const SESSION_ID_PREFIX: &str = "bs-";
/// Hex characters of the instance id and of a session id's random part.
const ID_HEX_CHARS: usize = 16;
/// The longest session counter a well-formed id carries.
const MAX_COUNTER_DIGITS: usize = 6;
/// The last counter an instance mints (the most `MAX_COUNTER_DIGITS`
/// digits hold); past it, a new session is refused, never wrapped.
const MAX_COUNTER: u64 = 999_999;
/// Attempts to remove an ended session's directory before it is kept for a
/// later retry.
const REMOVAL_ATTEMPTS: u32 = 5;
/// The longest task label a caller may give a session.
pub(crate) const MAX_TASK_CHARS: usize = 64;
/// Ended sessions remembered so a late request learns why its session ended.
const ENDED_MEMORY: usize = 64;
/// The broker's budgets. Configured by orceld only; never a caller's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Budgets {
    /// Open sessions one client (one MCP session) may hold at once.
    pub per_client: usize,
    /// Open sessions on the whole device, across every orceld.
    pub device: usize,
    /// Actions one session may run in its lifetime.
    pub actions_per_session: u64,
    /// Receipts one session keeps (the oldest are dropped and counted).
    pub receipts_per_session: usize,
}

impl Budgets {
    /// The defaults of this packet: two sessions per client, four per
    /// device, 512 actions and 128 receipts per session.
    pub(crate) const DEFAULT: Self = Self {
        per_client: 2,
        device: 4,
        actions_per_session: 512,
        receipts_per_session: 128,
    };
}

/// SG-000135 OB-04: where a session's engine runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SessionMode {
    /// Headless, isolated, never the OS input, clipboard, focus or a
    /// foreground window: the default.
    #[default]
    Shadow,
    /// A headed engine window of its own, named as an Orcel agent session.
    /// Orcel never activates it, but the engine may bring it to the front
    /// when it opens and when it opens a page (measured; see
    /// OB04_MODES_PROFILES.md). Chosen by the caller and approved by the
    /// owner; it never advertises no-interference.
    Visible,
}

impl SessionMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Visible => "visible",
        }
    }

    /// Parse a mode name; anything else is refused.
    pub(crate) fn parse(value: &str) -> Result<Self, ProviderError> {
        match value {
            "shadow" => Ok(Self::Shadow),
            "visible" => Ok(Self::Visible),
            _ => Err(ProviderError::new(
                FailureCode::InvalidRequest,
                "mode is shadow or visible",
            )),
        }
    }

    /// Whether the mode may claim it does not interfere with the person:
    /// only Shadow (FX-6: Visible never advertises no-interference).
    pub(crate) fn no_interference(self) -> bool {
        self == Self::Shadow
    }
}

/// SG-000135 OB-04: what a new session is opened with.
#[derive(Debug, Default)]
pub(crate) struct SessionOptions {
    pub mode: SessionMode,
    /// A persistent Orcel-managed profile, held for the session's life;
    /// `None` for the default ephemeral profile.
    pub profile: Option<crate::browser_profiles::ProfileLease>,
}

/// What the broker needs from a session's worker.
pub(crate) trait SessionWorker {
    /// Whether the worker still answers.
    fn is_usable(&mut self) -> bool;
    /// End the worker; true when its process family is confirmed gone.
    fn shutdown(self) -> bool;
}

/// Where one session keeps its state: everything under its own directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionDirs {
    /// The session's directory; removed when the session ends.
    pub root: PathBuf,
    /// The Orcel-managed profile root the session's host creates its
    /// ephemeral profiles in.
    pub profiles: PathBuf,
    pub staging: PathBuf,
    pub host: PathBuf,
    pub pages: PathBuf,
    pub intents: PathBuf,
    /// SG-000135 OB-04: the persistent profile's data folder the session's
    /// host uses in place of an ephemeral profile (outside `root`, kept when
    /// the session ends), or `None`.
    pub persistent_profile: Option<PathBuf>,
}

impl SessionDirs {
    fn under(root: PathBuf) -> Self {
        Self {
            persistent_profile: None,
            profiles: root.join("profiles"),
            staging: root.join("staging"),
            host: root.join("host"),
            pages: root.join("pages.jsonl"),
            intents: root.join("intents.jsonl"),
            root,
        }
    }

    fn create(&self) -> Result<(), ProviderError> {
        real_dir(&self.root)?;
        for dir in [&self.profiles, &self.staging, &self.host] {
            real_dir(dir)?;
        }
        Ok(())
    }
}

/// Whether `metadata` (from `symlink_metadata`) is a reparse point: a
/// symbolic link, a junction or any other Windows reparse point.
pub(crate) fn is_reparse(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    metadata.file_type().is_symlink()
}

/// Create `dir` if needed and require it to be a real directory, not a
/// junction, a symbolic link or a file.
pub(crate) fn real_dir(dir: &Path) -> Result<(), ProviderError> {
    let refused = || {
        ProviderError::new(
            FailureCode::ProviderUnavailable,
            "the browser session state could not be created as a real directory",
        )
    };
    std::fs::create_dir_all(dir).map_err(|_| refused())?;
    match std::fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.is_dir() && !is_reparse(&metadata) => Ok(()),
        _ => Err(refused()),
    }
}

/// Remove the tree at `path` without ever following a reparse point: a
/// link or junction inside it is removed as a link, its target untouched.
/// A `path` that is itself a reparse point is refused (left in place).
/// True when nothing is left at `path`.
pub(crate) fn remove_tree(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
        Ok(metadata) if is_reparse(&metadata) => false,
        Ok(metadata) if !metadata.is_dir() => std::fs::remove_file(path).is_ok(),
        Ok(_) => {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    let child = entry.path();
                    match std::fs::symlink_metadata(&child) {
                        Ok(metadata) if is_reparse(&metadata) => {
                            // The link itself, never its target.
                            if std::fs::remove_dir(&child).is_err() {
                                let _ = std::fs::remove_file(&child);
                            }
                        }
                        _ => {
                            remove_tree(&child);
                        }
                    }
                }
            }
            let _ = std::fs::remove_dir(path);
            std::fs::symlink_metadata(path).is_err()
        }
    }
}

/// Try an exclusive lock on the lock file at `path` (created if missing).
/// `Ok(Some)` holds it; `Ok(None)` means another process holds it.
pub(crate) fn try_lock_file(path: &Path) -> Result<Option<File>, ProviderError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|_| {
            ProviderError::new(
                FailureCode::ProviderUnavailable,
                "a browser broker lock file could not be opened",
            )
        })?;
    match fs4::FileExt::try_lock(&file) {
        Ok(()) => Ok(Some(file)),
        Err(fs4::TryLockError::WouldBlock) => Ok(None),
        Err(fs4::TryLockError::Error(_)) => Err(ProviderError::new(
            FailureCode::ProviderUnavailable,
            "a browser broker lock file could not be locked",
        )),
    }
}

/// Whether `name` is an instance id (16 lowercase hex characters).
fn is_instance_id(name: &str) -> bool {
    name.len() == ID_HEX_CHARS
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The shared approval ledger's revoke epoch, read and verified now (an
/// emergency revoke in any orceld advances it), or `None` when the ledger
/// could not be verified just now (busy, unreadable or failing
/// verification). orceld checks it before every broker action and again
/// right before the action runs.
pub(crate) fn verified_epoch(approval: &impl orcel_approval::ApprovalBroker) -> Option<u64> {
    approval.verified_revoke_epoch()
}

/// Check `seen` (one read of the approval epoch) and return it as the
/// baseline the action is checked against again right before it runs. The
/// epoch is read once, so a revoke landing between two reads can never
/// become the baseline.
pub(crate) fn checked_baseline<W: SessionWorker>(
    broker: &mut Broker<W>,
    seen: Option<u64>,
) -> Result<u64, ProviderError> {
    broker.check_epoch(seen)?;
    seen.ok_or_else(|| {
        ProviderError::new(
            FailureCode::ApprovalUnavailable,
            "the approval ledger could not be verified just now",
        )
    })
}

/// Why a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndReason {
    Closed,
    McpSessionEnded,
    EmergencyStop,
    HostLost,
}

impl EndReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::McpSessionEnded => "mcp_session_ended",
            Self::EmergencyStop => "emergency_stop",
            Self::HostLost => "host_lost",
        }
    }
}

/// What ending a session did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndReport {
    pub session_id: String,
    pub reason: EndReason,
    /// The worker's process family is confirmed gone.
    pub worker_ended: bool,
    /// The session's profile directory no longer exists.
    pub profile_removed: bool,
    /// SG-000135 OB-04: the persistent profile the session held, kept (and
    /// released for the next session), if any.
    pub persistent_profile: Option<String>,
    /// SG-000135 OB-04: the worker could not be confirmed gone, so the
    /// persistent profile stays locked (quarantined) for this orceld's life,
    /// and no later session can open it while an engine may still run in it.
    pub profile_quarantined: bool,
}

impl EndReport {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "session_id": self.session_id,
            "reason": self.reason.as_str(),
            "worker_ended": self.worker_ended,
            "profile_removed": self.profile_removed,
            "profile_mode": if self.persistent_profile.is_some() { "persistent" } else { "ephemeral" },
            "profile": self.persistent_profile,
            "profile_kept": self.persistent_profile.is_some(),
            "profile_quarantined": self.profile_quarantined,
        })
    }
}

/// SG-000135 OB-05: one evidence receipt: what orceld dispatched, under
/// which authority, on what, and what became of it. Written to orceld's
/// audit chain after the action's intent (`browser_receipts.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Receipt {
    pub seq: u64,
    pub session_id: String,
    pub action: String,
    /// SG-000135 OB-04: `shadow` or `visible`.
    pub mode: String,
    pub page_id: Option<String>,
    pub generation_before: Option<u64>,
    pub generation_after: Option<u64>,
    /// The page's origin before and after (scheme, host and port only).
    pub origin_before: Option<String>,
    pub origin_after: Option<String>,
    /// The committed URL, as its SHA-256 only (never the URL, its query or
    /// fragment).
    pub url_sha256: Option<String>,
    /// The page and node acted on (role and keyed name digest only).
    pub target: Option<ReceiptTarget>,
    /// `done`, `denied`, `refused`, `not_dispatched`, `failed` or `unknown`
    /// (the OB-01 word, kept).
    pub outcome: String,
    /// OB-05: `sent`, `refused`, `failed`, `superseded` or `unknown`; whether
    /// the effect happened; whether a person is needed.
    pub disposition: Disposition,
    pub failure_code: Option<String>,
    /// `observe`, `verify`, `reply`, `screenshot` or `none`: where the
    /// post-action evidence digest comes from.
    pub evidence_kind: String,
    pub evidence_sha256: Option<String>,
    /// OB-05: the snapshot the action was planned on, if the session took one
    /// of that page.
    pub pre_evidence: Option<PreEvidence>,
    /// OB-05: the evidence files kept (content-addressed, digests only here).
    pub evidence_files: Vec<EvidenceFile>,
    /// The approval broker's record id, for an approved action.
    pub record_id: Option<String>,
    /// SG-000135 OB-08: the Full Access lease that authorized the action
    /// instead of an approval (then `record_id` is `None`).
    pub lease_id: Option<String>,
    /// OB-05: the authority service's epoch the lease was checked at.
    pub lease_epoch: Option<u64>,
    /// OB-05: the approval epoch the action was checked against.
    pub approval_epoch: Option<u64>,
    /// SG-000135 OB-04: the persistent Orcel-managed profile the session
    /// acted in, or `None` for an ephemeral profile.
    pub profile: Option<String>,
    /// OB-05: the intent written before the action (digest and chain place).
    pub intent_sha256: Option<String>,
    pub intent_audit: ReceiptAudit,
    pub intent_at_ms: Option<u64>,
    pub at_ms: u64,
    /// The previous receipt's digest in this session (empty for the first).
    pub previous_sha256: String,
    pub receipt_sha256: String,
    /// Where the receipt sits in orceld's audit chain. Not covered by
    /// `receipt_sha256` (known only once written).
    pub audit: ReceiptAudit,
}

impl Receipt {
    pub(crate) fn to_json(&self) -> Value {
        let authority = match (&self.record_id, &self.lease_id) {
            (_, Some(_)) => "lease",
            (Some(_), None) => "approval",
            (None, None) => "none",
        };
        json!({
            "contract": RECEIPT_CONTRACT,
            "seq": self.seq,
            "session_id": self.session_id,
            "action": self.action,
            "mode": self.mode,
            "profile": self.profile,
            "page_id": self.page_id,
            "generation_before": self.generation_before,
            "generation_after": self.generation_after,
            "origin_before": self.origin_before,
            "origin_after": self.origin_after,
            "url_sha256": self.url_sha256,
            "target": self.target.as_ref().map(ReceiptTarget::to_json),
            "authority": {
                "kind": authority,
                "record_id": self.record_id,
                "lease_id": self.lease_id,
                "lease_epoch": self.lease_epoch,
                "approval_epoch": self.approval_epoch,
            },
            "record_id": self.record_id,
            "lease_id": self.lease_id,
            "outcome": self.outcome,
            "result": self.disposition.result,
            "effect": self.disposition.effect,
            "needs_person": self.disposition.needs_person,
            "failure_code": self.failure_code,
            "pre_evidence": self.pre_evidence.as_ref().map(PreEvidence::to_json),
            "evidence_kind": self.evidence_kind,
            "evidence_sha256": self.evidence_sha256,
            "evidence_files": self.evidence_files.iter().map(EvidenceFile::to_json).collect::<Vec<_>>(),
            "intent_sha256": self.intent_sha256,
            "intent_audit": self.intent_audit.to_json(),
            "intent_at_ms": self.intent_at_ms,
            "at_ms": self.at_ms,
            "duration_ms": self.intent_at_ms.map(|start| self.at_ms.saturating_sub(start)),
            "previous_sha256": self.previous_sha256,
            "receipt_sha256": self.receipt_sha256,
            "provisional": false,
            "audit": self.audit.to_json(),
        })
    }

    /// The receipt's `dispatch` event in orceld's chain: the receipt's own
    /// fields and digest (ids, outcome, origins and digests only; never a
    /// URL, a value or page content).
    fn audit_draft(&self, client: &str) -> orcel_audit::EventDraft {
        let mut receipt = self.to_json();
        if let Value::Object(map) = &mut receipt {
            map.remove("audit");
        }
        orcel_audit::EventDraft {
            principal_id: Some(client.to_owned()),
            capability: Some("browser.session".to_owned()),
            operation: Some(self.action.clone()),
            ..orcel_audit::EventDraft::new(
                orcel_contracts::event::AuditEventKind::Dispatch,
                json!({"source": SOURCE_RECEIPT, "receipt": receipt}),
            )
        }
    }
}

/// What a caller of the broker reports about one action.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ActionRecord {
    pub action: String,
    /// OB-05: the intent written before the action ran (`begin_intent`);
    /// `None` only in tests of the receipt list itself.
    pub intent: Option<Intent>,
    pub page_id: Option<String>,
    pub generation_before: Option<u64>,
    pub generation_after: Option<u64>,
    pub origin_before: Option<String>,
    pub origin_after: Option<String>,
    pub url_sha256: Option<String>,
    pub target: Option<ReceiptTarget>,
    pub outcome: String,
    pub failure_code: Option<String>,
    /// A person's input arrived while the sent action was in flight.
    pub superseded: bool,
    pub evidence_kind: String,
    pub evidence_sha256: Option<String>,
    pub pre_evidence: Option<PreEvidence>,
    pub evidence_files: Vec<EvidenceFile>,
    pub record_id: Option<String>,
    /// SG-000135 OB-08: the lease that authorized the action, if one did.
    pub lease_id: Option<String>,
    pub lease_epoch: Option<u64>,
    pub approval_epoch: Option<u64>,
}

/// A device-wide session slot: an exclusive lock on one slot file, held
/// while the session lives and released by the OS if orceld dies.
struct DeviceSlot {
    _file: File,
}

fn acquire_slot(dir: &Path, slots: usize) -> Result<DeviceSlot, ProviderError> {
    real_dir(dir)?;
    for index in 0..slots {
        if let Some(file) = try_lock_file(&dir.join(format!("slot-{index}.lock")))? {
            return Ok(DeviceSlot { _file: file });
        }
    }
    Err(ProviderError::new(
        FailureCode::OutputLimit,
        format!("the device already runs {slots} browser sessions; close one first"),
    ))
}

/// One broker session.
pub(crate) struct BrokerSession<W> {
    pub id: String,
    pub client: String,
    pub task: Option<String>,
    pub dirs: SessionDirs,
    pub created_ms: u64,
    /// SG-000135 OB-04: Shadow or Visible, fixed for the session's life.
    pub mode: SessionMode,
    /// SG-000135 OB-04: the persistent profile held, released when the
    /// session ends (after its worker is gone).
    profile: Option<crate::browser_profiles::ProfileLease>,
    pub worker: W,
    /// The session's page id in its worker's page store, once opened.
    pub page_id: Option<String>,
    actions: u64,
    actions_budget: u64,
    receipts: VecDeque<Receipt>,
    receipts_budget: usize,
    receipts_dropped: u64,
    last_receipt_sha256: String,
    next_seq: u64,
    /// orceld's audit chain, when the broker was given one.
    audit: Option<std::sync::Arc<orcel_audit::ChainWriter>>,
    /// SG-000135 OB-05: where evidence files are kept, when the broker was
    /// given a store.
    evidence: Option<EvidenceStore>,
    /// SG-000135 OB-05: the latest snapshot of each page (generation and
    /// frame digest), the pre-action evidence of the next action on it.
    observations: BTreeMap<String, (u64, String)>,
    /// SG-000135 OB-05: the node targets (role, keyed name digest) of the
    /// latest snapshot, and the page it was of.
    targets: BTreeMap<String, (String, String)>,
    targets_page: Option<String>,
    /// SG-000135 OB-05 (FA-J): measured intent-to-receipt latency.
    latency_total_ms: u64,
    latency_max_ms: u64,
    _slot: DeviceSlot,
}

impl<W> BrokerSession<W> {
    /// Count one action against the session's budget, before it runs.
    pub(crate) fn begin_action(&mut self) -> Result<(), ProviderError> {
        if self.actions >= self.actions_budget {
            return Err(ProviderError::new(
                FailureCode::OutputLimit,
                "the browser session used its action budget; close it and create a new one",
            ));
        }
        self.actions += 1;
        Ok(())
    }

    /// SG-000135 OB-05: write the intent of the next action to the audit
    /// chain before anything is sent. A chain that refuses it refuses the
    /// action: nothing may be sent without its intent on record.
    pub(crate) fn begin_intent(
        &mut self,
        draft: IntentDraft,
        at_ms: u64,
    ) -> Result<Intent, ProviderError> {
        let seq = self.next_seq;
        let mut intent = Intent {
            seq,
            session_id: self.id.clone(),
            mode: self.mode.as_str().to_owned(),
            profile: self.profile_name().map(str::to_owned),
            draft,
            at_ms,
            previous_receipt_sha256: self.last_receipt_sha256.clone(),
            intent_sha256: String::new(),
            audit: ReceiptAudit::NotConfigured,
        };
        intent.intent_sha256 = intent.digest();
        if let Some(chain) = &self.audit {
            match chain.append(intent.audit_draft(&self.client)) {
                Ok(appended) => intent.audit = ReceiptAudit::Chained(appended.at),
                Err(error) => {
                    return Err(ProviderError::new(
                        FailureCode::InternalError,
                        format!(
                            "the audit chain refused the intent of browser session action {seq}, so nothing was sent: {error}"
                        ),
                    ))
                }
            }
        }
        // The seq is the intent's: its receipt carries the same one, and an
        // intent with no receipt leaves a gap the verifier reports.
        self.next_seq += 1;
        Ok(intent)
    }

    /// Append the receipt of one action, chained to the previous one and
    /// bound to its intent.
    pub(crate) fn record(&mut self, record: ActionRecord, at_ms: u64) -> Receipt {
        let seq = match &record.intent {
            Some(intent) => intent.seq,
            None => {
                let seq = self.next_seq;
                self.next_seq += 1;
                seq
            }
        };
        let previous = self.last_receipt_sha256.clone();
        let disposition = disposition(
            &record.outcome,
            record.failure_code.as_deref(),
            record.superseded,
        );
        let mut receipt = Receipt {
            seq,
            session_id: self.id.clone(),
            action: record.action,
            mode: self.mode.as_str().to_owned(),
            page_id: record.page_id,
            generation_before: record.generation_before,
            generation_after: record.generation_after,
            // What the intent saw before the action, unless the caller says.
            origin_before: record.origin_before.or_else(|| {
                record
                    .intent
                    .as_ref()
                    .and_then(|intent| intent.draft.origin_before.clone())
            }),
            origin_after: record.origin_after,
            url_sha256: record.url_sha256,
            target: record.target,
            outcome: record.outcome,
            disposition,
            failure_code: record.failure_code,
            evidence_kind: record.evidence_kind,
            evidence_sha256: record.evidence_sha256,
            pre_evidence: record.pre_evidence,
            evidence_files: record.evidence_files,
            record_id: record.record_id,
            lease_id: record.lease_id,
            lease_epoch: record.lease_epoch,
            approval_epoch: record.approval_epoch,
            profile: self.profile_name().map(str::to_owned),
            intent_sha256: record.intent.as_ref().map(|i| i.intent_sha256.clone()),
            intent_audit: record
                .intent
                .as_ref()
                .map(|i| i.audit.clone())
                .unwrap_or(ReceiptAudit::NotConfigured),
            intent_at_ms: record.intent.as_ref().map(|i| i.at_ms),
            at_ms,
            previous_sha256: previous,
            receipt_sha256: String::new(),
            audit: ReceiptAudit::NotConfigured,
        };
        receipt.receipt_sha256 = receipt_digest(&receipt);
        if let Some(chain) = &self.audit {
            receipt.audit = match chain.append(receipt.audit_draft(&self.client)) {
                Ok(appended) => ReceiptAudit::Chained(appended.at),
                Err(error) => ReceiptAudit::Failed(error.to_string()),
            };
        }
        if let Some(start) = receipt.intent_at_ms {
            let latency = at_ms.saturating_sub(start);
            self.latency_total_ms = self.latency_total_ms.saturating_add(latency);
            self.latency_max_ms = self.latency_max_ms.max(latency);
        }
        self.last_receipt_sha256 = receipt.receipt_sha256.clone();
        if self.receipts.len() >= self.receipts_budget {
            self.receipts.pop_front();
            self.receipts_dropped += 1;
        }
        self.receipts.push_back(receipt.clone());
        receipt
    }

    /// SG-000135 OB-05: keep `bytes` as evidence of `kind` (content-addressed,
    /// in the private evidence store). Without a store the receipt names the
    /// digest with `stored: false`.
    pub(crate) fn keep_evidence(&self, kind: EvidenceKind, bytes: &[u8]) -> EvidenceFile {
        match &self.evidence {
            Some(store) => store.put(kind, bytes),
            None => EvidenceFile {
                kind,
                sha256: crate::browser_receipts::sha256_hex(bytes),
                bytes: bytes.len() as u64,
                stored: false,
            },
        }
    }

    /// SG-000135 OB-05: a snapshot of `page_id` at `generation` was taken:
    /// its frame digest is the pre-action evidence of the next action on the
    /// page, and its nodes the targets that action names.
    pub(crate) fn note_observation(
        &mut self,
        page_id: &str,
        generation: u64,
        sha256: &str,
        nodes: &Value,
    ) {
        self.observations
            .insert(page_id.to_owned(), (generation, sha256.to_owned()));
        self.targets = crate::browser_receipts::targets_from_nodes(nodes);
        self.targets_page = Some(page_id.to_owned());
    }

    /// SG-000135 OB-05: the latest snapshot of `page_id`, if any.
    pub(crate) fn pre_evidence(&self, page_id: &str) -> Option<PreEvidence> {
        self.observations
            .get(page_id)
            .map(|(generation, sha256)| PreEvidence {
                page_id: page_id.to_owned(),
                generation: *generation,
                sha256: sha256.clone(),
            })
    }

    /// SG-000135 OB-05: what an action names: the page, and for a node its
    /// id, with the role and keyed name digest the latest snapshot of that
    /// page gave it.
    pub(crate) fn target_of(&self, page_id: Option<&str>, node_id: Option<&str>) -> ReceiptTarget {
        let known = node_id
            .filter(|_| page_id.is_some() && self.targets_page.as_deref() == page_id)
            .and_then(|node| self.targets.get(node));
        ReceiptTarget {
            page_id: page_id.map(str::to_owned),
            node_id: node_id.map(str::to_owned),
            role: known.map(|(role, _)| role.clone()),
            name_digest: known.map(|(_, name)| name.clone()),
        }
    }

    pub(crate) fn receipts(&self) -> impl Iterator<Item = &Receipt> {
        self.receipts.iter()
    }

    #[cfg(test)]
    pub(crate) fn actions(&self) -> u64 {
        self.actions
    }

    /// SG-000135 OB-04: the persistent profile's name, if the session holds one.
    pub(crate) fn profile_name(&self) -> Option<&str> {
        self.profile.as_ref().map(|lease| lease.name.as_str())
    }

    /// SG-000135 OB-04: how the session runs, as replies show it.
    pub(crate) fn mode_json(&self) -> Value {
        json!({
            "mode": self.mode.as_str(),
            "no_interference": self.mode.no_interference(),
            "profile_mode": if self.profile.is_some() { "persistent" } else { "ephemeral" },
            "profile": self.profile_name(),
        })
    }

    /// SG-000135 OB-05 (FA-J): what was measured of the session's actions.
    pub(crate) fn measured_json(&self) -> Value {
        let recorded = self.next_seq.saturating_sub(1);
        json!({
            "actions_recorded": recorded,
            "latency_ms_total": self.latency_total_ms,
            "latency_ms_max": self.latency_max_ms,
            "latency": "from each action's intent on the audit chain to its receipt, orceld's clock",
        })
    }

    /// SG-000135 OB-05: the session's start or end, chained (best effort:
    /// a chain that refuses it refuses the next action's intent anyway).
    fn chain_session_event(&self, detail: Value) {
        if let Some(chain) = &self.audit {
            let _ = chain.append(orcel_audit::EventDraft {
                principal_id: Some(self.client.clone()),
                capability: Some("browser.session".to_owned()),
                operation: detail["event"].as_str().map(str::to_owned),
                ..orcel_audit::EventDraft::new(
                    orcel_contracts::event::AuditEventKind::Dispatch,
                    detail,
                )
            });
        }
    }
}

/// The digest of a receipt's fields: canonical JSON of every field but the
/// digest and its chain place, under [`crate::browser_receipts::RECEIPT_DOMAIN`]
/// (an absent field is `null`, never equal to any present value).
fn receipt_digest(receipt: &Receipt) -> String {
    receipt_digest_of(&receipt.to_json()).unwrap_or_default()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The broker: every open session of this orceld.
pub(crate) struct Broker<W> {
    /// This orceld's instance id (the `orcel_session_id`).
    instance: String,
    /// The broker's root in orceld's protected browser state.
    root: PathBuf,
    budgets: Budgets,
    sessions: BTreeMap<String, BrokerSession<W>>,
    ended: VecDeque<(String, EndReason)>,
    counter: u64,
    /// Ended sessions whose directory could not be removed yet.
    pending_removal: Vec<PathBuf>,
    /// The approval epoch this broker last saw.
    epoch: Option<u64>,
    /// SG-000135 OB-04: persistent profiles whose session's worker could not
    /// be confirmed gone, kept locked for this orceld's life.
    quarantined: Vec<crate::browser_profiles::ProfileLease>,
    /// SG-000135 OB-04: (workspace, client, profile) the owner approved for
    /// use in this orceld (one MCP session's life). Cleared whenever every
    /// session ends (emergency stop, an approval epoch that moved or could
    /// not be verified, orceld's input closing), so a revoke always asks
    /// again before a signed-in profile is reused.
    profile_approvals: std::collections::BTreeSet<(String, String, String)>,
    /// orceld's audit chain every intent and receipt is written to.
    audit: Option<std::sync::Arc<orcel_audit::ChainWriter>>,
    /// SG-000135 OB-05: the private store of evidence files.
    evidence: Option<EvidenceStore>,
    /// This instance's lock, held for the broker's (orceld's) lifetime.
    _instance_lock: File,
}

impl<W: SessionWorker> Broker<W> {
    /// SG-000135 OB-05: write every session's intents and receipts to
    /// `chain`.
    pub(crate) fn with_audit_chain(
        mut self,
        chain: Option<std::sync::Arc<orcel_audit::ChainWriter>>,
    ) -> Self {
        self.audit = chain;
        self
    }

    /// SG-000135 OB-05: keep evidence files in `store`.
    pub(crate) fn with_evidence(mut self, store: Option<EvidenceStore>) -> Self {
        self.evidence = store;
        self
    }

    /// Start a broker rooted at `root` (orceld's own state, never a
    /// caller's) for the orceld instance `instance` (16 lowercase hex
    /// characters): hold the instance's lock, then sweep what exited
    /// instances left.
    pub(crate) fn start(
        root: PathBuf,
        instance: String,
        budgets: Budgets,
    ) -> Result<Self, ProviderError> {
        if !is_instance_id(&instance) {
            return Err(ProviderError::new(
                FailureCode::InternalError,
                "the browser broker's instance id is malformed",
            ));
        }
        real_dir(&root)?;
        real_dir(&root.join("instances"))?;
        real_dir(&root.join("sessions"))?;
        let lock = try_lock_file(&root.join("instances").join(format!("{instance}.lock")))?
            .ok_or_else(|| {
                ProviderError::new(
                    FailureCode::InternalError,
                    "another browser broker holds this instance id",
                )
            })?;
        let mut broker = Self {
            instance,
            root,
            budgets,
            sessions: BTreeMap::new(),
            ended: VecDeque::new(),
            counter: 0,
            pending_removal: Vec::new(),
            epoch: None,
            quarantined: Vec::new(),
            profile_approvals: std::collections::BTreeSet::new(),
            audit: None,
            evidence: None,
            _instance_lock: lock,
        };
        broker.sweep_leftovers();
        Ok(broker)
    }

    /// Remove the session folders of every other instance whose lock is
    /// free (its orceld exited or crashed), and their lock files. A folder
    /// that is a junction or symbolic link, or whose name is not an
    /// instance id, is skipped and left untouched. Returns how many
    /// instances' folders were removed.
    pub(crate) fn sweep_leftovers(&mut self) -> usize {
        self.retry_pending_removal();
        let sessions = self.root.join("sessions");
        let instances = self.root.join("instances");
        let Ok(entries) = std::fs::read_dir(&sessions) else {
            return 0;
        };
        let mut swept = 0;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == self.instance || !is_instance_id(&name) {
                continue;
            }
            let path = entry.path();
            match std::fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_dir() && !is_reparse(&metadata) => {}
                _ => continue,
            }
            let lock_path = instances.join(format!("{name}.lock"));
            // Held: that orceld still runs. Free: it is gone.
            let Ok(Some(lock)) = try_lock_file(&lock_path) else {
                continue;
            };
            if remove_tree(&path) {
                swept += 1;
                drop(lock);
                let _ = std::fs::remove_file(&lock_path);
            }
        }
        swept
    }

    /// Retry removing ended sessions' directories that were still busy.
    fn retry_pending_removal(&mut self) {
        self.pending_removal.retain(|path| !remove_tree(path));
    }

    /// The directories of ended sessions still waiting to be removed.
    #[cfg(test)]
    pub(crate) fn pending_removal(&self) -> &[PathBuf] {
        &self.pending_removal
    }

    /// Check the approval epoch before (and again right before running) a
    /// broker action. When it moved (an emergency revoke in this or any
    /// other orceld), every session ends as by emergency stop and the
    /// action is refused; an epoch that could not be verified (`None`)
    /// ends every session and refuses the action too (fail closed). The
    /// first verified sight is the baseline.
    pub(crate) fn check_epoch(&mut self, epoch: Option<u64>) -> Result<(), ProviderError> {
        let Some(epoch) = epoch else {
            self.end_all(EndReason::EmergencyStop);
            return Err(ProviderError::new(
                FailureCode::ApprovalUnavailable,
                "the approval ledger could not be verified just now, so an emergency revoke cannot be ruled out; every browser session ended; retry",
            ));
        };
        match self.epoch.replace(epoch) {
            Some(seen) if seen != epoch => {
                self.end_all(EndReason::EmergencyStop);
                Err(ProviderError::new(
                    FailureCode::TargetStale,
                    "an emergency revoke moved the approval epoch; every browser session ended",
                ))
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn instance(&self) -> &str {
        &self.instance
    }

    /// Where this instance's sessions keep their directories.
    fn sessions_root(&self) -> PathBuf {
        self.root.join("sessions").join(&self.instance)
    }

    /// Open a session for `client`, whose worker `start` launches on the
    /// session's own directories. `random` is 8 fresh random bytes.
    #[cfg(test)]
    pub(crate) fn create(
        &mut self,
        client: &str,
        task: Option<&str>,
        random: [u8; 8],
        now_ms: u64,
        start: impl FnOnce(&str, &SessionDirs) -> Result<W, ProviderError>,
    ) -> Result<&mut BrokerSession<W>, ProviderError> {
        self.create_with(
            client,
            task,
            SessionOptions::default(),
            random,
            now_ms,
            start,
        )
    }

    /// Open a session for `client` with `options` (SG-000135 OB-04: its
    /// mode, and a persistent profile already held for it). The worker
    /// `start` launches sees the profile's data folder in
    /// `SessionDirs::persistent_profile`. On any refusal the profile is
    /// released with `options`.
    pub(crate) fn create_with(
        &mut self,
        client: &str,
        task: Option<&str>,
        options: SessionOptions,
        random: [u8; 8],
        now_ms: u64,
        start: impl FnOnce(&str, &SessionDirs) -> Result<W, ProviderError>,
    ) -> Result<&mut BrokerSession<W>, ProviderError> {
        if let Some(task) = task {
            check_task(task)?;
        }
        let held = self
            .sessions
            .values()
            .filter(|session| session.client == client)
            .count();
        if held >= self.budgets.per_client {
            return Err(ProviderError::new(
                FailureCode::OutputLimit,
                format!(
                    "this client already holds {} browser sessions; close one first",
                    self.budgets.per_client
                ),
            ));
        }
        if self.counter >= MAX_COUNTER {
            return Err(ProviderError::new(
                FailureCode::OutputLimit,
                "this orceld minted its last browser session id; restart the MCP session",
            ));
        }
        self.retry_pending_removal();
        let sessions_root = self.sessions_root();
        real_dir(&sessions_root)?;
        let slot = acquire_slot(&self.root.join("slots"), self.budgets.device)?;
        self.counter += 1;
        let id = format!(
            "{SESSION_ID_PREFIX}{}-{}-{}",
            self.instance,
            self.counter,
            hex(&random)
        );
        let mut dirs = SessionDirs::under(sessions_root.join(&id));
        dirs.persistent_profile = options.profile.as_ref().map(|lease| lease.data_dir.clone());
        if std::fs::symlink_metadata(&dirs.root).is_ok() {
            return Err(ProviderError::new(
                FailureCode::InternalError,
                "a new browser session's directory already exists",
            ));
        }
        if let Err(error) = dirs.create() {
            remove_tree(&dirs.root);
            return Err(error);
        }
        let worker = match start(&id, &dirs) {
            Ok(worker) => worker,
            Err(error) => {
                remove_tree(&dirs.root);
                return Err(error);
            }
        };
        let session = BrokerSession {
            id: id.clone(),
            client: client.to_owned(),
            task: task.map(str::to_owned),
            dirs,
            created_ms: now_ms,
            mode: options.mode,
            profile: options.profile,
            worker,
            page_id: None,
            actions: 0,
            actions_budget: self.budgets.actions_per_session,
            receipts: VecDeque::new(),
            receipts_budget: self.budgets.receipts_per_session,
            receipts_dropped: 0,
            last_receipt_sha256: String::new(),
            next_seq: 1,
            audit: self.audit.clone(),
            evidence: self.evidence.clone(),
            observations: BTreeMap::new(),
            targets: BTreeMap::new(),
            targets_page: None,
            latency_total_ms: 0,
            latency_max_ms: 0,
            _slot: slot,
        };
        // SG-000135 OB-05: the session's start, chained (the task label as a
        // digest only: it is the caller's text).
        session.chain_session_event(json!({
            "source": SOURCE_SESSION,
            "event": "session_start",
            "session_id": session.id,
            "mode": session.mode.as_str(),
            "profile": session.profile_name(),
            "task_sha256": session
                .task
                .as_deref()
                .map(|task| crate::browser_receipts::sha256_hex(task.as_bytes())),
            "at_ms": now_ms,
        }));
        Ok(self.sessions.entry(id).or_insert(session))
    }

    /// The open session `id`, if `client` owns it and its worker still
    /// answers. A session whose worker is gone ends here.
    pub(crate) fn session(
        &mut self,
        client: &str,
        id: &str,
    ) -> Result<&mut BrokerSession<W>, ProviderError> {
        self.check_owned(client, id)?;
        let usable = self
            .sessions
            .get_mut(id)
            .map(|session| session.worker.is_usable())
            .unwrap_or(false);
        if !usable {
            self.end(id, EndReason::HostLost);
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "the browser session's worker ended; create a new session",
            ));
        }
        self.sessions.get_mut(id).ok_or_else(unknown_session)
    }

    /// The open session `id`, for reading only (no liveness probe).
    pub(crate) fn peek(&self, client: &str, id: &str) -> Result<&BrokerSession<W>, ProviderError> {
        self.check_owned(client, id)?;
        self.sessions.get(id).ok_or_else(unknown_session)
    }

    fn check_owned(&self, client: &str, id: &str) -> Result<(), ProviderError> {
        let instance = parse_session_id(id)?;
        if instance != self.instance {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "that browser session belongs to an earlier orceld run; create a new session",
            ));
        }
        let Some(session) = self.sessions.get(id) else {
            if let Some((_, reason)) = self.ended.iter().find(|(ended, _)| ended == id) {
                return Err(ProviderError::new(
                    FailureCode::TargetStale,
                    format!("that browser session ended: {}", reason.as_str()),
                ));
            }
            return Err(unknown_session());
        };
        if session.client != client {
            return Err(ProviderError::new(
                FailureCode::CapabilityDenied,
                "that browser session belongs to another client",
            ));
        }
        Ok(())
    }

    /// Close `client`'s session `id`.
    pub(crate) fn close(&mut self, client: &str, id: &str) -> Result<EndReport, ProviderError> {
        self.check_owned(client, id)?;
        self.end(id, EndReason::Closed).ok_or_else(unknown_session)
    }

    /// The MCP session `client` ended: every session it holds ends. Each
    /// local MCP session starts its own orceld, which ends every session
    /// when its input closes (`end_all`); this is the per-client form for a
    /// transport whose orceld outlives one client.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn end_client(&mut self, client: &str) -> Vec<EndReport> {
        self.profile_approvals
            .retain(|(_, owner, _)| owner != client);
        let ids: Vec<String> = self
            .sessions
            .values()
            .filter(|session| session.client == client)
            .map(|session| session.id.clone())
            .collect();
        ids.iter()
            .filter_map(|id| self.end(id, EndReason::McpSessionEnded))
            .collect()
    }

    /// End every session (emergency stop, or orceld's input closed).
    pub(crate) fn end_all(&mut self, reason: EndReason) -> Vec<EndReport> {
        // SG-000135 OB-04: no profile approval outlives an emergency stop,
        // a moved or unverifiable approval epoch, or the end of the sessions.
        self.profile_approvals.clear();
        let ids: Vec<String> = self.sessions.keys().cloned().collect();
        let reports = ids.iter().filter_map(|id| self.end(id, reason)).collect();
        self.retry_pending_removal();
        // Nothing of this instance is left; its directory goes too.
        let _ = std::fs::remove_dir(self.sessions_root());
        reports
    }

    fn end(&mut self, id: &str, reason: EndReason) -> Option<EndReport> {
        let mut session = self.sessions.remove(id)?;
        let root = session.dirs.root.clone();
        let (last_receipt, recorded) = (
            session.last_receipt_sha256.clone(),
            session.next_seq.saturating_sub(1),
        );
        let ended_session = SessionEnd {
            client: session.client.clone(),
            audit: session.audit.clone(),
        };
        let persistent_profile = session.profile_name().map(str::to_owned);
        let profile = session.profile.take();
        // The worker first; the persistent profile's lock is released only
        // after the worker is confirmed gone. If it is not, the profile stays
        // locked (quarantined) for this orceld's life.
        let worker_ended = session.worker.shutdown();
        let profile_quarantined = match profile {
            Some(lease) if !worker_ended => {
                self.quarantined.push(lease);
                true
            }
            _ => false,
        };
        // The worker removes its own profile on a clean shutdown; the
        // session's directory (profiles, staging, page store) goes here,
        // retried while a just-ended process may still hold a file, then
        // kept for a later retry.
        let mut profile_removed = false;
        for attempt in 0..REMOVAL_ATTEMPTS {
            if remove_tree(&root) {
                profile_removed = true;
                break;
            }
            if attempt + 1 < REMOVAL_ATTEMPTS {
                std::thread::sleep(std::time::Duration::from_millis(
                    50 * u64::from(attempt + 1),
                ));
            }
        }
        if !profile_removed {
            self.pending_removal.push(root);
        }
        if self.ended.len() >= ENDED_MEMORY {
            self.ended.pop_front();
        }
        self.ended.push_back((id.to_owned(), reason));
        // SG-000135 OB-05: the session's end and its last receipt, chained.
        ended_session.chain(json!({
            "source": SOURCE_SESSION,
            "event": "session_end",
            "session_id": id,
            "reason": reason.as_str(),
            "actions_recorded": recorded,
            "last_receipt_sha256": last_receipt,
            "worker_ended": worker_ended,
            "profile_removed": profile_removed,
            "profile_quarantined": profile_quarantined,
        }));
        Some(EndReport {
            session_id: id.to_owned(),
            reason,
            worker_ended,
            profile_removed,
            persistent_profile,
            profile_quarantined,
        })
    }

    /// SG-000135 OB-04: whether the owner already approved `client` using
    /// the persistent profile `name` in `workspace` in this orceld, since
    /// the last time every session ended.
    pub(crate) fn profile_approved(&self, workspace: &str, client: &str, name: &str) -> bool {
        self.profile_approvals
            .contains(&(workspace.to_owned(), client.to_owned(), name.to_owned()))
    }

    /// SG-000135 OB-04: record that the owner approved `client` using the
    /// persistent profile `name` in `workspace`.
    pub(crate) fn note_profile_approved(&mut self, workspace: &str, client: &str, name: &str) {
        self.profile_approvals
            .insert((workspace.to_owned(), client.to_owned(), name.to_owned()));
    }

    /// The open sessions of `client`, in id order.
    #[cfg(test)]
    pub(crate) fn client_sessions(&self, client: &str) -> Vec<&BrokerSession<W>> {
        self.sessions
            .values()
            .filter(|session| session.client == client)
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn open_count(&self) -> usize {
        self.sessions.len()
    }

    /// `browser_task_status`: the session, its budgets and its receipts.
    pub(crate) fn status(&self, client: &str, id: &str) -> Result<Value, ProviderError> {
        let session = self.peek(client, id)?;
        Ok(json!({
            "session_id": session.id,
            "task": session.task,
            "state": "open",
            "page_id": session.page_id,
            "created_at_ms": session.created_ms,
            "actions_used": session.actions,
            "actions_budget": session.actions_budget,
            "receipts": session.receipts().map(Receipt::to_json).collect::<Vec<_>>(),
            "receipts_dropped": session.receipts_dropped,
            "receipt_contract": RECEIPT_CONTRACT,
            "last_receipt_sha256": session.last_receipt_sha256,
            "measured": session.measured_json(),
            "mode": session.mode.as_str(),
            "no_interference": session.mode.no_interference(),
            "profile_mode": if session.profile.is_some() { "persistent" } else { "ephemeral" },
            "profile": session.profile_name(),
        }))
    }
}

/// SG-000135 OB-05: what a session's end event needs once the session is gone.
struct SessionEnd {
    client: String,
    audit: Option<std::sync::Arc<orcel_audit::ChainWriter>>,
}

impl SessionEnd {
    fn chain(&self, detail: Value) {
        if let Some(chain) = &self.audit {
            let _ = chain.append(orcel_audit::EventDraft {
                principal_id: Some(self.client.clone()),
                capability: Some("browser.session".to_owned()),
                operation: Some("session_end".to_owned()),
                ..orcel_audit::EventDraft::new(
                    orcel_contracts::event::AuditEventKind::Dispatch,
                    detail,
                )
            });
        }
    }
}

/// SG-000135 OB-07: one page of a session that waits for the person
/// ("Needs you"), as the challenge detector last reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NeedsYou {
    pub page_id: String,
    /// `sign_in`, `mfa`, `passkey`, `captcha` or `other` (the detector could
    /// not answer, so the page is held).
    pub kind: &'static str,
    /// The detector's closed signal names.
    pub signals: Vec<String>,
    /// The detector no longer sees it; the page waits out the quiet period.
    pub clearing: bool,
}

/// SG-000135 OB-07: why a page needs the person, in fixed words (never page
/// text).
fn needs_you_reason(kind: &str) -> &'static str {
    match kind {
        "captcha" => "a CAPTCHA or bot check is on the page; Orcel never solves or skips one",
        "mfa" => "the page asks for a one-time code or another second factor; Orcel never enters one",
        "sign_in" => "the page asks someone to sign in; Orcel never types a password, and the browser's own saved sign-in or the person completes it",
        "passkey" => "the page asks for a passkey or security key; only the person can answer it",
        _ => "Orcel could not check this page for a sign-in, code, passkey or CAPTCHA, so it waits for the person",
    }
}

/// SG-000135 OB-07: the `needs_you` list a reply and `browser_task_status`
/// carry: per waiting page its id, kind, closed signals, a fixed reason,
/// whether the detector already sees it gone, and the handoff for the
/// session's mode. A Shadow session has no window the person could use:
/// its challenge ends the mission there, and the person completes the check
/// in a Visible session (with a persistent profile, a sign-in carries over
/// to the next Shadow run). A Visible session's person uses its window.
pub(crate) fn needs_you_json(mode: SessionMode, pages: &[NeedsYou]) -> Value {
    let handoff = match mode {
        SessionMode::Visible => "visible_window",
        SessionMode::Shadow => "rerun_in_visible",
    };
    let guidance = match mode {
        SessionMode::Visible => "the person completes it in this session's window; once it no longer needs you (about three seconds after it is gone), observe the page again before acting",
        SessionMode::Shadow => "a Shadow session has no window for the person: close this session; the person completes the check in a Visible session (a persistent profile keeps the sign-in), then run the task again",
    };
    Value::Array(
        pages
            .iter()
            .map(|page| {
                json!({
                    "page_id": page.page_id,
                    "kind": page.kind,
                    "signals": page.signals,
                    "reason": needs_you_reason(page.kind),
                    "clearing": page.clearing,
                    "handoff": handoff,
                    "guidance": guidance,
                })
            })
            .collect(),
    )
}

fn unknown_session() -> ProviderError {
    ProviderError::new(
        FailureCode::TargetStale,
        "no such browser session; create one with browser_session_create",
    )
}

/// The instance part of a well-formed session id
/// (`bs-<16 hex>-<counter>-<16 hex>`), or a typed refusal.
pub(crate) fn parse_session_id(id: &str) -> Result<&str, ProviderError> {
    let malformed = || ProviderError::new(FailureCode::InvalidRequest, "session_id is malformed");
    let rest = id.strip_prefix(SESSION_ID_PREFIX).ok_or_else(malformed)?;
    let mut parts = rest.split('-');
    let (Some(instance), Some(counter), Some(random), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(malformed());
    };
    let lower_hex = |part: &str| {
        part.len() == ID_HEX_CHARS
            && part
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let counter_ok = !counter.is_empty()
        && counter.len() <= MAX_COUNTER_DIGITS
        && counter.bytes().all(|b| b.is_ascii_digit())
        && !counter.starts_with('0');
    if !lower_hex(instance) || !counter_ok || !lower_hex(random) {
        return Err(malformed());
    }
    Ok(instance)
}

/// A task label: short, printable, one line. It names the session for
/// the person; it grants nothing.
pub(crate) fn check_task(task: &str) -> Result<(), ProviderError> {
    if task.is_empty()
        || task.chars().count() > MAX_TASK_CHARS
        || task.chars().any(|c| c.is_control())
    {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            format!("task is one line of 1 to {MAX_TASK_CHARS} characters"),
        ));
    }
    Ok(())
}

/// A fresh instance id for this orceld: 16 lowercase hex characters.
pub(crate) fn instance_id(random: [u8; 8]) -> String {
    hex(&random)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A test worker: it writes a marker into its session's profile root
    /// (as a host's profile would hold cookies) and records its shutdown.
    struct TestWorker {
        profile_marker: PathBuf,
        usable: Rc<RefCell<bool>>,
        shutdowns: Rc<RefCell<Vec<PathBuf>>>,
    }

    impl SessionWorker for TestWorker {
        fn is_usable(&mut self) -> bool {
            *self.usable.borrow()
        }
        fn shutdown(self) -> bool {
            self.shutdowns
                .borrow_mut()
                .push(self.profile_marker.clone());
            // OB-04: a worker whose profile holds "stuck" cannot be
            // confirmed gone.
            !matches!(std::fs::read(&self.profile_marker), Ok(bytes) if bytes == b"stuck")
        }
    }

    struct Scene {
        root: PathBuf,
        shutdowns: Rc<RefCell<Vec<PathBuf>>>,
        usable: Rc<RefCell<bool>>,
        seed: u8,
    }

    impl Scene {
        fn new(name: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let root = std::env::temp_dir()
                .join(format!("orcel-ob01-{name}-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&root).unwrap();
            Self {
                root,
                shutdowns: Rc::new(RefCell::new(Vec::new())),
                usable: Rc::new(RefCell::new(true)),
                seed: 0,
            }
        }

        fn broker(&self, instance: &str, budgets: Budgets) -> Broker<TestWorker> {
            Broker::start(self.root.join("broker"), instance.to_owned(), budgets).unwrap()
        }

        fn random(&mut self) -> [u8; 8] {
            self.seed = self.seed.wrapping_add(1);
            [self.seed, 1, 2, 3, 4, 5, 6, 7]
        }

        fn create(
            &mut self,
            broker: &mut Broker<TestWorker>,
            client: &str,
            secret: &str,
        ) -> Result<String, ProviderError> {
            let (shutdowns, usable) = (Rc::clone(&self.shutdowns), Rc::clone(&self.usable));
            let random = self.random();
            broker
                .create(client, Some("task"), random, 1, move |_, dirs| {
                    let marker = dirs.profiles.join("cookies.txt");
                    std::fs::write(&marker, secret).unwrap();
                    Ok(TestWorker {
                        profile_marker: marker,
                        usable,
                        shutdowns,
                    })
                })
                .map(|session| session.id.clone())
        }
    }

    impl Drop for Scene {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    const INSTANCE: &str = "0123456789abcdef";
    const OTHER_INSTANCE: &str = "fedcba9876543210";

    #[test]
    fn create_mints_a_bound_id_and_a_private_profile_dir_under_the_broker_root() {
        let mut scene = Scene::new("create");
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        let id = scene.create(&mut broker, "client-a", "a-cookie").unwrap();
        assert_eq!(parse_session_id(&id).unwrap(), INSTANCE);
        let session = broker.peek("client-a", &id).unwrap();
        assert_eq!(session.task.as_deref(), Some("task"));
        assert!(session
            .dirs
            .profiles
            .starts_with(scene.root.join("broker").join("sessions").join(INSTANCE)));
        assert!(session.dirs.profiles.join("cookies.txt").exists());
        assert_eq!(session.page_id, None);
        let status = broker.status("client-a", &id).unwrap();
        assert_eq!(status["state"], "open");
        assert_eq!(status["profile_mode"], "ephemeral");
        assert_eq!(status["receipts"], json!([]));
    }

    #[test]
    fn close_shuts_the_worker_down_and_removes_the_profile() {
        let mut scene = Scene::new("close");
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        let id = scene.create(&mut broker, "client-a", "a-cookie").unwrap();
        let root = broker.peek("client-a", &id).unwrap().dirs.root.clone();
        let report = broker.close("client-a", &id).unwrap();
        assert_eq!(report.reason, EndReason::Closed);
        assert!(report.worker_ended);
        assert!(report.profile_removed);
        assert!(!root.exists());
        assert_eq!(scene.shutdowns.borrow().len(), 1);
        // The id is now refused, with the reason.
        let again = broker.close("client-a", &id).unwrap_err();
        assert_eq!(again.code, FailureCode::TargetStale);
        assert!(again.message.contains("closed"), "{}", again.message);
        assert!(broker.session("client-a", &id).is_err());
        assert_eq!(broker.open_count(), 0);
    }

    #[test]
    fn per_client_and_device_budgets_refuse_before_any_worker_starts() {
        let mut scene = Scene::new("limits");
        let budgets = Budgets {
            per_client: 2,
            device: 3,
            ..Budgets::DEFAULT
        };
        let mut broker = scene.broker(INSTANCE, budgets);
        let a1 = scene.create(&mut broker, "client-a", "1").unwrap();
        scene.create(&mut broker, "client-a", "2").unwrap();
        let refused = scene.create(&mut broker, "client-a", "3").unwrap_err();
        assert_eq!(refused.code, FailureCode::OutputLimit);
        assert!(refused.message.contains("client"));
        // Another client still fits under the device cap of three...
        scene.create(&mut broker, "client-b", "4").unwrap();
        // ...and a second orceld on the device shares that cap: its slot
        // files are the same, so it finds them all locked.
        let mut second = scene.broker(OTHER_INSTANCE, budgets);
        let device = scene.create(&mut second, "client-c", "5").unwrap_err();
        assert_eq!(device.code, FailureCode::OutputLimit);
        assert!(device.message.contains("device"));
        assert_eq!(scene.shutdowns.borrow().len(), 0, "nothing started");
        // Closing one frees its slot for the other orceld.
        broker.close("client-a", &a1).unwrap();
        scene.create(&mut second, "client-c", "6").unwrap();
    }

    #[test]
    fn a_failed_worker_start_leaves_no_directory_and_no_slot() {
        let mut scene = Scene::new("failstart");
        let budgets = Budgets {
            device: 1,
            ..Budgets::DEFAULT
        };
        let mut broker = scene.broker(INSTANCE, budgets);
        let failed = broker
            .create("client-a", None, [9; 8], 1, |_, _| {
                Err::<TestWorker, _>(ProviderError::new(
                    FailureCode::ProviderUnavailable,
                    "no engine",
                ))
            })
            .map(|_| ());
        assert_eq!(failed.unwrap_err().code, FailureCode::ProviderUnavailable);
        let sessions = scene.root.join("broker").join("sessions").join(INSTANCE);
        assert_eq!(
            std::fs::read_dir(&sessions).map(|d| d.count()).unwrap_or(0),
            0
        );
        // The single device slot is free again.
        scene.create(&mut broker, "client-a", "ok").unwrap();
    }

    #[test]
    fn sessions_are_isolated_from_each_other_and_from_other_clients() {
        let mut scene = Scene::new("isolation");
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        let a = scene.create(&mut broker, "client-a", "a-secret").unwrap();
        let b = scene.create(&mut broker, "client-b", "b-secret").unwrap();
        let (a_dirs, b_dirs) = (
            broker.peek("client-a", &a).unwrap().dirs.clone(),
            broker.peek("client-b", &b).unwrap().dirs.clone(),
        );
        assert_ne!(a_dirs.root, b_dirs.root);
        assert!(!a_dirs.root.starts_with(&b_dirs.root) && !b_dirs.root.starts_with(&a_dirs.root));
        assert_eq!(
            std::fs::read_to_string(a_dirs.profiles.join("cookies.txt")).unwrap(),
            "a-secret"
        );
        assert_eq!(
            std::fs::read_to_string(b_dirs.profiles.join("cookies.txt")).unwrap(),
            "b-secret"
        );
        // Another client never reaches a session it does not own.
        for result in [
            broker.session("client-b", &a).map(|_| ()),
            broker.peek("client-b", &a).map(|_| ()),
            broker.close("client-b", &a).map(|_| ()),
            broker.status("client-b", &a).map(|_| ()),
        ] {
            assert_eq!(result.unwrap_err().code, FailureCode::CapabilityDenied);
        }
        // Receipts stay with their session.
        broker
            .session("client-a", &a)
            .unwrap()
            .record(record("browser_open", "done"), 5);
        assert_eq!(broker.peek("client-a", &a).unwrap().receipts().count(), 1);
        assert_eq!(broker.peek("client-b", &b).unwrap().receipts().count(), 0);
        // Closing one leaves the other's profile untouched.
        broker.close("client-a", &a).unwrap();
        assert!(!a_dirs.root.exists());
        assert!(b_dirs.profiles.join("cookies.txt").exists());
        assert!(broker.session("client-b", &b).is_ok());
    }

    #[test]
    fn an_id_from_an_earlier_orceld_or_a_malformed_id_is_refused() {
        let mut scene = Scene::new("restart");
        let mut first = scene.broker(INSTANCE, Budgets::DEFAULT);
        let id = scene.create(&mut first, "client-a", "x").unwrap();
        first.end_all(EndReason::McpSessionEnded);
        // A restarted orceld has a new instance id: the old id is stale.
        let mut second = scene.broker(OTHER_INSTANCE, Budgets::DEFAULT);
        let stale = second.session("client-a", &id).map(|_| ()).unwrap_err();
        assert_eq!(stale.code, FailureCode::TargetStale);
        assert!(stale.message.contains("earlier orceld"));
        for bad in [
            "",
            "bs-",
            "bs-0123456789abcdef-1",
            "bs-0123456789ABCDEF-1-0001020304050607",
            "bs-0123456789abcdef-01-0001020304050607",
            "bs-0123456789abcdef-1-0001020304050607-x",
            "bs-0123456789abcdef-1234567-0001020304050607",
            "pg-0123456789abcdef-1-0001020304050607",
            "bs-0123456789abcdef-1-../../profile0",
        ] {
            assert_eq!(
                second
                    .session("client-a", bad)
                    .map(|_| ())
                    .unwrap_err()
                    .code,
                FailureCode::InvalidRequest,
                "{bad}"
            );
        }
    }

    #[test]
    fn emergency_stop_ends_every_session_of_every_client() {
        let mut scene = Scene::new("estop");
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        let a = scene.create(&mut broker, "client-a", "1").unwrap();
        let b = scene.create(&mut broker, "client-b", "2").unwrap();
        let reports = broker.end_all(EndReason::EmergencyStop);
        assert_eq!(reports.len(), 2);
        assert!(reports
            .iter()
            .all(|r| r.reason == EndReason::EmergencyStop && r.worker_ended && r.profile_removed));
        assert_eq!(broker.open_count(), 0);
        assert!(!scene
            .root
            .join("broker")
            .join("sessions")
            .join(INSTANCE)
            .exists());
        for (client, id) in [("client-a", &a), ("client-b", &b)] {
            let refused = broker.session(client, id).map(|_| ()).unwrap_err();
            assert!(
                refused.message.contains("emergency_stop"),
                "{}",
                refused.message
            );
        }
        // The broker serves new sessions afterwards.
        scene.create(&mut broker, "client-a", "3").unwrap();
    }

    #[test]
    fn the_end_of_an_mcp_session_ends_only_its_own_sessions() {
        let mut scene = Scene::new("mcpend");
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        let a1 = scene.create(&mut broker, "client-a", "1").unwrap();
        let a2 = scene.create(&mut broker, "client-a", "2").unwrap();
        let b = scene.create(&mut broker, "client-b", "3").unwrap();
        let reports = broker.end_client("client-a");
        assert_eq!(reports.len(), 2);
        assert!(reports
            .iter()
            .all(|r| r.reason == EndReason::McpSessionEnded && r.profile_removed));
        for id in [&a1, &a2] {
            let refused = broker.session("client-a", id).map(|_| ()).unwrap_err();
            assert!(refused.message.contains("mcp_session_ended"));
        }
        assert!(broker.session("client-b", &b).is_ok());
        assert_eq!(broker.client_sessions("client-a").len(), 0);
        assert_eq!(broker.client_sessions("client-b").len(), 1);
    }

    #[test]
    fn a_session_whose_worker_died_ends_and_is_refused() {
        let mut scene = Scene::new("hostlost");
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        let id = scene.create(&mut broker, "client-a", "1").unwrap();
        let root = broker.peek("client-a", &id).unwrap().dirs.root.clone();
        *scene.usable.borrow_mut() = false;
        let refused = broker.session("client-a", &id).map(|_| ()).unwrap_err();
        assert_eq!(refused.code, FailureCode::TargetStale);
        assert!(!root.exists(), "its profile is removed");
        let again = broker.session("client-a", &id).map(|_| ()).unwrap_err();
        assert!(again.message.contains("host_lost"));
    }

    fn record(action: &str, outcome: &str) -> ActionRecord {
        ActionRecord {
            action: action.to_owned(),
            page_id: Some("pg-1".into()),
            generation_before: Some(0),
            generation_after: Some(1),
            outcome: outcome.to_owned(),
            evidence_kind: "reply".into(),
            evidence_sha256: Some("ab".repeat(32)),
            ..ActionRecord::default()
        }
    }

    /// SG-000135 OB-05: a broker writing to a fresh chain at `name` in the
    /// scene, with an evidence store beside it.
    fn chained(
        scene: &Scene,
        instance: &str,
        name: &str,
    ) -> Result<(Broker<TestWorker>, PathBuf, EvidenceStore), String> {
        let chain_path = scene.root.join(format!("{name}-chain.jsonl"));
        let chain = std::sync::Arc::new(
            orcel_audit::ChainWriter::open(&chain_path, orcel_audit::ORCELD_LOG)
                .map_err(|e| e.to_string())?,
        );
        let dir = scene.root.join(format!("{name}-evidence"));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let store = EvidenceStore::at(dir);
        let broker = scene
            .broker(instance, Budgets::DEFAULT)
            .with_audit_chain(Some(chain))
            .with_evidence(Some(store.clone()));
        Ok((broker, chain_path, store))
    }

    fn events(chain_path: &Path) -> Result<Vec<orcel_contracts::event::AuditEvent>, String> {
        std::fs::read_to_string(chain_path)
            .map_err(|e| e.to_string())?
            .lines()
            .map(|line| serde_json::from_str(line).map_err(|e| e.to_string()))
            .collect()
    }

    fn draft(action: &str, node: Option<&str>) -> IntentDraft {
        IntentDraft {
            action: action.to_owned(),
            page_id: Some("pg-1".into()),
            generation_before: Some(3),
            origin_before: Some("https://fixture.test".into()),
            url_sha256: None,
            target: Some(ReceiptTarget {
                page_id: Some("pg-1".into()),
                node_id: node.map(str::to_owned),
                ..ReceiptTarget::default()
            }),
            approval_epoch: Some(7),
        }
    }

    /// One action as live dispatch runs it: intent, then receipt.
    fn act_once(
        session: &mut BrokerSession<TestWorker>,
        intent: IntentDraft,
        record: ActionRecord,
        at: u64,
    ) -> Result<Receipt, String> {
        session.begin_action().map_err(|e| e.message)?;
        let intent = session.begin_intent(intent, at).map_err(|e| e.message)?;
        Ok(session.record(
            ActionRecord {
                intent: Some(intent),
                ..record
            },
            at + 5,
        ))
    }

    /// SG-000135 OB-05 (FA-J): every action family is written to the chain
    /// as an intent before it runs and a receipt after; each receipt names
    /// its authority, mode, origin, target, evidence, outcome, times and both
    /// chain places, recomputes from its fields, and `audit-verify
    /// --receipts` verifies every one of them and their evidence files.
    #[test]
    fn ob05_every_action_family_is_receipted_on_the_chain_and_verifies() -> Result<(), String> {
        use orcel_contracts::event::AuditEventKind;
        let mut scene = Scene::new("ob05-families");
        let (mut broker, chain_path, store) = chained(&scene, INSTANCE, "families")?;
        let id = scene
            .create(&mut broker, "client-a", "1")
            .map_err(|e| e.message)?;
        let session = broker.session("client-a", &id).map_err(|e| e.message)?;
        // A snapshot keeps its frame as an evidence file, and its nodes name
        // the targets of the next actions.
        let nodes = json!([{"node_id": "n7", "role": "textbox", "name_digest": "k".repeat(64),
            "value_digest": "v", "redacted": false, "children": []}]);
        let frame = serde_json::to_string(&nodes).map_err(|e| e.to_string())?;
        let frame_file = session.keep_evidence(EvidenceKind::Snapshot, frame.as_bytes());
        let snapshot = act_once(
            session,
            draft("browser_snapshot", None),
            ActionRecord {
                action: "browser_snapshot".into(),
                outcome: "done".into(),
                evidence_kind: "observe".into(),
                evidence_sha256: Some(frame_file.sha256.clone()),
                evidence_files: vec![frame_file.clone()],
                approval_epoch: Some(7),
                ..record("browser_snapshot", "done")
            },
            100,
        )?;
        session.note_observation("pg-1", 3, &frame_file.sha256, &nodes);
        let target = session.target_of(Some("pg-1"), Some("n7"));
        assert_eq!(target.role.as_deref(), Some("textbox"));
        assert_eq!(target.name_digest, Some("k".repeat(64)));
        let shot = session.keep_evidence(EvidenceKind::Screenshot, b"\x89PNG masked");
        let families: Vec<(&str, Option<&str>, ActionRecord)> = vec![
            (
                "browser_open",
                None,
                ActionRecord {
                    url_sha256: Some(crate::browser_receipts::url_digest(
                        "https://fixture.test/a",
                    )),
                    record_id: Some("apr-1".into()),
                    ..record("browser_open", "done")
                },
            ),
            (
                "browser_click",
                Some("n7"),
                ActionRecord {
                    lease_id: Some("al-1".into()),
                    lease_epoch: Some(4),
                    ..record("browser_click", "done")
                },
            ),
            (
                "browser_fill",
                Some("n7"),
                ActionRecord {
                    record_id: Some("apr-2".into()),
                    ..record("browser_fill", "done")
                },
            ),
            (
                "browser_select",
                Some("n7"),
                record("browser_select", "done"),
            ),
            ("browser_tabs", None, record("browser_tabs", "done")),
            ("browser_verify", None, record("browser_verify", "done")),
            ("browser_extract", None, record("browser_extract", "done")),
            (
                "browser_screenshot",
                None,
                ActionRecord {
                    evidence_kind: "screenshot".into(),
                    evidence_sha256: Some(shot.sha256.clone()),
                    evidence_files: vec![shot.clone()],
                    ..record("browser_screenshot", "done")
                },
            ),
            (
                "browser_click",
                Some("n7"),
                ActionRecord {
                    failure_code: Some("HUMAN_VERIFICATION_REQUIRED".into()),
                    evidence_kind: "none".into(),
                    evidence_sha256: None,
                    ..record("browser_click", "refused")
                },
            ),
        ];
        let mut receipts = vec![snapshot];
        for (n, (action, node, record)) in families.into_iter().enumerate() {
            let target = session.target_of(Some("pg-1"), node);
            let pre_evidence = session.pre_evidence("pg-1");
            receipts.push(act_once(
                session,
                IntentDraft {
                    target: Some(target.clone()),
                    ..draft(action, node)
                },
                ActionRecord {
                    target: Some(target),
                    pre_evidence,
                    approval_epoch: Some(7),
                    ..record
                },
                200 + 10 * n as u64,
            )?);
        }
        let events = events(&chain_path)?;
        // The opening event, the session's start, and two per action.
        assert_eq!(events.len(), 2 + 2 * receipts.len(), "{events:?}");
        assert_eq!(events[1].detail["event"], "session_start");
        for (n, receipt) in receipts.iter().enumerate() {
            let (intent_event, receipt_event) = (&events[2 + 2 * n], &events[3 + 2 * n]);
            assert_eq!(intent_event.kind, AuditEventKind::Dispatch);
            assert_eq!(intent_event.detail["source"], "browser_intent");
            assert_eq!(receipt_event.detail["source"], "browser_receipt");
            assert_eq!(receipt_event.principal_id.as_deref(), Some("client-a"));
            assert_eq!(
                receipt_event.operation.as_deref(),
                Some(receipt.action.as_str())
            );
            let json = receipt.to_json();
            assert_eq!(json["contract"], RECEIPT_CONTRACT);
            assert_eq!(json["provisional"], false);
            assert_eq!(json["mode"], "shadow");
            assert_eq!(json["origin_before"], "https://fixture.test");
            assert_eq!(json["authority"]["approval_epoch"], 7);
            assert_eq!(json["duration_ms"], 5);
            assert_eq!(
                json["intent_sha256"],
                intent_event.detail["intent"]["intent_sha256"]
            );
            assert_eq!(json["intent_audit"]["seq"], intent_event.seq);
            assert_eq!(json["intent_audit"]["digest"], intent_event.digest.as_str());
            assert_eq!(json["audit"]["seq"], receipt_event.seq);
            assert_eq!(receipt.receipt_sha256, receipt_digest(receipt));
            assert_eq!(
                receipt_event.detail["receipt"]["receipt_sha256"],
                receipt.receipt_sha256.as_str()
            );
        }
        let by_action = |action: &str| {
            receipts
                .iter()
                .find(|receipt| receipt.action == action)
                .map(Receipt::to_json)
                .unwrap_or_default()
        };
        assert_eq!(by_action("browser_open")["authority"]["kind"], "approval");
        assert_eq!(by_action("browser_click")["authority"]["kind"], "lease");
        assert_eq!(by_action("browser_click")["authority"]["lease_epoch"], 4);
        assert_eq!(by_action("browser_click")["target"]["role"], "textbox");
        assert_eq!(
            by_action("browser_fill")["pre_evidence"]["sha256"],
            frame_file.sha256.as_str()
        );
        assert_eq!(by_action("browser_select")["authority"]["kind"], "none");
        assert_eq!(
            by_action("browser_screenshot")["evidence_files"][0]["stored"],
            true
        );
        let refused = receipts.last().map(Receipt::to_json).unwrap_or_default();
        assert_eq!(refused["result"], "refused");
        assert_eq!(refused["effect"], "none");
        assert_eq!(refused["needs_person"], true);
        // The session's end is chained with its last receipt.
        let last = receipts.last().map(|r| r.receipt_sha256.clone());
        broker.close("client-a", &id).map_err(|e| e.message)?;
        let events = self::events(&chain_path)?;
        let end = events.last().ok_or("no end event")?;
        assert_eq!(end.detail["event"], "session_end");
        assert_eq!(end.detail["last_receipt_sha256"], json!(last));
        // The chain and every receipt verify, evidence files included.
        let report = orcel_audit::verify_file(&chain_path).map_err(|e| e.to_string())?;
        assert_eq!(report.verdict, orcel_audit::Verdict::Intact, "{report:?}");
        let verified = crate::browser_receipts::verify_receipts(&chain_path, Some(&store), None)?;
        assert!(
            !verified.broken && !verified.unrecorded,
            "{}",
            verified.value
        );
        assert_eq!(verified.value["receipts"], receipts.len());
        assert_eq!(verified.value["evidence"]["checked"], 2);
        // One receipt's inclusion, by its digest.
        let one = &receipts[3].receipt_sha256;
        let found = crate::browser_receipts::verify_receipts(&chain_path, Some(&store), Some(one))?;
        assert_eq!(found.value["receipt"]["found"], true, "{}", found.value);
        assert_eq!(found.value["receipt"]["digest_recomputes"], true);
        let absent = "0".repeat(64);
        let missing =
            crate::browser_receipts::verify_receipts(&chain_path, Some(&store), Some(&absent))?;
        assert!(missing.broken);
        assert_eq!(missing.value["receipt"]["found"], false);
        Ok(())
    }

    /// SG-000135 OB-05: nothing secret reaches the chain or a receipt: a URL
    /// with a token, a typed value and the page's cookies never appear, only
    /// the URL's digest and the page's origin.
    #[test]
    fn ob05_no_secret_reaches_the_chain_or_the_receipt() -> Result<(), String> {
        let mut scene = Scene::new("ob05-redaction");
        let (mut broker, chain_path, _store) = chained(&scene, INSTANCE, "redaction")?;
        let id = scene
            .create(&mut broker, "client-a", "COOKIE-VALUE-123")
            .map_err(|e| e.message)?;
        let session = broker.session("client-a", &id).map_err(|e| e.message)?;
        let secret_url = "https://fixture.test/reset?token=TOKEN-SECRET-456#frag-789";
        // A fill reply as live dispatch builds it never holds the value; even
        // a reply that did, only its URL's digest is kept.
        let reply =
            json!({"url": secret_url, "value": "TYPED-SECRET-hunter2", "record_id": "apr-9"});
        let receipt = act_once(
            session,
            IntentDraft {
                url_sha256: Some(crate::browser_receipts::url_digest(secret_url)),
                ..draft("browser_fill", Some("n2"))
            },
            ActionRecord {
                url_sha256: crate::browser_receipts::reply_url_digest(&reply),
                origin_after: Some("https://fixture.test".into()),
                ..record("browser_fill", "done")
            },
            10,
        )?;
        let text = std::fs::read_to_string(&chain_path).map_err(|e| e.to_string())?;
        let receipt_text = receipt.to_json().to_string();
        for secret in [
            "TOKEN-SECRET-456",
            "token=",
            "frag-789",
            "/reset",
            "TYPED-SECRET-hunter2",
            "COOKIE-VALUE-123",
        ] {
            assert!(!text.contains(secret), "the chain holds {secret}");
            assert!(!receipt_text.contains(secret), "the receipt holds {secret}");
        }
        assert_eq!(
            receipt.url_sha256.as_deref(),
            Some(crate::browser_receipts::url_digest(secret_url).as_str())
        );
        Ok(())
    }

    /// SG-000135 OB-05: a tampered receipt, a tampered or removed evidence
    /// file and a receipt with no intent are each found by the verifier.
    #[test]
    fn ob05_tampered_receipts_and_evidence_files_are_detected() -> Result<(), String> {
        let mut scene = Scene::new("ob05-tamper");
        let (mut broker, chain_path, store) = chained(&scene, INSTANCE, "tamper")?;
        let id = scene
            .create(&mut broker, "client-a", "1")
            .map_err(|e| e.message)?;
        let session = broker.session("client-a", &id).map_err(|e| e.message)?;
        let shot = session.keep_evidence(EvidenceKind::Screenshot, b"\x89PNG masked image");
        act_once(
            session,
            draft("browser_screenshot", None),
            ActionRecord {
                evidence_kind: "screenshot".into(),
                evidence_sha256: Some(shot.sha256.clone()),
                evidence_files: vec![shot.clone()],
                ..record("browser_screenshot", "done")
            },
            10,
        )?;
        let original = std::fs::read_to_string(&chain_path).map_err(|e| e.to_string())?;
        let verify = |store: Option<&EvidenceStore>| {
            crate::browser_receipts::verify_receipts(&chain_path, store, None)
        };
        assert!(!verify(Some(&store))?.broken);
        // The evidence file edited, then removed.
        let file = store.dir().join(format!("{}.png", shot.sha256));
        std::fs::write(&file, b"another image").map_err(|e| e.to_string())?;
        let report = verify(Some(&store))?;
        assert!(report.broken, "{}", report.value);
        assert_eq!(report.value["evidence"]["errors"][0]["check"], "mismatch");
        std::fs::remove_file(&file).map_err(|e| e.to_string())?;
        let report = verify(Some(&store))?;
        assert_eq!(report.value["evidence"]["errors"][0]["check"], "missing");
        // Without the folder the files are listed as not checked, never as
        // verified.
        let report = verify(None)?;
        assert!(!report.broken);
        assert_eq!(report.value["evidence"]["checked"], 0);
        // A receipt field edited in the chain: its digest no longer
        // recomputes (and the chain itself is broken).
        std::fs::write(
            &chain_path,
            original.replacen("\"result\":\"sent\"", "\"result\":\"refused\"", 1),
        )
        .map_err(|e| e.to_string())?;
        let report = verify(None)?;
        assert!(report.broken);
        assert_eq!(report.value["digest_errors"][0]["kind"], "receipt");
        assert_ne!(
            orcel_audit::verify_file(&chain_path)
                .map_err(|e| e.to_string())?
                .verdict,
            orcel_audit::Verdict::Intact
        );
        // An intent removed: its receipt names an intent that is not there.
        let without_intent: String = original
            .lines()
            .filter(|line| !line.contains("\"browser_intent\""))
            .map(|line| format!("{line}\n"))
            .collect();
        std::fs::write(&chain_path, without_intent).map_err(|e| e.to_string())?;
        let report = verify(None)?;
        assert!(report.broken);
        assert!(report.value["link_errors"]
            .to_string()
            .contains("no intent"));
        Ok(())
    }

    /// SG-000135 OB-05: write before dispatch. A chain that refuses the
    /// intent refuses the action with nothing sent; an intent whose receipt
    /// never came (orceld stopped between them) is reported
    /// DISPATCHED_UNRECORDED, and a receipt the chain refused is marked so.
    #[test]
    fn ob05_intent_before_dispatch_and_a_crash_between_is_detected() -> Result<(), String> {
        let mut scene = Scene::new("ob05-crash");
        let (mut broker, chain_path, _store) = chained(&scene, INSTANCE, "crash")?;
        let id = scene
            .create(&mut broker, "client-a", "1")
            .map_err(|e| e.message)?;
        let session = broker.session("client-a", &id).map_err(|e| e.message)?;
        act_once(
            session,
            draft("browser_open", None),
            record("browser_open", "done"),
            10,
        )?;
        // The intent of a click is written; orceld stops before its receipt.
        let lost = session
            .begin_intent(draft("browser_click", Some("n1")), 20)
            .map_err(|e| e.message)?;
        drop(lost);
        let report = crate::browser_receipts::verify_receipts(&chain_path, None, None)?;
        assert!(!report.broken && report.unrecorded, "{}", report.value);
        let open = &report.value["dispatched_unrecorded"][0];
        assert_eq!(open["action"], "browser_click");
        assert_eq!(open["seq"], 2);
        assert_eq!(open["state"], "DISPATCHED_UNRECORDED");
        // The CLI's exit code for it, with the chain intact.
        let (text, code) = crate::audit_chain::verify_with_held(&chain_path, None)?;
        let (_, code) = crate::audit_chain::with_receipts(&chain_path, text, code, None, None)?;
        assert_eq!(code, crate::browser_receipts::EXIT_RECEIPTS_UNRECORDED);
        // A chain that refuses writes: the next intent is refused, so the
        // action never runs.
        let text = std::fs::read_to_string(&chain_path).map_err(|e| e.to_string())?;
        std::fs::write(
            &chain_path,
            text.replacen("browser_open", "browser_tabs", 1),
        )
        .map_err(|e| e.to_string())?;
        let chain = std::sync::Arc::new(
            orcel_audit::ChainWriter::open(&chain_path, orcel_audit::ORCELD_LOG)
                .map_err(|e| e.to_string())?,
        );
        let mut broken = scene
            .broker("0123456789abcded", Budgets::DEFAULT)
            .with_audit_chain(Some(chain));
        let other = scene
            .create(&mut broken, "client-b", "2")
            .map_err(|e| e.message)?;
        let session = broken.session("client-b", &other).map_err(|e| e.message)?;
        let refused = session
            .begin_intent(draft("browser_click", Some("n1")), 30)
            .err()
            .ok_or("the intent should be refused")?;
        assert_eq!(refused.code, FailureCode::InternalError);
        assert!(
            refused.message.contains("nothing was sent"),
            "{}",
            refused.message
        );
        // A receipt the chain refuses is marked failed (live dispatch then
        // withholds the result and names it DISPATCHED_UNRECORDED).
        let receipt = session.record(record("browser_click", "done"), 31);
        assert!(
            matches!(&receipt.audit, ReceiptAudit::Failed(error) if error.contains("broken")),
            "{:?}",
            receipt.audit
        );
        assert!(receipt.to_json()["audit"]["error"].is_string());
        // Without a chain, receipts say so and are otherwise the same.
        let mut plain = scene.broker("0123456789abcdee", Budgets::DEFAULT);
        let third = scene
            .create(&mut plain, "client-c", "3")
            .map_err(|e| e.message)?;
        let session = plain.session("client-c", &third).map_err(|e| e.message)?;
        let receipt = act_once(
            session,
            draft("browser_open", None),
            record("browser_open", "done"),
            1,
        )?;
        assert_eq!(receipt.audit, ReceiptAudit::NotConfigured);
        assert!(receipt.to_json()["audit"].is_null());
        assert!(receipt.to_json()["intent_audit"].is_null());
        assert!(receipt.intent_sha256.is_some());
        Ok(())
    }

    /// SG-000135 OB-05: how each end of an action reads in its receipt,
    /// including a person taking over before the send (refused, nothing
    /// done) and during it (superseded).
    #[test]
    fn ob05_outcomes_map_to_what_completed_what_is_uncertain_and_who_is_needed() {
        let mut scene = Scene::new("ob05-outcomes");
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        let id = scene.create(&mut broker, "client-a", "1").unwrap();
        let session = broker.session("client-a", &id).unwrap();
        let cases = [
            ("done", None, false, "sent", "applied", false),
            ("done", None, true, "superseded", "applied", true),
            (
                "refused",
                Some("HUMAN_TAKEOVER"),
                false,
                "refused",
                "none",
                true,
            ),
            (
                "failed",
                Some("HUMAN_TAKEOVER"),
                false,
                "refused",
                "none",
                true,
            ),
            (
                "denied",
                Some("APPROVAL_DENIED"),
                false,
                "refused",
                "none",
                false,
            ),
            (
                "failed",
                Some("TARGET_STALE"),
                false,
                "failed",
                "none",
                false,
            ),
            (
                "unknown",
                Some("TARGET_STALE"),
                false,
                "unknown",
                "unknown",
                true,
            ),
        ];
        for (outcome, code, superseded, result, effect, person) in cases {
            let receipt = session.record(
                ActionRecord {
                    failure_code: code.map(str::to_owned),
                    superseded,
                    ..record("browser_click", outcome)
                },
                1,
            );
            let json = receipt.to_json();
            assert_eq!(json["outcome"], outcome);
            assert_eq!(
                (&json["result"], &json["effect"], &json["needs_person"]),
                (&json!(result), &json!(effect), &json!(person)),
                "{outcome} {code:?}"
            );
        }
        let status = broker.status("client-a", &id).unwrap();
        assert_eq!(status["receipt_contract"], RECEIPT_CONTRACT);
        assert_eq!(status["measured"]["actions_recorded"], 7);
    }
    #[test]
    fn receipts_chain_by_digest_and_stay_bounded() {
        let mut scene = Scene::new("receipts");
        let budgets = Budgets {
            receipts_per_session: 3,
            actions_per_session: 4,
            ..Budgets::DEFAULT
        };
        let mut broker = scene.broker(INSTANCE, budgets);
        let id = scene.create(&mut broker, "client-a", "1").unwrap();
        let session = broker.session("client-a", &id).unwrap();
        let mut previous = String::new();
        for n in 0..4u64 {
            session.begin_action().unwrap();
            let receipt = session.record(record("browser_click", "done"), 10 + n);
            assert_eq!(receipt.seq, n + 1);
            assert_eq!(receipt.previous_sha256, previous);
            assert_eq!(receipt.receipt_sha256, receipt_digest(&receipt));
            assert_eq!(receipt.receipt_sha256.len(), 64);
            previous = receipt.receipt_sha256.clone();
        }
        // The action budget is spent.
        assert_eq!(
            session.begin_action().unwrap_err().code,
            FailureCode::OutputLimit
        );
        assert_eq!(session.actions(), 4);
        let status = broker.status("client-a", &id).unwrap();
        assert_eq!(status["receipts"].as_array().map(Vec::len), Some(3));
        assert_eq!(status["receipts_dropped"], 1);
        assert_eq!(status["receipts"][0]["seq"], 2);
        assert_eq!(status["receipts"][0]["provisional"], false);
        assert_eq!(status["last_receipt_sha256"], previous);
        // A change to any field changes the digest.
        let mut receipt = broker
            .peek("client-a", &id)
            .unwrap()
            .receipts()
            .last()
            .cloned()
            .unwrap();
        let digest = receipt.receipt_sha256.clone();
        receipt.outcome = "failed".into();
        assert_ne!(receipt_digest(&receipt), digest);
    }

    #[test]
    fn ob07_needs_you_names_the_page_kind_and_handoff_and_never_page_text() {
        let pages = [NeedsYou {
            page_id: "pg-0123".into(),
            kind: "captcha",
            signals: vec!["captcha_widget".into()],
            clearing: false,
        }];
        let shadow = needs_you_json(SessionMode::Shadow, &pages);
        assert_eq!(shadow[0]["page_id"], "pg-0123");
        assert_eq!(shadow[0]["kind"], "captcha");
        assert_eq!(shadow[0]["signals"][0], "captcha_widget");
        assert_eq!(shadow[0]["handoff"], "rerun_in_visible");
        assert_eq!(shadow[0]["clearing"], false);
        let visible = needs_you_json(SessionMode::Visible, &pages);
        assert_eq!(visible[0]["handoff"], "visible_window");
        for kind in ["captcha", "mfa", "sign_in", "passkey", "other"] {
            let text = needs_you_reason(kind);
            assert!(!text.is_empty() && !text.contains("http"), "{kind}");
        }
        assert_eq!(needs_you_json(SessionMode::Shadow, &[]), json!([]));
    }

    #[test]
    fn a_task_label_is_one_short_line() {
        let mut scene = Scene::new("task");
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        for bad in ["", "a\nb", &"x".repeat(MAX_TASK_CHARS + 1)] {
            let refused = broker
                .create("client-a", Some(bad), [1; 8], 1, |_, _| {
                    Err::<TestWorker, _>(ProviderError::new(
                        FailureCode::InternalError,
                        "unreached",
                    ))
                })
                .map(|_| ())
                .unwrap_err();
            assert_eq!(refused.code, FailureCode::InvalidRequest, "{bad:?}");
        }
        assert!(check_task("Book a table").is_ok());
        let _ = scene.random();
    }

    /// A directory link at `link` to `target`: a junction on Windows (no
    /// privilege needed), a symbolic link elsewhere. False if the OS
    /// refused to make one.
    fn dir_link(link: &Path, target: &Path) -> bool {
        #[cfg(windows)]
        {
            std::process::Command::new("cmd")
                .arg("/C")
                .arg("mklink")
                .arg("/J")
                .arg(link)
                .arg(target)
                .output()
                .map(|out| out.status.success())
                .unwrap_or(false)
        }
        #[cfg(not(windows))]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
    }

    const DEAD_INSTANCE: &str = "00000000000000aa";

    /// A crashed orceld: its sessions' folders stay and its lock is free.
    /// The next broker removes them; a live instance's folders and a link
    /// planted among the instance folders are left alone, and the link's
    /// target is never touched.
    #[test]
    fn start_sweeps_only_unlocked_instances_and_never_follows_links() {
        let mut scene = Scene::new("sweep");
        // The crashed one: a broker with a session, dropped without ending.
        let crashed = {
            let mut broker = scene.broker(DEAD_INSTANCE, Budgets::DEFAULT);
            let id = scene.create(&mut broker, "client-a", "left").unwrap();
            broker.peek("client-a", &id).unwrap().dirs.root.clone()
        };
        assert!(crashed.exists());
        // A live one keeps its lock.
        let mut live = scene.broker(OTHER_INSTANCE, Budgets::DEFAULT);
        let live_id = scene.create(&mut live, "client-b", "kept").unwrap();
        let live_root = live.peek("client-b", &live_id).unwrap().dirs.root.clone();
        // A link named like an instance, pointing outside the broker.
        let outside = scene.root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep.txt"), "mine").unwrap();
        let sessions = scene.root.join("broker").join("sessions");
        let linked = dir_link(&sessions.join("00000000000000bb"), &outside);

        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        assert!(!crashed.exists(), "the crashed instance's session is swept");
        assert!(!sessions.join(DEAD_INSTANCE).exists());
        assert!(!scene
            .root
            .join("broker")
            .join("instances")
            .join(format!("{DEAD_INSTANCE}.lock"))
            .exists());
        assert!(live_root.join("profiles").join("cookies.txt").exists());
        assert!(outside.join("keep.txt").exists());
        if linked {
            assert!(std::fs::symlink_metadata(sessions.join("00000000000000bb")).is_ok());
        }
        // Sweeping again finds nothing new, and the live one still runs.
        assert_eq!(broker.sweep_leftovers(), 0);
        assert!(live.session("client-b", &live_id).is_ok());
        let _ = scene.create(&mut broker, "client-c", "x").unwrap();
    }

    /// Removal never follows a link inside a session's tree.
    #[test]
    fn removal_removes_a_link_inside_the_tree_but_not_its_target() {
        let scene = Scene::new("nofollow");
        let tree = scene.root.join("tree");
        let outside = scene.root.join("outside");
        std::fs::create_dir_all(tree.join("profiles")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep.txt"), "mine").unwrap();
        std::fs::write(tree.join("profiles").join("a.txt"), "a").unwrap();
        let linked = dir_link(&tree.join("profiles").join("link"), &outside);
        assert!(remove_tree(&tree));
        assert!(!tree.exists());
        assert!(outside.join("keep.txt").exists(), "linked: {linked}");
        // A tree that is itself a link is refused and left.
        let top = scene.root.join("top-link");
        if dir_link(&top, &outside) {
            assert!(!remove_tree(&top));
            assert!(outside.join("keep.txt").exists());
        }
    }

    /// A state directory that is a junction or link is refused.
    #[test]
    fn a_linked_state_directory_is_refused() {
        let mut scene = Scene::new("linkedslots");
        let outside = scene.root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(scene.root.join("broker")).unwrap();
        if !dir_link(&scene.root.join("broker").join("slots"), &outside) {
            return;
        }
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        let refused = scene.create(&mut broker, "client-a", "x").unwrap_err();
        assert_eq!(refused.code, FailureCode::ProviderUnavailable);
        assert_eq!(
            std::fs::read_dir(&outside).unwrap().count(),
            0,
            "nothing written through it"
        );
        let linked_root = Scene::new("linkedroot");
        if dir_link(&linked_root.root.join("broker"), &outside) {
            let started = Broker::<TestWorker>::start(
                linked_root.root.join("broker"),
                INSTANCE.into(),
                Budgets::DEFAULT,
            );
            assert!(started.is_err());
        }
    }

    /// A removal that fails (a file still held open) is kept and retried.
    #[cfg(windows)]
    #[test]
    fn a_busy_profile_is_retried_until_removed() {
        use std::os::windows::fs::OpenOptionsExt;
        let mut scene = Scene::new("busy");
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        let id = scene.create(&mut broker, "client-a", "x").unwrap();
        let root = broker.peek("client-a", &id).unwrap().dirs.root.clone();
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(root.join("profiles").join("cookies.txt"))
            .unwrap();
        let report = broker.close("client-a", &id).unwrap();
        assert!(!report.profile_removed);
        assert_eq!(broker.pending_removal(), std::slice::from_ref(&root));
        drop(held);
        broker.end_all(EndReason::McpSessionEnded);
        assert!(broker.pending_removal().is_empty());
        assert!(!root.exists());
    }

    /// An emergency revoke in any orceld moves the approval epoch; the next
    /// broker action here sees it, ends every session and is refused.
    #[test]
    fn a_moved_approval_epoch_ends_every_session() {
        let mut scene = Scene::new("epoch");
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        assert!(
            broker.check_epoch(Some(3)).is_ok(),
            "the first sight is the baseline"
        );
        let a = scene.create(&mut broker, "client-a", "1").unwrap();
        let b = scene.create(&mut broker, "client-b", "2").unwrap();
        assert!(broker.check_epoch(Some(3)).is_ok());
        let moved = broker.check_epoch(Some(4)).unwrap_err();
        assert_eq!(moved.code, FailureCode::TargetStale);
        for (client, id) in [("client-a", &a), ("client-b", &b)] {
            let refused = broker.session(client, id).map(|_| ()).unwrap_err();
            assert!(refused.message.contains("emergency_stop"));
        }
        // The new epoch is the baseline from now on.
        assert!(broker.check_epoch(Some(4)).is_ok());
    }

    /// The epoch is read once per action: a revoke that lands after the
    /// check is not taken as the baseline, so the re-check right before the
    /// action sees the change and the action never runs.
    #[test]
    fn the_baseline_is_the_epoch_that_was_checked() {
        let mut scene = Scene::new("baseline");
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        let reads = std::cell::RefCell::new(vec![Some(5u64), Some(6)]);
        let probe = || reads.borrow_mut().remove(0);
        assert_eq!(checked_baseline(&mut broker, probe()).ok(), Some(5));
        let id = scene.create(&mut broker, "client-a", "1").unwrap();
        let baseline = checked_baseline(&mut broker, Some(5)).unwrap();
        // The revoke lands now; the re-check before the action reads 6.
        let current = probe() == Some(baseline);
        assert!(!current, "the action is refused before it runs");
        // And the next check ends every session.
        assert!(broker.check_epoch(Some(6)).is_err());
        assert!(broker.session("client-a", &id).is_err());
        assert!(checked_baseline(&mut broker, None).is_err());
    }

    /// A busy or unverifiable ledger gives no verified epoch: every session
    /// ends and the action is refused, never run on a stale view.
    #[test]
    fn an_unverified_epoch_ends_every_session_and_refuses() {
        let mut scene = Scene::new("unverified");
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        assert!(broker.check_epoch(Some(0)).is_ok());
        let a = scene.create(&mut broker, "client-a", "1").unwrap();
        let refused = broker.check_epoch(None).unwrap_err();
        assert_eq!(refused.code, FailureCode::ApprovalUnavailable);
        let ended = broker.session("client-a", &a).map(|_| ()).unwrap_err();
        assert!(ended.message.contains("emergency_stop"));
        // A real busy ledger: another writer holds its lock.
        let ledger = scene.root.join("approvals.jsonl");
        let approval = orcel_approval::LocalApprovalBroker::with_path_and_soft_decider(
            &ledger,
            std::sync::Arc::new(orcel_approval::NoPresenceVerifier),
            std::sync::Arc::new(|_| orcel_approval::ApprovalDecision::Approved),
        );
        assert_eq!(verified_epoch(&approval), Some(0));
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(orcel_approval::approval_ledger_lock_path(&ledger))
            .unwrap();
        fs4::FileExt::lock(&lock).unwrap();
        assert_eq!(
            verified_epoch(&approval),
            None,
            "a busy ledger is not verified"
        );
        let _b = scene.create(&mut broker, "client-a", "2").unwrap();
        assert!(broker.check_epoch(verified_epoch(&approval)).is_err());
        assert_eq!(broker.client_sessions("client-a").len(), 0);
        drop(lock);
        assert_eq!(verified_epoch(&approval), Some(0));
    }

    #[test]
    fn the_counter_is_refused_before_it_outgrows_the_id() {
        let mut scene = Scene::new("counter");
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        broker.counter = MAX_COUNTER - 1;
        let last = scene.create(&mut broker, "client-a", "1").unwrap();
        assert!(last.contains("-999999-"));
        assert!(parse_session_id(&last).is_ok());
        let refused = scene.create(&mut broker, "client-a", "2").unwrap_err();
        assert_eq!(refused.code, FailureCode::OutputLimit);
    }

    #[test]
    fn an_absent_receipt_field_never_digests_like_a_present_one() {
        let mut scene = Scene::new("presence");
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        let id = scene.create(&mut broker, "client-a", "1").unwrap();
        let session = broker.session("client-a", &id).unwrap();
        let mut absent = session.record(record("browser_open", "done"), 1);
        absent.page_id = None;
        absent.generation_before = None;
        let mut dash = absent.clone();
        dash.page_id = Some("-".into());
        assert_ne!(receipt_digest(&absent), receipt_digest(&dash));
        let mut empty = absent.clone();
        empty.page_id = Some(String::new());
        assert_ne!(receipt_digest(&absent), receipt_digest(&empty));
    }

    #[test]
    fn a_held_instance_id_cannot_start_twice() {
        let scene = Scene::new("twice");
        let _first = scene.broker(INSTANCE, Budgets::DEFAULT);
        assert!(Broker::<TestWorker>::start(
            scene.root.join("broker"),
            INSTANCE.into(),
            Budgets::DEFAULT
        )
        .is_err());
        assert!(Broker::<TestWorker>::start(
            scene.root.join("broker"),
            "../x".into(),
            Budgets::DEFAULT
        )
        .is_err());
    }

    // SG-000135 OB-04: modes and persistent profiles.

    type Outcome = Result<(), Box<dyn std::error::Error>>;

    fn boxed(error: ProviderError) -> Box<dyn std::error::Error> {
        format!("{:?}: {}", error.code, error.message).into()
    }

    impl Scene {
        /// Open a session with `options`; its worker writes `secret` into
        /// whichever profile the session runs in (the persistent profile's
        /// data folder, or its own ephemeral profile root), as an engine
        /// would write cookies.
        fn create_in(
            &mut self,
            broker: &mut Broker<TestWorker>,
            client: &str,
            options: SessionOptions,
            secret: &str,
        ) -> Result<String, ProviderError> {
            let (shutdowns, usable) = (Rc::clone(&self.shutdowns), Rc::clone(&self.usable));
            let random = self.random();
            let secret = secret.to_owned();
            broker
                .create_with(client, Some("task"), options, random, 1, move |_, dirs| {
                    let profile = dirs
                        .persistent_profile
                        .clone()
                        .unwrap_or_else(|| dirs.profiles.clone());
                    let marker = profile.join("cookies.txt");
                    std::fs::write(&marker, secret).map_err(|_| {
                        ProviderError::new(FailureCode::InternalError, "test marker")
                    })?;
                    Ok(TestWorker {
                        profile_marker: marker,
                        usable,
                        shutdowns,
                    })
                })
                .map(|session| session.id.clone())
        }

        fn store(&self) -> Result<crate::browser_profiles::ProfileStore, ProviderError> {
            crate::browser_profiles::ProfileStore::open(self.root.join("named-profiles"))
        }
    }

    #[test]
    fn ob04_a_persistent_profile_outlives_its_session_and_serves_the_next_one() -> Outcome {
        let mut scene = Scene::new("persist");
        let store = scene.store().map_err(boxed)?;
        store.create("work", "client-a", 1).map_err(boxed)?;
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        let lease = store.acquire("work").map_err(boxed)?;
        let data = lease.data_dir.clone();
        let first = scene
            .create_in(
                &mut broker,
                "client-a",
                SessionOptions {
                    mode: SessionMode::Shadow,
                    profile: Some(lease),
                },
                "session=kept",
            )
            .map_err(boxed)?;
        let session_root = broker
            .peek("client-a", &first)
            .map_err(boxed)?
            .dirs
            .root
            .clone();
        assert!(
            !data.starts_with(&session_root),
            "the profile lives outside the session"
        );
        let status = broker.status("client-a", &first).map_err(boxed)?;
        assert_eq!(status["profile_mode"], "persistent");
        assert_eq!(status["profile"], "work");
        // One live session per profile, in this orceld or any other.
        assert!(store.acquire("work").is_err());
        let report = broker.close("client-a", &first).map_err(boxed)?;
        assert_eq!(report.persistent_profile.as_deref(), Some("work"));
        assert!(
            report.profile_removed,
            "the session's own directory is gone"
        );
        assert!(!session_root.exists());
        assert_eq!(std::fs::read(data.join("cookies.txt"))?, b"session=kept");
        assert_eq!(report.to_json()["profile_kept"], true);

        // A later session (here a new orceld instance) reopens it.
        drop(broker);
        let mut later = scene.broker(OTHER_INSTANCE, Budgets::DEFAULT);
        let lease = store.acquire("work").map_err(boxed)?;
        assert_eq!(
            std::fs::read(lease.data_dir.join("cookies.txt"))?,
            b"session=kept"
        );
        let second = scene
            .create_in(
                &mut later,
                "client-b",
                SessionOptions {
                    mode: SessionMode::Shadow,
                    profile: Some(lease),
                },
                "session=kept",
            )
            .map_err(boxed)?;
        // The earlier instance's session id is refused here.
        assert!(later.status("client-a", &first).is_err());
        later.close("client-b", &second).map_err(boxed)?;
        assert!(store.acquire("work").is_ok(), "released at close");
        Ok(())
    }

    #[test]
    fn ob04_sessions_on_different_profiles_share_no_profile_staging_or_downloads() -> Outcome {
        let mut scene = Scene::new("isolate");
        let store = scene.store().map_err(boxed)?;
        store.create("alpha", "client-a", 1).map_err(boxed)?;
        store.create("beta", "client-a", 1).map_err(boxed)?;
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        let open = |scene: &mut Scene, broker: &mut Broker<TestWorker>, name: &str| {
            let lease = store.acquire(name).map_err(boxed)?;
            scene
                .create_in(
                    broker,
                    "client-a",
                    SessionOptions {
                        mode: SessionMode::Shadow,
                        profile: Some(lease),
                    },
                    name,
                )
                .map_err(boxed)
        };
        let a = open(&mut scene, &mut broker, "alpha")?;
        let b = open(&mut scene, &mut broker, "beta")?;
        let dirs_a = broker.peek("client-a", &a).map_err(boxed)?.dirs.clone();
        let dirs_b = broker.peek("client-a", &b).map_err(boxed)?.dirs.clone();
        let (Some(profile_a), Some(profile_b)) = (
            dirs_a.persistent_profile.clone(),
            dirs_b.persistent_profile.clone(),
        ) else {
            return Err("both sessions hold a persistent profile".into());
        };
        for (left, right) in [
            (&profile_a, &profile_b),
            (&dirs_a.staging, &dirs_b.staging),
            (&dirs_a.host, &dirs_b.host),
            (&dirs_a.root, &dirs_b.root),
        ] {
            assert_ne!(left, right);
            assert!(!left.starts_with(right) && !right.starts_with(left));
        }
        assert_eq!(std::fs::read(profile_a.join("cookies.txt"))?, b"alpha");
        assert_eq!(std::fs::read(profile_b.join("cookies.txt"))?, b"beta");
        broker.end_all(EndReason::Closed);
        assert_eq!(std::fs::read(profile_a.join("cookies.txt"))?, b"alpha");
        Ok(())
    }

    #[test]
    fn ob04_the_mode_is_recorded_and_only_shadow_claims_no_interference() -> Outcome {
        let mut scene = Scene::new("modes");
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        let shadow = scene
            .create_in(&mut broker, "client-a", SessionOptions::default(), "s")
            .map_err(boxed)?;
        let visible = scene
            .create_in(
                &mut broker,
                "client-a",
                SessionOptions {
                    mode: SessionMode::Visible,
                    profile: None,
                },
                "v",
            )
            .map_err(boxed)?;
        let shadow_status = broker.status("client-a", &shadow).map_err(boxed)?;
        assert_eq!(shadow_status["mode"], "shadow");
        assert_eq!(shadow_status["no_interference"], true);
        assert_eq!(shadow_status["profile_mode"], "ephemeral");
        let visible_status = broker.status("client-a", &visible).map_err(boxed)?;
        assert_eq!(visible_status["mode"], "visible");
        assert_eq!(visible_status["no_interference"], false);
        assert_eq!(
            SessionMode::parse("visible").map_err(boxed)?,
            SessionMode::Visible
        );
        assert!(SessionMode::parse("headed").is_err());
        assert!(SessionMode::parse("Shadow").is_err());
        Ok(())
    }

    #[test]
    fn ob04_a_refused_session_releases_the_profile_it_was_given() -> Outcome {
        let mut scene = Scene::new("release");
        let store = scene.store().map_err(boxed)?;
        store.create("work", "client-a", 1).map_err(boxed)?;
        let budgets = Budgets {
            per_client: 0,
            ..Budgets::DEFAULT
        };
        let mut broker = scene.broker(INSTANCE, budgets);
        let lease = store.acquire("work").map_err(boxed)?;
        let refused = scene.create_in(
            &mut broker,
            "client-a",
            SessionOptions {
                mode: SessionMode::Shadow,
                profile: Some(lease),
            },
            "x",
        );
        assert!(refused.is_err());
        assert!(store.acquire("work").is_ok(), "released with the refusal");
        Ok(())
    }

    #[test]
    fn ob04_a_profile_whose_worker_is_not_confirmed_gone_stays_locked() -> Outcome {
        let mut scene = Scene::new("quarantine");
        let store = scene.store().map_err(boxed)?;
        store.create("work", "client-a", 1).map_err(boxed)?;
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        let lease = store.acquire("work").map_err(boxed)?;
        let id = scene
            .create_in(
                &mut broker,
                "client-a",
                SessionOptions {
                    mode: SessionMode::Shadow,
                    profile: Some(lease),
                },
                "stuck",
            )
            .map_err(boxed)?;
        let report = broker.close("client-a", &id).map_err(boxed)?;
        assert!(!report.worker_ended);
        assert!(report.profile_quarantined);
        assert_eq!(report.to_json()["profile_quarantined"], true);
        assert!(
            store.acquire("work").is_err(),
            "quarantined for this orceld's life"
        );
        assert!(store.check_delete("work").is_err());
        drop(broker);
        assert!(
            store.acquire("work").is_ok(),
            "released when the orceld ends"
        );
        Ok(())
    }

    #[test]
    fn ob04_profile_approvals_are_per_client_and_receipts_name_the_profile() -> Outcome {
        let mut scene = Scene::new("approvals");
        let store = scene.store().map_err(boxed)?;
        store.create("work", "client-a", 1).map_err(boxed)?;
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        assert!(!broker.profile_approved("default", "client-a", "work"));
        broker.note_profile_approved("default", "client-a", "work");
        assert!(broker.profile_approved("default", "client-a", "work"));
        assert!(!broker.profile_approved("default", "client-b", "work"));
        assert!(!broker.profile_approved("default", "client-a", "other"));
        // Another workspace asks again.
        assert!(!broker.profile_approved("second", "client-a", "work"));
        let lease = store.acquire("work").map_err(boxed)?;
        let id = scene
            .create_in(
                &mut broker,
                "client-a",
                SessionOptions {
                    mode: SessionMode::Shadow,
                    profile: Some(lease),
                },
                "x",
            )
            .map_err(boxed)?;
        let session = broker.session("client-a", &id).map_err(boxed)?;
        let receipt = session.record(record("browser_open", "done"), 1);
        assert_eq!(receipt.profile.as_deref(), Some("work"));
        let mut other = receipt.clone();
        other.profile = None;
        assert_ne!(receipt_digest(&receipt), receipt_digest(&other));
        assert_eq!(receipt.to_json()["profile"], "work");
        broker.end_client("client-a");
        assert!(!broker.profile_approved("default", "client-a", "work"));
        Ok(())
    }

    /// SG-000135 OB-04 re-judge: an emergency revoke (the approval epoch
    /// moved), an epoch that cannot be verified, and an emergency stop all
    /// forget every profile approval, so the same MCP session is asked again
    /// before it reuses a signed-in profile.
    #[test]
    fn ob04_a_revoke_or_stop_forgets_every_profile_approval() -> Outcome {
        let scene = Scene::new("revoke");
        let mut broker = scene.broker(INSTANCE, Budgets::DEFAULT);
        broker.check_epoch(Some(1)).map_err(boxed)?;
        broker.note_profile_approved("default", "client-a", "work");
        broker.check_epoch(Some(1)).map_err(boxed)?;
        assert!(
            broker.profile_approved("default", "client-a", "work"),
            "an unchanged epoch keeps it"
        );
        assert!(
            broker.check_epoch(Some(2)).is_err(),
            "the revoke moved the epoch"
        );
        assert!(!broker.profile_approved("default", "client-a", "work"));
        broker.note_profile_approved("default", "client-a", "work");
        assert!(broker.check_epoch(None).is_err());
        assert!(!broker.profile_approved("default", "client-a", "work"));
        broker.note_profile_approved("default", "client-a", "work");
        broker.end_all(EndReason::EmergencyStop);
        assert!(!broker.profile_approved("default", "client-a", "work"));
        Ok(())
    }
}
