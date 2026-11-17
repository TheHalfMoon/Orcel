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
//!   Profiles are ephemeral in this packet: the directory is removed when
//!   the session ends. Persistent profiles, and routing the
//!   `browser_structured` shapes through the broker, are deferred to the
//!   packet the grain names for them (SG-000135 is being amended to place
//!   both in OB-04, beside Shadow and Visible).
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
//! Every action yields a provisional receipt (session, page, generation
//! before and after, action, outcome, evidence digest), chained by digest
//! within the session and returned by `browser_task_status`. Receipts are
//! orceld's own records of what it dispatched; the SG-000131 audit chain
//! (OB-05) is not here yet.
//!
//! The broker grants nothing: profile gate, policy, the takeover gate and
//! the approval broker still decide every action. It is generic over the
//! worker so its rules are tested without a browser.

use orcel_contracts::FailureCode;
use orcel_provider_fs::ProviderError;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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
/// Domain separation for receipt digests.
const RECEIPT_DOMAIN: &str = "orcel-ob01-receipt/1";

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
}

impl SessionDirs {
    fn under(root: PathBuf) -> Self {
        Self {
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
fn is_reparse(metadata: &std::fs::Metadata) -> bool {
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
fn real_dir(dir: &Path) -> Result<(), ProviderError> {
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
fn remove_tree(path: &Path) -> bool {
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
fn try_lock_file(path: &Path) -> Result<Option<File>, ProviderError> {
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
}

impl EndReport {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "session_id": self.session_id,
            "reason": self.reason.as_str(),
            "worker_ended": self.worker_ended,
            "profile_removed": self.profile_removed,
        })
    }
}

/// One provisional receipt: what orceld dispatched and what became of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Receipt {
    pub seq: u64,
    pub session_id: String,
    pub action: String,
    pub page_id: Option<String>,
    pub generation_before: Option<u64>,
    pub generation_after: Option<u64>,
    /// `done`, `denied`, `refused`, `not_dispatched`, `failed` or `unknown`.
    pub outcome: String,
    pub failure_code: Option<String>,
    /// `observe`, `verify`, `reply` or `none`: where the evidence digest
    /// comes from.
    pub evidence_kind: String,
    pub evidence_sha256: Option<String>,
    /// The approval broker's record id, for an approved action.
    pub record_id: Option<String>,
    pub at_ms: u64,
    /// The previous receipt's digest in this session (empty for the first).
    pub previous_sha256: String,
    pub receipt_sha256: String,
}

impl Receipt {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "seq": self.seq,
            "session_id": self.session_id,
            "action": self.action,
            "page_id": self.page_id,
            "generation_before": self.generation_before,
            "generation_after": self.generation_after,
            "outcome": self.outcome,
            "failure_code": self.failure_code,
            "evidence_kind": self.evidence_kind,
            "evidence_sha256": self.evidence_sha256,
            "record_id": self.record_id,
            "at_ms": self.at_ms,
            "previous_sha256": self.previous_sha256,
            "receipt_sha256": self.receipt_sha256,
            "provisional": true,
        })
    }
}

/// What a caller of the broker reports about one action.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ActionRecord {
    pub action: String,
    pub page_id: Option<String>,
    pub generation_before: Option<u64>,
    pub generation_after: Option<u64>,
    pub outcome: String,
    pub failure_code: Option<String>,
    pub evidence_kind: String,
    pub evidence_sha256: Option<String>,
    pub record_id: Option<String>,
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

    /// Append the receipt of one action, chained to the previous one.
    pub(crate) fn record(&mut self, record: ActionRecord, at_ms: u64) -> Receipt {
        let seq = self.next_seq;
        self.next_seq += 1;
        let previous = self.last_receipt_sha256.clone();
        let mut receipt = Receipt {
            seq,
            session_id: self.id.clone(),
            action: record.action,
            page_id: record.page_id,
            generation_before: record.generation_before,
            generation_after: record.generation_after,
            outcome: record.outcome,
            failure_code: record.failure_code,
            evidence_kind: record.evidence_kind,
            evidence_sha256: record.evidence_sha256,
            record_id: record.record_id,
            at_ms,
            previous_sha256: previous,
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = receipt_digest(&receipt);
        self.last_receipt_sha256 = receipt.receipt_sha256.clone();
        if self.receipts.len() >= self.receipts_budget {
            self.receipts.pop_front();
            self.receipts_dropped += 1;
        }
        self.receipts.push_back(receipt.clone());
        receipt
    }

    pub(crate) fn receipts(&self) -> impl Iterator<Item = &Receipt> {
        self.receipts.iter()
    }

    #[cfg(test)]
    pub(crate) fn actions(&self) -> u64 {
        self.actions
    }
}

/// The digest of a receipt's fields (length-prefixed, so no two receipts
/// share one).
fn receipt_digest(receipt: &Receipt) -> String {
    // A presence tag first, so an absent field never equals any present
    // value (None is "\0", Some(v) is "\x01" then v).
    let optional = |value: &Option<String>| match value {
        Some(text) => format!("\u{1}{text}"),
        None => "\u{0}".to_owned(),
    };
    let number = |value: Option<u64>| match value {
        Some(n) => format!("\u{1}{n}"),
        None => "\u{0}".to_owned(),
    };
    let mut hasher = Sha256::new();
    for part in [
        RECEIPT_DOMAIN.to_owned(),
        receipt.seq.to_string(),
        receipt.session_id.clone(),
        receipt.action.clone(),
        optional(&receipt.page_id),
        number(receipt.generation_before),
        number(receipt.generation_after),
        receipt.outcome.clone(),
        optional(&receipt.failure_code),
        receipt.evidence_kind.clone(),
        optional(&receipt.evidence_sha256),
        optional(&receipt.record_id),
        receipt.at_ms.to_string(),
        receipt.previous_sha256.clone(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hex(&hasher.finalize())
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
    /// This instance's lock, held for the broker's (orceld's) lifetime.
    _instance_lock: File,
}

impl<W: SessionWorker> Broker<W> {
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
    pub(crate) fn create(
        &mut self,
        client: &str,
        task: Option<&str>,
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
        let dirs = SessionDirs::under(sessions_root.join(&id));
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
            worker,
            page_id: None,
            actions: 0,
            actions_budget: self.budgets.actions_per_session,
            receipts: VecDeque::new(),
            receipts_budget: self.budgets.receipts_per_session,
            receipts_dropped: 0,
            last_receipt_sha256: String::new(),
            next_seq: 1,
            _slot: slot,
        };
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
        let ids: Vec<String> = self.sessions.keys().cloned().collect();
        let reports = ids.iter().filter_map(|id| self.end(id, reason)).collect();
        self.retry_pending_removal();
        // Nothing of this instance is left; its directory goes too.
        let _ = std::fs::remove_dir(self.sessions_root());
        reports
    }

    fn end(&mut self, id: &str, reason: EndReason) -> Option<EndReport> {
        let session = self.sessions.remove(id)?;
        let root = session.dirs.root.clone();
        let worker_ended = session.worker.shutdown();
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
        Some(EndReport {
            session_id: id.to_owned(),
            reason,
            worker_ended,
            profile_removed,
        })
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
            "last_receipt_sha256": session.last_receipt_sha256,
            "profile_mode": "ephemeral",
        }))
    }
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
            true
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
        assert_eq!(status["receipts"][0]["provisional"], true);
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
}
