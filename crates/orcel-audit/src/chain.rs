//! The hash-chained audit log (spec 4.8, WP1-03).
//!
//! One file per device and user (`audit-chain.jsonl` beside the plain
//! `audit.jsonl`), shared by every orceld: one contract
//! [`AuditEvent`] per line, each carrying the previous event's digest, its
//! own `seq` (0-based, gapless) and `digest` = SHA-256 of
//! [`AuditEvent::digest_input`] (canonical JSON of the event without its
//! digest, so `prev_digest` and `seq` are covered).
//!
//! Event 0 is a `rotation` event (`action: open`) that opens the file; its
//! digest is the file id anchors name. It records the file it follows: the
//! previous file's id, head seq and head digest ([`ChainLink`]), or
//! `previous_file_id: "none"` for a log's first file; its `prev_digest` is
//! that head digest, or [`GENESIS_PREV_DIGEST`]. A file is replaced only by
//! [`move_aside`], which keeps the old file and opens the new one linked to
//! the old file's last verifiable record: never a clean slate.
//!
//! Appending takes an OS lock on `<chain>.lock` (several orcelds append to
//! one file), brings this writer's view up to the file's end (verifying
//! what other writers added, and following a linked replacement), writes
//! one whole line and `sync_data`s it before returning. A file that shrank,
//! was replaced by an unlinked file, or whose added records do not chain,
//! is refused: nothing is appended and the caller gets
//! [`ChainError::Broken`]. A torn last line (a crash in the middle of a
//! write) is moved to `<chain>.quarantine-<ms>-<pid>`, cut from the file and
//! recorded as a `rotation` event before anything else is appended, so the
//! cut is itself in the chain. A last line that is a whole valid event
//! without its line end is not what a crash leaves, and is refused.
//!
//! Every [`ANCHOR_INTERVAL_EVENTS`] events the writer asks its
//! [`Anchorer`] to hold `(log, file id, seq, digest)` and records the answer
//! as an `anchor` event (see [`crate::anchor`]).
//!
//! Limits (WP1-03 slice 1): one file grows without rotation (a writer reads
//! it whole once per process); a writer follows one linked replacement, and
//! refuses a file two replacements on until it restarts.

use crate::anchor::{AnchorOutcome, Anchorer, LocalMarker};
use crate::redact::{bounded, field_text, sha256_hex};
use crate::{MAX_FIELD_CHARS, MAX_TARGET_CHARS};
use orcel_contracts::event::{
    AnchorRef, AuditEvent, AuditEventKind, ANCHOR_INTERVAL_EVENTS, GENESIS_PREV_DIGEST,
};
use orcel_contracts::job::ExecutionState;
use orcel_contracts::lease::DispatchAuthority;
use orcel_contracts::Contract;
use serde_json::{json, Value};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The longest line the writer writes. A larger event keeps a digest of its
/// detail instead of the detail.
pub const MAX_EVENT_BYTES: usize = 16 * 1024;
/// The longest line a reader accepts.
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// How long an append waits for another writer's lock.
const LOCK_WAIT: Duration = Duration::from_secs(10);
/// `previous_file_id` of a log's first file.
pub const NO_PREVIOUS_FILE: &str = "none";
/// The `status` of an anchor event whose holder refused the file.
pub const LINK_REFUSED: &str = "link_refused";

/// What the operator is told when a chain does not verify.
pub const RECOVERY_HINT: &str = "run `orceld audit-verify` to see where; \
     `orceld audit-move-aside` keeps this file and opens a new one linked to its last \
     verifiable record (a continuation, not a clean slate); until then every dispatch is refused";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// The file could not be read or written.
    Io(String),
    /// Another writer held the lock past [`LOCK_WAIT`].
    Busy,
    /// The file on disk does not verify at `seq`; nothing was appended.
    Broken { seq: u64, reason: String },
    /// The event could not be encoded, or is too large even without its
    /// detail.
    Encode(String),
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) => write!(f, "audit chain I/O: {message}"),
            Self::Busy => write!(f, "audit chain busy: another writer held its lock"),
            Self::Broken { seq, reason } => write!(
                f,
                "audit chain broken at seq {seq}: {reason}; nothing was appended ({RECOVERY_HINT})"
            ),
            Self::Encode(message) => write!(f, "audit chain encoding: {message}"),
        }
    }
}

impl std::error::Error for ChainError {}

impl From<ChainError> for io::Error {
    fn from(error: ChainError) -> Self {
        io::Error::other(error.to_string())
    }
}

fn io_error(what: &str, error: io::Error) -> ChainError {
    ChainError::Io(format!("{what}: {error}"))
}

/// The file a chain file follows, as its opening event records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainLink {
    pub previous_file_id: String,
    pub previous_head_seq: u64,
    pub previous_head_digest: String,
}

impl ChainLink {
    /// The link an opening event records, or `None` for a first file.
    pub(crate) fn of_opening(event: &AuditEvent) -> Result<Option<Self>, String> {
        if event.kind != AuditEventKind::Rotation || event.detail["action"] != "open" {
            return Err("the first record does not open the file".to_owned());
        }
        let previous = event.detail["previous_file_id"]
            .as_str()
            .ok_or("the opening record names no previous file")?;
        if previous == NO_PREVIOUS_FILE {
            return Ok(None);
        }
        let seq = event.detail["previous_head_seq"]
            .as_u64()
            .ok_or("the opening record names no previous head seq")?;
        let digest = event.detail["previous_head_digest"]
            .as_str()
            .ok_or("the opening record names no previous head digest")?;
        Ok(Some(Self {
            previous_file_id: previous.to_owned(),
            previous_head_seq: seq,
            previous_head_digest: digest.to_owned(),
        }))
    }
}

/// An event before the writer gives it its place in the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventDraft {
    pub at_ms: u64,
    pub kind: AuditEventKind,
    pub request_id: Option<String>,
    pub job_id: Option<String>,
    pub principal_id: Option<String>,
    pub capability: Option<String>,
    pub operation: Option<String>,
    pub authority: Option<DispatchAuthority>,
    pub state: Option<ExecutionState>,
    pub asserted_by_session: bool,
    pub caller_pid: Option<u32>,
    pub caller_image: Option<String>,
    /// Bounded and redacted by the caller; replaced by its digest when the
    /// event would pass [`MAX_EVENT_BYTES`].
    pub detail: Value,
}

impl EventDraft {
    /// A draft of `kind` stamped now, with no request fields. Everything
    /// orceld writes is a claim of the user session (C-27 e), so
    /// `asserted_by_session` starts true.
    pub fn new(kind: AuditEventKind, detail: Value) -> Self {
        Self {
            at_ms: now_ms(),
            kind,
            request_id: None,
            job_id: None,
            principal_id: None,
            capability: None,
            operation: None,
            authority: None,
            state: None,
            asserted_by_session: true,
            caller_pid: None,
            caller_image: None,
            detail,
        }
    }
}

/// An event as written, and its anchor's outcome when it was due one.
#[derive(Debug, Clone, PartialEq)]
pub struct Appended {
    pub event: AuditEvent,
    /// Where the event sits: `(log, file id, seq, digest)`.
    pub at: AnchorRef,
    /// `Some` when this event was due an anchor: what the anchorer
    /// answered, or why the anchor event could not be written.
    pub anchor: Option<Result<AnchorOutcome, String>>,
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// The chain file kept beside the plain log `plain`: `audit.jsonl` keeps
/// `audit-chain.jsonl` (the registered `AUDIT_CHAIN` store).
pub fn chain_path_for(plain: &Path) -> PathBuf {
    let stem = plain
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .filter(|stem| !stem.is_empty())
        .unwrap_or_else(|| "audit".to_owned());
    plain.with_file_name(format!("{stem}-chain.jsonl"))
}

/// SHA-256 of the event's canonical digest input.
pub(crate) fn digest_of(event: &AuditEvent) -> Result<String, String> {
    event
        .digest_input()
        .map(|input| sha256_hex(input.as_bytes()))
        .map_err(|error| format!("{error:?}"))
}

/// Whether `event` is due an anchor: every [`ANCHOR_INTERVAL_EVENTS`]th
/// event, anchor events themselves excepted.
pub(crate) fn anchor_due(event: &AuditEvent) -> bool {
    event.kind != AuditEventKind::Anchor && (event.seq + 1) % ANCHOR_INTERVAL_EVENTS == 0
}

/// One step of reading a chain file.
pub(crate) enum Step {
    /// A whole line that chains; its length in bytes.
    Event(Box<AuditEvent>, u64),
    End,
    /// Bytes after the last line end.
    Torn(Vec<u8>),
    /// A whole line that does not chain, or an oversized one.
    Broken(String),
}

/// Reads a chain file line by line from a known position, checking each
/// event against the one before.
pub(crate) struct Scanner<R> {
    reader: R,
    pub next_seq: u64,
    pub head: String,
    pub file_id: Option<String>,
    pub link: Option<ChainLink>,
}

impl<R: BufRead> Scanner<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader,
            next_seq: 0,
            head: GENESIS_PREV_DIGEST.to_owned(),
            file_id: None,
            link: None,
        }
    }

    fn resume(reader: R, cursor: &Cursor) -> Self {
        Self {
            reader,
            next_seq: cursor.next_seq,
            head: cursor.head.clone(),
            file_id: cursor.file_id.clone(),
            link: cursor.link.clone(),
        }
    }

    pub(crate) fn step(&mut self) -> io::Result<Step> {
        let mut line = Vec::new();
        let read = self
            .reader
            .by_ref()
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(Step::End);
        }
        if line.len() > MAX_LINE_BYTES {
            return Ok(Step::Broken(format!(
                "a line longer than {MAX_LINE_BYTES} bytes"
            )));
        }
        if line.last() != Some(&b'\n') {
            return Ok(Step::Torn(line));
        }
        let length = line.len() as u64;
        match self.check(&line[..line.len() - 1]) {
            Ok((event, link)) => {
                if event.seq == 0 {
                    self.file_id = Some(event.digest.clone());
                    self.link = link;
                }
                self.next_seq += 1;
                self.head.clone_from(&event.digest);
                Ok(Step::Event(Box::new(event), length))
            }
            Err(reason) => Ok(Step::Broken(reason)),
        }
    }

    /// The event on `line` if it is the next link of the chain, and, for an
    /// opening event, the file it follows.
    pub(crate) fn check(&self, line: &[u8]) -> Result<(AuditEvent, Option<ChainLink>), String> {
        let event: AuditEvent =
            serde_json::from_slice(line).map_err(|error| format!("not an audit event: {error}"))?;
        if event.contract != AuditEvent::CONTRACT {
            return Err(format!("contract {:?}", event.contract));
        }
        if event.seq != self.next_seq {
            return Err(format!(
                "seq {} where {} was next (a record removed, added or moved)",
                event.seq, self.next_seq
            ));
        }
        let link = if event.seq == 0 {
            let link = ChainLink::of_opening(&event)?;
            let expected = link.as_ref().map_or(GENESIS_PREV_DIGEST, |link| {
                link.previous_head_digest.as_str()
            });
            if event.prev_digest != expected {
                return Err(
                    "the opening record's prev_digest is not the head it follows".to_owned(),
                );
            }
            link
        } else {
            if event.prev_digest != self.head {
                return Err("prev_digest is not the previous record's digest".to_owned());
            }
            None
        };
        if digest_of(&event)? != event.digest {
            return Err("digest does not match the record (edited)".to_owned());
        }
        Ok((event, link))
    }
}

/// This writer's view of the file: everything before `len` verified.
#[derive(Clone)]
struct Cursor {
    verified: bool,
    len: u64,
    next_seq: u64,
    head: String,
    file_id: Option<String>,
    link: Option<ChainLink>,
    /// Why this chain refuses further records: the anchor holder refused a
    /// file that does not continue the one it holds anchors of, or this
    /// file conflicts with the head the holder holds. Fail closed until the
    /// operator restores the file the holder knows.
    refused: Option<String>,
}

impl Cursor {
    fn empty() -> Self {
        Self {
            verified: false,
            len: 0,
            next_seq: 0,
            head: GENESIS_PREV_DIGEST.to_owned(),
            file_id: None,
            link: None,
            refused: None,
        }
    }
}

/// Why the current file conflicts with `held`, the anchor the holder holds
/// for this log, or `None` when it continues it: the same file holding that
/// record, or a file linked to the held file at or past the held seq.
pub(crate) fn held_conflict(
    held: &AnchorRef,
    file_id: &str,
    link: Option<&ChainLink>,
    next_seq: u64,
    digest_at_held: Option<&str>,
) -> Option<String> {
    if held.file_id == file_id {
        if held.seq >= next_seq {
            return Some(format!(
                "the anchor holder holds seq {} of this file, past its end (records were cut)",
                held.seq
            ));
        }
        if digest_at_held != Some(held.digest.as_str()) {
            return Some(format!(
                "the record at seq {} is not the one the anchor holder holds",
                held.seq
            ));
        }
        return None;
    }
    match link {
        Some(link) if link.previous_file_id == held.file_id => {
            if link.previous_head_seq > held.seq
                || (link.previous_head_seq == held.seq && link.previous_head_digest == held.digest)
            {
                None
            } else {
                Some(
                    "this file links to the held file at a head before, or other than, the \
                     anchored record"
                        .to_owned(),
                )
            }
        }
        _ => Some(
            "this file does not continue the file the anchor holder holds anchors of \
             (the chain was replaced, not continued)"
                .to_owned(),
        ),
    }
}

/// The opening event of the file at `path`, if it has a whole first line.
fn opening_of(path: &Path) -> io::Result<Option<(AuditEvent, Option<ChainLink>)>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut scanner = Scanner::new(BufReader::new(file));
    Ok(match scanner.step()? {
        Step::Event(event, _) => Some((*event, scanner.link)),
        _ => None,
    })
}

/// Appends to one chain file. Every writer of the file, in this process or
/// another, takes the file's OS lock for each append.
pub struct ChainWriter {
    path: PathBuf,
    lock_path: PathBuf,
    log: String,
    cursor: Mutex<Cursor>,
    anchorer: RwLock<Arc<dyn Anchorer>>,
}

impl fmt::Debug for ChainWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainWriter")
            .field("path", &self.path)
            .field("log", &self.log)
            .finish_non_exhaustive()
    }
}

fn lock_path_of(path: &Path) -> PathBuf {
    let mut lock_name = path.as_os_str().to_owned();
    lock_name.push(".lock");
    PathBuf::from(lock_name)
}

/// Writers of one chain in this process take their turn here first, so
/// the OS lock is contended by one thread per process and no thread
/// starves polling it. One mutex per chain path, made once and kept for
/// the process's life.
fn process_turn(lock_path: &Path) -> &'static Mutex<()> {
    type Turns = Mutex<std::collections::HashMap<PathBuf, &'static Mutex<()>>>;
    static TURNS: std::sync::OnceLock<Turns> = std::sync::OnceLock::new();
    let turns = TURNS.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    let mut turns = turns
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    turns
        .entry(lock_path.to_path_buf())
        .or_insert_with(|| Box::leak(Box::new(Mutex::new(()))))
}

/// The chain's lock: this process's turn, then the file's OS lock, waiting
/// up to [`LOCK_WAIT`] for other processes; released when dropped,
/// including when the process dies.
struct Held {
    _file: File,
    _turn: MutexGuard<'static, ()>,
}

fn lock(lock_path: &Path) -> Result<Held, ChainError> {
    let turn = process_turn(lock_path)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let file = os_lock(lock_path)?;
    Ok(Held {
        _file: file,
        _turn: turn,
    })
}
fn os_lock(lock_path: &Path) -> Result<File, ChainError> {
    let file = crate::open_options()
        .read(true)
        .open(lock_path)
        .map_err(|error| io_error("open the chain lock", error))?;
    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        match fs4::FileExt::try_lock(&file) {
            Ok(()) => return Ok(file),
            Err(fs4::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(fs4::TryLockError::WouldBlock) => return Err(ChainError::Busy),
            Err(fs4::TryLockError::Error(error)) => return Err(io_error("lock the chain", error)),
        }
    }
}

/// A name beside `path` for a file moved aside, owned by the chain's
/// registered store (`.quarantine-` siblings).
fn aside_name(path: &Path, what: &str) -> String {
    format!(
        "{}.quarantine-{what}{}-{}",
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        now_ms(),
        std::process::id()
    )
}

impl ChainWriter {
    /// A writer for the chain at `path`, named `log` in its anchors (for
    /// example `orceld`). Creates missing parent directories (owner only on
    /// Unix); the file itself is read and created at the first append.
    /// Anchors are local, unanchored markers until [`Self::set_anchorer`].
    pub fn open(path: impl Into<PathBuf>, log: &str) -> io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            crate::create_parent_dirs(parent)?;
        }
        Ok(Self {
            lock_path: lock_path_of(&path),
            path,
            log: log.to_owned(),
            cursor: Mutex::new(Cursor::empty()),
            anchorer: RwLock::new(Arc::new(LocalMarker)),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Who holds this chain's anchors from now on.
    pub fn set_anchorer(&self, anchorer: Arc<dyn Anchorer>) {
        match self.anchorer.write() {
            Ok(mut slot) => *slot = anchorer,
            Err(poisoned) => *poisoned.into_inner() = anchorer,
        }
    }

    fn anchorer(&self) -> Arc<dyn Anchorer> {
        match self.anchorer.read() {
            Ok(slot) => Arc::clone(&slot),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    fn cursor(&self) -> MutexGuard<'_, Cursor> {
        // A panic while the cursor was held can have left it anywhere: start
        // over from the file.
        self.cursor.lock().unwrap_or_else(|poisoned| {
            let mut cursor = poisoned.into_inner();
            cursor.verified = false;
            cursor
        })
    }

    /// Appends `draft`, flushed to disk before this returns. When the event
    /// is due an anchor, asks the anchorer (outside the file lock) and
    /// records its answer as an `anchor` event.
    pub fn append(&self, draft: EventDraft) -> Result<Appended, ChainError> {
        let (mut appended, link) = self.append_one(draft, false)?;
        if anchor_due(&appended.event) {
            let outcome = self.anchorer().anchor(&appended.at, link.as_ref());
            let marker = EventDraft {
                asserted_by_session: false,
                ..EventDraft::new(AuditEventKind::Anchor, outcome.detail(&appended.at))
            };
            // A refusal is recorded even though it stops the chain.
            let refused = matches!(outcome, AnchorOutcome::Refused { .. });
            appended.anchor = Some(
                self.append_one(marker, refused)
                    .map(|_| outcome)
                    .map_err(|error| error.to_string()),
            );
        }
        Ok(appended)
    }

    fn append_one(
        &self,
        draft: EventDraft,
        record_refusal: bool,
    ) -> Result<(Appended, Option<ChainLink>), ChainError> {
        let mut cursor = self.cursor();
        let _lock = lock(&self.lock_path)?;
        self.sync(&mut cursor)?;
        if let (Some(reason), false) = (&cursor.refused, record_refusal) {
            return Err(ChainError::Broken {
                seq: cursor.next_seq,
                reason: format!("refused: {reason}"),
            });
        }
        let refusal = (draft.kind == AuditEventKind::Anchor && record_refusal).then(|| {
            draft.detail["reason"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        });
        let appended = self.write_event(&mut cursor, draft)?;
        if let Some(reason) = refusal {
            cursor.refused = Some(format!("the anchor holder refused this file: {reason}"));
        }
        Ok((appended, cursor.link.clone()))
    }

    /// Brings `cursor` to the file's end under the lock: follows a linked
    /// replacement, verifies what was added since, quarantines a torn last
    /// line, opens an empty file.
    fn sync(&self, cursor: &mut Cursor) -> Result<(), ChainError> {
        if !cursor.verified {
            *cursor = Cursor::empty();
        }
        if let Some(known) = cursor.file_id.clone() {
            match opening_of(&self.path).map_err(|error| io_error("read the chain", error))? {
                Some((opening, _)) if opening.digest == known => {}
                Some((_, Some(link))) if link.previous_file_id == known => {
                    // Moved aside and continued by a linked file, which must
                    // keep every record this writer verified.
                    let verified_head = cursor.next_seq.saturating_sub(1);
                    if link.previous_head_seq < verified_head
                        || (link.previous_head_seq == verified_head
                            && link.previous_head_digest != cursor.head)
                    {
                        return Err(ChainError::Broken {
                            seq: cursor.next_seq,
                            reason: format!(
                                "the linked file continues from seq {}, before the head this \
                                 writer verified (seq {verified_head}): records were dropped",
                                link.previous_head_seq
                            ),
                        });
                    }
                    *cursor = Cursor::empty();
                }
                Some(_) => {
                    return Err(ChainError::Broken {
                        seq: cursor.next_seq,
                        reason: "the chain file was replaced by a file that does not link to it"
                            .to_owned(),
                    })
                }
                None => {
                    return Err(ChainError::Broken {
                        seq: cursor.next_seq,
                        reason: "the chain file was removed or emptied".to_owned(),
                    })
                }
            }
        }
        let file = match File::open(&self.path) {
            Ok(file) => Some(file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(io_error("open the chain", error)),
        };
        let end = match &file {
            Some(file) => file
                .metadata()
                .map_err(|error| io_error("read the chain's size", error))?
                .len(),
            None => 0,
        };
        if end < cursor.len {
            return Err(ChainError::Broken {
                seq: cursor.next_seq,
                reason: format!(
                    "the file shrank from {} to {end} bytes (records were cut)",
                    cursor.len
                ),
            });
        }
        // A writer reading the file from its start (a new process, or a
        // linked replacement) checks it against the anchor the holder holds.
        let from_start = cursor.len == 0;
        let held = if from_start {
            self.anchorer().held(&self.log)
        } else {
            None
        };
        let mut digest_at_held = None;
        if let Some(mut file) = file.filter(|_| end > cursor.len) {
            file.seek(SeekFrom::Start(cursor.len))
                .map_err(|error| io_error("read the chain", error))?;
            let mut scanner = Scanner::resume(BufReader::new(file), cursor);
            loop {
                match scanner
                    .step()
                    .map_err(|error| io_error("read the chain", error))?
                {
                    Step::Event(event, length) => {
                        if held.as_ref().is_some_and(|held| held.seq == event.seq) {
                            digest_at_held = Some(event.digest.clone());
                        }
                        if event.kind == AuditEventKind::Anchor
                            && event.detail["status"] == LINK_REFUSED
                        {
                            cursor.refused = Some(format!(
                                "the anchor holder refused this file: {}",
                                event.detail["reason"].as_str().unwrap_or_default()
                            ));
                        }
                        cursor.len += length;
                        cursor.next_seq = scanner.next_seq;
                        cursor.head.clone_from(&scanner.head);
                        cursor.file_id.clone_from(&scanner.file_id);
                        cursor.link.clone_from(&scanner.link);
                        cursor.verified = true;
                    }
                    Step::End => break,
                    Step::Broken(reason) => {
                        return Err(ChainError::Broken {
                            seq: cursor.next_seq,
                            reason,
                        })
                    }
                    Step::Torn(bytes) => {
                        // A whole valid event that lost only its line end is
                        // not a torn write; cutting it would delete a record.
                        if scanner.check(&bytes).is_ok() {
                            return Err(ChainError::Broken {
                                seq: cursor.next_seq,
                                reason: "the last record lost its line end, which a crash \
                                         does not do"
                                    .to_owned(),
                            });
                        }
                        cursor.verified = true;
                        self.quarantine_tail(cursor, &bytes)?;
                        break;
                    }
                }
            }
        }
        cursor.verified = true;
        self.open_file_if_empty(cursor, None, None)?;
        if let (Some(held), Some(file_id)) = (&held, cursor.file_id.clone()) {
            if let Some(conflict) = held_conflict(
                held,
                &file_id,
                cursor.link.as_ref(),
                cursor.next_seq,
                digest_at_held.as_deref(),
            ) {
                cursor.refused = Some(conflict);
            }
        }
        Ok(())
    }

    /// Moves a torn last line aside, cuts it from the chain and records
    /// both in the chain.
    fn quarantine_tail(&self, cursor: &mut Cursor, bytes: &[u8]) -> Result<(), ChainError> {
        let name = aside_name(&self.path, "");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options
            .open(self.path.with_file_name(&name))
            .and_then(|mut file| file.write_all(bytes).and_then(|()| file.sync_all()))
            .map_err(|error| io_error("quarantine the torn tail", error))?;
        OpenOptions::new()
            .write(true)
            .open(&self.path)
            .and_then(|file| file.set_len(cursor.len).and_then(|()| file.sync_all()))
            .map_err(|error| io_error("cut the torn tail", error))?;
        self.open_file_if_empty(cursor, None, None)?;
        let detail = json!({
            "action": "quarantined_torn_tail",
            "bytes": bytes.len(),
            "sha256": sha256_hex(bytes),
            "quarantine_file": name,
        });
        self.write_event(
            cursor,
            EventDraft {
                asserted_by_session: false,
                ..EventDraft::new(AuditEventKind::Rotation, detail)
            },
        )
        .map(|_| ())
    }

    /// Event 0 of a new file: a `rotation` event opening it, linked to the
    /// file it follows.
    fn open_file_if_empty(
        &self,
        cursor: &mut Cursor,
        link: Option<&ChainLink>,
        moved: Option<Value>,
    ) -> Result<(), ChainError> {
        if cursor.next_seq > 0 {
            return Ok(());
        }
        let detail = json!({
            "action": "open",
            "log": self.log,
            "contract": AuditEvent::CONTRACT,
            "anchor_interval_events": ANCHOR_INTERVAL_EVENTS,
            "previous_file_id": link.map_or(NO_PREVIOUS_FILE, |link| link.previous_file_id.as_str()),
            "previous_head_seq": link.map(|link| link.previous_head_seq),
            "previous_head_digest": link.map(|link| link.previous_head_digest.as_str()),
            "moved_aside": moved,
        });
        cursor.head = link.map_or_else(
            || GENESIS_PREV_DIGEST.to_owned(),
            |link| link.previous_head_digest.clone(),
        );
        cursor.link = link.cloned();
        self.write_event(
            cursor,
            EventDraft {
                asserted_by_session: false,
                ..EventDraft::new(AuditEventKind::Rotation, detail)
            },
        )
        .map(|_| ())
    }

    fn write_event(&self, cursor: &mut Cursor, draft: EventDraft) -> Result<Appended, ChainError> {
        let field = |value: Option<String>| value.map(|value| field_text(&value, MAX_FIELD_CHARS));
        let mut event = AuditEvent {
            contract: AuditEvent::CONTRACT.to_owned(),
            seq: cursor.next_seq,
            prev_digest: cursor.head.clone(),
            at_ms: draft.at_ms,
            kind: draft.kind,
            request_id: field(draft.request_id),
            job_id: field(draft.job_id),
            principal_id: field(draft.principal_id),
            capability: field(draft.capability),
            operation: field(draft.operation),
            authority: draft.authority,
            state: draft.state,
            asserted_by_session: draft.asserted_by_session,
            caller_pid: draft.caller_pid,
            caller_image: draft
                .caller_image
                .map(|image| field_text(&image, MAX_TARGET_CHARS)),
            detail: draft.detail,
            digest: String::new(),
        };
        let mut line = encode(&mut event)?;
        if line.len() >= MAX_EVENT_BYTES {
            let detail = serde_json::to_vec(&event.detail)
                .map_err(|error| ChainError::Encode(error.to_string()))?;
            event.detail = json!({
                "oversized_detail": {"bytes": detail.len(), "sha256": sha256_hex(&detail)},
            });
            line = encode(&mut event)?;
            if line.len() >= MAX_EVENT_BYTES {
                return Err(ChainError::Encode(format!(
                    "an event of {} bytes without its detail",
                    line.len()
                )));
            }
        }
        line.push(b'\n');
        let written = crate::open_options()
            .open(&self.path)
            .and_then(|mut file| file.write_all(&line).and_then(|()| file.sync_data()));
        if let Err(error) = written {
            // Part of the line may be on disk: read the file again next time.
            cursor.verified = false;
            return Err(io_error("write the chain", error));
        }
        cursor.len += line.len() as u64;
        cursor.next_seq += 1;
        cursor.head.clone_from(&event.digest);
        if event.seq == 0 {
            cursor.file_id = Some(event.digest.clone());
        }
        let at = AnchorRef {
            log: self.log.clone(),
            file_id: cursor.file_id.clone().unwrap_or_default(),
            seq: event.seq,
            digest: event.digest.clone(),
        };
        Ok(Appended {
            event,
            at,
            anchor: None,
        })
    }
}

/// What [`move_aside`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MovedAside {
    /// The old file's new name, beside the chain.
    pub moved_to: String,
    /// The new file's link to the old one (`None` when the old file held no
    /// verifiable record).
    pub link: Option<ChainLink>,
    /// The new file's id.
    pub file_id: String,
}

/// Operator recovery for a chain that does not verify: under the chain's
/// lock, keeps the file as `<chain>.quarantine-moved-<ms>-<pid>` and opens a
/// new file whose opening event links to the old file's last verifiable
/// record and names where the old file went. Running writers follow the
/// linked file. A continuation, never a clean slate: everything the old
/// file held stays, and the gap is recorded.
pub fn move_aside(path: &Path, log: &str) -> Result<MovedAside, ChainError> {
    let _lock = lock(&lock_path_of(path))?;
    let file = File::open(path).map_err(|error| io_error("open the chain", error))?;
    let mut scanner = Scanner::new(BufReader::new(file));
    let mut stopped = "end".to_owned();
    loop {
        match scanner
            .step()
            .map_err(|error| io_error("read the chain", error))?
        {
            Step::Event(..) => {}
            Step::End => break,
            Step::Torn(_) => {
                "torn tail".clone_into(&mut stopped);
                break;
            }
            Step::Broken(reason) => {
                stopped = format!("broken at seq {}: {reason}", scanner.next_seq);
                break;
            }
        }
    }
    let link = scanner.file_id.clone().map(|file_id| ChainLink {
        previous_file_id: file_id,
        previous_head_seq: scanner.next_seq.saturating_sub(1),
        previous_head_digest: scanner.head.clone(),
    });
    let moved_to = aside_name(path, "moved-");
    std::fs::rename(path, path.with_file_name(&moved_to))
        .map_err(|error| io_error("move the chain aside", error))?;
    let writer = ChainWriter::open(path, log).map_err(|error| io_error("open the chain", error))?;
    let mut cursor = Cursor::empty();
    cursor.verified = true;
    writer.open_file_if_empty(
        &mut cursor,
        link.as_ref(),
        Some(json!({"file": moved_to, "stopped": bounded(&stopped, MAX_FIELD_CHARS)})),
    )?;
    Ok(MovedAside {
        moved_to,
        link,
        file_id: cursor.file_id.unwrap_or_default(),
    })
}

/// Digests `event` and encodes it as one JSON line (without its line end).
fn encode(event: &mut AuditEvent) -> Result<Vec<u8>, ChainError> {
    event.digest = digest_of(event).map_err(ChainError::Encode)?;
    serde_json::to_vec(event).map_err(|error| ChainError::Encode(error.to_string()))
}
