//! SG-000120 RJ-01: the kernel's append-only intent journal.
//!
//! Extracted from the SG-000108 download-intent journal
//! (`crates/orceld/src/live_browser.rs`, `intents.jsonl`) without changing
//! its bytes, so every provider can record an intent before it acts and
//! settle it after:
//!
//! - [`append_line`] writes one JSON line and syncs it to disk before it
//!   returns. A torn tail (a crash mid-append) is sealed with a newline
//!   first, so the new line never fuses with it.
//! - [`read_lines`] reads every line back in order. Zero bytes (allocated
//!   but unwritten after a power loss) are dropped; a torn line, a strict
//!   prefix whose JSON ends early, is skipped and counted in
//!   [`Lines::torn`]; any other unreadable line fails closed.
//! - Lines are at most [`MAX_LINE_BYTES`] and a journal at most
//!   [`MAX_JOURNAL_BYTES`]: a longer line is refused at append, a larger
//!   journal fails closed at read.
//! - [`Journal`] is one exclusive writer: a second writer of the same
//!   journal is refused while the first holds it (an OS file lock on
//!   `<journal>.lock`, released when the handle closes, including on process
//!   death).
//!
//! Entries hold what a caller decided and did (ids, paths, sizes, hashes,
//! states, outcomes), never secret values or file contents; the journal
//! records, it never authorizes.

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

/// Longest line, newline included.
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// Largest journal a reader accepts.
pub const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;

/// Why a journal operation failed. Messages never quote journal content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    /// The journal could not be written or synced.
    Write,
    /// The journal exists but could not be read.
    Read,
    /// A line that is not a torn prefix could not be parsed.
    Unreadable,
    /// Another writer holds the journal.
    Busy,
    /// A line or the journal exceeds its bound.
    TooLarge,
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Write => "the journal could not be written",
            Self::Read => "the journal could not be read",
            Self::Unreadable => "the journal is unreadable",
            Self::Busy => "another writer holds the journal",
            Self::TooLarge => "a journal line or the journal exceeds its bound",
        })
    }
}

impl std::error::Error for JournalError {}

/// The lines of a journal, in order, and how many torn lines were skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lines<T> {
    pub lines: Vec<T>,
    /// Torn prefixes skipped (a typed warning for the caller to report).
    pub torn: usize,
}

/// Appends one line and syncs it to disk before returning. This takes no
/// writer lock: it is the SG-000108 download journal's path, whose single
/// writer is the one live browser of an orceld run. New journals write
/// through [`Journal::append`], which holds the one-writer lock.
pub fn append_line<T: Serialize>(path: &Path, line: &T) -> Result<(), JournalError> {
    let mut bytes = serde_json::to_vec(line).map_err(|_| JournalError::Write)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_LINE_BYTES {
        return Err(JournalError::TooLarge);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| JournalError::Write)?;
    }
    if torn_tail(path)? {
        bytes.insert(0, b'\n');
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|_| JournalError::Write)?;
    file.write_all(&bytes).map_err(|_| JournalError::Write)?;
    file.sync_data().map_err(|_| JournalError::Write)?;
    sync_parent(path)
}

/// On Unix the directory entry of a new journal is synced too, so the
/// journal itself survives a crash; Windows makes the entry durable with
/// the file.
#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), JournalError> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| JournalError::Write),
        _ => Ok(()),
    }
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), JournalError> {
    Ok(())
}

/// Whether the journal ends without a newline (a torn final line).
fn torn_tail(path: &Path) -> Result<bool, JournalError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(JournalError::Write),
    };
    let length = file.metadata().map_err(|_| JournalError::Write)?.len();
    if length == 0 {
        return Ok(false);
    }
    let mut last = [0u8; 1];
    file.seek(SeekFrom::Start(length - 1))
        .and_then(|_| file.read_exact(&mut last))
        .map_err(|_| JournalError::Write)?;
    Ok(last[0] != b'\n')
}

/// Every line of the journal, in order. A missing journal has none.
pub fn read_lines<T: DeserializeOwned>(path: &Path) -> Result<Lines<T>, JournalError> {
    if let Ok(metadata) = std::fs::metadata(path) {
        if metadata.len() > MAX_JOURNAL_BYTES {
            return Err(JournalError::TooLarge);
        }
    }
    let text = match std::fs::read(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Lines {
                lines: Vec::new(),
                torn: 0,
            })
        }
        Err(_) => return Err(JournalError::Read),
    };
    let mut lines = Vec::new();
    let mut torn = 0;
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
        match serde_json::from_slice::<T>(raw) {
            Ok(line) => lines.push(line),
            Err(error) if error.is_eof() => torn += 1,
            Err(_) => return Err(JournalError::Unreadable),
        }
    }
    Ok(Lines { lines, torn })
}

/// Where one intent stands. An intent is `Pending` once recorded and
/// `Dispatched` once its effect may have started; it ends `Settled` (the
/// reply came back), `Abandoned` (it never started) or `Unknown` (it may
/// have started and no reply came back), and an unknown or still-open one
/// becomes `Reconciled` once a provider's probe has decided it. Nothing
/// here re-dispatches anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentState {
    Pending,
    Dispatched,
    Settled,
    Abandoned,
    Unknown,
    Reconciled,
}

impl IntentState {
    /// Whether `next` may follow `self`. A recorded intent never returns to
    /// `Pending`, and a settled, abandoned or reconciled one never changes.
    pub fn may_become(self, next: IntentState) -> bool {
        use IntentState::*;
        matches!(
            (self, next),
            (Pending, Dispatched | Settled | Abandoned | Reconciled)
                | (Dispatched, Settled | Unknown | Reconciled)
                | (Unknown, Reconciled)
        )
    }

    /// Whether a provider still has to decide what happened.
    pub fn is_open(self) -> bool {
        matches!(
            self,
            IntentState::Pending | IntentState::Dispatched | IntentState::Unknown
        )
    }
}

/// The intents a journal leaves open, in the order they were recorded,
/// from `(intent id, state)` events in journal order. The first event of
/// an intent must be `Pending`; any transition `may_become` refuses fails
/// closed, so a journal that skips or reverses a state is never read as
/// settled.
pub fn recover<'a>(
    events: impl IntoIterator<Item = (&'a str, IntentState)>,
) -> Result<Vec<(String, IntentState)>, JournalError> {
    let mut states: Vec<(String, IntentState)> = Vec::new();
    for (id, next) in events {
        match states.iter_mut().find(|(known, _)| known == id) {
            None if next == IntentState::Pending => states.push((id.to_owned(), next)),
            None => return Err(JournalError::Unreadable),
            Some((_, state)) if state.may_become(next) => *state = next,
            Some(_) => return Err(JournalError::Unreadable),
        }
    }
    states.retain(|(_, state)| state.is_open());
    Ok(states)
}

/// One exclusive writer of a journal.
#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    // Held for the writer's lifetime; the OS releases it on close or death.
    _lock: File,
}

impl Journal {
    /// Opens the journal for writing, refusing while another writer holds it.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, JournalError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| JournalError::Write)?;
        }
        let mut lock_name = path.clone().into_os_string();
        lock_name.push(".lock");
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(PathBuf::from(lock_name))
            .map_err(|_| JournalError::Write)?;
        match fs4::FileExt::try_lock(&lock) {
            Ok(()) => Ok(Self { path, _lock: lock }),
            Err(fs4::TryLockError::WouldBlock) => Err(JournalError::Busy),
            Err(_) => Err(JournalError::Write),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one line and syncs it before returning.
    pub fn append<T: Serialize>(&self, line: &T) -> Result<(), JournalError> {
        append_line(&self.path, line)
    }

    /// Every line written so far, in order.
    pub fn read<T: DeserializeOwned>(&self) -> Result<Lines<T>, JournalError> {
        read_lines(&self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Line {
        event: String,
        id: String,
    }

    fn line(event: &str, id: &str) -> Line {
        Line {
            event: event.into(),
            id: id.into(),
        }
    }

    fn dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "orcel-journal-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn lines_round_trip_in_order_and_are_byte_stable() {
        let path = dir("round").join("intents.jsonl");
        append_line(&path, &line("pending", "r1")).unwrap();
        append_line(&path, &line("settled", "r1")).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"event\":\"pending\",\"id\":\"r1\"}\n{\"event\":\"settled\",\"id\":\"r1\"}\n"
        );
        let read: Lines<Line> = read_lines(&path).unwrap();
        assert_eq!(read.lines, [line("pending", "r1"), line("settled", "r1")]);
        assert_eq!(read.torn, 0);
    }

    #[test]
    fn a_missing_journal_has_no_lines() {
        let read: Lines<Line> = read_lines(&dir("missing").join("none.jsonl")).unwrap();
        assert!(read.lines.is_empty());
        assert_eq!(read.torn, 0);
    }

    #[test]
    fn a_torn_tail_is_counted_and_sealed_by_the_next_append() {
        let path = dir("torn").join("intents.jsonl");
        append_line(&path, &line("pending", "r1")).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"event\":\"pend")
            .unwrap();
        let read: Lines<Line> = read_lines(&path).unwrap();
        assert_eq!(read.lines, [line("pending", "r1")]);
        assert_eq!(read.torn, 1, "the torn prefix is reported, not guessed");
        append_line(&path, &line("pending", "r2")).unwrap();
        let read: Lines<Line> = read_lines(&path).unwrap();
        assert_eq!(read.lines, [line("pending", "r1"), line("pending", "r2")]);
        assert_eq!(read.torn, 1);
    }

    #[test]
    fn zero_filled_runs_are_dropped() {
        let path = dir("zeros").join("intents.jsonl");
        append_line(&path, &line("pending", "r1")).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"event\":\"se\0\0\0\0\n\0\0\0")
            .unwrap();
        let read: Lines<Line> = read_lines(&path).unwrap();
        assert_eq!(read.lines, [line("pending", "r1")]);
        assert_eq!(read.torn, 1);
    }

    #[test]
    fn a_corrupt_complete_line_fails_closed() {
        let path = dir("corrupt").join("intents.jsonl");
        std::fs::write(&path, "{\"event\":\"pending\",\"id\":7}\n").unwrap();
        assert_eq!(
            read_lines::<Line>(&path).unwrap_err(),
            JournalError::Unreadable
        );
        std::fs::write(&path, "not json\n").unwrap();
        assert_eq!(
            read_lines::<Line>(&path).unwrap_err(),
            JournalError::Unreadable
        );
    }

    #[test]
    fn lines_and_journals_are_bounded() {
        let path = dir("bounds").join("intents.jsonl");
        let long = line("pending", &"x".repeat(MAX_LINE_BYTES));
        assert_eq!(
            append_line(&path, &long).unwrap_err(),
            JournalError::TooLarge
        );
        assert!(!path.exists(), "a refused line writes nothing");
        let fits = line("pending", &"x".repeat(MAX_LINE_BYTES - 64));
        append_line(&path, &fits).unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(MAX_JOURNAL_BYTES + 1).unwrap();
        assert_eq!(
            read_lines::<Line>(&path).unwrap_err(),
            JournalError::TooLarge,
            "an oversized journal fails closed, it is not read in part"
        );
    }

    #[test]
    fn a_second_writer_is_refused_until_the_first_closes() {
        let path = dir("writer").join("intents.jsonl");
        let first = Journal::open(&path).unwrap();
        assert_eq!(Journal::open(&path).unwrap_err(), JournalError::Busy);
        first.append(&line("pending", "r1")).unwrap();
        drop(first);
        let second = Journal::open(&path).unwrap();
        let read: Lines<Line> = second.read().unwrap();
        assert_eq!(read.lines, [line("pending", "r1")]);
    }

    fn state(event: &str) -> IntentState {
        match event {
            "pending" => IntentState::Pending,
            "dispatched" => IntentState::Dispatched,
            "settled" => IntentState::Settled,
            "abandoned" => IntentState::Abandoned,
            "unknown" => IntentState::Unknown,
            "reconciled" => IntentState::Reconciled,
            other => panic!("{other}"),
        }
    }

    #[test]
    fn recover_lists_an_intent_whose_writer_crashed_between_pending_and_dispatch() {
        let path = dir("crash").join("intents.jsonl");
        {
            let writer = Journal::open(&path).unwrap();
            writer.append(&line("pending", "r1")).unwrap();
            writer.append(&line("dispatched", "r1")).unwrap();
            writer.append(&line("settled", "r1")).unwrap();
            // The writer dies after recording r9 and before dispatching it.
            writer.append(&line("pending", "r9")).unwrap();
        }
        let read: Lines<Line> = read_lines(&path).unwrap();
        let open = recover(
            read.lines
                .iter()
                .map(|line| (line.id.as_str(), state(&line.event))),
        )
        .unwrap();
        assert_eq!(open, [("r9".to_string(), IntentState::Pending)]);
    }

    #[test]
    fn recover_keeps_dispatched_and_unknown_intents_open_until_reconciled() {
        let open = recover([
            ("a", IntentState::Pending),
            ("a", IntentState::Dispatched),
            ("b", IntentState::Pending),
            ("b", IntentState::Dispatched),
            ("b", IntentState::Unknown),
            ("c", IntentState::Pending),
            ("c", IntentState::Dispatched),
            ("c", IntentState::Unknown),
            ("c", IntentState::Reconciled),
        ])
        .unwrap();
        assert_eq!(
            open,
            [
                ("a".to_string(), IntentState::Dispatched),
                ("b".to_string(), IntentState::Unknown)
            ]
        );
    }

    #[test]
    fn recover_fails_closed_on_a_transition_the_model_refuses() {
        use IntentState::*;
        for events in [
            vec![("a", Settled)],
            vec![("a", Pending), ("a", Pending)],
            vec![("a", Pending), ("a", Settled), ("a", Dispatched)],
            vec![("a", Pending), ("a", Abandoned), ("a", Reconciled)],
            vec![("a", Pending), ("a", Unknown)],
            vec![("a", Pending), ("a", Dispatched), ("a", Abandoned)],
        ] {
            assert_eq!(
                recover(events.clone()).unwrap_err(),
                JournalError::Unreadable,
                "{events:?}"
            );
        }
    }

    #[test]
    fn the_sg000108_download_events_are_lawful_transitions() {
        // The download writer emits only pending, settled, abandoned and
        // reconciled; each of its sequences is a lawful path here.
        use IntentState::*;
        for (next, open) in [(Settled, false), (Abandoned, false), (Reconciled, false)] {
            assert!(Pending.may_become(next));
            assert_eq!(next.is_open(), open);
        }
        assert!(Pending.is_open());
    }
}
