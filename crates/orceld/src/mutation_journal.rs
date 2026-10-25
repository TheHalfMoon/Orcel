//! SG-000120 RJ-02 (file provider): the durable journal of approved file
//! mutations (`fs.write`, `fs.edit`, `fs.mkdir`, `fs.move`, `fs.remove`),
//! `mutations.jsonl` beside the audit log in the private state root.
//!
//! Every mutation records `pending` before its approval is asked for, bound
//! to the approval digest, workspace and policy revision, the target and
//! the postcondition the approved effect must leave; `dispatched`
//! immediately before the provider acts; and `settled` or `abandoned` once
//! its outcome is known. If `pending` or `dispatched` cannot be written,
//! nothing is asked, spent or changed. Entries hold paths, sizes, hashes,
//! states and outcomes, never file content.
//!
//! When an orceld starts it reconciles only the intents an exited orceld
//! left open (never a running one's): a `pending`-only intent never reached
//! its effect and is closed `nothing_done` without reading anything; a
//! `dispatched` one is compared with its postcondition and closed `done`,
//! `nothing_done` or `unknown`. Nothing is written, removed or retried: an
//! unknown outcome can only be repeated by a new request, under a new
//! intent and a fresh single-use approval. The outcomes are kept, bounded,
//! for RJ-03's resume summary.

use orcel_contracts::FailureCode;
use orcel_journal::{IntentState, JournalError};
use orcel_provider_fs::ProviderError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

const SCHEMA: &str = "orcel-mutation/1";
const LOCK_WAIT: Duration = Duration::from_secs(5);
/// Largest file a starting orceld hashes to reconcile a mutation.
const MAX_RECONCILE_BYTES: u64 = 64 * 1024 * 1024;
/// Most closed outcomes the journal keeps for the resume summary.
pub(crate) const MAX_OUTCOMES: usize = 256;

/// What the approved effect must leave at the target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Postcondition {
    /// A regular file with `sha256`; `before` is the file's hash before
    /// (`None` when it did not exist).
    File {
        sha256: String,
        before: Option<String>,
    },
    /// A directory at the target.
    Directory,
    /// The target moved to `to` (workspace-relative); `sha256` is the
    /// moved file's hash when it was a file.
    Moved { to: String, sha256: Option<String> },
    /// Nothing at the target; `before` identifies what was there.
    Absent {
        before_kind: String,
        before_sha256: Option<String>,
    },
}

/// One approved mutation, as journaled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Mutation {
    pub capability: String,
    pub operation: String,
    pub approval_digest: String,
    pub workspace_id: String,
    pub policy_revision: String,
    pub root: PathBuf,
    pub target: String,
    pub postcondition: Postcondition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Owner {
    run: String,
    pid: u32,
    generation: u64,
    boot_id: Option<String>,
}

impl Owner {
    fn current(run: &str) -> Option<Self> {
        let instance = orcel_platform::process::current_instance().ok()?;
        Some(Self {
            run: run.to_owned(),
            pid: instance.pid,
            generation: instance.generation,
            boot_id: instance.boot_id.map(|id| id.to_string()),
        })
    }

    /// An identity the OS will not report counts as running.
    fn has_exited(&self) -> bool {
        match orcel_platform::process::start_generation(self.pid) {
            Ok(now) => {
                now.generation != self.generation
                    || now.boot_id.map(|id| id.to_string()) != self.boot_id
            }
            Err(orcel_platform::PlatformError::ProcessGone(_)) => true,
            Err(_) => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Line {
    Pending {
        schema: String,
        owner: Owner,
        intent: String,
        mutation: Mutation,
    },
    Dispatched {
        schema: String,
        intent: String,
    },
    Settled {
        schema: String,
        intent: String,
        outcome: String,
    },
    Abandoned {
        schema: String,
        intent: String,
        outcome: String,
    },
    /// A closed intent's summary, kept (bounded) for RJ-03 after the
    /// intent's own lines are compacted away.
    Outcome {
        schema: String,
        intent: String,
        capability: String,
        operation: String,
        workspace_id: String,
        target: String,
        outcome: String,
        at_ms: u64,
    },
}

impl Line {
    fn schema(&self) -> &str {
        match self {
            Line::Pending { schema, .. }
            | Line::Dispatched { schema, .. }
            | Line::Settled { schema, .. }
            | Line::Abandoned { schema, .. }
            | Line::Outcome { schema, .. } => schema,
        }
    }

    fn intent_event(&self) -> Option<(&str, IntentState)> {
        match self {
            Line::Pending { intent, .. } => Some((intent, IntentState::Pending)),
            Line::Dispatched { intent, .. } => Some((intent, IntentState::Dispatched)),
            Line::Settled { intent, .. } => Some((intent, IntentState::Settled)),
            Line::Abandoned { intent, .. } => Some((intent, IntentState::Abandoned)),
            Line::Outcome { .. } => None,
        }
    }
}

/// How an exited run's dispatched mutation turned out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reconciled {
    /// The postcondition holds.
    Done,
    /// The target is as it was before: the effect never happened.
    NothingDone,
    /// Neither: orceld cannot tell. Nothing is retried.
    Unknown,
}

impl Reconciled {
    fn outcome(&self) -> &'static str {
        match self {
            Reconciled::Done => "reconciled_done",
            Reconciled::NothingDone => "reconciled_nothing_done",
            Reconciled::Unknown => "reconciled_unknown",
        }
    }
}

enum Found {
    Missing,
    Directory,
    File(String),
    Other,
}

/// What is at `relative` under `root`, without following a final link.
fn found(root: &Path, relative: &str) -> Found {
    let path = root.join(relative);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Found::Missing,
        Err(_) => Found::Other,
        Ok(metadata) if metadata.file_type().is_symlink() => Found::Other,
        Ok(metadata) if metadata.is_dir() => Found::Directory,
        // A file too large to hash at start is not guessed at.
        Ok(metadata) if metadata.is_file() && metadata.len() > MAX_RECONCILE_BYTES => Found::Other,
        Ok(metadata) if metadata.is_file() => match std::fs::read(&path) {
            Ok(bytes) => {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(&bytes);
                Found::File(hash.iter().map(|byte| format!("{byte:02x}")).collect())
            }
            Err(_) => Found::Other,
        },
        Ok(_) => Found::Other,
    }
}

/// Compares a dispatched mutation's target with its postcondition only.
pub(crate) fn reconcile(mutation: &Mutation) -> Reconciled {
    let root = &mutation.root;
    match &mutation.postcondition {
        Postcondition::File { sha256, before } => match found(root, &mutation.target) {
            Found::File(now) if &now == sha256 => Reconciled::Done,
            Found::File(now) if before.as_deref() == Some(now.as_str()) => Reconciled::NothingDone,
            Found::Missing if before.is_none() => Reconciled::NothingDone,
            _ => Reconciled::Unknown,
        },
        Postcondition::Directory => match found(root, &mutation.target) {
            Found::Directory => Reconciled::Done,
            Found::Missing => Reconciled::NothingDone,
            _ => Reconciled::Unknown,
        },
        Postcondition::Moved { to, sha256 } => {
            let source = found(root, &mutation.target);
            let destination = found(root, to);
            let moved = match (&destination, sha256) {
                (Found::File(now), Some(expected)) => now == expected,
                (Found::Directory, None) => true,
                _ => false,
            };
            let unmoved = match (&source, sha256) {
                (Found::File(now), Some(expected)) => now == expected,
                (Found::Directory, None) => true,
                _ => false,
            };
            match (source, destination) {
                (Found::Missing, _) if moved => Reconciled::Done,
                (_, Found::Missing) if unmoved => Reconciled::NothingDone,
                _ => Reconciled::Unknown,
            }
        }
        Postcondition::Absent {
            before_kind,
            before_sha256,
        } => match found(root, &mutation.target) {
            Found::Missing => Reconciled::Done,
            Found::File(now)
                if before_kind == "file" && before_sha256.as_deref() == Some(now.as_str()) =>
            {
                Reconciled::NothingDone
            }
            Found::Directory if before_kind == "directory" => Reconciled::NothingDone,
            _ => Reconciled::Unknown,
        },
    }
}

pub(crate) struct MutationJournal {
    path: PathBuf,
    owner: Owner,
    counter: std::sync::atomic::AtomicU64,
}

/// What a starting orceld found.
#[derive(Debug)]
pub(crate) struct Restored {
    pub torn: usize,
    pub reconciled: usize,
}

fn unavailable() -> ProviderError {
    ProviderError::new(
        FailureCode::ProviderUnavailable,
        "the mutation journal could not be written; nothing was asked, spent or changed",
    )
}

impl MutationJournal {
    fn new(path: PathBuf, owner: Owner) -> Self {
        Self {
            path,
            owner,
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn line(&self, line: &Line) -> Result<(), JournalError> {
        orcel_journal::append_shared(&self.path, line, LOCK_WAIT)
    }

    /// Reconciles the open intents of exited runs (newest first), records
    /// their outcomes, and compacts the journal to live runs' open intents
    /// plus the newest [`MAX_OUTCOMES`] outcomes.
    fn restore(&self) -> Result<Restored, JournalError> {
        orcel_journal::with_lock(&self.path, LOCK_WAIT, || {
            let read = orcel_journal::read_lines::<Line>(&self.path)?;
            if read.lines.iter().any(|line| line.schema() != SCHEMA) {
                return Err(JournalError::Unreadable);
            }
            let open = orcel_journal::recover(read.lines.iter().filter_map(Line::intent_event))?;
            let mut pending: Vec<(Owner, String, Mutation, IntentState)> = Vec::new();
            let mut outcomes: Vec<Line> = Vec::new();
            let mut closed: Vec<(String, String)> = Vec::new();
            let mut mutations: Vec<(String, Mutation)> = Vec::new();
            for line in &read.lines {
                match line {
                    Line::Pending {
                        owner,
                        intent,
                        mutation,
                        ..
                    } => {
                        mutations.push((intent.clone(), mutation.clone()));
                        if let Some((_, state)) = open.iter().find(|(id, _)| id == intent) {
                            pending.push((owner.clone(), intent.clone(), mutation.clone(), *state));
                        }
                    }
                    Line::Settled {
                        intent, outcome, ..
                    }
                    | Line::Abandoned {
                        intent, outcome, ..
                    } => closed.push((intent.clone(), outcome.clone())),
                    Line::Outcome { .. } => outcomes.push(line.clone()),
                    Line::Dispatched { .. } => {}
                }
            }
            let now = orcel_approval::now_ms();
            let summary = |intent: &str, mutation: &Mutation, outcome: &str| Line::Outcome {
                schema: SCHEMA.to_owned(),
                intent: intent.to_owned(),
                capability: mutation.capability.clone(),
                operation: mutation.operation.clone(),
                workspace_id: mutation.workspace_id.clone(),
                target: mutation.target.clone(),
                outcome: outcome.to_owned(),
                at_ms: now,
            };
            // Intents closed by their own run become outcome summaries.
            for (intent, outcome) in &closed {
                if let Some((_, mutation)) = mutations.iter().find(|(id, _)| id == intent) {
                    outcomes.push(summary(intent, mutation, outcome));
                }
            }
            let mut reconciled = 0;
            let mut kept_groups: Vec<Vec<Line>> = Vec::new();
            for (owner, intent, mutation, state) in pending.into_iter().rev() {
                if owner.run == self.owner.run || !owner.has_exited() {
                    let mut group = vec![Line::Pending {
                        schema: SCHEMA.to_owned(),
                        owner,
                        intent: intent.clone(),
                        mutation,
                    }];
                    if state == IntentState::Dispatched {
                        group.push(Line::Dispatched {
                            schema: SCHEMA.to_owned(),
                            intent,
                        });
                    }
                    kept_groups.push(group);
                    continue;
                }
                let result = if state == IntentState::Dispatched {
                    reconcile(&mutation)
                } else {
                    Reconciled::NothingDone
                };
                reconciled += 1;
                outcomes.push(summary(&intent, &mutation, result.outcome()));
            }
            if outcomes.len() > MAX_OUTCOMES {
                outcomes.drain(..outcomes.len() - MAX_OUTCOMES);
            }
            let mut kept = outcomes;
            kept.extend(kept_groups.into_iter().rev().flatten());
            orcel_journal::rewrite(&self.path, &kept)?;
            Ok(Restored {
                torn: read.torn,
                reconciled,
            })
        })
    }
}

/// The journal of this orceld, set once at start. `Unset` only in unit
/// tests that never start orceld; product orceld is always `Ready` or
/// `Faulted`.
enum State {
    Ready(MutationJournal),
    Faulted,
}

static JOURNAL: OnceLock<State> = OnceLock::new();

/// `ORCEL_MUTATION_JOURNAL_PATH`, else `mutations.jsonl` in the private
/// state root beside the audit log. Fails closed.
pub(crate) fn default_path() -> Result<PathBuf, orcel_platform::PlatformError> {
    use orcel_platform::paths;
    if let Some(path) = std::env::var_os("ORCEL_MUTATION_JOURNAL_PATH") {
        return paths::private_file_override(path);
    }
    let root = paths::state_root()?;
    paths::ensure_private_dir(&root)?;
    Ok(root.join("mutations.jsonl"))
}

/// Opens this orceld's mutation journal: reconciles what exited runs left
/// open. A journal that cannot be opened or read refuses every journaled
/// mutation instead of running it unjournaled.
pub(crate) fn start(path: Result<PathBuf, orcel_platform::PlatformError>, run: &str) {
    let state = match (path, Owner::current(run)) {
        (Ok(path), Some(owner)) => {
            let journal = MutationJournal::new(path, owner);
            match journal.restore() {
                Ok(restored) => {
                    if restored.torn > 0 {
                        eprintln!(
                            "orceld mutation journal: skipped {} torn line(s) left by a crash",
                            restored.torn
                        );
                    }
                    if restored.reconciled > 0 {
                        eprintln!(
                            "orceld mutation journal: reconciled {} mutation(s) an exited orceld left open",
                            restored.reconciled
                        );
                    }
                    State::Ready(journal)
                }
                Err(JournalError::Busy) => {
                    eprintln!("orceld mutation journal: busy in another orceld at start; file mutations are refused in this session, restart it to retry");
                    State::Faulted
                }
                Err(failure) => {
                    eprintln!("orceld mutation journal: {failure}; file mutations are refused until it is repaired");
                    State::Faulted
                }
            }
        }
        (Err(failure), _) => {
            eprintln!("orceld mutation journal: no private location ({failure}); file mutations are refused");
            State::Faulted
        }
        (_, None) => {
            eprintln!("orceld mutation journal: this process's identity is unavailable; file mutations are refused");
            State::Faulted
        }
    };
    let _ = JOURNAL.set(state);
}

/// One journaled mutation in flight.
pub(crate) struct Intent {
    id: String,
    journal: Option<&'static MutationJournal>,
    closed: bool,
}

/// Where a mutation is journaled.
#[derive(Clone, Copy)]
pub(crate) enum Sink {
    /// No journal was started (unit tests that never start orceld).
    None,
    /// The journal could not be opened or read: every mutation is refused.
    Faulted,
    Journal(&'static MutationJournal),
}

/// This orceld's sink.
pub(crate) fn global() -> Sink {
    match JOURNAL.get() {
        None => Sink::None,
        Some(State::Faulted) => Sink::Faulted,
        Some(State::Ready(journal)) => Sink::Journal(journal),
    }
}

/// Records `mutation` before its approval is asked for. Refuses (nothing
/// asked) when the journal is faulted or the line cannot be written.
pub(crate) fn pending(sink: Sink, mutation: Mutation) -> Result<Intent, ProviderError> {
    let journal = match sink {
        Sink::None => {
            return Ok(Intent {
                id: String::new(),
                journal: None,
                closed: true,
            })
        }
        Sink::Faulted => return Err(ProviderError::new(
            FailureCode::ProviderUnavailable,
            "the mutation journal is unavailable; file mutations are refused until it is repaired",
        )),
        Sink::Journal(journal) => journal,
    };
    let n = journal
        .counter
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let id = format!("{}.m{n}", journal.owner.run);
    orcel_journal::append_opening_shared(
        &journal.path,
        &Line::Pending {
            schema: SCHEMA.to_owned(),
            owner: journal.owner.clone(),
            intent: id.clone(),
            mutation,
        },
        LOCK_WAIT,
    )
    .map_err(|_| unavailable())?;
    Ok(Intent {
        id,
        journal: Some(journal),
        closed: false,
    })
}

impl Intent {
    /// Immediately before the provider acts. If it cannot be written the
    /// provider must not act; the intent is then closed `not_dispatched`.
    pub(crate) fn dispatched(&mut self) -> Result<(), ProviderError> {
        let Some(journal) = self.journal else {
            return Ok(());
        };
        let written = journal.line(&Line::Dispatched {
            schema: SCHEMA.to_owned(),
            intent: self.id.clone(),
        });
        if written.is_err() {
            // Settled is lawful after pending and after dispatched (the
            // line may be on disk although the write reported failure).
            self.settle("not_dispatched");
            return Err(unavailable());
        }
        Ok(())
    }

    /// The effect never started (refused, denied or blocked).
    pub(crate) fn abandon(&mut self, outcome: &str) {
        if self.closed {
            return;
        }
        self.closed = true;
        if let Some(journal) = self.journal {
            let _ = journal.line(&Line::Abandoned {
                schema: SCHEMA.to_owned(),
                intent: self.id.clone(),
                outcome: outcome.to_owned(),
            });
        }
    }

    /// The provider acted; its outcome is known.
    pub(crate) fn settle(&mut self, outcome: &str) {
        if self.closed {
            return;
        }
        self.closed = true;
        if let Some(journal) = self.journal {
            let _ = journal.line(&Line::Settled {
                schema: SCHEMA.to_owned(),
                intent: self.id.clone(),
                outcome: outcome.to_owned(),
            });
        }
    }
}

/// Runs one journaled mutation: `pending` before `approve`, `dispatched`
/// before `act`, then the outcome. A failure of `approve` abandons the
/// intent; `act`'s result settles it.
pub(crate) fn journaled<T>(
    sink: Sink,
    mutation: Mutation,
    approve: impl FnOnce() -> Result<(), ProviderError>,
    act: impl FnOnce() -> Result<T, ProviderError>,
) -> Result<T, ProviderError> {
    let mut intent = pending(sink, mutation)?;
    if let Err(refusal) = approve() {
        intent.abandon(match refusal.code {
            FailureCode::ApprovalDenied => "approval_denied",
            _ => "approval_unavailable",
        });
        return Err(refusal);
    }
    intent.dispatched()?;
    let result = act();
    intent.settle(if result.is_ok() { "done" } else { "failed" });
    result
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A journal at `path` owned by this process with run `run`.
    pub(crate) fn journal(path: PathBuf, run: &str) -> MutationJournal {
        MutationJournal::new(path, Owner::current(run).unwrap())
    }

    /// A journal at `path` whose owner process does not exist.
    pub(crate) fn exited_journal(path: PathBuf, run: &str) -> MutationJournal {
        MutationJournal::new(
            path,
            Owner {
                run: run.to_owned(),
                pid: 0x7FFF_FFF0,
                generation: 1,
                boot_id: None,
            },
        )
    }

    pub(crate) fn restore(journal: &MutationJournal) -> Restored {
        journal.restore().unwrap()
    }

    /// Writes an intent as `journal`'s run would, optionally dispatched,
    /// and leaves it open (as a crash would).
    pub(crate) fn leave_open(
        journal: &MutationJournal,
        intent: &str,
        mutation: Mutation,
        dispatched: bool,
    ) {
        journal
            .line(&Line::Pending {
                schema: SCHEMA.to_owned(),
                owner: journal.owner.clone(),
                intent: intent.to_owned(),
                mutation,
            })
            .unwrap();
        if dispatched {
            journal
                .line(&Line::Dispatched {
                    schema: SCHEMA.to_owned(),
                    intent: intent.to_owned(),
                })
                .unwrap();
        }
    }
}

#[cfg(test)]
#[path = "mutation_journal_tests.rs"]
mod tests;
