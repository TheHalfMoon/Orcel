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

use crate::journal_owner::Owner;
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
/// Longest a starting orceld spends probing targets; intents left after it
/// are recorded unknown rather than delaying the start.
const RECONCILE_BUDGET: Duration = Duration::from_secs(60);

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
    /// A directory at the target. `created` is the first missing path
    /// on the way to it (the target itself when its parent existed): if
    /// that is still missing, nothing was created. Empty when the target
    /// already existed: the provider refuses, so a dispatched one is
    /// unknown.
    Directory { created: String },
    /// The target moved to `to` (workspace-relative); `sha256` is the
    /// moved file's hash when it was a file.
    Moved { to: String, sha256: Option<String> },
    /// Nothing at the target; `before` identifies what was there.
    Absent {
        before_kind: String,
        before_sha256: Option<String>,
    },
    /// Git (target: the repository): `refs/heads/<branch>` created at
    /// `head` and checked out.
    GitBranch { branch: String, head: String },
    /// Git: one commit on `branch` with parent `parent` and a message
    /// whose normalized SHA-256 is `message_sha256` (never the message).
    GitCommit {
        branch: String,
        parent: String,
        message_sha256: String,
    },
    /// Git index changes (stage, unstage): not probed; a dispatched one
    /// is unknown.
    GitIndex,
    /// A network effect (push, fetch): never probed, so a dispatched one
    /// is unknown, and so is an error after dispatch.
    Remote,
    /// An effect orceld cannot read back (a process run, a clipboard
    /// placement, desktop input or a UI action): a dispatched one is
    /// unknown, and so is an error after dispatch.
    Opaque,
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
        at_ms: u64,
    },
    Abandoned {
        schema: String,
        intent: String,
        outcome: String,
        at_ms: u64,
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

/// `relative` as a path under `root`, or `None` when it is not a plain
/// workspace-relative path whose nearest existing ancestor resolves
/// inside `root`.
fn confined(root: &Path, relative: &str) -> Option<PathBuf> {
    use std::path::Component;
    let path = Path::new(relative);
    if relative.is_empty()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return None;
    }
    let root = std::fs::canonicalize(root).ok()?;
    let joined = root.join(path);
    // A link swapped in since the effect cannot point the check elsewhere.
    let mut ancestor = joined.parent()?;
    loop {
        match std::fs::canonicalize(ancestor) {
            Ok(resolved) if resolved.starts_with(&root) => return Some(joined),
            Ok(_) => return None,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ancestor = ancestor.parent()?;
            }
            Err(_) => return None,
        }
    }
}

/// The first path on the way to `relative` that does not exist yet: what
/// `mkdir` creates first. `relative` itself when its parent exists, or
/// when it is not a plain relative path (the provider then refuses it);
/// empty when the whole path already exists.
pub(crate) fn first_missing(root: &Path, relative: &str) -> String {
    use std::path::Component;
    let mut prefix = PathBuf::new();
    let mut shown: Vec<&str> = Vec::new();
    for component in Path::new(relative).components() {
        let Component::Normal(part) = component else {
            return relative.to_owned();
        };
        let Some(part) = part.to_str() else {
            return relative.to_owned();
        };
        prefix.push(part);
        shown.push(part);
        if let Err(error) = std::fs::symlink_metadata(root.join(&prefix)) {
            if error.kind() == std::io::ErrorKind::NotFound {
                return shown.join("/");
            }
        }
    }
    String::new()
}

/// What is at `relative` under `root`, without following a final link.
fn found(root: &Path, relative: &str) -> Found {
    let Some(path) = confined(root, relative) else {
        return Found::Other;
    };
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Found::Missing,
        Err(_) => Found::Other,
        Ok(metadata) if metadata.file_type().is_symlink() => Found::Other,
        Ok(metadata) if metadata.is_dir() && !crate::report_check::is_reparse_point(&metadata) => {
            Found::Directory
        }
        // A file too large to hash at start is not guessed at.
        Ok(metadata) if metadata.is_file() => {
            match crate::report_check::hash_regular_file(&path, MAX_RECONCILE_BYTES) {
                Ok((sha256, _)) => Found::File(sha256),
                Err(_) => Found::Other,
            }
        }
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
        Postcondition::Directory { created } if created.is_empty() => Reconciled::Unknown,
        Postcondition::Directory { created } => match found(root, &mutation.target) {
            Found::Directory => Reconciled::Done,
            Found::Missing if matches!(found(root, created), Found::Missing) => {
                Reconciled::NothingDone
            }
            // Some missing parents now exist but not the target: partly done.
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
        Postcondition::GitBranch { .. } | Postcondition::GitCommit { .. } => {
            crate::git_mutation::reconcile(root, &mutation.target, &mutation.postcondition)
        }
        Postcondition::GitIndex | Postcondition::Remote | Postcondition::Opaque => {
            Reconciled::Unknown
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
    /// Targets whose latest outcome is unknown, by (workspace, target).
    unknown: std::sync::Mutex<std::collections::HashMap<(String, String), Unknown>>,
}

/// A target whose latest approved step has an unknown outcome. A dependent
/// step (the next mutation of the same target in the same workspace) is
/// refused once with this named; the request after that asks for a new
/// explicit approval whose prompt says so (see [`UnknownNotice`]).
#[derive(Debug, Clone)]
struct Unknown {
    intent: String,
    operation: String,
    /// The refusal was returned: the next request may ask for approval.
    surfaced: bool,
}

/// How an outcome changes what is known about its target: `Some(true)`
/// unknown, `Some(false)` known again (it acted, or nothing happened after
/// a dispatch), `None` no change (it never started).
fn leaves_unknown(outcome: &str) -> Option<bool> {
    match outcome {
        "unknown" | "reconciled_unknown" => Some(true),
        "done" | "failed" | "reconciled_done" | "reconciled_nothing_done" => Some(false),
        _ => None,
    }
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
            unknown: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn unknown_targets(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<(String, String), Unknown>> {
        // The map holds no invariant a panicking holder could break.
        self.unknown
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Records `outcome` of `intent` for its target.
    fn note(&self, workspace_id: &str, target: &str, intent: &str, operation: &str, outcome: &str) {
        let key = (workspace_id.to_owned(), target.to_owned());
        match leaves_unknown(outcome) {
            Some(true) => {
                self.unknown_targets().insert(
                    key,
                    Unknown {
                        intent: intent.to_owned(),
                        operation: operation.to_owned(),
                        surfaced: false,
                    },
                );
            }
            Some(false) => {
                self.unknown_targets().remove(&key);
            }
            None => {}
        }
    }

    /// The operation of the unknown step on this target once its refusal
    /// was returned: the prompt of the next approval must name it.
    fn surfaced_unknown(&self, workspace_id: &str, target: &str) -> Option<String> {
        self.unknown_targets()
            .get(&(workspace_id.to_owned(), target.to_owned()))
            .filter(|unknown| unknown.surfaced)
            .map(|unknown| unknown.operation.clone())
    }

    fn line(&self, line: &Line) -> Result<(), JournalError> {
        orcel_journal::append_shared(&self.path, line, LOCK_WAIT)
    }

    /// Reconciles the open intents of exited runs, records their outcomes
    /// in journal order, and compacts the journal to live runs' open intents
    /// plus the newest [`MAX_OUTCOMES`] outcomes.
    fn restore(&self) -> Result<Restored, JournalError> {
        orcel_journal::with_lock(&self.path, LOCK_WAIT, || {
            let read = orcel_journal::read_lines::<Line>(&self.path)?;
            if read.lines.iter().any(|line| line.schema() != SCHEMA) {
                return Err(JournalError::Unreadable);
            }
            let open: std::collections::HashMap<String, IntentState> =
                orcel_journal::recover(read.lines.iter().filter_map(Line::intent_event))?
                    .into_iter()
                    .collect();
            let mut mutations: std::collections::HashMap<&str, &Mutation> =
                std::collections::HashMap::new();
            let summary =
                |intent: &str, mutation: &Mutation, outcome: &str, at_ms: u64| Line::Outcome {
                    schema: SCHEMA.to_owned(),
                    intent: intent.to_owned(),
                    capability: mutation.capability.clone(),
                    operation: mutation.operation.clone(),
                    workspace_id: mutation.workspace_id.clone(),
                    target: mutation.target.clone(),
                    outcome: outcome.to_owned(),
                    at_ms,
                };
            let now = orcel_approval::now_ms();
            let deadline = std::time::Instant::now() + RECONCILE_BUDGET;
            // Outcomes stay in journal order, so the bound drops the oldest.
            let mut outcomes: Vec<Line> = Vec::new();
            let mut live: Vec<Line> = Vec::new();
            let mut reconciled = 0;
            for line in &read.lines {
                match line {
                    Line::Pending {
                        owner,
                        intent,
                        mutation,
                        ..
                    } => {
                        mutations.insert(intent, mutation);
                        let Some(state) = open.get(intent).copied() else {
                            continue;
                        };
                        if owner.run == self.owner.run || !owner.has_exited() {
                            live.push(line.clone());
                            if state == IntentState::Dispatched {
                                live.push(Line::Dispatched {
                                    schema: SCHEMA.to_owned(),
                                    intent: intent.clone(),
                                });
                            }
                            continue;
                        }
                        let result = if state != IntentState::Dispatched {
                            Reconciled::NothingDone
                        } else if std::time::Instant::now() < deadline {
                            reconcile(mutation)
                        } else {
                            Reconciled::Unknown
                        };
                        reconciled += 1;
                        outcomes.push(summary(intent, mutation, result.outcome(), now));
                    }
                    Line::Settled {
                        intent,
                        outcome,
                        at_ms,
                        ..
                    }
                    | Line::Abandoned {
                        intent,
                        outcome,
                        at_ms,
                        ..
                    } => {
                        if let Some(mutation) = mutations.get(intent.as_str()) {
                            outcomes.push(summary(intent, mutation, outcome, *at_ms));
                        }
                    }
                    Line::Outcome { .. } => outcomes.push(line.clone()),
                    Line::Dispatched { .. } => {}
                }
            }
            if outcomes.len() > MAX_OUTCOMES {
                outcomes.drain(..outcomes.len() - MAX_OUTCOMES);
            }
            // What is known about each target, oldest outcome first.
            for line in &outcomes {
                if let Line::Outcome {
                    intent,
                    operation,
                    workspace_id,
                    target,
                    outcome,
                    ..
                } = line
                {
                    self.note(workspace_id, target, intent, operation, outcome);
                }
            }
            let mut kept = outcomes;
            kept.extend(live);
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
                    eprintln!("orceld mutation journal: busy in another orceld at start; approved effects (files, Git, processes, clipboard, desktop) are refused in this session, restart it to retry");
                    State::Faulted
                }
                Err(failure) => {
                    eprintln!("orceld mutation journal: {failure}; approved effects (files, Git, processes, clipboard, desktop) are refused until it is repaired");
                    State::Faulted
                }
            }
        }
        (Err(failure), _) => {
            eprintln!("orceld mutation journal: no private location ({failure}); approved effects (files, Git, processes, clipboard, desktop) are refused");
            State::Faulted
        }
        (_, None) => {
            eprintln!("orceld mutation journal: this process's identity is unavailable; approved effects (files, Git, processes, clipboard, desktop) are refused");
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
    /// (workspace, target, operation) of the mutation.
    key: (String, String, String),
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

/// An [`Postcondition::Opaque`] mutation of `request` on `target` (an
/// identifier such as an element id or executable path; never content).
pub(crate) fn opaque(
    workspace: &orcel_policy::Workspace,
    request: &orcel_contracts::RequestEnvelope,
    approval_digest: &str,
    target: &str,
) -> Mutation {
    Mutation {
        capability: request.capability.clone(),
        operation: request.operation.clone(),
        approval_digest: approval_digest.to_owned(),
        workspace_id: workspace.id.clone(),
        policy_revision: orcel_policy::POLICY_REVISION.to_owned(),
        root: workspace.root.clone(),
        target: target.to_owned(),
        postcondition: Postcondition::Opaque,
    }
}

/// The approval broker every dispatch uses: when the target's latest step
/// has an unknown outcome (and its refusal was returned), the prompt of the
/// new approval says so before anything else. Nothing else changes.
pub(crate) struct UnknownNotice<'a, B> {
    pub(crate) approval: &'a B,
    pub(crate) sink: Sink,
}

impl<B: orcel_approval::ApprovalBroker> orcel_approval::ApprovalBroker for UnknownNotice<'_, B> {
    fn request_token(
        &self,
        prompt: &orcel_approval::ApprovalPrompt,
    ) -> Result<orcel_approval::ApprovedToken, orcel_approval::ApprovalError> {
        let earlier = match self.sink {
            Sink::Journal(journal) => {
                journal.surfaced_unknown(&prompt.workspace_id, &prompt.target)
            }
            Sink::None | Sink::Faulted => None,
        };
        match earlier {
            Some(operation) => {
                let mut noticed = prompt.clone();
                noticed.summary = format!(
                    "UNKNOWN EARLIER OUTCOME: an earlier approved {operation} on this target \
                     may or may not have happened and was not retried; check the current \
                     state before approving. {}",
                    prompt.summary
                );
                self.approval.request_token(&noticed)
            }
            None => self.approval.request_token(prompt),
        }
    }

    fn consume(
        &self,
        token: &orcel_approval::ApprovedToken,
        expected: &orcel_approval::ConsumeExpectation,
        now_ms: u64,
    ) -> Result<(), orcel_approval::ApprovalError> {
        self.approval.consume(token, expected, now_ms)
    }

    fn emergency_revoke(
        &self,
        prompt: &orcel_approval::ApprovalPrompt,
    ) -> Result<u64, orcel_approval::ApprovalError> {
        self.approval.emergency_revoke(prompt)
    }

    fn history(&self, limit: usize) -> Vec<orcel_approval::ApprovalRecordSummary> {
        self.approval.history(limit)
    }
}

/// This orceld's sink.
pub(crate) fn global() -> Sink {
    match JOURNAL.get() {
        // Unit tests that never start orceld; product orceld always
        // starts the journal, so an unset one there refuses.
        None if cfg!(test) => Sink::None,
        None => Sink::Faulted,
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
                key: Default::default(),
            })
        }
        Sink::Faulted => return Err(ProviderError::new(
            FailureCode::ProviderUnavailable,
            "the mutation journal is unavailable; approved effects (files, Git, processes, clipboard, desktop) are refused until it is repaired",
        )),
        Sink::Journal(journal) => journal,
    };
    // SG-000120 RJ-02: a dependent step after an unknown outcome is
    // refused once; nothing is ever retried in its place.
    {
        let mut unknown = journal.unknown_targets();
        let key = (mutation.workspace_id.clone(), mutation.target.clone());
        if let Some(earlier) = unknown.get_mut(&key) {
            if !earlier.surfaced {
                earlier.surfaced = true;
                return Err(ProviderError::new(
                    FailureCode::TargetStale,
                    format!(
                        "an earlier approved {} on this target ({}) has an unknown outcome and \
                         was not retried; verify the target's current state, then request \
                         again: the next request asks for a new explicit approval that names \
                         the unknown outcome",
                        earlier.operation, earlier.intent
                    ),
                ));
            }
        }
    }
    let key = (
        mutation.workspace_id.clone(),
        mutation.target.clone(),
        mutation.operation.clone(),
    );
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
        key,
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
            return Err(ProviderError::new(
                FailureCode::ProviderUnavailable,
                "the mutation journal could not be written after approval; the approval is \
                 spent and nothing was changed; request the change again",
            ));
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
            // A close line that cannot be written leaves the intent open;
            // the next orceld reconciles it by its postcondition.
            let _ = journal.line(&Line::Abandoned {
                schema: SCHEMA.to_owned(),
                intent: self.id.clone(),
                outcome: outcome.to_owned(),
                at_ms: orcel_approval::now_ms(),
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
            // As in `abandon`: unwritten, it is reconciled on restart.
            let _ = journal.line(&Line::Settled {
                schema: SCHEMA.to_owned(),
                intent: self.id.clone(),
                outcome: outcome.to_owned(),
                at_ms: orcel_approval::now_ms(),
            });
            let (workspace_id, target, operation) = &self.key;
            journal.note(workspace_id, target, &self.id, operation, outcome);
        }
    }
}

/// Runs one journaled mutation: `pending` before `approve`, `dispatched`
/// before `act`, then the outcome. A failure of `approve` abandons the
/// intent; `act`'s result settles it (`unknown` when a failed Git or
/// network effect may still have acted).
pub(crate) fn journaled<T>(
    sink: Sink,
    mutation: Mutation,
    approve: impl FnOnce() -> Result<(), ProviderError>,
    act: impl FnOnce() -> Result<T, ProviderError>,
) -> Result<T, ProviderError> {
    journaled_with(sink, mutation, approve, |()| act())
}

/// [`journaled`], where the approval step hands its result (the spent
/// token) to the effect.
pub(crate) fn journaled_with<A, T>(
    sink: Sink,
    mutation: Mutation,
    approve: impl FnOnce() -> Result<A, ProviderError>,
    act: impl FnOnce(A) -> Result<T, ProviderError>,
) -> Result<T, ProviderError> {
    // A Git command can fail (timeout, postcondition) after it changed the
    // repository, and a network effect after it reached the remote.
    let uncertain = matches!(
        mutation.postcondition,
        Postcondition::Remote
            | Postcondition::GitBranch { .. }
            | Postcondition::GitCommit { .. }
            | Postcondition::GitIndex
            | Postcondition::Opaque
    );
    let mut intent = pending(sink, mutation)?;
    crash_point("pending");
    let approved = match approve() {
        Ok(approved) => approved,
        Err(refusal) => {
            intent.abandon(match refusal.code {
                FailureCode::ApprovalDenied => "approval_denied",
                FailureCode::TargetStale => "target_stale",
                _ => "approval_unavailable",
            });
            return Err(refusal);
        }
    };
    intent.dispatched()?;
    crash_point("dispatched");
    let result = act(approved);
    crash_point("effect");
    intent.settle(match (&result, uncertain) {
        (Ok(_), _) => "done",
        (Err(_), true) => "unknown",
        (Err(_), false) => "failed",
    });
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
        MutationJournal::new(path, Owner::exited(run))
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

#[cfg(test)]
#[path = "mutation_journal_git_tests.rs"]
mod git_tests;

/// Test builds only: the fault-injection suite's child process dies here
/// when `ORCEL_RJ02_CRASH_AT` names this transition. Product builds have
/// no such point.
#[cfg(test)]
pub(crate) fn crash_point(at: &str) {
    if std::env::var("ORCEL_RJ02_CRASH_AT").as_deref() == Ok(at) {
        std::process::abort();
    }
}

#[cfg(not(test))]
pub(crate) fn crash_point(_at: &str) {}

#[cfg(test)]
#[path = "mutation_journal_crash_tests.rs"]
mod crash_tests;
