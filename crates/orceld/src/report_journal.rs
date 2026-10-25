//! SG-000120 RJ-02 (report provider): the durable journal of SG-000126
//! report tasks, under orceld's private state root.
//!
//! Every orceld (one per MCP session) appends to the same journal under its
//! writer lock, taken per line:
//!
//! - `task` lines are snapshots of a task record (ids, paths, sizes, hashes,
//!   states and step outcomes, never file content), written best effort
//!   after every step, so `task.list` and `task.get` keep showing a task
//!   after its orceld exits;
//! - a commit records `pending` before it asks for approval (if that cannot
//!   be written, nothing is asked and nothing is spent), and `settled` or
//!   `abandoned` once it knows the outcome.
//!
//! When an orceld starts, it reconciles every commit left `pending` by an
//! orceld that has exited (never one that still runs): a destination that
//! does not exist was never written (`abandoned`); one that exists is
//! re-read by the independent checker (`verified` only when it passes);
//! anything else is `unknown`. Nothing is written to the user's files and
//! nothing is retried. Tasks of exited runs come back read-only; a task of
//! an earlier run cannot be previewed or committed again.

use super::{error, Proposal, ReportTask, SourceRecord, Step, TaskState, MAX_STEPS, MAX_TASKS};
use crate::report_check;
use orcel_contracts::FailureCode;
use orcel_journal::{IntentState, JournalError};
use orcel_provider_fs::ProviderError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;

const SCHEMA: &str = "orcel-report-task/1";
/// How long one append waits for another orceld's line.
const LOCK_WAIT: Duration = Duration::from_secs(5);
/// Most tasks of earlier runs a starting orceld shows and keeps.
pub(super) const MAX_EARLIER_TASKS: usize = MAX_TASKS / 2;

/// The orceld run that wrote a line: its process instance and run id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Owner {
    run: String,
    pid: u32,
    generation: u64,
    /// Linux boot id, as decimal text (a u128 does not survive JSON).
    boot_id: Option<String>,
}

impl Owner {
    pub(super) fn current(run: &str) -> Option<Self> {
        let instance = orcel_platform::process::current_instance().ok()?;
        Some(Self {
            run: run.to_owned(),
            pid: instance.pid,
            generation: instance.generation,
            boot_id: instance.boot_id.map(|id| id.to_string()),
        })
    }

    /// Whether this run's process has exited. An identity the OS will not
    /// report counts as running, so a live orceld's commit is never touched.
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
struct SourceLine {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProposalLine {
    name: String,
    destination: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct StepLine {
    step_id: String,
    kind: String,
    outcome: String,
    at_ms: u64,
}

/// One task record, as `task.get` reports it plus the canonical folder.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct TaskLine {
    id: String,
    workspace_id: String,
    folder: String,
    folder_canonical: PathBuf,
    sources: Vec<SourceLine>,
    proposal: Option<ProposalLine>,
    report: Option<ProposalLine>,
    check: Option<Value>,
    state: String,
    steps: Vec<StepLine>,
    next_step: u64,
    created_at_ms: u64,
    updated_at_ms: u64,
}

/// What a pending commit needs to be reconciled without its orceld.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CommitLine {
    pub task_id: String,
    /// The approval this commit asks for: its digest, workspace and policy
    /// revision (the intent is bound to exactly that approval).
    pub approval_digest: String,
    pub workspace_id: String,
    pub policy_revision: String,
    pub root: PathBuf,
    pub folder: String,
    pub folder_canonical: PathBuf,
    pub destination: String,
    pub sha256: String,
    pub bytes: u64,
    sources: Vec<SourceLine>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Line {
    Task {
        schema: String,
        owner: Owner,
        task: TaskLine,
    },
    Pending {
        schema: String,
        owner: Owner,
        intent: String,
        commit: CommitLine,
    },
    /// Written immediately before the create: from here on the effect may
    /// have started.
    Dispatched { schema: String, intent: String },
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
}

impl Line {
    fn schema(&self) -> &str {
        match self {
            Line::Task { schema, .. }
            | Line::Pending { schema, .. }
            | Line::Dispatched { schema, .. }
            | Line::Settled { schema, .. }
            | Line::Abandoned { schema, .. } => schema,
        }
    }

    fn intent_event(&self) -> Option<(&str, IntentState)> {
        match self {
            Line::Task { .. } => None,
            Line::Pending { intent, .. } => Some((intent, IntentState::Pending)),
            Line::Dispatched { intent, .. } => Some((intent, IntentState::Dispatched)),
            Line::Settled { intent, .. } => Some((intent, IntentState::Settled)),
            Line::Abandoned { intent, .. } => Some((intent, IntentState::Abandoned)),
        }
    }
}

pub(super) fn task_line(task: &ReportTask) -> TaskLine {
    let source = |source: &SourceRecord| SourceLine {
        path: source.path.clone(),
        sha256: source.sha256.clone(),
        bytes: source.bytes,
    };
    let proposal = |proposal: &Proposal| ProposalLine {
        name: proposal.name.clone(),
        destination: proposal.destination.clone(),
        sha256: proposal.sha256.clone(),
        bytes: proposal.bytes,
    };
    TaskLine {
        id: task.id.clone(),
        workspace_id: task.workspace_id.clone(),
        folder: task.folder.clone(),
        folder_canonical: task.folder_canonical.clone(),
        sources: task.sources.iter().map(source).collect(),
        proposal: task.proposal.as_ref().map(proposal),
        report: task.report.as_ref().map(proposal),
        check: task.check.clone(),
        state: task.state.as_str().to_owned(),
        steps: task
            .steps
            .iter()
            .map(|step| StepLine {
                step_id: step.step_id.clone(),
                kind: step.kind.clone(),
                outcome: step.outcome.clone(),
                at_ms: step.at_ms,
            })
            .collect(),
        next_step: task.next_step,
        created_at_ms: task.created_at_ms,
        updated_at_ms: task.updated_at_ms,
    }
}

/// A task of an earlier run, read-only: its state is never `observed`,
/// `proposed` or `committing` any more, since its orceld has exited.
fn restored_task(line: TaskLine, run: &str) -> ReportTask {
    let mut state = TaskState::from_str(&line.state).unwrap_or(TaskState::Failed);
    let mut steps: Vec<Step> = line
        .steps
        .into_iter()
        .map(|step| Step {
            step_id: step.step_id,
            kind: step.kind,
            outcome: step.outcome,
            at_ms: step.at_ms,
        })
        .collect();
    let mut next_step = line.next_step;
    if !state.is_final() && state != TaskState::ApprovalDenied {
        state = TaskState::Failed;
        next_step += 1;
        steps.push(Step {
            step_id: format!("s{next_step}"),
            kind: "run".to_owned(),
            outcome: "orceld_run_ended".to_owned(),
            at_ms: line.updated_at_ms,
        });
        if steps.len() > MAX_STEPS {
            steps.remove(0);
        }
    }
    let source = |source: SourceLine| SourceRecord {
        path: source.path,
        sha256: source.sha256,
        bytes: source.bytes,
    };
    let proposal = |proposal: ProposalLine| Proposal {
        name: proposal.name,
        destination: proposal.destination,
        sha256: proposal.sha256,
        bytes: proposal.bytes,
    };
    ReportTask {
        id: line.id,
        run: run.to_owned(),
        workspace_id: line.workspace_id,
        // The planner's free-text title is never journaled.
        title: String::new(),
        folder: line.folder,
        folder_resolved: PathBuf::new(),
        folder_canonical: line.folder_canonical,
        sources: line.sources.into_iter().map(source).collect(),
        proposal: line.proposal.map(proposal),
        report: line.report.map(proposal),
        check: line.check,
        state,
        steps,
        next_step,
        created_at_ms: line.created_at_ms,
        updated_at_ms: line.updated_at_ms,
    }
}

pub(super) fn commit_line(
    task: &ReportTask,
    root: &Path,
    proposal: &Proposal,
    approval_digest: &str,
) -> CommitLine {
    CommitLine {
        task_id: task.id.clone(),
        approval_digest: approval_digest.to_owned(),
        workspace_id: task.workspace_id.clone(),
        policy_revision: orcel_policy::POLICY_REVISION.to_owned(),
        root: root.to_path_buf(),
        folder: task.folder.clone(),
        folder_canonical: task.folder_canonical.clone(),
        destination: proposal.destination.clone(),
        sha256: proposal.sha256.clone(),
        bytes: proposal.bytes,
        sources: task
            .sources
            .iter()
            .map(|source| SourceLine {
                path: source.path.clone(),
                sha256: source.sha256.clone(),
                bytes: source.bytes,
            })
            .collect(),
    }
}

/// How a pending commit of an exited orceld turned out.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Reconciled {
    /// No destination: the create never happened.
    NothingWritten,
    /// The destination exists and the independent checker passes.
    Verified(Value),
    /// The destination exists and does not check: orceld cannot tell what
    /// happened. Nothing is retried.
    Unknown(String),
}

impl Reconciled {
    fn outcome(&self) -> &'static str {
        match self {
            Reconciled::NothingWritten => "nothing_written",
            Reconciled::Verified(_) => "verified",
            Reconciled::Unknown(_) => "unknown",
        }
    }
}

/// Reconciles one pending commit against its destination only.
pub(super) fn reconcile(commit: &CommitLine) -> Reconciled {
    let destination = commit.root.join(&commit.destination);
    match std::fs::symlink_metadata(&destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Reconciled::NothingWritten
        }
        Err(_) => return Reconciled::Unknown("the destination could not be read".to_owned()),
        Ok(_) => {}
    }
    let sources: Vec<SourceRecord> = commit
        .sources
        .iter()
        .map(|source| SourceRecord {
            path: source.path.clone(),
            sha256: source.sha256.clone(),
            bytes: source.bytes,
        })
        .collect();
    match report_check::check(&report_check::Expectation {
        root: &commit.root,
        folder_path: &commit.root.join(&commit.folder),
        folder: &commit.folder_canonical,
        destination: &commit.destination,
        sha256: &commit.sha256,
        bytes: commit.bytes,
        sources: &sources,
    }) {
        Ok(record) => Reconciled::Verified(record),
        Err(reason) => Reconciled::Unknown(reason),
    }
}

/// The journal of one orceld run.
pub(super) struct ReportJournal {
    path: PathBuf,
    owner: Owner,
}

/// What a starting orceld found in the journal.
pub(super) struct Restored {
    pub tasks: Vec<ReportTask>,
    pub torn: usize,
    pub reconciled: usize,
}

fn unavailable() -> ProviderError {
    error(
        FailureCode::ProviderUnavailable,
        "the report task journal could not be written; nothing was asked or spent",
    )
}

impl ReportJournal {
    pub(super) fn new(path: PathBuf, owner: Owner) -> Self {
        Self { path, owner }
    }

    fn line(&self, line: &Line) -> Result<(), JournalError> {
        orcel_journal::append_shared(&self.path, line, LOCK_WAIT)
    }

    /// Best effort: a lost snapshot loses history, never safety.
    pub(super) fn snapshot(&self, task: &ReportTask) {
        let _ = self.line(&Line::Task {
            schema: SCHEMA.to_owned(),
            owner: self.owner.clone(),
            task: task_line(task),
        });
    }

    /// Records a commit before its approval is asked for. An error means
    /// nothing may be asked or spent.
    pub(super) fn pending(&self, intent: &str, commit: CommitLine) -> Result<(), ProviderError> {
        orcel_journal::append_opening_shared(
            &self.path,
            &Line::Pending {
                schema: SCHEMA.to_owned(),
                owner: self.owner.clone(),
                intent: intent.to_owned(),
                commit,
            },
            LOCK_WAIT,
        )
        .map_err(|_| unavailable())
    }

    /// Immediately before the create. If this cannot be written the create
    /// must not run: a later reconcile would otherwise read a pending-only
    /// intent as never started.
    pub(super) fn dispatched(&self, intent: &str) -> Result<(), ProviderError> {
        self.line(&Line::Dispatched {
            schema: SCHEMA.to_owned(),
            intent: intent.to_owned(),
        })
        .map_err(|_| unavailable())
    }

    /// The commit's effect never started (refused, denied or blocked
    /// before the create).
    pub(super) fn abandoned(&self, intent: &str, outcome: &str) {
        let _ = self.line(&Line::Abandoned {
            schema: SCHEMA.to_owned(),
            intent: intent.to_owned(),
            outcome: outcome.to_owned(),
        });
    }

    /// The commit's create ran and its outcome is known.
    pub(super) fn settled(&self, intent: &str, outcome: &str) {
        let _ = self.line(&Line::Settled {
            schema: SCHEMA.to_owned(),
            intent: intent.to_owned(),
            outcome: outcome.to_owned(),
        });
    }

    /// Reads the journal at start: reconciles the pending commits of exited
    /// runs, restores the tasks of exited runs (read-only, newest
    /// [`MAX_EARLIER_TASKS`]), and compacts the journal to what is still
    /// needed. Fails closed on an unreadable journal.
    pub(super) fn restore(&self) -> Result<Restored, JournalError> {
        orcel_journal::with_lock(&self.path, LOCK_WAIT, || {
            let read = orcel_journal::read_lines::<Line>(&self.path)?;
            if read.lines.iter().any(|line| line.schema() != SCHEMA) {
                return Err(JournalError::Unreadable);
            }
            let open = orcel_journal::recover(read.lines.iter().filter_map(Line::intent_event))?;
            let mut snapshots: Vec<(Owner, TaskLine)> = Vec::new();
            let mut pending: Vec<(Owner, String, CommitLine, IntentState)> = Vec::new();
            for line in &read.lines {
                match line {
                    Line::Task { owner, task, .. } => {
                        match snapshots.iter_mut().find(|(_, known)| known.id == task.id) {
                            Some(slot) => *slot = (owner.clone(), task.clone()),
                            None => snapshots.push((owner.clone(), task.clone())),
                        }
                    }
                    Line::Pending {
                        owner,
                        intent,
                        commit,
                        ..
                    } => {
                        if let Some((_, state)) = open.iter().find(|(id, _)| id == intent) {
                            pending.push((owner.clone(), intent.clone(), commit.clone(), *state));
                        }
                    }
                    _ => {}
                }
            }

            let mut exited: Vec<String> = Vec::new();
            let mut live: Vec<String> = Vec::new();
            let mut is_exited = |owner: &Owner| {
                if exited.contains(&owner.run) {
                    return true;
                }
                if live.contains(&owner.run) {
                    return false;
                }
                let gone = owner.has_exited();
                if gone {
                    exited.push(owner.run.clone());
                } else {
                    live.push(owner.run.clone());
                }
                gone
            };

            // Reconcile the commits left pending by exited runs.
            let mut reconciled = 0;
            // Newest first, so a task's latest open attempt decides it and a
            // stale earlier one (whose abandoned line was lost) cannot.
            let mut kept_groups: Vec<Vec<Line>> = Vec::new();
            for (owner, intent, commit, state) in pending.into_iter().rev() {
                if !is_exited(&owner) || owner.run == self.owner.run {
                    // A live run's open commit is kept exactly: pending,
                    // and dispatched when its create may have started.
                    let mut group = vec![Line::Pending {
                        schema: SCHEMA.to_owned(),
                        owner,
                        intent: intent.clone(),
                        commit,
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
                // Pending only: the create never started, so the
                // destination is not even read. Dispatched: the
                // destination decides.
                let result = if state == IntentState::Dispatched {
                    reconcile(&commit)
                } else {
                    Reconciled::NothingWritten
                };
                reconciled += 1;
                if let Some((_, task)) = snapshots.iter_mut().find(|(_, task)| {
                    task.id == commit.task_id
                        && (task.state == TaskState::Proposed.as_str()
                            || task.state == TaskState::Committing.as_str())
                }) {
                    // Only a task still waiting on this commit takes its
                    // result; a task that already finished keeps its state.
                    let now = orcel_approval::now_ms();
                    task.next_step += 1;
                    task.steps.push(StepLine {
                        step_id: format!("s{}", task.next_step),
                        kind: "reconcile".to_owned(),
                        outcome: result.outcome().to_owned(),
                        at_ms: now,
                    });
                    if task.steps.len() > MAX_STEPS {
                        task.steps.remove(0);
                    }
                    task.updated_at_ms = now;
                    match &result {
                        Reconciled::Verified(record) => {
                            task.state = TaskState::Verified.as_str().to_owned();
                            task.check = Some(record.clone());
                            task.report = task.proposal.clone();
                        }
                        Reconciled::Unknown(reason) => {
                            task.state = TaskState::Failed.as_str().to_owned();
                            task.check = Some(serde_json::json!({
                                "checker": report_check::CHECKER,
                                "passed": false,
                                "reason": reason,
                            }));
                        }
                        Reconciled::NothingWritten => {
                            task.state = TaskState::Failed.as_str().to_owned();
                        }
                    }
                }
            }

            // Earlier runs' tasks, newest last, bounded.
            let mut earlier: Vec<(Owner, TaskLine)> = snapshots
                .into_iter()
                .filter(|(owner, _)| owner.run != self.owner.run && is_exited(owner))
                .collect();
            earlier.sort_by_key(|(_, task)| task.updated_at_ms);
            if earlier.len() > MAX_EARLIER_TASKS {
                earlier.drain(..earlier.len() - MAX_EARLIER_TASKS);
            }

            // Compact: the kept tasks of exited runs, every line of runs
            // still alive (their own snapshots and open commits), nothing
            // else. Reconciled commits are settled by the rewrite itself.
            let mut kept: Vec<Line> = earlier
                .iter()
                .map(|(owner, task)| Line::Task {
                    schema: SCHEMA.to_owned(),
                    owner: owner.clone(),
                    task: task.clone(),
                })
                .collect();
            // A live run's tasks: its newest snapshot of each.
            let mut live_tasks: Vec<(Owner, TaskLine)> = Vec::new();
            for line in read.lines {
                if let Line::Task { owner, task, .. } = line {
                    if !is_exited(&owner) {
                        match live_tasks.iter_mut().find(|(_, known)| known.id == task.id) {
                            Some(slot) => *slot = (owner, task),
                            None => live_tasks.push((owner, task)),
                        }
                    }
                }
            }
            kept.extend(live_tasks.into_iter().map(|(owner, task)| Line::Task {
                schema: SCHEMA.to_owned(),
                owner,
                task,
            }));
            // Back in journal order, each pending line before its dispatched.
            kept.extend(kept_groups.into_iter().rev().flatten());
            orcel_journal::rewrite(&self.path, &kept)?;

            Ok(Restored {
                tasks: earlier
                    .into_iter()
                    .map(|(owner, task)| restored_task(task, &owner.run))
                    .collect(),
                torn: read.torn,
                reconciled,
            })
        })
    }
}

#[cfg(test)]
#[path = "report_journal_tests.rs"]
mod tests;
