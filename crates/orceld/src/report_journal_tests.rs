//! SG-000120 RJ-02 (report provider): the durable report task journal,
//! through the real workspace provider, the real checker and the real
//! approval broker. Only the SOFT consent is scripted.

use super::super::tests::{consent, plan_report, request, start_q3, Scene};
use super::super::{dispatch, TaskRegistry};
use super::*;
use orcel_approval::ApprovalDecision;
use serde_json::json;

fn journal_path(scene: &Scene) -> PathBuf {
    scene.dir.join("state").join("report-tasks.jsonl")
}

/// An owner whose process does not exist: its pending commits are
/// reconciled by the next orceld.
fn exited_owner(run: &str) -> Owner {
    Owner::exited(run)
}

fn lines(path: &Path) -> Vec<Line> {
    orcel_journal::read_lines::<Line>(path).unwrap().lines
}

/// Starts and previews a Q3 report in `tasks`; returns (task id, report).
fn proposed(scene: &Scene, tasks: &TaskRegistry) -> (String, String) {
    let started = start_q3(scene, tasks);
    let task = started["task_id"].as_str().unwrap().to_owned();
    let report = plan_report(&started);
    let approval = consent(scene, &[]);
    dispatch(
        &scene.workspace,
        &approval.broker,
        tasks,
        &request(
            "preview",
            json!({"task_id": task, "name": "q3.md", "content": report}),
        ),
    )
    .expect("preview");
    (task, report)
}

fn commit_request(task: &str, content: &str) -> orcel_contracts::RequestEnvelope {
    request(
        "commit",
        json!({"task_id": task, "name": "q3.md", "content": content, "expected_sha256": super::super::sha256_hex(content.as_bytes())}),
    )
}

/// Writes a pending commit for the report previewed in `tasks`, as the run
/// `owner`, the way a commit records it before its approval.
fn leave_pending(scene: &Scene, tasks: &TaskRegistry, task: &str, owner: Owner, dispatched: bool) {
    let record = tasks
        .lock()
        .iter()
        .find(|known| known.id == task)
        .cloned()
        .unwrap();
    let proposal = record.proposal.clone().unwrap();
    let journal = ReportJournal::new(journal_path(scene), owner);
    journal.snapshot(&record);
    journal
        .pending(
            &format!("{task}.c0"),
            commit_line(&record, &scene.workspace.root, &proposal, &"d".repeat(64)),
        )
        .unwrap();
    if dispatched {
        journal.dispatched(&format!("{task}.c0")).unwrap();
    }
}

#[test]
fn rj02_an_approved_journey_is_journaled_and_survives_a_restart() {
    let scene = Scene::new("rj02-journey");
    let path = journal_path(&scene);
    let tasks = TaskRegistry::with_journal(path.clone());
    let (task, report) = proposed(&scene, &tasks);
    let approval = consent(
        &scene,
        &[ApprovalDecision::Denied, ApprovalDecision::Approved],
    );
    let denied = dispatch(
        &scene.workspace,
        &approval.broker,
        &tasks,
        &commit_request(&task, &report),
    )
    .unwrap_err();
    assert_eq!(denied.code, FailureCode::ApprovalDenied);
    let created = dispatch(
        &scene.workspace,
        &approval.broker,
        &tasks,
        &commit_request(&task, &report),
    )
    .expect("approved commit");
    assert_eq!(created["state"], "verified");

    // Two commit attempts, each its own intent: the denied one abandoned,
    // the approved one settled. Nothing is left open.
    let written = lines(&path);
    let events: Vec<(&str, IntentState)> = written.iter().filter_map(Line::intent_event).collect();
    assert_eq!(events.len(), 5, "{events:?}");
    assert_eq!(events[0].1, IntentState::Pending);
    assert_eq!(events[1], (events[0].0, IntentState::Abandoned));
    assert_eq!(events[2].1, IntentState::Pending);
    assert_ne!(
        events[2].0, events[0].0,
        "a second attempt has its own intent"
    );
    assert_eq!(events[3], (events[2].0, IntentState::Dispatched));
    assert_eq!(events[4], (events[2].0, IntentState::Settled));
    assert!(orcel_journal::recover(events.iter().copied())
        .unwrap()
        .is_empty());

    // The journal holds paths and hashes, never content.
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("north,Q3"), "no source content");
    assert!(!text.contains("Q3 revenue summary"), "no report content");

    // A later orceld (this run has "exited": its registry is gone and a new
    // run starts) shows the task read-only, still verified.
    drop(tasks);
    let mut restarted = TaskRegistry::new();
    restarted.journal = Some(ReportJournal::new(path.clone(), exited_owner("next")));
    // Restore as the next run, treating the earlier run as exited.
    let restored = restore_as_exited(&path, &restarted.seed);
    *restarted.lock() = restored;
    let record = restarted.get(&task).expect("the task survives");
    assert_eq!(record["state"], "verified");
    let refused = dispatch(
        &scene.workspace,
        &approval.broker,
        &restarted,
        &commit_request(&task, &report),
    )
    .unwrap_err();
    assert!(
        refused.message.contains("earlier orceld run"),
        "{}",
        refused.message
    );
}

/// Restores `path` as a new run that treats every earlier run as exited
/// (in a test, the earlier run is this very process).
fn restore_as_exited(path: &Path, run: &str) -> Vec<ReportTask> {
    let rewritten: Vec<Line> = lines(path)
        .into_iter()
        .map(|line| match line {
            Line::Task { schema, task, .. } => Line::Task {
                schema,
                owner: exited_owner("earlier"),
                task,
            },
            Line::Pending {
                schema,
                intent,
                commit,
                ..
            } => Line::Pending {
                schema,
                owner: exited_owner("earlier"),
                intent,
                commit,
            },
            other => other,
        })
        .collect();
    orcel_journal::rewrite(path, &rewritten).unwrap();
    let journal = ReportJournal::new(path.to_path_buf(), exited_owner(run));
    journal.restore().unwrap().tasks
}

#[test]
fn rj02_a_crash_before_the_write_reconciles_as_nothing_written() {
    let scene = Scene::new("rj02-nothing");
    let tasks = TaskRegistry::new();
    let (task, _) = proposed(&scene, &tasks);
    leave_pending(&scene, &tasks, &task, exited_owner("crashed"), false);
    let before = scene.tree();

    let next = ReportJournal::new(journal_path(&scene), exited_owner("next"));
    let restored = next.restore().unwrap();
    assert_eq!(restored.reconciled, 1);
    assert_eq!(scene.tree(), before, "reconciling writes nothing");
    let record = &restored.tasks[0];
    assert_eq!(record.state, TaskState::Failed);
    assert_eq!(
        record
            .steps
            .last()
            .map(|step| (step.kind.as_str(), step.outcome.as_str())),
        Some(("reconcile", "nothing_written"))
    );
    // The commit is closed for good: a second start reconciles nothing.
    let again = ReportJournal::new(journal_path(&scene), exited_owner("third"));
    assert_eq!(again.restore().unwrap().reconciled, 0);
}

#[test]
fn rj02_a_crash_after_the_write_reconciles_through_the_independent_checker() {
    let scene = Scene::new("rj02-written");
    let tasks = TaskRegistry::new();
    let (task, report) = proposed(&scene, &tasks);
    leave_pending(&scene, &tasks, &task, exited_owner("crashed"), true);
    // The create happened, then orceld died before it could settle.
    std::fs::write(scene.workspace.root.join("reports").join("q3.md"), &report).unwrap();
    let before = scene.tree();

    let next = ReportJournal::new(journal_path(&scene), exited_owner("next"));
    let restored = next.restore().unwrap();
    assert_eq!(restored.reconciled, 1);
    assert_eq!(scene.tree(), before, "nothing is written twice or removed");
    let record = &restored.tasks[0];
    assert_eq!(record.state, TaskState::Verified);
    assert_eq!(record.check.as_ref().unwrap()["passed"], true);
    assert_eq!(
        record.report.as_ref().unwrap().sha256,
        super::super::sha256_hex(report.as_bytes())
    );
}

#[test]
fn rj02_a_destination_that_does_not_check_is_unknown_and_left_alone() {
    let scene = Scene::new("rj02-unknown");
    let tasks = TaskRegistry::new();
    let (task, _) = proposed(&scene, &tasks);
    leave_pending(&scene, &tasks, &task, exited_owner("crashed"), true);
    std::fs::write(
        scene.workspace.root.join("reports").join("q3.md"),
        "not the approved bytes",
    )
    .unwrap();
    let before = scene.tree();

    let next = ReportJournal::new(journal_path(&scene), exited_owner("next"));
    let restored = next.restore().unwrap();
    assert_eq!(
        scene.tree(),
        before,
        "the unknown file is left for the user"
    );
    let record = &restored.tasks[0];
    assert_eq!(record.state, TaskState::Failed);
    assert_eq!(
        record.steps.last().map(|step| step.outcome.as_str()),
        Some("unknown")
    );
    assert_eq!(record.check.as_ref().unwrap()["passed"], false);
}

#[test]
fn rj02_a_running_orcelds_pending_commit_is_never_touched() {
    let scene = Scene::new("rj02-live");
    let tasks = TaskRegistry::new();
    let (task, _) = proposed(&scene, &tasks);
    // This test process is the "other" orceld, still running.
    let live = Owner::current("other-live-run").unwrap();
    leave_pending(&scene, &tasks, &task, live, true);

    let next = ReportJournal::new(journal_path(&scene), exited_owner("next"));
    let restored = next.restore().unwrap();
    assert_eq!(restored.reconciled, 0);
    assert!(restored.tasks.is_empty(), "a live run's tasks stay its own");
    let open = orcel_journal::recover(
        lines(&journal_path(&scene))
            .iter()
            .filter_map(Line::intent_event)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(
        open.len(),
        1,
        "the live commit stays pending in the compacted journal"
    );
}

#[test]
fn rj02_an_unreadable_journal_refuses_commits_and_asks_nothing() {
    let scene = Scene::new("rj02-faulted");
    let path = journal_path(&scene);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        "{\"event\":\"task\",\"schema\":\"something-else\"}\n",
    )
    .unwrap();
    let tasks = TaskRegistry::with_journal(path.clone());
    assert!(tasks.journal_faulted);
    let (task, report) = proposed(&scene, &tasks);
    let before = scene.tree();
    let approval = consent(&scene, &[ApprovalDecision::Approved]);
    let refused = dispatch(
        &scene.workspace,
        &approval.broker,
        &tasks,
        &commit_request(&task, &report),
    )
    .unwrap_err();
    assert_eq!(refused.code, FailureCode::ProviderUnavailable);
    assert!(
        approval.prompts.lock().unwrap().is_empty(),
        "nothing was asked"
    );
    assert_eq!(scene.tree(), before, "nothing was written");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "{\"event\":\"task\",\"schema\":\"something-else\"}\n",
        "the unreadable journal is left for repair, not rewritten"
    );
}

#[test]
fn rj02_a_commit_that_cannot_be_journaled_asks_nothing() {
    let scene = Scene::new("rj02-unwritable");
    // The journal's directory is a file, so no line can be written.
    let blocker = scene.dir.join("state");
    std::fs::write(&blocker, "not a directory").unwrap();
    let tasks = TaskRegistry::new();
    let (task, report) = proposed(&scene, &tasks);
    let mut journaled = tasks;
    journaled.journal = Some(ReportJournal::new(
        journal_path(&scene),
        exited_owner("this"),
    ));
    // The registry's own run owns the task, so open_task admits it.
    for known in journaled.lock().iter_mut() {
        known.run = journaled.seed.clone();
    }
    let before = scene.tree();
    let approval = consent(&scene, &[ApprovalDecision::Approved]);
    let refused = dispatch(
        &scene.workspace,
        &approval.broker,
        &journaled,
        &commit_request(&task, &report),
    )
    .unwrap_err();
    assert_eq!(refused.code, FailureCode::ProviderUnavailable);
    assert!(
        approval.prompts.lock().unwrap().is_empty(),
        "nothing was asked or spent"
    );
    assert_eq!(scene.tree(), before);
}

#[test]
fn rj02_the_journal_is_compacted_and_bounded_to_earlier_tasks() {
    let scene = Scene::new("rj02-compact");
    let path = journal_path(&scene);
    let tasks = TaskRegistry::new();
    let (task, _) = proposed(&scene, &tasks);
    let record = tasks
        .lock()
        .iter()
        .find(|known| known.id == task)
        .cloned()
        .unwrap();
    let journal = ReportJournal::new(path.clone(), exited_owner("old"));
    for n in 0..(MAX_EARLIER_TASKS + 10) {
        let mut copy = record.clone();
        copy.id = format!("rpt-{n:032x}");
        copy.updated_at_ms = n as u64;
        journal.snapshot(&copy);
        journal.snapshot(&copy);
    }
    let restored = ReportJournal::new(path.clone(), exited_owner("next"))
        .restore()
        .unwrap();
    assert_eq!(restored.tasks.len(), MAX_EARLIER_TASKS);
    assert_eq!(
        lines(&path).len(),
        MAX_EARLIER_TASKS,
        "one snapshot per kept task; the oldest tasks and duplicate snapshots are gone"
    );
}

#[test]
fn rj02_a_pending_only_commit_never_reads_its_destination() {
    // The orceld died while the user was still being asked: the create
    // never started, so a file another process made there meanwhile, even
    // with the approved bytes, is not taken as this commit's report.
    let scene = Scene::new("rj02-pending-only");
    let tasks = TaskRegistry::new();
    let (task, report) = proposed(&scene, &tasks);
    leave_pending(&scene, &tasks, &task, exited_owner("crashed"), false);
    std::fs::write(scene.workspace.root.join("reports").join("q3.md"), &report).unwrap();
    let before = scene.tree();
    let restored = ReportJournal::new(journal_path(&scene), exited_owner("next"))
        .restore()
        .unwrap();
    assert_eq!(scene.tree(), before);
    let record = &restored.tasks[0];
    assert_eq!(record.state, TaskState::Failed);
    assert_eq!(
        record.steps.last().map(|step| step.outcome.as_str()),
        Some("nothing_written")
    );
    assert!(record.report.is_none());
}

#[test]
fn rj02_a_reconcile_never_overwrites_a_finished_task() {
    let scene = Scene::new("rj02-finished");
    let tasks = TaskRegistry::new();
    let (task, _) = proposed(&scene, &tasks);
    leave_pending(&scene, &tasks, &task, exited_owner("crashed"), true);
    // A later snapshot of the same run shows the task finished (its
    // settle line was lost).
    let mut finished = tasks
        .lock()
        .iter()
        .find(|known| known.id == task)
        .cloned()
        .unwrap();
    finished.state = TaskState::Verified;
    ReportJournal::new(journal_path(&scene), exited_owner("crashed")).snapshot(&finished);
    let restored = ReportJournal::new(journal_path(&scene), exited_owner("next"))
        .restore()
        .unwrap();
    assert_eq!(restored.reconciled, 1);
    assert_eq!(
        restored.tasks[0].state,
        TaskState::Verified,
        "the finished state is kept"
    );
}

#[test]
fn rj02_an_existing_destination_at_the_create_closes_the_journaled_commit() {
    // The real commit path: approved, then a file appears just before the
    // create. The create refuses it; the journal records pending,
    // dispatched and settled.
    let scene = Scene::new("rj02-exists");
    let path = journal_path(&scene);
    let tasks = TaskRegistry::with_journal(path.clone());
    let (task, report) = proposed(&scene, &tasks);
    let approval = consent(&scene, &[ApprovalDecision::Approved]);
    let destination = scene.workspace.root.join("reports").join("q3.md");
    let refused = super::super::dispatch_with(
        &scene.workspace,
        &approval.broker,
        &tasks,
        &commit_request(&task, &report),
        &super::super::Hooks {
            after_approval: &|| {},
            before_write: &|| std::fs::write(&destination, "someone else's").unwrap(),
        },
    )
    .unwrap_err();
    assert_eq!(refused.code, FailureCode::TargetStale);
    assert_eq!(
        std::fs::read_to_string(&destination).unwrap(),
        "someone else's"
    );
    let written = lines(&path);
    let outcomes: Vec<(IntentState, String)> = written
        .iter()
        .filter_map(|line| match line {
            Line::Pending { .. } => Some((IntentState::Pending, String::new())),
            Line::Dispatched { .. } => Some((IntentState::Dispatched, String::new())),
            Line::Settled { outcome, .. } => Some((IntentState::Settled, outcome.clone())),
            Line::Abandoned { outcome, .. } => Some((IntentState::Abandoned, outcome.clone())),
            Line::Task { .. } => None,
        })
        .collect();
    assert_eq!(
        outcomes,
        [
            (IntentState::Pending, String::new()),
            (IntentState::Dispatched, String::new()),
            (IntentState::Settled, "destination_exists".to_owned()),
        ]
    );
}

#[test]
fn rj02_compaction_keeps_a_live_runs_dispatched_commit() {
    let scene = Scene::new("rj02-live-dispatched");
    let tasks = TaskRegistry::new();
    let (task, _) = proposed(&scene, &tasks);
    let live = Owner::current("other-live-run").unwrap();
    leave_pending(&scene, &tasks, &task, live, true);
    ReportJournal::new(journal_path(&scene), exited_owner("next"))
        .restore()
        .unwrap();
    let open = orcel_journal::recover(
        lines(&journal_path(&scene))
            .iter()
            .filter_map(Line::intent_event)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(
        open.iter().map(|(_, state)| *state).collect::<Vec<_>>(),
        [IntentState::Dispatched],
        "the live commit keeps its dispatched state through compaction"
    );
}

#[test]
fn rj02_the_title_is_never_journaled() {
    let scene = Scene::new("rj02-title");
    let path = journal_path(&scene);
    let tasks = TaskRegistry::with_journal(path.clone());
    let (task, _) = proposed(&scene, &tasks);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        !text.contains("Q3 revenue"),
        "the planner title is not kept"
    );
    let _ = task;
}

#[test]
fn rj02_the_newest_open_attempt_of_a_task_decides_it() {
    // An earlier denied attempt lost its abandoned line; the later attempt
    // was dispatched and wrote the approved report before the crash.
    let scene = Scene::new("rj02-two-attempts");
    let tasks = TaskRegistry::new();
    let (task, report) = proposed(&scene, &tasks);
    let record = tasks
        .lock()
        .iter()
        .find(|known| known.id == task)
        .cloned()
        .unwrap();
    let proposal = record.proposal.clone().unwrap();
    let journal = ReportJournal::new(journal_path(&scene), exited_owner("crashed"));
    journal.snapshot(&record);
    for (intent, dispatched) in [(format!("{task}.c0"), false), (format!("{task}.c1"), true)] {
        journal
            .pending(
                &intent,
                commit_line(&record, &scene.workspace.root, &proposal, &"d".repeat(64)),
            )
            .unwrap();
        if dispatched {
            journal.dispatched(&intent).unwrap();
        }
    }
    std::fs::write(scene.workspace.root.join("reports").join("q3.md"), &report).unwrap();
    let restored = ReportJournal::new(journal_path(&scene), exited_owner("next"))
        .restore()
        .unwrap();
    assert_eq!(restored.reconciled, 2);
    assert_eq!(restored.tasks[0].state, TaskState::Verified);
}

// ---- fault injection: a real child process killed at each transition ----

/// The child: the whole F2 journey with an approved commit, killed at
/// `ORCEL_RJ02_CRASH_AT`. A no-op unless the suite started this process.
#[test]
fn rj02_report_crash_child() {
    let Ok(dir) = std::env::var("ORCEL_RJ02_REPORT_DIR") else {
        return;
    };
    let dir = PathBuf::from(dir);
    let scene = Scene {
        workspace: orcel_policy::Workspace {
            id: "default".into(),
            root: dir.join("ws"),
        },
        dir,
    };
    let tasks = TaskRegistry::with_journal(journal_path(&scene));
    let (task, report) = proposed(&scene, &tasks);
    let approval = consent(&scene, &[ApprovalDecision::Approved]);
    let result = dispatch(
        &scene.workspace,
        &approval.broker,
        &tasks,
        &commit_request(&task, &report),
    );
    // Only reached when no crash point fired; the parent then fails.
    std::mem::forget(scene);
    result.unwrap();
}

#[test]
fn rj02_report_fault_injection_kills_the_commit_at_each_transition() {
    let exe = std::env::current_exe().unwrap();
    for transition in ["pending", "dispatched", "effect"] {
        let scene = Scene::new(&format!("rj02-kill-{transition}"));
        let status = std::process::Command::new(&exe)
            .args([
                "--exact",
                "report_task::journal::tests::rj02_report_crash_child",
                "--test-threads=1",
            ])
            .env("ORCEL_RJ02_REPORT_DIR", &scene.dir)
            .env("ORCEL_RJ02_CRASH_AT", transition)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success(), "{transition}: the child must die");
        let destination = scene.workspace.root.join("reports").join("q3.md");
        let written = transition == "effect";
        assert_eq!(destination.exists(), written, "{transition}");
        let before = scene.tree();

        let next = ReportJournal::new(journal_path(&scene), Owner::current("next").unwrap());
        let restored = next.restore().unwrap();
        assert_eq!(restored.reconciled, 1, "{transition}");
        assert_eq!(scene.tree(), before, "{transition}: nothing written twice");
        let record = &restored.tasks[0];
        if written {
            assert_eq!(record.state, TaskState::Verified, "{transition}");
        } else {
            assert_eq!(record.state, TaskState::Failed, "{transition}");
            assert_eq!(
                record.steps.last().map(|step| step.outcome.as_str()),
                Some("nothing_written"),
                "{transition}"
            );
        }
        let again = ReportJournal::new(journal_path(&scene), Owner::current("third").unwrap());
        assert_eq!(again.restore().unwrap().reconciled, 0, "{transition}");
        assert_eq!(scene.tree(), before, "{transition}");
    }
}
