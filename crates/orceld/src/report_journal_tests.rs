//! SG-000120 RJ-02 (report provider): the durable report task journal,
//! through the real workspace provider, the real checker and the real
//! approval broker. Only the SOFT consent is scripted.

use super::super::tests::{consent, plan_report, request, start_q3, Scene};
use super::super::{dispatch, TaskRegistry};
use super::*;
use orcel_approval::ApprovalDecision;
use serde_json::json;
use std::sync::atomic::Ordering;
use std::sync::OnceLock;

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
    restarted.journal = OnceLock::from(ReportJournal::new(path.clone(), exited_owner("next")));
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
    assert!(tasks.journal_faulted.load(Ordering::Acquire));
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

/// A journal another orceld holds at start no longer refuses commits for the whole session:
/// the next commit restores it first, and while it is still held that commit is refused as busy,
/// to be tried again, not as unreadable.
#[test]
fn rj02_a_journal_busy_at_start_is_restored_before_the_next_commit() {
    let scene = Scene::new("rj02-busy-start");
    let path = journal_path(&scene);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = {
        let path = path.clone();
        std::thread::spawn(move || {
            orcel_journal::with_lock(&path, std::time::Duration::from_secs(5), || {
                held_tx.send(()).unwrap();
                let _ = release_rx.recv();
                Ok(())
            })
            .unwrap();
        })
    };
    held_rx.recv().unwrap();

    let tasks = TaskRegistry::with_journal(path.clone());
    assert!(
        !tasks.journal_faulted.load(Ordering::Acquire),
        "busy is not unreadable"
    );
    assert!(tasks.journal().is_none());
    let busy = tasks.journal_ready().unwrap_err();
    assert_eq!(busy.code, FailureCode::ProviderUnavailable);
    assert!(busy.message.contains("busy"), "{}", busy.message);
    assert!(!tasks.journal_faulted.load(Ordering::Acquire));

    // A task this run started while the journal was busy.
    let (task, _report) = proposed(&scene, &tasks);

    release_tx.send(()).unwrap();
    holder.join().unwrap();
    tasks
        .journal_ready()
        .expect("restored once the other orceld lets go");
    assert!(tasks.journal().is_some());
    tasks.journal_ready().expect("and stays ready");
    // The restore recorded that task, so a commit that follows has it in the journal.
    let journaled = std::fs::read_to_string(&path).unwrap();
    assert!(journaled.contains(&task), "{journaled}");
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
    journaled.journal = OnceLock::from(ReportJournal::new(
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
fn f4_a_stopped_task_of_an_exited_run_is_restored_stopped() {
    let scene = Scene::new("f4-stopped");
    let tasks = TaskRegistry::new();
    let task = start_q3(&scene, &tasks)["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    tasks.stop(&task, "default").expect("stop");
    let stopped = tasks
        .lock()
        .iter()
        .find(|known| known.id == task)
        .cloned()
        .unwrap();
    ReportJournal::new(journal_path(&scene), exited_owner("crashed")).snapshot(&stopped);
    let restored = ReportJournal::new(journal_path(&scene), exited_owner("next"))
        .restore()
        .unwrap();
    assert_eq!(restored.tasks.len(), 1);
    assert_eq!(restored.tasks[0].state, TaskState::Stopped);
    assert_eq!(restored.reconciled, 0);
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
            after_preview_check: &|| {},
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

// ---- SG-000120 RJ-03: the resume summary after a real crash ----

fn crashed_journey(label: &str, transition: &str) -> Scene {
    let scene = Scene::new(label);
    // orceld's private state root exists before it starts.
    std::fs::create_dir_all(journal_path(&scene).parent().unwrap()).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
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
    assert!(!status.success(), "the child must die at {transition}");
    scene
}

fn resume(scene: &Scene, tasks: &TaskRegistry, session: &str) -> Result<Value, ProviderError> {
    let task = tasks.lock()[0].id.clone();
    let mut summary = request("resume_summary", json!({ "task_id": task }));
    summary.client_session_id = session.to_owned();
    dispatch(
        &scene.workspace,
        &consent(scene, &[]).broker,
        tasks,
        &summary,
    )
}

#[test]
fn rj03_a_reconnecting_session_reads_what_its_crashed_task_did() {
    // The child's requests carry client session "sg126".
    let session = request("start", json!({})).client_session_id;

    // Killed after the create: reconciled verified, so the commit is done.
    let scene = crashed_journey("rj03-done", "effect");
    let tasks = TaskRegistry::with_journal(journal_path(&scene));
    let summary = resume(&scene, &tasks, &session).unwrap();
    let kinds = |list: &str| -> Vec<String> {
        summary[list]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["kind"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(kinds("completed"), ["observe", "preview", "commit"]);
    assert!(kinds("unknown").is_empty());
    assert!(summary["note"].as_str().unwrap().contains("do NOT re-run"));

    // Killed after the create, then the file changed before the restart:
    // unknown, with the check that settles it.
    let scene = crashed_journey("rj03-unknown", "effect");
    std::fs::write(
        scene.workspace.root.join("reports").join("q3.md"),
        "someone else's bytes",
    )
    .unwrap();
    let tasks = TaskRegistry::with_journal(journal_path(&scene));
    let summary = resume(&scene, &tasks, &session).unwrap();
    assert_eq!(summary["unknown"][0]["kind"], "commit");
    assert_eq!(summary["unknown"][0]["outcome"], "reconcile:unknown");
    let check = summary["next_verification"][0].as_str().unwrap();
    assert!(
        check.contains("reports/q3.md") || check.contains(r"reports\q3.md"),
        "{check}"
    );
    assert!(summary["note"]
        .as_str()
        .unwrap()
        .contains("do not assume they succeeded OR failed"));

    // Fingerprints only: no source text, report text or title.
    let text = summary.to_string();
    for secret in ["north,Q3", "37300.75", "Q3 revenue"] {
        assert!(!text.contains(secret), "{secret}");
    }
    let fingerprint = summary["completed"][0]["input_fingerprint"]
        .as_str()
        .unwrap();
    assert_eq!(fingerprint.len(), 64);

    // Another session or another workspace gets the same refusal as an
    // unknown task id.
    for refused in [resume(&scene, &tasks, "another-session").unwrap_err(), {
        let mut elsewhere = scene.workspace.clone();
        elsewhere.id = "elsewhere".into();
        let task = tasks.lock()[0].id.clone();
        let mut summary = request("resume_summary", json!({ "task_id": task }));
        summary.client_session_id = session.clone();
        dispatch(&elsewhere, &consent(&scene, &[]).broker, &tasks, &summary).unwrap_err()
    }] {
        assert_eq!(refused.code, FailureCode::CapabilityDenied);
        assert!(refused.message.contains("no task with this id"));
    }
}

/// The summaries `tasks.list()` returns.
fn listed(tasks: &TaskRegistry) -> Vec<Value> {
    tasks.list()["tasks"].as_array().unwrap().clone()
}

#[test]
fn xs_another_running_sessions_task_is_shown_with_its_real_state_and_never_acted_on() {
    let scene = Scene::new("xs-live");
    let path = journal_path(&scene);
    // Two orcelds over one journal: both are this test process, as two runs.
    // The state directory exists first, as in product, so both load the
    // same fingerprint key.
    orcel_platform::paths::ensure_private_dir(path.parent().unwrap()).unwrap();
    let holder = TaskRegistry::with_journal(path.clone());
    let other = TaskRegistry::with_journal(path.clone());
    let (task, report) = proposed(&scene, &other);
    let own = start_q3(&scene, &holder)["task_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let entries = listed(&holder);
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert_eq!(entries[0]["task_id"], own.as_str(), "newest first");
    assert_eq!(entries[0]["owner"], "this_session");
    assert_eq!(entries[1]["task_id"], task.as_str());
    assert_eq!(entries[1]["state"], "proposed", "its real state");
    assert_eq!(entries[1]["owner"], "other_session");

    let record = holder.get(&task).expect("another session's task");
    assert_eq!(record["state"], "proposed");
    assert_eq!(record["owner"], "other_session");
    assert_eq!(record["proposal"]["destination"], "reports/q3.md");
    for hidden in ["session", "run", "pid"] {
        assert!(record.get(hidden).is_none(), "{hidden}: {record}");
    }
    assert!(
        holder.lock().iter().all(|known| known.id != task),
        "shown, never kept in the registry"
    );

    // No action of the holder finds it: nothing is asked or written.
    let before = scene.tree();
    let approval = consent(&scene, &[ApprovalDecision::Approved]);
    let refusals = [
        dispatch(
            &scene.workspace,
            &approval.broker,
            &holder,
            &request(
                "preview",
                json!({"task_id": task, "name": "q3.md", "content": report}),
            ),
        )
        .unwrap_err(),
        dispatch(
            &scene.workspace,
            &approval.broker,
            &holder,
            &commit_request(&task, &report),
        )
        .unwrap_err(),
        holder.stop(&task, &scene.workspace.id).unwrap_err(),
    ];
    for refused in refusals {
        assert_eq!(
            refused.code,
            FailureCode::TargetStale,
            "{}",
            refused.message
        );
    }
    assert!(approval.prompts.lock().unwrap().is_empty(), "nothing asked");
    assert_eq!(scene.tree(), before, "nothing written");
    // The resume lookup: the same session fingerprint (one key file), yet
    // the holder answers as for an unknown id.
    let refused = dispatch(
        &scene.workspace,
        &consent(&scene, &[]).broker,
        &holder,
        &request("resume_summary", json!({ "task_id": task })),
    )
    .unwrap_err();
    assert_eq!(refused.code, FailureCode::CapabilityDenied);
    assert!(
        dispatch(
            &scene.workspace,
            &consent(&scene, &[]).broker,
            &other,
            &request("resume_summary", json!({ "task_id": task })),
        )
        .is_ok(),
        "its own session still reads it"
    );

    // The owning session is untouched and sees the holder's task in turn.
    assert_eq!(other.get(&task).unwrap()["owner"], "this_session");
    assert_eq!(other.get(&task).unwrap()["state"], "proposed");
    assert_eq!(other.get(&own).unwrap()["owner"], "other_session");

    // The owner's next step shows up in the holder's view.
    let approval = consent(&scene, &[ApprovalDecision::Approved]);
    dispatch(
        &scene.workspace,
        &approval.broker,
        &other,
        &commit_request(&task, &report),
    )
    .expect("the owner commits");
    assert_eq!(holder.get(&task).unwrap()["state"], "verified");
    assert_eq!(listed(&holder)[1]["state"], "verified");
}

#[test]
fn xs_an_exited_runs_task_is_shown_as_an_earlier_run() {
    let scene = Scene::new("xs-exited");
    let path = journal_path(&scene);
    let scratch = TaskRegistry::new();
    let snapshot_as = |task: &str, owner: Owner| {
        let record = scratch
            .lock()
            .iter()
            .find(|known| known.id == task)
            .cloned()
            .unwrap();
        ReportJournal::new(path.clone(), owner).snapshot(&record);
    };
    let (task, _) = proposed(&scene, &scratch);
    snapshot_as(&task, exited_owner("gone"));

    let holder = TaskRegistry::with_journal(path.clone());
    let record = holder.get(&task).expect("an earlier run's task");
    assert_eq!(record["owner"], "earlier_run");
    assert_eq!(record["state"], "failed", "its run ended while it was open");
    assert_eq!(listed(&holder)[0]["owner"], "earlier_run");

    // A run that exited after this one started (its task was not restored
    // at start) is shown the same way, never as a running session's.
    let (late, _) = proposed(&scene, &scratch);
    snapshot_as(&late, exited_owner("gone-later"));
    let record = holder.get(&late).expect("a later exited run's task");
    assert_eq!(record["owner"], "earlier_run");
    assert_eq!(record["state"], "failed");
    assert_eq!(listed(&holder).len(), 2);
    assert!(listed(&holder)
        .iter()
        .all(|entry| entry["owner"] == "earlier_run"));
    assert!(holder.journal().unwrap().peek_live().is_empty());
    assert!(
        holder.lock().iter().all(|known| known.id != late),
        "shown, never kept in the registry"
    );
}

/// A process that stays alive until killed, to stand for another session's
/// orceld that can exit.
fn long_running_child() -> std::process::Child {
    let mut command = if cfg!(windows) {
        let mut command = std::process::Command::new("ping");
        command.args(["-n", "120", "127.0.0.1"]);
        command
    } else {
        let mut command = std::process::Command::new("sleep");
        command.arg("120");
        command
    };
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn child")
}

#[test]
fn xs_a_session_that_exits_stays_listed_as_an_earlier_run() {
    let scene = Scene::new("xs-exits");
    let path = journal_path(&scene);
    orcel_platform::paths::ensure_private_dir(path.parent().unwrap()).unwrap();
    let holder = TaskRegistry::with_journal(path.clone());

    // The other session's orceld is a real process, so that it can exit.
    let mut child = long_running_child();
    let instance = orcel_platform::process::start_generation(child.id()).unwrap();
    let owner = Owner {
        run: "exiting-run".to_owned(),
        pid: instance.pid,
        generation: instance.generation,
        boot_id: instance.boot_id.map(|id| id.to_string()),
    };
    let scratch = TaskRegistry::new();
    let (task, report) = proposed(&scene, &scratch);
    let record = scratch.lock()[0].clone();
    ReportJournal::new(path.clone(), owner).snapshot(&record);

    let shown = holder.get(&task).expect("a running session's task");
    assert_eq!(shown["owner"], "other_session");
    assert_eq!(shown["state"], "proposed");

    child.kill().unwrap();
    child.wait().unwrap();
    drop(child);
    // Past the liveness TTL: drop the cached "alive" answer, as the TTL would.
    holder.journal().unwrap().peek.lock().unwrap().alive.clear();

    let journal_bytes = std::fs::read(&path).unwrap();
    let before = scene.tree();
    let shown = holder.get(&task).expect("still listed once its run exited");
    assert_eq!(shown["owner"], "earlier_run");
    assert_eq!(shown["state"], "failed", "it was open when its run ended");
    let last = shown["steps"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(
        (last["kind"].as_str(), last["outcome"].as_str()),
        (Some("run"), Some("orceld_run_ended"))
    );
    let entries = listed(&holder);
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["owner"], "earlier_run");
    assert_eq!(entries[0]["state"], "failed");
    assert!(
        holder.lock().is_empty(),
        "shown, never kept in the registry"
    );

    // Still read-only: nothing is asked, written or journaled.
    let approval = consent(&scene, &[ApprovalDecision::Approved]);
    let refusals = [
        dispatch(
            &scene.workspace,
            &approval.broker,
            &holder,
            &request(
                "preview",
                json!({"task_id": task, "name": "q3.md", "content": report}),
            ),
        )
        .unwrap_err(),
        dispatch(
            &scene.workspace,
            &approval.broker,
            &holder,
            &commit_request(&task, &report),
        )
        .unwrap_err(),
        holder.stop(&task, &scene.workspace.id).unwrap_err(),
    ];
    for refused in refusals {
        assert_eq!(
            refused.code,
            FailureCode::TargetStale,
            "{}",
            refused.message
        );
    }
    assert!(approval.prompts.lock().unwrap().is_empty(), "nothing asked");
    assert_eq!(scene.tree(), before, "nothing written");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        journal_bytes,
        "nothing journaled"
    );
}

#[test]
fn xs_earlier_runs_tasks_stay_within_the_bound_counting_those_restored() {
    let scene = Scene::new("xs-bound");
    let path = journal_path(&scene);
    let scratch = TaskRegistry::new();
    let snapshot_as = |owner: &str| {
        start_q3(&scene, &scratch);
        let record = scratch.lock().last().cloned().unwrap();
        ReportJournal::new(path.clone(), exited_owner(owner)).snapshot(&record);
    };
    // One earlier run's task is restored at start...
    snapshot_as("gone");
    let holder = TaskRegistry::with_journal(path.clone());
    assert_eq!(holder.lock().len(), 1);
    // ...then a full bound's worth of runs exit after it started.
    for _ in 0..MAX_EARLIER_TASKS {
        snapshot_as("gone-later");
    }
    let entries = listed(&holder);
    assert_eq!(entries.len(), MAX_EARLIER_TASKS, "restored ones count");
    assert!(entries.iter().all(|entry| entry["owner"] == "earlier_run"));
    let own = start_q3(&scene, &holder)["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let entries = listed(&holder);
    assert_eq!(entries.len(), MAX_EARLIER_TASKS + 1);
    assert_eq!(entries[0]["task_id"], own.as_str());
}

#[test]
fn xs_peek_live_never_writes_and_skips_torn_and_oversized_lines() {
    use std::io::Write as _;
    let scene = Scene::new("xs-peek");
    let path = journal_path(&scene);
    let holder = TaskRegistry::with_journal(path.clone());
    let other = TaskRegistry::with_journal(path.clone());
    let (task, _) = proposed(&scene, &other);

    // A whole line over the line bound, of a live run: never read.
    let mut big = other.lock()[0].clone();
    big.id = "rpt-big".to_owned();
    big.folder = "x".repeat(orcel_journal::MAX_LINE_BYTES);
    let mut bytes = serde_json::to_vec(&Line::Task {
        schema: SCHEMA.to_owned(),
        owner: Owner::current("big-run").unwrap(),
        task: task_line(&big),
    })
    .unwrap();
    bytes.push(b'\n');
    // Then a torn last line, as a crash in the middle of an append leaves.
    bytes.extend_from_slice(br#"{"event":"task","schema":"orcel-report-task/1","owner":{"run":"#);
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&bytes)
        .unwrap();

    let dir = path.parent().unwrap().to_path_buf();
    let listing = || {
        let mut entries: Vec<(String, u64, SystemTime)> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let meta = entry.metadata().unwrap();
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    meta.len(),
                    meta.modified().unwrap(),
                )
            })
            .collect();
        entries.sort();
        entries
    };
    let journal_bytes = std::fs::read(&path).unwrap();
    let before = listing();
    let journal = holder.journal.get().unwrap();
    for _ in 0..3 {
        let live = journal.peek_live();
        assert_eq!(live.len(), 1, "only the whole, bounded line");
        assert_eq!(live[0].id, task);
        assert_eq!(live[0].state, TaskState::Proposed);
        assert_eq!(listed(&holder).len(), 1);
        assert!(holder.get(&task).is_some());
    }
    assert_eq!(std::fs::read(&path).unwrap(), journal_bytes);
    assert_eq!(listing(), before, "no file created, changed or removed");
}

/// How many times `journal`'s peek has read the journal file.
fn peek_reads(journal: &ReportJournal) -> usize {
    journal.peek.lock().unwrap().reads
}

/// Appends raw bytes to the journal at `path`.
fn append_raw(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

#[test]
fn xs_a_torn_line_in_the_middle_still_lets_the_peek_cache() {
    let scene = Scene::new("xs-cache");
    let path = journal_path(&scene);
    let scratch = TaskRegistry::new();
    let task = start_q3(&scene, &scratch)["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let record = scratch.lock()[0].clone();
    // A live run (this process, as another run) wrote the task, a crash
    // left a torn line, and later appends followed it.
    let writer = ReportJournal::new(path.clone(), Owner::current("writer-run").unwrap());
    writer.snapshot(&record);
    append_raw(
        &path,
        br#"{"event":"task","schema":"orcel-report-task/1","ow"#,
    );
    append_raw(&path, b"\n");
    writer.snapshot(&record);

    let peeker = ReportJournal::new(path.clone(), Owner::current("peeker-run").unwrap());
    for _ in 0..3 {
        let live = peeker.peek_live();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].id, task);
    }
    assert_eq!(peek_reads(&peeker), 1, "an unchanged journal is read once");

    // A torn tail is read again on every call, since it may be completing.
    append_raw(
        &path,
        br#"{"event":"task","schema":"orcel-report-task/1","ow"#,
    );
    peeker.peek_live();
    peeker.peek_live();
    assert_eq!(peek_reads(&peeker), 3);
    // Once the line is whole the stamp is trusted again.
    append_raw(&path, b"\n");
    peeker.peek_live();
    peeker.peek_live();
    assert_eq!(peek_reads(&peeker), 4);
}

#[test]
fn xs_a_missing_or_unreadable_journal_is_never_cached_as_empty() {
    let scene = Scene::new("xs-unreadable");
    let path = journal_path(&scene);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let peeker = ReportJournal::new(path.clone(), Owner::current("peeker-run").unwrap());

    // Missing: read again on every call.
    assert!(peeker.peek_live().is_empty());
    assert!(peeker.peek_live().is_empty());
    assert_eq!(peek_reads(&peeker), 2);

    // Unreadable (a directory where the journal belongs: its metadata
    // reads, the file does not): read again on every call.
    std::fs::create_dir(&path).unwrap();
    assert!(peeker.peek_live().is_empty());
    assert!(peeker.peek_live().is_empty());
    assert_eq!(peek_reads(&peeker), 4, "a failed read is not cached");

    // Once it reads, the other run's task shows.
    std::fs::remove_dir(&path).unwrap();
    let scratch = TaskRegistry::new();
    let task = start_q3(&scene, &scratch)["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    ReportJournal::new(path.clone(), Owner::current("writer-run").unwrap())
        .snapshot(&scratch.lock()[0].clone());
    let live = peeker.peek_live();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].id, task);
}
