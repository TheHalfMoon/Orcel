//! SG-000120 RJ-02 (file provider): the mutation journal through the real
//! file provider and the fs dispatch, with a scripted approval broker.

use super::test_support::{exited_journal, journal, leave_open, restore};
use super::*;
use crate::fs_mutation::dispatch_fs_mutation_to;
use orcel_approval::test_support::FixedApprovalBroker;
use orcel_approval::ApprovalDecision;
use orcel_contracts::RequestEnvelope;
use orcel_policy::Workspace;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Scene {
    dir: PathBuf,
    workspace: Workspace,
}

impl Scene {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "orceld-rj02fs-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("ws")).unwrap();
        let root = std::fs::canonicalize(dir.join("ws")).unwrap();
        Self {
            workspace: Workspace {
                id: "default".into(),
                root,
            },
            dir,
        }
    }

    fn journal_path(&self) -> PathBuf {
        self.dir.join("state").join("mutations.jsonl")
    }

    fn root(&self) -> &Path {
        &self.workspace.root
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn sha(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

fn request(capability: &str, operation: &str, target: &str, arguments: Value) -> RequestEnvelope {
    RequestEnvelope {
        version: 1,
        request_id: "rj02fs".into(),
        client_session_id: "s".into(),
        workspace_id: "default".into(),
        capability: capability.into(),
        operation: operation.into(),
        target: Some(target.into()),
        arguments,
    }
}

fn mutation(scene: &Scene, target: &str, postcondition: Postcondition) -> Mutation {
    Mutation {
        capability: "fs.test".into(),
        operation: "test".into(),
        approval_digest: "d".repeat(64),
        workspace_id: "default".into(),
        policy_revision: orcel_policy::POLICY_REVISION.into(),
        root: scene.root().to_path_buf(),
        target: target.into(),
        postcondition,
    }
}

fn lines(path: &Path) -> Vec<Line> {
    orcel_journal::read_lines::<Line>(path).unwrap().lines
}

fn events(path: &Path) -> Vec<(IntentState, String)> {
    lines(path)
        .into_iter()
        .filter_map(|line| match line {
            Line::Pending { .. } => Some((IntentState::Pending, String::new())),
            Line::Dispatched { .. } => Some((IntentState::Dispatched, String::new())),
            Line::Settled { outcome, .. } => Some((IntentState::Settled, outcome)),
            Line::Abandoned { outcome, .. } => Some((IntentState::Abandoned, outcome)),
            Line::Outcome { .. } => None,
        })
        .collect()
}

fn outcomes(path: &Path) -> Vec<String> {
    lines(path)
        .into_iter()
        .filter_map(|line| match line {
            Line::Outcome { outcome, .. } => Some(outcome),
            _ => None,
        })
        .collect()
}

fn leaked(journal: MutationJournal) -> &'static MutationJournal {
    Box::leak(Box::new(journal))
}

// ---- reconcile: the postcondition decides, nothing else ----

#[test]
fn rj02_reconcile_reads_each_postcondition() {
    let scene = Scene::new("reconcile");
    let root = scene.root();
    std::fs::write(root.join("new.txt"), "new").unwrap();
    std::fs::write(root.join("old.txt"), "old").unwrap();
    std::fs::write(root.join("other.txt"), "other").unwrap();
    std::fs::create_dir(root.join("dir")).unwrap();
    let file = |target: &str, before: Option<&str>| {
        reconcile(&mutation(
            &scene,
            target,
            Postcondition::File {
                sha256: sha("new"),
                before: before.map(sha),
            },
        ))
    };
    assert_eq!(file("new.txt", Some("old")), Reconciled::Done);
    assert_eq!(file("old.txt", Some("old")), Reconciled::NothingDone);
    assert_eq!(file("missing.txt", None), Reconciled::NothingDone);
    assert_eq!(file("other.txt", Some("old")), Reconciled::Unknown);
    assert_eq!(file("missing.txt", Some("old")), Reconciled::Unknown);
    assert_eq!(
        reconcile(&mutation(&scene, "dir", Postcondition::Directory)),
        Reconciled::Done
    );
    assert_eq!(
        reconcile(&mutation(&scene, "nodir", Postcondition::Directory)),
        Reconciled::NothingDone
    );
    assert_eq!(
        reconcile(&mutation(&scene, "new.txt", Postcondition::Directory)),
        Reconciled::Unknown
    );
    let moved = |from: &str, to: &str, content: &str| {
        reconcile(&mutation(
            &scene,
            from,
            Postcondition::Moved {
                to: to.into(),
                sha256: Some(sha(content)),
            },
        ))
    };
    assert_eq!(moved("gone.txt", "new.txt", "new"), Reconciled::Done);
    assert_eq!(
        moved("old.txt", "absent.txt", "old"),
        Reconciled::NothingDone
    );
    assert_eq!(moved("old.txt", "new.txt", "old"), Reconciled::Unknown);
    let absent = |target: &str, kind: &str, content: Option<&str>| {
        reconcile(&mutation(
            &scene,
            target,
            Postcondition::Absent {
                before_kind: kind.into(),
                before_sha256: content.map(sha),
            },
        ))
    };
    assert_eq!(absent("gone.txt", "file", Some("x")), Reconciled::Done);
    assert_eq!(
        absent("old.txt", "file", Some("old")),
        Reconciled::NothingDone
    );
    assert_eq!(
        absent("other.txt", "file", Some("old")),
        Reconciled::Unknown
    );
    assert_eq!(absent("dir", "directory", None), Reconciled::NothingDone);
}

// ---- restore: only exited runs, nothing written, nothing retried ----

#[test]
fn rj02_an_exited_runs_pending_only_mutation_is_nothing_done_without_reading() {
    let scene = Scene::new("pending-only");
    // The approved bytes are there, but the intent never dispatched: it is
    // not this mutation's effect.
    std::fs::write(scene.root().join("a.txt"), "new").unwrap();
    let crashed = exited_journal(scene.journal_path(), "crashed");
    leave_open(
        &crashed,
        "crashed.m0",
        mutation(
            &scene,
            "a.txt",
            Postcondition::File {
                sha256: sha("new"),
                before: None,
            },
        ),
        false,
    );
    let restored = restore(&exited_journal(scene.journal_path(), "next"));
    assert_eq!(restored.reconciled, 1);
    assert_eq!(outcomes(&scene.journal_path()), ["reconciled_nothing_done"]);
    assert_eq!(
        std::fs::read_to_string(scene.root().join("a.txt")).unwrap(),
        "new"
    );
}

#[test]
fn rj02_an_exited_runs_dispatched_mutation_is_reconciled_against_its_postcondition() {
    let scene = Scene::new("dispatched");
    std::fs::write(scene.root().join("done.txt"), "new").unwrap();
    std::fs::write(scene.root().join("mangled.txt"), "half").unwrap();
    let crashed = exited_journal(scene.journal_path(), "crashed");
    leave_open(
        &crashed,
        "crashed.m0",
        mutation(
            &scene,
            "done.txt",
            Postcondition::File {
                sha256: sha("new"),
                before: Some(sha("old")),
            },
        ),
        true,
    );
    leave_open(
        &crashed,
        "crashed.m1",
        mutation(
            &scene,
            "mangled.txt",
            Postcondition::File {
                sha256: sha("new"),
                before: Some(sha("old")),
            },
        ),
        true,
    );
    let before = std::fs::read(scene.root().join("mangled.txt")).unwrap();
    let restored = restore(&exited_journal(scene.journal_path(), "next"));
    assert_eq!(restored.reconciled, 2);
    let mut found = outcomes(&scene.journal_path());
    found.sort();
    assert_eq!(found, ["reconciled_done", "reconciled_unknown"]);
    assert_eq!(
        std::fs::read(scene.root().join("mangled.txt")).unwrap(),
        before,
        "an unknown outcome is left for the user, never retried"
    );
    // Closed for good: a third start reconciles nothing.
    assert_eq!(
        restore(&exited_journal(scene.journal_path(), "third")).reconciled,
        0
    );
}

#[test]
fn rj02_a_running_orcelds_open_mutation_is_never_touched() {
    let scene = Scene::new("live");
    let live = journal(scene.journal_path(), "live-run");
    leave_open(
        &live,
        "live-run.m0",
        mutation(&scene, "a.txt", Postcondition::Directory),
        true,
    );
    let restored = restore(&exited_journal(scene.journal_path(), "next"));
    assert_eq!(restored.reconciled, 0);
    assert_eq!(
        events(&scene.journal_path()),
        [
            (IntentState::Pending, String::new()),
            (IntentState::Dispatched, String::new())
        ],
        "the live intent keeps pending and dispatched through compaction"
    );
}

#[test]
fn rj02_outcomes_are_kept_bounded_for_the_resume_summary() {
    let scene = Scene::new("bounded");
    let crashed = exited_journal(scene.journal_path(), "crashed");
    for n in 0..(MAX_OUTCOMES + 20) {
        leave_open(
            &crashed,
            &format!("crashed.m{n}"),
            mutation(&scene, "x", Postcondition::Directory),
            false,
        );
    }
    restore(&exited_journal(scene.journal_path(), "next"));
    assert_eq!(lines(&scene.journal_path()).len(), MAX_OUTCOMES);
    assert!(
        events(&scene.journal_path()).is_empty(),
        "no open intent remains"
    );
}

// ---- the real dispatch path ----

#[test]
fn rj02_an_approved_mkdir_is_journaled_pending_dispatched_settled() {
    let scene = Scene::new("mkdir");
    let sink = Sink::Journal(leaked(journal(scene.journal_path(), "this")));
    dispatch_fs_mutation_to(
        sink,
        &scene.workspace,
        &FixedApprovalBroker(ApprovalDecision::Approved),
        &request("fs.mkdir", "mkdir", "made", json!({})),
    )
    .unwrap();
    assert!(scene.root().join("made").is_dir());
    assert_eq!(
        events(&scene.journal_path()),
        [
            (IntentState::Pending, String::new()),
            (IntentState::Dispatched, String::new()),
            (IntentState::Settled, "done".to_owned()),
        ]
    );
    let text = std::fs::read_to_string(scene.journal_path()).unwrap();
    assert!(text.contains(&"\"approval_digest\"".to_string()));
}

#[test]
fn rj02_a_denied_edit_is_abandoned_and_changes_nothing() {
    let scene = Scene::new("deny");
    std::fs::write(scene.root().join("a.txt"), "alpha").unwrap();
    let sink = Sink::Journal(leaked(journal(scene.journal_path(), "this")));
    let refused = dispatch_fs_mutation_to(
        sink,
        &scene.workspace,
        &FixedApprovalBroker(ApprovalDecision::Denied),
        &request(
            "fs.edit",
            "edit",
            "a.txt",
            json!({ "old": "alpha", "new": "beta", "expected_sha256": sha("alpha") }),
        ),
    );
    assert!(refused.is_err());
    assert_eq!(
        std::fs::read_to_string(scene.root().join("a.txt")).unwrap(),
        "alpha"
    );
    assert_eq!(
        events(&scene.journal_path()),
        [
            (IntentState::Pending, String::new()),
            (IntentState::Abandoned, "approval_denied".to_owned()),
        ]
    );
    let text = std::fs::read_to_string(scene.journal_path()).unwrap();
    assert!(
        !text.contains("alpha") && !text.contains("beta"),
        "no file content"
    );
}

#[test]
fn rj02_a_faulted_or_unwritable_journal_refuses_with_nothing_asked_or_changed() {
    let scene = Scene::new("faulted");
    let asked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    struct Recording(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl orcel_approval::ApprovalBroker for Recording {
        fn request_token(
            &self,
            _prompt: &orcel_approval::ApprovalPrompt,
        ) -> Result<orcel_approval::ApprovedToken, orcel_approval::ApprovalError> {
            self.0.store(true, Ordering::SeqCst);
            Err(orcel_approval::ApprovalError {
                code: FailureCode::ApprovalDenied,
                message: "test".into(),
            })
        }
        fn consume(
            &self,
            _token: &orcel_approval::ApprovedToken,
            _expected: &orcel_approval::ConsumeExpectation,
            _now_ms: u64,
        ) -> Result<(), orcel_approval::ApprovalError> {
            Err(orcel_approval::ApprovalError {
                code: FailureCode::ApprovalDenied,
                message: "test".into(),
            })
        }
    }
    let broker = Recording(asked.clone());
    let refused = dispatch_fs_mutation_to(
        Sink::Faulted,
        &scene.workspace,
        &broker,
        &request("fs.mkdir", "mkdir", "made", json!({})),
    )
    .unwrap_err();
    assert_eq!(refused.code, FailureCode::ProviderUnavailable);
    // The journal's directory is a file: no line can be written.
    std::fs::write(scene.dir.join("state"), "not a directory").unwrap();
    let sink = Sink::Journal(leaked(journal(scene.journal_path(), "this")));
    let refused = dispatch_fs_mutation_to(
        sink,
        &scene.workspace,
        &broker,
        &request("fs.mkdir", "mkdir", "made", json!({})),
    )
    .unwrap_err();
    assert_eq!(refused.code, FailureCode::ProviderUnavailable);
    assert!(!asked.load(Ordering::SeqCst), "nothing was asked");
    assert!(!scene.root().join("made").exists(), "nothing was changed");
}
