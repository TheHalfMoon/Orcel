//! SG-000120 RJ-02 (Git provider): local Git mutations through the real
//! Git dispatch, journaled; branch creation and commits reconciled from
//! refs; network effects never probed.

use super::test_support::{exited_journal, journal, leave_open, restore};
use super::*;
use crate::git_mutation::dispatch_to;
use orcel_approval::test_support::FixedApprovalBroker;
use orcel_approval::ApprovalDecision;
use orcel_contracts::RequestEnvelope;
use orcel_policy::Workspace;
use serde_json::{json, Value};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Repo {
    dir: PathBuf,
    workspace: Workspace,
}

impl Repo {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "orceld-rj02git-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("ws")).unwrap();
        let root = std::fs::canonicalize(dir.join("ws")).unwrap();
        let repo = Self {
            workspace: Workspace {
                id: "default".into(),
                root,
            },
            dir,
        };
        repo.git(&["init", "-q", "-b", "main"]);
        repo.git(&["config", "user.name", "Orcel Test"]);
        repo.git(&["config", "user.email", "orcel@example.invalid"]);
        std::fs::write(repo.root().join("a.txt"), "one\n").unwrap();
        repo.git(&["add", "a.txt"]);
        repo.git(&["commit", "-q", "-m", "initial"]);
        repo
    }

    fn root(&self) -> &Path {
        &self.workspace.root
    }

    fn journal_path(&self) -> PathBuf {
        self.dir.join("state").join("mutations.jsonl")
    }

    fn git(&self, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(self.root())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn head(&self) -> String {
        self.git(&["rev-parse", "HEAD"])
    }

    fn request(&self, capability: &str, operation: &str, arguments: Value) -> RequestEnvelope {
        let mut arguments = arguments;
        arguments["expected_head"] = json!(self.head());
        RequestEnvelope {
            version: 1,
            request_id: "rj02git".into(),
            client_session_id: "s".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: Some(".".into()),
            arguments,
        }
    }

    fn mutation(&self, postcondition: Postcondition) -> Mutation {
        Mutation {
            capability: "git.test".into(),
            operation: "test".into(),
            approval_digest: "d".repeat(64),
            workspace_id: "default".into(),
            policy_revision: orcel_policy::POLICY_REVISION.into(),
            root: self.root().to_path_buf(),
            target: ".".into(),
            postcondition,
        }
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn events(path: &Path) -> Vec<(IntentState, String)> {
    orcel_journal::read_lines::<Line>(path)
        .unwrap()
        .lines
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
    orcel_journal::read_lines::<Line>(path)
        .unwrap()
        .lines
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

fn message_sha256(message: &str) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "{:x}",
        Sha256::digest(orcel_provider_git::normalized_commit_message(message).as_bytes())
    )
}

#[test]
fn rj02_an_approved_commit_is_journaled_without_its_message() {
    let repo = Repo::new("commit");
    std::fs::write(repo.root().join("a.txt"), "two\n").unwrap();
    repo.git(&["add", "a.txt"]);
    let parent = repo.head();
    let sink = Sink::Journal(leaked(journal(repo.journal_path(), "this")));
    dispatch_to(
        sink,
        &repo.workspace,
        &FixedApprovalBroker(ApprovalDecision::Approved),
        &repo.request(
            "git.commit",
            "commit",
            json!({ "message": "private-commit-words" }),
        ),
    )
    .unwrap()
    .unwrap();
    assert_ne!(repo.head(), parent);
    assert_eq!(
        events(&repo.journal_path()),
        [
            (IntentState::Pending, String::new()),
            (IntentState::Dispatched, String::new()),
            (IntentState::Settled, "done".to_owned()),
        ]
    );
    let text = std::fs::read_to_string(repo.journal_path()).unwrap();
    assert!(!text.contains("private-commit-words"), "no message text");
    assert!(text.contains(&message_sha256("private-commit-words")));
    // The commit as made reconciles as done.
    assert_eq!(
        reconcile(&repo.mutation(Postcondition::GitCommit {
            branch: "main".into(),
            parent,
            message_sha256: message_sha256("private-commit-words"),
        })),
        Reconciled::Done
    );
}

#[test]
fn rj02_a_denied_stage_is_abandoned_and_the_index_is_unchanged() {
    let repo = Repo::new("deny");
    std::fs::write(repo.root().join("a.txt"), "two\n").unwrap();
    let sink = Sink::Journal(leaked(journal(repo.journal_path(), "this")));
    let refused = dispatch_to(
        sink,
        &repo.workspace,
        &FixedApprovalBroker(ApprovalDecision::Denied),
        &repo.request("git.stage", "stage", json!({ "paths": ["a.txt"] })),
    );
    assert!(refused.is_err());
    assert_eq!(repo.git(&["diff", "--cached", "--name-only"]), "");
    assert_eq!(
        events(&repo.journal_path()),
        [
            (IntentState::Pending, String::new()),
            (IntentState::Abandoned, "approval_denied".to_owned()),
        ]
    );
}

#[test]
fn rj02_a_commit_is_reconciled_from_the_branch_tip() {
    let repo = Repo::new("commit-reconcile");
    let parent = repo.head();
    let commit = |message: &str| {
        reconcile(&repo.mutation(Postcondition::GitCommit {
            branch: "main".into(),
            parent: parent.clone(),
            message_sha256: message_sha256(message),
        }))
    };
    assert_eq!(commit("approved"), Reconciled::NothingDone);
    std::fs::write(repo.root().join("a.txt"), "two\n").unwrap();
    repo.git(&["commit", "-q", "-am", "approved  \n\n\n"]);
    assert_eq!(
        commit("approved"),
        Reconciled::Done,
        "Git's whitespace cleanup is matched"
    );
    assert_eq!(commit("another message"), Reconciled::Unknown);
    std::fs::write(repo.root().join("a.txt"), "three\n").unwrap();
    repo.git(&["commit", "-q", "-am", "approved"]);
    assert_eq!(
        commit("approved"),
        Reconciled::Unknown,
        "a later commit hides whether ours was made"
    );
    let missing = reconcile(&repo.mutation(Postcondition::GitCommit {
        branch: "gone".into(),
        parent: parent.clone(),
        message_sha256: message_sha256("approved"),
    }));
    assert_eq!(missing, Reconciled::Unknown);
}

#[test]
fn rj02_a_branch_creation_is_reconciled_from_its_ref_and_checkout() {
    let repo = Repo::new("branch-reconcile");
    let head = repo.head();
    let branch = |name: &str, at: &str| {
        reconcile(&repo.mutation(Postcondition::GitBranch {
            branch: name.into(),
            head: at.into(),
        }))
    };
    assert_eq!(branch("feature", &head), Reconciled::NothingDone);
    repo.git(&["branch", "feature"]);
    assert_eq!(
        branch("feature", &head),
        Reconciled::Unknown,
        "created but not checked out"
    );
    repo.git(&["switch", "-q", "feature"]);
    assert_eq!(branch("feature", &head), Reconciled::Done);
    assert_eq!(branch("feature", &"0".repeat(40)), Reconciled::Unknown);
}

#[test]
fn rj02_an_exited_runs_dispatched_git_mutations_are_reconciled_and_never_retried() {
    let repo = Repo::new("restore");
    let parent = repo.head();
    let crashed = exited_journal(repo.journal_path(), "crashed");
    leave_open(
        &crashed,
        "crashed.m0",
        repo.mutation(Postcondition::GitCommit {
            branch: "main".into(),
            parent: parent.clone(),
            message_sha256: message_sha256("never made"),
        }),
        true,
    );
    leave_open(
        &crashed,
        "crashed.m1",
        repo.mutation(Postcondition::GitIndex),
        true,
    );
    leave_open(
        &crashed,
        "crashed.m2",
        repo.mutation(Postcondition::Remote),
        true,
    );
    let restored = restore(&exited_journal(repo.journal_path(), "next"));
    assert_eq!(restored.reconciled, 3);
    assert_eq!(
        outcomes(&repo.journal_path()),
        [
            "reconciled_nothing_done",
            "reconciled_unknown",
            "reconciled_unknown"
        ]
    );
    assert_eq!(repo.head(), parent, "nothing was retried");
}

#[test]
fn rj02_a_network_effect_that_errs_after_dispatch_is_unknown() {
    let repo = Repo::new("remote");
    let sink = Sink::Journal(leaked(journal(repo.journal_path(), "this")));
    let result: Result<(), ProviderError> = journaled(
        sink,
        repo.mutation(Postcondition::Remote),
        || Ok(()),
        || {
            Err(ProviderError::new(
                FailureCode::ProviderUnavailable,
                "connection reset",
            ))
        },
    );
    assert!(result.is_err());
    assert_eq!(
        events(&repo.journal_path()),
        [
            (IntentState::Pending, String::new()),
            (IntentState::Dispatched, String::new()),
            (IntentState::Settled, "unknown".to_owned()),
        ]
    );
}

#[test]
fn rj02_a_repository_changed_during_the_prompt_is_abandoned_stale_and_unchanged() {
    struct ChangesTheRepo(PathBuf);
    impl orcel_approval::ApprovalBroker for ChangesTheRepo {
        fn request_token(
            &self,
            prompt: &orcel_approval::ApprovalPrompt,
        ) -> Result<orcel_approval::ApprovedToken, orcel_approval::ApprovalError> {
            std::fs::write(self.0.join("a.txt"), "changed while asking\n").unwrap();
            FixedApprovalBroker(ApprovalDecision::Approved).request_token(prompt)
        }
        fn consume(
            &self,
            token: &orcel_approval::ApprovedToken,
            expected: &orcel_approval::ConsumeExpectation,
            now_ms: u64,
        ) -> Result<(), orcel_approval::ApprovalError> {
            FixedApprovalBroker(ApprovalDecision::Approved).consume(token, expected, now_ms)
        }
    }
    let repo = Repo::new("stale");
    std::fs::write(repo.root().join("a.txt"), "two\n").unwrap();
    let sink = Sink::Journal(leaked(journal(repo.journal_path(), "this")));
    let refused = dispatch_to(
        sink,
        &repo.workspace,
        &ChangesTheRepo(repo.root().to_path_buf()),
        &repo.request("git.stage", "stage", json!({ "paths": ["a.txt"] })),
    )
    .unwrap_err();
    assert_eq!(refused.code, FailureCode::TargetStale);
    assert_eq!(repo.git(&["diff", "--cached", "--name-only"]), "");
    assert_eq!(
        events(&repo.journal_path()),
        [
            (IntentState::Pending, String::new()),
            (IntentState::Abandoned, "target_stale".to_owned()),
        ]
    );
}

#[test]
fn rj02_a_git_refusal_before_the_prompt_journals_nothing() {
    let repo = Repo::new("early-refusal");
    std::fs::write(repo.root().join("a.txt"), "two\n").unwrap();
    let sink = Sink::Journal(leaked(journal(repo.journal_path(), "this")));
    let mut request = repo.request("git.stage", "stage", json!({ "paths": ["a.txt"] }));
    request.arguments["expected_head"] = json!("0".repeat(40));
    let refused = dispatch_to(
        sink,
        &repo.workspace,
        &FixedApprovalBroker(ApprovalDecision::Approved),
        &request,
    )
    .unwrap_err();
    assert_eq!(refused.code, FailureCode::TargetStale);
    assert!(!repo.journal_path().exists(), "nothing was journaled");
}

#[test]
fn rj02_a_commit_without_a_branch_reconciles_unknown() {
    let repo = Repo::new("detached");
    let parent = repo.head();
    repo.git(&["switch", "-q", "--detach"]);
    assert_eq!(
        reconcile(&repo.mutation(Postcondition::GitCommit {
            branch: String::new(),
            parent,
            message_sha256: message_sha256("x"),
        })),
        Reconciled::Unknown
    );
}
