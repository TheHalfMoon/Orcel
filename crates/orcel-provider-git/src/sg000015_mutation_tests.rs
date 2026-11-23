use crate::GitProvider;
use orcel_contracts::FailureCode;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn temp_root(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "orcel-sg000015-{label}-{}-{suffix}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("create temp root");
    root
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null_device())
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("start git helper");
    assert!(
        output.status.success(),
        "git helper failed: {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn repository() -> PathBuf {
    let root = temp_root("repo");
    git(&root, &["init"]);
    git(&root, &["config", "user.email", "orcel@example.invalid"]);
    git(&root, &["config", "user.name", "Orcel Test"]);
    fs::write(root.join("a.txt"), "one\n").expect("seed a");
    fs::write(root.join("b.txt"), "base\n").expect("seed b");
    git(&root, &["add", "a.txt", "b.txt"]);
    git(&root, &["commit", "-m", "initial"]);
    root
}

#[test]
fn branch_stage_unstage_and_commit_are_exact_and_verified() {
    let root = repository();
    let provider = GitProvider::new(&root).expect("provider");

    let branch_state = provider.branch_state(".").expect("branch state");
    let original_head = branch_state.head.clone();
    let created = provider
        .create_branch(".", "orcel/sg000015", &branch_state)
        .expect("create branch");
    assert_eq!(created["head"], original_head);
    assert_eq!(created["branch"], "orcel/sg000015");

    fs::write(root.join("a.txt"), "two\n").expect("modify a");
    let paths = vec!["a.txt".to_owned()];
    let stage_state = provider.path_state(".", &paths).expect("stage state");
    let staged = provider
        .stage(".", &paths, &stage_state)
        .expect("stage exact path");
    assert!(staged["index_entries"]
        .as_str()
        .is_some_and(|value| value.contains("a.txt")));

    let unstage_state = provider.unstage_state(".", &paths).expect("unstage state");
    provider
        .unstage(".", &paths, &unstage_state)
        .expect("unstage exact path");
    let cached = git(&root, &["diff", "--cached", "--name-only", "--", "a.txt"]);
    assert!(cached.trim().is_empty());

    let stage_state = provider.path_state(".", &paths).expect("stage state again");
    provider
        .stage(".", &paths, &stage_state)
        .expect("stage for commit");
    let commit_state = provider.staged_state(".").expect("commit state");
    let committed = provider
        .commit(".", "approved local mutation", &commit_state)
        .expect("commit");
    assert_eq!(committed["previous_head"], original_head);
    assert_eq!(committed["parent"], original_head);
    assert_ne!(committed["head"], original_head);
    assert_eq!(committed["branch"], "orcel/sg000015");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn stale_head_and_unsafe_paths_fail_before_mutation() {
    let root = repository();
    let provider = GitProvider::new(&root).expect("provider");
    fs::write(root.join("a.txt"), "two\n").expect("modify a");
    let paths = vec!["a.txt".to_owned()];
    let stale = provider.path_state(".", &paths).expect("state");

    fs::write(root.join("b.txt"), "advanced\n").expect("modify b");
    git(&root, &["add", "b.txt"]);
    git(&root, &["commit", "-m", "advance head"]);
    let error = provider
        .stage(".", &paths, &stale)
        .expect_err("stale HEAD must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert!(
        git(&root, &["diff", "--cached", "--name-only", "--", "a.txt"])
            .trim()
            .is_empty()
    );

    for unsafe_path in ["../escape.txt", ".git/config", ":(glob)*"] {
        let error = provider
            .path_state(".", &[unsafe_path.to_owned()])
            .expect_err("unsafe path must fail");
        assert_eq!(error.code, FailureCode::InvalidRequest);
    }

    let _ = fs::remove_dir_all(root);
}

#[test]
fn configured_filter_driver_is_denied_before_stage() {
    let root = repository();
    fs::write(root.join(".gitattributes"), "filtered.txt filter=orcel\n")
        .expect("write attributes");
    fs::write(root.join("filtered.txt"), "content\n").expect("write filtered path");
    git(&root, &["add", ".gitattributes"]);
    git(&root, &["commit", "-m", "attributes"]);

    let provider = GitProvider::new(&root).expect("provider");
    let error = provider
        .path_state(".", &["filtered.txt".to_owned()])
        .expect_err("filter-bearing path must be denied");
    assert_eq!(error.code, FailureCode::CapabilityDenied);
    assert!(git(
        &root,
        &["diff", "--cached", "--name-only", "--", "filtered.txt"]
    )
    .trim()
    .is_empty());

    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn repository_hook_cannot_run_during_branch_creation() {
    use std::os::unix::fs::PermissionsExt;

    let root = repository();
    let sentinel = root.join("hook-ran.txt");
    let hook = root.join(".git").join("hooks").join("post-checkout");
    fs::write(
        &hook,
        format!("#!/bin/sh\nprintf hook > '{}'\n", sentinel.display()),
    )
    .expect("write hook");
    let mut permissions = fs::metadata(&hook).expect("hook metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&hook, permissions).expect("make hook executable");

    let provider = GitProvider::new(&root).expect("provider");
    let state = provider.branch_state(".").expect("branch state");
    provider
        .create_branch(".", "orcel/no-hooks", &state)
        .expect("create branch with hooks disabled");
    assert!(!sentinel.exists(), "repository hook unexpectedly executed");

    let _ = fs::remove_dir_all(root);
}

// Git for Windows maps `/dev/null` to the null device; Git 2.56 rejects `NUL`.
fn null_device() -> &'static str {
    "/dev/null"
}
