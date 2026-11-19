//! Follow-up to #824 (SG-000132): an untracked nested folder's `.git` file
//! is followed by Git's untracked-file walk (status in every mode but
//! `no`), so a `gitdir:` naming a share would leak NTLM credentials from a
//! plain status read. The provider walks the working tree first and
//! refuses such a repository; with real Git, local folders only.

use orcel_contracts::FailureCode;
use orcel_provider_git::GitProvider;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn temp_root(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "orcel-nested-{name}-{nanos}-{}",
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).expect("root");
    root
}

fn git(cwd: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .expect("git")
        .success()
}

fn repository() -> PathBuf {
    let root = temp_root("repo");
    assert!(git(&root, &["init", "-q"]));
    assert!(git(&root, &["config", "user.name", "Orcel Test"]));
    assert!(git(
        &root,
        &["config", "user.email", "orcel@example.invalid"]
    ));
    fs::write(root.join("a.txt"), "one\n").expect("a");
    fs::write(root.join(".gitignore"), "build/\n").expect("ignore");
    assert!(git(&root, &["add", "a.txt", ".gitignore"]));
    assert!(git(&root, &["commit", "-q", "-m", "initial"]));
    root
}

fn code(provider: &GitProvider) -> Option<FailureCode> {
    provider.status(".").err().map(|error| error.code)
}

#[test]
fn nested_gitfile_naming_a_share_is_refused_before_status_walks() {
    for target in [
        r"\\orcel-unreachable.invalid\share\repo.git",
        "//orcel-unreachable.invalid/share/repo.git",
        r"\\?\UNC\orcel-unreachable.invalid\share\repo.git",
        r"\\.\pipe\orcel",
    ] {
        let repo = repository();
        let nested = repo.join("deep").join("sub");
        fs::create_dir_all(&nested).expect("nested");
        fs::write(nested.join("f.txt"), "f\n").expect("f");
        fs::write(nested.join(".git"), format!("gitdir: {target}\n")).expect(".git file");
        let provider = GitProvider::new(&repo).expect("provider");
        let started = Instant::now();
        assert_eq!(code(&provider), Some(FailureCode::PathEscape), "{target}");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "refused without a network attempt"
        );
        // Every operation resolves its repository through the same walk.
        assert_eq!(
            provider.diff(".", false).err().map(|e| e.code),
            Some(FailureCode::PathEscape)
        );
        let _ = fs::remove_dir_all(&repo);
    }
}

#[test]
fn nested_gitfile_outside_the_workspace_is_refused_and_inside_is_fine() {
    let repo = repository();
    let outside = temp_root("outside");
    assert!(git(&outside, &["init", "-q"]));
    let nested = repo.join("sub");
    fs::create_dir_all(&nested).expect("nested");
    fs::write(
        nested.join(".git"),
        format!("gitdir: {}\n", outside.join(".git").display()),
    )
    .expect(".git file");
    let provider = GitProvider::new(&repo).expect("provider");
    assert_eq!(code(&provider), Some(FailureCode::PathEscape));
    // A nested repository of its own, inside the workspace: status works
    // and shows it as one untracked folder.
    fs::remove_file(nested.join(".git")).expect("remove");
    assert!(git(&nested, &["init", "-q"]));
    fs::write(nested.join("f.txt"), "f\n").expect("f");
    let status = provider.status(".").expect("status");
    assert!(
        status["porcelain_v2"]
            .as_str()
            .is_some_and(|text| text.contains("? sub/")),
        "{status}"
    );
    let _ = fs::remove_dir_all(&repo);
    let _ = fs::remove_dir_all(&outside);
}

#[test]
fn ignored_folders_are_not_walked_unless_something_in_them_is_tracked() {
    let repo = repository();
    let nested = repo.join("build").join("sub");
    fs::create_dir_all(&nested).expect("nested");
    fs::write(
        nested.join(".git"),
        "gitdir: //orcel-unreachable.invalid/share/x\n",
    )
    .expect(".git file");
    let provider = GitProvider::new(&repo).expect("provider");
    // Git does not walk an ignored folder, so neither does the check.
    provider
        .status(".")
        .expect("status with an ignored nested folder");
    // Once the index tracks something in it, Git walks it: refused.
    fs::write(repo.join("build").join("keep.txt"), "k\n").expect("keep");
    assert!(git(&repo, &["add", "-f", "build/keep.txt"]));
    assert_eq!(code(&provider), Some(FailureCode::PathEscape));
    let _ = fs::remove_dir_all(&repo);
}

/// Git asks whether an ignored folder is itself a repository (reading its
/// `.git`) before skipping it, so that `.git` is checked too.
#[test]
fn an_ignored_folder_that_is_itself_a_pointer_is_refused() {
    let repo = repository();
    let build = repo.join("build");
    fs::create_dir_all(&build).expect("build");
    fs::write(
        build.join(".git"),
        "gitdir: //orcel-unreachable.invalid/share/x\n",
    )
    .expect(".git file");
    let provider = GitProvider::new(&repo).expect("provider");
    assert_eq!(code(&provider), Some(FailureCode::PathEscape));
    let _ = fs::remove_dir_all(&repo);
}

#[test]
fn a_working_tree_deeper_than_the_bound_is_refused() {
    let repo = repository();
    let mut deep = repo.clone();
    for _ in 0..70 {
        deep.push("d");
    }
    fs::create_dir_all(&deep).expect("deep");
    fs::write(deep.join("f.txt"), "f\n").expect("f");
    let provider = GitProvider::new(&repo).expect("provider");
    assert_eq!(code(&provider), Some(FailureCode::CapabilityDenied));
    let _ = fs::remove_dir_all(&repo);
}
