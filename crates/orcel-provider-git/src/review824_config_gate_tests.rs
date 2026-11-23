//! Review of #824 (SG-000132 slice 4): the repository configuration gate,
//! with real Git. Hooks defined in configuration (`hook.<name>.command` and
//! `hook.<name>.event`, which neither `core.hooksPath` nor `--no-verify`
//! turns off) make the provider refuse the repository before any Git
//! command runs in it, for reads (no approval) and mutations alike; a `.git`
//! file or configuration value naming a network share is refused before
//! Git could open it.

use crate::GitProvider;
use orcel_contracts::FailureCode;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "orcel-review824-{name}-{nanos}-{}",
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
    assert!(git(&root, &["add", "a.txt"]));
    assert!(git(&root, &["commit", "-q", "-m", "initial"]));
    root
}

/// Configures hooks for `events` that append to `marker`.
fn configure_hooks(repo: &Path, marker: &Path, events: &[&str]) {
    let target = marker.display().to_string().replace('\\', "/");
    for (index, event) in events.iter().enumerate() {
        let name = format!("hook.evil{index}");
        assert!(git(
            repo,
            &[
                "config",
                &format!("{name}.command"),
                &format!("echo {event} >> '{target}'")
            ]
        ));
        assert!(git(repo, &["config", &format!("{name}.event"), event]));
    }
}

#[test]
fn review824_config_defined_hooks_refuse_the_repository_before_git_runs() {
    let repo = repository();
    let marker = repo.parent().expect("parent").join(format!(
        "{}-marker",
        repo.file_name().and_then(|n| n.to_str()).expect("name")
    ));
    configure_hooks(
        &repo,
        &marker,
        &["post-index-change", "reference-transaction", "post-commit"],
    );
    fs::write(repo.join("a.txt"), "two\n").expect("a");
    let provider = GitProvider::new(&repo).expect("provider");
    // Reads (no approval in Full Control) and mutations are all refused.
    assert_eq!(
        provider.diff(".", false).map(|_| ()).unwrap_err().code,
        FailureCode::CapabilityDenied
    );
    assert_eq!(
        provider.status(".").map(|_| ()).unwrap_err().code,
        FailureCode::CapabilityDenied
    );
    assert_eq!(
        provider.branch_state(".").map(|_| ()).unwrap_err().code,
        FailureCode::CapabilityDenied
    );
    assert!(
        !marker.exists(),
        "a configured hook ran: {}",
        fs::read_to_string(&marker).unwrap_or_default()
    );
    // Control: Git itself, with the provider's own hook overrides, does
    // run configuration-defined hooks where it supports them.
    let control = Command::new("git")
        .args(["-c", "core.hooksPath=", "-c", "core.fsmonitor=false"])
        .args(["diff", "--no-ext-diff", "--no-textconv"])
        .current_dir(&repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("git");
    let _ = git(&repo, &["update-ref", "refs/heads/control", "HEAD"]);
    if marker.exists() {
        println!("control: this Git runs configuration-defined hooks");
    } else {
        println!(
            "control: this Git does not run configuration-defined hooks ({})",
            String::from_utf8_lossy(&control.stderr).trim()
        );
    }
    // Without the hook keys, the same repository works.
    let _ = fs::remove_file(&marker);
    assert!(git(&repo, &["config", "--remove-section", "hook.evil0"]));
    assert!(git(&repo, &["config", "--remove-section", "hook.evil1"]));
    assert!(git(&repo, &["config", "--remove-section", "hook.evil2"]));
    provider.diff(".", false).expect("diff without hooks");
    let state = provider.branch_state(".").expect("state");
    provider
        .create_branch(".", "topic", &state)
        .expect("branch without hooks");
    assert!(!marker.exists());
    let _ = fs::remove_dir_all(&repo);
    let _ = fs::remove_file(&marker);
}

#[test]
fn review824_hooks_in_the_worktree_config_and_old_section_forms_are_refused() {
    let repo = repository();
    assert!(git(&repo, &["config", "extensions.worktreeConfig", "true"]));
    fs::write(
        repo.join(".git").join("config.worktree"),
        "[HOOK.evil]\n\tcommand = echo x\n\tevent = post-index-change\n",
    )
    .expect("config.worktree");
    let provider = GitProvider::new(&repo).expect("provider");
    assert_eq!(
        provider.status(".").map(|_| ()).unwrap_err().code,
        FailureCode::CapabilityDenied
    );
    let _ = fs::remove_dir_all(&repo);
}

#[test]
fn review824_command_valued_keys_and_includes_are_refused() {
    for (key, value) in [
        ("alias.st", "!echo evil"),
        ("core.sshCommand", "evil"),
        ("core.hooksPath", "myhooks"),
        ("credential.helper", "evil"),
        ("diff.x.command", "evil"),
        ("merge.x.driver", "evil"),
        ("remote.origin.uploadpack", "evil"),
        (
            "url.https://evil.invalid/.insteadOf",
            "https://example.com/",
        ),
        ("include.path", "../x.cfg"),
        ("includeIf.gitdir:/.path", "../x.cfg"),
        ("core.excludesFile", r"\\orcel-unreachable.invalid\share\x"),
        ("core.attributesFile", "//orcel-unreachable.invalid/share/x"),
    ] {
        let repo = repository();
        assert!(git(&repo, &["config", key, value]), "{key}");
        let provider = GitProvider::new(&repo).expect("provider");
        assert_eq!(
            provider.status(".").map(|_| ()).unwrap_err().code,
            FailureCode::CapabilityDenied,
            "{key}"
        );
        let _ = fs::remove_dir_all(&repo);
    }
}

#[test]
fn review824_a_git_file_naming_a_share_is_refused_before_git_opens_it() {
    for target in [
        r"\\orcel-unreachable.invalid\share\repo.git",
        "//orcel-unreachable.invalid/share/repo.git",
        r"\\?\UNC\orcel-unreachable.invalid\share\repo.git",
        r"\\.\pipe\orcel",
    ] {
        let root = temp_root("pointer");
        fs::write(root.join(".git"), format!("gitdir: {target}\n")).expect(".git file");
        let provider = GitProvider::new(&root).expect("provider");
        let started = std::time::Instant::now();
        assert_eq!(
            provider.status(".").map(|_| ()).unwrap_err().code,
            FailureCode::PathEscape,
            "{target}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "refused without a network attempt"
        );
        let _ = fs::remove_dir_all(&root);
    }
}

/// Re-review of #824: submodules fail closed (their own configuration and
/// filters are outside the gate), and a gitlink to a nested repository
/// without `.gitmodules` is never entered.
#[test]
fn review824_submodules_are_refused_and_nested_repositories_never_entered() {
    let repo = repository();
    fs::write(
        repo.join(".gitmodules"),
        "[submodule \"sm\"]\n\tpath = sm\n\turl = ./sm\n",
    )
    .expect(".gitmodules");
    let provider = GitProvider::new(&repo).expect("provider");
    assert_eq!(
        provider.status(".").map(|_| ()).unwrap_err().code,
        FailureCode::CapabilityDenied
    );
    fs::remove_file(repo.join(".gitmodules")).expect("remove");
    let modules = repo.join(".git").join("modules").join("sm");
    fs::create_dir_all(&modules).expect("modules");
    fs::write(
        modules.join("config"),
        "[filter \"evil\"]\n\tclean = evil\n",
    )
    .expect("config");
    assert_eq!(
        provider.status(".").map(|_| ()).unwrap_err().code,
        FailureCode::CapabilityDenied
    );
    fs::remove_dir_all(repo.join(".git").join("modules")).expect("remove");

    // A nested repository whose own filter would leave a marker, staged in
    // the parent as a gitlink (no .gitmodules).
    let nested = repo.join("sm");
    fs::create_dir_all(&nested).expect("nested");
    assert!(git(&nested, &["init", "-q"]));
    assert!(git(&nested, &["config", "user.name", "Orcel Test"]));
    assert!(git(
        &nested,
        &["config", "user.email", "orcel@example.invalid"]
    ));
    fs::write(nested.join("x.txt"), "x\n").expect("x");
    assert!(git(&nested, &["add", "x.txt"]));
    assert!(git(&nested, &["commit", "-q", "-m", "nested"]));
    let marker = repo.parent().expect("parent").join(format!(
        "{}-nested-marker",
        repo.file_name().and_then(|n| n.to_str()).expect("name")
    ));
    let target = marker.display().to_string().replace('\\', "/");
    assert!(git(
        &nested,
        &[
            "config",
            "filter.evil.clean",
            &format!("sh -c \"echo ran > '{target}'; cat\"")
        ]
    ));
    fs::write(nested.join(".gitattributes"), "* filter=evil\n").expect("attributes");
    fs::write(nested.join("x.txt"), "changed\n").expect("x");
    assert!(git(&repo, &["add", "sm"]));
    let _ = fs::remove_file(&marker);
    fs::write(repo.join("a.txt"), "two\n").expect("a");
    provider.status(".").expect("status");
    provider.diff(".", false).expect("diff");
    provider.diff(".", true).expect("staged diff");
    let paths = vec!["a.txt".to_owned()];
    let state = provider.path_state(".", &paths).expect("state");
    provider.stage(".", &paths, &state).expect("stage");
    let staged = provider.staged_state(".").expect("staged");
    provider.commit(".", "change", &staged).expect("commit");
    assert!(!marker.exists(), "the nested repository's filter ran");
    let _ = fs::remove_dir_all(&repo);
    let _ = fs::remove_file(&marker);
}
