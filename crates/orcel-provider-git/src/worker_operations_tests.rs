//! The seven Full Control Git operations as `orceld fc-worker` makes them
//! (`GitProvider::with_program` with an absolute program), against real Git
//! and a repository whose hooks and configuration name programs. They moved
//! here from orceld's `fc_worker_tests.rs`, where Git is off
//! ([`crate::confinement`]).

use crate::GitProvider;
use orcel_contracts::FailureCode;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn root() -> PathBuf {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "orcel-git-worker-{}-{nanos}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("root");
    dir
}

/// The Git program as an absolute path (the worker never searches for it).
fn program() -> PathBuf {
    let name = if cfg!(windows) { "git.exe" } else { "git" };
    std::env::split_paths(&std::env::var_os("PATH").expect("PATH"))
        .map(|folder| folder.join(name))
        .find(|candidate| candidate.is_absolute() && candidate.is_file())
        .expect("Git on PATH")
}

fn provider(root: &Path) -> GitProvider {
    GitProvider::with_program(root, program()).expect("provider")
}

/// Git for the test's own setup, with no system or global config.
fn setup(cwd: &Path, args: &[&str]) {
    let status = Command::new(program())
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .expect("git");
    assert!(status.success(), "{args:?}");
}

fn marker(root: &Path, name: &str) -> PathBuf {
    root.join(format!("marker-{name}"))
}

/// A shell command that leaves `name`'s marker.
fn marker_command(root: &Path, name: &str) -> String {
    format!(
        "echo ran > '{}'",
        marker(root, name).display().to_string().replace('\\', "/")
    )
}

fn write_hook(root: &Path, path: &Path, name: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{}\n", marker_command(root, name))).expect("hook");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
}

/// Review of #824: configuration that names programs. The gate refuses the
/// repository.
fn configure_programs(root: &Path, repo: &Path) -> Vec<PathBuf> {
    let custom = repo.join("myhooks");
    std::fs::create_dir_all(&custom).expect("custom hooks");
    let mut names = Vec::new();
    for name in ["pre-commit", "post-commit", "post-index-change"] {
        let label = format!("custom-{name}");
        write_hook(root, &custom.join(name), &label);
        names.push(label);
    }
    setup(repo, &["config", "core.hooksPath", "myhooks"]);
    for (index, event) in ["post-index-change", "reference-transaction", "post-commit"]
        .iter()
        .enumerate()
    {
        let name = format!("config-hook-{event}");
        setup(
            repo,
            &[
                "config",
                &format!("hook.evil{index}.command"),
                &marker_command(root, &name),
            ],
        );
        setup(repo, &["config", &format!("hook.evil{index}.event"), event]);
        names.push(name);
    }
    for (key, name) in PROGRAM_KEYS {
        setup(
            repo,
            &[
                "config",
                key,
                &format!("!sh -c \"{}\"", marker_command(root, name)),
            ],
        );
        names.push((*name).to_owned());
    }
    names.iter().map(|name| marker(root, name)).collect()
}

const PROGRAM_KEYS: &[(&str, &str)] = &[
    ("core.fsmonitor", "fsmonitor"),
    ("core.pager", "pager"),
    ("diff.external", "diff-external"),
    ("gpg.program", "gpg"),
    ("core.sshCommand", "ssh"),
    ("core.askPass", "askpass"),
    ("credential.helper", "credential"),
    ("diff.evil.textconv", "textconv"),
];

/// A repository whose `.git/hooks`, filter drivers and attributes name
/// programs that leave a marker file next to the repository; its
/// configuration names no program the gate refuses (filters are neutralized,
/// not refused).
fn hostile_repository(root: &Path) -> (PathBuf, Vec<PathBuf>) {
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).expect("repo");
    setup(&repo, &["init", "-q", "-b", "main"]);
    setup(&repo, &["config", "user.name", "Orcel Test"]);
    setup(&repo, &["config", "user.email", "orcel@example.invalid"]);
    std::fs::write(repo.join("a.txt"), "zero\n").expect("a");
    setup(&repo, &["add", "a.txt"]);
    setup(&repo, &["commit", "-q", "-m", "initial"]);
    let hooks = repo.join(".git").join("hooks");
    std::fs::create_dir_all(&hooks).expect("hooks");
    let mut names = Vec::new();
    for name in [
        "pre-commit",
        "commit-msg",
        "post-commit",
        "post-checkout",
        "post-index-change",
        "reference-transaction",
    ] {
        write_hook(root, &hooks.join(name), name);
        names.push(name);
    }
    for (key, name) in [
        ("filter.evil.clean", "filter-clean"),
        ("filter.evil.smudge", "filter-smudge"),
        ("filter.evil.process", "filter-process"),
    ] {
        setup(
            &repo,
            &[
                "config",
                key,
                &format!("!sh -c \"{}\"", marker_command(root, name)),
            ],
        );
        names.push(name);
    }
    setup(&repo, &["config", "commit.gpgSign", "true"]);
    setup(&repo, &["config", "log.showSignature", "true"]);
    setup(&repo, &["config", "filter.evil.required", "true"]);
    std::fs::write(
        repo.join(".gitattributes"),
        "*.evil filter=evil diff=evil\n",
    )
    .expect("attributes");
    std::fs::write(repo.join("a.txt"), "one\n").expect("a");
    // Setting the configuration up may itself have run a hook.
    let markers: Vec<PathBuf> = names.iter().map(|name| marker(root, name)).collect();
    for marker in &markers {
        let _ = std::fs::remove_file(marker);
    }
    (repo, markers)
}

fn none_ran(markers: &[PathBuf]) {
    for marker in markers {
        assert!(!marker.exists(), "{} ran", marker.display());
    }
}

fn paths(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

/// Review of #824 (high): a repository whose configuration defines hooks or
/// names other programs is refused before Git runs in it, for reads and
/// changes alike, and each refused key alone is enough.
#[test]
fn a_repository_whose_configuration_runs_programs_is_refused() {
    let root = root();
    let (repo, mut markers) = hostile_repository(&root);
    markers.extend(configure_programs(&root, &repo));
    let provider = provider(&root);
    let a = paths(&["a.txt"]);
    for (name, result) in [
        ("status", provider.status("repo").map(drop)),
        ("diff", provider.diff("repo", false).map(drop)),
        ("log", provider.log("repo", 5).map(drop)),
        ("add", provider.path_state("repo", &a).map(drop)),
        ("branch", provider.branch_state("repo").map(drop)),
    ] {
        assert_eq!(
            result.err().map(|error| error.code),
            Some(FailureCode::CapabilityDenied),
            "{name}"
        );
    }
    none_ran(&markers);
    setup(&repo, &["config", "--unset", "core.hooksPath"]);
    for (key, _) in PROGRAM_KEYS {
        setup(&repo, &["config", "--unset", key]);
    }
    for section in ["hook.evil1", "hook.evil2"] {
        setup(&repo, &["config", "--remove-section", section]);
    }
    assert_eq!(
        provider.diff("repo", false).err().map(|error| error.code),
        Some(FailureCode::CapabilityDenied),
        "one post-index-change hook in configuration"
    );
    setup(&repo, &["config", "--remove-section", "hook.evil0"]);
    provider
        .diff("repo", false)
        .expect("the same repository without program keys");
    none_ran(&markers);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_operations_honor_no_hook_or_filter() {
    let root = root();
    let (repo, markers) = hostile_repository(&root);
    let provider = provider(&root);
    let status = provider.status("repo").expect("status");
    assert!(
        status["porcelain_v2"]
            .as_str()
            .is_some_and(|text| text.contains("a.txt")),
        "{status}"
    );
    let add = |names: &[&str]| {
        let names = paths(names);
        provider
            .path_state("repo", &names)
            .and_then(|state| provider.stage("repo", &names, &state))
    };
    add(&["a.txt", ".gitattributes"]).expect("add");
    let diff = provider.diff("repo", true).expect("diff");
    assert!(
        diff["diff"]
            .as_str()
            .is_some_and(|text| text.contains("+one")),
        "{diff}"
    );
    let committed = provider
        .staged_state("repo")
        .and_then(|state| provider.commit("repo", "first", &state))
        .expect("commit with hooks and signing disabled");
    assert_eq!(committed["branch"], "main");
    provider
        .branch_state("repo")
        .and_then(|state| provider.create_branch("repo", "topic", &state))
        .expect("branch");
    std::fs::write(repo.join("b.txt"), "two\n").expect("b");
    add(&["b.txt"]).expect("add b");
    let b = paths(&["b.txt"]);
    provider
        .unstage_state("repo", &b)
        .and_then(|state| provider.unstage("repo", &b, &state))
        .expect("unstage b");
    let log = provider.log("repo", 5).expect("log");
    assert_eq!(log["commits"][0]["subject"], "first");
    // A commit message that looks like an option is only a message.
    add(&["b.txt"]).expect("add b again");
    provider
        .staged_state("repo")
        .and_then(|state| provider.commit("repo", "--upload-pack=evil", &state))
        .expect("commit");
    // A file under a configured filter driver is refused, not filtered.
    std::fs::write(repo.join("x.evil"), "x\n").expect("x");
    assert!(add(&["x.evil"]).is_err());
    none_ran(&markers);
    // Control: the same repository with plain Git does run its hook, so the
    // absence above is the provider's hardening, not a dead hook.
    let _ = Command::new(program())
        .args(["-c", "commit.gpgSign=false", "-c", "core.fsmonitor=false"])
        .args(["commit", "-q", "--allow-empty", "-m", "control"])
        .current_dir(&repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status();
    assert!(
        marker(&root, "pre-commit").exists(),
        "plain Git runs the planted hook"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn options_and_git_directories_outside_the_root_are_refused() {
    let root = root();
    let (_, markers) = hostile_repository(&root);
    let provider = provider(&root);
    for branch in ["-c core.sshCommand=evil", "--upload-pack=evil", "-f"] {
        assert_eq!(
            provider
                .branch_state("repo")
                .and_then(|state| provider.create_branch("repo", branch, &state))
                .err()
                .map(|error| error.code),
            Some(FailureCode::InvalidRequest),
            "{branch}"
        );
    }
    for path in [
        "--upload-pack=evil",
        ":(glob)*",
        "../outside.txt",
        ".git/config",
    ] {
        let names = paths(&[path]);
        assert!(
            provider
                .path_state("repo", &names)
                .and_then(|state| provider.stage("repo", &names, &state))
                .is_err(),
            "{path}"
        );
    }
    // A repository whose Git directory is outside the root.
    let outside = root.with_extension("outside-repo");
    std::fs::create_dir_all(&outside).expect("outside");
    setup(&outside, &["init", "-q"]);
    let pointer = root.join("pointer");
    std::fs::create_dir_all(&pointer).expect("pointer");
    std::fs::write(
        pointer.join(".git"),
        format!("gitdir: {}\n", outside.join(".git").display()),
    )
    .expect(".git file");
    assert_eq!(
        provider.status("pointer").err().map(|error| error.code),
        Some(FailureCode::PathEscape)
    );
    // The program is an absolute path to an existing file.
    assert_eq!(
        GitProvider::with_program(&root, "git")
            .err()
            .map(|error| error.code),
        Some(FailureCode::ProviderUnavailable)
    );
    none_ran(&markers);
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside);
}
