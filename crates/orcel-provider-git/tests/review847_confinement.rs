//! Review of #847: what Git itself follows out of a repository while its
//! top level, Git folder and common folder still report the repository: a
//! reference backend at another place (`extensions.refStorage`), a Git
//! folder that is partly a link, and a working tree a branch switch
//! re-applies a sparse checkout to (through a junction). Real Git, real
//! repositories.

use orcel_contracts::FailureCode;
use orcel_provider_git::GitProvider;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn temp_root(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "orcel-review847-{label}-{}-{suffix}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).expect("temp root");
    root
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("git");
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A repository with `prod/x.txt` and `other/y.txt` committed.
fn repository(at: &Path) {
    fs::create_dir_all(at.join("prod")).expect("prod");
    fs::create_dir_all(at.join("other")).expect("other");
    git(at, &["init", "-q", "-b", "main"]);
    git(at, &["config", "user.email", "orcel@example.invalid"]);
    git(at, &["config", "user.name", "Orcel Test"]);
    git(at, &["config", "core.autocrlf", "false"]);
    fs::write(at.join("prod").join("x.txt"), "x\n").expect("x");
    fs::write(at.join("other").join("y.txt"), "y\n").expect("y");
    git(at, &["add", "."]);
    git(at, &["commit", "-q", "-m", "initial"]);
}

/// A folder link: a junction on Windows (no privilege), a symlink elsewhere.
fn link(at: &Path, target: &Path) {
    #[cfg(windows)]
    {
        let made = Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(at)
            .arg(target)
            .output()
            .expect("mklink");
        assert!(made.status.success());
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, at).expect("symlink");
}

fn unlink(at: &Path) {
    #[cfg(windows)]
    let _ = fs::remove_dir(at);
    #[cfg(unix)]
    let _ = fs::remove_file(at);
}

/// Appends `text` to a configuration file.
fn configure(file: &Path, text: &str) {
    let mut existing = fs::read_to_string(file).unwrap_or_default();
    existing.push_str(text);
    fs::write(file, existing).expect("config");
}

/// Every operation of `provider` on `.` that Orcel offers without a
/// network, and whether any of them ran.
fn anything_ran(provider: &GitProvider) -> Vec<&'static str> {
    let mut ran = Vec::new();
    if provider.status(".").is_ok() {
        ran.push("status");
    }
    if provider.diff(".", false).is_ok() {
        ran.push("diff");
    }
    if provider.log(".", 5).is_ok() {
        ran.push("log");
    }
    if let Ok(state) = provider.branch_state(".") {
        ran.push("branch_state");
        if provider.create_branch(".", "covered", &state).is_ok() {
            ran.push("create_branch");
        }
    }
    if let Ok(state) = provider.staged_state(".") {
        ran.push("staged_state");
        if provider.commit(".", "covered", &state).is_ok() {
            ran.push("commit");
        }
    }
    ran
}

/// Everything a Git change could have changed in `repo`.
fn state(repo: &Path) -> String {
    format!(
        "{}|{}|{}",
        git(repo, &["for-each-ref"]),
        git(repo, &["symbolic-ref", "HEAD"]),
        git(repo, &["reflog", "show", "--all"])
    )
}

#[test]
fn a_reference_backend_elsewhere_is_never_used() {
    let root = temp_root("refstorage");
    let other = root.join("other-repository");
    repository(&other);
    let workspace = root.join("workspace");
    git(
        &root,
        &[
            "clone",
            "-q",
            &other.display().to_string(),
            &workspace.display().to_string(),
        ],
    );
    git(
        &workspace,
        &["config", "user.email", "orcel@example.invalid"],
    );
    git(&workspace, &["config", "user.name", "Orcel Test"]);
    fs::write(workspace.join("prod").join("x.txt"), "changed\n").expect("x");
    git(&workspace, &["add", "prod/x.txt"]);
    let elsewhere = other.join(".git").display().to_string().replace('\\', "/");
    let before = state(&other);
    let config = workspace.join(".git").join("config");
    let original = fs::read_to_string(&config).expect("config");
    for text in [
        format!("[extensions]\n\trefStorage = files://{elsewhere}\n"),
        format!("[EXTENSIONS]\n\tREFSTORAGE = \"files://{elsewhere}\"\n"),
        format!("[extensions]\n\trefstorage = reftable://{elsewhere}\n"),
        "[extensions]\n\trefstorage = reftable\n".to_owned(),
        "[extensions]\n\trefstorage = Files\n".to_owned(),
        "[extensions]\n\trefstorage\n".to_owned(),
        "[extensions \"x\"]\n\trefstorage = files\n".to_owned(),
    ] {
        fs::write(
            &config,
            original.replace("repositoryformatversion = 0", "repositoryformatversion = 1"),
        )
        .expect("config");
        configure(&config, &text);
        let provider = GitProvider::new(&workspace).expect("provider");
        let ran = anything_ran(&provider);
        assert!(ran.is_empty(), "{text:?}: {ran:?}");
        assert_eq!(
            provider.status(".").unwrap_err().code,
            FailureCode::CapabilityDenied
        );
        assert_eq!(state(&other), before, "{text:?}");
    }
    // The same in the per-worktree file, and with the extension that makes
    // Git read that file.
    fs::write(&config, &original).expect("config");
    configure(&config, "[extensions]\n\tworktreeConfig = true\n");
    configure(
        &workspace.join(".git").join("config.worktree"),
        &format!("[extensions]\n\trefStorage = files://{elsewhere}\n"),
    );
    let provider = GitProvider::new(&workspace).expect("provider");
    assert!(anything_ran(&provider).is_empty());
    assert_eq!(state(&other), before);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn only_known_extensions_with_known_values_are_accepted() {
    let root = temp_root("extensions");
    repository(&root);
    let config = root.join(".git").join("config");
    let original = fs::read_to_string(&config)
        .expect("config")
        .replace("repositoryformatversion = 0", "repositoryformatversion = 1");
    for (text, accepted) in [
        ("refStorage = files", true),
        ("noop = anything", true),
        ("worktreeConfig = true", true),
        ("worktreeconfig", true),
        ("worktreeConfig = maybe", false),
        ("objectFormat = sha1", true),
        ("objectFormat = md5", false),
        ("compatObjectFormat = sha256", false),
        ("preciousObjects = false", true),
        ("preciousObjects = x", false),
        ("relativeWorktrees = true", true),
        ("partialClone = origin", true),
        ("partialClone = https://example.invalid/x", false),
        ("partialClone = --upload-pack=x", false),
        ("somethingNew = 1", false),
        ("noop-v1 = 1", false),
        ("submodulePathConfig = true", false),
    ] {
        fs::write(&config, format!("{original}[extensions]\n\t{text}\n")).expect("config");
        let provider = GitProvider::new(&root).expect("provider");
        // Refused by the gate; an older Git may refuse an accepted one.
        let refused = provider.log(".", 1).err().is_some_and(|error| {
            error.code == FailureCode::CapabilityDenied
                && error.message.contains("not known to keep Git")
        });
        assert_eq!(refused, !accepted, "{text}");
    }
    let _ = fs::remove_dir_all(&root);
}

/// A repository whose sparse checkout now excludes `prod` and includes
/// `other`, without having been re-applied: `prod/x.txt` is still in the
/// working tree and `other/y.txt` is not.
fn sparse_repository(repo: &Path) {
    repository(repo);
    git(repo, &["sparse-checkout", "init", "--no-cone"]);
    let patterns = repo.join(".git").join("info").join("sparse-checkout");
    fs::write(&patterns, "/prod/\n").expect("patterns");
    git(repo, &["sparse-checkout", "reapply"]);
    assert!(!repo.join("other").join("y.txt").exists());
    // The next re-application deletes prod/x.txt and writes other/y.txt.
    fs::write(&patterns, "/other/\n").expect("patterns");
}

/// Every operation of `provider`; after each, `check`.
fn every_operation(repo: &Path, provider: &GitProvider, check: &dyn Fn(&str)) {
    if let Ok(state) = provider.branch_state(".") {
        let _ = provider.create_branch(".", "topic", &state);
    }
    check("create_branch");
    fs::write(repo.join("new.txt"), "new\n").expect("new");
    let paths = vec!["new.txt".to_owned()];
    for _ in 0..2 {
        if let Ok(state) = provider.path_state(".", &paths) {
            let _ = provider.stage(".", &paths, &state);
        }
        check("stage");
        if let Ok(state) = provider.unstage_state(".", &paths) {
            let _ = provider.unstage(".", &paths, &state);
        }
        check("unstage");
    }
    git(repo, &["update-index", "--add", "new.txt"]);
    if let Ok(state) = provider.staged_state(".") {
        let _ = provider.commit(".", "new", &state);
    }
    check("commit");
    let _ = provider.status(".");
    let _ = provider.diff(".", false);
    check("a read");
}

#[test]
fn no_operation_writes_the_working_tree() {
    let root = temp_root("sparse");
    let repo = root.join("repo");
    sparse_repository(&repo);
    let provider = GitProvider::new(&repo).expect("provider");
    every_operation(&repo, &provider, &|what| {
        assert!(
            repo.join("prod").join("x.txt").exists(),
            "{what} deleted a working tree file"
        );
        assert!(
            !repo.join("other").join("y.txt").exists(),
            "{what} wrote a working tree file"
        );
    });
    // The branch was made all the same.
    assert_eq!(
        git(&repo, &["symbolic-ref", "HEAD"]).trim(),
        "refs/heads/topic"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn no_operation_writes_outside_through_a_link() {
    let root = temp_root("sparse-link");
    let repo = root.join("repo");
    sparse_repository(&repo);
    let outside = root.join("outside");
    fs::create_dir_all(outside.join("prod")).expect("outside");
    fs::create_dir_all(outside.join("other")).expect("outside");
    fs::copy(
        repo.join("prod").join("x.txt"),
        outside.join("prod").join("x.txt"),
    )
    .expect("copy");
    let _ = fs::remove_dir_all(repo.join("prod"));
    let _ = fs::remove_dir_all(repo.join("other"));
    link(&repo.join("prod"), &outside.join("prod"));
    link(&repo.join("other"), &outside.join("other"));
    let _ = Command::new("git")
        .args(["update-index", "-q", "--refresh"])
        .current_dir(&repo)
        .output();
    let provider = GitProvider::new(&repo).expect("provider");
    every_operation(&repo, &provider, &|what| {
        assert!(
            outside.join("prod").join("x.txt").exists(),
            "{what} deleted a file outside"
        );
        assert!(
            !outside.join("other").join("y.txt").exists(),
            "{what} wrote a file outside"
        );
    });
    unlink(&repo.join("prod"));
    unlink(&repo.join("other"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_branch_is_created_only_when_it_is_new_and_plainly_named() {
    let root = temp_root("branch");
    repository(&root);
    git(&root, &["branch", "taken"]);
    git(&root, &["switch", "-q", "-c", "previous"]);
    git(&root, &["switch", "-q", "main"]);
    let provider = GitProvider::new(&root).expect("provider");
    for bad in [
        "taken", "main", "HEAD", "@{-1}", "a..b", "taken/x", "x.lock", "a b",
    ] {
        let state = provider.branch_state(".").expect("state");
        let refused = provider.create_branch(".", bad, &state);
        assert!(refused.is_err(), "{bad}: {refused:?}");
        assert_eq!(
            git(&root, &["symbolic-ref", "HEAD"]).trim(),
            "refs/heads/main",
            "{bad}"
        );
    }
    assert_eq!(
        git(&root, &["for-each-ref", "--format=%(refname)"])
            .lines()
            .count(),
        3
    );
    // Local changes and the index stay as they are.
    fs::write(root.join("prod").join("x.txt"), "changed\n").expect("x");
    git(&root, &["add", "prod/x.txt"]);
    fs::write(root.join("other").join("y.txt"), "changed\n").expect("y");
    let before = git(&root, &["status", "--porcelain"]);
    let state = provider.branch_state(".").expect("state");
    provider
        .create_branch(".", "feature/new", &state)
        .expect("branch");
    assert_eq!(git(&root, &["status", "--porcelain"]), before);
    assert!(
        git(&root, &["reflog", "show", "feature/new"]).contains("branch: Created from"),
        "the branch has its reflog entry"
    );
    let _ = fs::remove_dir_all(&root);
}

/// Parts of the Git folder that lead elsewhere.
#[test]
fn a_git_folder_that_is_partly_a_link_is_refused() {
    let root = temp_root("linked");
    for part in ["refs", "refs/heads", "logs", "objects"] {
        let repo = root.join(part.replace('/', "-"));
        repository(&repo);
        fs::write(repo.join("prod").join("x.txt"), "changed\n").expect("x");
        git(&repo, &["add", "prod/x.txt"]);
        let inside = part
            .split('/')
            .fold(repo.join(".git"), |at, name| at.join(name));
        let outside = root.join(format!("outside-{}", part.replace('/', "-")));
        fs::rename(&inside, &outside).expect("move");
        link(&inside, &outside);
        let provider = GitProvider::new(&repo).expect("provider");
        let ran = anything_ran(&provider);
        assert!(ran.is_empty(), "{part}: {ran:?}");
        unlink(&inside);
    }
    let _ = fs::remove_dir_all(&root);
}

/// A tracked folder that now leads outside: Git for Windows reads and stages
/// through a junction.
#[test]
fn a_tracked_folder_behind_a_link_is_neither_read_nor_staged() {
    let root = temp_root("behind");
    let repo = root.join("repo");
    repository(&repo);
    let outside = root.join("outside");
    fs::create_dir_all(&outside).expect("outside");
    fs::write(outside.join("x.txt"), "secret outside\n").expect("secret");
    fs::write(outside.join("new.txt"), "secret outside\n").expect("secret");
    let _ = fs::remove_dir_all(repo.join("prod"));
    link(&repo.join("prod"), &outside);
    let provider = GitProvider::new(&repo).expect("provider");
    for result in [
        provider.diff(".", false),
        provider.status("."),
        provider.diff(".", true),
    ] {
        let text = format!("{result:?}");
        assert!(!text.contains("secret outside"), "{text}");
        assert!(!text.contains("new.txt"), "{text}");
    }
    for path in ["prod/x.txt", "prod/new.txt"] {
        let paths = vec![path.to_owned()];
        if let Ok(state) = provider.path_state(".", &paths) {
            let staged = provider.stage(".", &paths, &state);
            assert!(staged.is_err(), "{path}: {staged:?}");
        }
    }
    unlink(&repo.join("prod"));
    // A link that names no tracked file.
    fs::create_dir_all(repo.join("prod")).expect("prod");
    fs::write(repo.join("prod").join("x.txt"), "changed\n").expect("x");
    link(&repo.join("free"), &outside);
    // Git for Windows walks an untracked junction too: not ignored, refused;
    // ignored, not walked.
    let status = format!("{:?}", provider.status("."));
    assert!(!status.contains("new.txt"), "{status}");
    fs::write(repo.join(".git").join("info").join("exclude"), "free\n").expect("exclude");
    let status = provider.status(".").expect("an ignored link");
    assert!(!status.to_string().contains("free"), "{status}");
    assert!(provider.diff(".", false).is_ok());
    let paths = vec!["free/new.txt".to_owned()];
    assert!(provider.path_state(".", &paths).is_err());
    unlink(&repo.join("free"));
    let _ = fs::remove_dir_all(&root);
}
