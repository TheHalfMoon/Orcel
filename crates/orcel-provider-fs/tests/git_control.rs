//! Filesystem tools must not mutate repository control data, even through aliases.
use orcel_contracts::FailureCode;
use orcel_provider_fs::FsProvider;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn sandbox(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "orcel-fs-git-{label}-{}-{nonce}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

#[cfg(unix)]
fn alias_dir(target: &Path, alias: &Path) {
    std::os::unix::fs::symlink(target, alias).unwrap();
}

#[cfg(windows)]
fn alias_dir(target: &Path, alias: &Path) {
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(alias)
        .arg(target)
        .status()
        .unwrap();
    assert!(status.success(), "create an in-workspace junction");
}

#[test]
fn every_mutation_refuses_git_control_paths() {
    let root = sandbox("controls");
    fs::create_dir_all(root.join(".git/hooks")).unwrap();
    fs::write(root.join(".git/config"), "safe").unwrap();
    fs::write(root.join(".git/hooks/pre-commit"), "safe").unwrap();
    fs::write(root.join("normal.txt"), "normal").unwrap();
    let p = FsProvider::new(&root).unwrap();
    let id = p.entry_identity("normal.txt").unwrap();

    for name in [
        ".git/config",
        ".GIT/hooks/pre-commit",
        "./.git/config",
        "sub/../.git/config",
    ] {
        assert!(p.preview_write(name, "bad").is_err(), "preview {name}");
        assert!(
            p.write_text(name, "bad", None, true).is_err(),
            "write {name}"
        );
        assert!(p.create_text(name, "bad").is_err(), "create {name}");
        assert!(p.entry_identity(name).is_err(), "identity {name}");
        assert!(
            p.edit_preview(name, "safe", "bad", &"0".repeat(64), 1)
                .is_err(),
            "edit {name}"
        );
        assert!(p.remove_entry(name, &id).is_err(), "remove {name}");
    }
    assert!(p.mkdir(".git/new", true).is_err());
    assert!(p.mkdir("newdir/.git/config", true).is_err());
    assert!(!root.join("newdir").exists());
    assert!(p.move_entry("normal.txt", ".git/normal.txt", &id).is_err());
    assert_eq!(
        fs::read_to_string(root.join(".git/config")).unwrap(),
        "safe"
    );
    assert_eq!(
        fs::read_to_string(root.join(".git/hooks/pre-commit")).unwrap(),
        "safe"
    );
    assert_eq!(
        fs::read_to_string(root.join("normal.txt")).unwrap(),
        "normal"
    );
    assert!(!root.join(".git/new").exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn resolved_git_alias_is_not_mutable() {
    let root = sandbox("alias");
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::write(root.join(".git/config"), "safe").unwrap();
    fs::write(root.join("normal.txt"), "normal").unwrap();
    alias_dir(&root.join(".git"), &root.join("alias"));
    let p = FsProvider::new(&root).unwrap();
    let id = p.entry_identity("normal.txt").unwrap();

    assert_eq!(
        p.preview_write("alias/config", "bad").unwrap_err().code,
        FailureCode::CapabilityDenied
    );
    assert!(p.write_text("alias/config", "bad", None, false).is_err());
    assert!(p.create_text("alias/new", "bad").is_err());
    assert!(p.mkdir("alias/newdir", true).is_err());
    assert!(p.entry_identity("alias/config").is_err());
    assert!(p.move_entry("normal.txt", "alias/normal.txt", &id).is_err());
    assert!(p.remove_entry("alias/config", &id).is_err());
    assert_eq!(
        fs::read_to_string(root.join(".git/config")).unwrap(),
        "safe"
    );
    assert_eq!(
        fs::read_to_string(root.join("normal.txt")).unwrap(),
        "normal"
    );

    #[cfg(windows)]
    fs::remove_dir(root.join("alias")).unwrap();
    #[cfg(unix)]
    fs::remove_file(root.join("alias")).unwrap();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn configured_git_metadata_workspace_is_read_only_to_fs_tools() {
    let root = sandbox("git-root");
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::write(root.join(".git/config"), "safe").unwrap();
    let p = FsProvider::new(root.join(".git")).unwrap();
    assert_eq!(
        p.preview_write("config", "bad").unwrap_err().code,
        FailureCode::CapabilityDenied
    );
    assert!(p.write_text("config", "bad", None, false).is_err());
    assert!(p.create_text("new", "bad").is_err());
    assert!(p.mkdir("new", true).is_err());
    assert_eq!(
        fs::read_to_string(root.join(".git/config")).unwrap(),
        "safe"
    );
    let _ = fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn windows_streams_and_dotted_aliases_are_denied() {
    let root = sandbox("windows");
    fs::write(root.join("normal.txt"), "safe").unwrap();
    let p = FsProvider::new(&root).unwrap();
    for name in ["normal.txt:stream", ".git.", ".git ", "normal.txt."] {
        assert!(p.preview_write(name, "bad").is_err(), "preview {name}");
        assert!(
            p.write_text(name, "bad", None, true).is_err(),
            "write {name}"
        );
        assert!(p.create_text(name, "bad").is_err(), "create {name}");
    }
    assert_eq!(fs::read_to_string(root.join("normal.txt")).unwrap(), "safe");
    let _ = fs::remove_dir_all(root);
}

/// A Git directory under another name, as `git init --separate-git-dir gitmeta` makes:
/// Git knows it by its contents, so the filesystem tools must too.
fn git_dir_at(dir: &Path) {
    fs::create_dir_all(dir.join("objects")).unwrap();
    fs::create_dir_all(dir.join("refs/heads")).unwrap();
    fs::create_dir_all(dir.join("hooks")).unwrap();
    fs::write(dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(dir.join("config"), "safe").unwrap();
}

#[test]
fn a_git_directory_under_another_name_is_not_mutable() {
    let root = sandbox("separate");
    git_dir_at(&root.join("gitmeta"));
    fs::write(root.join(".git"), "gitdir: gitmeta\n").unwrap();
    fs::write(root.join("normal.txt"), "normal").unwrap();
    let p = FsProvider::new(&root).unwrap();
    let id = p.entry_identity("normal.txt").unwrap();

    assert_eq!(
        p.preview_write("gitmeta/config", "bad").unwrap_err().code,
        FailureCode::CapabilityDenied
    );
    assert!(p.write_text("gitmeta/config", "bad", None, false).is_err());
    assert!(p.create_text("gitmeta/hooks/pre-commit", "bad").is_err());
    assert!(p.mkdir("gitmeta/hooks/newdir", true).is_err());
    assert!(p.create_text("gitmeta/refs/heads/evil", "bad").is_err());
    assert!(p
        .move_entry("normal.txt", "gitmeta/normal.txt", &id)
        .is_err());
    assert_eq!(
        fs::read_to_string(root.join("gitmeta/config")).unwrap(),
        "safe"
    );
    assert!(!root.join("gitmeta/hooks/pre-commit").exists());
    // An ordinary folder beside it is still writable.
    p.create_text("notes/todo.txt", "fine").unwrap_err();
    p.mkdir("notes", false).unwrap();
    p.create_text("notes/todo.txt", "fine").unwrap();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_workspace_that_is_a_git_directory_is_read_only_to_fs_tools() {
    let root = sandbox("bare");
    git_dir_at(&root.join("proj.git"));
    let p = FsProvider::new(root.join("proj.git")).unwrap();
    assert_eq!(
        p.create_text("hooks/post-update", "bad").unwrap_err().code,
        FailureCode::CapabilityDenied
    );
    assert!(p.write_text("config", "bad", None, false).is_err());
    assert_eq!(
        fs::read_to_string(root.join("proj.git/config")).unwrap(),
        "safe"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_file_with_another_hard_link_is_not_written() {
    let root = sandbox("hardlink");
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::write(root.join(".git/config"), "safe").unwrap();
    fs::hard_link(root.join(".git/config"), root.join("hl.txt")).unwrap();
    let p = FsProvider::new(&root).unwrap();
    assert_eq!(
        p.preview_write("hl.txt", "bad").unwrap_err().code,
        FailureCode::CapabilityDenied
    );
    let current = sha256(b"safe");
    assert!(p
        .write_text("hl.txt", "bad", Some(&current), false)
        .is_err());
    assert_eq!(
        fs::read_to_string(root.join(".git/config")).unwrap(),
        "safe"
    );
    // A file with one name is written as before.
    fs::write(root.join("single.txt"), "one").unwrap();
    let preview = p.preview_write("single.txt", "two").unwrap();
    p.write_text(
        "single.txt",
        "two",
        preview.current_sha256.as_deref(),
        false,
    )
    .unwrap();
    assert_eq!(fs::read_to_string(root.join("single.txt")).unwrap(), "two");
    let _ = fs::remove_dir_all(root);
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
