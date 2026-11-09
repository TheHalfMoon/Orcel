//! #384 item 2: the helper verifies the executable through the file it
//! launches.

use super::*;

fn copy_of(source: &Path, dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::copy(source, &path).unwrap();
    std::fs::canonicalize(path).unwrap()
}

fn digest_of(path: &Path) -> [u8; 32] {
    crate::digest::sha256(&std::fs::read(path).unwrap())
}

fn code(result: Result<PinnedExecutable, ContainError>) -> Option<ErrorCode> {
    result.err().map(|error| error.code)
}

#[test]
fn the_registered_digest_opens_and_any_other_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let executable = copy_of(&std::env::current_exe().unwrap(), dir.path(), "tool");
    let digest = digest_of(&executable);
    let pinned = PinnedExecutable::open(&executable, &digest).unwrap();
    assert_eq!(pinned.path(), executable);
    drop(pinned);
    let mut wrong = digest;
    wrong[0] ^= 1;
    assert_eq!(
        code(PinnedExecutable::open(&executable, &wrong)),
        Some(ErrorCode::ExecutableChanged)
    );
}

#[cfg(unix)]
#[test]
fn a_final_symlink_is_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let executable = copy_of(&std::env::current_exe().unwrap(), dir.path(), "tool");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&executable, &link).unwrap();
    assert_eq!(
        code(PinnedExecutable::open(&link, &digest_of(&executable))),
        Some(ErrorCode::LaunchFailed)
    );
}

/// Linux: the bytes that run are the bytes that were hashed, even when the
/// path names another file by the time of the launch.
#[cfg(target_os = "linux")]
#[test]
fn linux_executes_the_verified_file_not_the_path() {
    let dir = tempfile::tempdir().unwrap();
    // Since Ubuntu 26.04 the coreutils are one multi-call binary that picks its command from
    // the name in argv[0], so the copy keeps the name `echo`, and argv[0] is its path, as the
    // launch in linux.rs sets it, not `/proc/self/fd/<n>`.
    let echo = copy_of(Path::new("/bin/echo"), dir.path(), "echo");
    let pinned = PinnedExecutable::open(&echo, &digest_of(&echo)).unwrap();
    // The file swapped in must differ under any name: on 26.04 /bin/false is the same
    // multi-call binary, and named `echo` it would echo too.
    let other = dir.path().join("other");
    std::fs::write(&other, "#!/bin/sh\nexit 3\n").unwrap();
    std::fs::set_permissions(&other, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    std::fs::rename(&other, &echo).unwrap();
    let mut command = std::process::Command::new(pinned.exec_path());
    std::os::unix::process::CommandExt::arg0(&mut command, pinned.path());
    let output = command.arg("pinned").output().unwrap();
    assert!(
        output.status.success(),
        "{:?}, stdout {:?}, stderr {:?}, /bin/echo is {:?}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        std::fs::canonicalize("/bin/echo"),
    );
    assert_eq!(output.stdout, b"pinned\n");
}

/// macOS: a file swapped in under the same path after the check is refused.
#[cfg(target_os = "macos")]
#[test]
fn macos_refuses_a_path_that_names_another_file() {
    let dir = tempfile::tempdir().unwrap();
    let executable = copy_of(Path::new("/bin/echo"), dir.path(), "tool");
    let pinned = PinnedExecutable::open(&executable, &digest_of(&executable)).unwrap();
    assert!(pinned.check_still_named().is_ok());
    let other = copy_of(Path::new("/bin/echo"), dir.path(), "other");
    std::fs::rename(&other, &executable).unwrap();
    assert_eq!(
        pinned.check_still_named().err().map(|error| error.code),
        Some(ErrorCode::ExecutableChanged)
    );
}

/// Windows: while the verified file is held, nobody can write, rename or
/// delete it, nor rename the directory above it.
#[cfg(windows)]
#[test]
fn windows_holds_the_verified_file_against_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let executable = copy_of(&std::env::current_exe().unwrap(), &bin, "tool.exe");
    let pinned = PinnedExecutable::open(&executable, &digest_of(&executable)).unwrap();
    assert!(std::fs::OpenOptions::new()
        .write(true)
        .open(&executable)
        .is_err());
    assert!(std::fs::rename(&executable, bin.join("moved.exe")).is_err());
    assert!(std::fs::remove_file(&executable).is_err());
    assert!(std::fs::rename(&bin, dir.path().join("bin2")).is_err());
    drop(pinned);
    assert!(std::fs::rename(&executable, bin.join("moved.exe")).is_ok());
}
