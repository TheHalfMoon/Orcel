//! XP-01B owner-only state files.
//!
//! Authority keys, trust records, lease stores and the executable registry
//! are written readable by their owner only (mode 0600 on Unix). On Windows
//! the files inherit the per-user `%LOCALAPPDATA%` ACL, as before.
//!
//! An atomic replace writes a sibling temp file first. Its name carries a
//! random suffix and it is created with `create_new`, so a pre-created or
//! symlinked temp name is never opened, followed or reused.

use std::collections::hash_map::RandomState;
use std::fs::{File, OpenOptions};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Attempts before giving up when random temp names keep colliding.
const TEMP_ATTEMPTS: u32 = 16;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Replaces `path` with `bytes` through a fresh owner-only temp file in the
/// same directory and a rename. The parent directory must already exist.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let (temp, mut file) = create_private_temp(path)?;
    let synced = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let written = synced.and_then(|()| std::fs::rename(&temp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written
}

/// Opens `path` for appending, creating it owner-only when it is missing.
pub fn open_private_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    owner_only(&mut options);
    options.open(path)
}

fn create_private_temp(path: &Path) -> io::Result<(PathBuf, File)> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "state file path has no file name",
        )
    })?;
    for _ in 0..TEMP_ATTEMPTS {
        let temp = path.with_file_name(format!(
            ".{}.tmp-{:016x}",
            name.to_string_lossy(),
            random_suffix()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        owner_only(&mut options);
        match options.open(&temp) {
            Ok(file) => return Ok((temp, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique state temp file",
    ))
}

/// A suffix nobody can predict: `RandomState` is seeded from the OS once per
/// process, mixed with the time, the pid and a per-process counter.
fn random_suffix() -> u64 {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(SEQUENCE.fetch_add(1, Ordering::Relaxed));
    hasher.write_u32(std::process::id());
    if let Ok(elapsed) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        hasher.write_u128(elapsed.as_nanos());
    }
    hasher.finish()
}

#[cfg(unix)]
fn owner_only(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn owner_only(_options: &mut OpenOptions) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sandbox(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "orcel-platform-files-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("sandbox");
        dir
    }

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp_file() {
        let dir = sandbox("atomic");
        let path = dir.join("state.json");
        write_private_atomic(&path, b"one").expect("first");
        write_private_atomic(&path, b"two").expect("second");
        assert_eq!(std::fs::read(&path).expect("read"), b"two");
        let names: Vec<_> = std::fs::read_dir(&dir)
            .expect("dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("state.json")]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn temp_suffixes_differ_between_calls() {
        assert_ne!(random_suffix(), random_suffix());
    }

    #[test]
    fn append_creates_and_extends() {
        let dir = sandbox("append");
        let path = dir.join("trust.jsonl");
        open_private_append(&path)
            .and_then(|mut file| file.write_all(b"a\n"))
            .expect("first");
        open_private_append(&path)
            .and_then(|mut file| file.write_all(b"b\n"))
            .expect("second");
        assert_eq!(std::fs::read(&path).expect("read"), b"a\nb\n");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn files_are_owner_only_whatever_the_umask() {
        use std::os::unix::fs::PermissionsExt;
        let dir = sandbox("mode");
        let atomic = dir.join("leases.json");
        write_private_atomic(&atomic, b"{}").expect("atomic");
        let appended = dir.join("trust.jsonl");
        open_private_append(&appended).expect("append");
        for path in [atomic, appended] {
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{}", path.display());
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_temp_symlink_is_never_followed() {
        let dir = sandbox("planted");
        let victim = dir.join("victim");
        std::fs::write(&victim, b"keep").expect("victim");
        // Every predictable name an attacker could plant is a symlink; the
        // writer must still succeed without touching the victim.
        let path = dir.join("state.json");
        for name in [".state.json.tmp", ".state.json.tmp-0"] {
            std::os::unix::fs::symlink(&victim, dir.join(name)).expect("plant");
        }
        write_private_atomic(&path, b"new").expect("write");
        assert_eq!(std::fs::read(&victim).expect("victim"), b"keep");
        assert_eq!(std::fs::read(&path).expect("state"), b"new");
        let _ = std::fs::remove_dir_all(dir);
    }
}
