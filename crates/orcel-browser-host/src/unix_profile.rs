//! SG-000115 slice A3, inert pre-activation engineering (category A3 in
//! `docs/orcel/implementation-readiness/prep/SG-000115.md`): the Unix
//! profile hold. It covers profile ownership, locking and symlink
//! protection, and is the counterpart of the Windows profile handling.
//!
//! The module is compiled only into Unix test builds
//! (`#[cfg(all(test, unix))]` in `lib.rs`), and `libc` is a Unix
//! dev-dependency only, so no release build contains it. No production path
//! calls it: `profile.rs` is unchanged, and macOS/Linux launch stays
//! refused. The tests use scratch directories only and never start a
//! browser.
//!
//! What the hold does:
//! - **Root descriptor:** opens the profile root with `O_DIRECTORY |
//!   O_NOFOLLOW | O_CLOEXEC`, so a link or a non-directory at the root
//!   refuses. It then checks through that descriptor that the owner is this
//!   user and the mode is exactly 0700.
//! - **Lock:** opens the lock file relative to the root descriptor
//!   (`openat`, `O_NOFOLLOW`, created 0600). A lock file that is a link, is
//!   not a regular file, or has another owner or wider mode refuses. The
//!   lock is taken with a non-blocking exclusive `flock`, so a second hold
//!   on the same profile refuses as busy.
//! - **Lifetime:** both descriptors stay open while the hold lives, and
//!   dropping the hold releases the lock.
//! - **Swap detection:** `verify` checks that the path still names the
//!   same directory (device and inode) as the held descriptor, so a profile
//!   swapped out from under the hold is detected.
//!
//! Open for activation (not decided here):
//! - **Ancestors:** whether the profile's ancestors must also be owned by
//!   this user or root and not writable by others (the parent of the
//!   profile is the state root, owned elsewhere).
//! - **Last component only:** `O_NOFOLLOW` (and `symlink_metadata` in
//!   `verify`) refuse a link at the last path component only; links in
//!   the middle of the path are followed. Activation needs a walk from a
//!   trusted state root (`openat` per component), `openat2`
//!   (`RESOLVE_NO_SYMLINKS`) on Linux or `O_NOFOLLOW_ANY` on macOS.
//! - **macOS ACLs:** extended ACL entries are separate from the mode bits
//!   on macOS, so exactly 0700 / 0600 does not exclude another user there
//!   (on Linux the mode's group bits carry the ACL mask). Activation must
//!   refuse any allow entry (`acl_get_fd_np`).
//! - **Point in time:** `verify` checks one moment; the engine re-resolves
//!   the `--user-data-dir` path itself. Activation must decide how the
//!   engine receives the profile and whether to re-verify after it exits.
//! - **`flock`:** advisory (it binds Orcel's own holders only); on NFS it
//!   may become an `fcntl` lock or fail (`ENOTSUP`, which refuses); a child
//!   that forks without exec keeps it (`O_CLOEXEC` covers exec).
//! - **Leftovers:** the Unix leftover sweep is slice A5, and it must never
//!   unlink a live lock file.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// The lock file's name inside the profile root.
pub(crate) const LOCK_NAME: &str = "orcel-profile.lock";

/// Why a profile cannot be held; every case refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProfileError {
    /// The path does not exist.
    Missing,
    /// A link, or not a directory, at the root; or a link or a non-regular
    /// file at the lock.
    NotPlain,
    /// Another owner, or a mode other than 0700 (root) / 0600 (lock).
    Permissions,
    /// Another hold has the lock.
    Busy,
    /// Swapped: the path no longer names the held directory.
    Swapped,
    /// Any other failure (fails closed).
    Platform(i32),
}

/// A held profile: the root and lock descriptors, open for its lifetime.
#[derive(Debug)]
pub(crate) struct ProfileHold {
    root: OwnedFd,
    _lock: OwnedFd,
    identity: (u64, u64),
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn fstat(fd: &OwnedFd) -> Result<libc::stat, ProfileError> {
    // SAFETY: stat is plain data; zeroed is a valid value.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is an open descriptor and `stat` a valid out-pointer.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(ProfileError::Platform(errno()));
    }
    Ok(stat)
}

/// Owned by this user with exactly `mode` permission bits. (`st_mode` is
/// `u32` on Linux and `u16` on macOS, so the cast is needed on one of them.)
#[allow(clippy::unnecessary_cast)]
fn owned_with_mode(stat: &libc::stat, mode: u32) -> bool {
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    stat.st_uid == me && (stat.st_mode as u32) & 0o7777 == mode
}

/// Device and inode. (`st_dev` is `u64` on Linux and `i32` on macOS.)
#[allow(clippy::unnecessary_cast)]
fn identity(stat: &libc::stat) -> (u64, u64) {
    (stat.st_dev as u64, stat.st_ino as u64)
}

/// Open the lock file relative to the held root, never following a link
/// and never blocking on a FIFO: create it exclusively (and set 0600
/// explicitly, whatever the umask), or open the existing one.
fn open_lock(root: &OwnedFd, name: &CString) -> Result<OwnedFd, ProfileError> {
    let flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    // SAFETY: relative to the held root descriptor; exclusive creation.
    let raw = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CREAT | libc::O_EXCL,
            0o600 as libc::c_uint,
        )
    };
    if raw >= 0 {
        // SAFETY: `raw` is a descriptor this call just opened and owns.
        let lock = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: an open descriptor this call created.
        if unsafe { libc::fchmod(lock.as_raw_fd(), 0o600) } != 0 {
            return Err(ProfileError::Platform(errno()));
        }
        return Ok(lock);
    }
    if errno() != libc::EEXIST {
        return Err(lock_open_error(errno()));
    }
    // SAFETY: relative to the held root descriptor; no creation.
    let raw = unsafe { libc::openat(root.as_raw_fd(), name.as_ptr(), flags) };
    if raw < 0 {
        return Err(lock_open_error(errno()));
    }
    // SAFETY: `raw` is a descriptor this call just opened and owns.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn lock_open_error(errno: i32) -> ProfileError {
    match errno {
        libc::ELOOP | libc::EISDIR => ProfileError::NotPlain,
        other => ProfileError::Platform(other),
    }
}

impl ProfileHold {
    /// Hold the profile at `path`: refuse a link, a non-directory, another
    /// owner, a mode other than 0700, an unsafe lock file, or a profile
    /// another hold already has.
    pub(crate) fn open(path: &Path) -> Result<Self, ProfileError> {
        let c_path =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| ProfileError::NotPlain)?;
        // SAFETY: a NUL-terminated path; the flags request a directory,
        // never follow a link at the last component, and close on exec.
        let raw = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(match errno() {
                libc::ENOENT => ProfileError::Missing,
                libc::ELOOP | libc::ENOTDIR => ProfileError::NotPlain,
                other => ProfileError::Platform(other),
            });
        }
        // SAFETY: `raw` is a descriptor this call just opened and owns.
        let root = unsafe { OwnedFd::from_raw_fd(raw) };
        let root_stat = fstat(&root)?;
        if (root_stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            return Err(ProfileError::NotPlain);
        }
        if !owned_with_mode(&root_stat, 0o700) {
            return Err(ProfileError::Permissions);
        }

        let lock_name = CString::new(LOCK_NAME).map_err(|_| ProfileError::NotPlain)?;
        let lock = open_lock(&root, &lock_name)?;
        let lock_stat = fstat(&lock)?;
        if (lock_stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(ProfileError::NotPlain);
        }
        // One name only: a hard link to another file of this user (a key,
        // say) is not a lock file.
        if lock_stat.st_nlink != 1 {
            return Err(ProfileError::NotPlain);
        }
        if !owned_with_mode(&lock_stat, 0o600) {
            return Err(ProfileError::Permissions);
        }
        // SAFETY: an open descriptor; non-blocking exclusive lock.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(match errno() {
                busy if busy == libc::EWOULDBLOCK || busy == libc::EAGAIN => ProfileError::Busy,
                other => ProfileError::Platform(other),
            });
        }
        // The name still names the locked file: if it was unlinked and
        // recreated between the open and the lock, two holders could lock
        // different files.
        // SAFETY: stat is plain data; zeroed is a valid value.
        let mut named: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: relative to the held root; never follows a link.
        if unsafe {
            libc::fstatat(
                root.as_raw_fd(),
                lock_name.as_ptr(),
                &mut named,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
            || identity(&named) != identity(&lock_stat)
        {
            return Err(ProfileError::Swapped);
        }
        Ok(Self {
            identity: identity(&root_stat),
            root,
            _lock: lock,
        })
    }

    /// The path still names the held directory: same device and inode, and
    /// still not a link.
    pub(crate) fn verify(&self, path: &Path) -> Result<(), ProfileError> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ProfileError::Swapped)
            }
            Err(error) => return Err(ProfileError::Platform(error.raw_os_error().unwrap_or(0))),
        };
        use std::os::unix::fs::MetadataExt;
        if !metadata.file_type().is_dir() || (metadata.dev(), metadata.ino()) != self.identity {
            return Err(ProfileError::Swapped);
        }
        // The held directory is still this user's, mode 0700 (a later
        // chmod is caught here).
        if !owned_with_mode(&fstat(&self.root)?, 0o700) {
            return Err(ProfileError::Permissions);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn scratch(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "orcel-sg115-profile-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    /// A fresh profile directory with mode 0700 under a scratch root.
    fn profile(label: &str) -> (PathBuf, PathBuf) {
        let root = scratch(label);
        let dir = root.join("profile");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        (root, dir)
    }

    #[test]
    fn a_private_profile_is_held_and_a_second_hold_is_busy() {
        let (root, dir) = profile("held");
        let hold = ProfileHold::open(&dir).unwrap();
        hold.verify(&dir).unwrap();
        let lock = std::fs::symlink_metadata(dir.join(LOCK_NAME)).unwrap();
        assert!(lock.file_type().is_file());
        assert_eq!(lock.permissions().mode() & 0o7777, 0o600);
        assert_eq!(ProfileHold::open(&dir).unwrap_err(), ProfileError::Busy);
        drop(hold);
        // Dropping the hold releases the lock.
        let again = ProfileHold::open(&dir).unwrap();
        drop(again);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_profile_with_a_wider_mode_is_refused() {
        for mode in [0o755, 0o750, 0o701, 0o1700, 0o2700, 0o4700, 0o500] {
            let (root, dir) = profile("mode");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                ProfileHold::open(&dir).unwrap_err(),
                ProfileError::Permissions,
                "{mode:o}"
            );
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::remove_dir_all(&root).ok();
        }
    }

    #[test]
    fn a_link_or_a_file_at_the_profile_root_is_refused() {
        let (root, dir) = profile("link");
        let link = root.join("linked");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert_eq!(
            ProfileHold::open(&link).unwrap_err(),
            ProfileError::NotPlain
        );
        let file = root.join("file");
        std::fs::write(&file, "x").unwrap();
        assert_eq!(
            ProfileHold::open(&file).unwrap_err(),
            ProfileError::NotPlain
        );
        assert_eq!(
            ProfileHold::open(&root.join("absent")).unwrap_err(),
            ProfileError::Missing
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_unsafe_lock_file_is_refused() {
        // A link at the lock name, even to a harmless file.
        let (root, dir) = profile("lock-link");
        let target = root.join("target");
        std::fs::write(&target, "").unwrap();
        std::os::unix::fs::symlink(&target, dir.join(LOCK_NAME)).unwrap();
        assert_eq!(ProfileHold::open(&dir).unwrap_err(), ProfileError::NotPlain);
        std::fs::remove_dir_all(&root).ok();

        // A dangling link at the lock name.
        let (root, dir) = profile("lock-dangling");
        std::os::unix::fs::symlink(root.join("missing"), dir.join(LOCK_NAME)).unwrap();
        assert_eq!(ProfileHold::open(&dir).unwrap_err(), ProfileError::NotPlain);
        assert!(
            !root.join("missing").exists(),
            "the link was never followed"
        );
        std::fs::remove_dir_all(&root).ok();

        // A hard link to another file of this user at the lock name.
        let (root, dir) = profile("lock-hardlink");
        let key = root.join("key");
        std::fs::write(&key, "secret").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&key, dir.join(LOCK_NAME)).unwrap();
        assert_eq!(ProfileHold::open(&dir).unwrap_err(), ProfileError::NotPlain);
        assert_eq!(std::fs::read_to_string(&key).unwrap(), "secret");
        std::fs::remove_dir_all(&root).ok();

        // A directory at the lock name.
        let (root, dir) = profile("lock-dir");
        std::fs::create_dir(dir.join(LOCK_NAME)).unwrap();
        assert_eq!(ProfileHold::open(&dir).unwrap_err(), ProfileError::NotPlain);
        std::fs::remove_dir_all(&root).ok();

        // A pre-existing lock file with a wider mode.
        let (root, dir) = profile("lock-mode");
        std::fs::write(dir.join(LOCK_NAME), "").unwrap();
        std::fs::set_permissions(dir.join(LOCK_NAME), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert_eq!(
            ProfileHold::open(&dir).unwrap_err(),
            ProfileError::Permissions
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_later_chmod_is_caught_by_verify() {
        let (root, dir) = profile("chmod");
        let hold = ProfileHold::open(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(hold.verify(&dir).unwrap_err(), ProfileError::Permissions);
        drop(hold);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_profile_swapped_under_the_hold_is_detected() {
        let (root, dir) = profile("swap");
        let hold = ProfileHold::open(&dir).unwrap();
        std::fs::rename(&dir, root.join("moved")).unwrap();
        assert_eq!(hold.verify(&dir).unwrap_err(), ProfileError::Swapped);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(hold.verify(&dir).unwrap_err(), ProfileError::Swapped);
        std::fs::remove_dir(&dir).unwrap();
        std::os::unix::fs::symlink(root.join("moved"), &dir).unwrap();
        // A link back to the held directory is still refused.
        assert_eq!(hold.verify(&dir).unwrap_err(), ProfileError::Swapped);
        drop(hold);
        std::fs::remove_dir_all(&root).ok();
    }

    /// Pre-activation boundary: only lib.rs (the test-only declaration)
    /// names this module; production profile handling is unchanged.
    #[test]
    fn the_unix_profile_hold_is_unreachable_from_production() {
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for dir in ["src", "tests"] {
            let mut stack = vec![crate_dir.join(dir)];
            while let Some(next) = stack.pop() {
                for entry in std::fs::read_dir(&next).unwrap() {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if path.extension().is_some_and(|ext| ext == "rs") {
                        files.push(path);
                    }
                }
            }
        }
        assert!(files.len() > 10, "the scan found the crate's sources");
        let mut named = Vec::new();
        for path in &files {
            if *path == crate_dir.join("src").join("unix_profile.rs")
                || *path == crate_dir.join("src").join("lib.rs")
            {
                continue;
            }
            if std::fs::read_to_string(path)
                .unwrap_or_default()
                .contains("unix_profile")
            {
                named.push(path.display().to_string());
            }
        }
        assert!(named.is_empty(), "{named:?}");
        let lib = std::fs::read_to_string(crate_dir.join("src/lib.rs"))
            .unwrap()
            .replace("\r\n", "\n");
        let lines: Vec<&str> = lib.lines().collect();
        let code: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| {
                line.contains("unix_profile") && !line.trim_start().starts_with("//")
            })
            .map(|(index, _)| index)
            .collect();
        assert_eq!(code.len(), 1, "lib.rs declares the module once");
        assert_eq!(lines[code[0]], "mod unix_profile;");
        assert_eq!(lines[code[0] - 1], "#[cfg(all(test, unix))]");
    }
}
