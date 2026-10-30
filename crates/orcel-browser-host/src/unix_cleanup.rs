//! SG-000115 slice A5, inert pre-activation engineering (category A5 in
//! `docs/orcel/implementation-readiness/prep/SG-000115.md`): Unix shutdown,
//! cleanup and crash recovery for a held profile, and their regression
//! tests. This is the Unix counterpart of `leftovers.rs`.
//!
//! The module is compiled only into Unix test builds
//! (`#[cfg(all(test, unix))]` in `lib.rs`), so no release build contains
//! it. No production path calls it, and macOS/Linux launch stays refused.
//! Tests use scratch directories and fixture processes (`python3`) only;
//! they never start a browser.
//!
//! - **Removal through the hold:** `sweep_held_profile` deletes a profile
//!   only through its hold. It first verifies the path still names the held
//!   directory and the lock name still names the held lock, then deletes the
//!   contents relative to the held descriptor (`openat` with `O_NOFOLLOW |
//!   O_DIRECTORY`, then `unlinkat`).
//!   - A symbolic link is removed as a link and never followed, so nothing
//!     outside the profile is touched.
//!   - A subdirectory on another device (a mount point), or one that is not
//!     the entry that was listed, refuses: the sweep never crosses a mount.
//!   - Depth, entry counts and listing sizes are bounded. Exceeding them
//!     fails closed and leaves the rest in place.
//! - **Lock last:** the lock file is unlinked last, while still held, and
//!   only after the hold re-checks that the lock name still names the file
//!   it locked, so a lock swapped in by another holder is refused, not
//!   unlinked (see the open items for the remaining same-user window).
//! - **Crash recovery:** a holder that crashed released its `flock` with
//!   its process. `recover_stale_profile` treats a profile it can hold as
//!   stale and removes it, and leaves one that another live holder has
//!   (`Busy`).
//!
//! Open for activation (not decided here):
//! - **An orphaned engine:** recovery can't yet tell whether an engine
//!   process is still using the profile. The lock is `O_CLOEXEC`, so an
//!   engine never holds it; if the host crashes while Chrome or Edge keeps
//!   running, recovery would call the profile stale and delete it under the
//!   browser. Activation must first establish that no engine process uses
//!   the profile (the A2 process tree, or the engine's own `SingletonLock`).
//! - **Same-user window:** between `verify_lock` and the unlink, or while
//!   the contents are cleared, a process of the same user could rename the
//!   lock and let a second holder in; that holder's lock or files could then
//!   be removed. It needs a same-user adversary; activation must close it
//!   (for example a per-profile directory lock held for the whole sweep).
//! - **Final directory removal:** the profile directory itself is removed
//!   by path (`rmdir`) after a fresh `verify`, which is a point-in-time
//!   check. A swap between the two leaves at most an empty directory
//!   removed, or the call failing closed.
//! - **Engine coordination:** whether a sweep must also wait for the
//!   engine's processes to exit (A2) before deleting, and what to do with
//!   files the engine recreates mid-sweep.

use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::unix_profile::{ProfileError, ProfileHold, LOCK_NAME};

/// At most this many levels of nested directories below the profile root
/// are cleared (the files inside the deepest one are removed too).
pub(crate) const MAX_DEPTH: usize = 64;
/// At most this many entries are removed in one sweep.
pub(crate) const MAX_ENTRIES: usize = 100_000;

/// Why a sweep stopped; every case leaves the rest in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CleanupError {
    /// The profile could not be held or verified.
    Profile(ProfileError),
    /// Deeper than `MAX_DEPTH` or more than `MAX_ENTRIES`.
    Bound,
    /// A subdirectory on another device, or not the entry that was listed.
    Crossing,
    /// A system call failed.
    Platform(i32),
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    // SAFETY: the thread-local errno location is always valid.
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    // SAFETY: the thread-local errno location is always valid.
    unsafe { *libc::__error() = 0 };
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("the inert Unix cleanup supports Linux and macOS only");

/// What `recover_stale_profile` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Recovery {
    /// Nothing was at the path.
    Absent,
    /// A live holder has it: left in place.
    InUse,
    /// A stale profile (its holder gone): removed.
    Removed,
}

/// Remove a held profile and its contents, then the directory itself.
pub(crate) fn sweep_held_profile(hold: ProfileHold, path: &Path) -> Result<(), CleanupError> {
    hold.verify(path).map_err(CleanupError::Profile)?;
    hold.verify_lock().map_err(CleanupError::Profile)?;
    let root = fstat_raw(hold.root_fd())?;
    let mut budget = MAX_ENTRIES;
    clear_dir(
        hold.root_fd(),
        device_of(&root),
        0,
        &mut budget,
        Some(LOCK_NAME),
    )?;
    // The lock last, while still held, and only while its name still names
    // the file this hold locked: another holder's live lock is never
    // unlinked.
    hold.verify_lock().map_err(CleanupError::Profile)?;
    let lock = CString::new(LOCK_NAME).map_err(|_| CleanupError::Platform(0))?;
    // SAFETY: relative to the held root; removes the name, not a target.
    if unsafe { libc::unlinkat(hold.root_fd(), lock.as_ptr(), 0) } != 0 {
        return Err(CleanupError::Platform(errno()));
    }
    hold.verify(path).map_err(CleanupError::Profile)?;
    let c_path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| CleanupError::Platform(0))?;
    // SAFETY: a NUL-terminated path; rmdir removes only an empty directory.
    if unsafe { libc::rmdir(c_path.as_ptr()) } != 0 {
        return Err(CleanupError::Platform(errno()));
    }
    drop(hold);
    Ok(())
}

/// Recover after a crash: a profile no live holder has is removed; one in
/// use is left alone. It cannot yet tell whether an orphaned engine still
/// uses the profile (see the module's open items).
pub(crate) fn recover_stale_profile(path: &Path) -> Result<Recovery, CleanupError> {
    match ProfileHold::open(path) {
        Ok(hold) => sweep_held_profile(hold, path).map(|()| Recovery::Removed),
        Err(ProfileError::Busy) => Ok(Recovery::InUse),
        Err(ProfileError::Missing) => Ok(Recovery::Absent),
        Err(error) => Err(CleanupError::Profile(error)),
    }
}

/// `st_dev` is `u64` on Linux and `i32` on macOS.
#[allow(clippy::unnecessary_cast)]
fn fstat_raw(fd: i32) -> Result<libc::stat, CleanupError> {
    // SAFETY: stat is plain data; zeroed is a valid value.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is an open descriptor and `stat` a valid out-pointer.
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(CleanupError::Platform(errno()));
    }
    Ok(stat)
}

/// The device of a stat (`u64` on Linux, `i32` on macOS).
#[allow(clippy::unnecessary_cast)]
fn device_of(stat: &libc::stat) -> u64 {
    stat.st_dev as u64
}

/// One listed entry: its name, whether it is a real directory, and its
/// device and inode as listed.
struct Entry {
    name: CString,
    is_dir: bool,
    dev: u64,
    ino: u64,
}

/// Delete everything in the directory `dir` (a descriptor on device
/// `device`), never following a link and never crossing a mount, bounded.
/// `keep` names one top-level entry to leave.
#[allow(clippy::unnecessary_cast)]
fn clear_dir(
    dir: i32,
    device: u64,
    depth: usize,
    budget: &mut usize,
    keep: Option<&str>,
) -> Result<(), CleanupError> {
    if depth > MAX_DEPTH {
        return Err(CleanupError::Bound);
    }
    // The budget is charged when a level is listed, so the listings held
    // at once across all levels never exceed MAX_ENTRIES names in total.
    let cap = budget.saturating_add(1 + usize::from(keep.is_some()));
    let entries: Vec<Entry> = list(dir, cap)?
        .into_iter()
        .filter(|entry| !keep.is_some_and(|keep| entry.name.as_bytes() == keep.as_bytes()))
        .collect();
    if entries.len() > *budget {
        return Err(CleanupError::Bound);
    }
    *budget -= entries.len();
    for entry in entries {
        if entry.is_dir {
            if entry.dev != device {
                return Err(CleanupError::Crossing);
            }
            // SAFETY: relative to `dir`; a directory only, never a link.
            let raw = unsafe {
                libc::openat(
                    dir,
                    entry.name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err(CleanupError::Platform(errno()));
            }
            // SAFETY: `raw` is a descriptor this call just opened and owns.
            let child = unsafe { OwnedFd::from_raw_fd(raw) };
            // The opened directory is the listed one, on the same device.
            let opened = fstat_raw(child.as_raw_fd())?;
            if opened.st_dev as u64 != device || opened.st_ino as u64 != entry.ino {
                return Err(CleanupError::Crossing);
            }
            clear_dir(child.as_raw_fd(), device, depth + 1, budget, None)?;
            drop(child);
            // SAFETY: relative to `dir`; removes the now empty directory.
            if unsafe { libc::unlinkat(dir, entry.name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
                return Err(CleanupError::Platform(errno()));
            }
        } else {
            // A file, a link (removed as a link) or anything else.
            // SAFETY: relative to `dir`; never follows a link.
            if unsafe { libc::unlinkat(dir, entry.name.as_ptr(), 0) } != 0 {
                return Err(CleanupError::Platform(errno()));
            }
        }
    }
    Ok(())
}

/// The entries of `dir` (not `.` or `..`), at most `cap` of them, each with
/// `fstatat(AT_SYMLINK_NOFOLLOW)`, so a link is never a directory.
#[allow(clippy::unnecessary_cast)]
fn list(dir: i32, cap: usize) -> Result<Vec<Entry>, CleanupError> {
    // A second descriptor for reading: fdopendir takes ownership of it.
    // SAFETY: duplicates an open descriptor.
    let copy = unsafe { libc::fcntl(dir, libc::F_DUPFD_CLOEXEC, 0) };
    if copy < 0 {
        return Err(CleanupError::Platform(errno()));
    }
    // SAFETY: `copy` is an open directory descriptor; on success the stream
    // owns it and closedir closes it.
    let stream = unsafe { libc::fdopendir(copy) };
    if stream.is_null() {
        // Read errno before close can overwrite it.
        let error = errno();
        // SAFETY: fdopendir failed, so `copy` is still ours to close.
        unsafe { libc::close(copy) };
        return Err(CleanupError::Platform(error));
    }
    // SAFETY: rewinds the stream to the start of the directory.
    unsafe { libc::rewinddir(stream) };
    let mut names = Vec::new();
    let outcome = loop {
        clear_errno();
        // SAFETY: a valid stream; the entry stays valid until the next call.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            // NULL is the end only when errno is still zero.
            let error = errno();
            break if error == 0 {
                Ok(())
            } else {
                Err(CleanupError::Platform(error))
            };
        }
        // SAFETY: d_name is a NUL-terminated name inside the entry; the
        // pointer is taken without a reference to the whole array, which
        // may run past the entry's record.
        let name =
            unsafe { CStr::from_ptr(std::ptr::addr_of!((*entry).d_name).cast::<libc::c_char>()) }
                .to_owned();
        if name.as_bytes() == b"." || name.as_bytes() == b".." {
            continue;
        }
        if names.len() >= cap {
            break Err(CleanupError::Bound);
        }
        names.push(name);
    };
    // SAFETY: closes the stream and its descriptor once.
    unsafe { libc::closedir(stream) };
    outcome?;
    let mut entries = Vec::with_capacity(names.len());
    for name in names {
        // SAFETY: stat is plain data; zeroed is a valid value.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: relative to `dir`; never follows a link.
        if unsafe { libc::fstatat(dir, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            let error = errno();
            if error == libc::ENOENT {
                continue;
            }
            return Err(CleanupError::Platform(error));
        }
        entries.push(Entry {
            name,
            is_dir: (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR,
            dev: stat.st_dev as u64,
            ino: stat.st_ino as u64,
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    fn scratch(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "orcel-sg115-cleanup-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn profile(label: &str) -> (PathBuf, PathBuf) {
        let root = scratch(label);
        let dir = root.join("profile");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        (root, dir)
    }

    fn populate(dir: &Path) {
        std::fs::create_dir_all(dir.join("Default/Cache/deep/er")).unwrap();
        std::fs::write(dir.join("Default/Preferences"), "{}").unwrap();
        std::fs::write(dir.join("Default/Cache/deep/er/blob"), "x").unwrap();
        std::fs::write(dir.join("Local State"), "{}").unwrap();
    }

    #[test]
    fn a_held_profile_is_removed_entirely() {
        let (root, dir) = profile("remove");
        populate(&dir);
        let hold = ProfileHold::open(&dir).unwrap();
        sweep_held_profile(hold, &dir).unwrap();
        assert!(!dir.exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn links_inside_the_profile_are_removed_never_followed() {
        let (root, dir) = profile("links");
        let outside = root.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("keep"), "precious").unwrap();
        std::fs::create_dir(dir.join("Default")).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("Default/linked-dir")).unwrap();
        std::os::unix::fs::symlink(outside.join("keep"), dir.join("linked-file")).unwrap();
        std::os::unix::fs::symlink(root.join("missing"), dir.join("dangling")).unwrap();
        let hold = ProfileHold::open(&dir).unwrap();
        sweep_held_profile(hold, &dir).unwrap();
        assert!(!dir.exists());
        assert_eq!(
            std::fs::read_to_string(outside.join("keep")).unwrap(),
            "precious"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    fn chain(dir: &Path, levels: usize) -> PathBuf {
        let mut deep = dir.to_path_buf();
        for level in 0..levels {
            deep = deep.join(format!("d{level}"));
        }
        std::fs::create_dir_all(&deep).unwrap();
        deep
    }

    #[test]
    fn a_profile_at_the_depth_bound_is_removed() {
        let (root, dir) = profile("depth-ok");
        // MAX_DEPTH nested directories: the deepest is cleared by the call at
        // depth MAX_DEPTH, the last one allowed.
        chain(&dir, MAX_DEPTH);
        let hold = ProfileHold::open(&dir).unwrap();
        sweep_held_profile(hold, &dir).unwrap();
        assert!(!dir.exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_profile_deeper_than_the_bound_fails_closed() {
        let (root, dir) = profile("deep");
        // One level more than the bound.
        let deepest = chain(&dir, MAX_DEPTH + 1);
        let hold = ProfileHold::open(&dir).unwrap();
        assert_eq!(sweep_held_profile(hold, &dir), Err(CleanupError::Bound));
        assert!(
            dir.join("d0").exists() && deepest.exists(),
            "the chain is left in place"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn the_entry_budget_fails_closed() {
        let (root, dir) = profile("budget");
        for index in 0..5 {
            std::fs::write(dir.join(format!("f{index}")), "x").unwrap();
        }
        let hold = ProfileHold::open(&dir).unwrap();
        let device = device_of(&fstat_raw(hold.root_fd()).unwrap());
        // One entry over the budget: refused before anything is removed.
        let mut budget = 4;
        assert_eq!(
            clear_dir(hold.root_fd(), device, 0, &mut budget, Some(LOCK_NAME)),
            Err(CleanupError::Bound)
        );
        assert!(dir.join("f0").exists() && dir.join("f4").exists());
        // Exactly the budget: everything but the lock is removed.
        let mut budget = 5;
        clear_dir(hold.root_fd(), device, 0, &mut budget, Some(LOCK_NAME)).unwrap();
        assert_eq!(budget, 0);
        assert!(!dir.join("f0").exists() && dir.join(LOCK_NAME).exists());
        drop(hold);
        std::fs::remove_dir_all(&root).ok();
    }

    /// A renamed lock and a second holder: the sweep refuses, and the
    /// second holder's live lock and files survive.
    #[test]
    fn another_holders_live_lock_is_never_unlinked() {
        let (root, dir) = profile("lock-swap");
        populate(&dir);
        let first = ProfileHold::open(&dir).unwrap();
        std::fs::rename(dir.join(LOCK_NAME), dir.join("moved.lock")).unwrap();
        let second = ProfileHold::open(&dir).unwrap();
        assert_eq!(
            sweep_held_profile(first, &dir),
            Err(CleanupError::Profile(ProfileError::Swapped))
        );
        assert!(
            dir.join(LOCK_NAME).exists(),
            "the second holder's lock survives"
        );
        assert!(dir.join("Local State").exists(), "nothing was deleted");
        drop(second);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_swapped_profile_is_not_removed() {
        let (root, dir) = profile("swap");
        populate(&dir);
        let hold = ProfileHold::open(&dir).unwrap();
        std::fs::rename(&dir, root.join("moved")).unwrap();
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("other"), "not ours").unwrap();
        assert_eq!(
            sweep_held_profile(hold, &dir),
            Err(CleanupError::Profile(ProfileError::Swapped))
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("other")).unwrap(),
            "not ours"
        );
        assert!(root.join("moved/Local State").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn recovery_leaves_a_live_profile_and_removes_a_crashed_one() {
        let (root, dir) = profile("crash");
        populate(&dir);
        // Creates the lock file.
        drop(ProfileHold::open(&dir).unwrap());
        // A fixture process holds the profile's lock, then is killed.
        let script = "import fcntl,os,sys,time\n\
                      fd = os.open(sys.argv[1], os.O_RDWR)\n\
                      fcntl.flock(fd, fcntl.LOCK_EX)\n\
                      print('locked', flush=True)\n\
                      time.sleep(60)\n";
        /// Kills the fixture holder even when the test fails first.
        struct Holder(std::process::Child);
        impl Drop for Holder {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut holder = Holder(
            Command::new("python3")
                .arg("-c")
                .arg(script)
                .arg(dir.join(LOCK_NAME))
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut line = String::new();
        BufReader::new(holder.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "locked");
        // Live: left in place, untouched.
        assert_eq!(recover_stale_profile(&dir), Ok(Recovery::InUse));
        assert!(dir.join("Local State").exists());
        // Crashed: its lock died with it, so the profile is stale and removed.
        holder.0.kill().unwrap();
        holder.0.wait().unwrap();
        assert_eq!(recover_stale_profile(&dir), Ok(Recovery::Removed));
        assert!(!dir.exists());
        assert_eq!(recover_stale_profile(&dir), Ok(Recovery::Absent));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn recovery_refuses_an_unsafe_profile() {
        let (root, dir) = profile("unsafe");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            recover_stale_profile(&dir),
            Err(CleanupError::Profile(ProfileError::Permissions))
        );
        assert!(dir.exists());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&root).ok();
    }

    /// Pre-activation boundary: only lib.rs (the test-only declaration)
    /// names this module.
    #[test]
    fn the_unix_cleanup_is_unreachable_from_production() {
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
            if *path == crate_dir.join("src").join("unix_cleanup.rs")
                || *path == crate_dir.join("src").join("lib.rs")
            {
                continue;
            }
            // The module's name may appear in its test-only sibling, whose
            // own scan pins the declaration, and in the SG-000085 governance
            // allowlist; its functions may appear nowhere else.
            let names_module = *path == crate_dir.join("src").join("unix_profile.rs")
                || *path == crate_dir.join("tests").join("sg000085_qualification.rs");
            let source = std::fs::read_to_string(path).unwrap();
            for needle in [
                "unix_cleanup",
                "sweep_held_profile",
                "recover_stale_profile",
            ] {
                if names_module && needle == "unix_cleanup" {
                    continue;
                }
                if source.contains(needle) {
                    named.push(format!("{}: {needle}", path.display()));
                }
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
                line.contains("unix_cleanup") && !line.trim_start().starts_with("//")
            })
            .map(|(index, _)| index)
            .collect();
        assert_eq!(code.len(), 1, "lib.rs declares the module once");
        assert_eq!(lines[code[0]], "mod unix_cleanup;");
        assert_eq!(lines[code[0] - 1], "#[cfg(all(test, unix))]");
    }
}
