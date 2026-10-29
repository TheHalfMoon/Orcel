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
//! - **Removal through the hold:** `sweep_held_profile` deletes a profile only
//!   through its hold. It first verifies the path still names the held
//!   directory, then deletes the contents relative to the held descriptor
//!   (`openat` with `O_NOFOLLOW | O_DIRECTORY`, then `unlinkat`). A
//!   symbolic link is removed as a link and never followed, so nothing
//!   outside the profile is touched. Depth and entry counts are bounded,
//!   and exceeding them fails closed, leaving the rest in place.
//! - **Lock last:** the lock file is removed last, while still held, so a
//!   concurrent opener that raced the unlink fails A3's name check. A live
//!   lock of another holder is never unlinked: `recover_stale_profile` only
//!   removes a profile whose lock it could take.
//! - **Crash recovery:** a holder that crashed released its `flock` with
//!   its process. `recover_stale_profile` treats a profile it can hold as stale
//!   and removes it, and leaves one another live holder has (`Busy`).
//!
//! Open for activation (not decided here):
//! - **Final directory removal:** the profile directory itself is removed
//!   by path (`rmdir`) after a fresh `verify`, which is a point-in-time
//!   check. A swap between the two leaves at most an empty directory
//!   removed or the call failing closed.
//! - **Engine coordination:** whether a sweep must also wait for the
//!   engine's processes to exit (A2) before deleting, and what to do with
//!   files the engine recreates mid-sweep.

use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::unix_profile::{ProfileError, ProfileHold, LOCK_NAME};

/// At most this many levels below the profile root are removed.
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
    /// A system call failed.
    Platform(i32),
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

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
    let mut budget = MAX_ENTRIES;
    clear_dir(hold.root_fd(), 0, &mut budget, Some(LOCK_NAME))?;
    // The lock last, while still held: a racing opener fails A3's name check.
    let lock = CString::new(LOCK_NAME).map_err(|_| CleanupError::Platform(0))?;
    // SAFETY: relative to the held root; removes the name, not a target.
    if unsafe { libc::unlinkat(hold.root_fd(), lock.as_ptr(), 0) } != 0 && errno() != libc::ENOENT {
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
/// use is left alone.
pub(crate) fn recover_stale_profile(path: &Path) -> Result<Recovery, CleanupError> {
    match ProfileHold::open(path) {
        Ok(hold) => sweep_held_profile(hold, path).map(|()| Recovery::Removed),
        Err(ProfileError::Busy) => Ok(Recovery::InUse),
        Err(ProfileError::Missing) => Ok(Recovery::Absent),
        Err(error) => Err(CleanupError::Profile(error)),
    }
}

/// Delete everything in the directory `dir` (a descriptor), never following
/// a link, bounded. `keep` names one top-level entry to leave.
fn clear_dir(
    dir: i32,
    depth: usize,
    budget: &mut usize,
    keep: Option<&str>,
) -> Result<(), CleanupError> {
    if depth > MAX_DEPTH {
        return Err(CleanupError::Bound);
    }
    for (name, is_dir) in list(dir)? {
        if keep.is_some_and(|keep| name.as_bytes() == keep.as_bytes()) {
            continue;
        }
        if *budget == 0 {
            return Err(CleanupError::Bound);
        }
        *budget -= 1;
        if is_dir {
            // SAFETY: relative to `dir`; a directory only, never a link.
            let raw = unsafe {
                libc::openat(
                    dir,
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err(CleanupError::Platform(errno()));
            }
            // SAFETY: `raw` is a descriptor this call just opened and owns.
            let child = unsafe { OwnedFd::from_raw_fd(raw) };
            clear_dir(child.as_raw_fd(), depth + 1, budget, None)?;
            drop(child);
            // SAFETY: relative to `dir`; removes the now empty directory.
            if unsafe { libc::unlinkat(dir, name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
                return Err(CleanupError::Platform(errno()));
            }
        } else {
            // A file, a link (removed as a link) or anything else.
            // SAFETY: relative to `dir`; never follows a link.
            if unsafe { libc::unlinkat(dir, name.as_ptr(), 0) } != 0 {
                return Err(CleanupError::Platform(errno()));
            }
        }
    }
    Ok(())
}

/// The entries of `dir` (not `.` or `..`): name, and whether it is a real
/// directory (`fstatat` with `AT_SYMLINK_NOFOLLOW`, so a link is not).
fn list(dir: i32) -> Result<Vec<(CString, bool)>, CleanupError> {
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
        // SAFETY: fdopendir failed, so `copy` is still ours to close.
        unsafe { libc::close(copy) };
        return Err(CleanupError::Platform(errno()));
    }
    // SAFETY: rewinds the stream to the start of the directory.
    unsafe { libc::rewinddir(stream) };
    let mut names = Vec::new();
    loop {
        // SAFETY: a valid stream; the entry stays valid until the next call.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: d_name is a NUL-terminated name inside the entry.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_owned();
        if name.as_bytes() == b"." || name.as_bytes() == b".." {
            continue;
        }
        if names.len() >= MAX_ENTRIES {
            // SAFETY: closes the stream and its descriptor once.
            unsafe { libc::closedir(stream) };
            return Err(CleanupError::Bound);
        }
        names.push(name);
    }
    // SAFETY: closes the stream and its descriptor once.
    unsafe { libc::closedir(stream) };
    let mut entries = Vec::with_capacity(names.len());
    for name in names {
        // SAFETY: stat is plain data; zeroed is a valid value.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: relative to `dir`; never follows a link.
        if unsafe { libc::fstatat(dir, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            if errno() == libc::ENOENT {
                continue;
            }
            return Err(CleanupError::Platform(errno()));
        }
        let is_dir = (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        entries.push((name, is_dir));
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

    #[test]
    fn a_profile_deeper_than_the_bound_fails_closed() {
        let (root, dir) = profile("deep");
        let mut deep = dir.clone();
        for level in 0..=MAX_DEPTH + 1 {
            deep = deep.join(format!("d{level}"));
        }
        std::fs::create_dir_all(&deep).unwrap();
        let hold = ProfileHold::open(&dir).unwrap();
        assert_eq!(sweep_held_profile(hold, &dir), Err(CleanupError::Bound));
        assert!(dir.exists(), "the rest is left in place");
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
        drop(ProfileHold::open(&dir).unwrap()); // creates the lock file
                                                // A fixture process holds the profile's lock, then is killed.
        let script = "import fcntl,os,sys,time\n\
                      fd = os.open(sys.argv[1], os.O_RDWR)\n\
                      fcntl.flock(fd, fcntl.LOCK_EX)\n\
                      print('locked', flush=True)\n\
                      time.sleep(60)\n";
        let mut holder = Command::new("python3")
            .arg("-c")
            .arg(script)
            .arg(dir.join(LOCK_NAME))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(holder.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "locked");
        // Live: left in place, untouched.
        assert_eq!(recover_stale_profile(&dir), Ok(Recovery::InUse));
        assert!(dir.join("Local State").exists());
        // Crashed: its lock died with it, so the profile is stale and removed.
        holder.kill().unwrap();
        holder.wait().unwrap();
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
            for needle in [
                "unix_cleanup",
                "sweep_held_profile",
                "recover_stale_profile",
            ] {
                if std::fs::read_to_string(path).unwrap().contains(needle) {
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
