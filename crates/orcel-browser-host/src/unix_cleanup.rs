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
//! - **An orphaned engine (A3b, partly closed):** the Orcel lock is
//!   `O_CLOEXEC`, so an engine never holds it. Recovery now keeps the
//!   profile (`EngineMayBeAlive`) when the engine's own `SingletonLock`
//!   names a live pid on this host, another host, or cannot be read, and
//!   when any readable process carries `--user-data-dir=<profile>` (Linux:
//!   `/proc/<pid>/cmdline`; macOS since B2: this user's processes through
//!   `sysctl KERN_PROCARGS2`). Still open: another user's process, whose
//!   arguments macOS (and Linux under `hidepid`) hides.
//! - **Same-user window:** between `verify_lock` and the unlink, or while
//!   the contents are cleared, a process of the same user could rename the
//!   lock and let a second holder in; that holder's lock or files could then
//!   be removed. It needs a same-user adversary; activation must close it
//!   (for example a per-profile directory lock held for the whole sweep).
//! - **Final directory removal:** for a hold from `open_beneath` (B5,
//!   `recover_stale_profile_beneath`), the profile directory is removed
//!   with `unlinkat(AT_REMOVEDIR)` relative to its held, private parent,
//!   after checking that the name there still names the held directory; a
//!   swapped ancestor is never re-resolved. A hold from the path-based
//!   `open` (still used by `recover_stale_profile` and A6) removes it by
//!   path (`rmdir`) after a fresh `verify`, a point-in-time check: a swap
//!   between the two leaves at most an empty directory removed, or the call
//!   failing closed.
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
    /// No Orcel holder, but an engine may still be using it: left in place.
    EngineMayBeAlive,
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
    // B5: held-parent unlinkat for an open_beneath hold, never a path
    // reconstructed through potentially swapped ancestor components.
    hold.remove_directory(path).map_err(|error| match error {
        ProfileError::Platform(code) => CleanupError::Platform(code),
        other => CleanupError::Profile(other),
    })?;
    drop(hold);
    Ok(())
}

/// Recover after a crash: a profile no live holder has is removed, unless
/// an engine may still be using it (A3b, `engine_may_be_alive`); one in use
/// is left alone.
pub(crate) fn recover_stale_profile(path: &Path) -> Result<Recovery, CleanupError> {
    match ProfileHold::open(path) {
        Ok(hold) if engine_may_be_alive(&hold, path) => Ok(Recovery::EngineMayBeAlive),
        Ok(hold) => sweep_held_profile(hold, path).map(|()| Recovery::Removed),
        Err(ProfileError::Busy) => Ok(Recovery::InUse),
        Err(ProfileError::Missing) => Ok(Recovery::Absent),
        Err(error) => Err(CleanupError::Profile(error)),
    }
}

/// B5 inert anchored recovery: the trusted state root and EVERY
/// component of a relative profile path must be held with O_NOFOLLOW,
/// and the final directory is removed through its held parent descriptor.
/// Untrusted absolute, dot, or parent components refuse before deletion.
/// No production path calls this while SG-000115 is unactivated.
pub(crate) fn recover_stale_profile_beneath(
    state_root: &Path,
    relative: &Path,
) -> Result<Recovery, CleanupError> {
    let path = state_root.join(relative);
    match ProfileHold::open_beneath(state_root, relative) {
        Ok(hold) if engine_may_be_alive(&hold, &path) => Ok(Recovery::EngineMayBeAlive),
        Ok(hold) => sweep_held_profile(hold, &path).map(|()| Recovery::Removed),
        Err(ProfileError::Busy) => Ok(Recovery::InUse),
        Err(ProfileError::Missing) => Ok(Recovery::Absent),
        Err(error) => Err(CleanupError::Profile(error)),
    }
}

/// The engine's own profile lock: a link named `SingletonLock` whose
/// target is `<hostname>-<pid>` (Chromium's `ProcessSingleton`).
pub(crate) const SINGLETON_LOCK: &str = "SingletonLock";

/// A3b: whether an engine may still be using the profile after its host
/// crashed (the Orcel lock is `O_CLOEXEC`, so an engine never holds it).
/// True, and the profile kept, when any of these holds:
/// - `SingletonLock` exists but is not a link, or its target cannot be
///   read or parsed;
/// - it names another host (its pid cannot be checked here);
/// - it names this host and a pid that is alive (`kill(pid, 0)` succeeds,
///   or fails with `EPERM`: another user's process is alive too);
/// - on Linux, any readable process's command line carries this profile as
///   `--user-data-dir=<path>`.
///
/// A dead pid on this host, and no such process, lets recovery remove the
/// profile. A reused pid can only keep a profile (fail safe).
pub(crate) fn engine_may_be_alive(hold: &ProfileHold, path: &Path) -> bool {
    singleton_lock_alive(hold) || named_by_a_running_engine(path)
}

fn singleton_lock_alive(hold: &ProfileHold) -> bool {
    let Ok(name) = CString::new(SINGLETON_LOCK) else {
        return true;
    };
    let mut buffer = [0u8; 512];
    // SAFETY: relative to the held root; reads at most `buffer.len()` bytes.
    let read = unsafe {
        libc::readlinkat(
            hold.root_fd(),
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    if read < 0 {
        // No lock at all: nothing names a live engine here.
        return errno() != libc::ENOENT;
    }
    let read = read as usize;
    if read >= buffer.len() {
        return true;
    }
    let Ok(target) = std::str::from_utf8(&buffer[..read]) else {
        return true;
    };
    let Some((host, pid)) = target.rsplit_once('-') else {
        return true;
    };
    let Ok(pid) = pid.parse::<libc::pid_t>() else {
        return true;
    };
    if pid <= 0 || this_host().as_deref() != Some(host) {
        return true;
    }
    // SAFETY: signal 0 only checks that the process exists.
    unsafe { libc::kill(pid, 0) == 0 || errno() == libc::EPERM }
}

fn this_host() -> Option<String> {
    let mut buffer = [0u8; 256];
    // SAFETY: gethostname writes at most `buffer.len()` bytes.
    if unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } != 0 {
        return None;
    }
    let end = buffer.iter().position(|byte| *byte == 0)?;
    String::from_utf8(buffer[..end].to_vec()).ok()
}

/// The `--user-data-dir=` arguments that name this profile: the path as
/// given and as resolved, so a trailing slash or a linked spelling still
/// names the same profile.
fn wanted_arguments(path: &Path) -> Vec<Vec<u8>> {
    let mut spellings = vec![path.as_os_str().as_bytes().to_vec()];
    if let Ok(real) = path.canonicalize() {
        spellings.push(real.as_os_str().as_bytes().to_vec());
    }
    spellings
        .into_iter()
        .map(|spelling| [b"--user-data-dir=".as_slice(), spelling.as_slice()].concat())
        .collect()
}

/// Linux: a readable process whose command line names this profile as
/// `--user-data-dir=<path>`.
#[cfg(target_os = "linux")]
fn named_by_a_running_engine(path: &Path) -> bool {
    let wanted = wanted_arguments(path);
    let Ok(entries) = std::fs::read_dir("/proc") else {
        // The process table cannot be read: assume an engine may be alive.
        return true;
    };
    entries.flatten().any(|entry| {
        let name = entry.file_name();
        if name.to_str().is_none_or(|n| n.parse::<u32>().is_err()) {
            return false;
        }
        match std::fs::read(entry.path().join("cmdline")) {
            Ok(cmdline) => cmdline_names(&cmdline, &wanted),
            // Exited between the listing and the read: not alive.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            // Unreadable (for example `hidepid=`): it may be an engine.
            Err(_) => true,
        }
    })
}

/// Whether a `/proc/<pid>/cmdline` names one of `wanted` as an argument.
/// Arguments are NUL-separated, and a whole argument counts; Chromium on
/// Linux rewrites its process title (`setproctitle`) into one space-joined
/// string, so a space-separated token counts too.
fn cmdline_names(cmdline: &[u8], wanted: &[Vec<u8>]) -> bool {
    let named = |token: &[u8]| wanted.iter().any(|w| token == w.as_slice());
    // A whole argument (B2: a profile path with a space matches here), or
    // a space-separated token of a rewritten title.
    cmdline.split(|byte| *byte == 0).any(named)
        || cmdline
            .split(|byte| *byte == 0)
            .flat_map(|arg| arg.split(|byte| *byte == b' '))
            .any(named)
}

/// At most this many of this user's processes are listed on macOS; more
/// keeps the profile.
#[cfg(target_os = "macos")]
const MAX_PIDS: usize = 65_536;
/// Room for one process's `KERN_PROCARGS2` (macOS `ARG_MAX`, 1 MiB).
#[cfg(target_os = "macos")]
const PROCARGS_MAX: usize = 1 << 20;

/// macOS (B2, B3): a process of this user whose arguments, read with
/// `sysctl KERN_PROCARGS2`, name this profile as `--user-data-dir=<path>`.
///
/// B3: this user's processes are the ones the kernel lists for this
/// effective uid (`sysctl KERN_PROC_UID`, which an unprivileged process is
/// served, as `ps` is). A process outside that list is another user's by the
/// kernel's own report, never inferred from a refusal. A list that cannot be
/// read, or does not check out, keeps the profile; so does a process of this
/// user whose arguments cannot be read or parsed. A process that has exited,
/// or a zombie, does not. Another user's arguments (root's included) cannot
/// be read without privilege, so such an engine is not seen (open item, B4).
#[cfg(target_os = "macos")]
fn named_by_a_running_engine(path: &Path) -> bool {
    let wanted = wanted_arguments(path);
    let Some(mine) = my_processes() else {
        return true;
    };
    let mut buffer = vec![0u8; PROCARGS_MAX];
    mine.iter()
        .filter(|(pid, stat)| *pid > 0 && *stat != SZOMB)
        .any(|(pid, _)| match procargs(*pid, &mut buffer) {
            Ok(Some(raw)) => match argv_of(raw) {
                Some(argv) => cmdline_names(argv, &wanted),
                None => true,
            },
            Ok(None) => false,
            Err(_) => true,
        })
}

/// `SZOMB` in `<sys/proc.h>`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const SZOMB: u8 = 5;
/// Offsets in `struct kinfo_proc` (it starts with `struct extern_proc`) on
/// 64-bit macOS: `p_stat` (a `char`) and `p_pid` (an `int`). The layout is
/// checked at run time: the list must name this process as running.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const KP_STAT: usize = 36;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const KP_PID: usize = 40;
/// `sizeof(struct kinfo_proc)` on 64-bit macOS.
#[cfg(target_os = "macos")]
const KINFO_PROC_SIZE: usize = 648;

/// The (pid, `p_stat`) of each `kinfo_proc` record in `raw`, each `entry`
/// bytes long; `None` unless the records divide `raw` exactly, fit the
/// bound, and include `me` as a process that is not a zombie (the layout
/// check).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn kinfo_records(raw: &[u8], entry: usize, me: i32, bound: usize) -> Option<Vec<(i32, u8)>> {
    if entry < KP_PID + 4 || raw.is_empty() || raw.len() % entry != 0 || raw.len() / entry > bound {
        return None;
    }
    let records: Vec<(i32, u8)> = raw
        .chunks_exact(entry)
        .map(|record| {
            let pid = i32::from_ne_bytes(record[KP_PID..KP_PID + 4].try_into().unwrap());
            (pid, record[KP_STAT])
        })
        .collect();
    records
        .iter()
        .any(|(pid, stat)| *pid == me && *stat != SZOMB)
        .then_some(records)
}

/// A `sysctl` read of `mib` into `buffer` (`None` for a size query); the
/// byte count, or the errno.
#[cfg(target_os = "macos")]
fn sysctl_read(mib: &mut [libc::c_int], buffer: Option<&mut [u8]>) -> Result<usize, i32> {
    let (pointer, mut size) = match buffer {
        Some(buffer) => (buffer.as_mut_ptr().cast(), buffer.len()),
        None => (std::ptr::null_mut(), 0),
    };
    // SAFETY: `mib` holds `mib.len()` names; the buffer, when given, holds
    // `size` bytes; nothing is written to the kernel.
    let status = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            pointer,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return Err(errno());
    }
    Ok(size)
}

/// B3: the size of one `kinfo_proc` record, from a real read of this
/// process's own record (a size query alone reports spare room, so it is
/// not used); the record must carry this process's pid at `KP_PID`.
#[cfg(target_os = "macos")]
fn record_size(me: i32) -> Option<usize> {
    let mut buffer = vec![0u8; 4096];
    let size = sysctl_read(
        &mut [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, me],
        Some(&mut buffer),
    )
    .ok()?;
    // Exactly one record of the known size (`libc` has no Apple
    // `kinfo_proc`, so the size is pinned here): any other layout keeps
    // the profile.
    if size != KINFO_PROC_SIZE {
        return None;
    }
    let pid = i32::from_ne_bytes(buffer[KP_PID..KP_PID + 4].try_into().ok()?);
    (pid == me).then_some(size)
}

/// B3: this user's processes as the kernel lists them for this effective
/// uid (`KERN_PROC_UID`), with their `p_stat`. `None` when the list cannot
/// be read or does not check out.
#[cfg(target_os = "macos")]
fn my_processes() -> Option<Vec<(i32, u8)>> {
    // SAFETY: no arguments; cannot fail.
    let me = unsafe { libc::getpid() };
    let entry = record_size(me)?;
    // SAFETY: no arguments; cannot fail.
    let uid = unsafe { libc::geteuid() } as libc::c_int;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_UID, uid];
    // The list can grow between the size query and the read: retry.
    for _ in 0..4 {
        let needed = sysctl_read(&mut mib, None).ok()?;
        let room = needed + needed / 4 + entry * 16;
        if room > entry * MAX_PIDS {
            return None;
        }
        let mut buffer = vec![0u8; room];
        match sysctl_read(&mut mib, Some(&mut buffer)) {
            Ok(size) => return kinfo_records(&buffer[..size], entry, me, MAX_PIDS),
            Err(libc::ENOMEM) => continue,
            Err(_) => return None,
        }
    }
    None
}

/// The raw `KERN_PROCARGS2` of `pid`; `Ok(None)` when it has exited.
#[cfg(target_os = "macos")]
fn procargs(pid: i32, buffer: &mut [u8]) -> Result<Option<&[u8]>, i32> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size = buffer.len();
    // SAFETY: a three-element name and a buffer of `size` bytes; nothing is
    // written to the kernel.
    let status = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buffer.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return match errno() {
            libc::ESRCH => Ok(None),
            other => Err(other),
        };
    }
    Ok(Some(&buffer[..size.min(buffer.len())]))
}

/// The argument strings of a `KERN_PROCARGS2` buffer, NUL-separated: it
/// holds `argc` (a native-endian `i32`), the executable path, NUL padding,
/// then `argc` NUL-terminated arguments (then the environment, ignored).
/// `None` when the layout does not hold. An empty first argument would be
/// read as padding, shifting one environment string into the arguments;
/// that can only add a match (keep), never hide one.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn argv_of(raw: &[u8]) -> Option<&[u8]> {
    let (count, rest) = raw.split_first_chunk::<4>()?;
    let argc = usize::try_from(i32::from_ne_bytes(*count)).ok()?;
    let path_end = rest.iter().position(|byte| *byte == 0)?;
    let start = path_end + rest[path_end..].iter().position(|byte| *byte != 0)?;
    let mut end = start;
    for _ in 0..argc {
        end += rest[end..].iter().position(|byte| *byte == 0)? + 1;
    }
    Some(&rest[start..end])
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

    // B5: anchored recovery beneath a held state root.
    fn nested_profile(label: &str) -> (PathBuf, PathBuf) {
        let root = scratch(label);
        let middle = root.join("middle");
        std::fs::create_dir(&middle).unwrap();
        let profile = middle.join("profile");
        std::fs::create_dir(&profile).unwrap();
        std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o700)).unwrap();
        (root, profile)
    }

    #[test]
    fn b5_recovery_beneath_a_held_state_root_removes_only_stale_profile() {
        let (root, profile) = nested_profile("b5-stale");
        populate(&profile);
        assert_eq!(
            recover_stale_profile_beneath(&root, Path::new("middle/profile")),
            Ok(Recovery::Removed)
        );
        assert!(!profile.exists());
        assert!(root.join("middle").is_dir());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn b5_recovery_refuses_parent_symlink_without_following_foreign_data() {
        let (root, profile) = nested_profile("b5-ancestor-link");
        populate(&profile);
        let moved = root.join("moved");
        std::fs::rename(root.join("middle"), &moved).unwrap();
        std::os::unix::fs::symlink(&moved, root.join("middle")).unwrap();
        assert_eq!(
            recover_stale_profile_beneath(&root, Path::new("middle/profile")),
            Err(CleanupError::Profile(ProfileError::NotPlain))
        );
        assert!(moved.join("profile/Local State").is_file());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn b5_recovery_refuses_dot_parent_or_absolute_relative_paths() {
        let (root, profile) = nested_profile("b5-components");
        populate(&profile);
        for value in [
            "../profile",
            "middle/../middle/profile",
            "./middle/profile",
            "/middle/profile",
            "",
        ] {
            assert_eq!(
                recover_stale_profile_beneath(&root, Path::new(value)),
                Err(CleanupError::Profile(ProfileError::NotPlain)),
                "{value:?}"
            );
        }
        assert!(profile.join("Local State").is_file());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn b5_anchored_sweep_refuses_swapped_intermediate_parent() {
        let (root, profile) = nested_profile("b5-parent-swap");
        populate(&profile);
        let hold = ProfileHold::open_beneath(&root, Path::new("middle/profile")).unwrap();
        let original = root.join("original-middle");
        std::fs::rename(root.join("middle"), &original).unwrap();
        let attacker = root.join("attacker");
        std::fs::create_dir(&attacker).unwrap();
        let attacker_profile = attacker.join("profile");
        std::fs::create_dir(&attacker_profile).unwrap();
        std::fs::set_permissions(&attacker_profile, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        std::fs::write(attacker_profile.join("keep"), "untouched").unwrap();
        std::os::unix::fs::symlink(&attacker, root.join("middle")).unwrap();
        assert_eq!(
            sweep_held_profile(hold, &profile),
            Err(CleanupError::Profile(ProfileError::Swapped))
        );
        assert_eq!(
            std::fs::read_to_string(attacker_profile.join("keep")).unwrap(),
            "untouched"
        );
        assert!(original.join("profile/Local State").exists());
        std::fs::remove_dir_all(&root).ok();
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

    fn singleton(dir: &Path, target: &str) {
        std::os::unix::fs::symlink(target, dir.join(SINGLETON_LOCK)).unwrap();
    }

    /// A3b: after a host crash, an engine that still runs keeps its profile.
    #[test]
    fn recovery_keeps_a_profile_whose_engine_still_runs() {
        let host = this_host().expect("a host name");
        let mut sleeper = Command::new("python3")
            .arg("-c")
            .arg("import time; time.sleep(30)")
            .spawn()
            .unwrap();
        let live = sleeper.id();
        let cases = [
            (format!("{host}-{live}"), Recovery::EngineMayBeAlive),
            (format!("another-host-{live}"), Recovery::EngineMayBeAlive),
            ("not a lock target".to_string(), Recovery::EngineMayBeAlive),
        ];
        for (index, (target, expected)) in cases.iter().enumerate() {
            let (root, dir) = profile(&format!("singleton-{index}"));
            populate(&dir);
            singleton(&dir, target);
            assert_eq!(
                recover_stale_profile(&dir).as_ref(),
                Ok(expected),
                "{target}"
            );
            assert!(dir.join("Local State").exists(), "{target}: kept");
            std::fs::remove_dir_all(&root).ok();
        }
        // A SingletonLock that is a regular file is not understood: kept.
        let (root, dir) = profile("singleton-file");
        populate(&dir);
        std::fs::write(dir.join(SINGLETON_LOCK), "x").unwrap();
        assert_eq!(recover_stale_profile(&dir), Ok(Recovery::EngineMayBeAlive));
        std::fs::remove_dir_all(&root).ok();
        let _ = sleeper.kill();
        let _ = sleeper.wait();
    }

    /// A3b: the engine's lock names a pid that has exited: the profile is
    /// stale and removed.
    #[test]
    fn recovery_removes_a_profile_whose_engine_is_gone() {
        let host = this_host().expect("a host name");
        let mut gone = Command::new("python3")
            .arg("-c")
            .arg("pass")
            .spawn()
            .unwrap();
        let pid = gone.id();
        gone.wait().unwrap();
        let (root, dir) = profile("singleton-dead");
        populate(&dir);
        singleton(&dir, &format!("{host}-{pid}"));
        assert_eq!(recover_stale_profile(&dir), Ok(Recovery::Removed));
        assert!(!dir.exists());
        std::fs::remove_dir_all(&root).ok();
    }

    /// A3b (Linux) and B2 (macOS): an engine started with this profile,
    /// before it wrote any lock, still keeps it.
    #[test]
    fn recovery_keeps_a_profile_named_by_a_running_process() {
        let (root, dir) = profile("cmdline");
        populate(&dir);
        let mut engine = Command::new("python3")
            .arg("-c")
            .arg("import time; time.sleep(30)")
            .arg(format!("--user-data-dir={}", dir.display()))
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        while !named_by_a_running_engine(&dir)
            && started.elapsed() < std::time::Duration::from_secs(10)
        {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(recover_stale_profile(&dir), Ok(Recovery::EngineMayBeAlive));
        assert!(dir.join("Local State").exists());
        let _ = engine.kill();
        let _ = engine.wait();
        assert_eq!(recover_stale_profile(&dir), Ok(Recovery::Removed));
        std::fs::remove_dir_all(&root).ok();
    }

    /// B3's premise, on the host that runs it: the kernel serves an
    /// unprivileged process the list of its user's processes, and that list
    /// names this process and a child of it, and not launchd (root's).
    #[cfg(target_os = "macos")]
    #[test]
    fn the_kernel_lists_this_users_processes_without_privilege() {
        let mut child = Command::new("python3")
            .arg("-c")
            .arg("import time; time.sleep(30)")
            .spawn()
            .unwrap();
        let mine = my_processes();
        let _ = child.kill();
        let _ = child.wait();
        let mine = mine.expect("this user's process list is served");
        // `sizeof(struct kinfo_proc)` on 64-bit macOS: the record size is
        // read, not a size query's padded answer.
        assert_eq!(record_size(std::process::id() as i32), Some(648));
        let pids: Vec<i32> = mine.iter().map(|(pid, _)| *pid).collect();
        assert!(pids.contains(&(std::process::id() as i32)));
        assert!(pids.contains(&(child.id() as i32)));
        assert!(!pids.contains(&1), "launchd is root's");
    }

    /// B3: the `kinfo_proc` list parser, on synthetic records.
    #[test]
    fn the_process_list_layout_is_checked() {
        fn record(pid: i32, stat: u8, entry: usize) -> Vec<u8> {
            let mut bytes = vec![0u8; entry];
            bytes[KP_STAT] = stat;
            bytes[KP_PID..KP_PID + 4].copy_from_slice(&pid.to_ne_bytes());
            bytes
        }
        let entry = 64;
        let raw = [
            record(7, 2, entry),
            record(9, SZOMB, entry),
            record(11, 2, entry),
        ]
        .concat();
        assert_eq!(
            kinfo_records(&raw, entry, 11, 10),
            Some(vec![(7, 2), (9, SZOMB), (11, 2)])
        );
        // This process must be listed, and not as a zombie.
        assert_eq!(kinfo_records(&raw, entry, 12, 10), None);
        assert_eq!(kinfo_records(&raw, entry, 9, 10), None);
        // A torn length, an empty list, a too-short record, or the bound.
        assert_eq!(kinfo_records(&raw[..raw.len() - 1], entry, 11, 10), None);
        assert_eq!(kinfo_records(&[], entry, 11, 10), None);
        assert_eq!(kinfo_records(&raw, 8, 11, 100), None);
        assert_eq!(kinfo_records(&raw, entry, 11, 2), None);
    }

    /// B3: the sandboxed run's profile (`sandbox-exec` denies
    /// `process-info-pidinfo`, so the host's own engine's BSD info is
    /// refused with `EPERM`).
    #[cfg(target_os = "macos")]
    const B3_SANDBOX: &str = "(version 1)(allow default)(deny process-info-pidinfo)";
    #[cfg(target_os = "macos")]
    const B3_PROFILE: &str = "ORCEL_B3_PROFILE";
    #[cfg(target_os = "macos")]
    const B3_ENGINE: &str = "ORCEL_B3_ENGINE";

    /// Whether `pid`'s BSD info is refused (the B2 owner read).
    #[cfg(target_os = "macos")]
    fn bsd_info_refused(pid: i32) -> bool {
        // SAFETY: plain data; zeroed is a valid value.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: the buffer is exactly one proc_bsdinfo of `size` bytes.
        let read = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        read <= 0 && errno() == libc::EPERM
    }

    /// Runs only inside B3's sandboxed re-run (the variables are unset in
    /// the shared suite, where it returns at once).
    #[cfg(target_os = "macos")]
    #[test]
    fn b3_sandboxed_entry() {
        let (Ok(profile), Ok(engine)) = (std::env::var(B3_PROFILE), std::env::var(B3_ENGINE))
        else {
            return;
        };
        let engine: i32 = engine.parse().unwrap();
        // B2's owner read is refused here, so B2 skipped the engine.
        let refused = bsd_info_refused(engine);
        // B3's list is still served and names the engine.
        let listed = my_processes().is_some_and(|mine| mine.iter().any(|(pid, _)| *pid == engine));
        let named = named_by_a_running_engine(Path::new(&profile));
        println!("B3-RESULT refused={refused} listed={listed} named={named}");
        assert!(refused, "the sandbox did not refuse the engine's BSD info");
        assert!(listed, "the sandbox also hid this user's process list");
        assert!(named, "the engine must keep its profile");
    }

    /// B3: a host denied process info (a sandbox) must not mistake its own
    /// running engine for another user's and let recovery delete its
    /// profile. Under B2 the refusal meant "another user", so this failed.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_host_denied_process_info_keeps_its_engines_profile() {
        let (root, dir) = profile("sandboxed");
        populate(&dir);
        // Killed and reaped however the test ends, so a failed assertion
        // leaves no engine behind.
        struct Engine(std::process::Child);
        impl Drop for Engine {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let engine = Engine(
            Command::new("python3")
                .arg("-c")
                .arg("import time; time.sleep(30)")
                .arg(format!("--user-data-dir={}", dir.display()))
                .spawn()
                .unwrap(),
        );
        let started = std::time::Instant::now();
        while !named_by_a_running_engine(&dir)
            && started.elapsed() < std::time::Duration::from_secs(10)
        {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let output = Command::new("/usr/bin/sandbox-exec")
            .args(["-p", B3_SANDBOX])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "unix_cleanup::tests::b3_sandboxed_entry",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(B3_PROFILE, &dir)
            .env(B3_ENGINE, engine.0.id().to_string())
            .output()
            .unwrap();
        drop(engine);
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("{stdout}");
        assert!(
            stdout.contains("B3-RESULT refused=true listed=true named=true"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success());
        std::fs::remove_dir_all(&root).ok();
    }

    /// B2: the `KERN_PROCARGS2` layout, on synthetic buffers.
    #[test]
    fn the_procargs_layout_yields_exactly_the_arguments() {
        fn buffer(argc: i32, body: &[u8]) -> Vec<u8> {
            [argc.to_ne_bytes().as_slice(), body].concat()
        }
        let raw = buffer(
            2,
            b"/usr/bin/python3\0\0\0\0python3\0--user-data-dir=/p/a b\0HOME=/x\0",
        );
        assert_eq!(
            argv_of(&raw),
            Some(b"python3\0--user-data-dir=/p/a b\0".as_slice())
        );
        let wanted = vec![b"--user-data-dir=/p/a b".to_vec()];
        assert!(cmdline_names(argv_of(&raw).unwrap(), &wanted));
        // Truncated before the last argument ends, a negative argc, no
        // executable path, or too short for argc: no layout.
        assert_eq!(argv_of(&buffer(3, b"/bin/x\0\0x\0y\0")), None);
        assert_eq!(argv_of(&buffer(-1, b"/bin/x\0\0x\0")), None);
        assert_eq!(argv_of(&buffer(1, b"/bin/x")), None);
        assert_eq!(argv_of(b"\x01\0"), None);
        assert_eq!(argv_of(&buffer(0, b"/bin/x\0\0")), None);
    }

    /// Chromium's rewritten process title is one space-joined string: the
    /// flag still counts there, and only as a whole token.
    #[test]
    fn the_command_line_match_handles_a_rewritten_process_title() {
        let wanted = vec![b"--user-data-dir=/p/profile".to_vec()];
        assert!(cmdline_names(
            b"chrome\0--user-data-dir=/p/profile\0",
            &wanted
        ));
        assert!(cmdline_names(
            b"/opt/google/chrome/chrome --user-data-dir=/p/profile --flag\0",
            &wanted
        ));
        assert!(!cmdline_names(
            b"chrome --user-data-dir=/p/profile2\0",
            &wanted
        ));
        assert!(!cmdline_names(b"chrome --user-data-dir=/p\0", &wanted));
        assert!(!cmdline_names(b"", &wanted));
        // B2: a whole argument with a space matches; a rewritten title with
        // that path cannot (recorded).
        let spaced = vec![b"--user-data-dir=/p/a b".to_vec()];
        assert!(cmdline_names(b"chrome\0--user-data-dir=/p/a b\0", &spaced));
        assert!(!cmdline_names(b"chrome --user-data-dir=/p/a b\0", &spaced));
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
                || *path == crate_dir.join("src").join("unix_rehearsal.rs")
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
        // A6's rehearsal (recorded rule change, prep/SG-000115.md) composes
        // this module; it is admitted only while declared once, private,
        // under the Unix test cfg.
        assert_eq!(lib.matches("mod unix_rehearsal;").count(), 1);
        assert!(!lib.contains("pub mod unix_rehearsal"));
        assert!(lib.contains("#[cfg(all(test, unix))]\nmod unix_rehearsal;\n"));
    }
}
