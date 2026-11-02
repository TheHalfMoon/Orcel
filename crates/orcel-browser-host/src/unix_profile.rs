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
//!   swapped out from under the hold is detected, and re-checks the held
//!   directory's owner and 0700 mode, so a later chmod is caught.
//!
//! Open for activation (not decided here):
//! - **Ancestors:** whether the profile's ancestors must also be owned by
//!   this user or root and not writable by others (the parent of the
//!   profile is the state root, owned elsewhere).
//! - **Last component only (`open`):** `O_NOFOLLOW` (and
//!   `symlink_metadata` in `verify`) refuse a link at the last path
//!   component only. **A3b:** `open_beneath` walks from a trusted state
//!   root, `openat` per component with `O_NOFOLLOW | O_DIRECTORY`, refuses
//!   a link, `..` or `.` anywhere below it, and requires every directory in
//!   between to be this user's and writable by no one else. Activation must
//!   use it (or `openat2` / `O_NOFOLLOW_ANY`). `verify` still re-checks the
//!   path by name.
//! - **macOS ACLs (B6a):** extended ACL entries are separate from the mode
//!   bits on macOS, so exactly 0700 / 0600 does not exclude another user
//!   there (on Linux the mode's group bits carry the ACL mask). The hold
//!   reads each directory's and the lock's extended ACL through its
//!   descriptor (`acl_get_fd_np`), walks its entries with the library's own
//!   calls, and refuses any entry that is not a deny entry; deny-only ACLs
//!   (macOS puts "everyone deny delete" on home folders) are accepted. An
//!   ACL that cannot be read refuses.
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
    /// A link, or not a directory, at the root; or a link, a non-regular
    /// file or a file with more than one name (a hard link) at the lock.
    NotPlain,
    /// Another owner, or a mode other than 0700 (root) / 0600 (lock).
    Permissions,
    /// Another hold has the lock.
    Busy,
    /// Swapped: the path no longer names the held directory, or the lock
    /// name no longer names the locked file.
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
    lock_identity: (u64, u64),
    /// B5: a held, private parent and the profile's single child name.
    /// Only open_beneath supplies this; ordinary open keeps legacy behavior.
    parent: Option<(OwnedFd, CString)>,
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

thread_local! {
    /// The account a profile must belong to: this user, unless a test sets
    /// another (to check that another account's profile is refused). This
    /// module is compiled into test builds only.
    static EXPECTED_OWNER: std::cell::Cell<Option<libc::uid_t>> = const { std::cell::Cell::new(None) };
}

/// The account a profile and its ancestors below the state root must
/// belong to.
fn expected_owner() -> libc::uid_t {
    // SAFETY: geteuid has no preconditions.
    EXPECTED_OWNER
        .with(|owner| owner.get())
        .unwrap_or_else(|| unsafe { libc::geteuid() })
}

/// Tests only: require `uid` as the owner on this thread while `run` runs.
/// The previous value is restored by a guard, so a panic inside `run` never
/// leaves the override set.
#[cfg(test)]
pub(crate) fn with_expected_owner<T>(uid: libc::uid_t, run: impl FnOnce() -> T) -> T {
    struct Restore(Option<libc::uid_t>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0;
            EXPECTED_OWNER.with(|owner| owner.set(previous));
        }
    }
    let _restore = Restore(EXPECTED_OWNER.with(|owner| owner.replace(Some(uid))));
    run()
}

/// Owned by the expected user with exactly `mode` permission bits.
/// (`st_mode` is `u32` on Linux and `u16` on macOS, so the cast is needed
/// on one of them.)
#[allow(clippy::unnecessary_cast)]
fn owned_with_mode(stat: &libc::stat, mode: u32) -> bool {
    stat.st_uid == expected_owner() && (stat.st_mode as u32) & 0o7777 == mode
}

/// A directory above the profile: owned by the expected user and writable
/// by neither group nor others, so no other account can swap what is below.
/// On macOS no extended ACL entry may allow anything either (B6a).
#[allow(clippy::unnecessary_cast)]
fn private_ancestor(fd: &OwnedFd) -> Result<(), ProfileError> {
    let stat = fstat(fd)?;
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(ProfileError::NotPlain);
    }
    if stat.st_uid != expected_owner() || (stat.st_mode as u32) & 0o022 != 0 {
        return Err(ProfileError::Permissions);
    }
    no_allow_acl(fd)
}

/// `ACL_EXTENDED_DENY` in `<sys/acl.h>`: the only entry tag that grants
/// nothing.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const ACL_EXTENDED_DENY: libc::c_int = 2;

/// B6a: whether a list of extended ACL entry tags may grant access. Only
/// deny entries are accepted; an allow entry, or any tag not known to be
/// deny, refuses. The tags come from the ACL library's own entry walk, not
/// from rendered text, so flags (inheritance, `inherited`) cannot hide an
/// allow entry.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn tags_may_grant(tags: &[libc::c_int]) -> bool {
    tags.iter().any(|tag| *tag != ACL_EXTENDED_DENY)
}

#[cfg(target_os = "macos")]
mod acl {
    /// `ACL_TYPE_EXTENDED` in `<sys/acl.h>`.
    pub(super) const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    /// `ACL_FIRST_ENTRY` and `ACL_NEXT_ENTRY` in `<sys/acl.h>`.
    pub(super) const ACL_FIRST_ENTRY: libc::c_int = 0;
    pub(super) const ACL_NEXT_ENTRY: libc::c_int = -1;
    /// At most this many entries are read; more refuses.
    pub(super) const MAX_ENTRIES: usize = 128;
    extern "C" {
        pub(super) fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
        pub(super) fn acl_get_entry(
            acl: *mut libc::c_void,
            entry_id: libc::c_int,
            entry: *mut *mut libc::c_void,
        ) -> libc::c_int;
        pub(super) fn acl_get_tag_type(
            entry: *mut libc::c_void,
            tag: *mut libc::c_int,
        ) -> libc::c_int;
        pub(super) fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    }
}

/// B6a (macOS): refuse an open file or directory whose extended ACL has any
/// entry other than a deny entry; none at all (`ENOENT`) or deny-only is
/// fine. An ACL or entry that cannot be read, or more than
/// `acl::MAX_ENTRIES` entries, refuses.
#[cfg(target_os = "macos")]
fn no_allow_acl(fd: &OwnedFd) -> Result<(), ProfileError> {
    // SAFETY: a live descriptor; the returned ACL is freed below.
    let acl = unsafe { acl::acl_get_fd_np(fd.as_raw_fd(), acl::ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        return match errno() {
            libc::ENOENT => Ok(()),
            other => Err(ProfileError::Platform(other)),
        };
    }
    let mut tags = Vec::new();
    let mut readable = true;
    let mut which = acl::ACL_FIRST_ENTRY;
    loop {
        let mut entry: *mut libc::c_void = std::ptr::null_mut();
        // SAFETY: `acl` came from acl_get_fd_np; the entry belongs to it
        // and is not freed separately.
        if unsafe { acl::acl_get_entry(acl, which, &mut entry) } != 0 {
            // -1 with EINVAL marks the end of the entries (as macOS
            // documents it); any other failure refuses.
            if errno() != libc::EINVAL {
                readable = false;
            }
            break;
        }
        let mut tag: libc::c_int = 0;
        // SAFETY: a live entry of `acl` and an int to write the tag to.
        if unsafe { acl::acl_get_tag_type(entry, &mut tag) } != 0 {
            readable = false;
            break;
        }
        tags.push(tag);
        if tags.len() > acl::MAX_ENTRIES {
            readable = false;
            break;
        }
        which = acl::ACL_NEXT_ENTRY;
    }
    // SAFETY: the ACL was allocated by acl_get_fd_np above.
    unsafe { acl::acl_free(acl) };
    if !readable || tags_may_grant(&tags) {
        return Err(ProfileError::Permissions);
    }
    Ok(())
}

/// Linux: POSIX ACL entries are bounded by the mask the mode's group bits
/// carry, which the mode checks already constrain.
#[cfg(not(target_os = "macos"))]
fn no_allow_acl(_fd: &OwnedFd) -> Result<(), ProfileError> {
    Ok(())
}

/// Open a directory with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`, at `path`
/// or (with `at`) relative to an open directory.
fn open_directory(at: Option<&OwnedFd>, name: &CString) -> Result<OwnedFd, ProfileError> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: a NUL-terminated name; relative to an open descriptor when
    // `at` is given. Never follows a link at the opened component.
    let raw = unsafe {
        match at {
            Some(dir) => libc::openat(dir.as_raw_fd(), name.as_ptr(), flags),
            None => libc::open(name.as_ptr(), flags),
        }
    };
    if raw < 0 {
        return Err(match errno() {
            libc::ENOENT => ProfileError::Missing,
            libc::ELOOP | libc::ENOTDIR => ProfileError::NotPlain,
            other => ProfileError::Platform(other),
        });
    }
    // SAFETY: `raw` is a descriptor this call just opened and owns.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
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
    /// The lock name still names the file this hold locked (another
    /// holder's lock after a rename is not ours).
    pub(crate) fn verify_lock(&self) -> Result<(), ProfileError> {
        let name = CString::new(LOCK_NAME).map_err(|_| ProfileError::NotPlain)?;
        // SAFETY: stat is plain data; zeroed is a valid value.
        let mut named: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: relative to the held root; never follows a link.
        if unsafe {
            libc::fstatat(
                self.root.as_raw_fd(),
                name.as_ptr(),
                &mut named,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
            || identity(&named) != self.lock_identity
        {
            return Err(ProfileError::Swapped);
        }
        Ok(())
    }

    /// The held root descriptor, for operations relative to it (the A5
    /// sweep, itself test-only).
    pub(crate) fn root_fd(&self) -> i32 {
        self.root.as_raw_fd()
    }

    /// Hold the profile at `path`: refuse a link, a non-directory, another
    /// owner, a mode other than 0700, an unsafe lock file, or a profile
    /// another hold already has.
    pub(crate) fn open(path: &Path) -> Result<Self, ProfileError> {
        let c_path =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| ProfileError::NotPlain)?;
        Self::hold(open_directory(None, &c_path)?, None)
    }

    /// Hold the profile at `state_root/relative`, opening every component
    /// below the state root relative to the one before it with
    /// `O_NOFOLLOW | O_DIRECTORY`. A link at any component below the state
    /// root refuses (not only at the last one, as `open` does), and so does
    /// `..`, `.` or an absolute part. The state root and every directory
    /// between it and the profile must belong to this user and be writable
    /// by neither group nor others. The state root's own path is opened
    /// with `O_NOFOLLOW` for its last component only: it is the trusted
    /// starting point.
    pub(crate) fn open_beneath(state_root: &Path, relative: &Path) -> Result<Self, ProfileError> {
        use std::path::Component;
        let c_root =
            CString::new(state_root.as_os_str().as_bytes()).map_err(|_| ProfileError::NotPlain)?;
        let mut dir = open_directory(None, &c_root)?;
        private_ancestor(&dir)?;
        let parts: Vec<Component<'_>> = relative.components().collect();
        if parts.is_empty() {
            return Err(ProfileError::NotPlain);
        }
        for (index, part) in parts.iter().enumerate() {
            let Component::Normal(name) = part else {
                return Err(ProfileError::NotPlain);
            };
            let name = CString::new(name.as_bytes()).map_err(|_| ProfileError::NotPlain)?;
            let next = open_directory(Some(&dir), &name)?;
            if index + 1 == parts.len() {
                // Keep the parent descriptor alive until the final unlinkat:
                // never re-resolve an attacker-swapped intermediate path.
                return Self::hold(next, Some((dir, name)));
            }
            private_ancestor(&next)?;
            dir = next;
        }
        Err(ProfileError::NotPlain)
    }

    /// The checks shared by `open` and `open_beneath`, on the opened root.
    fn hold(root: OwnedFd, parent: Option<(OwnedFd, CString)>) -> Result<Self, ProfileError> {
        let root_stat = fstat(&root)?;
        if (root_stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            return Err(ProfileError::NotPlain);
        }
        if !owned_with_mode(&root_stat, 0o700) {
            return Err(ProfileError::Permissions);
        }
        no_allow_acl(&root)?;

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
        no_allow_acl(&lock)?;
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
            lock_identity: identity(&lock_stat),
            root,
            _lock: lock,
            parent,
        })
    }

    /// The path still names the held directory (same device and inode, and
    /// still not a link), and the held directory is still this user's with
    /// mode 0700.
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
        if let Some((parent, name)) = &self.parent {
            // Root name must STILL designate the exact opened directory
            // relative to the held ancestor, never a symlink or replacement.
            private_ancestor(parent)?;
            // SAFETY: a live descriptor this hold owns, a NUL-terminated
            // name it owns, and a stat buffer of the right type.
            let mut named: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    &mut named,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
                || (named.st_mode & libc::S_IFMT) != libc::S_IFDIR
                || identity(&named) != self.identity
            {
                return Err(ProfileError::Swapped);
            }
        }
        // The held directory is still this user's, mode 0700 (a later
        // chmod is caught here).
        if !owned_with_mode(&fstat(&self.root)?, 0o700) {
            return Err(ProfileError::Permissions);
        }
        // B6a: an allow ACL added later is caught here too.
        no_allow_acl(&self.root)
    }

    /// B5: remove only the exact held directory entry. With open_beneath,
    /// unlinkat is relative to the *held parent*, never an untrusted
    /// re-resolved intermediate path. The legacy direct-open path retains
    /// its old behavior only for test callers and is not activated.
    pub(crate) fn remove_directory(&self, path: &Path) -> Result<(), ProfileError> {
        self.verify(path)?;
        let removed = if let Some((parent, name)) = &self.parent {
            // SAFETY: final-component directory unlink relative to held parent.
            unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
        } else {
            let name =
                CString::new(path.as_os_str().as_bytes()).map_err(|_| ProfileError::NotPlain)?;
            // SAFETY: legacy test-only whole-path directory unlink.
            unsafe { libc::rmdir(name.as_ptr()) }
        };
        if removed != 0 {
            return Err(ProfileError::Platform(errno()));
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
            // The bit really stuck, so a refusal is not a silently cleared bit.
            let applied = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o7777;
            assert_eq!(applied, mode, "{mode:o} applied as {applied:o}");
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

    /// A3b: another account's profile is refused, whatever its mode.
    #[test]
    fn another_accounts_profile_is_refused() {
        let (root, dir) = profile("owner");
        // SAFETY: geteuid has no preconditions.
        let other = unsafe { libc::geteuid() }.wrapping_add(1);
        assert_eq!(
            with_expected_owner(other, || ProfileHold::open(&dir).map(|_| ())),
            Err(ProfileError::Permissions)
        );
        // Through the walk too, at the first directory it checks.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            with_expected_owner(other, || ProfileHold::open_beneath(
                &root,
                Path::new("profile")
            )
            .map(|_| ())),
            Err(ProfileError::Permissions)
        );
        assert!(
            ProfileHold::open(&dir).is_ok(),
            "the override ends with the call"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// A state root with an intermediate directory and the profile below it.
    fn nested(label: &str) -> (PathBuf, PathBuf) {
        let root = scratch(label);
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let middle = root.join("middle");
        std::fs::create_dir(&middle).unwrap();
        std::fs::set_permissions(&middle, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = middle.join("profile");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        (root, dir)
    }

    /// B6a: only deny entries are accepted; an allow entry, or a tag not
    /// known to be deny, refuses.
    #[test]
    fn only_deny_entries_in_an_acl_are_accepted() {
        assert!(!tags_may_grant(&[]));
        assert!(!tags_may_grant(&[ACL_EXTENDED_DENY, ACL_EXTENDED_DENY]));
        assert!(tags_may_grant(&[1]), "ACL_EXTENDED_ALLOW");
        assert!(tags_may_grant(&[ACL_EXTENDED_DENY, 1]));
        assert!(tags_may_grant(&[0]), "ACL_UNDEFINED_TAG");
        assert!(tags_may_grant(&[7]), "an unknown tag");
    }

    /// B6a (macOS): set a real extended ACL on a descriptor.
    #[cfg(target_os = "macos")]
    fn set_acl(path: &Path, text: &str) {
        extern "C" {
            fn acl_from_text(text: *const libc::c_char) -> *mut libc::c_void;
            fn acl_set_fd_np(
                fd: libc::c_int,
                acl: *mut libc::c_void,
                kind: libc::c_int,
            ) -> libc::c_int;
            fn acl_free(object: *mut libc::c_void) -> libc::c_int;
        }
        let file = std::fs::File::open(path).unwrap();
        let text = CString::new(text).unwrap();
        // SAFETY: a NUL-terminated rendering; the ACL is freed below.
        let acl = unsafe { acl_from_text(text.as_ptr()) };
        assert!(!acl.is_null(), "the ACL text parses");
        // SAFETY: an open descriptor and the ACL parsed above.
        let status = unsafe { acl_set_fd_np(file.as_raw_fd(), acl, 0x0000_0100) };
        // SAFETY: the ACL came from acl_from_text.
        unsafe { acl_free(acl) };
        assert_eq!(status, 0, "the ACL is set");
    }

    #[cfg(target_os = "macos")]
    const EVERYONE_READ: &str =
        "!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:allow:read\n";
    #[cfg(target_os = "macos")]
    const EVERYONE_READ_INHERITED: &str = "!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:allow,file_inherit,directory_inherit:read\n";
    #[cfg(target_os = "macos")]
    const EVERYONE_DENY_DELETE: &str =
        "!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:deny:delete\n";

    /// B6a (macOS): an allow entry on the profile, on its lock, on an
    /// ancestor, or added after the hold, refuses; a deny-only ACL does not.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_macos_allow_acl_anywhere_on_the_path_refuses() {
        let (root, dir) = profile("acl-root");
        set_acl(&dir, EVERYONE_READ);
        assert_eq!(
            ProfileHold::open(&dir).unwrap_err(),
            ProfileError::Permissions
        );
        std::fs::remove_dir_all(&root).ok();

        let (root, dir) = profile("acl-deny");
        set_acl(&dir, EVERYONE_DENY_DELETE);
        ProfileHold::open(&dir).expect("a deny-only ACL is accepted");
        std::fs::remove_dir_all(&root).ok();

        let (root, dir) = profile("acl-lock");
        drop(ProfileHold::open(&dir).unwrap());
        set_acl(&dir.join(LOCK_NAME), EVERYONE_READ);
        assert_eq!(
            ProfileHold::open(&dir).unwrap_err(),
            ProfileError::Permissions
        );
        std::fs::remove_dir_all(&root).ok();

        let (root, _) = nested("acl-ancestor");
        set_acl(&root.join("middle"), EVERYONE_READ);
        assert_eq!(
            ProfileHold::open_beneath(&root, Path::new("middle/profile")).unwrap_err(),
            ProfileError::Permissions
        );
        std::fs::remove_dir_all(&root).ok();

        // An allow entry inherited from the parent (created with
        // inheritance flags, so the profile's own entry carries
        // `inherited`) refuses too: flags cannot hide an allow entry.
        let root = scratch("acl-inherited");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        set_acl(&root, EVERYONE_READ_INHERITED);
        let dir = root.join("profile");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            ProfileHold::open(&dir).unwrap_err(),
            ProfileError::Permissions
        );
        std::fs::remove_dir_all(&root).ok();

        let (root, dir) = profile("acl-later");
        let hold = ProfileHold::open(&dir).unwrap();
        set_acl(&dir, EVERYONE_READ);
        assert_eq!(hold.verify(&dir), Err(ProfileError::Permissions));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_profile_beneath_a_private_state_root_is_held() {
        let (root, _) = nested("beneath");
        let hold = ProfileHold::open_beneath(&root, Path::new("middle/profile")).unwrap();
        hold.verify_lock().unwrap();
        std::fs::remove_dir_all(&root).ok();
    }

    /// A3b: a link swapped in at a middle component refuses. `open`
    /// follows it (only its last component is checked); the walk does not.
    #[test]
    fn a_link_in_the_middle_of_the_path_is_refused_by_the_walk() {
        let (root, _) = nested("middle-link");
        let elsewhere = root.join("elsewhere");
        std::fs::rename(root.join("middle"), &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join("middle")).unwrap();
        assert!(
            ProfileHold::open(&root.join("middle/profile")).is_ok(),
            "the last-component check alone follows the middle link"
        );
        assert_eq!(
            ProfileHold::open_beneath(&root, Path::new("middle/profile")).map(|_| ()),
            Err(ProfileError::NotPlain)
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn the_walk_refuses_parent_dot_and_absolute_parts() {
        let (root, _) = nested("parts");
        for relative in [
            "../profile",
            "middle/../middle/profile",
            "./middle/profile",
            "/middle/profile",
            "",
        ] {
            assert_eq!(
                ProfileHold::open_beneath(&root, Path::new(relative)).map(|_| ()),
                Err(ProfileError::NotPlain),
                "{relative:?}"
            );
        }
        std::fs::remove_dir_all(&root).ok();
    }

    /// A3b: a directory between the state root and the profile that another
    /// account could write refuses, as does such a state root.
    #[test]
    fn a_writable_ancestor_is_refused_by_the_walk() {
        for (target, mode) in [("middle", 0o770), ("middle", 0o707), ("", 0o777)] {
            let (root, _) = nested(&format!("ancestor-{mode:o}"));
            let path = if target.is_empty() {
                root.clone()
            } else {
                root.join(target)
            };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                ProfileHold::open_beneath(&root, Path::new("middle/profile")).map(|_| ()),
                Err(ProfileError::Permissions),
                "{target:?} at {mode:o}"
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::remove_dir_all(&root).ok();
        }
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
            // unix_cleanup.rs (slice A5) is a sibling test-only module that
            // builds on the hold; its own scan pins its test-only declaration.
            if *path == crate_dir.join("src").join("unix_profile.rs")
                || *path == crate_dir.join("src").join("unix_cleanup.rs")
                || *path == crate_dir.join("src").join("unix_rehearsal.rs")
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
        // The exempted sibling (A5) is itself test-only.
        assert!(lib.contains("#[cfg(all(test, unix))]\nmod unix_cleanup;\n"));
        // A6's rehearsal (recorded rule change, prep/SG-000115.md) composes
        // this module; it is admitted only while declared once, private,
        // under the Unix test cfg.
        assert_eq!(lib.matches("mod unix_rehearsal;").count(), 1);
        assert!(!lib.contains("pub mod unix_rehearsal"));
        assert!(lib.contains("#[cfg(all(test, unix))]\nmod unix_rehearsal;\n"));
    }
}
