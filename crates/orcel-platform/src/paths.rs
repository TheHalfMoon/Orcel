//! XP-01 per-user Orcel state root.
//!
//! - Windows: `%LOCALAPPDATA%\Orcel` (unchanged from the earlier defaults).
//! - macOS: `$HOME/Library/Application Support/Orcel`.
//! - Linux and other Unix: `$XDG_STATE_HOME/orcel`, else
//!   `$HOME/.local/state/orcel`.
//!
//! Resolution never falls back to the shared temp directory, where another
//! local user could pre-create or symlink the location. When no usable
//! variable is set the caller gets a [`PlatformError`] and fails closed.
//!
//! The checks run when a path is resolved, not again at each later open.
//! That holds because [`ensure_private_dir`] also refuses any ancestor
//! another user could modify: once it passes, no other non-root user can
//! rename, replace or re-point any component of the path.
//!
//! On Unix the ancestor rule is strict: a group-writable home such as one
//! with mode 0775 is refused with [`PlatformError::WritableAncestor`] naming
//! that home, even when the group holds only its owner.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Component, Path, PathBuf};

/// The per-OS rule [`state_root_for`] applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateLayout {
    Windows,
    MacOs,
    /// Linux and other Unix systems: the XDG Base Directory state home.
    Xdg,
}

impl StateLayout {
    /// The layout of the running OS, or `None` on a target Orcel does not
    /// support.
    pub const fn current() -> Option<Self> {
        if cfg!(windows) {
            Some(Self::Windows)
        } else if cfg!(target_os = "macos") {
            Some(Self::MacOs)
        } else if cfg!(unix) {
            Some(Self::Xdg)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformError {
    /// No usable per-user location: the variables the layout needs are
    /// missing, empty, relative or contain `.`/`..` components.
    StateRootUnavailable(String),
    UnsupportedPlatform,
    NotAbsolute(PathBuf),
    Symlink(PathBuf),
    NotDirectory(PathBuf),
    ForeignOwner {
        path: PathBuf,
        owner: u32,
        expected: u32,
    },
    /// The directory grants group or other access (`mode` holds the
    /// permission bits).
    InsecureMode {
        path: PathBuf,
        mode: u32,
    },
    /// An ancestor is writable by group or other without being a root-owned
    /// sticky directory such as `/tmp` (`mode` holds the mode bits).
    WritableAncestor {
        path: PathBuf,
        mode: u32,
    },
    Io {
        path: PathBuf,
        kind: std::io::ErrorKind,
        message: String,
    },
    /// Windows: the owner or DACL lets another principal reach or change the
    /// path; macOS: an extended ACL entry does (#358, #384). `reason` names
    /// the grant.
    InsecureAcl {
        path: PathBuf,
        reason: String,
    },
    /// The process does not exist, has exited, or is a zombie waiting to be
    /// reaped (XP-03).
    ///
    /// For a socket peer (`peer`) this means only "refuse this connection"
    /// (#367); it does not prove the process exited. The pid is 0, a
    /// sentinel that names no process, when the kernel no longer names one,
    /// as for a macOS peer that has closed its end of the socket while it
    /// still runs. A consumer must never clean up, revoke or record state
    /// about a process because of this error.
    ProcessGone(u32),
    /// An identity fact (process start time, boot id, session or socket peer
    /// credentials) could not be read or parsed (XP-03).
    IdentityUnavailable(String),
    /// A local socket peer runs as a different user than this process
    /// (XP-03).
    PeerRefused {
        peer_uid: u32,
        expected_uid: u32,
    },
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateRootUnavailable(reason) => {
                write!(f, "Orcel state root is unavailable: {reason}")
            }
            Self::UnsupportedPlatform => {
                f.write_str("Orcel state root is unavailable on this platform")
            }
            Self::NotAbsolute(path) => {
                write!(f, "state path {} is not absolute", path.display())
            }
            Self::Symlink(path) => {
                write!(f, "state directory {} is a symbolic link", path.display())
            }
            Self::NotDirectory(path) => {
                write!(f, "state directory {} is not a directory", path.display())
            }
            Self::ForeignOwner {
                path,
                owner,
                expected,
            } => write!(
                f,
                "state directory {} is owned by uid {owner}, not the current uid {expected}",
                path.display()
            ),
            Self::InsecureMode { path, mode } => write!(
                f,
                "state directory {} grants group or other access (mode {mode:03o})",
                path.display()
            ),
            Self::WritableAncestor { path, mode } => write!(
                f,
                "state directory ancestor {} is writable by other users (mode {mode:04o})",
                path.display()
            ),
            Self::Io {
                path,
                kind: _,
                message,
            } => write!(f, "state directory {}: {message}", path.display()),
            Self::InsecureAcl { path, reason } => write!(
                f,
                "{} could be reached or changed by another user: {reason}",
                path.display()
            ),
            Self::ProcessGone(pid) => write!(f, "process {pid} is not running"),
            Self::IdentityUnavailable(reason) => {
                write!(f, "platform identity is unavailable: {reason}")
            }
            Self::PeerRefused {
                peer_uid,
                expected_uid,
            } => write!(
                f,
                "socket peer runs as uid {peer_uid}, not the current uid {expected_uid}"
            ),
        }
    }
}

impl std::error::Error for PlatformError {}

/// The per-user Orcel state root of the running OS, from the process
/// environment. The directory is not created or checked; see
/// [`ensure_private_dir`].
pub fn state_root() -> Result<PathBuf, PlatformError> {
    state_root_from(&|name| std::env::var_os(name))
}

/// The state root of the running OS's layout, derived from `lookup`.
pub fn state_root_from(
    lookup: &dyn Fn(&str) -> Option<OsString>,
) -> Result<PathBuf, PlatformError> {
    let layout = StateLayout::current().ok_or(PlatformError::UnsupportedPlatform)?;
    state_root_for(layout, lookup)
}

/// The Orcel state root `layout` derives from `lookup`. Values that are not
/// absolute are never used: a relative `XDG_STATE_HOME` is ignored as the
/// XDG specification requires, and a relative `HOME` or `LOCALAPPDATA` is an
/// error.
pub fn state_root_for(
    layout: StateLayout,
    lookup: &dyn Fn(&str) -> Option<OsString>,
) -> Result<PathBuf, PlatformError> {
    match layout {
        StateLayout::Windows => Ok(absolute_var(layout, lookup, "LOCALAPPDATA")
            .ok_or_else(|| unavailable("LOCALAPPDATA"))?
            .join("Orcel")),
        StateLayout::MacOs => Ok(absolute_var(layout, lookup, "HOME")
            .ok_or_else(|| unavailable("HOME"))?
            .join("Library")
            .join("Application Support")
            .join("Orcel")),
        StateLayout::Xdg => {
            if let Some(state_home) = absolute_var(layout, lookup, "XDG_STATE_HOME") {
                return Ok(state_home.join("orcel"));
            }
            Ok(absolute_var(layout, lookup, "HOME")
                .ok_or_else(|| unavailable("XDG_STATE_HOME or HOME"))?
                .join(".local")
                .join("state")
                .join("orcel"))
        }
    }
}

/// Makes sure `path` is a directory only the current user can reach.
///
/// On Unix every ancestor, from `/` down, must be owned by the current uid
/// or root and must not be writable by group or other unless it is a
/// root-owned sticky directory such as `/tmp`. A symlinked ancestor is
/// allowed only when the link is owned by the current uid or root and the
/// directories it resolves to pass the same checks; macOS needs this for
/// `/var` and `/tmp`. Missing ancestors are created one at a time, each
/// with mode 0700 (the XDG mode for state directories), and only after
/// their parent passed. The directory itself is created with mode 0700 when
/// missing, and is refused when it is a symbolic link, is not a directory,
/// is owned by another uid, or grants any group or other permission.
/// Nothing is repaired. On macOS an extended ACL `allow` entry is refused
/// too: any entry on the directory, and a write-granting entry on an
/// ancestor ([`PlatformError::InsecureAcl`]).
///
/// On Windows (#358 item 2) the owner and DACL take the place of the owner
/// and mode bits. Missing directories are created one at a time with a
/// protected DACL that admits only the user, `SYSTEM` and Administrators.
/// The directory must be owned by one of those (or TrustedInstaller), and no
/// other principal may hold any access to it. Every ancestor must have such
/// an owner, and no other principal may hold a right that deletes, renames
/// or re-points an entry (`DELETE`, `FILE_DELETE_CHILD`, `WRITE_DAC`,
/// `WRITE_OWNER`, `GENERIC_ALL`); adding entries is allowed, as under a
/// sticky `/tmp`. Junctions and symbolic links are refused on the directory
/// and on every ancestor. So an `ORCEL_*_PATH` override in a shared
/// directory such as `C:\Users\Public` is refused, while a private directory
/// created beneath it is accepted. Nothing is repaired.
pub fn ensure_private_dir(path: &Path) -> Result<(), PlatformError> {
    if !path.is_absolute() {
        return Err(PlatformError::NotAbsolute(path.to_path_buf()));
    }
    imp::ensure_private_dir(path)
}

/// XP-13b: an executable Orcel registers, hashes and runs must not be
/// replaceable by anyone but the user or root. The file is a regular file,
/// not a link, and it and every ancestor directory are owned by the user or
/// root and not writable by group or others. A world-writable ancestor is
/// accepted only when it is root-owned and sticky, like `/tmp`, because there
/// nobody else can rename or remove the user's own entries. On macOS, an
/// extended ACL entry that grants a write on the file or an ancestor is
/// refused too (#384 item 1).
///
/// On Windows (#384 item 4) the file and every ancestor must be owned by the
/// user, `SYSTEM`, Administrators or TrustedInstaller. No other principal may
/// hold a right that changes, renames or deletes the file or re-points its
/// DACL or owner. On an ancestor, no other principal may hold a right that
/// deletes, renames or re-points an entry (adding one is allowed). Junctions
/// and symbolic links on the path are refused.
pub fn check_owned_executable_location(path: &Path) -> Result<(), String> {
    imp::check_owned_executable_location(path)
}

/// A file location from an `ORCEL_*_PATH` override. Empty and relative
/// values are refused, so an override never resolves against the working
/// directory of whichever process reads it.
pub fn absolute_override(value: OsString) -> Result<PathBuf, PlatformError> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(PlatformError::NotAbsolute(path))
    }
}

/// A state file location from an `ORCEL_*` override (XP-01B): absolute, as
/// [`absolute_override`] requires, and inside a directory that passes
/// [`ensure_private_dir`] (created when missing). An override gets the same
/// guarantees as the default location instead of bypassing them.
pub fn private_file_override(value: OsString) -> Result<PathBuf, PlatformError> {
    private_file(absolute_override(value)?)
}

/// `path` once its parent directory passes [`ensure_private_dir`].
pub fn private_file(path: PathBuf) -> Result<PathBuf, PlatformError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| PlatformError::NotAbsolute(path.clone()))?;
    ensure_private_dir(parent)?;
    Ok(path)
}

/// macOS: the per-user temporary directory that
/// `confstr(_CS_DARWIN_USER_TEMP_DIR)` names (`/var/folders/<xx>/<id>/T/`).
/// It comes from the system, not from `TMPDIR`, so every process of the
/// user resolves the same directory. It is a 0700 directory of this user
/// alone, not the shared temporary directory that XP-01B keeps state out
/// of. `None` on other OSes, or when the
/// system gives no absolute path. The directory is not checked; see
/// [`ensure_private_dir`]. CR-01 binds its short-path socket there (#381).
pub fn macos_per_user_runtime_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut buf = vec![0u8; 1024];
        // SAFETY: `buf` holds `buf.len()` bytes; confstr writes at most that
        // many, NUL included, and returns the length it needed.
        let needed = unsafe {
            libc::confstr(
                libc::_CS_DARWIN_USER_TEMP_DIR,
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if needed == 0 || needed > buf.len() {
            return None;
        }
        buf.truncate(needed - 1);
        let path = PathBuf::from(OsString::from_vec(buf));
        path.is_absolute().then_some(path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// Unix: takes an exclusive advisory `flock` on `file` without waiting.
/// `Ok(false)` means another open file holds it. The lock belongs to this
/// open file and the kernel releases it when the file is closed, including
/// when the process dies. (`File::try_lock` is newer than the MSRV.)
#[cfg(unix)]
pub fn try_lock_exclusive(file: &std::fs::File) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd;
    loop {
        // SAFETY: the descriptor is valid while `file` is borrowed.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EWOULDBLOCK) => return Ok(false),
            Some(libc::EINTR) => {}
            _ => return Err(error),
        }
    }
}

fn unavailable(variables: &str) -> PlatformError {
    PlatformError::StateRootUnavailable(format!("{variables} is not set to an absolute path"))
}

/// `name` from `lookup` when `layout` can use it: absolute and free of
/// `.`/`..` components. Other per-user base directories (XP-17's XDG data,
/// config and runtime homes) use this so they get the same rules as the
/// state root.
pub fn absolute_var(
    layout: StateLayout,
    lookup: &dyn Fn(&str) -> Option<OsString>,
    name: &str,
) -> Option<PathBuf> {
    let value = lookup(name)?;
    is_usable_absolute(layout, &value).then(|| PathBuf::from(value))
}

/// Unix layouts are judged by Unix rules on every host, so their resolution
/// is testable on Windows too.
fn is_usable_absolute(layout: StateLayout, value: &OsStr) -> bool {
    match layout {
        StateLayout::Windows => {
            let path = Path::new(value);
            path.is_absolute()
                && !path.components().any(|component| {
                    matches!(component, Component::ParentDir | Component::CurDir)
                        || component.as_os_str() == ".."
                        || component.as_os_str() == "."
                })
        }
        StateLayout::MacOs | StateLayout::Xdg => {
            let bytes = value.as_encoded_bytes();
            bytes.first() == Some(&b'/')
                && !bytes
                    .split(|byte| *byte == b'/')
                    .any(|part| part == b"." || part == b"..")
        }
    }
}

fn io_error(path: &Path, error: std::io::Error) -> PlatformError {
    PlatformError::Io {
        path: path.to_path_buf(),
        kind: error.kind(),
        message: error.to_string(),
    }
}

#[cfg(unix)]
mod imp {
    use super::{io_error, PlatformError};
    use std::fs::Metadata;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    use std::path::Path;

    pub(super) fn ensure_private_dir(path: &Path) -> Result<(), PlatformError> {
        ensure_private_dir_as(path, current_uid())
    }

    pub(super) fn ensure_private_dir_as(path: &Path, uid: u32) -> Result<(), PlatformError> {
        let ancestors: Vec<&Path> = path.ancestors().skip(1).collect();
        // From `/` down, so each directory is accepted or created only after
        // its parent passed.
        for ancestor in ancestors.iter().rev() {
            let metadata = match std::fs::symlink_metadata(ancestor) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    create_private(ancestor)?
                }
                Err(error) => return Err(io_error(ancestor, error)),
            };
            verify_ancestor(ancestor, &metadata, uid)?;
            // The link itself passed; the directories it resolves to must
            // pass too before anything is created beneath it.
            if metadata.file_type().is_symlink() {
                verify_resolved(ancestor, uid)?;
            }
        }
        if let Some(parent) = path.parent() {
            verify_resolved(parent, uid)?;
        }
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_private(path)?,
            Err(error) => return Err(io_error(path, error)),
        };
        verify(path, &metadata, uid)
    }

    /// Checks every directory on the canonical path of `path`, which exists.
    fn verify_resolved(path: &Path, uid: u32) -> Result<(), PlatformError> {
        let resolved = std::fs::canonicalize(path).map_err(|error| io_error(path, error))?;
        for ancestor in resolved.ancestors() {
            let metadata =
                std::fs::symlink_metadata(ancestor).map_err(|error| io_error(ancestor, error))?;
            verify_ancestor(ancestor, &metadata, uid)?;
        }
        Ok(())
    }

    /// Creates one directory with mode 0700 and returns what is there
    /// afterwards. A directory another process created first is returned
    /// too, so it faces the same checks as one that already existed.
    fn create_private(path: &Path) -> Result<Metadata, PlatformError> {
        match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_error(path, error)),
        }
        std::fs::symlink_metadata(path).map_err(|error| io_error(path, error))
    }

    pub(super) fn verify_ancestor(
        path: &Path,
        metadata: &Metadata,
        uid: u32,
    ) -> Result<(), PlatformError> {
        let owner = metadata.uid();
        if owner != uid && owner != 0 {
            return Err(PlatformError::ForeignOwner {
                path: path.to_path_buf(),
                owner,
                expected: uid,
            });
        }
        let file_type = metadata.file_type();
        // A link cannot be re-pointed, only replaced through its parent,
        // which the walk checked first.
        if file_type.is_symlink() {
            return Ok(());
        }
        if !file_type.is_dir() {
            return Err(PlatformError::NotDirectory(path.to_path_buf()));
        }
        let mode = metadata.mode() & 0o7777;
        let sticky_root = owner == 0 && mode & 0o1000 != 0;
        if mode & 0o022 != 0 && !sticky_root {
            return Err(PlatformError::WritableAncestor {
                path: path.to_path_buf(),
                mode,
            });
        }
        acl_check(path, false, AclRefuse::Write).map_err(|reason| PlatformError::InsecureAcl {
            path: path.to_path_buf(),
            reason,
        })
    }

    /// macOS: refuse an extended ACL entry (#384 item 1). Elsewhere the mode
    /// bits already cover POSIX ACLs (see `macos_acl`).
    #[cfg(target_os = "macos")]
    use crate::macos_acl::{check as acl_check, Refuse as AclRefuse};

    #[cfg(not(target_os = "macos"))]
    #[derive(Clone, Copy)]
    enum AclRefuse {
        AnyAllow,
        Write,
    }

    #[cfg(not(target_os = "macos"))]
    fn acl_check(_path: &Path, _follow: bool, _refuse: AclRefuse) -> Result<(), String> {
        Ok(())
    }

    pub(super) fn verify(path: &Path, metadata: &Metadata, uid: u32) -> Result<(), PlatformError> {
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(PlatformError::Symlink(path.to_path_buf()));
        }
        if !file_type.is_dir() {
            return Err(PlatformError::NotDirectory(path.to_path_buf()));
        }
        if metadata.uid() != uid {
            return Err(PlatformError::ForeignOwner {
                path: path.to_path_buf(),
                owner: metadata.uid(),
                expected: uid,
            });
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(PlatformError::InsecureMode {
                path: path.to_path_buf(),
                mode,
            });
        }
        acl_check(path, false, AclRefuse::AnyAllow).map_err(|reason| PlatformError::InsecureAcl {
            path: path.to_path_buf(),
            reason,
        })
    }

    pub(super) fn check_owned_executable_location(path: &Path) -> Result<(), String> {
        const GROUP_OR_OTHER_WRITE: u32 = 0o022;
        const STICKY: u32 = 0o1000;
        let uid = current_uid();
        let trusted_owner = |metadata: &Metadata| metadata.uid() == uid || metadata.uid() == 0;
        let file = std::fs::symlink_metadata(path)
            .map_err(|error| format!("{} cannot be inspected: {error}", path.display()))?;
        if !file.file_type().is_file() {
            return Err(format!("{} is not a regular file", path.display()));
        }
        if !trusted_owner(&file) {
            return Err(format!("{} is owned by another user", path.display()));
        }
        if file.permissions().mode() & GROUP_OR_OTHER_WRITE != 0 {
            return Err(format!("{} is writable by group or others", path.display()));
        }
        acl_check(path, false, AclRefuse::Write)?;
        for ancestor in path.ancestors().skip(1) {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            let directory = std::fs::metadata(ancestor)
                .map_err(|error| format!("{} cannot be inspected: {error}", ancestor.display()))?;
            if !trusted_owner(&directory) {
                return Err(format!("{} is owned by another user", ancestor.display()));
            }
            let mode = directory.permissions().mode();
            let shared_sticky = mode & STICKY != 0 && directory.uid() == 0;
            if mode & GROUP_OR_OTHER_WRITE != 0 && !shared_sticky {
                return Err(format!(
                    "{} is writable by group or others",
                    ancestor.display()
                ));
            }
            acl_check(ancestor, true, AclRefuse::Write)?;
        }
        Ok(())
    }

    pub(super) fn current_uid() -> u32 {
        extern "C" {
            fn geteuid() -> u32;
        }
        // SAFETY: geteuid takes no arguments, always succeeds and touches no
        // memory; it is defined by the C library std already links, and
        // uid_t is a 32-bit unsigned integer on every supported Unix.
        unsafe { geteuid() }
    }
}

#[cfg(windows)]
mod imp {
    use super::{io_error, PlatformError};
    use crate::acl::{self, Role};
    use std::os::windows::fs::MetadataExt;
    use std::path::Path;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

    fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    fn judge(path: &Path, user: &str, role: Role) -> Result<(), String> {
        let (owner, dacl) = acl::security_of(path)?;
        acl::judge(&owner, dacl.as_deref(), user, role)
    }

    fn insecure(path: &Path) -> impl FnOnce(String) -> PlatformError + '_ {
        move |reason| PlatformError::InsecureAcl {
            path: path.to_path_buf(),
            reason,
        }
    }

    /// The directory at `path`, created private when missing, refused when
    /// it is a junction, a link or not a directory.
    fn directory(path: &Path, user: &str) -> Result<(), PlatformError> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_private(path, user)?
            }
            Err(error) => return Err(io_error(path, error)),
        };
        if is_reparse_point(&metadata) {
            return Err(PlatformError::Symlink(path.to_path_buf()));
        }
        if !metadata.is_dir() {
            return Err(PlatformError::NotDirectory(path.to_path_buf()));
        }
        Ok(())
    }

    pub(super) fn ensure_private_dir(path: &Path) -> Result<(), PlatformError> {
        let user = acl::current_user_sid().map_err(PlatformError::IdentityUnavailable)?;
        let ancestors: Vec<&Path> = path.ancestors().skip(1).collect();
        // From the volume root down, so each directory is accepted or created
        // only after its parent passed.
        for ancestor in ancestors.iter().rev() {
            directory(ancestor, &user)?;
            judge(ancestor, &user, Role::Ancestor).map_err(insecure(ancestor))?;
        }
        directory(path, &user)?;
        judge(path, &user, Role::PrivateDir).map_err(insecure(path))
    }

    /// Creates one directory with a protected owner-only DACL and returns
    /// what is there afterwards. A directory another process created first
    /// is returned too, so it faces the same checks as one that existed.
    fn create_private(path: &Path, user: &str) -> Result<std::fs::Metadata, PlatformError> {
        match acl::create_private_dir(path, user) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_error(path, error)),
        }
        std::fs::symlink_metadata(path).map_err(|error| io_error(path, error))
    }

    pub(super) fn check_owned_executable_location(path: &Path) -> Result<(), String> {
        let user = acl::current_user_sid()?;
        let file = std::fs::symlink_metadata(path)
            .map_err(|error| format!("{} cannot be inspected: {error}", path.display()))?;
        if !file.is_file() || is_reparse_point(&file) {
            return Err(format!("{} is not a regular file", path.display()));
        }
        judge(path, &user, Role::File).map_err(|reason| format!("{} {reason}", path.display()))?;
        for ancestor in path.ancestors().skip(1) {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            let directory = std::fs::symlink_metadata(ancestor)
                .map_err(|error| format!("{} cannot be inspected: {error}", ancestor.display()))?;
            if !directory.is_dir() || is_reparse_point(&directory) {
                return Err(format!(
                    "{} is a link or not a directory",
                    ancestor.display()
                ));
            }
            judge(ancestor, &user, Role::Ancestor)
                .map_err(|reason| format!("{} {reason}", ancestor.display()))?;
        }
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::PlatformError;
    use std::path::Path;

    pub(super) fn check_owned_executable_location(_path: &Path) -> Result<(), String> {
        Err("this platform has no ownership check".into())
    }

    pub(super) fn ensure_private_dir(_path: &Path) -> Result<(), PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn lookup(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: BTreeMap<String, OsString> = vars
            .iter()
            .map(|(name, value)| (name.to_string(), OsString::from(value)))
            .collect();
        move |name| map.get(name).cloned()
    }

    fn sandbox(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "orcel-platform-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("sandbox");
        // Independent of the umask, so the ancestor checks see a private base.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("chmod sandbox");
        }
        dir
    }

    #[test]
    fn xdg_state_home_is_used_when_absolute() {
        let root = state_root_for(
            StateLayout::Xdg,
            &lookup(&[("XDG_STATE_HOME", "/xdg/state"), ("HOME", "/home/u")]),
        );
        assert_eq!(root, Ok(PathBuf::from("/xdg/state").join("orcel")));
    }

    #[test]
    fn xdg_falls_back_to_home_local_state() {
        let root = state_root_for(StateLayout::Xdg, &lookup(&[("HOME", "/home/u")]));
        assert_eq!(
            root,
            Ok(PathBuf::from("/home/u")
                .join(".local")
                .join("state")
                .join("orcel"))
        );
    }

    #[test]
    fn relative_or_empty_xdg_state_home_is_ignored() {
        for value in ["state", "", "./state", "/x/../state", "~/.local/state"] {
            let root = state_root_for(
                StateLayout::Xdg,
                &lookup(&[("XDG_STATE_HOME", value), ("HOME", "/home/u")]),
            );
            assert_eq!(
                root,
                Ok(PathBuf::from("/home/u")
                    .join(".local")
                    .join("state")
                    .join("orcel")),
                "XDG_STATE_HOME={value:?}"
            );
        }
    }

    #[test]
    fn macos_uses_application_support() {
        let root = state_root_for(StateLayout::MacOs, &lookup(&[("HOME", "/Users/u")]));
        assert_eq!(
            root,
            Ok(PathBuf::from("/Users/u")
                .join("Library")
                .join("Application Support")
                .join("Orcel"))
        );
    }

    #[test]
    fn macos_ignores_xdg_state_home() {
        let root = state_root_for(
            StateLayout::MacOs,
            &lookup(&[("XDG_STATE_HOME", "/xdg"), ("HOME", "/Users/u")]),
        );
        assert_eq!(
            root,
            Ok(PathBuf::from("/Users/u")
                .join("Library")
                .join("Application Support")
                .join("Orcel"))
        );
    }

    #[test]
    fn relative_or_empty_home_is_refused() {
        for layout in [StateLayout::MacOs, StateLayout::Xdg] {
            for value in ["", "home/u", ".", "/home/../u"] {
                let root = state_root_for(layout, &lookup(&[("HOME", value)]));
                assert!(
                    matches!(root, Err(PlatformError::StateRootUnavailable(_))),
                    "{layout:?} HOME={value:?} gave {root:?}"
                );
            }
        }
    }

    #[test]
    fn missing_home_and_local_app_data_is_an_error_never_temp() {
        for layout in [StateLayout::Windows, StateLayout::MacOs, StateLayout::Xdg] {
            let root = state_root_for(layout, &lookup(&[]));
            assert!(
                matches!(root, Err(PlatformError::StateRootUnavailable(_))),
                "{layout:?} gave {root:?}"
            );
        }
        // The Windows layout reads only LOCALAPPDATA.
        let root = state_root_for(
            StateLayout::Windows,
            &lookup(&[("HOME", "/home/u"), ("XDG_STATE_HOME", "/xdg")]),
        );
        assert!(root.is_err(), "{root:?}");
    }

    #[test]
    fn current_layout_matches_the_build_target() {
        let layout = StateLayout::current();
        #[cfg(windows)]
        assert_eq!(layout, Some(StateLayout::Windows));
        #[cfg(target_os = "macos")]
        assert_eq!(layout, Some(StateLayout::MacOs));
        #[cfg(all(unix, not(target_os = "macos")))]
        assert_eq!(layout, Some(StateLayout::Xdg));
        assert!(layout.is_some());
    }

    #[cfg(windows)]
    #[test]
    fn windows_root_is_byte_identical_to_the_previous_default() {
        let local_app_data = r"C:\Users\u\AppData\Local";
        let root = state_root_for(
            StateLayout::Windows,
            &lookup(&[("LOCALAPPDATA", local_app_data), ("HOME", "/home/u")]),
        )
        .expect("root");
        // The expression the earlier defaults used.
        assert_eq!(root, PathBuf::from(local_app_data).join("Orcel"));
        assert_eq!(
            root.as_os_str().as_encoded_bytes(),
            br"C:\Users\u\AppData\Local\Orcel"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_relative_local_app_data_is_refused() {
        for value in [
            "",
            r"AppData\Local",
            r"\AppData\Local",
            r"C:\Users\..\Local",
        ] {
            let root = state_root_for(StateLayout::Windows, &lookup(&[("LOCALAPPDATA", value)]));
            assert!(root.is_err(), "LOCALAPPDATA={value:?} gave {root:?}");
        }
    }

    #[test]
    fn empty_or_relative_override_is_refused() {
        for value in ["", "custom.jsonl", "state/custom.jsonl", "./custom.jsonl"] {
            assert_eq!(
                absolute_override(OsString::from(value)),
                Err(PlatformError::NotAbsolute(PathBuf::from(value))),
                "{value:?}"
            );
        }
        let absolute = sandbox("override").join("custom.jsonl");
        assert_eq!(
            absolute_override(absolute.clone().into_os_string()),
            Ok(absolute.clone())
        );
        let _ = std::fs::remove_dir_all(absolute.parent().expect("parent"));
    }

    #[test]
    fn relative_directory_is_refused() {
        assert_eq!(
            ensure_private_dir(Path::new("orcel-relative")),
            Err(PlatformError::NotAbsolute(PathBuf::from("orcel-relative")))
        );
    }

    /// #358 item 2 and #384 item 4 on a real NTFS volume. `icacls` adds the
    /// entries another principal (Everyone, `S-1-1-0`) would hold.
    #[cfg(windows)]
    mod windows {
        use super::*;
        use crate::acl::{self, AceKind};

        const EVERYONE: &str = "S-1-1-0";

        fn grant(path: &Path, rights: &str) {
            let status = std::process::Command::new("icacls")
                .arg(path)
                .arg("/grant")
                .arg(format!("*{EVERYONE}:{rights}"))
                .stdout(std::process::Stdio::null())
                .status()
                .expect("icacls");
            assert!(status.success(), "icacls {} {rights}", path.display());
        }

        fn grants_everyone(path: &Path) -> bool {
            let (_, dacl) = acl::security_of(path).expect("security");
            dacl.expect("dacl")
                .iter()
                .any(|ace| ace.kind == AceKind::Allow && ace.sid == EVERYONE)
        }

        fn insecure(result: Result<(), PlatformError>, expected: &Path) {
            assert!(
                matches!(&result, Err(PlatformError::InsecureAcl { path, .. }) if path == expected),
                "{result:?}"
            );
        }

        #[test]
        fn missing_root_and_ancestors_are_created_with_a_protected_dacl() {
            let base = sandbox("win-create");
            // Everyone may read the parent, and that entry is inheritable.
            grant(&base, "(OI)(CI)(RX)");
            let root = base.join("missing").join("Orcel");
            assert_eq!(ensure_private_dir(&root), Ok(()));
            for created in [base.join("missing"), root.clone()] {
                assert!(created.is_dir());
                assert!(!grants_everyone(&created), "{}", created.display());
            }
            // Idempotent, and files created inside inherit the private DACL.
            assert_eq!(ensure_private_dir(&root), Ok(()));
            std::fs::write(root.join("state.json"), b"{}").expect("file");
            assert!(!grants_everyone(&root.join("state.json")));
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn an_existing_directory_others_can_reach_is_refused() {
            let base = sandbox("win-shared");
            let shared = base.join("shared");
            std::fs::create_dir(&shared).expect("dir");
            assert_eq!(ensure_private_dir(&shared), Ok(()));
            grant(&shared, "(RX)");
            insecure(ensure_private_dir(&shared), &shared);
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn an_ancestor_others_can_delete_from_is_refused_and_nothing_is_created() {
            let base = sandbox("win-ancestor");
            grant(&base, "(DC)");
            let root = base.join("Orcel");
            insecure(ensure_private_dir(&root), &base);
            assert!(!root.exists());
            let _ = std::fs::remove_dir_all(base);
        }

        /// Like a sticky `/tmp`: others may add entries, not replace ours.
        #[test]
        fn an_ancestor_others_can_only_add_to_is_accepted() {
            let base = sandbox("win-add");
            grant(&base, "(AD,WD)");
            assert_eq!(ensure_private_dir(&base.join("Orcel")), Ok(()));
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn files_and_junctions_are_refused() {
            let base = sandbox("win-links");
            let file = base.join("file");
            std::fs::write(&file, b"x").expect("file");
            assert_eq!(
                ensure_private_dir(&file),
                Err(PlatformError::NotDirectory(file.clone()))
            );
            let target = base.join("target");
            std::fs::create_dir(&target).expect("target");
            let junction = base.join("junction");
            let status = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&junction)
                .arg(&target)
                .stdout(std::process::Stdio::null())
                .status()
                .expect("mklink");
            assert!(status.success());
            assert_eq!(
                ensure_private_dir(&junction),
                Err(PlatformError::Symlink(junction.clone()))
            );
            assert_eq!(
                ensure_private_dir(&junction.join("Orcel")),
                Err(PlatformError::Symlink(junction.clone()))
            );
            assert!(!target.join("Orcel").exists());
            let _ = std::fs::remove_dir(&junction);
            let _ = std::fs::remove_dir_all(base);
        }

        /// The case #358 names: an `ORCEL_*_PATH` override in
        /// `C:\Users\Public`, which every interactive user can write.
        #[test]
        fn an_override_in_users_public_is_refused() {
            let public = Path::new(r"C:\Users\Public");
            if !public.is_dir() {
                return;
            }
            insecure(ensure_private_dir(public), public);
            assert!(matches!(
                private_file_override(OsString::from(r"C:\Users\Public\trust.jsonl")),
                Err(PlatformError::InsecureAcl { .. })
            ));
        }

        #[test]
        fn executables_others_can_replace_are_refused() {
            let base = sandbox("win-exe");
            let bin = base.join("bin");
            std::fs::create_dir(&bin).expect("bin");
            let tool = bin.join("tool.exe");
            std::fs::write(&tool, b"MZ").expect("tool");
            assert_eq!(check_owned_executable_location(&tool), Ok(()));
            // Reading and running are fine.
            grant(&tool, "(RX)");
            assert_eq!(check_owned_executable_location(&tool), Ok(()));
            grant(&tool, "(W)");
            assert!(check_owned_executable_location(&tool).is_err());

            let other = bin.join("other.exe");
            std::fs::write(&other, b"MZ").expect("other");
            grant(&bin, "(M)");
            let error = check_owned_executable_location(&other).expect_err("ancestor");
            assert!(error.contains(&bin.display().to_string()), "{error}");
            let _ = std::fs::remove_dir_all(base);
        }

        /// The system's own images pass: TrustedInstaller owns them and
        /// users may only read and run them.
        #[test]
        fn a_system32_image_is_accepted() {
            let root = std::env::var_os("SystemRoot").expect("SystemRoot");
            let whoami = Path::new(&root).join("System32").join("whoami.exe");
            assert_eq!(check_owned_executable_location(&whoami), Ok(()));
        }
    }

    #[cfg(unix)]
    mod unix {
        use super::*;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        fn set_mode(path: &Path, mode: u32) {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        }

        #[test]
        fn missing_root_and_ancestors_are_created_private() {
            let base = sandbox("create");
            let home = base.join("home");
            let root = state_root_for(
                StateLayout::Xdg,
                &lookup(&[("HOME", home.to_str().expect("utf-8"))]),
            )
            .expect("root");
            ensure_private_dir(&root).expect("created");
            for dir in [&root, &home.join(".local").join("state")] {
                let metadata = std::fs::symlink_metadata(dir).expect("metadata");
                assert!(metadata.is_dir());
                assert_eq!(
                    metadata.permissions().mode() & 0o077,
                    0,
                    "{}",
                    dir.display()
                );
                assert_eq!(metadata.uid(), imp::current_uid());
            }
            // Idempotent once private.
            ensure_private_dir(&root).expect("existing private root");
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn pre_created_symlink_root_is_refused() {
            let base = sandbox("symlink");
            let target = base.join("elsewhere");
            std::fs::create_dir(&target).expect("target");
            set_mode(&target, 0o700);
            let root = base.join("orcel");
            std::os::unix::fs::symlink(&target, &root).expect("symlink");
            assert_eq!(
                ensure_private_dir(&root),
                Err(PlatformError::Symlink(root.clone()))
            );
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn group_writable_root_is_refused() {
            let base = sandbox("group");
            let root = base.join("orcel");
            std::fs::create_dir(&root).expect("root");
            set_mode(&root, 0o770);
            assert_eq!(
                ensure_private_dir(&root),
                Err(PlatformError::InsecureMode {
                    path: root.clone(),
                    mode: 0o770
                })
            );
            // Not repaired: the mode is left for the person to inspect.
            let mode = std::fs::metadata(&root)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o770);
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn other_readable_root_is_refused() {
            let base = sandbox("other");
            let root = base.join("orcel");
            std::fs::create_dir(&root).expect("root");
            set_mode(&root, 0o705);
            assert!(matches!(
                ensure_private_dir(&root),
                Err(PlatformError::InsecureMode { mode: 0o705, .. })
            ));
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn non_directory_root_is_refused() {
            let base = sandbox("file");
            let root = base.join("orcel");
            std::fs::write(&root, b"x").expect("file");
            assert_eq!(
                ensure_private_dir(&root),
                Err(PlatformError::NotDirectory(root.clone()))
            );
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn foreign_owner_is_refused() {
            let base = sandbox("owner");
            set_mode(&base, 0o700);
            let metadata = std::fs::symlink_metadata(&base).expect("metadata");
            let other = metadata.uid().wrapping_add(1);
            assert_eq!(
                imp::verify(&base, &metadata, other),
                Err(PlatformError::ForeignOwner {
                    path: base.clone(),
                    owner: metadata.uid(),
                    expected: other,
                })
            );
            assert_eq!(imp::verify(&base, &metadata, metadata.uid()), Ok(()));
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn other_writable_parent_is_refused_and_nothing_is_created() {
            let base = sandbox("writable-parent");
            let parent = base.join("shared");
            std::fs::create_dir(&parent).expect("parent");
            set_mode(&parent, 0o777);
            let root = parent.join("orcel");
            assert_eq!(
                ensure_private_dir(&root),
                Err(PlatformError::WritableAncestor {
                    path: parent.clone(),
                    mode: 0o777
                })
            );
            assert!(std::fs::symlink_metadata(&root).is_err());
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn group_writable_parent_is_refused() {
            let base = sandbox("group-parent");
            let parent = base.join("group");
            std::fs::create_dir(&parent).expect("parent");
            set_mode(&parent, 0o770);
            assert!(matches!(
                ensure_private_dir(&parent.join("orcel")),
                Err(PlatformError::WritableAncestor { mode: 0o770, .. })
            ));
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn sticky_parent_not_owned_by_root_is_refused() {
            let base = sandbox("sticky");
            let parent = base.join("sticky");
            std::fs::create_dir(&parent).expect("parent");
            set_mode(&parent, 0o1777);
            // Only a root-owned sticky directory such as /tmp is exempt.
            assert!(matches!(
                ensure_private_dir(&parent.join("orcel")),
                Err(PlatformError::WritableAncestor { mode: 0o1777, .. })
            ));
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn symlinked_ancestor_into_a_writable_directory_is_refused() {
            let base = sandbox("symlink-ancestor");
            let shared = base.join("shared");
            std::fs::create_dir(&shared).expect("shared");
            set_mode(&shared, 0o777);
            let link = base.join("state");
            std::os::unix::fs::symlink(&shared, &link).expect("symlink");
            let root = link.join("orcel");
            let error = ensure_private_dir(&root).expect_err("writable link target");
            assert!(
                matches!(&error, PlatformError::WritableAncestor { path, mode: 0o777 }
                    if path.ends_with("shared")),
                "{error:?}"
            );
            assert!(std::fs::symlink_metadata(shared.join("orcel")).is_err());
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn symlinked_ancestor_into_a_private_directory_is_followed() {
            // The shape of macOS /var -> /private/var.
            let base = sandbox("symlink-private");
            let real = base.join("real");
            std::fs::create_dir(&real).expect("real");
            set_mode(&real, 0o700);
            let link = base.join("state");
            std::os::unix::fs::symlink(&real, &link).expect("symlink");
            ensure_private_dir(&link.join("orcel")).expect("private link target");
            assert!(real.join("orcel").is_dir());
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn nothing_is_created_below_a_link_into_a_writable_directory() {
            let base = sandbox("symlink-missing");
            let shared = base.join("shared");
            std::fs::create_dir(&shared).expect("shared");
            set_mode(&shared, 0o777);
            let link = base.join("state");
            std::os::unix::fs::symlink(&shared, &link).expect("symlink");
            // `a` is missing below the link, so it would be created first.
            let error = ensure_private_dir(&link.join("a").join("orcel")).expect_err("refused");
            assert!(
                matches!(&error, PlatformError::WritableAncestor { path, mode: 0o777 }
                    if path.ends_with("shared")),
                "{error:?}"
            );
            assert_eq!(
                std::fs::read_dir(&shared).expect("shared").count(),
                0,
                "nothing may be created in the link target"
            );
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn xdg_state_home_wins_over_a_valid_home() {
            let base = sandbox("xdg-wins");
            let home = base.join("home");
            let xdg = base.join("xdg");
            for dir in [&home, &xdg] {
                std::fs::create_dir(dir).expect("dir");
                set_mode(dir, 0o700);
            }
            let root = state_root_for(
                StateLayout::Xdg,
                &lookup(&[
                    ("HOME", home.to_str().expect("utf-8")),
                    ("XDG_STATE_HOME", xdg.to_str().expect("utf-8")),
                ]),
            )
            .expect("root");
            assert_eq!(root, xdg.join("orcel"));
            ensure_private_dir(&root).expect("private root");
            assert!(xdg.join("orcel").is_dir());
            assert!(std::fs::symlink_metadata(home.join(".local")).is_err());
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn group_writable_home_is_refused_by_name() {
            let base = sandbox("home-0775");
            let home = base.join("home");
            std::fs::create_dir(&home).expect("home");
            set_mode(&home, 0o775);
            let root = state_root_for(
                StateLayout::Xdg,
                &lookup(&[("HOME", home.to_str().expect("utf-8"))]),
            )
            .expect("root");
            assert_eq!(
                ensure_private_dir(&root),
                Err(PlatformError::WritableAncestor {
                    path: home.clone(),
                    mode: 0o775
                })
            );
            assert!(std::fs::symlink_metadata(home.join(".local")).is_err());
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn foreign_owned_ancestor_is_refused() {
            let base = sandbox("foreign-ancestor");
            let me = imp::current_uid();
            let other = me.wrapping_add(1);
            let root = base.join("orcel");
            // The sandbox is owned by the current uid, so for `other` it is an
            // ancestor owned by someone who is neither that uid nor root.
            let error = imp::ensure_private_dir_as(&root, other).expect_err("foreign");
            assert!(
                matches!(&error, PlatformError::ForeignOwner { owner, expected, .. }
                    if *owner == me && *expected == other),
                "{error:?}"
            );
            assert!(std::fs::symlink_metadata(&root).is_err());
            let _ = std::fs::remove_dir_all(base);
        }
    }

    /// #384 item 1: a `chmod +a` grant does not show in the mode bits.
    #[cfg(target_os = "macos")]
    mod macos {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn add_acl(path: &Path, entry: &str) {
            let status = std::process::Command::new("/bin/chmod")
                .arg("+a")
                .arg(entry)
                .arg(path)
                .status()
                .expect("chmod +a");
            assert!(status.success(), "chmod +a {entry} {}", path.display());
        }

        fn acl_refused(result: Result<(), PlatformError>, expected: &Path) {
            assert!(
                matches!(&result, Err(PlatformError::InsecureAcl { path, .. }) if path == expected),
                "{result:?}"
            );
        }

        #[test]
        fn an_acl_entry_on_the_private_dir_is_refused() {
            let base = sandbox("acl-root");
            let root = base.join("orcel");
            assert_eq!(ensure_private_dir(&root), Ok(()));
            // Even a read-only grant: the directory is the 0700 counterpart.
            add_acl(&root, "everyone allow list,search");
            acl_refused(ensure_private_dir(&root), &root);
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn a_write_acl_on_an_ancestor_is_refused_and_a_deny_is_not() {
            let base = sandbox("acl-ancestor");
            let parent = base.join("parent");
            std::fs::create_dir(&parent).expect("parent");
            add_acl(&parent, "everyone deny delete");
            assert_eq!(ensure_private_dir(&parent.join("a")), Ok(()));
            add_acl(&parent, "everyone allow add_file,delete_child");
            acl_refused(ensure_private_dir(&parent.join("b")), &parent);
            assert!(!parent.join("b").exists());
            let _ = std::fs::remove_dir_all(base);
        }

        #[test]
        fn a_write_acl_on_an_executable_or_its_directory_is_refused() {
            let base = sandbox("acl-exe");
            let bin = base.join("bin");
            std::fs::create_dir(&bin).expect("bin");
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod");
            let tool = bin.join("tool");
            std::fs::write(&tool, b"\xcf\xfa\xed\xfe").expect("tool");
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).expect("chmod");
            assert_eq!(check_owned_executable_location(&tool), Ok(()));
            add_acl(&tool, "everyone allow read,execute");
            assert_eq!(check_owned_executable_location(&tool), Ok(()));
            add_acl(&tool, "everyone allow write");
            assert!(check_owned_executable_location(&tool).is_err());

            let other = bin.join("other");
            std::fs::write(&other, b"\xcf\xfa\xed\xfe").expect("other");
            std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
            add_acl(&bin, "everyone allow delete_child");
            let error = check_owned_executable_location(&other).expect_err("ancestor");
            assert!(error.contains("delete_child"), "{error}");
            let _ = std::fs::remove_dir_all(base);
        }
    }
}
