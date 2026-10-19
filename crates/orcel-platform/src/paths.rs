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
/// Nothing is repaired.
///
/// On Windows the directory keeps its existing behavior: it inherits the
/// per-user `%LOCALAPPDATA%` ACL and is created by its first writer, so
/// only an existing non-directory is refused.
pub fn ensure_private_dir(path: &Path) -> Result<(), PlatformError> {
    if !path.is_absolute() {
        return Err(PlatformError::NotAbsolute(path.to_path_buf()));
    }
    imp::ensure_private_dir(path)
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

fn unavailable(variables: &str) -> PlatformError {
    PlatformError::StateRootUnavailable(format!("{variables} is not set to an absolute path"))
}

fn absolute_var(
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

#[cfg(not(unix))]
mod imp {
    use super::{io_error, PlatformError};
    use std::path::Path;

    pub(super) fn ensure_private_dir(path: &Path) -> Result<(), PlatformError> {
        match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_dir() => Ok(()),
            Ok(_) => Err(PlatformError::NotDirectory(path.to_path_buf())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(path, error)),
        }
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

    #[cfg(not(unix))]
    #[test]
    fn windows_keeps_missing_and_existing_directories_and_refuses_files() {
        let base = sandbox("win");
        let missing = base.join("missing").join("Orcel");
        assert_eq!(ensure_private_dir(&missing), Ok(()));
        // No directory is created on Windows; its first writer creates it.
        assert!(!missing.exists());
        assert_eq!(ensure_private_dir(&base), Ok(()));
        let file = base.join("file");
        std::fs::write(&file, b"x").expect("file");
        assert_eq!(
            ensure_private_dir(&file),
            Err(PlatformError::NotDirectory(file.clone()))
        );
        let _ = std::fs::remove_dir_all(base);
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
}
