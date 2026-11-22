//! MAC-M1-03: the per-user install tree on macOS (and its owner and mode
//! rules on every Unix).
//!
//! The install lives under the XP-01 state root, which on macOS is
//! `~/Library/Application Support/Orcel` ([`crate::layout::Layout`]):
//! `versions/<version>/` holds the hash-checked payload, `current.json`
//! points at the active version, `install.json` records it, and `bin/orcel`
//! is a copy of the active CLI. The same layout and the same
//! [`crate::install::Installer`] as on Windows; only the host operations
//! differ, and they take the place of the Windows owner-only DACL:
//!
//! - [`protect_tree`]: the root is made 0700 and must then pass XP-01's
//!   private-directory rule ([`orcel_platform::paths::verify_existing_private_dir`]:
//!   owned by the user, 0700, no extended ACL grant, and every ancestor owned
//!   by the user or root and not writable by group or others, so a root under
//!   an admin-writable folder such as `/Applications` is refused). Every
//!   entry beneath loses its group and other bits. A link, an entry of
//!   another owner, or anything but a file or a folder fails closed and
//!   nothing further is changed.
//! - [`verify_tree`]: the same root rule, then every entry beneath must be
//!   this user's, not a link, not writable by group or others, and a file
//!   must have no other hard link
//!   ([`orcel_platform::paths::check_migration_entry`]).
//!
//! Hashes and unlisted files are the manifest's job
//! ([`crate::manifest::verify_payload`]), which also refuses a hard-linked
//! payload file on Unix.
//!
//! [`MacosPlatform`] exists on macOS only, and `host_platform()` does not
//! return it yet: the `orcel` lifecycle commands on macOS wait for the
//! founder's activation of the macOS M1 grain (approval 1 in
//! `MACOS_M0_READINESS.md`). Until then it is reached from tests on the
//! hosted macOS runner only.

use crate::LifecycleError;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// The macOS release the install supports at least (MAC-M1-01's deployment
/// target).
pub const MIN_MACOS_MAJOR: u32 = 15;

fn effective_uid() -> Result<u32, LifecycleError> {
    orcel_platform::session::effective_uid()
        .ok_or_else(|| LifecycleError::platform("the effective user id is unavailable"))
}

fn refuse(path: &Path, why: &str) -> LifecycleError {
    LifecycleError::state(format!(
        "the Orcel install tree is not private to you and was not changed further: {} {why}",
        path.display()
    ))
}

/// Makes `root` and everything beneath it private to the user (see the
/// module documentation).
pub fn protect_tree(root: &Path) -> Result<(), LifecycleError> {
    let uid = effective_uid()?;
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| LifecycleError::io(format!("inspect {}", root.display()), error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(refuse(root, "is not a plain folder"));
    }
    if metadata.uid() != uid {
        return Err(refuse(root, "is owned by another user"));
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))
        .map_err(|error| LifecycleError::io(format!("protect {}", root.display()), error))?;
    orcel_platform::paths::verify_existing_private_dir(root)
        .map_err(|error| LifecycleError::state(format!("the Orcel install root: {error}")))?;
    protect_children(root, uid)
}

fn protect_children(dir: &Path, uid: u32) -> Result<(), LifecycleError> {
    let entries = fs::read_dir(dir)
        .map_err(|error| LifecycleError::io(format!("read {}", dir.display()), error))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| LifecycleError::io(format!("read {}", dir.display()), error))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| LifecycleError::io(format!("inspect {}", path.display()), error))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(refuse(&path, "is a link"));
        }
        if metadata.uid() != uid {
            return Err(refuse(&path, "is owned by another user"));
        }
        if file_type.is_dir() {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|error| {
                LifecycleError::io(format!("protect {}", path.display()), error)
            })?;
            protect_children(&path, uid)?;
        } else if file_type.is_file() {
            let mode = metadata.mode() & 0o700;
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).map_err(|error| {
                LifecycleError::io(format!("protect {}", path.display()), error)
            })?;
        } else {
            return Err(refuse(&path, "is neither a file nor a folder"));
        }
    }
    Ok(())
}

/// Verifies that `root` and everything beneath it are private to the user
/// (see the module documentation). Changes nothing.
pub fn verify_tree(root: &Path) -> Result<(), LifecycleError> {
    orcel_platform::paths::verify_existing_private_dir(root)
        .map_err(|error| LifecycleError::state(format!("the Orcel install root: {error}")))?;
    verify_children(root)
}

fn verify_children(dir: &Path) -> Result<(), LifecycleError> {
    let entries = fs::read_dir(dir)
        .map_err(|error| LifecycleError::io(format!("read {}", dir.display()), error))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| LifecycleError::io(format!("read {}", dir.display()), error))?;
        let path = entry.path();
        orcel_platform::paths::check_migration_entry(&path)
            .map_err(|reason| LifecycleError::state(format!("the Orcel install tree: {reason}")))?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| LifecycleError::io(format!("inspect {}", path.display()), error))?;
        if metadata.is_dir() {
            verify_children(&path)?;
        } else if !metadata.is_file() {
            return Err(refuse(&path, "is neither a file nor a folder"));
        }
    }
    Ok(())
}

/// Parses `sw_vers -productVersion` output such as `15.8.2` into its major
/// version.
pub fn parse_macos_major(output: &str) -> Result<u32, LifecycleError> {
    let text = output.trim();
    text.split('.')
        .next()
        .filter(|major| !major.is_empty() && major.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|major| major.parse().ok())
        .ok_or_else(|| LifecycleError::prerequisite(format!("unexpected macOS version {text:?}")))
}

#[cfg(target_os = "macos")]
pub use macos::MacosPlatform;

#[cfg(target_os = "macos")]
mod macos {
    use super::{parse_macos_major, MIN_MACOS_MAJOR};
    use crate::platform::Platform;
    use crate::version::Version;
    use crate::LifecycleError;
    use std::path::Path;

    /// The macOS host operations of the per-user install (MAC-M1-03).
    #[derive(Debug, Default)]
    pub struct MacosPlatform;

    impl Platform for MacosPlatform {
        fn windows_build(&self) -> Result<u32, LifecycleError> {
            Err(LifecycleError::prerequisite("this is macOS, not Windows"))
        }
        /// Running as root is the avoidable elevation on macOS: the
        /// install is per user and needs no administrator rights.
        fn is_avoidably_elevated(&self) -> Result<bool, LifecycleError> {
            Ok(super::effective_uid()? == 0)
        }
        fn protect_tree(&self, root: &Path) -> Result<(), LifecycleError> {
            super::protect_tree(root)
        }
        fn verify_tree_acl(&self, root: &Path) -> Result<(), LifecycleError> {
            super::verify_tree(root)
        }
        /// The user's shell `PATH` is not managed on macOS; nothing is
        /// added (`bin/orcel` is used by its full path).
        fn add_user_path(&self, _dir: &Path) -> Result<bool, LifecycleError> {
            Ok(false)
        }
        fn remove_user_path(&self, _dir: &Path) -> Result<bool, LifecycleError> {
            Ok(false)
        }
        fn add_start_menu_entry(&self, _cli: &Path) -> Result<(), LifecycleError> {
            Err(LifecycleError::platform("macOS has no Start Menu"))
        }
        fn remove_start_menu_entry(&self, _cli: &Path) -> Result<bool, LifecycleError> {
            Ok(false)
        }
        fn has_start_menu_entry(&self, _cli: &Path) -> Result<bool, LifecycleError> {
            Ok(false)
        }
        fn node_version(&self, node: &Path) -> Result<Version, LifecycleError> {
            crate::platform::run_node_version(node)
        }
        /// macOS 15 or later, read from `/usr/bin/sw_vers` by absolute path.
        fn check_os_version(&self) -> Result<(), LifecycleError> {
            let output = std::process::Command::new("/usr/bin/sw_vers")
                .arg("-productVersion")
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output()
                .map_err(|error| {
                    LifecycleError::prerequisite(format!("read the macOS version: {error}"))
                })?;
            if !output.status.success() {
                return Err(LifecycleError::prerequisite(
                    "sw_vers could not read the macOS version",
                ));
            }
            let major = parse_macos_major(&String::from_utf8_lossy(&output.stdout))?;
            if major < MIN_MACOS_MAJOR {
                return Err(LifecycleError::prerequisite(format!(
                    "macOS {major} is older than the supported minimum macOS {MIN_MACOS_MAJOR}"
                )));
            }
            Ok(())
        }
        fn check_lifecycle_supported(&self) -> Result<(), LifecycleError> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_dir;

    /// A parent folder 0755 whatever the umask, so only what a test changes
    /// is insecure.
    fn parent(label: &str) -> std::path::PathBuf {
        let dir = temp_dir(label);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        dir
    }

    fn private_root(label: &str) -> std::path::PathBuf {
        let root = parent(label).join("Orcel");
        fs::create_dir_all(root.join("versions/0.2.0")).unwrap();
        fs::write(root.join("versions/0.2.0/orceld"), b"x").unwrap();
        fs::set_permissions(
            root.join("versions/0.2.0/orceld"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        root
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o777
    }

    #[test]
    fn protect_strips_group_and_other_bits_and_verify_then_passes() {
        let root = private_root("unix-protect");
        protect_tree(&root).unwrap();
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&root.join("versions")), 0o700);
        assert_eq!(mode(&root.join("versions/0.2.0/orceld")), 0o700);
        verify_tree(&root).unwrap();
    }

    #[test]
    fn a_group_writable_entry_fails_verification() {
        let root = private_root("unix-group-write");
        protect_tree(&root).unwrap();
        let file = root.join("versions/0.2.0/orceld");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o720)).unwrap();
        assert!(verify_tree(&root).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(root.join("versions"), fs::Permissions::from_mode(0o702)).unwrap();
        assert!(verify_tree(&root).is_err());
    }

    #[test]
    fn a_readable_root_fails_verification() {
        let root = private_root("unix-root-mode");
        protect_tree(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(verify_tree(&root).is_err());
    }

    #[test]
    fn links_fail_closed_in_protect_and_verify() {
        let root = private_root("unix-link");
        protect_tree(&root).unwrap();
        let outside = parent("unix-link-target");
        std::os::unix::fs::symlink(&outside, root.join("versions/escape")).unwrap();
        assert!(verify_tree(&root).is_err());
        assert!(protect_tree(&root).is_err());
        // The link target was never touched.
        assert_ne!(mode(&outside), 0o700);
    }

    #[test]
    fn a_hard_linked_file_fails_verification() {
        let root = private_root("unix-hardlink");
        protect_tree(&root).unwrap();
        let alias = temp_dir("unix-hardlink-alias").join("alias");
        fs::hard_link(root.join("versions/0.2.0/orceld"), alias).unwrap();
        assert!(verify_tree(&root).is_err());
    }

    #[test]
    fn a_root_under_a_group_writable_folder_is_refused() {
        // The shape of /Applications (root:admin 0775): writable by a group.
        let shared = temp_dir("unix-shared-parent");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o775)).unwrap();
        let root = shared.join("Orcel");
        fs::create_dir_all(&root).unwrap();
        assert!(protect_tree(&root).is_err());
        assert!(verify_tree(&root).is_err());
    }

    #[test]
    fn macos_versions_parse_strictly() {
        assert_eq!(parse_macos_major("15.8.2\n").unwrap(), 15);
        assert_eq!(parse_macos_major("26.7.2").unwrap(), 26);
        assert_eq!(parse_macos_major("15").unwrap(), 15);
        for bad in ["", "x.1", "-15.0", " .1"] {
            assert!(parse_macos_major(bad).is_err(), "{bad:?}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn this_runner_is_a_supported_macos_and_not_root() {
        use crate::platform::Platform;
        let platform = MacosPlatform;
        platform.check_os_version().unwrap();
        assert!(!platform.is_avoidably_elevated().unwrap());
        platform.check_lifecycle_supported().unwrap();
        assert!(platform.windows_build().is_err());
    }
}
