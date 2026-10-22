//! Which `orceld` the CLI starts for a one-shot local request on Linux and
//! macOS (#382 item 6, XP-17).
//!
//! Windows runs the active version of the verified per-user install. Other
//! OSes have no such payload (see [`crate::layout::Layout`]): `orceld` is the
//! one installed next to this `orcel` (a tarball or source build), else on
//! Linux the deb/rpm binary in [`crate::linux::PACKAGE_LIB_DIR`]. Never
//! `PATH`, never an environment variable.
//!
//! A candidate is used only under the rule XP-10 applies to its approval
//! helper and XP-06 to the native host: the canonical path is a regular
//! file owned by root or this user that nobody else can write, and every
//! ancestor directory up to `/` is owned by root or this user and writable
//! by nobody else. A binary dropped in `/tmp` or a group-writable directory
//! is refused.

#[cfg(unix)]
use crate::LifecycleError;
use std::path::{Path, PathBuf};

/// `orceld`'s file name on Linux and macOS.
pub const ORCELD_FILE_NAME: &str = "orceld";

/// Whether a file or directory with this owner and mode may be trusted:
/// owned by root or `euid`, and writable by nobody else.
pub fn owner_and_mode_trusted(uid: u32, mode: u32, euid: u32) -> bool {
    (uid == 0 || uid == euid) && mode & 0o022 == 0
}

/// The candidates in order: next to the canonical `current_exe`, then the
/// package location on Linux.
pub fn candidates(current_exe: Option<&Path>) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = current_exe
        .and_then(|exe| std::fs::canonicalize(exe).ok())
        .and_then(|exe| exe.parent().map(|dir| dir.join(ORCELD_FILE_NAME)))
        .into_iter()
        .collect();
    if cfg!(target_os = "linux") {
        found.push(Path::new(crate::linux::PACKAGE_LIB_DIR).join(ORCELD_FILE_NAME));
    }
    found
}

/// The first existing candidate, checked as described above. A candidate
/// that exists but fails the check is an error, never skipped for the next.
#[cfg(unix)]
pub fn trusted_orceld(candidates: &[PathBuf], euid: u32) -> Result<PathBuf, LifecycleError> {
    use std::os::unix::fs::MetadataExt;
    let Some(candidate) = candidates.iter().find(|candidate| candidate.exists()) else {
        return Err(LifecycleError::not_installed(format!(
            "orceld is not installed next to orcel{}",
            if cfg!(target_os = "linux") {
                format!(" or in {}", crate::linux::PACKAGE_LIB_DIR)
            } else {
                String::new()
            }
        )));
    };
    let refuse = |what: &Path| {
        LifecycleError::state(format!(
            "refusing to start {}: {} is not owned by root or this user, or another user can write it",
            candidate.display(),
            what.display()
        ))
    };
    let canonical = std::fs::canonicalize(candidate)
        .map_err(|error| LifecycleError::io(format!("resolve {}", candidate.display()), error))?;
    let meta = std::fs::metadata(&canonical)
        .map_err(|error| LifecycleError::io(format!("inspect {}", canonical.display()), error))?;
    if !meta.is_file() || !owner_and_mode_trusted(meta.uid(), meta.mode(), euid) {
        return Err(refuse(&canonical));
    }
    for dir in canonical.ancestors().skip(1) {
        let meta = std::fs::metadata(dir)
            .map_err(|error| LifecycleError::io(format!("inspect {}", dir.display()), error))?;
        if !owner_and_mode_trusted(meta.uid(), meta.mode(), euid) {
            return Err(refuse(dir));
        }
    }
    Ok(canonical)
}

/// The `orceld` of this Linux or macOS machine for the current user.
#[cfg(unix)]
pub fn resolve() -> Result<PathBuf, LifecycleError> {
    let euid = orcel_platform::session::effective_uid()
        .ok_or_else(|| LifecycleError::platform("the current uid is unknown"))?;
    let exe = std::env::current_exe().ok();
    trusted_orceld(&candidates(exe.as_deref()), euid)
}

/// The variables `orceld` needs on Linux and macOS to find this user's
/// state root and secret store, which the CLI's Windows-shaped child
/// environment ([`crate::ipc::child_environment`]) leaves out: `HOME`, the
/// XDG state and runtime directories and, for the Secret Service, the
/// session bus address (which `orceld` accepts only as a local Unix socket).
/// None of them is a secret. Empty on Windows.
pub fn session_env(lookup: &dyn Fn(&str) -> Option<String>) -> Vec<(&'static str, String)> {
    const NAMES: [&str; 4] = [
        "HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
    ];
    if cfg!(windows) {
        return Vec::new();
    }
    NAMES
        .into_iter()
        .filter_map(|name| lookup(name).map(|value| (name, value)))
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn session_env_passes_only_the_named_variables_off_windows() {
        let lookup = |name: &str| (name != "XDG_STATE_HOME").then(|| format!("v-{name}"));
        let env = session_env(&lookup);
        if cfg!(windows) {
            assert!(env.is_empty());
        } else {
            assert_eq!(
                env,
                vec![
                    ("HOME", "v-HOME".to_owned()),
                    ("XDG_RUNTIME_DIR", "v-XDG_RUNTIME_DIR".to_owned()),
                    (
                        "DBUS_SESSION_BUS_ADDRESS",
                        "v-DBUS_SESSION_BUS_ADDRESS".to_owned()
                    ),
                ]
            );
        }
    }

    use super::*;

    #[test]
    fn owner_and_mode_rule_matches_xp10() {
        assert!(owner_and_mode_trusted(0, 0o755, 501));
        assert!(owner_and_mode_trusted(501, 0o700, 501));
        assert!(!owner_and_mode_trusted(502, 0o755, 501));
        assert!(!owner_and_mode_trusted(501, 0o775, 501));
        assert!(!owner_and_mode_trusted(0, 0o757, 501));
        assert!(!owner_and_mode_trusted(0, 0o1777, 501));
    }

    #[test]
    fn candidates_are_the_sibling_then_the_package() {
        let exe = std::env::current_exe().unwrap();
        let found = candidates(Some(&exe));
        let sibling = std::fs::canonicalize(&exe)
            .unwrap()
            .parent()
            .unwrap()
            .join(ORCELD_FILE_NAME);
        assert_eq!(found[0], sibling);
        if cfg!(target_os = "linux") {
            assert_eq!(found[1], Path::new("/usr/lib/orcel/orceld"));
            assert_eq!(found.len(), 2);
        } else {
            assert_eq!(found.len(), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn only_a_private_orceld_is_trusted() {
        use std::os::unix::fs::PermissionsExt;
        let euid = orcel_platform::session::effective_uid().unwrap();
        let dir = crate::test_support::temp_dir("orceld-path");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let orceld = dir.join(ORCELD_FILE_NAME);
        let candidates = [orceld.clone()];
        assert!(matches!(
            trusted_orceld(&candidates, euid),
            Err(error) if error.to_string().contains("not installed")
        ));
        std::fs::write(&orceld, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&orceld, std::fs::Permissions::from_mode(0o755)).unwrap();
        // The temp dir's ancestors (for example a sticky, world-writable
        // /tmp) decide; the file itself must pass only when they do.
        let ancestors_ok = dir.ancestors().all(|ancestor| {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(ancestor)
                .is_ok_and(|meta| owner_and_mode_trusted(meta.uid(), meta.mode(), euid))
        });
        assert_eq!(trusted_orceld(&candidates, euid).is_ok(), ancestors_ok);
        std::fs::set_permissions(&orceld, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(trusted_orceld(&candidates, euid).is_err());
        std::fs::set_permissions(&orceld, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(trusted_orceld(&candidates, euid).is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        // A symlink in a trusted place to a file elsewhere is judged by
        // its target.
        let link_dir = crate::test_support::temp_dir("orceld-link");
        let link = link_dir.join(ORCELD_FILE_NAME);
        std::os::unix::fs::symlink("/tmp", &link).unwrap();
        assert!(trusted_orceld(&[link], euid).is_err());
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(link_dir);
    }

    /// #417: the success path, in a private directory beside the test binary
    /// (under the build tree, not a sticky, world-writable temp directory), so
    /// the ancestors are the checkout's own. On Linux CI that chain must be
    /// trusted, so a pass means `trusted_orceld` returned the file.
    #[cfg(unix)]
    #[test]
    fn a_private_orceld_in_a_trusted_tree_is_accepted() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let euid = orcel_platform::session::effective_uid().unwrap();
        let base = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let dir = base.join(format!("orceld-path-trusted-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let orceld = dir.join(ORCELD_FILE_NAME);
        std::fs::write(&orceld, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&orceld, std::fs::Permissions::from_mode(0o755)).unwrap();
        let canonical = std::fs::canonicalize(&orceld).unwrap();
        let chain_trusted = canonical.ancestors().all(|ancestor| {
            std::fs::metadata(ancestor)
                .is_ok_and(|meta| owner_and_mode_trusted(meta.uid(), meta.mode(), euid))
        });
        if cfg!(target_os = "linux") && std::env::var_os("CI").is_some() {
            assert!(chain_trusted, "the CI build tree must be a trusted chain");
        }
        if chain_trusted {
            assert_eq!(
                trusted_orceld(std::slice::from_ref(&orceld), euid).unwrap(),
                canonical
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
