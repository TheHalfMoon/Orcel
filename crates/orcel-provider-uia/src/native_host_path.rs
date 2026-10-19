// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//
// XP-06: which `orcel-native-host` binary orceld may start on macOS and
// Linux. ORCEL_COMPUTER_HOST_BIN only selects the host; it is trusted only
// when it names the pinned binary, under the rule XP-10 applies to its
// approval helper (`orcel-approval/src/linux.rs`, `trusted_file` and
// `helper_path`):
//
// - an absolute path that is already canonical: no `PATH` lookup, no
//   symlink, no `..`;
// - next to the running orceld, or at `/usr/libexec/orcel/orcel-native-host`;
// - a regular file owned by root or this user that nobody else can write,
//   in directories that are owned by root or this user and that nobody else
//   can write, up to `/`.
//
// Anything else is refused before the binary is started, so a file dropped
// in /tmp or a name resolved through PATH never becomes the observation host.
//
// The check records the file's device and inode, and the adapter re-reads
// them (with owner and mode) immediately before it spawns the host
// (`TrustedHostBinary::verify_unchanged`), so a file swapped or loosened
// after the check is refused. The remaining window between that re-read and
// exec is open only to root and this user, because every directory on the
// path must be writable by nobody else, and those can already replace orceld.
//
// macOS packaging (XP-16): `/Applications` is `root:admin` mode 0775, which
// this rule refuses, so a host inside `/Applications/Orcel.app` is not
// trusted. The rule is not relaxed to admin-group directories: any admin user
// could then swap the host of another user. XP-16 must install the host where
// every ancestor is owned by root or the user and writable by nobody else
// (for example a per-user `~/Applications` bundle, or a root:wheel 0755
// location), and keep a test for it.

#[cfg(unix)]
use crate::UiaError;
#[cfg(unix)]
use orcel_contracts::FailureCode;
#[cfg(unix)]
use std::path::{Path, PathBuf};

/// The host's file name.
pub const NATIVE_HOST_FILE_NAME: &str = "orcel-native-host";
/// Where packages install the host when it is not next to orceld.
pub const SYSTEM_NATIVE_HOST_PATH: &str = "/usr/libexec/orcel/orcel-native-host";

#[cfg(unix)]
fn refused(message: String) -> UiaError {
    UiaError::new(FailureCode::ProviderUnavailable, message)
}

/// Whether a file or directory with this owner and mode may be trusted:
/// owned by root or by `euid`, and writable by nobody else.
pub fn owner_and_mode_trusted(uid: u32, mode: u32, euid: u32) -> bool {
    (uid == 0 || uid == euid) && mode & 0o022 == 0
}

/// The pinned host as it was checked: its canonical path and the device
/// and inode of the file at check time.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedHostBinary {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

#[cfg(unix)]
impl TrustedHostBinary {
    fn recorded(path: PathBuf, meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            path,
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-reads the file right before it is started. It must still be the
    /// same file (device and inode), not a symlink, owned by root or this
    /// user and writable by nobody else.
    pub fn verify_unchanged(&self) -> Result<(), UiaError> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(&self.path)
            .map_err(|error| refused(format!("{}: {error}", self.path.display())))?;
        if !meta.file_type().is_file() || meta.dev() != self.dev || meta.ino() != self.ino {
            return Err(refused(format!(
                "{} changed since it was checked",
                self.path.display()
            )));
        }
        let euid = orcel_platform::session::effective_uid()
            .ok_or_else(|| refused("this process's uid is unreadable".to_owned()))?;
        if !owner_and_mode_trusted(meta.uid(), meta.mode(), euid) {
            return Err(refused(format!(
                "{} changed owner or mode since it was checked",
                self.path.display()
            )));
        }
        Ok(())
    }

    /// The identity of `path` without the location and ancestor checks,
    /// for tests of the re-check itself.
    #[cfg(test)]
    pub(crate) fn record_for_test(path: &Path) -> Self {
        Self::recorded(path.to_path_buf(), &std::fs::metadata(path).unwrap())
    }
}

/// The pinned host `configured` names, checked as described above.
/// `orceld_dir` is the canonical directory of the running orceld.
#[cfg(unix)]
pub fn trusted_native_host_path(
    configured: &Path,
    orceld_dir: Option<&Path>,
) -> Result<TrustedHostBinary, UiaError> {
    use std::os::unix::fs::MetadataExt;

    if !configured.is_absolute() {
        return Err(refused(format!(
            "ORCEL_COMPUTER_HOST_BIN must be an absolute path, not {}",
            configured.display()
        )));
    }
    let canonical = std::fs::canonicalize(configured)
        .map_err(|error| refused(format!("{}: {error}", configured.display())))?;
    if canonical != configured {
        return Err(refused(format!(
            "ORCEL_COMPUTER_HOST_BIN must be canonical (no symlink): {} resolves to {}",
            configured.display(),
            canonical.display()
        )));
    }
    let pinned = orceld_dir
        .map(|dir| dir.join(NATIVE_HOST_FILE_NAME))
        .into_iter()
        .chain(std::iter::once(PathBuf::from(SYSTEM_NATIVE_HOST_PATH)))
        .any(|candidate| candidate == canonical);
    if !pinned {
        return Err(refused(format!(
            "{} is neither next to orceld nor {SYSTEM_NATIVE_HOST_PATH}",
            canonical.display()
        )));
    }
    let euid = orcel_platform::session::effective_uid()
        .ok_or_else(|| refused("this process's uid is unreadable".to_owned()))?;
    let meta = std::fs::metadata(&canonical)
        .map_err(|error| refused(format!("{}: {error}", canonical.display())))?;
    if !meta.is_file() || !owner_and_mode_trusted(meta.uid(), meta.mode(), euid) {
        return Err(refused(format!(
            "{} is not a file owned by root or this user that only its owner can write",
            canonical.display()
        )));
    }
    for dir in canonical.ancestors().skip(1) {
        let meta = std::fs::metadata(dir)
            .map_err(|error| refused(format!("{}: {error}", dir.display())))?;
        if !owner_and_mode_trusted(meta.uid(), meta.mode(), euid) {
            return Err(refused(format!(
                "{} can be written by another user",
                dir.display()
            )));
        }
    }
    Ok(TrustedHostBinary::recorded(canonical, &meta))
}

#[cfg(test)]
mod tests {
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

    #[cfg(unix)]
    mod unix {
        use super::super::*;
        use std::os::unix::fs::PermissionsExt;

        /// A private directory next to this test binary, standing in for
        /// the directory of orceld.
        struct Fixture {
            dir: PathBuf,
        }

        impl Fixture {
            fn new(label: &str) -> Self {
                let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
                let dir = exe
                    .parent()
                    .unwrap()
                    .join(format!("xp06-{label}-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir(&dir).unwrap();
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
                Self { dir }
            }

            fn host(&self, mode: u32) -> PathBuf {
                let path = self.dir.join(NATIVE_HOST_FILE_NAME);
                std::fs::write(&path, b"host").unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
                path
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.dir);
            }
        }

        fn ancestors_trusted(dir: &Path) -> bool {
            use std::os::unix::fs::MetadataExt;
            let euid = orcel_platform::session::effective_uid().unwrap();
            dir.ancestors().all(|dir| {
                std::fs::metadata(dir)
                    .is_ok_and(|meta| owner_and_mode_trusted(meta.uid(), meta.mode(), euid))
            })
        }

        #[test]
        fn xp06_pinned_host_next_to_orceld_is_accepted() {
            let fixture = Fixture::new("pinned");
            let host = fixture.host(0o755);
            let result = trusted_native_host_path(&host, Some(&fixture.dir));
            if ancestors_trusted(&fixture.dir) {
                assert_eq!(result.unwrap().path(), host);
            } else {
                // A checkout under a directory others can write is refused.
                assert!(result.is_err());
            }
        }

        #[test]
        fn xp06_host_outside_the_pinned_locations_is_refused() {
            let fixture = Fixture::new("elsewhere");
            let host = fixture.host(0o755);
            let other = fixture.dir.join("not-orceld");
            let error = trusted_native_host_path(&host, Some(&other)).unwrap_err();
            assert!(
                error.message.contains("neither next to orceld"),
                "{error:?}"
            );
            // A copy dropped in /tmp, which everyone can write.
            let dropped = Path::new("/tmp").join(format!(
                "xp06-dropped-{}-{NATIVE_HOST_FILE_NAME}",
                std::process::id()
            ));
            std::fs::write(&dropped, b"host").unwrap();
            let refused = trusted_native_host_path(&dropped, Some(Path::new("/tmp")));
            let _ = std::fs::remove_file(&dropped);
            assert!(refused.is_err());
            let tmp_named = Path::new("/tmp").join(NATIVE_HOST_FILE_NAME);
            assert!(trusted_native_host_path(&tmp_named, Some(Path::new("/tmp"))).is_err());
        }

        #[test]
        fn xp06_path_lookup_and_symlinks_are_refused() {
            let fixture = Fixture::new("names");
            let host = fixture.host(0o755);
            let bare = Path::new(NATIVE_HOST_FILE_NAME);
            let error = trusted_native_host_path(bare, Some(&fixture.dir)).unwrap_err();
            assert!(error.message.contains("absolute"), "{error:?}");
            let link_dir = fixture.dir.join("links");
            std::fs::create_dir(&link_dir).unwrap();
            let link = link_dir.join(NATIVE_HOST_FILE_NAME);
            std::os::unix::fs::symlink(&host, &link).unwrap();
            let error = trusted_native_host_path(&link, Some(&link_dir)).unwrap_err();
            assert!(error.message.contains("canonical"), "{error:?}");
            let dotted = fixture
                .dir
                .join("links")
                .join("..")
                .join(NATIVE_HOST_FILE_NAME);
            assert!(trusted_native_host_path(&dotted, Some(&fixture.dir)).is_err());
        }

        #[test]
        fn xp06_host_swapped_after_the_check_is_refused_before_spawn() {
            let fixture = Fixture::new("swapped");
            let host = fixture.host(0o755);
            let checked = TrustedHostBinary::record_for_test(&host);
            checked.verify_unchanged().unwrap();

            // Loosened in place: same inode, group-writable.
            std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o775)).unwrap();
            let error = checked.verify_unchanged().unwrap_err();
            assert!(error.message.contains("owner or mode"), "{error:?}");
            std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o755)).unwrap();
            checked.verify_unchanged().unwrap();

            // Replaced by another file under the same name.
            std::fs::remove_file(&host).unwrap();
            fixture.host(0o755);
            let error = checked.verify_unchanged().unwrap_err();
            assert!(error.message.contains("changed since"), "{error:?}");

            // Replaced by a symlink to a file elsewhere.
            std::fs::remove_file(&host).unwrap();
            let elsewhere = fixture.dir.join("elsewhere");
            std::fs::write(&elsewhere, b"host").unwrap();
            std::os::unix::fs::symlink(&elsewhere, &host).unwrap();
            assert!(checked.verify_unchanged().is_err());

            // The adapter refuses before it starts anything.
            let error = crate::ComputerHostAdapter::from_trusted(&checked)
                .err()
                .expect("refused before spawn");
            assert!(error.message.contains("changed since"), "{error:?}");
        }

        #[test]
        fn xp06_writable_host_is_refused() {
            let fixture = Fixture::new("writable");
            let host = fixture.host(0o775);
            let error = trusted_native_host_path(&host, Some(&fixture.dir)).unwrap_err();
            assert!(
                error.message.contains("only its owner can write"),
                "{error:?}"
            );
        }
    }
}
