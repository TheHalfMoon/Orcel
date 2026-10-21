//! The executable the helper launches, verified through the descriptor it
//! then runs (#384 item 2).
//!
//! orceld checks the registered digest by path before it starts the helper,
//! so without this a file swapped in between that check and the launch would
//! run. The spec carries the digest; the helper opens the canonical path once
//! (never through a final link), hashes the bytes through that open file and
//! refuses a mismatch as `executable_changed`. Then:
//!
//! - **Linux** executes that same open file (`/proc/self/fd/N`). Landlock's
//!   `EXECUTE` rule names the inode the path held when the ruleset was built,
//!   so a file swapped in before then is refused by Landlock, not run.
//! - **Windows** keeps the file open with `FILE_SHARE_READ` only until the
//!   process exists, so nobody can write, rename or delete it in between, and
//!   no directory above it can be renamed while a file in it is open.
//!   `CreateProcessW` maps the very file that was hashed.
//! - **macOS** has no `fexecve`, and `sandbox-exec` execs a path. Right
//!   before the launch the path's device, inode, size, mode and modification
//!   time must still equal the open file's. A swap inside that last window
//!   is the residual, the same as the Safe tier's on macOS.

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::containment::{containment_error, error, os_detail, ContainError, ErrorCode};

/// A registered executable is never larger than this (the registry's bound).
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

/// The open, verified executable.
pub(crate) struct PinnedExecutable {
    path: PathBuf,
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
    file: File,
}

fn changed() -> ContainError {
    error(
        ErrorCode::ExecutableChanged,
        "the contained executable does not match the digest in the spec; nothing was launched",
        false,
        None,
    )
}

impl PinnedExecutable {
    /// Opens `path` (canonical, checked by the caller) without following a
    /// final link and verifies its bytes against `expected`.
    pub(crate) fn open(path: &Path, expected: &[u8; 32]) -> Result<Self, ContainError> {
        let file = open_unfollowed(path).map_err(|cause| {
            containment_error("failed to open the contained executable", os_detail(&cause))
        })?;
        let metadata = file.metadata().map_err(|cause| {
            containment_error(
                "failed to inspect the contained executable",
                os_detail(&cause),
            )
        })?;
        if !metadata.is_file() {
            return Err(containment_error(
                "the contained executable is not a file",
                None,
            ));
        }
        if metadata.len() > MAX_EXECUTABLE_BYTES {
            return Err(changed());
        }
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
        (&file)
            .take(MAX_EXECUTABLE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|cause| {
                containment_error("failed to read the contained executable", os_detail(&cause))
            })?;
        if bytes.len() as u64 > MAX_EXECUTABLE_BYTES || crate::digest::sha256(&bytes) != *expected {
            return Err(changed());
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    /// Tests only: pin whatever `path` holds now (the macOS and Windows
    /// platform tests launch through it).
    #[cfg(all(test, any(target_os = "macos", windows)))]
    pub(crate) fn for_test(path: &Path) -> Self {
        let digest = crate::digest::sha256(&std::fs::read(path).expect("read executable"));
        Self::open(path, &digest).expect("pin executable")
    }

    /// The canonical path, for policy rules and `argv[0]`.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Linux: the path that executes this open file itself.
    #[cfg(target_os = "linux")]
    pub(crate) fn exec_path(&self) -> PathBuf {
        use std::os::fd::AsRawFd;
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }

    /// macOS: the path must still name the open, verified file.
    #[cfg(target_os = "macos")]
    pub(crate) fn check_still_named(&self) -> Result<(), ContainError> {
        use std::os::unix::fs::MetadataExt;
        let identity = |m: &std::fs::Metadata| {
            (
                m.dev(),
                m.ino(),
                m.size(),
                m.mode(),
                m.mtime(),
                m.mtime_nsec(),
            )
        };
        let open = self.file.metadata().map_err(|_| changed())?;
        let named = std::fs::symlink_metadata(&self.path).map_err(|_| changed())?;
        if identity(&open) != identity(&named) {
            return Err(changed());
        }
        Ok(())
    }
}

#[cfg(unix)]
fn open_unfollowed(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
fn open_unfollowed(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_unfollowed(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

#[cfg(test)]
#[path = "pinned_tests.rs"]
mod tests;
