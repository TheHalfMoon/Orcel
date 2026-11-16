//! macOS and Linux: the socket in the per-user runtime directory, derived
//! as orceld derives it (protocol section 1; `socket_dir` in
//! `crates/orceld/src/app_api.rs`), and the socket peer's uid read before the
//! first write. Only Windows is qualified in SG-000119; this code keeps the
//! later stages small and runs on the existing root legs.
//!
//! Known limit: when the OS has no private runtime directory, orceld falls
//! back to the `run` folder of its state root. This client does not resolve
//! the state root (state stores are named only through `orcel_platform`'s
//! registry, #655), so it reports that the app API has no location.

use crate::error::{ClientError, Unavailable};
use crate::identity::{self, ServerFacts};
use crate::transport::{Canceller, Conn};
use std::ffi::OsString;
use std::io;
use std::net::Shutdown;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

/// An absolute value without `.` or `..` components, as orceld requires of
/// every base directory it reads.
fn usable_absolute(value: OsString) -> Option<PathBuf> {
    let path = PathBuf::from(value);
    (path.is_absolute()
        && !path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir)))
    .then_some(path)
}

/// A runtime directory as the XDG spec requires one: a real directory owned
/// by this user with no group or other access.
fn private_runtime(dir: &Path) -> bool {
    // SAFETY: geteuid has no preconditions.
    let ours = unsafe { libc::geteuid() };
    std::fs::symlink_metadata(dir).is_ok_and(|meta| {
        meta.file_type().is_dir() && meta.uid() == ours && meta.permissions().mode() & 0o077 == 0
    })
}

#[cfg(target_os = "macos")]
fn runtime_dir() -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let mut buf = vec![0u8; 1024];
    // SAFETY: `buf` holds `buf.len()` bytes; confstr writes at most that many,
    // NUL included, and returns the length it needed.
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
    usable_absolute(OsString::from_vec(buf))
}

#[cfg(not(target_os = "macos"))]
fn runtime_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR").and_then(usable_absolute)
}

/// `<runtime dir>/orcel/app-api<suffix>.sock`, when there is a private
/// runtime directory (see the module's known limit).
pub(crate) fn socket_path(suffix: &str) -> Result<PathBuf, ClientError> {
    runtime_dir()
        .filter(|dir| private_runtime(dir))
        .map(|runtime| runtime.join("orcel").join(format!("app-api{suffix}.sock")))
        .ok_or(ClientError::Unavailable(Unavailable::NoLocation))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    // SAFETY: an all-zero ucred is a valid value for getsockopt to fill.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` describe a writable ucred of that size.
    let read = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    (read == 0 && len as usize == std::mem::size_of::<libc::ucred>()).then_some(cred.uid)
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `uid` and `gid` are writable.
    (unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0).then_some(uid)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
)))]
fn peer_uid(_stream: &UnixStream) -> Option<u32> {
    None
}

/// Connects to `path` and confirms the peer runs as this uid before
/// returning; nothing is written here.
pub(crate) fn connect(path: &Path) -> Result<UnixStream, ClientError> {
    let stream = UnixStream::connect(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            ClientError::Unavailable(Unavailable::NotRunning)
        }
        _ => ClientError::io(&error),
    })?;
    // SAFETY: geteuid has no preconditions.
    let ours = unsafe { libc::geteuid() };
    let facts = match peer_uid(&stream) {
        Some(peer) => ServerFacts::PeerUid { peer, ours },
        None => ServerFacts::Unreadable,
    };
    identity::decide(&facts).map_err(ClientError::NotYours)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| ClientError::io(&error))?;
    Ok(stream)
}

impl Conn for UnixStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_read_timeout(self, timeout)
    }

    fn canceller(&self) -> io::Result<Canceller> {
        let clone = self.try_clone()?;
        Ok(Canceller::new(move || {
            let _ = clone.shutdown(Shutdown::Both);
        }))
    }
}
