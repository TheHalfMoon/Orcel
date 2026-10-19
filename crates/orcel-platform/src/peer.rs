//! XP-03 kernel-reported credentials of a local Unix socket peer.
//!
//! [`verify_unix_peer`] asks the kernel who is on the other end of a
//! connected `UnixStream` and refuses a peer that runs as a different user
//! than this process. The answer comes from the kernel, not from anything
//! the peer sends, so a peer cannot claim another identity:
//!
//! - Linux: `SO_PEERCRED` gives the pid, uid and gid the peer had when it
//!   connected (or created the socket pair).
//! - macOS: `getpeereid` gives the uid and gid; `LOCAL_PEERPID` the pid.
//!
//! This module opens no listener. CR-01 builds the app API transport on it
//! and adds code identity. Windows named-pipe clients are checked by the
//! pipe servers themselves; only the OS-agnostic comparison
//! [`require_same_user`] is shared.
//!
//! Provenance: the `getsockopt` calls (`SOL_LOCAL`/`LOCAL_PEERPID` on macOS,
//! `SOL_SOCKET`/`SO_PEERCRED` into a `ucred` on Linux) follow the pattern of
//! `socket_listener_pid` in cua@a802eaf26ca97616a6bf0de6a29729a9346fbb1f
//! `libs/cua/crates/cua-daemon/src/lib.rs` (blob
//! 10940238921f0f5e44969624480c9c7d9aa07e6e, transplant row T-CUA-24; MIT,
//! Copyright (c) 2025 Cua AI, Inc.; full notice in
//! `docs/orcel/notices/cua-MIT.txt`). Modifications: server-side use on an
//! accepted stream, the uid and gid (and `getpeereid` on macOS), typed
//! errors, and the uid comparison.

use crate::PlatformError;

/// Who is on the other end of a local socket, as the kernel reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The peer's pid; `None` when the kernel does not report one (for
    /// example a peer in another pid namespace).
    pub pid: Option<u32>,
    pub uid: u32,
    pub gid: u32,
    /// How the credentials were read, for example `"linux-so-peercred"`.
    pub source: &'static str,
}

/// Accept `peer` only when it runs as `expected_uid`.
pub fn require_same_user(
    peer: PeerIdentity,
    expected_uid: u32,
) -> Result<PeerIdentity, PlatformError> {
    if peer.uid == expected_uid {
        Ok(peer)
    } else {
        Err(PlatformError::PeerRefused {
            peer_uid: peer.uid,
            expected_uid,
        })
    }
}

/// The kernel-reported credentials of the peer of `stream`.
#[cfg(unix)]
pub fn unix_peer_credentials(
    stream: &std::os::unix::net::UnixStream,
) -> Result<PeerIdentity, PlatformError> {
    use std::os::fd::AsRawFd;
    imp::peer_credentials(stream.as_raw_fd())
}

/// The credentials of the peer of `stream`, refused with
/// [`PlatformError::PeerRefused`] unless the peer runs as this process's
/// effective uid.
#[cfg(unix)]
pub fn verify_unix_peer(
    stream: &std::os::unix::net::UnixStream,
) -> Result<PeerIdentity, PlatformError> {
    let expected = crate::session::effective_uid()
        .ok_or_else(|| PlatformError::IdentityUnavailable("effective uid is unreadable".into()))?;
    require_same_user(unix_peer_credentials(stream)?, expected)
}

#[cfg(unix)]
fn os_error(call: &str) -> PlatformError {
    PlatformError::IdentityUnavailable(format!("{call}: {}", std::io::Error::last_os_error()))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use super::{os_error, PeerIdentity};
    use crate::PlatformError;
    use std::os::fd::RawFd;

    pub(super) fn peer_credentials(fd: RawFd) -> Result<PeerIdentity, PlatformError> {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `len` bytes into `cred`, a live,
        // properly sized and aligned ucred; `fd` is borrowed from a
        // UnixStream that outlives the call.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(os_error("getsockopt(SO_PEERCRED)"));
        }
        if len as usize != std::mem::size_of::<libc::ucred>() {
            return Err(PlatformError::IdentityUnavailable(
                "getsockopt(SO_PEERCRED) returned a short ucred".into(),
            ));
        }
        Ok(PeerIdentity {
            pid: u32::try_from(cred.pid).ok().filter(|pid| *pid > 0),
            uid: cred.uid,
            gid: cred.gid,
            source: "linux-so-peercred",
        })
    }
}

#[cfg(target_vendor = "apple")]
mod imp {
    use super::{os_error, PeerIdentity};
    use crate::PlatformError;
    use std::os::fd::RawFd;

    pub(super) fn peer_credentials(fd: RawFd) -> Result<PeerIdentity, PlatformError> {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: getpeereid writes one uid_t and one gid_t through the two
        // live pointers; `fd` is borrowed from a UnixStream that outlives
        // the call.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
            return Err(os_error("getpeereid"));
        }
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `len` bytes into `pid`, a live
        // pid_t; `fd` is borrowed from a UnixStream that outlives the call.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut len,
            )
        };
        let pid = (rc == 0 && len as usize == std::mem::size_of::<libc::pid_t>())
            .then(|| u32::try_from(pid).ok().filter(|pid| *pid > 0))
            .flatten();
        Ok(PeerIdentity {
            pid,
            uid,
            gid,
            source: "macos-getpeereid",
        })
    }
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
mod imp {
    use super::PeerIdentity;
    use crate::PlatformError;
    use std::os::fd::RawFd;

    pub(super) fn peer_credentials(_fd: RawFd) -> Result<PeerIdentity, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(uid: u32) -> PeerIdentity {
        PeerIdentity {
            pid: Some(4242),
            uid,
            gid: 20,
            source: "test",
        }
    }

    #[test]
    fn a_peer_with_a_different_uid_is_refused() {
        assert_eq!(require_same_user(peer(501), 501), Ok(peer(501)));
        assert_eq!(
            require_same_user(peer(0), 501),
            Err(PlatformError::PeerRefused {
                peer_uid: 0,
                expected_uid: 501,
            })
        );
        assert_eq!(
            require_same_user(peer(502), 501),
            Err(PlatformError::PeerRefused {
                peer_uid: 502,
                expected_uid: 501,
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn peer_of_a_socketpair_is_this_process() {
        let (left, right) = std::os::unix::net::UnixStream::pair().unwrap();
        let uid = crate::session::effective_uid().unwrap();
        for stream in [&left, &right] {
            let identity = verify_unix_peer(stream).expect("own peer accepted");
            assert_eq!(identity.uid, uid);
            // SAFETY: getegid takes no arguments, always succeeds and touches
            // no memory.
            assert_eq!(identity.gid, unsafe { libc::getegid() });
            assert_eq!(identity.pid, Some(std::process::id()));
        }
        // The same stream is refused for any other expected user.
        let other = uid.wrapping_add(1);
        assert_eq!(
            require_same_user(unix_peer_credentials(&left).unwrap(), other),
            Err(PlatformError::PeerRefused {
                peer_uid: uid,
                expected_uid: other,
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn peer_of_an_accepted_connection_is_the_connecting_process() {
        use std::os::unix::net::{UnixListener, UnixStream};
        // A short path (sun_path holds about 104 bytes on macOS); the test
        // binds one socket for itself and removes it afterwards.
        let dir = std::env::temp_dir().join(format!("xp03-peer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let client = UnixStream::connect(&path).unwrap();
        let (server, _) = listener.accept().unwrap();
        let seen_by_server = verify_unix_peer(&server).unwrap();
        let seen_by_client = verify_unix_peer(&client).unwrap();
        assert_eq!(seen_by_server.pid, Some(std::process::id()));
        assert_eq!(seen_by_client.pid, Some(std::process::id()));
        drop((server, client, listener));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
