//! XP-03 kernel-reported identity of a local Unix socket peer.
//!
//! [`verify_unix_peer`] asks the kernel who is on the other end of a
//! connected `UnixStream`, binds that to the peer's exact process instance
//! (pid plus start generation, see [`crate::process`]), and refuses a peer
//! that runs as a different user than this process. Every fact comes from
//! the kernel, not from anything the peer sends. If the instance cannot be
//! established, the call fails closed.
//!
//! - Linux 6.5 and later: `SO_PEERCRED` gives the uid and gid the peer had
//!   when it connected. `SO_PEERPIDFD` gives a pidfd that pins the peer
//!   process itself. Its pid is read from `/proc/self/fdinfo`, the start
//!   generation is read, and then the pidfd is read again. While the pidfd
//!   still names that pid, the process has not exited, so its pid cannot
//!   have been reused in between. A peer that has exited is
//!   [`PlatformError::ProcessGone`].
//! - Older Linux kernels, without `SO_PEERPIDFD`: the `SO_PEERCRED` pid is
//!   only a number. The generation is read, the process now holding that
//!   pid must still run as the connecting uid, and a second read must give
//!   the same generation. Residual race: if the peer exits and a process of
//!   the *same* user takes its pid before the first read, that process is
//!   reported. Callers that need more must require a 6.5+ kernel
//!   (`source == "linux-so-peerpidfd"`).
//! - macOS: `getpeereid` gives the uid and gid. `LOCAL_PEERTOKEN` gives the
//!   peer's audit token, which records the euid, egid, pid, audit session
//!   and pidversion atomically at connect time; it must agree with
//!   `getpeereid`. The generation of the pid is then read, the pid's current
//!   pidversion (`PROC_PIDUNIQIDENTIFIERINFO`) must equal the token's, and a
//!   second read must give the same generation. A pid that was reused, or a
//!   peer that has exec'd since it connected, has a new pidversion and is
//!   reported as [`PlatformError::ProcessGone`].
//!
//! This module opens no listener. CR-01 builds the app API transport on it
//! and adds code identity. Windows named-pipe clients are checked by the
//! pipe servers themselves; only the OS-agnostic comparison
//! [`require_same_user`] is shared.
//!
//! Provenance: the `getsockopt` calls (`SOL_LOCAL` options on macOS,
//! `SOL_SOCKET`/`SO_PEERCRED` into a `ucred` on Linux) follow the pattern of
//! `socket_listener_pid` in cua@a802eaf26ca97616a6bf0de6a29729a9346fbb1f
//! `libs/cua/crates/cua-daemon/src/lib.rs` (blob
//! 10940238921f0f5e44969624480c9c7d9aa07e6e, transplant row T-CUA-24; MIT,
//! Copyright (c) 2025 Cua AI, Inc.; full notice in
//! `docs/orcel/notices/cua-MIT.txt`). Modifications: server-side use on an
//! accepted stream, `SO_PEERPIDFD` and `LOCAL_PEERTOKEN` (in place of the
//! donor's `LOCAL_PEERPID`) with the generation binding, `getpeereid`, typed
//! errors, and the uid comparison.

use crate::process::ProcessGeneration;
use crate::PlatformError;

/// Who is on the other end of a local socket, as the kernel reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The peer's process instance at the time of the call.
    pub process: ProcessGeneration,
    /// The uid and gid the peer had when it connected.
    pub uid: u32,
    pub gid: u32,
    /// macOS: the audit session id from the peer's audit token. `None` on
    /// Linux, or when the peer has no audit session.
    pub audit_session: Option<u32>,
    /// How the identity was read, for example `"linux-so-peerpidfd"`.
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

/// The kernel-reported identity of the peer of `stream`, bound to its
/// process instance.
///
/// # `ProcessGone` (#367)
///
/// [`PlatformError::ProcessGone`] means only "refuse this connection". It
/// does not prove that the process exited: on macOS the pid is 0 when the
/// peer has closed its end (`LOCAL_PEERTOKEN` answers ENOTCONN), even while
/// the process still runs, and on Linux it also covers a peer whose pidfd no
/// longer names a live process. A consumer must never clean up, revoke or
/// record state about a process because of it; pid 0 names no process.
///
/// # Sources
///
/// Check [`PeerIdentity::source`] before an authority-bearing decision:
/// `"linux-so-peercred"` (kernels without `SO_PEERPIDFD`) has the pid-reuse
/// race described in the module docs and must be refused there, or the
/// exception recorded (#367). CR-01's app API refuses it.
#[cfg(unix)]
pub fn unix_peer_credentials(
    stream: &std::os::unix::net::UnixStream,
) -> Result<PeerIdentity, PlatformError> {
    use std::os::fd::AsRawFd;
    imp::peer_credentials(stream.as_raw_fd())
}

/// The identity of the peer of `stream`, refused with
/// [`PlatformError::PeerRefused`] unless the peer runs as this process's
/// effective uid. [`PlatformError::ProcessGone`] and the identity source
/// carry the same caveats as in [`unix_peer_credentials`].
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

#[cfg(target_os = "linux")]
mod imp {
    use super::{os_error, PeerIdentity};
    use crate::process;
    use crate::PlatformError;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::OnceLock;

    pub(super) fn peer_credentials(fd: RawFd) -> Result<PeerIdentity, PlatformError> {
        let cred = peer_cred(fd)?;
        identity_for(&cred, pidfd_supported()?, || raw_pidfd(fd))
    }

    /// The identity of `cred`'s process. A kernel with SO_PEERPIDFD
    /// (`pidfd_supported`) never takes the pid-number fallback, whatever
    /// `pidfd` answers: an exited peer must not be replaced by whoever
    /// reuses its pid.
    pub(super) fn identity_for(
        cred: &libc::ucred,
        pidfd_supported: bool,
        pidfd: impl FnOnce() -> std::io::Result<OwnedFd>,
    ) -> Result<PeerIdentity, PlatformError> {
        if pidfd_supported {
            from_pidfd(cred, &pidfd().map_err(|error| pidfd_error(error, cred))?)
        } else {
            from_ucred(cred)
        }
    }

    /// Whether this kernel has `SO_PEERPIDFD` (Linux 6.5+), probed once on a
    /// fresh socket pair whose peer is this live process. Only ENOPROTOOPT,
    /// the answer of a kernel that does not know the option, means "no".
    /// On a capable kernel, EINVAL means the peer has exited. Only a
    /// definite answer is cached.
    pub(super) fn pidfd_supported() -> Result<bool, PlatformError> {
        static SUPPORTED: OnceLock<bool> = OnceLock::new();
        if let Some(supported) = SUPPORTED.get() {
            return Ok(*supported);
        }
        let (probe, _peer) = std::os::unix::net::UnixStream::pair().map_err(|error| {
            PlatformError::IdentityUnavailable(format!("SO_PEERPIDFD probe socketpair: {error}"))
        })?;
        let supported = match raw_pidfd(probe.as_raw_fd()) {
            Ok(_pidfd) => true,
            Err(error) if error.raw_os_error() == Some(libc::ENOPROTOOPT) => false,
            Err(error) => {
                return Err(PlatformError::IdentityUnavailable(format!(
                    "SO_PEERPIDFD probe: {error}"
                )))
            }
        };
        Ok(*SUPPORTED.get_or_init(|| supported))
    }

    pub(super) fn peer_cred(fd: RawFd) -> Result<libc::ucred, PlatformError> {
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
        Ok(cred)
    }

    fn cred_pid(cred: &libc::ucred) -> Result<u32, PlatformError> {
        u32::try_from(cred.pid)
            .ok()
            .filter(|pid| *pid > 0)
            .ok_or_else(|| {
                PlatformError::IdentityUnavailable(
                    "the socket peer's pid is not visible in this pid namespace".into(),
                )
            })
    }

    /// `getsockopt(SO_PEERPIDFD)` on `fd`.
    fn raw_pidfd(fd: RawFd) -> std::io::Result<OwnedFd> {
        let mut pidfd: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `len` bytes into `pidfd`, a live
        // c_int; `fd` is borrowed from a UnixStream that outlives the call.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                (&mut pidfd as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if pidfd < 0 || len as usize != std::mem::size_of::<libc::c_int>() {
            return Err(std::io::Error::other(
                "getsockopt(SO_PEERPIDFD) returned no descriptor",
            ));
        }
        // SAFETY: getsockopt returned a new pidfd that nothing else owns;
        // OwnedFd takes ownership and closes it exactly once.
        Ok(unsafe { OwnedFd::from_raw_fd(pidfd) })
    }

    /// A `SO_PEERPIDFD` failure on a kernel known to support it.
    fn pidfd_error(error: std::io::Error, cred: &libc::ucred) -> PlatformError {
        match error.raw_os_error() {
            // The peer has exited (EINVAL) or been reaped (ESRCH).
            Some(libc::EINVAL) | Some(libc::ESRCH) => match cred_pid(cred) {
                Ok(pid) => PlatformError::ProcessGone(pid),
                Err(unavailable) => unavailable,
            },
            _ => PlatformError::IdentityUnavailable(format!("getsockopt(SO_PEERPIDFD): {error}")),
        }
    }

    /// The pid a pidfd names now, from `/proc/self/fdinfo/<fd>`; `None` once
    /// the process has been reaped (the kernel reports `Pid: -1`). `Pid: 0`
    /// means the process lives in a pid namespace this one cannot see, which
    /// is unavailable, not gone.
    fn pidfd_pid(pidfd: &OwnedFd) -> Result<Option<u32>, PlatformError> {
        let path = format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd());
        let text = std::fs::read_to_string(&path)
            .map_err(|error| PlatformError::IdentityUnavailable(format!("{path}: {error}")))?;
        fdinfo_pid(&path, &text)
    }

    /// The `Pid:` line of a pidfd's fdinfo `text` (read from `path`).
    pub(super) fn fdinfo_pid(path: &str, text: &str) -> Result<Option<u32>, PlatformError> {
        let pid = text
            .lines()
            .find_map(|line| line.strip_prefix("Pid:"))
            .and_then(|value| value.trim().parse::<i64>().ok())
            .ok_or_else(|| PlatformError::IdentityUnavailable(format!("{path} has no Pid")))?;
        match pid {
            -1 => Ok(None),
            0 => Err(PlatformError::IdentityUnavailable(
                "the socket peer's pid is not visible in this pid namespace".into(),
            )),
            pid => u32::try_from(pid)
                .map(Some)
                .map_err(|_| PlatformError::IdentityUnavailable(format!("{path} has pid {pid}"))),
        }
    }

    fn from_pidfd(cred: &libc::ucred, pidfd: &OwnedFd) -> Result<PeerIdentity, PlatformError> {
        let Some(pid) = pidfd_pid(pidfd)? else {
            return Err(PlatformError::ProcessGone(cred_pid(cred)?));
        };
        if cred.pid > 0 && cred.pid as u32 != pid {
            return Err(PlatformError::IdentityUnavailable(format!(
                "SO_PEERCRED pid {} and SO_PEERPIDFD pid {pid} disagree",
                cred.pid
            )));
        }
        let process = process::start_generation(pid)?;
        // The pidfd pins the process, not the number: if it still names
        // `pid`, the peer has not exited, so the generation read above is
        // the peer's own.
        if pidfd_pid(pidfd)? != Some(pid) {
            return Err(PlatformError::ProcessGone(pid));
        }
        Ok(PeerIdentity {
            process,
            uid: cred.uid,
            gid: cred.gid,
            audit_session: None,
            source: "linux-so-peerpidfd",
        })
    }

    /// The pre-6.5 path; see the module docs for its residual race.
    pub(super) fn from_ucred(cred: &libc::ucred) -> Result<PeerIdentity, PlatformError> {
        let pid = cred_pid(cred)?;
        let process = process::start_generation(pid)?;
        let now_uid = process::effective_uid_of(pid)?;
        if now_uid != cred.uid {
            return Err(PlatformError::IdentityUnavailable(format!(
                "pid {pid} now runs as uid {now_uid}, not the connecting uid {}",
                cred.uid
            )));
        }
        if process::start_generation(pid)? != process {
            return Err(PlatformError::ProcessGone(pid));
        }
        Ok(PeerIdentity {
            process,
            uid: cred.uid,
            gid: cred.gid,
            audit_session: None,
            source: "linux-so-peercred",
        })
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{os_error, PeerIdentity};
    use crate::process;
    use crate::PlatformError;
    use std::os::fd::RawFd;

    /// `LOCAL_PEERTOKEN` from <sys/un.h>: the peer's audit token.
    const LOCAL_PEERTOKEN: libc::c_int = 0x006;
    /// `PROC_PIDUNIQIDENTIFIERINFO` from <sys/proc_info.h>.
    const PROC_PIDUNIQIDENTIFIERINFO: libc::c_int = 17;

    /// `audit_token_t`: val[1] euid, val[2] egid, val[5] pid, val[6] asid,
    /// val[7] pidversion (the libbsm `audit_token_to_*` accessors).
    #[repr(C)]
    #[derive(Default)]
    struct AuditToken {
        val: [u32; 8],
    }

    /// `struct proc_uniqidentifierinfo` from <sys/proc_info.h>.
    #[repr(C)]
    #[derive(Default)]
    struct UniqIdentifierInfo {
        p_uuid: [u8; 16],
        p_uniqueid: u64,
        p_puniqueid: u64,
        p_idversion: i32,
        p_orig_ppidversion: i32,
        p_reserve2: u64,
        p_reserve3: u64,
    }

    // The kernel copies exactly these sizes; a layout mistake must not
    // compile.
    const _: () = assert!(std::mem::size_of::<AuditToken>() == 32);
    const _: () = assert!(std::mem::size_of::<UniqIdentifierInfo>() == 56);

    pub(super) fn peer_credentials(fd: RawFd) -> Result<PeerIdentity, PlatformError> {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: getpeereid writes one uid_t and one gid_t through the two
        // live pointers; `fd` is borrowed from a UnixStream that outlives
        // the call.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
            return Err(os_error("getpeereid"));
        }
        let mut token = AuditToken::default();
        let mut len = std::mem::size_of::<AuditToken>() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `len` bytes into `token`, a live
        // audit_token_t of exactly that size; `fd` is borrowed from a
        // UnixStream that outlives the call.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                LOCAL_PEERTOKEN,
                (&mut token as *mut AuditToken).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            // getpeereid keeps answering from the cached connect-time
            // credentials, but once the peer has closed its end the token is
            // gone. The kernel no longer names the peer's pid, so it is 0.
            if error.raw_os_error() == Some(libc::ENOTCONN) {
                return Err(PlatformError::ProcessGone(0));
            }
            return Err(PlatformError::IdentityUnavailable(format!(
                "getsockopt(LOCAL_PEERTOKEN): {error}"
            )));
        }
        if len as usize != std::mem::size_of::<AuditToken>() {
            return Err(PlatformError::IdentityUnavailable(
                "getsockopt(LOCAL_PEERTOKEN) returned a short token".into(),
            ));
        }
        let [_, euid, egid, _, _, pid, asid, pidversion] = token.val;
        if euid != uid || egid != gid {
            return Err(PlatformError::IdentityUnavailable(format!(
                "peer audit token ({euid}:{egid}) and getpeereid ({uid}:{gid}) disagree"
            )));
        }
        if pid == 0 {
            return Err(PlatformError::IdentityUnavailable(
                "the peer audit token has no pid".into(),
            ));
        }
        let process = process::start_generation(pid)?;
        // A reused pid, or a peer that exec'd since it connected, has a new
        // pidversion. Re-reading the generation afterwards ties the version
        // check to the same instance.
        if pid_version(pid)? != pidversion as i32 || process::start_generation(pid)? != process {
            return Err(PlatformError::ProcessGone(pid));
        }
        Ok(PeerIdentity {
            process,
            uid,
            gid,
            audit_session: (asid != 0).then_some(asid),
            source: "macos-local-peertoken",
        })
    }

    /// The current pidversion of `pid`.
    fn pid_version(pid: u32) -> Result<i32, PlatformError> {
        let raw_pid = libc::pid_t::try_from(pid).map_err(|_| PlatformError::ProcessGone(pid))?;
        let mut info = UniqIdentifierInfo::default();
        let size = std::mem::size_of::<UniqIdentifierInfo>() as libc::c_int;
        // SAFETY: the buffer is a live, writable proc_uniqidentifierinfo and
        // `size` is its exact size, which is what this flavor writes.
        let written = unsafe {
            libc::proc_pidinfo(
                raw_pid,
                PROC_PIDUNIQIDENTIFIERINFO,
                0,
                (&mut info as *mut UniqIdentifierInfo).cast(),
                size,
            )
        };
        if written <= 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Err(PlatformError::ProcessGone(pid));
            }
            return Err(PlatformError::IdentityUnavailable(format!(
                "proc_pidinfo({pid}, PROC_PIDUNIQIDENTIFIERINFO): {error}"
            )));
        }
        if written != size {
            return Err(PlatformError::IdentityUnavailable(format!(
                "proc_pidinfo({pid}, PROC_PIDUNIQIDENTIFIERINFO) returned {written} of {size} bytes"
            )));
        }
        Ok(info.p_idversion)
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
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
            process: ProcessGeneration {
                pid: 4242,
                generation: 7,
                boot_id: None,
                source: "test",
            },
            uid,
            gid: 20,
            audit_session: None,
            source: "test",
        }
    }

    /// Synthetic: a real peer under another uid needs root to create, and CI
    /// does not run as root, so this exercises the comparison every real
    /// peer goes through.
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
    fn peer_of_a_socketpair_is_this_process_instance() {
        let (left, right) = std::os::unix::net::UnixStream::pair().unwrap();
        let uid = crate::session::effective_uid().unwrap();
        let me = crate::process::current_instance().unwrap();
        for stream in [&left, &right] {
            let identity = verify_unix_peer(stream).expect("own peer accepted");
            assert_eq!(identity.process, me);
            assert_eq!(identity.uid, uid);
            // SAFETY: getegid takes no arguments, always succeeds and touches
            // no memory.
            assert_eq!(identity.gid, unsafe { libc::getegid() });
        }
        // The same kernel-read peer is refused for any other expected user.
        let other = uid.wrapping_add(1);
        assert_eq!(
            require_same_user(unix_peer_credentials(&left).unwrap(), other),
            Err(PlatformError::PeerRefused {
                peer_uid: uid,
                expected_uid: other,
            })
        );
    }

    /// The pre-6.5 path is tested directly, because a 6.5+ kernel (like the
    /// CI runners') always takes the pidfd path.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_so_peercred_fallback_binds_the_same_instance() {
        use std::os::fd::AsRawFd;
        let (left, _right) = std::os::unix::net::UnixStream::pair().unwrap();
        let cred = imp::peer_cred(left.as_raw_fd()).unwrap();
        let identity = imp::from_ucred(&cred).unwrap();
        assert_eq!(
            identity.process,
            crate::process::current_instance().unwrap()
        );
        assert_eq!(identity.source, "linux-so-peercred");
        assert!(
            imp::pidfd_supported().unwrap(),
            "this kernel should support SO_PEERPIDFD (Linux 6.5+)"
        );
        assert_eq!(
            unix_peer_credentials(&left).unwrap().source,
            "linux-so-peerpidfd"
        );
        let hidden = libc::ucred { pid: 0, ..cred };
        assert!(matches!(
            imp::from_ucred(&hidden),
            Err(PlatformError::IdentityUnavailable(_))
        ));
    }

    /// #367 item 3: `Pid: 0` (a pid namespace this one cannot see) is
    /// unavailable, never gone; `Pid: -1` (reaped) is gone.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_fdinfo_pid_zero_is_unavailable_not_gone() {
        let path = "/proc/self/fdinfo/9";
        let fdinfo = |pid: &str| {
            format!(
                "pos:	0
flags:	02000002
Pid:	{pid}
"
            )
        };
        assert!(matches!(
            imp::fdinfo_pid(path, &fdinfo("0")),
            Err(PlatformError::IdentityUnavailable(_))
        ));
        assert_eq!(imp::fdinfo_pid(path, &fdinfo("-1")), Ok(None));
        assert_eq!(imp::fdinfo_pid(path, &fdinfo("4242")), Ok(Some(4242)));
        assert!(matches!(
            imp::fdinfo_pid(
                path, "pos:	0
"
            ),
            Err(PlatformError::IdentityUnavailable(_))
        ));
    }

    /// #367 item 3: on a kernel with `SO_PEERPIDFD`, an EINVAL or ESRCH
    /// answer (the peer exited) is `ProcessGone`, never the `SO_PEERCRED`
    /// fallback, even though the pid still names a live process here.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_pidfd_failure_on_a_capable_kernel_never_falls_back() {
        use std::os::fd::AsRawFd;
        let (left, _right) = std::os::unix::net::UnixStream::pair().unwrap();
        let cred = imp::peer_cred(left.as_raw_fd()).unwrap();
        let pid = std::process::id();
        for errno in [libc::EINVAL, libc::ESRCH] {
            let injected = imp::identity_for(&cred, true, || {
                Err(std::io::Error::from_raw_os_error(errno))
            });
            assert_eq!(
                injected,
                Err(PlatformError::ProcessGone(pid)),
                "errno {errno}"
            );
        }
        assert!(matches!(
            imp::identity_for(&cred, true, || Err(std::io::Error::from_raw_os_error(
                libc::EPERM
            ))),
            Err(PlatformError::IdentityUnavailable(_))
        ));
        // Only a kernel without the option takes the fallback.
        assert_eq!(
            imp::identity_for(&cred, false, || Err(std::io::Error::from_raw_os_error(
                libc::EINVAL
            )))
            .unwrap()
            .source,
            "linux-so-peercred"
        );
    }

    #[cfg(unix)]
    const HELPER_SOCKET: &str = "XP03_PEER_HELPER_SOCKET";

    /// The child half of `an_exited_peer_is_reported_gone`: it connects,
    /// sends its own instance over the socket (libtest captures stdout) and
    /// waits until the parent closes its stdin. Run on its own, without the
    /// variable, it does nothing.
    #[cfg(unix)]
    #[test]
    fn peer_helper_child() {
        use std::io::{BufRead, Write};
        let Some(path) = std::env::var_os(HELPER_SOCKET) else {
            return;
        };
        let mut stream = std::os::unix::net::UnixStream::connect(path).expect("connect");
        let me = crate::process::current_instance().expect("own instance");
        writeln!(stream, "{} {}", me.pid, me.generation).expect("send instance");
        stream.flush().expect("flush");
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        drop(stream);
    }

    #[cfg(unix)]
    #[test]
    fn an_exited_peer_is_reported_gone() {
        use std::io::{BufRead, BufReader, ErrorKind};
        use std::os::unix::net::UnixListener;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        // A short path (sun_path holds about 104 bytes on macOS); the test
        // binds one socket for itself and removes it afterwards.
        let dir = std::env::temp_dir().join(format!("xp03-gone-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "peer::tests::peer_helper_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(HELPER_SOCKET, &path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn helper");

        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let server = loop {
            let accepted = listener.accept();
            if matches!(&accepted, Err(error) if error.kind() == ErrorKind::WouldBlock) {
                assert!(Instant::now() < deadline, "helper never connected");
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            break accepted.expect("accept helper").0;
        };
        server.set_nonblocking(false).unwrap();

        server
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let mut line = String::new();
        BufReader::new(&server)
            .read_line(&mut line)
            .expect("helper sent its instance");
        let mut fields = line.split_whitespace();
        let pid: u32 = fields.next().unwrap().parse().unwrap();
        let generation: u64 = fields.next().unwrap().parse().unwrap();

        // Live: the accepted peer is exactly the helper's instance.
        let live = verify_unix_peer(&server).expect("live helper peer");
        assert_eq!(live.process.pid, pid);
        assert_eq!(live.process.generation, generation);
        assert_eq!(live.process, crate::process::start_generation(pid).unwrap());

        // Exited and reaped: the same connection now reports gone, or, if
        // the OS already reused the pid, never the helper's instance.
        drop(child.stdin.take());
        child.wait().unwrap();
        let after = verify_unix_peer(&server);
        // A capable Linux kernel never takes the pid-number fallback, so the
        // exited peer is gone even if its pid was already reused. macOS no
        // longer names the pid once the peer closed its end (0).
        let gone = if cfg!(target_os = "macos") {
            matches!(after, Err(PlatformError::ProcessGone(gone)) if gone == pid || gone == 0)
        } else {
            after == Err(PlatformError::ProcessGone(pid))
        };
        assert!(gone, "exited peer {pid} read as {after:?}");
        drop((server, listener));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn peer_of_an_accepted_connection_is_the_connecting_process() {
        use std::os::unix::net::{UnixListener, UnixStream};
        let dir = std::env::temp_dir().join(format!("xp03-peer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let client = UnixStream::connect(&path).unwrap();
        let (server, _) = listener.accept().unwrap();
        let me = crate::process::current_instance().unwrap();
        assert_eq!(verify_unix_peer(&server).unwrap().process, me);
        assert_eq!(verify_unix_peer(&client).unwrap().process, me);
        drop((server, client, listener));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
