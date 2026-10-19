//! XP-03 current user and login session.
//!
//! [`current`] reports who this process runs as and which login session it
//! belongs to, from kernel sources only:
//!
//! - Windows: the terminal session id (`ProcessIdToSessionId`), the value the
//!   UIA desktop observer compares; that code moved here from
//!   `orcel-provider-uia`. The user SID and logon LUID binding stays in
//!   `orcel-policy` `current_windows_identity`, so `uid` is `None`.
//! - Linux: the effective uid and the audit session id
//!   (`/proc/self/sessionid`), which logind uses as its session id when the
//!   kernel has audit support. `XDG_SESSION_ID` is only a cross-check, since
//!   the environment is caller-controlled: it sets `session_verified` when it
//!   names the same session and is otherwise ignored.
//! - macOS: the effective uid and the audit session id (`getaudit_addr`).

use crate::PlatformError;

/// The user and login session of a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIdentity {
    /// Effective uid on Unix; `None` on Windows.
    pub uid: Option<u32>,
    /// Kernel session id: the Windows terminal session, or the Linux/macOS
    /// audit session. `None` when the process has no such session, for
    /// example a Linux service started outside any login.
    pub session_id: Option<u32>,
    /// True when `session_id` came from the kernel and nothing contradicts
    /// it. On Linux it also needs `XDG_SESSION_ID` to name the same session.
    pub session_verified: bool,
    /// How the session was read, for example `"linux-audit-session"`.
    pub source: &'static str,
}

/// The user and login session of this process.
pub fn current() -> Result<SessionIdentity, PlatformError> {
    imp::current()
}

/// The effective uid of this process; `None` on Windows.
pub fn effective_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        // SAFETY: geteuid takes no arguments, always succeeds and touches no
        // memory.
        Some(unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// The terminal session id of `pid`.
#[cfg(windows)]
pub fn session_of_pid(pid: u32) -> Result<u32, PlatformError> {
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    let mut session = 0u32;
    // SAFETY: `session` is a live u32 the call writes; the pid is a plain
    // value.
    unsafe { ProcessIdToSessionId(pid, &mut session) }
        .map(|_| session)
        .map_err(|error| {
            PlatformError::IdentityUnavailable(format!("ProcessIdToSessionId({pid}): {error}"))
        })
}

#[cfg(windows)]
mod imp {
    use super::SessionIdentity;
    use crate::PlatformError;

    pub(super) fn current() -> Result<SessionIdentity, PlatformError> {
        Ok(SessionIdentity {
            uid: None,
            session_id: Some(super::session_of_pid(std::process::id())?),
            session_verified: true,
            source: "win32-terminal-session",
        })
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::SessionIdentity;
    use crate::PlatformError;
    use std::io::ErrorKind;

    /// The kernel's "no audit session" value.
    const AUDIT_SESSION_UNSET: u32 = u32::MAX;
    const SESSION_ID_PATH: &str = "/proc/self/sessionid";

    pub(super) fn current() -> Result<SessionIdentity, PlatformError> {
        let uid = super::effective_uid().ok_or_else(|| {
            PlatformError::IdentityUnavailable("effective uid is unreadable".into())
        })?;
        let audit = match std::fs::read_to_string(SESSION_ID_PATH) {
            Ok(text) => Some(parse_audit_session(&text)?),
            // A kernel built without audit support has no such file.
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => {
                return Err(PlatformError::IdentityUnavailable(format!(
                    "{SESSION_ID_PATH}: {error}"
                )))
            }
        };
        let logind = std::env::var("XDG_SESSION_ID").ok();
        Ok(linux_session(uid, audit.flatten(), logind.as_deref()))
    }

    /// `Some(None)` for the unset marker, `Some(Some(id))` for a session.
    pub(super) fn parse_audit_session(text: &str) -> Result<Option<u32>, PlatformError> {
        let id = text.trim().parse::<u32>().map_err(|_| {
            PlatformError::IdentityUnavailable(format!("{SESSION_ID_PATH} is malformed"))
        })?;
        Ok((id != AUDIT_SESSION_UNSET).then_some(id))
    }

    pub(super) fn linux_session(
        uid: u32,
        audit: Option<u32>,
        logind: Option<&str>,
    ) -> SessionIdentity {
        match audit {
            Some(id) => SessionIdentity {
                uid: Some(uid),
                session_id: Some(id),
                session_verified: logind.and_then(|name| name.parse::<u32>().ok()) == Some(id),
                source: "linux-audit-session",
            },
            None => SessionIdentity {
                uid: Some(uid),
                session_id: None,
                session_verified: false,
                source: "linux-no-audit-session",
            },
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::SessionIdentity;
    use crate::PlatformError;

    /// `struct au_mask` from <bsm/audit.h>.
    #[repr(C)]
    #[derive(Default)]
    struct AuMask {
        am_success: u32,
        am_failure: u32,
    }

    /// `struct au_tid_addr` from <bsm/audit.h>.
    #[repr(C)]
    #[derive(Default)]
    struct AuTidAddr {
        at_port: libc::dev_t,
        at_type: u32,
        at_addr: [u32; 4],
    }

    /// `struct auditinfo_addr` from <bsm/audit.h>.
    #[repr(C)]
    #[derive(Default)]
    struct AuditinfoAddr {
        ai_auid: u32,
        ai_mask: AuMask,
        ai_termid: AuTidAddr,
        ai_asid: libc::pid_t,
        ai_flags: u64,
    }

    // The kernel copies exactly this many bytes; a layout mistake must not
    // compile.
    const _: () = assert!(std::mem::size_of::<AuditinfoAddr>() == 48);

    extern "C" {
        /// getaudit_addr(2), in libSystem, which std already links.
        fn getaudit_addr(info: *mut AuditinfoAddr, length: libc::c_int) -> libc::c_int;
    }

    /// `AU_DEFAUDITSID`: the process has no audit session.
    const NO_AUDIT_SESSION: libc::pid_t = 0;

    pub(super) fn current() -> Result<SessionIdentity, PlatformError> {
        let uid = super::effective_uid().ok_or_else(|| {
            PlatformError::IdentityUnavailable("effective uid is unreadable".into())
        })?;
        let mut info = AuditinfoAddr::default();
        // SAFETY: `info` is a live, writable auditinfo_addr whose layout
        // matches <bsm/audit.h> (size checked above) and the length passed
        // is its exact size, so the kernel writes only inside it.
        let rc = unsafe {
            getaudit_addr(
                &mut info,
                std::mem::size_of::<AuditinfoAddr>() as libc::c_int,
            )
        };
        if rc != 0 {
            return Err(PlatformError::IdentityUnavailable(format!(
                "getaudit_addr: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(macos_session(uid, info.ai_asid))
    }

    pub(super) fn macos_session(uid: u32, asid: libc::pid_t) -> SessionIdentity {
        let session_id = (asid != NO_AUDIT_SESSION)
            .then(|| u32::try_from(asid).ok())
            .flatten();
        SessionIdentity {
            uid: Some(uid),
            session_id,
            session_verified: session_id.is_some(),
            source: "macos-audit-session",
        }
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod imp {
    use super::SessionIdentity;
    use crate::PlatformError;

    pub(super) fn current() -> Result<SessionIdentity, PlatformError> {
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_session_is_stable_and_names_this_user() {
        let first = current().expect("current session");
        assert_eq!(first, current().unwrap());
        assert_eq!(first.uid, effective_uid());
        assert_eq!(first.uid.is_some(), cfg!(unix));
        if first.session_verified {
            assert!(first.session_id.is_some());
        }
        if cfg!(windows) {
            assert!(first.session_id.is_some() && first.session_verified);
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_session_of_own_pid_matches_current() {
        let session = session_of_pid(std::process::id()).unwrap();
        assert_eq!(current().unwrap().session_id, Some(session));
        assert!(matches!(
            session_of_pid(i32::MAX as u32),
            Err(PlatformError::IdentityUnavailable(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_audit_session_is_cross_checked_against_logind() {
        let verified = imp::linux_session(1000, Some(3), Some("3"));
        assert_eq!(verified.session_id, Some(3));
        assert!(verified.session_verified);
        // A different or non-numeric XDG_SESSION_ID never replaces the
        // kernel value; it only leaves the session unverified.
        for logind in [Some("4"), Some("c1"), None] {
            let session = imp::linux_session(1000, Some(3), logind);
            assert_eq!(session.session_id, Some(3));
            assert!(!session.session_verified, "{logind:?}");
        }
        let none = imp::linux_session(1000, None, Some("3"));
        assert_eq!(none.session_id, None);
        assert!(!none.session_verified);
        assert_eq!(imp::parse_audit_session("4294967295\n"), Ok(None));
        assert_eq!(imp::parse_audit_session("7\n"), Ok(Some(7)));
        assert!(imp::parse_audit_session("x").is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_audit_session_zero_means_none() {
        let session = imp::macos_session(501, 100_007);
        assert_eq!(session.session_id, Some(100_007));
        assert!(session.session_verified);
        let none = imp::macos_session(501, 0);
        assert_eq!(none.session_id, None);
        assert!(!none.session_verified);
    }
}
