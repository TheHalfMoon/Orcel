//! The client's typed failures. None of them carries text orceld wrote:
//! an error frame's free-text `message` is never kept, only its code.

use crate::identity::IdentityRefusal;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// orceld's endpoint is not there, or did not answer in time: the
    /// window shows orceld as unavailable. The detail is this client's own.
    Unavailable(Unavailable),
    /// The endpoint's server could not be confirmed as this user's orceld;
    /// nothing was written to it.
    NotYours(IdentityRefusal),
    /// orceld answered with `read_only` other than `true`.
    Incompatible,
    /// orceld's client slots are all taken (`BUSY`).
    Busy,
    /// orceld refused the request with this error code (the code only,
    /// `[A-Z_]`, at most 32; anything else reads `INVALID`).
    Refused(String),
    /// A frame larger than 64 KiB, newline included.
    FrameTooLarge,
    /// A frame that is not this protocol.
    Protocol(&'static str),
    /// `task.get` answered a record the sanitiser refused entirely.
    TaskWithheld,
}

/// Why orceld is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// No endpoint: orceld is not running (or has not opened it yet).
    NotRunning,
    /// The endpoint exists but no instance became free in time.
    NoFreeInstance,
    /// Connecting, writing or reading timed out.
    TimedOut,
    /// The connection ended or failed (the OS error code, if any).
    ConnectionLost(Option<i32>),
    /// This OS has no app API location.
    NoLocation,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(Unavailable::NotRunning) => write!(f, "orceld is not running"),
            Self::Unavailable(Unavailable::NoFreeInstance) => {
                write!(f, "orceld's endpoint had no free instance")
            }
            Self::Unavailable(Unavailable::TimedOut) => write!(f, "orceld did not answer in time"),
            Self::Unavailable(Unavailable::ConnectionLost(Some(code))) => {
                write!(f, "the connection to orceld was lost (OS error {code})")
            }
            Self::Unavailable(Unavailable::ConnectionLost(None)) => {
                write!(f, "the connection to orceld was lost")
            }
            Self::Unavailable(Unavailable::NoLocation) => {
                write!(f, "the app API has no location on this OS")
            }
            Self::NotYours(refusal) => write!(f, "{refusal}"),
            Self::Incompatible => write!(f, "incompatible orceld"),
            Self::Busy => write!(f, "orceld has no free client slot"),
            Self::Refused(code) => write!(f, "orceld refused the request ({code})"),
            Self::FrameTooLarge => write!(f, "a frame exceeded 64 KiB"),
            Self::Protocol(what) => write!(f, "orceld sent an unexpected frame: {what}"),
            Self::TaskWithheld => write!(f, "the task record was withheld"),
        }
    }
}

impl std::error::Error for ClientError {}

impl ClientError {
    /// An I/O failure on an open connection.
    pub(crate) fn io(error: &std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::TimedOut {
            Self::Unavailable(Unavailable::TimedOut)
        } else {
            Self::Unavailable(Unavailable::ConnectionLost(error.raw_os_error()))
        }
    }
}

/// An error frame's code, kept only when it is `[A-Z_]`, at most 32.
pub(crate) fn error_code(code: Option<&str>) -> String {
    match code {
        Some(code)
            if !code.is_empty()
                && code.len() <= 32
                && code.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') =>
        {
            code.to_owned()
        }
        _ => "INVALID".to_owned(),
    }
}
