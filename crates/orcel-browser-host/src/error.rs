//! SG-000074 error vocabulary: typed unavailability and fail-closed errors.
//!
//! A missing or unsupported browser engine is never an exception and never
//! a fallback: it is [`HostError::Unavailable`], and callers must surface
//! it as typed unavailable.

use std::fmt;

/// Why a browser engine cannot be used. Variants are exhaustive so new
/// failure modes force an explicit decision at every match site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableReason {
    /// No supported engine executable was discovered.
    NoEngine,
    /// An engine-like executable failed version, publisher, or kind checks.
    UnsupportedEngine,
    /// A supervised launch or handshake step failed.
    LaunchFailed,
    /// The host channel carried malformed or unexpected frames.
    ProtocolViolation,
    /// The worker runtime is missing, too old, or refused to start (it
    /// requires Node.js 22.14+ run with exactly --disable-sigusr1).
    UnsupportedRuntime,
    /// A mandatory managed browser policy is present or unreadable; it would
    /// outrank the confinement flags, so the engine is not launched.
    ManagedPolicy,
    /// A browser operation (navigation, activation, download) ran past its
    /// deadline; nothing was committed.
    TimedOut,
    /// The engine could not carry out a browser operation (for example the
    /// element could not be clicked, or no document arrived); nothing was
    /// committed.
    ActionFailed,
    /// The worker process exited during an operation; the lifetime is over
    /// and nothing was committed.
    WorkerExited,
    /// The caller cancelled the lifetime (`CancelHandle::cancel`); nothing
    /// in flight was committed.
    Cancelled,
    /// BR-01: the approved element is gone (a re-render replaced it) and no
    /// single element with its approved role and accessible name took its
    /// place; nothing was clicked.
    TargetStale,
    /// BR-02: an approved action was dispatched and its outcome is unknown
    /// (it failed or timed out after the page may have changed). Observe
    /// again before anything else; it is never repeated automatically.
    OutcomeUnknown,
    /// BR-04: another element covers the approved one (an overlay, a
    /// banner), so the engine never performed the pointer action; observe
    /// again (after a download attempt, navigate again: its page is closed).
    TargetOccluded,
}

impl fmt::Display for UnavailableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEngine => write!(f, "no supported browser engine is installed"),
            Self::UnsupportedEngine => write!(f, "browser engine is unsupported or untrusted"),
            Self::LaunchFailed => write!(f, "browser host launch failed"),
            Self::ProtocolViolation => write!(f, "browser host protocol violation"),
            Self::UnsupportedRuntime => {
                write!(f, "browser worker runtime is missing or unsupported")
            }
            Self::ManagedPolicy => write!(f, "a managed browser policy prevents confinement"),
            Self::TimedOut => write!(f, "the browser operation timed out"),
            Self::ActionFailed => write!(f, "the browser action failed"),
            Self::WorkerExited => write!(f, "the browser worker exited"),
            Self::Cancelled => write!(f, "the browser operation was cancelled"),
            Self::TargetStale => write!(f, "the approved element is no longer on the page"),
            Self::TargetOccluded => write!(f, "another element covers the approved element"),
            Self::OutcomeUnknown => write!(
                f,
                "the approved action was dispatched and its outcome is unknown"
            ),
        }
    }
}

/// Why an approved download committed nothing (#307). Each is a refusal or
/// an engine outcome, never a partial write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadFailure {
    /// The document answered with a status other than 2xx (a redirect
    /// included: the approved document is exactly the approved link).
    HttpStatus,
    /// The document was larger than the transfer bound.
    Oversized,
    /// No document arrived in time; a request the browser policy refused
    /// also ends here, as it never answers.
    TimedOut,
    /// The engine could not click the link or capture the document.
    EngineFailed,
}

impl fmt::Display for DownloadFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpStatus => write!(f, "the document did not answer 2xx"),
            Self::Oversized => write!(f, "the document is larger than the transfer bound"),
            Self::TimedOut => write!(f, "no document arrived in time"),
            Self::EngineFailed => write!(f, "the engine could not capture the document"),
        }
    }
}

/// Every failure of the browser host. No variant widens authority.
#[derive(Debug)]
pub enum HostError {
    Unavailable(UnavailableReason),
    /// An approved download committed nothing, for a typed reason.
    Download(DownloadFailure),
    Invalid(String),
    Platform(String),
    Io(std::io::Error),
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(f, "browser unavailable: {reason}"),
            Self::Download(reason) => write!(f, "download refused: {reason}"),
            Self::Invalid(detail) => write!(f, "invalid browser host input: {detail}"),
            Self::Platform(detail) => write!(f, "browser host platform failure: {detail}"),
            Self::Io(err) => write!(f, "browser host I/O failure: {err}"),
        }
    }
}

impl std::error::Error for HostError {}

impl From<std::io::Error> for HostError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_reasons_render_without_authority() {
        for reason in [
            UnavailableReason::NoEngine,
            UnavailableReason::UnsupportedEngine,
            UnavailableReason::LaunchFailed,
            UnavailableReason::ProtocolViolation,
        ] {
            let text = HostError::Unavailable(reason).to_string();
            assert!(text.starts_with("browser unavailable: "));
        }
    }
}
