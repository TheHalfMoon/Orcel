//! Failure codes (spec section 4.10).
//!
//! Every existing variant keeps its frozen `SCREAMING_SNAKE_CASE` wire
//! spelling. Contracts v1 appends new variants at the end and maps every
//! variant to the HTTP status used by the loopback REST and
//! Firecrawl-compatible surfaces. The mapping is data only: nothing in this
//! crate answers HTTP.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureCode {
    InvalidRequest,
    CapabilityDenied,
    WorkspaceDenied,
    PathEscape,
    PathRaceDetected,
    ApprovalRequired,
    ApprovalDenied,
    ApprovalUnavailable,
    TargetStale,
    ProviderUnavailable,
    ProcessTimeout,
    ProcessTerminationUnverified,
    OutputLimit,
    PostconditionFailed,
    InternalError,
    /// SG-000055: a remote-context request without an exact active local
    /// remote-session lease. Never satisfiable by the remote side.
    RemoteSessionInactive,
    /// Contracts v1: a lease-gated executor was asked for without an active
    /// lease.
    LeaseRequired,
    /// Contracts v1: a lease exists but a binding, the epoch, the policy
    /// revision or the expiry does not match.
    LeaseInvalid,
    /// Contracts v1: no identity binding exists on this OS yet.
    LeaseUnsupportedPlatform,
    /// Contracts v1: Full Control dispatch refused because the protected
    /// indicator is not alive.
    IndicatorUnavailable,
    /// Contracts v1: the capability entry is `unsupported`.
    Unsupported,
    /// Contracts v1: the capability entry is `blocked` by policy.
    PolicyBlocked,
    /// Contracts v1: the job is unknown, expired or not owned by the caller.
    JobNotFound,
    /// Contracts v1: a queue, store or pending-approval bound was reached.
    QueueFull,
    /// Contracts v1: a per-origin politeness budget is exhausted.
    RateLimited,
    /// Contracts v1: the job or unit ended in `outcome_unknown`; it is never
    /// retried automatically.
    OutcomeUnknown,
    /// Contracts v1: the authority service is not installed or not
    /// answering, so Full Control is unavailable.
    AuthorityUnavailable,
    /// Contracts v1: an opt-in feature not granted to this client.
    PermissionRequired,
    /// SG-000135 OB-07: the page waits for a person to complete a sign-in,
    /// one-time code, passkey or CAPTCHA check ("Needs you"). Nothing was
    /// done; Orcel never completes one, and the agent may act on the page
    /// again only after the check is gone and it has observed the page anew.
    HumanVerificationRequired,
}

impl FailureCode {
    /// Every variant, in declaration order.
    pub const ALL: [Self; 29] = [
        Self::InvalidRequest,
        Self::CapabilityDenied,
        Self::WorkspaceDenied,
        Self::PathEscape,
        Self::PathRaceDetected,
        Self::ApprovalRequired,
        Self::ApprovalDenied,
        Self::ApprovalUnavailable,
        Self::TargetStale,
        Self::ProviderUnavailable,
        Self::ProcessTimeout,
        Self::ProcessTerminationUnverified,
        Self::OutputLimit,
        Self::PostconditionFailed,
        Self::InternalError,
        Self::RemoteSessionInactive,
        Self::LeaseRequired,
        Self::LeaseInvalid,
        Self::LeaseUnsupportedPlatform,
        Self::IndicatorUnavailable,
        Self::Unsupported,
        Self::PolicyBlocked,
        Self::JobNotFound,
        Self::QueueFull,
        Self::RateLimited,
        Self::OutcomeUnknown,
        Self::AuthorityUnavailable,
        Self::PermissionRequired,
        Self::HumanVerificationRequired,
    ];

    /// The HTTP status a REST or Firecrawl-compatible front answers with
    /// for this code (spec section 4.10). The match is exhaustive, so a new
    /// variant cannot compile without a mapping.
    pub const fn http_status(&self) -> u16 {
        match self {
            Self::InvalidRequest => 400,
            Self::CapabilityDenied
            | Self::WorkspaceDenied
            | Self::ApprovalDenied
            | Self::ApprovalRequired
            | Self::PathEscape
            | Self::RemoteSessionInactive
            | Self::LeaseRequired
            | Self::LeaseInvalid
            | Self::PolicyBlocked
            | Self::PermissionRequired => 403,
            Self::JobNotFound => 404,
            Self::ProcessTimeout => 408,
            Self::TargetStale | Self::PathRaceDetected | Self::HumanVerificationRequired => 409,
            Self::OutputLimit => 413,
            Self::QueueFull | Self::RateLimited => 429,
            Self::PostconditionFailed
            | Self::InternalError
            | Self::ProcessTerminationUnverified
            | Self::OutcomeUnknown => 500,
            Self::LeaseUnsupportedPlatform | Self::Unsupported => 501,
            Self::ApprovalUnavailable
            | Self::ProviderUnavailable
            | Self::IndicatorUnavailable
            | Self::AuthorityUnavailable => 503,
        }
    }
}
