//! The authority's one error type: a frozen [`FailureCode`] and a message
//! that names the rule, never a secret.

use orcel_contracts::FailureCode;
use std::fmt;

/// The reason prefix of [`AuthorityError::enrollment_unavailable`].
pub const ENROLLMENT_UNAVAILABLE: &str = "enrollment_unavailable";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityError {
    pub code: FailureCode,
    pub message: String,
}

impl AuthorityError {
    pub fn new(code: FailureCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The service is absent, not answering, or failed its identity check.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(FailureCode::AuthorityUnavailable, message)
    }

    /// The caller may not do this.
    pub fn denied(message: impl Into<String>) -> Self {
        Self::new(FailureCode::CapabilityDenied, message)
    }

    /// The request is malformed or out of bounds.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(FailureCode::InvalidRequest, message)
    }

    /// A lease exists but is revoked, expired, from another epoch or bound
    /// to someone else.
    pub fn lease_invalid(message: impl Into<String>) -> Self {
        Self::new(FailureCode::LeaseInvalid, message)
    }

    /// No lease where one is needed.
    pub fn lease_required(message: impl Into<String>) -> Self {
        Self::new(FailureCode::LeaseRequired, message)
    }

    /// Something inside the service failed; the request is refused.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(FailureCode::InternalError, message)
    }

    /// Hello key enrollment cannot run on this PC: no pinned TPM
    /// attestation root is present, so no attestation could be verified
    /// (fail closed). The message starts with [`ENROLLMENT_UNAVAILABLE`].
    pub fn enrollment_unavailable() -> Self {
        Self::new(
            FailureCode::Unsupported,
            format!(
                "{ENROLLMENT_UNAVAILABLE}: no pinned TPM attestation root (Microsoft TPM Root Certificate Authority 2014) is present on this PC, so no key attestation can be verified; enrollment is refused"
            ),
        )
    }

    /// This operating system has no authority service yet (track X).
    pub fn unsupported() -> Self {
        Self::new(
            FailureCode::Unsupported,
            "the Orcel authority service is Windows only in this slice; macOS and Linux arrive with track X",
        )
    }
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for AuthorityError {}
