//! Founder decision of 2026-11-23: Git is off until it runs inside an OS
//! sandbox.
//!
//! One compiled constant decides, and nothing at run time can change it: no
//! environment variable, configuration, registry value, request field,
//! policy or Cargo feature. [`require`] is the first thing a provider does
//! when it is made and is called again before every Git process starts, so
//! no approval, journal entry or lease is used for a Git operation that will
//! not run.

use super::GitProviderError;
use orcel_contracts::FailureCode;

/// Whether Git runs inside an OS sandbox. It does not yet. `cfg!(test)`
/// holds only while this crate's own unit tests are compiled, never when the
/// crate is a dependency and never for integration tests
/// (`tests/off_until_confined.rs` and orceld's tests check both), so the
/// provider's own checks stay tested while every shipped build refuses.
const PROCESS_CONFINED: bool = cfg!(test);

// A dev-dependency exists only for this crate's own tests, so compiler flags
// that set `test` on a build of anything else do not compile.
#[cfg(test)]
use serde as _;

/// What every Git operation answers while Git is off.
pub const OFF_MESSAGE: &str = "Git is off until it runs confined";

/// Refuses while Git does not run confined.
pub fn require() -> Result<(), GitProviderError> {
    if PROCESS_CONFINED {
        return Ok(());
    }
    Err(GitProviderError::new(
        FailureCode::ProviderUnavailable,
        OFF_MESSAGE,
    ))
}
