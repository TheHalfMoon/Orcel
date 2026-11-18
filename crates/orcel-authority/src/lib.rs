//! SG-000132 slice 1: the Orcel authority service.
//!
//! Spec sections 1.2 (C-26 to C-30), 4.8 and 4.13 of
//! `docs/orcel/implementation-readiness/prep/UNIFIED_INTEGRATION_SPEC.md`.
//! Orcel's Full Control authority (the lease-signing key, the leases, the
//! authority epoch, the revocation counter, the enrolled presence keys and
//! the Full Control audit chain) moves out of the user session into a
//! Windows service that runs as the virtual account
//! `NT SERVICE\OrcelAuthority`, with state in a directory users cannot read.
//!
//! Layout:
//!
//! - [`lease`]: the signed lease shapes (desktop Full User and browser Full
//!   Access), scope validation, the narrow default scope and the signing
//!   input. Platform independent.
//! - [`core`]: the authority state machine (grant intent, service-observed
//!   unlock, service-rendered confirmation, presence, issuance, verify,
//!   authorize, revoke, stop, expiry) behind small traits for the signer,
//!   presence verifier, confirmer, event sink and entropy. Platform
//!   independent, so its rules are tested on every OS.
//! - [`audit`]: the hash-chained audit log with session-asserted claims kept
//!   apart from service-observed facts.
//! - [`protocol`]: the pipe wire format (length-prefixed JSON).
//! - [`pipe_sddl`]: the pipe security descriptor and the exact client
//!   access mask (anti-squatting, spec 4.13).
//! - [`caller`]: what the service observed about a pipe client and which
//!   role that earns.
//! - `win` (Windows only): CNG signing and verification, DPAPI, the named
//!   pipe server and client with server verification, the SCM service
//!   entry, the Event Log, `WTSSendMessageW` confirmations and the state
//!   directory ACL check.
//! - [`client`]: the client every Orcel component uses (orceld first); it
//!   verifies the server before sending anything and fails closed.
//!
//! On macOS and Linux everything compiles, the platform independent rules
//! are tested, and every service or client entry point answers
//! [`AuthorityError::unsupported`] (track X brings the LaunchDaemon and the
//! systemd unit).

pub mod audit;
pub mod caller;
pub mod client;
pub mod core;
#[cfg(test)]
mod core_tests;
pub mod error;
pub mod lease;
pub mod pipe_sddl;
pub mod protocol;

#[cfg(windows)]
pub mod win;

pub use error::AuthorityError;

/// The SCM service name.
pub const SERVICE_NAME: &str = "OrcelAuthority";

/// The service's virtual account.
pub const SERVICE_ACCOUNT: &str = r"NT SERVICE\OrcelAuthority";

/// The installed service's pipe (spec 4.13).
pub const SERVICE_PIPE_NAME: &str = r"\\.\pipe\orcel-authority";

/// Every console-mode pipe name starts with this, so a console run can
/// never hold (squat) the installed service's name.
pub const CONSOLE_PIPE_PREFIX: &str = r"\\.\pipe\orcel-authority-console-";

/// The Event Log source the install script registers (spec 4.8).
pub const EVENT_SOURCE: &str = "Orcel";

/// Event id of an audit chain anchor (spec 4.8).
pub const EVENT_ANCHOR: u32 = 4100;

/// Event id of a granted scope (spec 4.13 step 6).
pub const EVENT_GRANTED_SCOPE: u32 = 4101;

/// Event id of a grant intent and of its confirmation result (spec 4.13
/// steps 1 and 4).
pub const EVENT_INTENT: u32 = 4102;

/// Event id (error type) of a refused start, such as a pre-created pipe
/// name (slice 1 addition; spec 4.13 asks for "an Event Log error").
pub const EVENT_SERVICE_ERROR: u32 = 4103;

/// How the authority runs. Some guarantees hold only as the installed
/// service; [`RunMode::Console`] is the test and development harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    /// Installed under the SCM as `NT SERVICE\OrcelAuthority`.
    Service,
    /// `orcel-authority --console` under the current user with a temporary
    /// state directory. The state is readable by that user, the pipe owner
    /// is that user, no session change is observed (so no grant window ever
    /// opens and nothing can be issued) and events go to a file.
    Console,
}

impl RunMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Console => "console",
        }
    }
}

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Bytes of lowercase or uppercase hex text, or none.
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    };
    text.as_bytes()
        .chunks(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

/// SHA-256 of `bytes`, lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(bytes))
}

/// Milliseconds since the Unix epoch (0 if the clock is before it).
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
