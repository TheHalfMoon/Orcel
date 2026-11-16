//! SG-000119 slice A1: the Control Room shell's client of orceld's local app
//! API (`orcel-app-api/1`, `docs/orcel/implementation-readiness/protocol/
//! ORCEL_APP_API_1.md`) and the closed sanitiser every answer and event
//! passes before the web view sees it. The preparation packet is
//! `docs/orcel/implementation-readiness/prep/SG-000119.md`.
//!
//! orceld stays the only authority. This crate only reads:
//!
//! - **Fixed endpoint.** On Windows `\\.\pipe\orcel-<user SID>-app`, the SID
//!   read from this process's token. No environment variable (including
//!   `ORCEL_APP_API_INSTANCE`), argument or configuration file changes it;
//!   an instance suffix exists only for this crate's own `#[cfg(test)]`
//!   tests. On macOS and Linux the socket in the per-user runtime directory
//!   is derived as orceld derives it (protocol section 1; the state-root
//!   fallback is a known limit, see `unix.rs`); only Windows is qualified.
//! - **Identification-only open and server identity before the first
//!   write.** The pipe is opened with `SECURITY_SQOS_PRESENT |
//!   SECURITY_IDENTIFICATION`; then the server's pid, its token user (must
//!   be this user) and its integrity level (Medium or above) are read before
//!   a byte is written ([`identity`]). Unix reads the socket peer's uid.
//! - **Closed methods.** [`Method`] has exactly `status.get`,
//!   `capabilities.get`, `events.subscribe`, `task.list` and `task.get`; no
//!   string becomes a method name.
//! - **Bounded frames and cursors.** At most 64 KiB per frame, newline
//!   included ([`frame`]); epoch-aware cursors that reject a gap before
//!   moving ([`cursor`]).
//! - **The sanitiser** ([`sanitize`]): named fields only, the text,
//!   identifier, path, file-name and hash rules, closed enums and caps;
//!   unknown fields and kinds dropped and counted; no path is opened or
//!   resolved.
//! - **One subscription per window** with a bounded queue of 256 frames
//!   ([`subscription`]), and at most two of orceld's client slots per window
//!   (one subscription, one serialized request).

pub mod client;
pub mod cursor;
pub mod error;
pub mod frame;
pub mod identity;
pub mod method;
pub mod sanitize;
pub mod subscription;
mod transport;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod win;

#[cfg(test)]
mod live_tests;

pub use client::AppApiClient;
pub use cursor::Cursor;
pub use error::ClientError;
pub use identity::IdentityRefusal;
pub use method::{Method, TaskId};
pub use subscription::{Feed, Next, StreamItem, Window};

/// This account's SID as `S-1-5-...`, read from this process's token (the
/// same SID the fixed pipe name carries). SG-000119 A2: the shell names its
/// single-instance mutex `Local\orcel-control-room-<SID>` with it and grants
/// that SID alone in the mutex's DACL.
#[cfg(windows)]
pub fn this_user_sid() -> std::io::Result<String> {
    win::current_user_sid()
}
