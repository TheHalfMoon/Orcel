//! Full Control indicator timing (spec section 4.14; Windows, Wave 1).
//!
//! Constants only. Under spec revision 8 the indicator is disclosure and a
//! convenient Stop: it heartbeats to the authority service, and the service
//! (not `orceld`, not the indicator) owns every executor Job Object and
//! handles stop, expiry, lock and sign-out (section 4.13). The indicator and
//! service pipe frames are defined with the service (WP1-10, WP1-12), so no
//! frame shape is frozen here. The heartbeat proves nothing against a
//! same-user agent (C-27 c).

/// The indicator heartbeats to the service at this interval while it is
/// topmost, visible, not cloaked, on a monitor and on the input desktop.
pub const INDICATOR_HEARTBEAT_INTERVAL_MS: u64 = 1_000;

/// The service refuses `Authorize` after this long without a heartbeat.
pub const INDICATOR_HEARTBEAT_STALE_MS: u64 = 5_000;
