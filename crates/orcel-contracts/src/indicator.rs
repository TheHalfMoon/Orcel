//! Full Control indicator protocol frames and the out-of-band revoke
//! request (spec section 4.13; Windows, Wave 1).
//!
//! Frames only. The indicator (`apps/orcel-indicator`, WP1-12) and the
//! `orceld` side are not part of this crate. Frames use the section 4.9
//! framing with a smaller bound. Nothing shown by the indicator is trusted
//! for authority.

use serde::{Deserialize, Serialize};

use crate::event::AnchorRef;
use crate::lease::LeaseView;
use crate::Contract;

pub const INDICATOR_GENERATION: u32 = 1;
pub const MAX_INDICATOR_FRAME_BYTES: usize = 16 * 1024;
/// The indicator sends a heartbeat at this interval while all visibility
/// checks pass.
pub const INDICATOR_HEARTBEAT_INTERVAL_MS: u64 = 1_000;
/// Full Control is refused when the last all-true heartbeat is older.
pub const INDICATOR_HEARTBEAT_STALE_MS: u64 = 2_000;
/// Without a `stop_ack` within this time the indicator stops executors
/// itself and writes a revoke request.
pub const STOP_ACK_TIMEOUT_MS: u64 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Button,
    Hotkey,
    CloseOrHide,
    SessionLock,
}

/// The five self-reported visibility checks behind a heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Visibility {
    pub topmost: bool,
    pub not_minimised: bool,
    pub not_cloaked: bool,
    pub on_monitor: bool,
    pub on_input_desktop: bool,
}

impl Visibility {
    pub const fn all_pass(&self) -> bool {
        self.topmost
            && self.not_minimised
            && self.not_cloaked
            && self.on_monitor
            && self.on_input_desktop
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case", deny_unknown_fields)]
pub enum OrceldToIndicator {
    Hello {
        generation: u32,
        orceld_pid: u32,
        orceld_start_time: u64,
        nonce: String,
    },
    /// Shown, never trusted for authority.
    State {
        #[serde(default)]
        lease: Option<LeaseView>,
        #[serde(default)]
        anchor: Option<AnchorRef>,
    },
    /// The handle value is valid in the indicator's own handle table.
    JobHandle {
        job_id: String,
        handle: u64,
    },
    JobGone {
        job_id: String,
    },
    StopAck {
        new_epoch: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case", deny_unknown_fields)]
pub enum IndicatorToOrceld {
    Hello {
        generation: u32,
        nonce: String,
    },
    Heartbeat {
        seq: u64,
        visible: Visibility,
    },
    StopRequest {
        reason: StopReason,
    },
    HotkeyStatus {
        registered: bool,
    },
    /// `false` when `DisableLockWorkstation` is set.
    LockStatus {
        available: bool,
    },
}

/// The file the indicator writes under the private state root's `stop`
/// directory when `orceld` does not acknowledge a stop. It can only remove
/// authority, never grant it, so it is unauthenticated on purpose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeRequest {
    /// `"orcel.revoke-request/1"`.
    pub contract: String,
    pub at_ms: u64,
    pub reason: StopReason,
    pub last_epoch_seen: u64,
}

impl Contract for RevokeRequest {
    const CONTRACT: &'static str = "orcel.revoke-request/1";
}
