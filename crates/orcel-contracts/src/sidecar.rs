//! Sidecar IPC: handshake, heartbeat and kill (spec section 4.9).
//!
//! Generalizes SG-000074 (`proto.rs`): anonymous pipes, `u32` little-endian
//! length plus JSON, closed vocabularies, unknown frames rejected without
//! action. Frames only: no host, no launch, no sandbox lives here
//! (`orcel-sidecar`, Wave 2).
//!
//! A sidecar's reported `kind` and `version` are informational; identity
//! comes from the launch hash (C-10). `session_nonce` proves liveness and
//! pairing of this pipe to this launch; it is not authentication, and no
//! frame grants authority.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SIDECAR_GENERATION: u32 = 1;
/// Control frames, as SG-000074's `MAX_FRAME_BYTES`.
pub const MAX_CONTROL_FRAME_BYTES: usize = 64 * 1024;
/// Ceiling for a sidecar's declared data frame bound.
pub const MAX_DATA_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// First frame both ways must be `hello` within this time.
pub const HELLO_TIMEOUT_MS: u64 = 5_000;
pub const HEARTBEAT_INTERVAL_MS: u64 = 2_000;
/// Missed `heartbeat_ack` frames that kill the child.
pub const MAX_MISSED_HEARTBEATS: u32 = 3;
pub const CANCEL_GRACE_MS: u64 = 2_000;
/// Ceiling for `Shutdown.deadline_ms`.
pub const MAX_SHUTDOWN_DEADLINE_MS: u64 = 5_000;
/// Where sockets cannot be denied outright, listener scans repeat at this
/// interval after `hello`.
pub const LISTENER_SCAN_INTERVAL_MS: u64 = 5_000;

/// Limits the host declares to the sidecar in `hello`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarLimits {
    /// Per-sidecar data frame bound, at most `MAX_DATA_FRAME_BYTES`.
    pub max_data_frame_bytes: u32,
    pub heartbeat_interval_ms: u64,
    pub cancel_grace_ms: u64,
}

impl SidecarLimits {
    /// Whether the declared limits stay inside the protocol ceilings.
    pub const fn within_ceilings(&self) -> bool {
        self.max_data_frame_bytes as usize <= MAX_DATA_FRAME_BYTES
            && self.heartbeat_interval_ms > 0
            && self.heartbeat_interval_ms <= HEARTBEAT_INTERVAL_MS
            && self.cancel_grace_ms <= CANCEL_GRACE_MS
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostToSidecar {
    Hello {
        generation: u32,
        session_nonce: String,
        limits: SidecarLimits,
    },
    Heartbeat {
        seq: u64,
    },
    /// Sidecar-specific body, closed per sidecar kind.
    Request {
        id: u64,
        body: Value,
    },
    Cancel {
        id: u64,
    },
    Shutdown {
        deadline_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case", deny_unknown_fields)]
pub enum SidecarToHost {
    Hello {
        generation: u32,
        session_nonce: String,
        kind: String,
        version: String,
    },
    HeartbeatAck {
        seq: u64,
    },
    Response {
        id: u64,
        body: Value,
    },
    Progress {
        id: u64,
        done: u64,
        #[serde(default)]
        total: Option<u64>,
    },
    Error {
        #[serde(default)]
        id: Option<u64>,
        code: String,
    },
    Bye {},
}
