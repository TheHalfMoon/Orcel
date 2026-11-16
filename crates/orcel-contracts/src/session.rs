//! Session (spec section 4.4).

use serde::{Deserialize, Serialize};

use crate::identity::Principal;
use crate::{Contract, RemoteContext};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Stdio,
    LoopbackMcp,
    LoopbackRest,
    Relay,
}

/// One client session as `orceld` sees it. A lease and every new approval
/// bind `orcel_session_id`, so an `orceld` restart invalidates them (C-02,
/// S10). `client_session_id` is never authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    /// `"orcel.session/1"`.
    pub contract: String,
    /// `validate_runtime_session`; replaced on restart.
    pub orcel_session_id: String,
    /// `RequestEnvelope.client_session_id`.
    pub client_session_id: String,
    pub principal: Principal,
    pub transport: Transport,
    /// `core`, `desktop_structured` or `browser_structured`.
    pub tool_surface_profile: String,
    /// SG-000055, only from the uplink.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemoteContext>,
    pub started_at_ms: u64,
}

impl Contract for Session {
    const CONTRACT: &'static str = "orcel.session/1";
}
