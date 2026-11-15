pub mod prompt_display;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const INTERNAL_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub version: u32,
    pub request_id: String,
    pub client_session_id: String,
    pub workspace_id: String,
    pub capability: String,
    pub operation: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
}

/// SG-000055 remote dispatch context.
///
/// Supplied only by the local device uplink from an authenticated, verified
/// relay route; never derived from tool arguments. It grants nothing: it only
/// selects the local remote-session lease that `orceld` must find active.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteContext {
    pub principal: String,
    pub remote_connection_id: String,
    pub connection_id: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub provider_kind: String,
    pub client_profile_id: String,
    pub client_profile_revision: u64,
    pub tool_surface_profile: String,
    pub scopes: Vec<String>,
}

/// The line-delimited request accepted by `orceld`: the unchanged internal
/// request plus an optional remote context and the transport's tool
/// surface profile. Local transports never send `remote`; remote dispatch
/// always does.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteRequestEnvelope {
    #[serde(flatten)]
    pub request: RequestEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemoteContext>,
    /// SG-000108 decision 6: the tool surface profile the MCP transport
    /// serves, as its local configuration selected it. It grants nothing
    /// by itself; `orceld` requires `browser_structured` for a live browser
    /// shape and ignores it for every other shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: FailureCode,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub workspace_id: String,
    pub policy_revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub version: u32,
    pub request_id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
}

impl ResponseEnvelope {
    pub fn success(request: &RequestEnvelope, result: Value, policy_revision: &str) -> Self {
        Self {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            ok: true,
            result: Some(result),
            error: None,
            evidence: Some(Evidence {
                workspace_id: request.workspace_id.clone(),
                policy_revision: policy_revision.to_owned(),
                target: request.target.clone(),
            }),
        }
    }

    pub fn failure(
        request_id: impl Into<String>,
        code: FailureCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: request_id.into(),
            ok: false,
            result: None,
            error: Some(ErrorBody {
                code,
                message: message.into(),
            }),
            evidence: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_session_inactive_has_the_frozen_wire_spelling() {
        let text = serde_json::to_string(&FailureCode::RemoteSessionInactive).unwrap();
        assert_eq!(text, "\"REMOTE_SESSION_INACTIVE\"");
    }

    #[test]
    fn local_requests_parse_without_remote_context() {
        let line = r#"{"version":1,"request_id":"r","client_session_id":"s","workspace_id":"w","capability":"fs.read","operation":"read","target":"a","arguments":{}}"#;
        let envelope: RemoteRequestEnvelope = serde_json::from_str(line).unwrap();
        assert!(envelope.remote.is_none());
        assert!(envelope.profile.is_none());
        assert_eq!(envelope.request.capability, "fs.read");
    }

    #[test]
    fn the_profile_travels_beside_the_request_and_is_omitted_when_absent() {
        let line = r#"{"version":1,"request_id":"r","client_session_id":"s","workspace_id":"w","capability":"fs.read","operation":"read","arguments":{},"profile":"browser_structured"}"#;
        let envelope: RemoteRequestEnvelope = serde_json::from_str(line).unwrap();
        assert_eq!(envelope.profile.as_deref(), Some("browser_structured"));
        assert_eq!(envelope.request.capability, "fs.read");
        let mut without = envelope;
        without.profile = None;
        let text = serde_json::to_string(&without).unwrap();
        assert!(!text.contains("profile"), "{text}");
    }

    #[test]
    fn remote_context_is_strict_camel_case() {
        let line = r#"{"version":1,"request_id":"r","client_session_id":"s","workspace_id":"w","capability":"fs.read","operation":"read","arguments":{},"remote":{"principal":"p","remoteConnectionId":"rc","connectionId":"cn","deviceId":"d","deviceEpoch":1,"providerKind":"generic","clientProfileId":"c","clientProfileRevision":1,"toolSurfaceProfile":"core","scopes":["orcel.read"]}}"#;
        let envelope: RemoteRequestEnvelope = serde_json::from_str(line).unwrap();
        let remote = envelope.remote.expect("remote context");
        assert_eq!(remote.remote_connection_id, "rc");
        let unknown = line.replace("\"scopes\"", "\"trusted\":true,\"scopes\"");
        assert!(serde_json::from_str::<RemoteRequestEnvelope>(&unknown).is_err());
        let missing = line.replace("\"deviceEpoch\":1,", "");
        assert!(serde_json::from_str::<RemoteRequestEnvelope>(&missing).is_err());
    }
}
