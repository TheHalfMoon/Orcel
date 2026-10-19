pub mod executable_registry;
pub mod full_control;
pub mod full_control_store;
pub mod protected_state;
pub mod remote_session;
#[path = "sg000039.rs"]
mod sg000039_legacy;
pub mod shell_session;
#[cfg(test)]
mod xp01b_tests;

pub use orcel_approval::ApprovalClass;
pub use sg000039_legacy::{
    validate_relative_target, FetchDestination, PolicyDecision, PolicyError, PushDestination,
    Workspace,
};

use orcel_contracts::{FailureCode, RequestEnvelope, INTERNAL_PROTOCOL_VERSION};

pub const POLICY_REVISION: &str = "sg-000040-v1";

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    legacy: sg000039_legacy::PolicyEngine,
}

impl PolicyEngine {
    pub fn new(workspaces: Vec<Workspace>) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000039_legacy::PolicyEngine::new(workspaces)?,
        })
    }

    pub fn with_destinations(
        workspaces: Vec<Workspace>,
        fetch_destinations: Vec<FetchDestination>,
        push_destinations: Vec<PushDestination>,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000039_legacy::PolicyEngine::with_destinations(
                workspaces,
                fetch_destinations,
                push_destinations,
            )?,
        })
    }

    pub fn workspace(&self, id: &str) -> Option<&Workspace> {
        self.legacy.workspace(id)
    }

    pub fn fetch_destination(
        &self,
        workspace_id: &str,
        policy_id: &str,
    ) -> Option<&FetchDestination> {
        self.legacy.fetch_destination(workspace_id, policy_id)
    }

    pub fn push_destination(
        &self,
        workspace_id: &str,
        policy_id: &str,
    ) -> Option<&PushDestination> {
        self.legacy.push_destination(workspace_id, policy_id)
    }

    pub fn authorize(&self, request: &RequestEnvelope) -> Result<PolicyDecision, PolicyError> {
        if is_full_user_desktop_shape(&request.capability, &request.operation) {
            if request.version != INTERNAL_PROTOCOL_VERSION {
                return Err(policy_error(
                    FailureCode::InvalidRequest,
                    "unsupported internal protocol version",
                ));
            }
            if request.target.is_some() {
                return Err(policy_error(
                    FailureCode::InvalidRequest,
                    "Full User desktop shapes do not accept a target field",
                ));
            }
            let workspace = self
                .legacy
                .workspace(&request.workspace_id)
                .ok_or_else(|| {
                    policy_error(
                        FailureCode::WorkspaceDenied,
                        "requested workspace is not configured",
                    )
                })?;
            return Ok(PolicyDecision {
                workspace: workspace.clone(),
                policy_revision: POLICY_REVISION,
            });
        }
        if is_fs_mutation_shape(&request.capability, &request.operation) {
            if request.version != INTERNAL_PROTOCOL_VERSION {
                return Err(policy_error(
                    FailureCode::InvalidRequest,
                    "unsupported internal protocol version",
                ));
            }
            validate_fs_mutation(request)?;
            let workspace = self
                .legacy
                .workspace(&request.workspace_id)
                .ok_or_else(|| {
                    policy_error(
                        FailureCode::WorkspaceDenied,
                        "requested workspace is not configured",
                    )
                })?;
            return Ok(PolicyDecision {
                workspace: workspace.clone(),
                policy_revision: POLICY_REVISION,
            });
        }
        if orcel_provider_network::is_network_fetch_shape(&request.capability, &request.operation) {
            self.validate_network_fetch(request)?;
            let workspace = self
                .legacy
                .workspace(&request.workspace_id)
                .ok_or_else(|| {
                    policy_error(
                        FailureCode::WorkspaceDenied,
                        "requested workspace is not configured",
                    )
                })?;
            return Ok(PolicyDecision {
                workspace: workspace.clone(),
                policy_revision: POLICY_REVISION,
            });
        }

        if orcel_provider_network::is_denied_network_shape(&request.capability, &request.operation)
        {
            return Err(policy_error(
                FailureCode::CapabilityDenied,
                format!(
                    "capability/operation is denied by {POLICY_REVISION}: {}/{}; SG-000040 authorizes only one explicit network/fetch HTTPS GET with no generic sockets, alternate methods, caller headers, request body, proxy, WebSocket, standing session, or ambient credentials",
                    request.capability, request.operation
                ),
            ));
        }

        let decision = self.legacy.authorize(request)?;
        Ok(PolicyDecision {
            workspace: decision.workspace,
            policy_revision: POLICY_REVISION,
        })
    }

    fn validate_network_fetch(&self, request: &RequestEnvelope) -> Result<(), PolicyError> {
        if request.version != INTERNAL_PROTOCOL_VERSION {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "unsupported internal protocol version",
            ));
        }
        if self.legacy.workspace(&request.workspace_id).is_none() {
            return Err(policy_error(
                FailureCode::WorkspaceDenied,
                "requested workspace is not configured",
            ));
        }
        if request.target.is_some() {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "network/fetch does not accept a target field",
            ));
        }
        let arguments = request.arguments.as_object().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "network/fetch arguments must be an object",
            )
        })?;
        if arguments.len() != 1 || !arguments.contains_key("url") {
            return Err(policy_error(
                FailureCode::CapabilityDenied,
                "network/fetch accepts exactly one caller field: url",
            ));
        }
        let url = arguments
            .get("url")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                policy_error(
                    FailureCode::InvalidRequest,
                    "network/fetch requires string arguments.url",
                )
            })?;
        orcel_provider_network::parse_target(url)
            .map_err(|error| policy_error(error.code, error.message))?;
        Ok(())
    }
}

/// SG-000095 local-only Full User desktop shapes. Authorization here only
/// admits the request to orceld; the dispatch path still requires a fresh
/// per-action approval plus an exact active FullControlLease immediately
/// before private-host actuation.
pub fn is_full_user_desktop_shape(capability: &str, operation: &str) -> bool {
    matches!(
        (capability, operation),
        ("desktop.cursor", "get") | ("desktop.input", "execute") | ("desktop.window", "action")
    )
}

/// SG-000061 bounded filesystem shapes. The legacy generic `fs.delete`
/// shape stays denied; `fs.remove` is the reviewed single-entry removal.
pub fn is_fs_mutation_shape(capability: &str, operation: &str) -> bool {
    matches!(
        (capability, operation),
        ("fs.read_range", "read")
            | ("fs.find", "find")
            | ("fs.mkdir", "mkdir")
            | ("fs.move", "move")
            | ("fs.remove", "remove")
            | ("fs.edit", "edit")
    )
}

fn validate_fs_mutation(request: &RequestEnvelope) -> Result<(), PolicyError> {
    let target = request.target.as_deref().ok_or_else(|| {
        policy_error(
            FailureCode::InvalidRequest,
            "workspace-relative target is required",
        )
    })?;
    validate_relative_target(target)?;
    let arguments = request
        .arguments
        .as_object()
        .ok_or_else(|| policy_error(FailureCode::InvalidRequest, "arguments must be an object"))?;
    let allowed: &[&str] = match request.capability.as_str() {
        "fs.read_range" => &["start_line", "max_lines"],
        "fs.find" => &["pattern", "max_results", "max_depth"],
        "fs.mkdir" => &["parents"],
        "fs.move" => &["to"],
        "fs.remove" => &[],
        "fs.edit" => &["old", "new", "expected_sha256", "replacements"],
        _ => &[],
    };
    if let Some(key) = arguments
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
    {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            format!(
                "{} does not accept argument field: {key}",
                request.capability
            ),
        ));
    }
    if request.capability == "fs.move" {
        let to = arguments
            .get("to")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                policy_error(FailureCode::InvalidRequest, "fs.move requires arguments.to")
            })?;
        validate_relative_target(to)?;
        if to == "." || to.is_empty() {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "fs.move destination must name an entry",
            ));
        }
    }
    if matches!(
        request.capability.as_str(),
        "fs.mkdir" | "fs.move" | "fs.remove" | "fs.edit"
    ) && (target == "." || target.is_empty())
    {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            "the workspace root itself cannot be mutated",
        ));
    }
    Ok(())
}

pub fn approval_class_for(capability: &str, operation: &str) -> ApprovalClass {
    if (capability, operation) == ("fs.remove", "remove") {
        return ApprovalClass::Strong;
    }
    if is_full_user_desktop_shape(capability, operation) {
        return ApprovalClass::Soft;
    }
    if is_fs_mutation_shape(capability, operation) {
        return ApprovalClass::Soft;
    }
    if orcel_provider_network::is_network_fetch_shape(capability, operation) {
        return ApprovalClass::Soft;
    }
    if orcel_provider_network::is_denied_network_shape(capability, operation) {
        return ApprovalClass::Strong;
    }
    sg000039_legacy::approval_class_for(capability, operation)
}

fn policy_error(code: FailureCode, message: impl Into<String>) -> PolicyError {
    PolicyError {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_contracts::RequestEnvelope;
    use serde_json::json;
    use std::path::PathBuf;

    fn engine() -> PolicyEngine {
        PolicyEngine::new(vec![Workspace {
            id: "default".into(),
            root: PathBuf::from("."),
        }])
        .unwrap()
    }

    fn request(arguments: serde_json::Value) -> RequestEnvelope {
        RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "network".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: "network".into(),
            operation: "fetch".into(),
            target: None,
            arguments,
        }
    }

    #[test]
    fn network_fetch_is_soft_and_exact_shape_only() {
        let policy = engine();
        let decision = policy
            .authorize(&request(json!({"url": "https://example.com/data?q=1"})))
            .unwrap();
        assert_eq!(decision.policy_revision, POLICY_REVISION);
        assert_eq!(approval_class_for("network", "fetch"), ApprovalClass::Soft);

        for args in [
            json!({}),
            json!({"url": "https://example.com/", "method": "POST"}),
            json!({"url": "https://example.com/", "headers": {}}),
            json!({"url": "https://example.com/", "body": "x"}),
        ] {
            assert!(policy.authorize(&request(args)).is_err());
        }
    }

    #[test]
    fn alternate_network_shapes_are_strong_denied() {
        let policy = engine();
        for operation in ["post", "connect", "socket", "websocket", "listen"] {
            let mut req = request(json!({"url": "https://example.com/"}));
            req.operation = operation.into();
            let error = policy.authorize(&req).unwrap_err();
            assert_eq!(error.code, FailureCode::CapabilityDenied);
            assert_eq!(
                approval_class_for("network", operation),
                ApprovalClass::Strong
            );
        }
    }

    #[test]
    fn malformed_or_widened_urls_fail_closed() {
        let policy = engine();
        for url in [
            "http://example.com/",
            "https://example.com:8443/",
            "https://user@example.com/",
            "https://127.0.0.1/",
            "https://localhost/",
        ] {
            let error = policy.authorize(&request(json!({"url": url}))).unwrap_err();
            assert!(matches!(
                error.code,
                FailureCode::InvalidRequest | FailureCode::CapabilityDenied
            ));
        }
    }
}
