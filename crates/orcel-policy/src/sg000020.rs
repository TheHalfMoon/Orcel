#[path = "sg000019.rs"]
mod sg000019_legacy;

pub use orcel_approval::ApprovalClass;
pub use sg000019_legacy::{
    validate_relative_target, FetchDestination, PolicyDecision, PolicyError, PushDestination,
    Workspace,
};

use orcel_contracts::{FailureCode, RequestEnvelope};
use serde_json::Value;

pub const POLICY_REVISION: &str = "sg-000020-v1";

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    legacy: sg000019_legacy::PolicyEngine,
}

impl PolicyEngine {
    pub fn new(workspaces: Vec<Workspace>) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000019_legacy::PolicyEngine::new(workspaces)?,
        })
    }

    pub fn with_destinations(
        workspaces: Vec<Workspace>,
        fetch_destinations: Vec<FetchDestination>,
        push_destinations: Vec<PushDestination>,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000019_legacy::PolicyEngine::with_destinations(
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
        if is_trust_read(request) {
            self.validate_trust_read(request)?;
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
        if is_trust_mutation(request) {
            self.validate_trust_mutation(request)?;
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
        if is_history_query(request) {
            self.validate_history_query(request)?;
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
        let decision = self.legacy.authorize(request)?;
        Ok(PolicyDecision {
            workspace: decision.workspace,
            policy_revision: POLICY_REVISION,
        })
    }
}

pub fn approval_class_for(capability: &str, operation: &str) -> ApprovalClass {
    if is_trust_mutation_shape(capability, operation) {
        return ApprovalClass::Strong;
    }
    sg000019_legacy::approval_class_for(capability, operation)
}

fn is_trust_read(request: &RequestEnvelope) -> bool {
    matches!(
        (request.capability.as_str(), request.operation.as_str()),
        ("workspace.trust.get", "get")
    )
}

fn is_trust_mutation(request: &RequestEnvelope) -> bool {
    is_trust_mutation_shape(&request.capability, &request.operation)
}

fn is_trust_mutation_shape(capability: &str, operation: &str) -> bool {
    matches!(
        (capability, operation),
        ("workspace.trust.grant", "grant")
            | ("workspace.trust.revoke", "revoke")
            | ("trust.revoke_emergency", "revoke")
    )
}

fn is_history_query(request: &RequestEnvelope) -> bool {
    matches!(
        (request.capability.as_str(), request.operation.as_str()),
        ("approval.history.query", "query") | ("trust.history.query", "query")
    )
}

impl PolicyEngine {
    fn validate_trust_read(&self, request: &RequestEnvelope) -> Result<(), PolicyError> {
        if request.version != orcel_contracts::INTERNAL_PROTOCOL_VERSION {
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
        let arguments = request.arguments.as_object().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "workspace.trust.get arguments must be an object",
            )
        })?;
        if !arguments.is_empty() {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "workspace.trust.get accepts no argument fields",
            ));
        }
        Ok(())
    }

    fn validate_trust_mutation(&self, request: &RequestEnvelope) -> Result<(), PolicyError> {
        if request.version != orcel_contracts::INTERNAL_PROTOCOL_VERSION {
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
        let arguments = request.arguments.as_object().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "trust mutation arguments must be an object",
            )
        })?;
        match (request.capability.as_str(), request.operation.as_str()) {
            ("workspace.trust.grant", "grant") | ("workspace.trust.revoke", "revoke") => {
                if !arguments.is_empty() {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        "workspace trust grant and revoke accept no caller-supplied trust fields; the capability itself selects the transition",
                    ));
                }
            }
            ("trust.revoke_emergency", "revoke") => {
                if !arguments.is_empty() {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        "emergency revoke accepts no argument fields",
                    ));
                }
            }
            _ => {
                return Err(policy_error(
                    FailureCode::CapabilityDenied,
                    format!(
                        "capability/operation is not allowed by {POLICY_REVISION}: {}/{}",
                        request.capability, request.operation
                    ),
                ));
            }
        }
        Ok(())
    }

    fn validate_history_query(&self, request: &RequestEnvelope) -> Result<(), PolicyError> {
        if request.version != orcel_contracts::INTERNAL_PROTOCOL_VERSION {
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
        let arguments = request.arguments.as_object().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "history query arguments must be an object",
            )
        })?;
        match (request.capability.as_str(), request.operation.as_str()) {
            ("approval.history.query", "query") | ("trust.history.query", "query") => {
                if arguments.len() > 1 {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        "history query accepts at most a limit field",
                    ));
                }
                if let Some(limit) = arguments.get("limit") {
                    let value = limit.as_u64().ok_or_else(|| {
                        policy_error(
                            FailureCode::InvalidRequest,
                            "history query limit must be an unsigned integer",
                        )
                    })?;
                    if !(1..=200).contains(&value) {
                        return Err(policy_error(
                            FailureCode::InvalidRequest,
                            "history query limit must be between 1 and 200",
                        ));
                    }
                }
                if let Some(key) = arguments.keys().find(|key| *key != "limit") {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        format!("history query does not accept argument field: {key}"),
                    ));
                }
            }
            _ => {
                return Err(policy_error(
                    FailureCode::CapabilityDenied,
                    format!(
                        "capability/operation is not allowed by {POLICY_REVISION}: {}/{}",
                        request.capability, request.operation
                    ),
                ));
            }
        }
        Ok(())
    }
}

fn policy_error(code: FailureCode, message: impl Into<String>) -> PolicyError {
    PolicyError {
        code,
        message: message.into(),
    }
}

#[allow(dead_code)]
fn validate_history_limit(arguments: &Value) -> Result<usize, PolicyError> {
    let limit = arguments.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;
    Ok(limit.clamp(1, 200))
}

#[cfg(test)]
mod sg000020_tests {
    use super::*;
    use serde_json::{json, Value};

    fn engine() -> (PolicyEngine, std::path::PathBuf) {
        let root = crate::test_support::unique_temp_dir("orcel-policy-sg000020");
        let engine = PolicyEngine::with_destinations(
            vec![Workspace {
                id: "default".into(),
                root: root.clone(),
            }],
            vec![FetchDestination {
                workspace_id: "default".into(),
                id: "github-main".into(),
                canonical_url: "https://github.com/TheHalfMoon/Orcel.git".into(),
                hostname: "github.com".into(),
                port: 443,
            }],
            vec![PushDestination {
                workspace_id: "default".into(),
                id: "github-push".into(),
                canonical_url: "https://github.com/TheHalfMoon/Orcel.git".into(),
                hostname: "github.com".into(),
                port: 443,
                credential_reference: "anonymous".into(),
            }],
        )
        .expect("policy");
        (engine, root)
    }

    fn request(capability: &str, operation: &str, arguments: Value) -> RequestEnvelope {
        RequestEnvelope {
            version: 1,
            request_id: "sg20".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: Some(".".into()),
            arguments,
        }
    }

    #[test]
    fn trust_mutations_map_to_strong_and_history_queries_are_bounded() {
        assert_eq!(
            approval_class_for("workspace.trust.grant", "grant"),
            ApprovalClass::Strong
        );
        assert_eq!(
            approval_class_for("workspace.trust.revoke", "revoke"),
            ApprovalClass::Strong
        );
        assert_eq!(
            approval_class_for("trust.revoke_emergency", "revoke"),
            ApprovalClass::Strong
        );
        assert_eq!(
            approval_class_for("approval.history.query", "query"),
            ApprovalClass::Soft
        );
        assert_eq!(approval_class_for("fs.write", "write"), ApprovalClass::Soft);
    }

    #[test]
    fn authorizes_trust_read_mutation_and_history_shapes() {
        let (engine, root) = engine();
        engine
            .authorize(&request("workspace.trust.get", "get", json!({})))
            .expect("trust get authorized");
        engine
            .authorize(&request("workspace.trust.grant", "grant", json!({})))
            .expect("trust grant authorized");
        engine
            .authorize(&request("workspace.trust.revoke", "revoke", json!({})))
            .expect("trust revoke authorized");
        engine
            .authorize(&request("trust.revoke_emergency", "revoke", json!({})))
            .expect("emergency revoke authorized");
        engine
            .authorize(&request(
                "approval.history.query",
                "query",
                json!({"limit": 10}),
            ))
            .expect("approval history query authorized");
        engine
            .authorize(&request("trust.history.query", "query", json!({})))
            .expect("trust history query authorized");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_caller_supplied_trust_fields_and_unknown_history_fields() {
        let (engine, root) = engine();
        let error = engine
            .authorize(&request(
                "workspace.trust.grant",
                "grant",
                json!({"trusted": true}),
            ))
            .expect_err("caller trust field must be rejected");
        assert_eq!(error.code, FailureCode::InvalidRequest);
        let error = engine
            .authorize(&request(
                "approval.history.query",
                "query",
                json!({"limit": 10, "secret": "x"}),
            ))
            .expect_err("unknown history field must be rejected");
        assert_eq!(error.code, FailureCode::InvalidRequest);
        let error = engine
            .authorize(&request(
                "approval.history.query",
                "query",
                json!({"limit": 500}),
            ))
            .expect_err("excessive limit must be rejected");
        assert_eq!(error.code, FailureCode::InvalidRequest);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn denies_legacy_privileged_and_approve_like_shapes() {
        let (engine, root) = engine();
        for (capability, operation) in [
            ("policy.change", "change"),
            ("workspace.trust_change", "trust_change"),
            ("approval", "approve"),
            ("git.push", "force-push"),
            ("fs.delete", "delete"),
        ] {
            let error = engine
                .authorize(&request(capability, operation, json!({})))
                .expect_err("must remain denied");
            assert_eq!(error.code, FailureCode::CapabilityDenied);
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn preserves_p06_and_strong_classification() {
        let (engine, root) = engine();
        let head = "0123456789abcdef0123456789abcdef01234567";
        engine
            .authorize(&request(
                "git.push.preview",
                "preview",
                json!({"policy_id": "github-push", "source_branch": "main", "dest_branch": "main", "credential_reference": "anonymous"}),
            ))
            .expect("push preview still authorized");
        engine
            .authorize(&request(
                "git.stage",
                "stage",
                json!({"expected_head": head, "paths": ["a.txt"]}),
            ))
            .expect("stage still authorized");
        assert_eq!(
            approval_class_for("policy.change", "change"),
            ApprovalClass::Strong
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
