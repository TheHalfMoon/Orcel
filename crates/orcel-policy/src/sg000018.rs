#[path = "sg000017.rs"]
mod sg000017_legacy;

pub use sg000017_legacy::{
    validate_relative_target, FetchDestination, PolicyDecision, PolicyError, PushDestination,
    Workspace,
};

use orcel_contracts::{FailureCode, RequestEnvelope};

pub const POLICY_REVISION: &str = "sg-000018-v1";

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    legacy: sg000017_legacy::PolicyEngine,
}

impl PolicyEngine {
    pub fn new(workspaces: Vec<Workspace>) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000017_legacy::PolicyEngine::new(workspaces)?,
        })
    }

    pub fn with_destinations(
        workspaces: Vec<Workspace>,
        fetch_destinations: Vec<FetchDestination>,
        push_destinations: Vec<PushDestination>,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000017_legacy::PolicyEngine::with_destinations(
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
        if is_approval_like(request) {
            return Err(policy_error(
                FailureCode::CapabilityDenied,
                format!(
                    "capability/operation is denied by {POLICY_REVISION}: {}/{}; approvals are granted only through the local approval broker and can never be produced, replayed, or delegated through the MCP request surface",
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
}

fn is_approval_like(request: &RequestEnvelope) -> bool {
    if request.capability == "approval"
        || request.capability.starts_with("approval.")
        || request.capability == "git.approve"
        || request.capability == "process.approve"
        || request.capability == "fs.approve"
    {
        return true;
    }
    matches!(
        request.operation.as_str(),
        "approve" | "deny" | "consume" | "replay" | "approve_token"
    )
}

fn policy_error(code: FailureCode, message: impl Into<String>) -> PolicyError {
    PolicyError {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod sg000018_tests {
    use super::*;
    use serde_json::{json, Value};

    fn engine() -> (PolicyEngine, std::path::PathBuf) {
        let root = crate::test_support::unique_temp_dir("orcel-policy-sg000018");
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
            request_id: "sg18".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: Some(".".into()),
            arguments,
        }
    }

    #[test]
    fn denies_approve_like_capabilities_through_the_request_surface() {
        let (engine, root) = engine();
        for (capability, operation) in [
            ("approval", "approve"),
            ("approval.approve", "approve"),
            ("approval.history", "query"),
            ("git.approve", "approve"),
            ("process.approve", "approve"),
            ("fs.approve", "approve"),
            ("git.push", "approve"),
            ("git.fetch", "consume"),
            ("process.spawn", "replay"),
            ("system.status", "approve"),
        ] {
            let error = engine
                .authorize(&request(capability, operation, json!({})))
                .expect_err("approve-like must be denied");
            assert_eq!(
                error.code,
                FailureCode::CapabilityDenied,
                "unexpected code for {capability}/{operation}"
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn preserves_p06_push_fetch_and_mutation_shapes() {
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
                "git.fetch.preview",
                "preview",
                json!({"policy_id": "github-main", "branch": "main"}),
            ))
            .expect("fetch preview still authorized");
        engine
            .authorize(&request(
                "git.stage",
                "stage",
                json!({"expected_head": head, "paths": ["a.txt"]}),
            ))
            .expect("stage still authorized");
        let _ = std::fs::remove_dir_all(root);
    }
}
