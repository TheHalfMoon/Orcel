#[path = "sg000018.rs"]
mod sg000018_legacy;

pub use orcel_approval::ApprovalClass;
pub use sg000018_legacy::{
    validate_relative_target, FetchDestination, PolicyDecision, PolicyError, PushDestination,
    Workspace,
};

use orcel_contracts::{FailureCode, RequestEnvelope};

pub const POLICY_REVISION: &str = "sg-000019-v1";

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    legacy: sg000018_legacy::PolicyEngine,
}

impl PolicyEngine {
    pub fn new(workspaces: Vec<Workspace>) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000018_legacy::PolicyEngine::new(workspaces)?,
        })
    }

    pub fn with_destinations(
        workspaces: Vec<Workspace>,
        fetch_destinations: Vec<FetchDestination>,
        push_destinations: Vec<PushDestination>,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000018_legacy::PolicyEngine::with_destinations(
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
        if is_privileged(request) {
            return Err(policy_error(
                FailureCode::CapabilityDenied,
                format!(
                    "capability/operation is denied by {POLICY_REVISION}: {}/{}; PRIVILEGED authority requires STRONG presence and no PRIVILEGED capability is authorized in this grain",
                    request.capability, request.operation
                ),
            ));
        }
        if is_selected_destructive(request) {
            return Err(policy_error(
                FailureCode::CapabilityDenied,
                format!(
                    "capability/operation is denied by {POLICY_REVISION}: {}/{}; selected DESTRUCTIVE authority requires STRONG presence and remains denied in this grain",
                    request.capability, request.operation
                ),
            ));
        }
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

pub fn approval_class_for(capability: &str, operation: &str) -> ApprovalClass {
    if is_privileged_shape(capability, operation)
        || is_selected_destructive_shape(capability, operation)
    {
        ApprovalClass::Strong
    } else {
        ApprovalClass::Soft
    }
}

fn is_privileged(request: &RequestEnvelope) -> bool {
    is_privileged_shape(&request.capability, &request.operation)
}

fn is_privileged_shape(capability: &str, operation: &str) -> bool {
    if matches!(
        capability,
        "policy.change"
            | "workspace.trust_change"
            | "workspace.trust-change"
            | "service.install"
            | "credential_binding_change"
            | "credential-binding-change"
            | "elevation.request"
    ) {
        return true;
    }
    if capability.starts_with("policy.")
        || capability.starts_with("workspace.trust")
        || capability.starts_with("service.")
        || capability.starts_with("credential_binding")
        || capability.starts_with("elevation.")
    {
        return true;
    }
    matches!(
        operation,
        "trust_change"
            | "trust-change"
            | "policy_change"
            | "policy-change"
            | "elevate"
            | "elevation"
            | "install-service"
    )
}

fn is_selected_destructive(request: &RequestEnvelope) -> bool {
    is_selected_destructive_shape(&request.capability, &request.operation)
}

fn is_selected_destructive_shape(capability: &str, operation: &str) -> bool {
    if matches!(
        (capability, operation),
        ("fs.delete", "delete")
            | ("git.reset", "reset_hard")
            | ("git.reset", "reset-hard")
            | ("process.kill", "kill_tree")
            | ("process.kill", "kill-tree")
            | ("browser.clear", "clear_profile")
            | ("browser.clear", "clear-profile")
            | ("git.push", "force-push")
            | ("git.push", "delete")
    ) {
        return true;
    }
    if capability == "fs.delete" || capability.starts_with("fs.delete.") {
        return true;
    }
    if capability == "git.reset" || capability == "process.kill" || capability == "browser.clear" {
        return true;
    }
    false
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
mod sg000019_tests {
    use super::*;
    use orcel_approval::ApprovalClass;
    use serde_json::{json, Value};

    fn engine() -> (PolicyEngine, std::path::PathBuf) {
        let root = crate::test_support::unique_temp_dir("orcel-policy-sg000019");
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
            request_id: "sg19".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: Some(".".into()),
            arguments,
        }
    }

    #[test]
    fn privileged_operations_map_to_strong_and_remain_denied() {
        let (engine, root) = engine();
        for (capability, operation) in [
            ("policy.change", "change"),
            ("workspace.trust_change", "trust_change"),
            ("service.install", "install"),
            ("credential_binding_change", "change"),
            ("elevation.request", "elevate"),
            ("policy.change", "approve"),
            ("workspace.trust_change", "change"),
        ] {
            assert_eq!(
                approval_class_for(capability, operation),
                ApprovalClass::Strong,
                "PRIVILEGED {capability}/{operation} must map to STRONG"
            );
            let error = engine
                .authorize(&request(capability, operation, json!({})))
                .expect_err("PRIVILEGED must remain denied without new authority");
            assert_eq!(error.code, FailureCode::CapabilityDenied);
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn selected_destructive_operations_map_to_strong_and_remain_denied() {
        let (engine, root) = engine();
        for (capability, operation) in [
            ("fs.delete", "delete"),
            ("git.reset", "reset_hard"),
            ("process.kill", "kill_tree"),
            ("browser.clear", "clear_profile"),
            ("git.push", "force-push"),
            ("git.push", "delete"),
        ] {
            assert_eq!(
                approval_class_for(capability, operation),
                ApprovalClass::Strong,
                "DESTRUCTIVE {capability}/{operation} must map to STRONG"
            );
            let error = engine
                .authorize(&request(capability, operation, json!({})))
                .expect_err("selected DESTRUCTIVE must remain denied");
            assert!(
                matches!(
                    error.code,
                    FailureCode::CapabilityDenied | FailureCode::InvalidRequest
                ),
                "unexpected code for {capability}/{operation}"
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn existing_file_process_and_git_operations_retain_soft_class() {
        for (capability, operation) in [
            ("fs.write", "write"),
            ("fs.write", "preview"),
            ("process.spawn", "spawn"),
            ("git.stage", "stage"),
            ("git.commit", "commit"),
            ("git.fetch.preview", "preview"),
            ("git.fetch", "fetch"),
            ("git.push.preview", "preview"),
            ("git.push", "push"),
            ("system.status", "get"),
        ] {
            assert_eq!(
                approval_class_for(capability, operation),
                ApprovalClass::Soft,
                "existing {capability}/{operation} must retain SOFT"
            );
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
    fn trust_changes_reuse_and_delegation_remain_unreachable() {
        let (engine, root) = engine();
        for (capability, operation) in [
            ("workspace.trust_change", "change"),
            ("policy.change", "change"),
            ("approval", "approve"),
            ("approval", "replay"),
            ("git.push", "force-push"),
        ] {
            let error = engine
                .authorize(&request(capability, operation, json!({})))
                .expect_err("must remain unreachable");
            assert_eq!(error.code, FailureCode::CapabilityDenied);
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
