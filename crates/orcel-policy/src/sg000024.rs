#[path = "sg000023.rs"]
mod sg000023_legacy;

pub use orcel_approval::ApprovalClass;
pub use sg000023_legacy::{
    validate_relative_target, FetchDestination, PolicyDecision, PolicyError, PushDestination,
    Workspace,
};

use orcel_contracts::{FailureCode, RequestEnvelope};
use serde_json::Value;

pub const POLICY_REVISION: &str = "sg-000024-v1";

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    legacy: sg000023_legacy::PolicyEngine,
}

impl PolicyEngine {
    pub fn new(workspaces: Vec<Workspace>) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000023_legacy::PolicyEngine::new(workspaces)?,
        })
    }

    pub fn with_destinations(
        workspaces: Vec<Workspace>,
        fetch_destinations: Vec<FetchDestination>,
        push_destinations: Vec<PushDestination>,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000023_legacy::PolicyEngine::with_destinations(
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
        if is_actuation_shape(request) {
            self.validate_actuation_shape(request)?;
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
        if orcel_provider_browser::is_allowed_browser_shape(&request.capability, &request.operation)
        {
            // SG-000021 through SG-000023 shapes retain their validation in
            // the legacy engine, but the reported revision advances to the
            // actuation revision.
            let legacy_request = RequestEnvelope {
                version: request.version,
                request_id: request.request_id.clone(),
                client_session_id: request.client_session_id.clone(),
                workspace_id: request.workspace_id.clone(),
                capability: request.capability.clone(),
                operation: request.operation.clone(),
                target: request.target.clone(),
                arguments: request.arguments.clone(),
            };
            self.legacy.authorize(&legacy_request)?;
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
        if orcel_provider_browser::is_denied_browser_shape(&request.capability, &request.operation)
        {
            return Err(policy_error(
                FailureCode::CapabilityDenied,
                format!(
                    "capability/operation is denied by {POLICY_REVISION}: {}/{}; SG-000024 authorizes only browser.profile/status, browser.destination/validate, browser.page/open, browser.navigation/preview, browser.navigation/navigate, read-only browser.snapshot/observe, and structured browser.dom/click and browser.dom/fill, and select, toggle, submit, keyboard, downloads, uploads, personal-profile access, debugging, scripting, and network egress remain absent",
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
    if is_actuation_shape_str(capability, operation) {
        return ApprovalClass::Soft;
    }
    if orcel_provider_browser::is_allowed_browser_shape(capability, operation) {
        return ApprovalClass::Soft;
    }
    if orcel_provider_browser::is_denied_browser_shape(capability, operation) {
        return ApprovalClass::Strong;
    }
    sg000023_legacy::approval_class_for(capability, operation)
}

fn is_actuation_shape(request: &RequestEnvelope) -> bool {
    is_actuation_shape_str(&request.capability, &request.operation)
}

fn is_actuation_shape_str(capability: &str, operation: &str) -> bool {
    matches!(
        (capability, operation),
        ("browser.dom", "click") | ("browser.dom", "fill")
    )
}

impl PolicyEngine {
    fn validate_actuation_shape(&self, request: &RequestEnvelope) -> Result<(), PolicyError> {
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
        if request.target.is_some() {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "browser actuation shapes do not accept a target field",
            ));
        }
        let arguments = request.arguments.as_object().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "browser arguments must be an object",
            )
        })?;
        let (capability, operation) = (request.capability.as_str(), request.operation.as_str());
        let shape = format!("{capability}/{operation}");
        let page_id = arguments
            .get("page_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                policy_error(
                    FailureCode::InvalidRequest,
                    format!("{shape} requires arguments.page_id as a string"),
                )
            })?;
        if page_id.is_empty() || page_id.len() > 256 {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                format!("{shape} page_id is empty or too large"),
            ));
        }
        if !page_id.starts_with(orcel_provider_browser::PAGE_ID_PREFIX) {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                format!("{shape} page_id is malformed"),
            ));
        }
        let expected_origin = arguments
            .get("expected_origin")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                policy_error(
                    FailureCode::InvalidRequest,
                    format!("{shape} requires arguments.expected_origin as a string"),
                )
            })?;
        if expected_origin.is_empty() || expected_origin.len() > 2048 {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                format!("{shape} expected_origin is empty or too large"),
            ));
        }
        for name in ["expected_generation", "expected_document_generation"] {
            let generation = arguments.get(name).and_then(Value::as_u64).ok_or_else(|| {
                policy_error(
                    FailureCode::InvalidRequest,
                    format!("{shape} requires arguments.{name} as an unsigned integer"),
                )
            })?;
            if generation > 1_000_000 {
                return Err(policy_error(
                    FailureCode::InvalidRequest,
                    format!("{shape} {name} is out of range"),
                ));
            }
        }
        let node_id = arguments
            .get("node_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                policy_error(
                    FailureCode::InvalidRequest,
                    format!("{shape} requires arguments.node_id as a string"),
                )
            })?;
        if node_id.is_empty() || node_id.len() > 256 {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                format!("{shape} node_id is empty or too large"),
            ));
        }
        if !node_id.starts_with(orcel_provider_browser::SNAPSHOT_NODE_PREFIX) {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                format!("{shape} node_id is malformed"),
            ));
        }
        let expected_role = arguments
            .get("expected_role")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                policy_error(
                    FailureCode::InvalidRequest,
                    format!("{shape} requires arguments.expected_role as a string"),
                )
            })?;
        let permitted = match operation {
            "click" => orcel_provider_browser::CLICK_ROLES.contains(&expected_role),
            "fill" => orcel_provider_browser::FILL_ROLES.contains(&expected_role),
            _ => false,
        };
        if !permitted {
            return Err(policy_error(
                FailureCode::CapabilityDenied,
                format!("{shape} expected_role does not permit the requested verb"),
            ));
        }
        let expected_state = arguments
            .get("expected_state")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                policy_error(
                    FailureCode::InvalidRequest,
                    format!("{shape} requires arguments.expected_state as a string"),
                )
            })?;
        if expected_state != orcel_provider_browser::ENABLED_NODE_STATE {
            return Err(policy_error(
                FailureCode::CapabilityDenied,
                format!("{shape} actuates only enabled nodes; disabled nodes are denied"),
            ));
        }
        match operation {
            "click" => {
                if arguments.contains_key("value") {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        "browser.dom/click does not accept a value field",
                    ));
                }
            }
            "fill" => {
                let value = arguments
                    .get("value")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        policy_error(
                            FailureCode::InvalidRequest,
                            "browser.dom/fill requires arguments.value as a string",
                        )
                    })?;
                if value.len() > orcel_provider_browser::MAX_FILL_VALUE_BYTES {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        format!(
                            "browser.dom/fill value exceeds at most {} bytes",
                            orcel_provider_browser::MAX_FILL_VALUE_BYTES
                        ),
                    ));
                }
            }
            _ => {
                return Err(policy_error(
                    FailureCode::CapabilityDenied,
                    format!("{shape} is not an authorized actuation verb"),
                ));
            }
        }
        if let Some(key) = arguments.keys().find(|key| {
            *key != "page_id"
                && *key != "expected_origin"
                && *key != "expected_generation"
                && *key != "expected_document_generation"
                && *key != "node_id"
                && *key != "expected_role"
                && *key != "expected_state"
                && *key != "value"
        }) {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                format!("{shape} does not accept argument field: {key}"),
            ));
        }
        reject_widening_fields(arguments)?;
        Ok(())
    }
}

fn reject_widening_fields(arguments: &serde_json::Map<String, Value>) -> Result<(), PolicyError> {
    const WIDENING: &[&str] = &[
        "profile_root",
        "root",
        "path",
        "argv",
        "executable",
        "script",
        "javascript",
        "command",
        "personal",
        "credentials",
        "cookies",
        "passwords",
        "session",
        "extensions",
        "devtools",
        "cdp",
        "approval",
        "token",
        "nonce",
        "digest",
        "selector",
        "coordinate",
        "x",
        "y",
    ];
    if let Some(key) = arguments
        .keys()
        .find(|key| WIDENING.contains(&key.as_str()))
    {
        return Err(policy_error(
            FailureCode::CapabilityDenied,
            format!(
                "browser request must not carry authority-widening field: {key}; caller-selected profiles, coordinates, selectors, browser argv, scripting, credential material, and caller-supplied approval material are denied"
            ),
        ));
    }
    Ok(())
}

fn policy_error(code: FailureCode, message: impl Into<String>) -> PolicyError {
    PolicyError {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod sg000024_tests {
    use super::*;
    use serde_json::{json, Value};

    fn engine() -> (PolicyEngine, std::path::PathBuf) {
        let root = crate::test_support::unique_temp_dir("orcel-policy-sg000024");
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
            request_id: "sg24".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: None,
            arguments,
        }
    }

    fn click_arguments() -> Value {
        json!({
            "page_id": "pg-abc",
            "expected_origin": "https://example.com:443",
            "expected_generation": 1,
            "expected_document_generation": 1,
            "node_id": "nd-abc",
            "expected_role": "link",
            "expected_state": "enabled",
        })
    }

    fn fill_arguments() -> Value {
        json!({
            "page_id": "pg-abc",
            "expected_origin": "https://example.com:443",
            "expected_generation": 1,
            "expected_document_generation": 1,
            "node_id": "nd-abc",
            "expected_role": "textbox",
            "expected_state": "enabled",
            "value": "hello",
        })
    }

    #[test]
    fn authorizes_click_and_fill_as_soft_and_retains_predecessors() {
        let (engine, root) = engine();
        engine
            .authorize(&request("browser.profile", "status", json!({})))
            .expect("profile status retained");
        engine
            .authorize(&request("browser.page", "open", json!({})))
            .expect("page open retained");
        engine
            .authorize(&request(
                "browser.navigation",
                "preview",
                json!({"page_id": "pg-abc", "url": "https://example.com/"}),
            ))
            .expect("navigation preview retained");
        engine
            .authorize(&request(
                "browser.snapshot",
                "observe",
                json!({
                    "page_id": "pg-abc",
                    "expected_origin": "https://example.com:443",
                    "expected_generation": 1,
                }),
            ))
            .expect("snapshot observe retained");
        engine
            .authorize(&request("browser.dom", "click", click_arguments()))
            .expect("dom click authorized");
        engine
            .authorize(&request("browser.dom", "fill", fill_arguments()))
            .expect("dom fill authorized");
        assert_eq!(
            approval_class_for("browser.dom", "click"),
            ApprovalClass::Soft
        );
        assert_eq!(
            approval_class_for("browser.dom", "fill"),
            ApprovalClass::Soft
        );
        assert_eq!(
            approval_class_for("browser.snapshot", "observe"),
            ApprovalClass::Soft
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_malformed_actuation_shapes() {
        let (engine, root) = engine();
        for (capability, operation, arguments) in [
            ("browser.dom", "click", json!({})),
            (
                "browser.dom",
                "click",
                json!({"page_id": "forged", "expected_origin": "https://example.com:443", "expected_generation": 1, "expected_document_generation": 1, "node_id": "nd-a", "expected_role": "link", "expected_state": "enabled"}),
            ),
            (
                "browser.dom",
                "click",
                json!({"page_id": "pg-a", "expected_origin": "", "expected_generation": 1, "expected_document_generation": 1, "node_id": "nd-a", "expected_role": "link", "expected_state": "enabled"}),
            ),
            (
                "browser.dom",
                "click",
                json!({"page_id": "pg-a", "expected_origin": "https://example.com:443", "expected_generation": 1, "expected_document_generation": 1, "node_id": "forged", "expected_role": "link", "expected_state": "enabled"}),
            ),
            (
                "browser.dom",
                "click",
                json!({"page_id": "pg-a", "expected_origin": "https://example.com:443", "expected_generation": 1, "expected_document_generation": 1, "node_id": "nd-a", "expected_role": "textbox", "expected_state": "enabled"}),
            ),
            (
                "browser.dom",
                "click",
                json!({"page_id": "pg-a", "expected_origin": "https://example.com:443", "expected_generation": 1, "expected_document_generation": 1, "node_id": "nd-a", "expected_role": "link", "expected_state": "disabled"}),
            ),
            (
                "browser.dom",
                "click",
                json!({"page_id": "pg-a", "expected_origin": "https://example.com:443", "expected_generation": 1, "expected_document_generation": 1, "node_id": "nd-a", "expected_role": "link", "expected_state": "enabled", "value": "x"}),
            ),
            (
                "browser.dom",
                "fill",
                json!({"page_id": "pg-a", "expected_origin": "https://example.com:443", "expected_generation": 1, "expected_document_generation": 1, "node_id": "nd-a", "expected_role": "link", "expected_state": "enabled", "value": "x"}),
            ),
            (
                "browser.dom",
                "fill",
                json!({"page_id": "pg-a", "expected_origin": "https://example.com:443", "expected_generation": 1, "expected_document_generation": 1, "node_id": "nd-a", "expected_role": "textbox", "expected_state": "enabled"}),
            ),
            (
                "browser.dom",
                "fill",
                json!({"page_id": "pg-a", "expected_origin": "https://example.com:443", "expected_generation": 1, "expected_document_generation": 1, "node_id": "nd-a", "expected_role": "textbox", "expected_state": "enabled", "value": "x", "script": "alert(1)"}),
            ),
            (
                "browser.dom",
                "fill",
                json!({"page_id": "pg-a", "expected_origin": "https://example.com:443", "expected_generation": 1, "expected_document_generation": 1, "node_id": "nd-a", "expected_role": "textbox", "expected_state": "enabled", "value": "x", "coordinate": [1, 2]}),
            ),
        ] {
            let error = engine
                .authorize(&request(capability, operation, arguments))
                .expect_err("malformed actuation must be rejected");
            assert!(matches!(
                error.code,
                FailureCode::InvalidRequest | FailureCode::CapabilityDenied
            ));
        }
        let oversized = json!({"page_id": "pg-a", "expected_origin": "https://example.com:443", "expected_generation": 1, "expected_document_generation": 1, "node_id": "nd-a", "expected_role": "textbox", "expected_state": "enabled", "value": "x".repeat(4097)});
        let error = engine
            .authorize(&request("browser.dom", "fill", oversized))
            .expect_err("oversized fill must be rejected");
        assert_eq!(error.code, FailureCode::InvalidRequest);
        let mut with_target = request("browser.dom", "click", click_arguments());
        with_target.target = Some(".".into());
        assert_eq!(
            engine.authorize(&with_target).unwrap_err().code,
            FailureCode::InvalidRequest
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn denies_extended_actuation_download_upload_scripting_and_personal_as_strong() {
        let (engine, root) = engine();
        for (capability, operation) in [
            ("browser.navigate", "navigate"),
            ("browser.snapshot", "capture"),
            ("browser.snapshot", "actuate"),
            ("browser.dom", "type"),
            ("browser.dom", "press"),
            ("browser.dom", "select"),
            ("browser.dom", "write"),
            ("browser.dom", "snapshot"),
            ("browser.dom", "observe"),
            ("browser.accessibility", "query"),
            ("browser.page", "close"),
            ("browser.navigation", "back"),
            // NOTE (SG-000025 successor): scoped bounded
            // browser.download/preview and browser.download/download into the
            // approved workspace download root are lawfully authorized by the
            // SG-000025 successor grain and are therefore no longer in this
            // denied set. The frozen qualified head recorded this shape as
            // denied; current-tree authority records the successor delta.
            // Downloaded-file execution, opening, and extraction remain denied
            // in every successor grain.
            ("browser.upload", "upload"),
            ("browser.profile", "use_personal"),
            ("browser.profile", "launch"),
            ("browser.debug", "attach"),
            ("browser.devtools", "command"),
            ("browser.cdp", "command"),
            ("browser.script", "evaluate"),
            ("browser.launch", "launch"),
            ("browser.attach", "attach"),
            ("browser.clear", "clear_profile"),
            ("browser.external_request", "fetch"),
            ("devtools", "command"),
            ("cdp", "command"),
            ("playwright", "command"),
            ("browser.unknown", "unknown"),
        ] {
            assert_eq!(
                approval_class_for(capability, operation),
                ApprovalClass::Strong,
                "{capability}/{operation} must map to STRONG"
            );
            let error = engine
                .authorize(&request(capability, operation, json!({})))
                .expect_err("denied shape must remain denied");
            assert_eq!(
                error.code,
                FailureCode::CapabilityDenied,
                "unexpected code for {capability}/{operation}"
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn preserves_p06_git_trust_and_strong_classification() {
        let (engine, root) = engine();
        let head = "0123456789abcdef0123456789abcdef01234567";
        let mut push_preview = request(
            "git.push.preview",
            "preview",
            json!({"policy_id": "github-push", "source_branch": "main", "dest_branch": "main", "credential_reference": "anonymous"}),
        );
        push_preview.target = Some(".".into());
        engine
            .authorize(&push_preview)
            .expect("push preview still authorized");
        let mut fetch_preview = request(
            "git.fetch.preview",
            "preview",
            json!({"policy_id": "github-main", "branch": "main"}),
        );
        fetch_preview.target = Some(".".into());
        engine
            .authorize(&fetch_preview)
            .expect("fetch preview still authorized");
        let mut stage = request(
            "git.stage",
            "stage",
            json!({"expected_head": head, "paths": ["a.txt"]}),
        );
        stage.target = Some(".".into());
        engine.authorize(&stage).expect("stage still authorized");
        engine
            .authorize(&request("workspace.trust.get", "get", json!({})))
            .expect("trust get still authorized");
        engine
            .authorize(&request("workspace.trust.grant", "grant", json!({})))
            .expect("trust grant still authorized");
        assert_eq!(
            approval_class_for("policy.change", "change"),
            ApprovalClass::Strong
        );
        assert_eq!(
            approval_class_for("workspace.trust.grant", "grant"),
            ApprovalClass::Strong
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
