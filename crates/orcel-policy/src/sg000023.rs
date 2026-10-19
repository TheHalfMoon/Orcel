#[path = "sg000022.rs"]
mod sg000022_legacy;

pub use orcel_approval::ApprovalClass;
pub use sg000022_legacy::{
    validate_relative_target, FetchDestination, PolicyDecision, PolicyError, PushDestination,
    Workspace,
};

use orcel_contracts::{FailureCode, RequestEnvelope};
use serde_json::Value;

pub const POLICY_REVISION: &str = "sg-000023-v1";

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    legacy: sg000022_legacy::PolicyEngine,
}

impl PolicyEngine {
    pub fn new(workspaces: Vec<Workspace>) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000022_legacy::PolicyEngine::new(workspaces)?,
        })
    }

    pub fn with_destinations(
        workspaces: Vec<Workspace>,
        fetch_destinations: Vec<FetchDestination>,
        push_destinations: Vec<PushDestination>,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000022_legacy::PolicyEngine::with_destinations(
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
        if is_snapshot_shape(request) {
            self.validate_snapshot_shape(request)?;
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
            // SG-000021 and SG-000022 shapes retain their validation in the
            // legacy engine, but the reported revision advances to the
            // observation revision.
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
                    "capability/operation is denied by {POLICY_REVISION}: {}/{}; SG-000023 authorizes only browser.profile/status, browser.destination/validate, browser.page/open, browser.navigation/preview, browser.navigation/navigate, and read-only browser.snapshot/observe, and DOM actuation, downloads, uploads, personal-profile access, debugging, scripting, and network egress remain absent",
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
    if is_snapshot_shape_str(capability, operation) {
        return ApprovalClass::Soft;
    }
    if orcel_provider_browser::is_allowed_browser_shape(capability, operation) {
        return ApprovalClass::Soft;
    }
    if orcel_provider_browser::is_denied_browser_shape(capability, operation) {
        return ApprovalClass::Strong;
    }
    sg000022_legacy::approval_class_for(capability, operation)
}

fn is_snapshot_shape(request: &RequestEnvelope) -> bool {
    is_snapshot_shape_str(&request.capability, &request.operation)
}

fn is_snapshot_shape_str(capability: &str, operation: &str) -> bool {
    matches!((capability, operation), ("browser.snapshot", "observe"))
}

impl PolicyEngine {
    fn validate_snapshot_shape(&self, request: &RequestEnvelope) -> Result<(), PolicyError> {
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
                "browser snapshot shapes do not accept a target field",
            ));
        }
        let arguments = request.arguments.as_object().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "browser arguments must be an object",
            )
        })?;
        let page_id = arguments
            .get("page_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                policy_error(
                    FailureCode::InvalidRequest,
                    "browser.snapshot/observe requires arguments.page_id as a string",
                )
            })?;
        if page_id.is_empty() || page_id.len() > 256 {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "browser.snapshot/observe page_id is empty or too large",
            ));
        }
        if !page_id.starts_with(orcel_provider_browser::PAGE_ID_PREFIX) {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "browser.snapshot/observe page_id is malformed",
            ));
        }
        let expected_origin = arguments
            .get("expected_origin")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                policy_error(
                    FailureCode::InvalidRequest,
                    "browser.snapshot/observe requires arguments.expected_origin as a string",
                )
            })?;
        if expected_origin.len() > 2048 {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "browser.snapshot/observe expected_origin is too large",
            ));
        }
        let expected_generation = arguments
            .get("expected_generation")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                policy_error(
                    FailureCode::InvalidRequest,
                    "browser.snapshot/observe requires arguments.expected_generation as an unsigned integer",
                )
            })?;
        if expected_generation > 1_000_000 {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "browser.snapshot/observe expected_generation is out of range",
            ));
        }
        for (key, minimum, maximum) in [
            (
                "max_nodes",
                1_u64,
                orcel_provider_browser::MAX_SNAPSHOT_NODES,
            ),
            (
                "max_depth",
                1_u64,
                orcel_provider_browser::MAX_SNAPSHOT_DEPTH,
            ),
            (
                "max_bytes",
                orcel_provider_browser::MIN_SNAPSHOT_BYTES,
                orcel_provider_browser::MAX_SNAPSHOT_BYTES as u64,
            ),
        ] {
            if let Some(value) = arguments.get(key) {
                let bound = value.as_u64().ok_or_else(|| {
                    policy_error(
                        FailureCode::InvalidRequest,
                        format!("browser.snapshot/observe {key} must be an unsigned integer"),
                    )
                })?;
                if !(minimum..=maximum).contains(&bound) {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        format!("browser.snapshot/observe {key} is out of range"),
                    ));
                }
            }
        }
        if let Some(key) = arguments.keys().find(|key| {
            *key != "page_id"
                && *key != "expected_origin"
                && *key != "expected_generation"
                && *key != "max_nodes"
                && *key != "max_depth"
                && *key != "max_bytes"
        }) {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                format!("browser.snapshot/observe does not accept argument field: {key}"),
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
        "node_id",
        "selector",
    ];
    if let Some(key) = arguments
        .keys()
        .find(|key| WIDENING.contains(&key.as_str()))
    {
        return Err(policy_error(
            FailureCode::CapabilityDenied,
            format!(
                "browser request must not carry authority-widening field: {key}; caller-selected profiles, node selectors, browser argv, scripting, credential material, and caller-supplied approval material are denied"
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
mod sg000023_tests {
    use super::*;
    use serde_json::{json, Value};

    fn engine() -> (PolicyEngine, std::path::PathBuf) {
        let root = crate::test_support::unique_temp_dir("orcel-policy-sg000023");
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
            request_id: "sg23".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: None,
            arguments,
        }
    }

    fn snapshot_arguments() -> Value {
        json!({
            "page_id": "pg-abc",
            "expected_origin": "https://example.com:443",
            "expected_generation": 1,
        })
    }

    #[test]
    fn authorizes_snapshot_observe_as_soft_and_retains_predecessors() {
        let (engine, root) = engine();
        engine
            .authorize(&request("browser.profile", "status", json!({})))
            .expect("profile status retained");
        engine
            .authorize(&request(
                "browser.destination",
                "validate",
                json!({"url": "https://example.com/"}),
            ))
            .expect("destination validate retained");
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
                "browser.navigation",
                "navigate",
                json!({
                    "page_id": "pg-abc",
                    "url": "https://example.com/",
                    "expected_origin": "",
                    "expected_generation": 0,
                    "expected_pinned_address": "93.184.216.34",
                }),
            ))
            .expect("navigation navigate retained");
        engine
            .authorize(&request(
                "browser.snapshot",
                "observe",
                snapshot_arguments(),
            ))
            .expect("snapshot observe authorized");
        engine
            .authorize(&request(
                "browser.snapshot",
                "observe",
                json!({
                    "page_id": "pg-abc",
                    "expected_origin": "https://example.com:443",
                    "expected_generation": 1,
                    "max_nodes": 10,
                    "max_depth": 2,
                    "max_bytes": 4096,
                }),
            ))
            .expect("bounded snapshot observe authorized");
        assert_eq!(
            approval_class_for("browser.snapshot", "observe"),
            ApprovalClass::Soft
        );
        assert_eq!(
            approval_class_for("browser.page", "open"),
            ApprovalClass::Soft
        );
        assert_eq!(
            approval_class_for("browser.navigation", "navigate"),
            ApprovalClass::Soft
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_malformed_snapshot_shapes() {
        let (engine, root) = engine();
        for arguments in [
            json!({}),
            json!({"page_id": "pg-a"}),
            json!({"expected_origin": "https://example.com:443", "expected_generation": 1}),
            json!({"page_id": "pg-a", "expected_origin": "https://example.com:443"}),
            json!({"page_id": "forged-id", "expected_origin": "", "expected_generation": 0}),
            json!({"page_id": "pg-a", "expected_origin": "", "expected_generation": "one"}),
            json!({"page_id": "pg-a", "expected_origin": "", "expected_generation": 0, "max_nodes": 0}),
            json!({"page_id": "pg-a", "expected_origin": "", "expected_generation": 0, "max_nodes": 201}),
            json!({"page_id": "pg-a", "expected_origin": "", "expected_generation": 0, "max_depth": 9}),
            json!({"page_id": "pg-a", "expected_origin": "", "expected_generation": 0, "max_bytes": 100}),
            json!({"page_id": "pg-a", "expected_origin": "", "expected_generation": 0, "script": "alert(1)"}),
            json!({"page_id": "pg-a", "expected_origin": "", "expected_generation": 0, "node_id": "nd-x"}),
            json!({"page_id": "pg-a", "expected_origin": "", "expected_generation": 0, "selector": "button"}),
            json!({"page_id": "pg-a", "expected_origin": "", "expected_generation": 0, "approval": "caller-token"}),
        ] {
            let error = engine
                .authorize(&request("browser.snapshot", "observe", arguments))
                .expect_err("malformed snapshot must be rejected");
            assert!(matches!(
                error.code,
                FailureCode::InvalidRequest | FailureCode::CapabilityDenied
            ));
        }
        let mut with_target = request("browser.snapshot", "observe", snapshot_arguments());
        with_target.target = Some(".".into());
        assert_eq!(
            engine.authorize(&with_target).unwrap_err().code,
            FailureCode::InvalidRequest
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn denies_actuation_download_upload_scripting_debugging_and_personal_shapes_as_strong() {
        let (engine, root) = engine();
        for (capability, operation) in [
            ("browser.navigate", "navigate"),
            ("browser.snapshot", "capture"),
            ("browser.snapshot", "actuate"),
            // NOTE (SG-000024 successor): structured browser.dom/click and
            // browser.dom/fill are lawfully authorized by the SG-000024
            // successor grain and are therefore no longer in this denied
            // set. The SG-000023 qualified head froze these shapes as
            // denied; current-tree authority records the successor delta.
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
