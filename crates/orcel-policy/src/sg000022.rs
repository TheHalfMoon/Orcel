#[path = "sg000021.rs"]
mod sg000021_legacy;

pub use orcel_approval::ApprovalClass;
pub use sg000021_legacy::{
    validate_relative_target, FetchDestination, PolicyDecision, PolicyError, PushDestination,
    Workspace,
};

use orcel_contracts::{FailureCode, RequestEnvelope};
use serde_json::Value;

pub const POLICY_REVISION: &str = "sg-000022-v1";

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    legacy: sg000021_legacy::PolicyEngine,
}

impl PolicyEngine {
    pub fn new(workspaces: Vec<Workspace>) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000021_legacy::PolicyEngine::new(workspaces)?,
        })
    }

    pub fn with_destinations(
        workspaces: Vec<Workspace>,
        fetch_destinations: Vec<FetchDestination>,
        push_destinations: Vec<PushDestination>,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000021_legacy::PolicyEngine::with_destinations(
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
        if is_navigation_shape(request) {
            self.validate_navigation_shape(request)?;
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
            // SG-000021 shapes retain their validation in the legacy engine, but
            // the reported revision advances to the navigation revision.
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
                    "capability/operation is denied by {POLICY_REVISION}: {}/{}; SG-000022 authorizes only browser.profile/status, browser.destination/validate, browser.page/open, browser.navigation/preview, and browser.navigation/navigate, and DOM observation, DOM actuation, downloads, uploads, personal-profile access, debugging, scripting, and network egress remain absent",
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
    if is_navigation_shape_str(capability, operation) {
        return ApprovalClass::Soft;
    }
    if orcel_provider_browser::is_allowed_browser_shape(capability, operation) {
        return ApprovalClass::Soft;
    }
    if orcel_provider_browser::is_denied_browser_shape(capability, operation) {
        return ApprovalClass::Strong;
    }
    sg000021_legacy::approval_class_for(capability, operation)
}

fn is_navigation_shape(request: &RequestEnvelope) -> bool {
    is_navigation_shape_str(&request.capability, &request.operation)
}

fn is_navigation_shape_str(capability: &str, operation: &str) -> bool {
    matches!(
        (capability, operation),
        ("browser.page", "open")
            | ("browser.navigation", "preview")
            | ("browser.navigation", "navigate")
    )
}

impl PolicyEngine {
    fn validate_navigation_shape(&self, request: &RequestEnvelope) -> Result<(), PolicyError> {
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
                "browser page and navigation shapes do not accept a target field",
            ));
        }
        let arguments = request.arguments.as_object().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "browser arguments must be an object",
            )
        })?;
        match (request.capability.as_str(), request.operation.as_str()) {
            ("browser.page", "open") => {
                if !arguments.is_empty() {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        "browser.page/open accepts no argument fields; page identity is server-allocated and caller-selected profiles are denied",
                    ));
                }
            }
            ("browser.navigation", "preview") => {
                let url = arguments
                    .get("url")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        policy_error(
                            FailureCode::InvalidRequest,
                            "browser.navigation/preview requires arguments.url as a string",
                        )
                    })?;
                if url.is_empty() || url.len() > 2048 {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        "browser.navigation/preview url is empty or too large",
                    ));
                }
                let page_id = arguments
                    .get("page_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        policy_error(
                            FailureCode::InvalidRequest,
                            "browser.navigation/preview requires arguments.page_id as a string",
                        )
                    })?;
                if page_id.is_empty() || page_id.len() > 256 {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        "browser.navigation/preview page_id is empty or too large",
                    ));
                }
                if let Some(chain) = arguments.get("redirect_chain") {
                    let hops = chain.as_array().ok_or_else(|| {
                        policy_error(
                            FailureCode::InvalidRequest,
                            "browser.navigation/preview redirect_chain must be an array of strings",
                        )
                    })?;
                    if hops.len() > 8 {
                        return Err(policy_error(
                            FailureCode::InvalidRequest,
                            "browser.navigation/preview redirect_chain exceeds at most 8 hops",
                        ));
                    }
                    for hop in hops {
                        let text = hop.as_str().ok_or_else(|| {
                            policy_error(
                                FailureCode::InvalidRequest,
                                "browser.navigation/preview redirect_chain entries must be strings",
                            )
                        })?;
                        if text.is_empty() || text.len() > 2048 {
                            return Err(policy_error(
                                FailureCode::InvalidRequest,
                                "browser.navigation/preview redirect hop is empty or too large",
                            ));
                        }
                    }
                }
                if let Some(key) = arguments
                    .keys()
                    .find(|key| *key != "page_id" && *key != "url" && *key != "redirect_chain")
                {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        format!("browser.navigation/preview does not accept argument field: {key}"),
                    ));
                }
                reject_widening_fields(arguments)?;
            }
            ("browser.navigation", "navigate") => {
                for name in ["page_id", "url", "expected_pinned_address"] {
                    let text = arguments.get(name).and_then(Value::as_str).ok_or_else(|| {
                        policy_error(
                            FailureCode::InvalidRequest,
                            format!(
                                "browser.navigation/navigate requires arguments.{name} as a string"
                            ),
                        )
                    })?;
                    if text.is_empty() || text.len() > 2048 {
                        return Err(policy_error(
                            FailureCode::InvalidRequest,
                            format!("browser.navigation/navigate {name} is empty or too large"),
                        ));
                    }
                }
                let expected_origin =
                    arguments
                        .get("expected_origin")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            policy_error(
                                FailureCode::InvalidRequest,
                                "browser.navigation/navigate requires arguments.expected_origin as a string",
                            )
                        })?;
                if expected_origin.len() > 2048 {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        "browser.navigation/navigate expected_origin is too large",
                    ));
                }
                if page_id_looks_forged(arguments)? {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        "browser.navigation/navigate page_id is malformed",
                    ));
                }
                let generation = arguments
                    .get("expected_generation")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        policy_error(
                            FailureCode::InvalidRequest,
                            "browser.navigation/navigate requires arguments.expected_generation as an unsigned integer",
                        )
                    })?;
                if generation > 1_000_000 {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        "browser.navigation/navigate expected_generation is out of range",
                    ));
                }
                if let Some(chain) = arguments.get("redirect_chain") {
                    let hops = chain.as_array().ok_or_else(|| {
                        policy_error(
                            FailureCode::InvalidRequest,
                            "browser.navigation/navigate redirect_chain must be an array of strings",
                        )
                    })?;
                    if hops.len() > 8 {
                        return Err(policy_error(
                            FailureCode::InvalidRequest,
                            "browser.navigation/navigate redirect_chain exceeds at most 8 hops",
                        ));
                    }
                    for hop in hops {
                        let text = hop.as_str().ok_or_else(|| {
                            policy_error(
                                FailureCode::InvalidRequest,
                                "browser.navigation/navigate redirect_chain entries must be strings",
                            )
                        })?;
                        if text.is_empty() || text.len() > 2048 {
                            return Err(policy_error(
                                FailureCode::InvalidRequest,
                                "browser.navigation/navigate redirect hop is empty or too large",
                            ));
                        }
                    }
                }
                if let Some(key) = arguments.keys().find(|key| {
                    *key != "page_id"
                        && *key != "url"
                        && *key != "expected_origin"
                        && *key != "expected_generation"
                        && *key != "expected_pinned_address"
                        && *key != "redirect_chain"
                }) {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        format!(
                            "browser.navigation/navigate does not accept argument field: {key}"
                        ),
                    ));
                }
                reject_widening_fields(arguments)?;
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

fn page_id_looks_forged(arguments: &serde_json::Map<String, Value>) -> Result<bool, PolicyError> {
    let page_id = arguments
        .get("page_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "browser.navigation/navigate requires arguments.page_id as a string",
            )
        })?;
    if page_id.len() > 256 {
        return Ok(true);
    }
    Ok(!page_id.starts_with(orcel_provider_browser::PAGE_ID_PREFIX))
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
        "extensions",
        "devtools",
        "cdp",
        "approval",
        "token",
        "nonce",
        "digest",
    ];
    if let Some(key) = arguments
        .keys()
        .find(|key| WIDENING.contains(&key.as_str()))
    {
        return Err(policy_error(
            FailureCode::CapabilityDenied,
            format!(
                "browser request must not carry authority-widening field: {key}; caller-selected profiles, browser argv, scripting, credential material, and caller-supplied approval material are denied"
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
mod sg000022_tests {
    use super::*;
    use serde_json::{json, Value};

    fn engine() -> (PolicyEngine, std::path::PathBuf) {
        let root = crate::test_support::unique_temp_dir("orcel-policy-sg000022");
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
            request_id: "sg22".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: None,
            arguments,
        }
    }

    #[test]
    fn authorizes_page_and_navigation_shapes_as_soft() {
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
            .expect("page open authorized");
        engine
            .authorize(&request(
                "browser.navigation",
                "preview",
                json!({"page_id": "pg-abc", "url": "https://example.com/"}),
            ))
            .expect("navigation preview authorized");
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
            .expect("navigation navigate shape authorized");
        assert_eq!(
            approval_class_for("browser.page", "open"),
            ApprovalClass::Soft
        );
        assert_eq!(
            approval_class_for("browser.navigation", "preview"),
            ApprovalClass::Soft
        );
        assert_eq!(
            approval_class_for("browser.navigation", "navigate"),
            ApprovalClass::Soft
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_malformed_page_and_navigation_shapes() {
        let (engine, root) = engine();
        let error = engine
            .authorize(&request(
                "browser.page",
                "open",
                json!({"profile_root": "/tmp/x"}),
            ))
            .expect_err("caller profile field must be rejected");
        assert_eq!(error.code, FailureCode::InvalidRequest);

        for arguments in [
            json!({}),
            json!({"page_id": "pg-a"}),
            json!({"url": "https://example.com/"}),
            json!({"page_id": "pg-a", "url": 42}),
            json!({"page_id": "pg-a", "url": "https://example.com/", "redirect_chain": "x"}),
            json!({"page_id": "pg-a", "url": "https://example.com/", "argv": ["--headless"]}),
        ] {
            let error = engine
                .authorize(&request("browser.navigation", "preview", arguments))
                .expect_err("malformed preview must be rejected");
            assert!(matches!(
                error.code,
                FailureCode::InvalidRequest | FailureCode::CapabilityDenied
            ));
        }

        for arguments in [
            json!({"page_id": "pg-a", "url": "https://example.com/"}),
            json!({
                "page_id": "pg-a",
                "url": "https://example.com/",
                "expected_origin": "",
                "expected_generation": "zero",
                "expected_pinned_address": "1.1.1.1",
            }),
            json!({
                "page_id": "forged-id",
                "url": "https://example.com/",
                "expected_origin": "",
                "expected_generation": 0,
                "expected_pinned_address": "1.1.1.1",
            }),
            json!({
                "page_id": "pg-a",
                "url": "https://example.com/",
                "expected_origin": "",
                "expected_generation": 0,
                "expected_pinned_address": "1.1.1.1",
                "approval": "caller-token",
            }),
            json!({
                "page_id": "pg-a",
                "url": "https://example.com/",
                "expected_origin": "",
                "expected_generation": 0,
                "expected_pinned_address": "1.1.1.1",
                "script": "alert(1)",
            }),
        ] {
            let error = engine
                .authorize(&request("browser.navigation", "navigate", arguments))
                .expect_err("malformed navigate must be rejected");
            assert!(matches!(
                error.code,
                FailureCode::InvalidRequest | FailureCode::CapabilityDenied
            ));
        }
        let mut with_target = request(
            "browser.navigation",
            "preview",
            json!({"page_id": "pg-a", "url": "https://example.com/"}),
        );
        with_target.target = Some(".".into());
        assert_eq!(
            engine.authorize(&with_target).unwrap_err().code,
            FailureCode::InvalidRequest
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn denies_dom_download_upload_scripting_debugging_and_personal_shapes_as_strong() {
        let (engine, root) = engine();
        for (capability, operation) in [
            ("browser.navigate", "navigate"),
            ("browser.snapshot", "capture"),
            // NOTE (SG-000023/SG-000024 successors): read-only
            // browser.snapshot/observe and structured browser.dom/click and
            // browser.dom/fill are lawfully authorized by successor grains
            // and are therefore no longer in this denied set. The SG-000022
            // qualified head froze these shapes as denied; current-tree
            // authority records the successor deltas.
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
