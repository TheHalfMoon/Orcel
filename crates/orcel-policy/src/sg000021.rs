#[path = "sg000020.rs"]
mod sg000020_legacy;

pub use orcel_approval::ApprovalClass;
pub use sg000020_legacy::{
    validate_relative_target, FetchDestination, PolicyDecision, PolicyError, PushDestination,
    Workspace,
};

use orcel_contracts::{FailureCode, RequestEnvelope};
use serde_json::Value;

pub const POLICY_REVISION: &str = "sg-000021-v1";

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    legacy: sg000020_legacy::PolicyEngine,
}

impl PolicyEngine {
    pub fn new(workspaces: Vec<Workspace>) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000020_legacy::PolicyEngine::new(workspaces)?,
        })
    }

    pub fn with_destinations(
        workspaces: Vec<Workspace>,
        fetch_destinations: Vec<FetchDestination>,
        push_destinations: Vec<PushDestination>,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000020_legacy::PolicyEngine::with_destinations(
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
        if orcel_provider_browser::is_allowed_browser_shape(&request.capability, &request.operation)
        {
            self.validate_allowed_browser_shape(request)?;
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
                    "capability/operation is denied by {POLICY_REVISION}: {}/{}; SG-000021 authorizes only browser.profile/status and browser.destination/validate, and browser navigation, DOM actuation, downloads, uploads, personal-profile access, debugging, scripting, and network egress remain absent",
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
    if orcel_provider_browser::is_allowed_browser_shape(capability, operation) {
        return ApprovalClass::Soft;
    }
    if orcel_provider_browser::is_denied_browser_shape(capability, operation) {
        return ApprovalClass::Strong;
    }
    sg000020_legacy::approval_class_for(capability, operation)
}

impl PolicyEngine {
    fn validate_allowed_browser_shape(&self, request: &RequestEnvelope) -> Result<(), PolicyError> {
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
                "browser profile and destination shapes do not accept a target field",
            ));
        }
        let arguments = request.arguments.as_object().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "browser arguments must be an object",
            )
        })?;
        match (request.capability.as_str(), request.operation.as_str()) {
            ("browser.profile", "status") => {
                if !arguments.is_empty() {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        "browser.profile/status accepts no argument fields; the profile root is owned by Orcel protected state and caller-selected profile directories are denied",
                    ));
                }
            }
            ("browser.destination", "validate") => {
                let url = arguments
                    .get("url")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        policy_error(
                            FailureCode::InvalidRequest,
                            "browser.destination/validate requires arguments.url as a string",
                        )
                    })?;
                if url.is_empty() || url.len() > 2048 {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        "browser.destination/validate url is empty or too large",
                    ));
                }
                if let Some(expected) = arguments.get("expected_origin") {
                    let text = expected.as_str().ok_or_else(|| {
                        policy_error(
                            FailureCode::InvalidRequest,
                            "browser.destination/validate expected_origin must be a string",
                        )
                    })?;
                    if text.is_empty() || text.len() > 2048 {
                        return Err(policy_error(
                            FailureCode::InvalidRequest,
                            "browser.destination/validate expected_origin is empty or too large",
                        ));
                    }
                }
                if let Some(key) = arguments
                    .keys()
                    .find(|key| *key != "url" && *key != "expected_origin")
                {
                    return Err(policy_error(
                        FailureCode::InvalidRequest,
                        format!(
                            "browser.destination/validate does not accept argument field: {key}"
                        ),
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

#[cfg(test)]
mod sg000021_tests {
    use super::*;
    use serde_json::{json, Value};

    fn engine() -> (PolicyEngine, std::path::PathBuf) {
        let root = crate::test_support::unique_temp_dir("orcel-policy-sg000021");
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
            request_id: "sg21".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: None,
            arguments,
        }
    }

    #[test]
    fn authorizes_only_the_two_typed_browser_shapes() {
        let (engine, root) = engine();
        engine
            .authorize(&request("browser.profile", "status", json!({})))
            .expect("profile status authorized");
        engine
            .authorize(&request(
                "browser.destination",
                "validate",
                json!({"url": "https://example.com/"}),
            ))
            .expect("destination validate authorized");
        engine
            .authorize(&request(
                "browser.destination",
                "validate",
                json!({"url": "https://example.com/", "expected_origin": "https://example.com/"}),
            ))
            .expect("destination validate with expected origin authorized");
        assert_eq!(
            approval_class_for("browser.profile", "status"),
            ApprovalClass::Soft
        );
        assert_eq!(
            approval_class_for("browser.destination", "validate"),
            ApprovalClass::Soft
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_caller_profile_roots_and_extra_destination_fields() {
        let (engine, root) = engine();
        for arguments in [
            json!({"profile_root": "C:\\Users\\Owner\\AppData\\Local\\Google\\Chrome\\User Data"}),
            json!({"root": "/tmp/caller-profile"}),
            json!({"argv": ["--headless"]}),
            json!({"personal": true}),
        ] {
            let error = engine
                .authorize(&request("browser.profile", "status", arguments))
                .expect_err("caller profile field must be rejected");
            assert_eq!(error.code, FailureCode::InvalidRequest);
        }
        for arguments in [
            json!({"url": "https://example.com/", "profile_root": "/tmp/x"}),
            json!({"url": "https://example.com/", "argv": ["--headless"]}),
            json!({"url": "https://example.com/", "script": "alert(1)"}),
            json!({}),
            json!({"url": 42}),
            json!({"url": "https://example.com/", "expected_origin": 42}),
        ] {
            let error = engine
                .authorize(&request("browser.destination", "validate", arguments))
                .expect_err("malformed destination shape must be rejected");
            assert_eq!(error.code, FailureCode::InvalidRequest);
        }
        let mut with_target = request(
            "browser.destination",
            "validate",
            json!({"url": "https://example.com/"}),
        );
        with_target.target = Some(".".into());
        assert_eq!(
            engine.authorize(&with_target).unwrap_err().code,
            FailureCode::InvalidRequest
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn denies_every_browser_actuation_shape_as_strong() {
        let (engine, root) = engine();
        for (capability, operation) in [
            ("browser.navigate", "navigate"),
            ("browser.snapshot", "capture"),
            // NOTE (SG-000024 successor): structured browser.dom/click and
            // browser.dom/fill are lawfully authorized by the SG-000024
            // successor grain and are therefore no longer in this denied
            // set. The SG-000021 qualified head froze these shapes as
            // denied; current-tree authority records the successor delta.
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
                .expect_err("actuation must remain denied");
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
