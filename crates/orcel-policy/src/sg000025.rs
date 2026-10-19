#[path = "sg000024.rs"]
mod sg000024_legacy;

pub use orcel_approval::ApprovalClass;
pub use sg000024_legacy::{
    validate_relative_target, FetchDestination, PolicyDecision, PolicyError, PushDestination,
    Workspace,
};

use orcel_contracts::{FailureCode, RequestEnvelope};
use serde_json::Value;

pub const POLICY_REVISION: &str = "sg-000025-v1";

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    legacy: sg000024_legacy::PolicyEngine,
}

impl PolicyEngine {
    pub fn new(workspaces: Vec<Workspace>) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000024_legacy::PolicyEngine::new(workspaces)?,
        })
    }

    pub fn with_destinations(
        workspaces: Vec<Workspace>,
        fetch_destinations: Vec<FetchDestination>,
        push_destinations: Vec<PushDestination>,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000024_legacy::PolicyEngine::with_destinations(
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

    /// Authorize one request. Download shapes are validated here so the
    /// download destination and content-type policy can never be reached
    /// through a predecessor engine. Every other browser shape retains its
    /// SG-000024 validation, and every remaining shape falls through to the
    /// predecessor engine unchanged.
    pub fn authorize(&self, request: &RequestEnvelope) -> Result<PolicyDecision, PolicyError> {
        if is_download_shape(request) {
            self.validate_download_shape(request)?;
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
                    "capability/operation is denied by {POLICY_REVISION}: {}/{}; SG-000025 authorizes only browser.profile/status, browser.destination/validate, browser.page/open, browser.navigation/preview, browser.navigation/navigate, read-only browser.snapshot/observe, structured browser.dom/click and browser.dom/fill, and scoped browser.download/preview and browser.download/download into the approved workspace download root, and select, toggle, submit, keyboard, downloaded-file execution, file opening, archive extraction, uploads, personal-profile access, debugging, scripting, and network egress remain absent",
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
    if is_download_shape_str(capability, operation) {
        return ApprovalClass::Soft;
    }
    if orcel_provider_browser::is_allowed_browser_shape(capability, operation) {
        return ApprovalClass::Soft;
    }
    if orcel_provider_browser::is_denied_browser_shape(capability, operation) {
        return ApprovalClass::Strong;
    }
    sg000024_legacy::approval_class_for(capability, operation)
}

fn is_download_shape(request: &RequestEnvelope) -> bool {
    is_download_shape_str(&request.capability, &request.operation)
}

fn is_download_shape_str(capability: &str, operation: &str) -> bool {
    matches!(
        (capability, operation),
        ("browser.download", "preview") | ("browser.download", "download")
    )
}

/// Fields that would widen download authority beyond the approved workspace
/// download root. None of them is accepted by any download shape.
const DOWNLOAD_WIDENING_FIELDS: &[&str] = &[
    "profile_root",
    "root",
    "path",
    "destination_root",
    "download_root",
    "absolute_destination",
    "drive",
    "unc",
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
    "execute",
    "open",
    "extract",
    "spawn",
    "shell",
    "run",
    "archive",
    "output",
    "overwrite",
];

impl PolicyEngine {
    /// Validate one download shape. This layer is pure policy: it performs no
    /// filesystem access, no network activity, and no mutation. Destination
    /// safety, type policy, and size bounds are decided from the declared
    /// identity only; the approved workspace root comes from configuration.
    fn validate_download_shape(&self, request: &RequestEnvelope) -> Result<(), PolicyError> {
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
                "browser download shapes do not accept a target field",
            ));
        }
        let arguments = request.arguments.as_object().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "browser arguments must be an object",
            )
        })?;
        let shape = format!("{}/{}", request.capability, request.operation);
        let allowed: &[&str] = match request.operation.as_str() {
            "preview" => {
                validate_download_preview_arguments(&shape, arguments)?;
                &[
                    "page_id",
                    "expected_origin",
                    "expected_generation",
                    "expected_document_generation",
                    "source_url",
                    "declared_filename",
                    "declared_media_type",
                    "declared_size_bytes",
                    "relative_destination",
                    "redirect_chain",
                ]
            }
            "download" => {
                validate_download_body_arguments(&shape, arguments)?;
                &[
                    "page_id",
                    "expected_origin",
                    "expected_generation",
                    "expected_document_generation",
                    "source_id",
                    "content_base64",
                ]
            }
            _ => {
                return Err(policy_error(
                    FailureCode::CapabilityDenied,
                    format!("{shape} is not an authorized download verb"),
                ))
            }
        };
        if let Some(key) = arguments
            .keys()
            .find(|key| DOWNLOAD_WIDENING_FIELDS.contains(&key.as_str()))
        {
            return Err(policy_error(
                FailureCode::CapabilityDenied,
                format!(
                    "browser download request must not carry authority-widening field: {key}; caller-selected destinations, caller-selected profiles, coordinates, selectors, browser argv, scripting, credential material, caller-supplied approval material, and downloaded-file execution, opening, and extraction are denied"
                ),
            ));
        }
        if let Some(key) = arguments
            .keys()
            .find(|key| !allowed.contains(&key.as_str()))
        {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                format!("{shape} does not accept argument field: {key}"),
            ));
        }
        Ok(())
    }
}

fn validate_download_preview_arguments(
    shape: &str,
    arguments: &serde_json::Map<String, Value>,
) -> Result<(), PolicyError> {
    let page_id = required_shape_string(shape, arguments, "page_id")?;
    if !page_id.starts_with(orcel_provider_browser::PAGE_ID_PREFIX) {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            format!("{shape} page_id is malformed"),
        ));
    }
    required_shape_string(shape, arguments, "expected_origin")?;
    required_shape_u64(shape, arguments, "expected_generation")?;
    required_shape_u64(shape, arguments, "expected_document_generation")?;
    required_shape_string(shape, arguments, "source_url")?;

    let declared_filename = required_shape_string(shape, arguments, "declared_filename")?;
    if declared_filename.is_empty()
        || declared_filename.len() > orcel_provider_browser::MAX_DOWNLOAD_COMPONENT_BYTES
    {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            format!(
                "{shape} declared_filename must be between 1 and at most {} bytes",
                orcel_provider_browser::MAX_DOWNLOAD_COMPONENT_BYTES
            ),
        ));
    }
    let declared_media_type = required_shape_string(shape, arguments, "declared_media_type")?;
    if !orcel_provider_browser::is_allowed_download_media_type(declared_media_type) {
        return Err(policy_error(
            FailureCode::CapabilityDenied,
            format!(
                "{shape} declared_media_type '{declared_media_type}' is not in the authorized download allowlist"
            ),
        ));
    }
    let declared_size_bytes = required_shape_u64(shape, arguments, "declared_size_bytes")?;
    if declared_size_bytes == 0 || declared_size_bytes > orcel_provider_browser::MAX_DOWNLOAD_BYTES
    {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            format!(
                "{shape} declared_size_bytes must be between 1 and the maximum of {} bytes",
                orcel_provider_browser::MAX_DOWNLOAD_BYTES
            ),
        ));
    }
    let relative_destination = required_shape_string(shape, arguments, "relative_destination")?;
    let (_, filename) = orcel_provider_browser::validate_download_relative_path(
        relative_destination,
    )
    .map_err(|error| {
        policy_error(
            error.code,
            format!("{shape} relative_destination is denied: {}", error.message),
        )
    })?;
    if filename != declared_filename {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            format!("{shape} declared_filename must equal the canonical destination file name"),
        ));
    }
    let extension_media_type = orcel_provider_browser::download_media_type_for_filename(&filename)
        .map_err(|error| policy_error(error.code, error.message))?;
    if extension_media_type != declared_media_type {
        return Err(policy_error(
            FailureCode::CapabilityDenied,
            format!(
                "{shape} declared media type does not match the destination extension; filename, declared type, and content must agree"
            ),
        ));
    }
    if let Some(chain) = arguments.get("redirect_chain") {
        let hops = chain.as_array().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                format!("{shape} redirect_chain must be an array of strings"),
            )
        })?;
        if hops.len() > orcel_provider_browser::MAX_REDIRECT_HOPS {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                format!(
                    "{shape} redirect_chain exceeds at most {} hops",
                    orcel_provider_browser::MAX_REDIRECT_HOPS
                ),
            ));
        }
        for hop in hops {
            if hop.as_str().is_none() {
                return Err(policy_error(
                    FailureCode::InvalidRequest,
                    format!("{shape} redirect_chain entries must be strings"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_download_body_arguments(
    shape: &str,
    arguments: &serde_json::Map<String, Value>,
) -> Result<(), PolicyError> {
    let page_id = required_shape_string(shape, arguments, "page_id")?;
    if !page_id.starts_with(orcel_provider_browser::PAGE_ID_PREFIX) {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            format!("{shape} page_id is malformed"),
        ));
    }
    required_shape_string(shape, arguments, "expected_origin")?;
    required_shape_u64(shape, arguments, "expected_generation")?;
    required_shape_u64(shape, arguments, "expected_document_generation")?;
    let source_id = required_shape_string(shape, arguments, "source_id")?;
    if !source_id.starts_with(orcel_provider_browser::DOWNLOAD_SOURCE_PREFIX) {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            format!("{shape} source_id is malformed"),
        ));
    }
    let body = required_shape_string(shape, arguments, "content_base64")?;
    if body.is_empty() || body.len() > orcel_provider_browser::MAX_DOWNLOAD_BODY_BYTES {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            format!(
                "{shape} content_base64 must be between 1 and at most {} bytes",
                orcel_provider_browser::MAX_DOWNLOAD_BODY_BYTES
            ),
        ));
    }
    if body.len() % 4 != 0 {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            format!("{shape} content_base64 is not a whole number of base64 groups"),
        ));
    }
    if !body
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            format!("{shape} content_base64 contains characters outside the base64 alphabet"),
        ));
    }
    Ok(())
}

fn required_shape_string<'a>(
    shape: &str,
    arguments: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a str, PolicyError> {
    arguments.get(name).and_then(Value::as_str).ok_or_else(|| {
        policy_error(
            FailureCode::InvalidRequest,
            format!("{shape} requires arguments.{name} as a string"),
        )
    })
}

fn required_shape_u64(
    shape: &str,
    arguments: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<u64, PolicyError> {
    arguments.get(name).and_then(Value::as_u64).ok_or_else(|| {
        policy_error(
            FailureCode::InvalidRequest,
            format!("{shape} requires arguments.{name} as an unsigned integer"),
        )
    })
}

fn policy_error(code: FailureCode, message: impl Into<String>) -> PolicyError {
    PolicyError {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod sg000025_tests {
    use super::*;
    use serde_json::{json, Value};

    fn engine() -> (PolicyEngine, std::path::PathBuf) {
        let root = crate::test_support::unique_temp_dir("orcel-policy-sg000025");
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
            request_id: "sg25".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: None,
            arguments,
        }
    }

    fn preview_arguments(destination: &str, filename: &str, media_type: &str) -> Value {
        json!({
            "page_id": "pg-abc",
            "expected_origin": "https://example.com:443",
            "expected_generation": 1,
            "expected_document_generation": 1,
            "source_url": "https://example.com/files/notes.txt",
            "declared_filename": filename,
            "declared_media_type": media_type,
            "declared_size_bytes": 5,
            "relative_destination": destination,
        })
    }

    fn body_arguments(body: &str) -> Value {
        json!({
            "page_id": "pg-abc",
            "expected_origin": "https://example.com:443",
            "expected_generation": 1,
            "expected_document_generation": 1,
            "source_id": "dl-abc",
            "content_base64": body,
        })
    }

    #[test]
    fn authorizes_download_preview_and_download_as_soft_and_retains_predecessors() {
        let (engine, root) = engine();
        let decision = engine
            .authorize(&request(
                "browser.download",
                "preview",
                preview_arguments("notes.txt", "notes.txt", "text/plain"),
            ))
            .expect("download preview authorized");
        assert_eq!(decision.policy_revision, POLICY_REVISION);
        assert_eq!(decision.workspace.id, "default");
        assert_eq!(
            approval_class_for("browser.download", "preview"),
            ApprovalClass::Soft
        );
        assert_eq!(
            approval_class_for("browser.download", "download"),
            ApprovalClass::Soft
        );
        engine
            .authorize(&request(
                "browser.download",
                "download",
                body_arguments("aGVsbG8="),
            ))
            .expect("download body authorized");
        engine
            .authorize(&request("browser.profile", "status", json!({})))
            .expect("profile status retained");
        engine
            .authorize(&request(
                "browser.dom",
                "click",
                json!({
                    "page_id": "pg-abc",
                    "expected_origin": "https://example.com:443",
                    "expected_generation": 1,
                    "expected_document_generation": 1,
                    "node_id": "nd-abc",
                    "expected_role": "link",
                    "expected_state": "enabled",
                }),
            ))
            .expect("actuation retained");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn denies_download_execution_open_extract_and_upload_shapes_as_strong() {
        let (engine, root) = engine();
        for (capability, operation) in [
            ("browser.download", "execute"),
            ("browser.download", "open"),
            ("browser.download", "extract"),
            ("browser.download", "launch"),
            ("browser.download", "resume"),
            ("browser.file", "execute"),
            ("browser.file", "open"),
            ("browser.archive", "extract"),
            ("browser.shell", "run"),
            // NOTE (SG-000026 successor): scoped browser.upload/preview and
            // browser.upload/submit of a recorded approved download artifact
            // to one typed file-input node are lawfully authorized by the
            // SG-000026 successor grain and are therefore no longer in this
            // denied set. browser.upload/upload, generic file read, directory
            // upload, multiple-file upload, and page byte transfer remain
            // denied in every successor grain.
            ("browser.upload", "upload"),
            ("browser.file", "read"),
            ("browser.fs", "read"),
            ("browser.directory", "upload"),
            ("browser.upload", "directory"),
            ("browser.upload", "multiple"),
            ("browser.unknown", "unknown"),
        ] {
            assert_eq!(
                approval_class_for(capability, operation),
                ApprovalClass::Strong,
                "{capability}/{operation} must map to STRONG"
            );
            let error = engine
                .authorize(&request(capability, operation, json!({})))
                .expect_err("denied download shape must remain denied");
            assert_eq!(
                error.code,
                FailureCode::CapabilityDenied,
                "unexpected code for {capability}/{operation}"
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn denies_dangerous_extensions_unknown_types_and_mismatched_types() {
        let (engine, root) = engine();
        for (filename, media_type) in [
            ("tool.exe", "text/plain"),
            ("archive.zip", "text/plain"),
            ("book.docm", "text/plain"),
            ("script.ps1", "text/plain"),
            ("noextension", "text/plain"),
            ("notes.txt", "application/x-msdownload"),
            ("image.png", "text/plain"),
        ] {
            let error = engine
                .authorize(&request(
                    "browser.download",
                    "preview",
                    preview_arguments(filename, filename, media_type),
                ))
                .unwrap_err();
            assert_eq!(
                error.code,
                FailureCode::CapabilityDenied,
                "{filename} with {media_type} must fail closed"
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn denies_path_escape_traversal_device_unc_ads_and_reserved_destinations() {
        let (engine, root) = engine();
        for destination in [
            "C:\\Windows\\evil.txt",
            "\\\\server\\share\\evil.txt",
            "\\\\?\\C:\\evil.txt",
            "\\\\.\\PhysicalDrive0\\evil.txt",
            "..\\escape.txt",
            "sub\\..\\..\\escape.txt",
            "notes.txt:hidden",
            "CON.txt",
            "LPT1.txt",
            "sub\\\\notes.txt",
            "sub.\\notes.txt",
            "sub \\notes.txt",
            "a<b.txt",
        ] {
            let error = engine
                .authorize(&request(
                    "browser.download",
                    "preview",
                    preview_arguments(destination, "notes.txt", "text/plain"),
                ))
                .unwrap_err();
            assert_eq!(
                error.code,
                FailureCode::PathEscape,
                "{destination} must fail closed as a path escape"
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn denies_caller_selected_destinations_and_execution_widening_fields() {
        let (engine, root) = engine();
        for field in [
            "destination_root",
            "download_root",
            "root",
            "path",
            "drive",
            "unc",
            "execute",
            "open",
            "extract",
            "overwrite",
            "archive",
        ] {
            let mut arguments = preview_arguments("notes.txt", "notes.txt", "text/plain");
            arguments
                .as_object_mut()
                .expect("object")
                .insert(field.to_owned(), json!("x"));
            let error = engine
                .authorize(&request("browser.download", "preview", arguments))
                .unwrap_err();
            assert_eq!(
                error.code,
                FailureCode::CapabilityDenied,
                "widening field {field} must fail closed"
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn denies_oversized_malformed_and_unknown_fields() {
        let (engine, root) = engine();
        for declared in [u64::MAX, 0, orcel_provider_browser::MAX_DOWNLOAD_BYTES + 1] {
            let mut arguments = preview_arguments("notes.txt", "notes.txt", "text/plain");
            arguments
                .as_object_mut()
                .expect("object")
                .insert("declared_size_bytes".to_owned(), json!(declared));
            assert_eq!(
                engine
                    .authorize(&request("browser.download", "preview", arguments))
                    .unwrap_err()
                    .code,
                FailureCode::InvalidRequest,
                "declared size {declared} must fail closed"
            );
        }

        let mut unknown = preview_arguments("notes.txt", "notes.txt", "text/plain");
        unknown
            .as_object_mut()
            .expect("object")
            .insert("unexpected".to_owned(), json!(1));
        assert_eq!(
            engine
                .authorize(&request("browser.download", "preview", unknown))
                .unwrap_err()
                .code,
            FailureCode::InvalidRequest
        );

        for body in ["", "abc", "aGVsbG8", "aGVs bG8=", "aGVsbG8=extra!"] {
            assert_eq!(
                engine
                    .authorize(&request(
                        "browser.download",
                        "download",
                        body_arguments(body)
                    ))
                    .unwrap_err()
                    .code,
                FailureCode::InvalidRequest,
                "malformed body must fail closed"
            );
        }

        let mut targeted = request(
            "browser.download",
            "preview",
            preview_arguments("notes.txt", "notes.txt", "text/plain"),
        );
        targeted.target = Some("notes.txt".into());
        assert_eq!(
            engine.authorize(&targeted).unwrap_err().code,
            FailureCode::InvalidRequest
        );
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
