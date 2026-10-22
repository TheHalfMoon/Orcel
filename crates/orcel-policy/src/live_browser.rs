//! SG-000108 slice 3c: the argument forms of the live browser shapes.
//!
//! The six live shapes reuse SG-000079's qualified names, but their live
//! forms carry only what a caller may say about a live page: its page id,
//! the store generation the caller saw, a URL to navigate to, an observed
//! node, and a file name inside the workspace's approved download root.
//! Everything else is the host's (its own pin, the committed document, the
//! link's destination) or orceld's (the workspace, the approval). orceld
//! routes a shape here only after its profile gate admitted the request
//! (local, `browser_structured`); the model-only forms keep their own rules.

use crate::PolicyError;
use orcel_contracts::{FailureCode, RequestEnvelope, INTERNAL_PROTOCOL_VERSION};
use serde_json::{Map, Value};

/// The live shapes and the argument fields each accepts.
const LIVE_FORMS: &[(&str, &str, &[&str])] = &[
    ("browser.page", "open", &[]),
    (
        "browser.navigation",
        "navigate",
        &["page_id", "url", "expected_generation"],
    ),
    (
        "browser.snapshot",
        "observe",
        &["page_id", "expected_generation"],
    ),
    (
        "browser.dom",
        "click",
        &["page_id", "node_id", "expected_generation"],
    ),
    (
        "browser.download",
        "preview",
        &["page_id", "node_id", "file_name", "expected_generation"],
    ),
    (
        "browser.download",
        "download",
        &["page_id", "node_id", "file_name", "expected_generation"],
    ),
];

/// Fields that would widen authority if a caller could name them; asking
/// for one is a capability denial, not a malformed request.
const AUTHORITY_FIELDS: &[&str] = &[
    "profile_root",
    "root",
    "path",
    "folder",
    "destination_root",
    "download_root",
    "absolute_destination",
    "pinned_address",
    "expected_pinned_address",
    "host",
    "argv",
    "executable",
    "script",
    "javascript",
    "evaluate",
    "command",
    "personal",
    "credentials",
    "cookies",
    "session",
    "devtools",
    "cdp",
    "approval",
    "token",
    "record_id",
    "binding",
    "nonce",
    "digest",
    "selector",
    "coordinate",
    "content_base64",
    "execute",
    "open",
    "overwrite",
];

const MAX_URL_BYTES: usize = 2048;
/// The file types a live download may create: documents and images, never
/// code, scripts, shortcuts or tool configuration (`conftest.py`,
/// `Makefile`, `package.json`, `*.bat`, `*.lnk`, `desktop.ini`).
const DOWNLOAD_EXTENSIONS: &[&str] = &[
    "pdf", "csv", "txt", "xlsx", "docx", "pptx", "png", "jpg", "jpeg",
];
const MAX_PAGE_ID_BYTES: usize = 128;
const MAX_NODE_ID_BYTES: usize = 64;

/// Whether a shape is one of the live forms.
pub fn is_live_browser_shape(capability: &str, operation: &str) -> bool {
    LIVE_FORMS
        .iter()
        .any(|(c, o, _)| *c == capability && *o == operation)
}

fn policy_error(code: FailureCode, message: impl Into<String>) -> PolicyError {
    PolicyError {
        code,
        message: message.into(),
    }
}

fn invalid(message: impl Into<String>) -> PolicyError {
    policy_error(FailureCode::InvalidRequest, message)
}

/// Validate a live shape's request: the protocol version, no target, and
/// exactly its own argument fields with well-formed values.
pub fn validate_live_browser(request: &RequestEnvelope) -> Result<(), PolicyError> {
    if request.version != INTERNAL_PROTOCOL_VERSION {
        return Err(invalid("unsupported internal protocol version"));
    }
    let fields = LIVE_FORMS
        .iter()
        .find(|(c, o, _)| *c == request.capability && *o == request.operation)
        .map(|(_, _, fields)| *fields)
        .ok_or_else(|| policy_error(FailureCode::CapabilityDenied, "not a live browser shape"))?;
    if request.target.is_some() {
        return Err(invalid("live browser shapes do not accept a target field"));
    }
    let empty = Map::new();
    let arguments = match &request.arguments {
        Value::Object(map) => map,
        Value::Null => &empty,
        _ => return Err(invalid("live browser arguments must be an object")),
    };
    for key in arguments.keys() {
        if AUTHORITY_FIELDS.contains(&key.as_str()) {
            return Err(policy_error(
                FailureCode::CapabilityDenied,
                format!(
                    "live browser requests must not carry authority-widening field: {key}; pins, folders, approvals, scripts, selectors and profiles are never the caller's"
                ),
            ));
        }
        if !fields.contains(&key.as_str()) {
            return Err(invalid(format!(
                "{}/{} does not accept argument field: {key}",
                request.capability, request.operation
            )));
        }
    }
    for field in fields {
        let value = arguments
            .get(*field)
            .ok_or_else(|| invalid(format!("live browser request requires arguments.{field}")))?;
        match *field {
            "page_id" => {
                let page = value
                    .as_str()
                    .ok_or_else(|| invalid("page_id must be a string"))?;
                if !page.starts_with(orcel_provider_browser::PAGE_ID_PREFIX)
                    || page.len() > MAX_PAGE_ID_BYTES
                    || !page
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err(invalid("page_id is malformed"));
                }
            }
            "url" => {
                let url = value
                    .as_str()
                    .ok_or_else(|| invalid("url must be a string"))?;
                if url.is_empty() || url.len() > MAX_URL_BYTES {
                    return Err(invalid("url is empty or too large"));
                }
                // SG-000075 admits HTTPS only for a live page.
                if !url
                    .get(..8)
                    .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
                {
                    return Err(invalid("a live page navigates to HTTPS only"));
                }
                orcel_provider_browser::parse_destination_url(url)
                    .map_err(|error| policy_error(error.code, error.message))?;
            }
            "expected_generation" => {
                value
                    .as_u64()
                    .ok_or_else(|| invalid("expected_generation must be an unsigned integer"))?;
            }
            "node_id" => {
                let node = value
                    .as_str()
                    .ok_or_else(|| invalid("node_id must be a string"))?;
                if node.is_empty()
                    || node.len() > MAX_NODE_ID_BYTES
                    || !node
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err(invalid("node_id is malformed"));
                }
            }
            "file_name" => {
                let name = value
                    .as_str()
                    .ok_or_else(|| invalid("file_name must be a string"))?;
                orcel_provider_browser::validate_download_relative_path(name)
                    .map_err(|error| policy_error(error.code, error.message))?;
                // Never a hidden name or folder (`.vscode/tasks.json`,
                // `.mcp.json`): a page's document does not configure tools.
                if name
                    .split(['/', '\\'])
                    .any(|segment| segment.starts_with('.'))
                {
                    return Err(invalid("file_name must not name a hidden file or folder"));
                }
                let extension = name
                    .rsplit_once('.')
                    .map(|(_, extension)| extension.to_ascii_lowercase());
                if !extension.is_some_and(|e| DOWNLOAD_EXTENSIONS.contains(&e.as_str())) {
                    return Err(invalid(format!(
                        "file_name must end in one of: {}",
                        DOWNLOAD_EXTENSIONS.join(", ")
                    )));
                }
            }
            _ => return Err(invalid("unknown live browser field")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request(capability: &str, operation: &str, arguments: Value) -> RequestEnvelope {
        RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "r".into(),
            client_session_id: "s".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: None,
            arguments,
        }
    }

    #[test]
    fn each_live_form_takes_exactly_its_fields() {
        let ok = [
            request("browser.page", "open", json!({})),
            request(
                "browser.navigation",
                "navigate",
                json!({"page_id": "pg-a1", "url": "https://example.org/reports", "expected_generation": 0}),
            ),
            request(
                "browser.snapshot",
                "observe",
                json!({"page_id": "pg-a1", "expected_generation": 1}),
            ),
            request(
                "browser.dom",
                "click",
                json!({"page_id": "pg-a1", "node_id": "d1-e7", "expected_generation": 1}),
            ),
            request(
                "browser.download",
                "preview",
                json!({"page_id": "pg-a1", "node_id": "d1-e7", "file_name": "report.pdf", "expected_generation": 1}),
            ),
            request(
                "browser.download",
                "download",
                json!({"page_id": "pg-a1", "node_id": "d1-e7", "file_name": "reports/2026-10.pdf", "expected_generation": 1}),
            ),
        ];
        for request in &ok {
            let accepted = validate_live_browser(request);
            assert!(
                accepted.is_ok(),
                "{}/{}: {:?}",
                request.capability,
                request.operation,
                accepted.err().map(|error| error.message)
            );
        }
        let code = |capability: &str, operation: &str, arguments: Value| {
            validate_live_browser(&request(capability, operation, arguments))
                .unwrap_err()
                .code
        };
        // Missing, extra, mistyped or malformed fields.
        for (capability, operation, arguments) in [
            (
                "browser.page",
                "open",
                json!({"url": "https://example.org/"}),
            ),
            (
                "browser.navigation",
                "navigate",
                json!({"page_id": "pg-a1", "url": "https://example.org/"}),
            ),
            (
                "browser.navigation",
                "navigate",
                json!({"page_id": "pg-a1", "url": "http://example.org/", "expected_generation": 0}),
            ),
            (
                "browser.navigation",
                "navigate",
                json!({"page_id": "forged", "url": "https://example.org/", "expected_generation": 0}),
            ),
            (
                "browser.navigation",
                "navigate",
                json!({"page_id": "pg-a1", "url": "https://example.org/", "expected_generation": "0"}),
            ),
            (
                "browser.dom",
                "click",
                json!({"page_id": "pg-a1", "node_id": "a b", "expected_generation": 1}),
            ),
            (
                "browser.download",
                "download",
                json!({"page_id": "pg-a1", "node_id": "d1-e7", "file_name": "../x.pdf", "expected_generation": 1}),
            ),
            (
                "browser.download",
                "download",
                json!({"page_id": "pg-a1", "node_id": "d1-e7", "file_name": "C:\\x.pdf", "expected_generation": 1}),
            ),
            (
                "browser.download",
                "download",
                json!({"page_id": "pg-a1", "node_id": "d1-e7", "file_name": "x.pdf:s", "expected_generation": 1}),
            ),
            (
                "browser.download",
                "download",
                json!({"page_id": "pg-a1", "node_id": "d1-e7", "file_name": ".mcp.json", "expected_generation": 1}),
            ),
            (
                "browser.download",
                "download",
                json!({"page_id": "pg-a1", "node_id": "d1-e7", "file_name": ".vscode/tasks.json", "expected_generation": 1}),
            ),
            (
                "browser.download",
                "download",
                json!({"page_id": "pg-a1", "node_id": "d1-e7", "file_name": "conftest.py", "expected_generation": 1}),
            ),
            (
                "browser.download",
                "download",
                json!({"page_id": "pg-a1", "node_id": "d1-e7", "file_name": "tools/package.json", "expected_generation": 1}),
            ),
            (
                "browser.download",
                "download",
                json!({"page_id": "pg-a1", "node_id": "d1-e7", "file_name": "run.bat", "expected_generation": 1}),
            ),
            (
                "browser.download",
                "download",
                json!({"page_id": "pg-a1", "node_id": "d1-e7", "file_name": "Makefile", "expected_generation": 1}),
            ),
            (
                "browser.download",
                "preview",
                json!({"page_id": "pg-a1", "node_id": "d1-e7", "file_name": "x.lnk", "expected_generation": 1}),
            ),
        ] {
            let refused = code(capability, operation, arguments.clone());
            assert!(
                matches!(
                    refused,
                    FailureCode::InvalidRequest | FailureCode::PathEscape
                ),
                "{capability}/{operation} {arguments}: {refused:?}"
            );
        }
        // Authority the caller never holds is a capability denial.
        for field in [
            "folder",
            "expected_pinned_address",
            "record_id",
            "binding",
            "selector",
            "content_base64",
            "script",
        ] {
            let mut arguments = json!({"page_id": "pg-a1", "node_id": "d1-e7", "file_name": "r.pdf", "expected_generation": 1});
            arguments[field] = json!("x");
            assert_eq!(
                code("browser.download", "download", arguments),
                FailureCode::CapabilityDenied,
                "{field}"
            );
        }
        // Model-only and denied shapes are not live forms.
        for (capability, operation) in [
            ("browser.dom", "fill"),
            ("browser.upload", "submit"),
            ("browser.navigation", "preview"),
            ("browser.cdp", "command"),
        ] {
            assert!(!is_live_browser_shape(capability, operation));
            assert_eq!(
                code(capability, operation, json!({})),
                FailureCode::CapabilityDenied
            );
        }
        let mut targeted = request("browser.page", "open", json!({}));
        targeted.target = Some("x".into());
        assert_eq!(
            validate_live_browser(&targeted).unwrap_err().code,
            FailureCode::InvalidRequest
        );
    }
}
