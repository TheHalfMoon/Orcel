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
//!
//! SG-000122 slice A2 adds the form actions (`browser.dom/fill`, promoted
//! from model-only, and `browser.form/select`, `/check` and `/enter`), each
//! SOFT-approved, and the read-only `browser.wait/text` and
//! `browser.verify/check`. A fill value or option label must be one the
//! approval prompt shows exactly and in full, or it is refused here. Enter
//! takes no key: it is the only key. Whether the target is a single-line
//! text field (an input of type text, search, email, url or tel), a native
//! select or a checkbox or radio, and whether its name looks secret, is the
//! host's to decide from its own observation, before any prompt.

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
    // SG-000122 slice A2: the live form actions (each SOFT-approved), the
    // text wait and the verifier (read-only), on an observed node of the
    // page's committed document. Their names never collide with the
    // closed-grain denials (`browser.dom/press`, `browser.dom/select`); on
    // the model-only path every browser.form, browser.wait and
    // browser.verify shape stays denied and STRONG.
    (
        "browser.dom",
        "fill",
        &["page_id", "node_id", "value", "expected_generation"],
    ),
    (
        "browser.form",
        "select",
        &["page_id", "node_id", "option", "expected_generation"],
    ),
    (
        "browser.form",
        "check",
        &["page_id", "node_id", "checked", "expected_generation"],
    ),
    (
        "browser.form",
        "enter",
        &["page_id", "node_id", "expected_generation"],
    ),
    (
        "browser.wait",
        "text",
        &[
            "page_id",
            "text",
            "appear",
            "timeout_ms",
            "expected_generation",
        ],
    ),
    (
        "browser.verify",
        "check",
        &["page_id", "checks", "expected_generation"],
    ),
];

/// SG-000122 slice A2: the live shapes added by this grain, beside
/// SG-000108's six. Each is reachable only through orceld's profile gate.
pub const LIVE_FORM_SHAPES: &[(&str, &str)] = &[
    ("browser.dom", "fill"),
    ("browser.form", "select"),
    ("browser.form", "check"),
    ("browser.form", "enter"),
    ("browser.wait", "text"),
    ("browser.verify", "check"),
];

/// The live shapes that change something and so need a fresh SOFT approval
/// from the broker, one per action. Every other live shape (open, observe,
/// the download preview, the text wait and the verifier) is read-only or
/// allocates only orceld's own state, and needs none.
const LIVE_SOFT_SHAPES: &[(&str, &str)] = &[
    ("browser.navigation", "navigate"),
    ("browser.dom", "click"),
    ("browser.download", "download"),
    ("browser.dom", "fill"),
    ("browser.form", "select"),
    ("browser.form", "check"),
    ("browser.form", "enter"),
];

/// The approval a live shape needs: SOFT for each consequential action,
/// none for the read-only ones, and `None` for anything that is not a live
/// shape.
pub fn live_approval_class(
    capability: &str,
    operation: &str,
) -> Option<Option<crate::ApprovalClass>> {
    if !is_live_browser_shape(capability, operation) {
        return None;
    }
    Some(
        LIVE_SOFT_SHAPES
            .contains(&(capability, operation))
            .then_some(crate::ApprovalClass::Soft),
    )
}

/// SG-000122: the longest fill value or option label, in bytes (the host's
/// `MAX_FORM_VALUE_BYTES`), and the longest awaited or verified text (the
/// host's `MAX_VERIFY_TEXT_BYTES`).
pub const MAX_FORM_VALUE_BYTES: usize = 1024;
pub const MAX_WAIT_TEXT_BYTES: usize = 1024;
/// SG-000122: the longest text wait (the host's `MAX_WAIT_MS`).
pub const MAX_WAIT_MS: u64 = 8_000;
/// SG-000122: the most postconditions one verification checks (the host's
/// `MAX_POSTCONDITIONS`).
pub const MAX_POSTCONDITIONS: usize = 16;
const MAX_VERIFY_URL_BYTES: usize = 2048;

/// The verifier's postcondition kinds and the fields each takes.
const POSTCONDITION_FORMS: &[(&str, &[&str])] = &[
    ("element_visible", &["node_id"]),
    ("text_visible", &["text"]),
    ("value_equals", &["node_id", "value"]),
    ("checked", &["node_id", "checked"]),
    ("url_is", &["url"]),
    ("download_sha256", &["sha256"]),
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
            "node_id" => validate_node_id(value)?,
            // SG-000122: the value is shown in the approval prompt exactly
            // and in full, so one the prompt would cut or escape is refused
            // here, before anything is asked; never truncated.
            "value" => {
                let text = value
                    .as_str()
                    .ok_or_else(|| invalid("value must be a string"))?;
                shown_in_full(text, "value")?;
            }
            "option" => {
                let label = value
                    .as_str()
                    .ok_or_else(|| invalid("option must be a string"))?;
                if label.is_empty() {
                    return Err(invalid("option must name one option label"));
                }
                shown_in_full(label, "option")?;
            }
            "checked" | "appear" => {
                value
                    .as_bool()
                    .ok_or_else(|| invalid(format!("{field} must be a boolean")))?;
            }
            "text" => bounded_text(value, "text")?,
            "timeout_ms" => {
                let timeout = value
                    .as_u64()
                    .ok_or_else(|| invalid("timeout_ms must be an unsigned integer"))?;
                if timeout == 0 || timeout > MAX_WAIT_MS {
                    return Err(invalid(format!(
                        "timeout_ms must be from 1 to {MAX_WAIT_MS}"
                    )));
                }
            }
            "checks" => validate_checks(value)?,
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

fn validate_node_id(value: &Value) -> Result<(), PolicyError> {
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
    Ok(())
}

/// SG-000122 (the amendment of SG-000108 decision 4): a fill value, or an
/// option label, the approval prompt shows exactly and in full: no character
/// it would escape, a displayed length (a backslash counting double) of at
/// most the prompt's summary bound, and at most the host's byte bound. The
/// rule is the prompt's own (`orcel_contracts::prompt_display`).
pub fn shown_in_full(text: &str, field: &str) -> Result<(), PolicyError> {
    use orcel_contracts::prompt_display::{shown_exactly, NotShownExactly, MAX_SUMMARY_CHARS};
    match shown_exactly(text, MAX_SUMMARY_CHARS) {
        Err(NotShownExactly::Escaped) => Err(invalid(format!(
            "{field} holds a character the approval prompt would escape (a control, line \
             break, bidi, format, zero-width, invisible or blank-looking character, or a \
             combining mark past the second in a row); it is refused, never shown altered"
        ))),
        Err(NotShownExactly::TooLong) => Err(invalid(format!(
            "{field} is longer than the approval prompt shows in full ({MAX_SUMMARY_CHARS} \
             displayed characters, a backslash counting two); it is refused, never cut"
        ))),
        Ok(_) if text.len() > MAX_FORM_VALUE_BYTES => Err(invalid(format!(
            "{field} is longer than {MAX_FORM_VALUE_BYTES} bytes"
        ))),
        Ok(_) => Ok(()),
    }
}

/// A text wait's or a verifier text check's literal: one bounded line.
fn bounded_text(value: &Value, field: &str) -> Result<(), PolicyError> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid(format!("{field} must be a string")))?;
    if text.is_empty() || text.len() > MAX_WAIT_TEXT_BYTES || text.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{field} must be one non-empty line of at most {MAX_WAIT_TEXT_BYTES} bytes"
        )));
    }
    Ok(())
}

/// The verifier's postconditions: 1 to `MAX_POSTCONDITIONS`, each exactly
/// one known kind with exactly its fields. The host checks them again.
fn validate_checks(value: &Value) -> Result<(), PolicyError> {
    let checks = value
        .as_array()
        .ok_or_else(|| invalid("checks must be an array"))?;
    if checks.is_empty() || checks.len() > MAX_POSTCONDITIONS {
        return Err(invalid(format!(
            "a verification checks 1 to {MAX_POSTCONDITIONS} postconditions"
        )));
    }
    for check in checks {
        let check = check
            .as_object()
            .ok_or_else(|| invalid("each check must be an object"))?;
        let kind = check
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("each check needs a kind"))?;
        let fields = POSTCONDITION_FORMS
            .iter()
            .find(|(name, _)| *name == kind)
            .map(|(_, fields)| *fields)
            .ok_or_else(|| invalid(format!("unknown check kind: {kind}")))?;
        for key in check.keys().filter(|key| key.as_str() != "kind") {
            if AUTHORITY_FIELDS.contains(&key.as_str()) {
                return Err(policy_error(
                    FailureCode::CapabilityDenied,
                    format!("a check must not carry authority-widening field: {key}"),
                ));
            }
            if !fields.contains(&key.as_str()) {
                return Err(invalid(format!("a {kind} check does not accept: {key}")));
            }
        }
        for field in fields {
            let value = check
                .get(*field)
                .ok_or_else(|| invalid(format!("a {kind} check requires {field}")))?;
            match *field {
                "node_id" => validate_node_id(value)?,
                "text" => bounded_text(value, "text")?,
                "checked" => {
                    value
                        .as_bool()
                        .ok_or_else(|| invalid("checked must be a boolean"))?;
                }
                // An empty expected value is a legitimate postcondition.
                "value" => {
                    let text = value
                        .as_str()
                        .ok_or_else(|| invalid("value must be a string"))?;
                    if text.len() > MAX_WAIT_TEXT_BYTES || text.chars().any(char::is_control) {
                        return Err(invalid("an expected value must be bounded and on one line"));
                    }
                }
                "url" => {
                    let url = value
                        .as_str()
                        .ok_or_else(|| invalid("url must be a string"))?;
                    if url.is_empty()
                        || url.len() > MAX_VERIFY_URL_BYTES
                        || url.chars().any(char::is_control)
                    {
                        return Err(invalid("a verified URL must be bounded"));
                    }
                }
                "sha256" => {
                    let digest = value
                        .as_str()
                        .ok_or_else(|| invalid("sha256 must be a string"))?;
                    if digest.len() != 64
                        || !digest
                            .bytes()
                            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                    {
                        return Err(invalid("a download digest is 64 lower-case hex digits"));
                    }
                }
                _ => return Err(invalid("unknown check field")),
            }
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
        // Model-only and denied shapes are not live forms (SG-000122 made
        // browser.dom/fill live; the uploads stay model-only).
        for (capability, operation) in [
            ("browser.upload", "preview"),
            ("browser.upload", "submit"),
            ("browser.navigation", "preview"),
            ("browser.dom", "press"),
            ("browser.dom", "select"),
            ("browser.dom", "hover"),
            ("browser.form", "press"),
            ("browser.form", "hover"),
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

    fn form_requests() -> Vec<RequestEnvelope> {
        vec![
            request(
                "browser.dom",
                "fill",
                json!({"page_id": "pg-a1", "node_id": "d2-e3", "value": "Ada Lovelace", "expected_generation": 2}),
            ),
            request(
                "browser.form",
                "select",
                json!({"page_id": "pg-a1", "node_id": "d2-e4", "option": "Porto", "expected_generation": 2}),
            ),
            request(
                "browser.form",
                "check",
                json!({"page_id": "pg-a1", "node_id": "d2-e5", "checked": true, "expected_generation": 2}),
            ),
            request(
                "browser.form",
                "enter",
                json!({"page_id": "pg-a1", "node_id": "d2-e3", "expected_generation": 2}),
            ),
            request(
                "browser.wait",
                "text",
                json!({"page_id": "pg-a1", "text": "Saved", "appear": true, "timeout_ms": 2000, "expected_generation": 2}),
            ),
            request(
                "browser.verify",
                "check",
                json!({"page_id": "pg-a1", "expected_generation": 2, "checks": [
                    {"kind": "text_visible", "text": "Saved"},
                    {"kind": "value_equals", "node_id": "d2-e3", "value": "Ada Lovelace"},
                    {"kind": "checked", "node_id": "d2-e5", "checked": true},
                    {"kind": "element_visible", "node_id": "d2-e4"},
                    {"kind": "url_is", "url": "https://example.org/done"},
                    {"kind": "download_sha256", "sha256": "0".repeat(64)}
                ]}),
            ),
        ]
    }

    /// SG-000122 slice A2: each live form takes exactly its fields; a caller
    /// selector and every authority field are refused; a key other than
    /// Enter (or any key at all), an input type and anything unknown are
    /// refused; waits and checks are bounded.
    #[test]
    fn sg122_each_live_form_action_takes_exactly_its_fields() {
        let requests = form_requests();
        assert_eq!(requests.len(), LIVE_FORM_SHAPES.len());
        for request in &requests {
            assert!(is_live_browser_shape(
                &request.capability,
                &request.operation
            ));
            assert!(LIVE_FORM_SHAPES
                .contains(&(request.capability.as_str(), request.operation.as_str())));
            let accepted = validate_live_browser(request);
            assert!(
                accepted.is_ok(),
                "{}/{}: {:?}",
                request.capability,
                request.operation,
                accepted.err().map(|error| error.message)
            );
            let fields = request.arguments.as_object().unwrap();
            // Each field is required.
            for missing in fields.keys() {
                let mut short = request.clone();
                short.arguments.as_object_mut().unwrap().remove(missing);
                assert_eq!(
                    validate_live_browser(&short).unwrap_err().code,
                    FailureCode::InvalidRequest,
                    "{}/{} without {missing}",
                    request.capability,
                    request.operation
                );
            }
            // Every authority field, a caller selector among them, is a
            // capability denial; other extra fields are malformed.
            for field in AUTHORITY_FIELDS {
                let mut widened = request.clone();
                widened.arguments[*field] = json!("x");
                assert_eq!(
                    validate_live_browser(&widened).unwrap_err().code,
                    FailureCode::CapabilityDenied,
                    "{}/{} {field}",
                    request.capability,
                    request.operation
                );
            }
            for extra in [
                "key",
                "type",
                "input_type",
                "frame",
                "options",
                "url",
                "accept_confirm",
            ] {
                if fields.contains_key(extra) {
                    continue;
                }
                let mut widened = request.clone();
                widened.arguments[extra] = json!("x");
                assert_eq!(
                    validate_live_browser(&widened).unwrap_err().code,
                    FailureCode::InvalidRequest,
                    "{}/{} {extra}",
                    request.capability,
                    request.operation
                );
            }
        }
        let code = |capability: &str, operation: &str, arguments: Value| {
            validate_live_browser(&request(capability, operation, arguments))
                .unwrap_err()
                .code
        };
        // Enter takes no key: Enter is the only key, and naming one (Enter
        // included) is refused, as is a press of anything.
        for key in ["Tab", "Escape", "Space", "ArrowDown", "Enter", "a"] {
            assert_eq!(
                code(
                    "browser.form",
                    "enter",
                    json!({"page_id": "pg-a1", "node_id": "d2-e3", "key": key, "expected_generation": 2})
                ),
                FailureCode::InvalidRequest,
                "{key}"
            );
        }
        let too_many = vec![json!({"kind": "text_visible", "text": "x"}); MAX_POSTCONDITIONS + 1];
        // Mistyped and out-of-range values.
        for (capability, operation, arguments) in [
            (
                "browser.dom",
                "fill",
                json!({"page_id": "pg-a1", "node_id": "d2-e3", "value": 7, "expected_generation": 2}),
            ),
            (
                "browser.form",
                "select",
                json!({"page_id": "pg-a1", "node_id": "d2-e4", "option": "", "expected_generation": 2}),
            ),
            (
                "browser.form",
                "select",
                json!({"page_id": "pg-a1", "node_id": "d2-e4", "option": ["Porto"], "expected_generation": 2}),
            ),
            (
                "browser.form",
                "check",
                json!({"page_id": "pg-a1", "node_id": "d2-e5", "checked": "true", "expected_generation": 2}),
            ),
            (
                "browser.wait",
                "text",
                json!({"page_id": "pg-a1", "text": "", "appear": true, "timeout_ms": 2000, "expected_generation": 2}),
            ),
            (
                "browser.wait",
                "text",
                json!({"page_id": "pg-a1", "text": "two\nlines", "appear": true, "timeout_ms": 2000, "expected_generation": 2}),
            ),
            (
                "browser.wait",
                "text",
                json!({"page_id": "pg-a1", "text": "x".repeat(MAX_WAIT_TEXT_BYTES + 1), "appear": true, "timeout_ms": 2000, "expected_generation": 2}),
            ),
            (
                "browser.wait",
                "text",
                json!({"page_id": "pg-a1", "text": "Saved", "appear": true, "timeout_ms": 0, "expected_generation": 2}),
            ),
            (
                "browser.wait",
                "text",
                json!({"page_id": "pg-a1", "text": "Saved", "appear": true, "timeout_ms": MAX_WAIT_MS + 1, "expected_generation": 2}),
            ),
            (
                "browser.wait",
                "text",
                json!({"page_id": "pg-a1", "text": "Saved", "appear": "yes", "timeout_ms": 2000, "expected_generation": 2}),
            ),
            (
                "browser.verify",
                "check",
                json!({"page_id": "pg-a1", "checks": [], "expected_generation": 2}),
            ),
            (
                "browser.verify",
                "check",
                json!({"page_id": "pg-a1", "checks": too_many, "expected_generation": 2}),
            ),
            (
                "browser.verify",
                "check",
                json!({"page_id": "pg-a1", "checks": [{"kind": "script", "source": "1"}], "expected_generation": 2}),
            ),
            (
                "browser.verify",
                "check",
                json!({"page_id": "pg-a1", "checks": [{"kind": "text_visible", "text": "x", "frame": "f1"}], "expected_generation": 2}),
            ),
            (
                "browser.verify",
                "check",
                json!({"page_id": "pg-a1", "checks": [{"kind": "text_visible"}], "expected_generation": 2}),
            ),
            (
                "browser.verify",
                "check",
                json!({"page_id": "pg-a1", "checks": [{"kind": "download_sha256", "sha256": "ABC"}], "expected_generation": 2}),
            ),
            (
                "browser.verify",
                "check",
                json!({"page_id": "pg-a1", "checks": [{"text": "x"}], "expected_generation": 2}),
            ),
        ] {
            assert_eq!(
                code(capability, operation, arguments.clone()),
                FailureCode::InvalidRequest,
                "{capability}/{operation} {arguments}"
            );
        }
        // A selector inside a check is still a capability denial.
        assert_eq!(
            code(
                "browser.verify",
                "check",
                json!({"page_id": "pg-a1", "checks": [{"kind": "element_visible", "node_id": "d2-e4", "selector": "#x"}], "expected_generation": 2})
            ),
            FailureCode::CapabilityDenied
        );
    }

    /// SG-000122 slice A2 (decision 4 amended): a fill value is shown in the
    /// prompt exactly and in full, so it is refused one displayed character
    /// past the bound (a backslash counting two) and with any character the
    /// prompt would escape, each class tested; an option label too.
    #[test]
    fn sg122_a_value_the_prompt_cannot_show_exactly_is_refused() {
        use orcel_contracts::prompt_display::MAX_SUMMARY_CHARS;
        let fill = |value: &str| {
            validate_live_browser(&request(
                "browser.dom",
                "fill",
                json!({"page_id": "pg-a1", "node_id": "d2-e3", "value": value, "expected_generation": 2}),
            ))
        };
        let select = |label: &str| {
            validate_live_browser(&request(
                "browser.form",
                "select",
                json!({"page_id": "pg-a1", "node_id": "d2-e4", "option": label, "expected_generation": 2}),
            ))
        };
        let at = "a".repeat(MAX_SUMMARY_CHARS);
        let slashes = "\\".repeat(MAX_SUMMARY_CHARS / 2);
        for fits in [
            at.as_str(),
            slashes.as_str(),
            "",
            "C:\\temp\\x",
            "e\u{301}\u{302}",
            "Zoë 日本",
        ] {
            assert!(fill(fits).is_ok(), "{fits:?}");
        }
        assert!(select(&at).is_ok());
        let past = format!("{at}a");
        let past_slashes = format!("{slashes}a");
        for over in [past.as_str(), past_slashes.as_str()] {
            assert_eq!(fill(over).unwrap_err().code, FailureCode::InvalidRequest);
            assert_eq!(select(over).unwrap_err().code, FailureCode::InvalidRequest);
        }
        // Within the displayed bound but past the host's byte bound.
        let wide = "é".repeat(MAX_FORM_VALUE_BYTES / 2 + 1);
        assert_eq!(fill(&wide).unwrap_err().code, FailureCode::InvalidRequest);
        for ch in [
            '\u{0}',
            '\u{1b}',
            '\u{7f}',
            '\u{85}',
            '\u{9f}',
            '\n',
            '\r',
            '\t',
            '\u{2028}',
            '\u{2029}',
            '\u{200e}',
            '\u{200f}',
            '\u{061c}',
            '\u{202a}',
            '\u{202e}',
            '\u{2066}',
            '\u{2069}',
            '\u{200b}',
            '\u{200d}',
            '\u{2060}',
            '\u{206a}',
            '\u{feff}',
            '\u{00ad}',
            '\u{034f}',
            '\u{17b4}',
            '\u{180e}',
            '\u{fe0f}',
            '\u{1bca0}',
            '\u{13430}',
            '\u{1d173}',
            '\u{e0100}',
            '\u{fff9}',
            '\u{e0001}',
            '\u{e0041}',
            '\u{115f}',
            '\u{3164}',
            '\u{ffa0}',
            '\u{00a0}',
            '\u{1680}',
            '\u{2003}',
            '\u{202f}',
            '\u{205f}',
            '\u{2800}',
            '\u{3000}',
        ] {
            let value = format!("a{ch}b");
            let refused = fill(&value).unwrap_err();
            assert_eq!(
                refused.code,
                FailureCode::InvalidRequest,
                "U+{:04X}",
                ch as u32
            );
            assert!(refused.message.contains("escape"), "{}", refused.message);
            assert!(select(&value).is_err(), "U+{:04X}", ch as u32);
        }
        // A third combining mark in a row would be escaped.
        assert!(fill("e\u{301}\u{302}\u{303}").is_err());
    }

    /// SG-000122 slice A2: each form action needs a fresh SOFT approval; the
    /// text wait, the verifier and the other read-only shapes need none.
    #[test]
    fn sg122_form_actions_are_soft_and_waits_and_checks_read_only() {
        use crate::ApprovalClass;
        for (capability, operation) in [
            ("browser.dom", "fill"),
            ("browser.form", "select"),
            ("browser.form", "check"),
            ("browser.form", "enter"),
            ("browser.dom", "click"),
            ("browser.navigation", "navigate"),
            ("browser.download", "download"),
        ] {
            assert_eq!(
                live_approval_class(capability, operation),
                Some(Some(ApprovalClass::Soft)),
                "{capability}/{operation}"
            );
        }
        for (capability, operation) in [
            ("browser.wait", "text"),
            ("browser.verify", "check"),
            ("browser.page", "open"),
            ("browser.snapshot", "observe"),
            ("browser.download", "preview"),
        ] {
            assert_eq!(
                live_approval_class(capability, operation),
                Some(None),
                "{capability}/{operation}"
            );
        }
        assert_eq!(live_approval_class("browser.dom", "press"), None);
        assert_eq!(live_approval_class("browser.upload", "submit"), None);
    }

    /// SG-000122's rule change on the closed-grain denials: the
    /// `DENIED_BROWSER_SHAPES` and sg000024 pins still deny
    /// `browser.dom/press` and `browser.dom/select` as STRONG, no live name
    /// collides with a denied shape, and the new live names stay denied and
    /// STRONG on the model-only path.
    #[test]
    fn sg122_closed_grain_pins_hold_and_no_live_name_collides() {
        use crate::ApprovalClass;
        use orcel_provider_browser::{is_denied_browser_shape, DENIED_BROWSER_SHAPES};
        for pinned in [("browser.dom", "press"), ("browser.dom", "select")] {
            assert!(DENIED_BROWSER_SHAPES.contains(&pinned), "{pinned:?}");
            assert!(is_denied_browser_shape(pinned.0, pinned.1));
            assert_eq!(
                crate::approval_class_for(pinned.0, pinned.1),
                ApprovalClass::Strong
            );
            assert!(!is_live_browser_shape(pinned.0, pinned.1));
        }
        for (capability, operation, _) in LIVE_FORMS {
            assert!(
                !DENIED_BROWSER_SHAPES.contains(&(*capability, *operation)),
                "{capability}/{operation} collides with a closed-grain denial"
            );
        }
        let root = std::env::temp_dir();
        let engine = crate::PolicyEngine::new(vec![crate::Workspace {
            id: "default".into(),
            root,
        }])
        .expect("policy");
        for (capability, operation) in LIVE_FORM_SHAPES {
            if *capability == "browser.dom" {
                // The promoted qualified shape keeps its model-only form.
                continue;
            }
            assert!(is_denied_browser_shape(capability, operation));
            assert_eq!(
                crate::approval_class_for(capability, operation),
                ApprovalClass::Strong,
                "{capability}/{operation}"
            );
            let model = request(capability, operation, json!({}));
            assert_eq!(
                engine.authorize(&model).unwrap_err().code,
                FailureCode::CapabilityDenied,
                "{capability}/{operation}"
            );
        }
    }
}
