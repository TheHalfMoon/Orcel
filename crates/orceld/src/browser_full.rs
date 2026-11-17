//! SG-000135 OB-02: the request forms of the `browser_full` broker shapes.
//!
//! Every shape is `browser.session/<operation>`; every one but `create`
//! names the broker's `session_id`. A caller says only what it may say
//! about its own session: the session id the broker minted, a URL, an
//! observed node, a value or option label, postconditions, the generation
//! it saw, and an optional task label for a new session. Profiles, pins,
//! folders, approvals, scripts, selectors and page ids are never the
//! caller's: the broker holds the session's page.
//!
//! Each shape that maps onto an existing live host action is also checked
//! in that action's live form by `PolicyEngine::authorize_live_browser`
//! (`live_request`), before anything runs, so a value, option, URL or check
//! the live path would refuse is refused here the same way.

use crate::browser_broker;
use orcel_contracts::{FailureCode, RequestEnvelope, INTERNAL_PROTOCOL_VERSION};
use orcel_provider_fs::ProviderError;
use serde_json::{json, Map, Value};

/// The page id the up-front live-form check uses: well formed, and never
/// one the page store mints (those are 32 hex characters).
pub(crate) const VALIDATION_PAGE_ID: &str = "pg-ob02-validation";

/// Each broker operation, its required and its optional argument fields.
const FORMS: &[(&str, &[&str], &[&str])] = &[
    ("create", &[], &["task"]),
    ("open", &["session_id", "url"], &[]),
    ("snapshot", &["session_id"], &[]),
    (
        "click",
        &["session_id", "node_id", "expected_generation"],
        &[],
    ),
    (
        "fill",
        &["session_id", "node_id", "value", "expected_generation"],
        &[],
    ),
    (
        "select",
        &["session_id", "node_id", "option", "expected_generation"],
        &[],
    ),
    (
        "verify",
        &["session_id", "checks", "expected_generation"],
        &[],
    ),
    ("extract", &["session_id", "expected_generation"], &[]),
    ("close", &["session_id"], &[]),
    ("status", &["session_id"], &[]),
];

/// One parsed broker request.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum FullAction {
    Create {
        task: Option<String>,
    },
    Open {
        session: String,
        url: String,
    },
    Snapshot {
        session: String,
    },
    Click {
        session: String,
        node_id: String,
        expected_generation: u64,
    },
    Fill {
        session: String,
        node_id: String,
        value: String,
        expected_generation: u64,
    },
    Select {
        session: String,
        node_id: String,
        option: String,
        expected_generation: u64,
    },
    Verify {
        session: String,
        checks: Value,
        expected_generation: u64,
    },
    Extract {
        session: String,
        expected_generation: u64,
    },
    Close {
        session: String,
    },
    Status {
        session: String,
    },
}

fn invalid(message: impl Into<String>) -> ProviderError {
    ProviderError::new(FailureCode::InvalidRequest, message)
}

/// Parse a `browser.session` request: its version, no target, exactly its
/// own fields, each of the right type, and a well-formed session id.
pub(crate) fn parse(request: &RequestEnvelope) -> Result<FullAction, ProviderError> {
    if request.version != INTERNAL_PROTOCOL_VERSION {
        return Err(invalid("unsupported internal protocol version"));
    }
    if request.capability != "browser.session" {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "not a browser_full shape",
        ));
    }
    let (required, optional) = FORMS
        .iter()
        .find(|(operation, _, _)| *operation == request.operation)
        .map(|(_, required, optional)| (*required, *optional))
        .ok_or_else(|| {
            ProviderError::new(FailureCode::CapabilityDenied, "not a browser_full shape")
        })?;
    if request.target.is_some() {
        return Err(invalid("browser_full shapes do not accept a target field"));
    }
    let empty = Map::new();
    let arguments = match &request.arguments {
        Value::Object(map) => map,
        Value::Null => &empty,
        _ => return Err(invalid("browser_full arguments must be an object")),
    };
    for key in arguments.keys() {
        if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
            return Err(invalid(format!(
                "browser.session/{} does not accept argument field: {key}",
                request.operation
            )));
        }
    }
    for field in required {
        if !arguments.contains_key(*field) {
            return Err(invalid(format!(
                "browser_full request requires arguments.{field}"
            )));
        }
    }
    let text = |name: &str| -> Result<String, ProviderError> {
        arguments
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| invalid(format!("{name} must be a string")))
    };
    let number = |name: &str| -> Result<u64, ProviderError> {
        arguments
            .get(name)
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid(format!("{name} must be an unsigned integer")))
    };
    let session = || -> Result<String, ProviderError> {
        let id = text("session_id")?;
        browser_broker::parse_session_id(&id)?;
        Ok(id)
    };
    Ok(match request.operation.as_str() {
        "create" => {
            let task = match arguments.get("task") {
                None => None,
                Some(_) => {
                    let task = text("task")?;
                    browser_broker::check_task(&task)?;
                    Some(task)
                }
            };
            FullAction::Create { task }
        }
        "open" => FullAction::Open {
            session: session()?,
            url: text("url")?,
        },
        "snapshot" => FullAction::Snapshot {
            session: session()?,
        },
        "click" => FullAction::Click {
            session: session()?,
            node_id: text("node_id")?,
            expected_generation: number("expected_generation")?,
        },
        "fill" => FullAction::Fill {
            session: session()?,
            node_id: text("node_id")?,
            value: text("value")?,
            expected_generation: number("expected_generation")?,
        },
        "select" => FullAction::Select {
            session: session()?,
            node_id: text("node_id")?,
            option: text("option")?,
            expected_generation: number("expected_generation")?,
        },
        "verify" => FullAction::Verify {
            session: session()?,
            checks: arguments.get("checks").cloned().unwrap_or(Value::Null),
            expected_generation: number("expected_generation")?,
        },
        "extract" => FullAction::Extract {
            session: session()?,
            expected_generation: number("expected_generation")?,
        },
        "close" => FullAction::Close {
            session: session()?,
        },
        "status" => FullAction::Status {
            session: session()?,
        },
        _ => {
            return Err(ProviderError::new(
                FailureCode::CapabilityDenied,
                "not a browser_full shape",
            ));
        }
    })
}

impl FullAction {
    /// The session the action names (none for `create`).
    #[cfg_attr(not(all(windows, feature = "live-browser-dev")), allow(dead_code))]
    pub(crate) fn session_id(&self) -> Option<&str> {
        match self {
            Self::Create { .. } => None,
            Self::Open { session, .. }
            | Self::Snapshot { session }
            | Self::Click { session, .. }
            | Self::Fill { session, .. }
            | Self::Select { session, .. }
            | Self::Verify { session, .. }
            | Self::Extract { session, .. }
            | Self::Close { session }
            | Self::Status { session } => Some(session),
        }
    }

    /// The MCP tool the action belongs to (the receipt's action name).
    #[cfg_attr(not(all(windows, feature = "live-browser-dev")), allow(dead_code))]
    pub(crate) fn tool(&self) -> &'static str {
        match self {
            Self::Create { .. } => "browser_session_create",
            Self::Open { .. } => "browser_open",
            Self::Snapshot { .. } => "browser_snapshot",
            Self::Click { .. } => "browser_click",
            Self::Fill { .. } => "browser_fill",
            Self::Select { .. } => "browser_select",
            Self::Verify { .. } => "browser_verify",
            Self::Extract { .. } => "browser_extract",
            Self::Close { .. } => "browser_close",
            Self::Status { .. } => "browser_task_status",
        }
    }

    /// The live shape the action maps onto, as the request the live policy
    /// validates, on the session's page `page_id` at `generation` (the
    /// caller's own generation where the action carries one). `None` for
    /// the actions that are the broker's own (create, close, status) and
    /// for extract, which has no live shape of its own.
    pub(crate) fn live_request(
        &self,
        base: &RequestEnvelope,
        page_id: &str,
        generation: u64,
    ) -> Option<RequestEnvelope> {
        let (capability, operation, arguments) = match self {
            Self::Open { url, .. } => (
                "browser.navigation",
                "navigate",
                json!({"page_id": page_id, "url": url, "expected_generation": generation}),
            ),
            Self::Snapshot { .. } => (
                "browser.snapshot",
                "observe",
                json!({"page_id": page_id, "expected_generation": generation}),
            ),
            Self::Click {
                node_id,
                expected_generation,
                ..
            } => (
                "browser.dom",
                "click",
                json!({"page_id": page_id, "node_id": node_id, "expected_generation": expected_generation}),
            ),
            Self::Fill {
                node_id,
                value,
                expected_generation,
                ..
            } => (
                "browser.dom",
                "fill",
                json!({"page_id": page_id, "node_id": node_id, "value": value, "expected_generation": expected_generation}),
            ),
            Self::Select {
                node_id,
                option,
                expected_generation,
                ..
            } => (
                "browser.form",
                "select",
                json!({"page_id": page_id, "node_id": node_id, "option": option, "expected_generation": expected_generation}),
            ),
            Self::Verify {
                checks,
                expected_generation,
                ..
            } => (
                "browser.verify",
                "check",
                json!({"page_id": page_id, "checks": checks, "expected_generation": expected_generation}),
            ),
            Self::Create { .. }
            | Self::Extract { .. }
            | Self::Close { .. }
            | Self::Status { .. } => return None,
        };
        Some(RequestEnvelope {
            version: base.version,
            request_id: base.request_id.clone(),
            client_session_id: base.client_session_id.clone(),
            workspace_id: base.workspace_id.clone(),
            capability: capability.to_owned(),
            operation: operation.to_owned(),
            target: None,
            arguments,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile_gate::BROWSER_FULL_SHAPES;
    use orcel_policy::{PolicyEngine, Workspace};

    const SESSION: &str = "bs-0123456789abcdef-1-0001020304050607";

    fn request(operation: &str, arguments: Value) -> RequestEnvelope {
        RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "r".into(),
            client_session_id: "s".into(),
            workspace_id: "default".into(),
            capability: "browser.session".into(),
            operation: operation.into(),
            target: None,
            arguments,
        }
    }

    fn policy() -> (PolicyEngine, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("orcel-ob02-policy-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        (
            PolicyEngine::new(vec![Workspace {
                id: "default".into(),
                root: root.clone(),
            }])
            .unwrap(),
            root,
        )
    }

    #[test]
    fn every_broker_shape_has_one_form_and_parses() {
        assert_eq!(FORMS.len(), BROWSER_FULL_SHAPES.len());
        for (capability, operation) in BROWSER_FULL_SHAPES {
            assert_eq!(*capability, "browser.session");
            assert_eq!(FORMS.iter().filter(|(o, _, _)| o == operation).count(), 1);
        }
        let cases = [
            ("create", json!({})),
            ("create", json!({"task": "Book a table"})),
            (
                "open",
                json!({"session_id": SESSION, "url": "https://example.com/"}),
            ),
            ("snapshot", json!({"session_id": SESSION})),
            (
                "click",
                json!({"session_id": SESSION, "node_id": "n1", "expected_generation": 1}),
            ),
            (
                "fill",
                json!({"session_id": SESSION, "node_id": "n1", "value": "Ada", "expected_generation": 1}),
            ),
            (
                "select",
                json!({"session_id": SESSION, "node_id": "n1", "option": "Two", "expected_generation": 1}),
            ),
            (
                "verify",
                json!({"session_id": SESSION, "checks": [{"kind": "url_is", "url": "https://example.com/"}], "expected_generation": 1}),
            ),
            (
                "extract",
                json!({"session_id": SESSION, "expected_generation": 1}),
            ),
            ("close", json!({"session_id": SESSION})),
            ("status", json!({"session_id": SESSION})),
        ];
        for (operation, arguments) in cases {
            let action = parse(&request(operation, arguments)).unwrap();
            assert_eq!(
                action.session_id().is_some(),
                operation != "create",
                "{operation}"
            );
        }
    }

    #[test]
    fn unknown_fields_authority_fields_and_bad_types_are_refused() {
        for (operation, arguments) in [
            (
                "open",
                json!({"session_id": SESSION, "url": "https://example.com/", "page_id": "pg-1"}),
            ),
            (
                "open",
                json!({"session_id": SESSION, "url": "https://example.com/", "profile_root": "C:\\Users"}),
            ),
            ("snapshot", json!({"session_id": SESSION, "selector": "#a"})),
            ("create", json!({"profile": "Default"})),
            ("create", json!({"task": 7})),
            ("create", json!({"task": "two\nlines"})),
            ("click", json!({"session_id": SESSION, "node_id": "n1"})),
            (
                "click",
                json!({"session_id": SESSION, "node_id": "n1", "expected_generation": -1}),
            ),
            (
                "fill",
                json!({"session_id": SESSION, "node_id": "n1", "value": 3, "expected_generation": 1}),
            ),
            ("close", json!({})),
            ("close", json!({"session_id": "bs-nope"})),
            ("status", json!({"session_id": 5})),
            ("status", json!("not an object")),
        ] {
            let refused = parse(&request(operation, arguments.clone())).unwrap_err();
            assert_eq!(
                refused.code,
                FailureCode::InvalidRequest,
                "{operation} {arguments}"
            );
        }
        let mut targeted = request("snapshot", json!({"session_id": SESSION}));
        targeted.target = Some("x".into());
        assert_eq!(
            parse(&targeted).unwrap_err().code,
            FailureCode::InvalidRequest
        );
        for (capability, operation) in [
            ("browser.session", "outline"),
            ("browser.session", "extract_schema"),
            ("browser.session", "evaluate"),
            ("browser.dom", "click"),
        ] {
            let mut other = request(operation, json!({}));
            other.capability = capability.into();
            assert_eq!(
                parse(&other).unwrap_err().code,
                FailureCode::CapabilityDenied
            );
        }
    }

    /// Each mapped action is checked in its live form by the live policy:
    /// what the live path refuses (a non-HTTPS URL, a value the prompt
    /// cannot show in full, malformed checks) is refused here.
    #[test]
    fn mapped_actions_pass_the_live_policy_in_their_live_form() {
        let (policy, root) = policy();
        let ok = [
            (
                "open",
                json!({"session_id": SESSION, "url": "https://example.com/"}),
            ),
            ("snapshot", json!({"session_id": SESSION})),
            (
                "click",
                json!({"session_id": SESSION, "node_id": "n1", "expected_generation": 2}),
            ),
            (
                "fill",
                json!({"session_id": SESSION, "node_id": "n1", "value": "Ada", "expected_generation": 2}),
            ),
            (
                "select",
                json!({"session_id": SESSION, "node_id": "n1", "option": "Two", "expected_generation": 2}),
            ),
            (
                "verify",
                json!({"session_id": SESSION, "checks": [{"kind": "url_is", "url": "https://example.com/"}], "expected_generation": 2}),
            ),
        ];
        let shapes = [
            ("browser.navigation", "navigate"),
            ("browser.snapshot", "observe"),
            ("browser.dom", "click"),
            ("browser.dom", "fill"),
            ("browser.form", "select"),
            ("browser.verify", "check"),
        ];
        for ((operation, arguments), (capability, live_operation)) in ok.into_iter().zip(shapes) {
            let base = request(operation, arguments);
            let action = parse(&base).unwrap();
            let live = action.live_request(&base, VALIDATION_PAGE_ID, 0).unwrap();
            assert_eq!(
                (live.capability.as_str(), live.operation.as_str()),
                (capability, live_operation)
            );
            assert!(live.arguments.get("session_id").is_none());
            policy.authorize_live_browser(&live).unwrap();
        }
        for (operation, arguments) in [
            (
                "open",
                json!({"session_id": SESSION, "url": "http://example.com/"}),
            ),
            (
                "open",
                json!({"session_id": SESSION, "url": "javascript:alert(1)"}),
            ),
            (
                "fill",
                json!({"session_id": SESSION, "node_id": "n1", "value": "a\u{202e}b", "expected_generation": 2}),
            ),
            (
                "fill",
                json!({"session_id": SESSION, "node_id": "bad node", "value": "a", "expected_generation": 2}),
            ),
            (
                "select",
                json!({"session_id": SESSION, "node_id": "n1", "option": "", "expected_generation": 2}),
            ),
            (
                "verify",
                json!({"session_id": SESSION, "checks": [], "expected_generation": 2}),
            ),
            (
                "verify",
                json!({"session_id": SESSION, "checks": [{"kind": "evaluate"}], "expected_generation": 2}),
            ),
        ] {
            let base = request(operation, arguments.clone());
            let action = parse(&base).unwrap();
            let live = action.live_request(&base, VALIDATION_PAGE_ID, 0).unwrap();
            assert!(
                policy.authorize_live_browser(&live).is_err(),
                "{operation} {arguments}"
            );
        }
        for (operation, arguments) in [
            ("create", json!({})),
            (
                "extract",
                json!({"session_id": SESSION, "expected_generation": 1}),
            ),
            ("close", json!({"session_id": SESSION})),
            ("status", json!({"session_id": SESSION})),
        ] {
            let base = request(operation, arguments);
            assert!(parse(&base)
                .unwrap()
                .live_request(&base, VALIDATION_PAGE_ID, 0)
                .is_none());
        }
        let _ = std::fs::remove_dir_all(root);
    }
}
