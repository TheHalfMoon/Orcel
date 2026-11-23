//! SG-000135 OB-02: the request forms of the `browser_full` broker shapes.
//!
//! Every shape is `browser.session/<operation>`; every one but `create`
//! names the broker's `session_id`. A caller says only what it may say
//! about its own session: the session id the broker minted, a URL, an
//! observed node, a value or option label, postconditions, the generation
//! it saw, and an optional task label for a new session. Pins, folders,
//! paths, approvals, scripts, selectors and page ids are never the
//! caller's: the broker holds the session's page.
//!
//! SG-000135 OB-04: a new session may also name its mode (`shadow`, the
//! default, or `visible`) and an existing Orcel-managed profile by its
//! checked name (never a path: orceld builds every path from the name under
//! its own state). `profiles` lists those profiles; `profile_create` and
//! `profile_delete` name one, and each asks the owner first.
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
    ("create", &[], &["task", "mode", "profile", "continue_from"]),
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
    // SG-000135 OB-03.
    (
        "screenshot",
        &["session_id", "expected_generation"],
        &["full_page"],
    ),
    ("tabs", &["session_id", "action"], &["url", "page_id"]),
    ("close", &["session_id"], &[]),
    ("status", &["session_id"], &[]),
    // SG-000135 OB-04: persistent Orcel-managed profiles.
    ("profiles", &[], &[]),
    ("profile_create", &["name"], &[]),
    ("profile_delete", &["name"], &[]),
];

/// SG-000135 OB-03: what `browser_tabs` asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TabOp {
    /// Every tab, read-only.
    List,
    /// A new active tab; with a URL, navigated there (a navigation: SOFT).
    New { url: Option<String> },
    /// Make the tab with this page id active.
    Switch { page_id: String },
    /// Close the tab with this page id.
    Close { page_id: String },
}

/// Whether `id` is a page id the page store mints (`pg-` and 32
/// lowercase hex).
pub(crate) fn is_page_id(id: &str) -> bool {
    id.strip_prefix("pg-").is_some_and(|hex| {
        hex.len() == 32
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// One parsed broker request.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum FullAction {
    Create {
        task: Option<String>,
        /// SG-000135 OB-04: Shadow (default) or Visible.
        mode: browser_broker::SessionMode,
        /// SG-000135 OB-04: an existing persistent profile's name, or
        /// `None` for an ephemeral profile (the default).
        profile: Option<String>,
        /// SG-000135 SH-2: the caller's open session whose task moves to
        /// this new session in `mode` (the other mode). It takes that
        /// session's profile and task label, so it names neither.
        continue_from: Option<String>,
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
    Screenshot {
        session: String,
        expected_generation: u64,
        full_page: bool,
    },
    Tabs {
        session: String,
        op: TabOp,
    },
    Close {
        session: String,
    },
    Status {
        session: String,
    },
    /// SG-000135 OB-04: list the persistent profiles (read-only).
    Profiles,
    /// SG-000135 OB-04: create a persistent profile (owner-approved).
    ProfileCreate {
        name: String,
    },
    /// SG-000135 OB-04: delete a persistent profile (owner-approved).
    ProfileDelete {
        name: String,
    },
}

/// The longest node id a request may name (the MCP schema's bound).
pub(crate) const MAX_NODE_ID_CHARS: usize = 64;

/// Whether `id` is a node id as the MCP schema admits it.
pub(crate) fn is_node_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_NODE_ID_CHARS
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
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
    // SG-000135 OB-05 review: a node id is what the MCP schema admits (1 to
    // 64 of A-Z, a-z, 0-9, `_` and `-`), so a receipt's target stays bounded.
    let node = || -> Result<String, ProviderError> {
        let id = text("node_id")?;
        if !is_node_id(&id) {
            return Err(invalid(format!(
                "node_id is 1 to {MAX_NODE_ID_CHARS} letters, digits, '_' or '-'"
            )));
        }
        Ok(id)
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
            let mode = match arguments.get("mode") {
                None => browser_broker::SessionMode::Shadow,
                Some(_) => browser_broker::SessionMode::parse(&text("mode")?)?,
            };
            let profile = match arguments.get("profile") {
                None => None,
                Some(_) => {
                    let name = text("profile")?;
                    crate::browser_profiles::check_name(&name)?;
                    Some(name)
                }
            };
            // SG-000135 SH-2: a switch names the session it continues and
            // the mode it moves to; the profile and task are that session's.
            let continue_from = match arguments.get("continue_from") {
                None => None,
                Some(_) => {
                    if !arguments.contains_key("mode") {
                        return Err(invalid(
                            "continue_from requires mode: the mode the task moves to",
                        ));
                    }
                    if task.is_some() || profile.is_some() {
                        return Err(invalid(
                            "continue_from takes the continued session's profile and task; name neither",
                        ));
                    }
                    let id = text("continue_from")?;
                    browser_broker::parse_session_id(&id)?;
                    Some(id)
                }
            };
            FullAction::Create {
                task,
                mode,
                profile,
                continue_from,
            }
        }
        "profiles" => FullAction::Profiles,
        "profile_create" | "profile_delete" => {
            let name = text("name")?;
            crate::browser_profiles::check_name(&name)?;
            if request.operation == "profile_create" {
                FullAction::ProfileCreate { name }
            } else {
                FullAction::ProfileDelete { name }
            }
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
            node_id: node()?,
            expected_generation: number("expected_generation")?,
        },
        "fill" => FullAction::Fill {
            session: session()?,
            node_id: node()?,
            value: text("value")?,
            expected_generation: number("expected_generation")?,
        },
        "select" => FullAction::Select {
            session: session()?,
            node_id: node()?,
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
        "screenshot" => FullAction::Screenshot {
            session: session()?,
            expected_generation: number("expected_generation")?,
            full_page: match arguments.get("full_page") {
                None => false,
                Some(value) => value
                    .as_bool()
                    .ok_or_else(|| invalid("full_page must be a boolean"))?,
            },
        },
        "tabs" => {
            let session = session()?;
            let action = text("action")?;
            let has = |name: &str| arguments.contains_key(name);
            let op = match action.as_str() {
                "list" if !has("url") && !has("page_id") => TabOp::List,
                "new" if !has("page_id") => TabOp::New {
                    url: if has("url") { Some(text("url")?) } else { None },
                },
                "switch" | "close" if !has("url") => {
                    if !has("page_id") {
                        return Err(invalid(format!(
                            "browser_tabs {action} requires arguments.page_id"
                        )));
                    }
                    let page_id = text("page_id")?;
                    if !is_page_id(&page_id) {
                        return Err(invalid("page_id is not a browser page id"));
                    }
                    if action == "switch" {
                        TabOp::Switch { page_id }
                    } else {
                        TabOp::Close { page_id }
                    }
                }
                "list" | "new" | "switch" | "close" => {
                    return Err(invalid(format!(
                        "browser_tabs {action} does not accept that argument field"
                    )));
                }
                _ => return Err(invalid("action must be list, new, switch or close")),
            };
            FullAction::Tabs { session, op }
        }
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
            Self::Create { .. }
            | Self::Profiles
            | Self::ProfileCreate { .. }
            | Self::ProfileDelete { .. } => None,
            Self::Open { session, .. }
            | Self::Snapshot { session }
            | Self::Click { session, .. }
            | Self::Fill { session, .. }
            | Self::Select { session, .. }
            | Self::Verify { session, .. }
            | Self::Extract { session, .. }
            | Self::Screenshot { session, .. }
            | Self::Tabs { session, .. }
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
            Self::Screenshot { .. } => "browser_screenshot",
            Self::Tabs { .. } => "browser_tabs",
            Self::Close { .. } => "browser_close",
            Self::Status { .. } => "browser_task_status",
            Self::Profiles => "browser_profiles",
            Self::ProfileCreate { .. } => "browser_profile_create",
            Self::ProfileDelete { .. } => "browser_profile_delete",
        }
    }

    /// SG-000135 OB-05: what a receipt names as the action's target: the
    /// node of a click, fill or select, or the tab a switch or close names.
    /// Never a value or an option label.
    #[cfg_attr(not(all(windows, feature = "live-browser-dev")), allow(dead_code))]
    pub(crate) fn receipt_target(&self) -> (Option<&str>, Option<&str>) {
        match self {
            Self::Click { node_id, .. }
            | Self::Fill { node_id, .. }
            | Self::Select { node_id, .. } => (None, Some(node_id)),
            Self::Tabs {
                op: TabOp::Switch { page_id } | TabOp::Close { page_id },
                ..
            } => (Some(page_id), None),
            _ => (None, None),
        }
    }

    /// SG-000135 OB-05: the URL an open or a new tab asks for (the receipt
    /// keeps its digest only).
    #[cfg_attr(not(all(windows, feature = "live-browser-dev")), allow(dead_code))]
    pub(crate) fn requested_url(&self) -> Option<&str> {
        match self {
            Self::Open { url, .. } => Some(url),
            Self::Tabs {
                op: TabOp::New { url },
                ..
            } => url.as_deref(),
            _ => None,
        }
    }

    /// SG-000135 OB-05: whether the action can change the page (a person's
    /// input during it supersedes it).
    #[cfg_attr(not(all(windows, feature = "live-browser-dev")), allow(dead_code))]
    pub(crate) fn changes_the_page(&self) -> bool {
        matches!(
            self,
            Self::Open { .. }
                | Self::Click { .. }
                | Self::Fill { .. }
                | Self::Select { .. }
                | Self::Tabs { .. }
        )
    }

    /// The live shape the action maps onto, as the request the live policy
    /// validates, on the session's page `page_id` at `generation` (the
    /// caller's own generation where the action carries one). `None` for
    /// the actions that are the broker's own (create, close, status), for
    /// extract and screenshot, which have no live shape of their own, and
    /// for a tab request other than a new tab to a URL (which is a
    /// navigation, checked as one).
    pub(crate) fn live_request(
        &self,
        base: &RequestEnvelope,
        page_id: &str,
        generation: u64,
    ) -> Option<RequestEnvelope> {
        let (capability, operation, arguments) = match self {
            Self::Open { url, .. }
            | Self::Tabs {
                op: TabOp::New { url: Some(url) },
                ..
            } => (
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
            | Self::Screenshot { .. }
            | Self::Tabs { .. }
            | Self::Close { .. }
            | Self::Status { .. }
            | Self::Profiles
            | Self::ProfileCreate { .. }
            | Self::ProfileDelete { .. } => return None,
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
    const PAGE: &str = "pg-0123456789abcdef0123456789abcdef";

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
            (
                "screenshot",
                json!({"session_id": SESSION, "expected_generation": 1}),
            ),
            (
                "screenshot",
                json!({"session_id": SESSION, "expected_generation": 1, "full_page": true}),
            ),
            ("tabs", json!({"session_id": SESSION, "action": "list"})),
            ("tabs", json!({"session_id": SESSION, "action": "new"})),
            (
                "tabs",
                json!({"session_id": SESSION, "action": "new", "url": "https://example.com/b"}),
            ),
            (
                "tabs",
                json!({"session_id": SESSION, "action": "switch", "page_id": PAGE}),
            ),
            (
                "tabs",
                json!({"session_id": SESSION, "action": "close", "page_id": PAGE}),
            ),
            ("close", json!({"session_id": SESSION})),
            ("status", json!({"session_id": SESSION})),
            ("create", json!({"mode": "visible"})),
            ("create", json!({"mode": "shadow", "profile": "work"})),
            ("profiles", json!({})),
            ("profile_create", json!({"name": "work"})),
            ("profile_delete", json!({"name": "work"})),
        ];
        for (operation, arguments) in cases {
            let action = parse(&request(operation, arguments)).unwrap();
            assert_eq!(
                action.session_id().is_some(),
                !["create", "profiles", "profile_create", "profile_delete"].contains(&operation),
                "{operation}"
            );
        }
    }

    /// SG-000135 OB-04: a mode is shadow or visible (shadow by default), and
    /// a profile is a checked name, never a path or a person's profile.
    #[test]
    fn ob04_mode_and_profile_are_closed_and_never_a_path() -> Result<(), String> {
        let parsed = |arguments: Value| {
            parse(&request("create", arguments)).map_err(|e| format!("{:?}: {}", e.code, e.message))
        };
        match parsed(json!({}))? {
            FullAction::Create { mode, profile, .. } => {
                assert_eq!(mode, browser_broker::SessionMode::Shadow);
                assert_eq!(profile, None);
            }
            other => return Err(format!("not a create: {other:?}")),
        }
        match parsed(json!({"mode": "visible", "profile": "shop-2"}))? {
            FullAction::Create { mode, profile, .. } => {
                assert_eq!(mode, browser_broker::SessionMode::Visible);
                assert_eq!(profile.as_deref(), Some("shop-2"));
            }
            other => return Err(format!("not a create: {other:?}")),
        }
        for arguments in [
            json!({"mode": "headed"}),
            json!({"mode": "Visible"}),
            json!({"mode": true}),
            json!({"profile": "Default"}),
            json!({"profile": "C:\\Users\\me\\AppData\\Local\\Google\\Chrome\\User Data"}),
            json!({"profile": "../work"}),
            json!({"profile": "work/data"}),
            json!({"profile": ""}),
            json!({"profile": 7}),
            json!({"profile_dir": "C:\\x"}),
        ] {
            assert!(parsed(arguments.clone()).is_err(), "{arguments}");
        }
        for (operation, arguments) in [
            ("profile_create", json!({})),
            ("profile_create", json!({"name": "Work"})),
            ("profile_create", json!({"name": "work", "path": "C:\\x"})),
            ("profile_delete", json!({"name": "a/b"})),
            ("profiles", json!({"name": "work"})),
        ] {
            assert!(
                parse(&request(operation, arguments.clone())).is_err(),
                "{operation} {arguments}"
            );
        }
        Ok(())
    }

    /// SG-000135 SH-2: a switch names a well-formed session id and the mode
    /// it moves to, and takes that session's profile and task (it names
    /// neither); without `continue_from` create is unchanged.
    #[test]
    fn sh2_continue_from_names_a_session_and_a_mode_only() -> Result<(), String> {
        let parsed = |arguments: Value| {
            parse(&request("create", arguments)).map_err(|e| format!("{:?}: {}", e.code, e.message))
        };
        match parsed(json!({"continue_from": SESSION, "mode": "visible"}))? {
            FullAction::Create {
                mode,
                profile,
                task,
                continue_from,
            } => {
                assert_eq!(mode, browser_broker::SessionMode::Visible);
                assert_eq!((profile, task), (None, None));
                assert_eq!(continue_from.as_deref(), Some(SESSION));
            }
            other => return Err(format!("not a create: {other:?}")),
        }
        match parsed(json!({"mode": "visible"}))? {
            FullAction::Create { continue_from, .. } => assert_eq!(continue_from, None),
            other => return Err(format!("not a create: {other:?}")),
        }
        for arguments in [
            json!({"continue_from": SESSION}),
            json!({"continue_from": SESSION, "mode": "visible", "profile": "work"}),
            json!({"continue_from": SESSION, "mode": "shadow", "task": "x"}),
            json!({"continue_from": "bs-1", "mode": "visible"}),
            json!({"continue_from": PAGE, "mode": "visible"}),
            json!({"continue_from": 7, "mode": "visible"}),
            json!({"continue_from": SESSION, "mode": "headed"}),
        ] {
            assert!(parsed(arguments.clone()).is_err(), "{arguments}");
        }
        Ok(())
    }

    /// SG-000135 OB-05 review: a node id is bounded as the MCP schema bounds
    /// it, at parse, before the live policy sees it (`bad node` included).
    #[test]
    fn ob05_node_ids_are_bounded_like_the_schema() {
        for (id, ok) in [
            ("n1", true),
            ("a_b-C9", true),
            (&*"n".repeat(64), true),
            (&*"n".repeat(65), false),
            ("", false),
            ("n 1", false),
            ("n/1", false),
            ("bad node", false),
            ("n\u{e9}", false),
        ] {
            assert_eq!(is_node_id(id), ok, "{id:?}");
            let parsed = parse(&request(
                "click",
                json!({"session_id": SESSION, "node_id": id, "expected_generation": 1}),
            ));
            assert_eq!(parsed.is_ok(), ok, "{id:?}");
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
            // SG-000135 OB-03: a screenshot names no window, target, clip
            // or page; a tab request only its own fields, each in its place.
            (
                "screenshot",
                json!({"session_id": SESSION, "expected_generation": 1, "hwnd": 7}),
            ),
            (
                "screenshot",
                json!({"session_id": SESSION, "expected_generation": 1, "page_id": PAGE}),
            ),
            (
                "screenshot",
                json!({"session_id": SESSION, "expected_generation": 1, "full_page": "yes"}),
            ),
            ("screenshot", json!({"session_id": SESSION})),
            ("tabs", json!({"session_id": SESSION})),
            ("tabs", json!({"session_id": SESSION, "action": "group"})),
            (
                "tabs",
                json!({"session_id": SESSION, "action": "list", "page_id": PAGE}),
            ),
            (
                "tabs",
                json!({"session_id": SESSION, "action": "new", "page_id": PAGE}),
            ),
            ("tabs", json!({"session_id": SESSION, "action": "switch"})),
            (
                "tabs",
                json!({"session_id": SESSION, "action": "close", "page_id": "pg-1"}),
            ),
            (
                "tabs",
                json!({"session_id": SESSION, "action": "switch", "page_id": PAGE, "url": "https://example.com/"}),
            ),
            (
                "tabs",
                json!({"session_id": SESSION, "action": "new", "url": 5}),
            ),
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
            (
                "tabs",
                json!({"session_id": SESSION, "action": "new", "url": "https://example.com/b"}),
            ),
        ];
        let shapes = [
            ("browser.navigation", "navigate"),
            ("browser.snapshot", "observe"),
            ("browser.dom", "click"),
            ("browser.dom", "fill"),
            ("browser.form", "select"),
            ("browser.verify", "check"),
            ("browser.navigation", "navigate"),
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
            (
                "tabs",
                json!({"session_id": SESSION, "action": "new", "url": "http://example.com/"}),
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
            (
                "screenshot",
                json!({"session_id": SESSION, "expected_generation": 1}),
            ),
            ("tabs", json!({"session_id": SESSION, "action": "list"})),
            ("tabs", json!({"session_id": SESSION, "action": "new"})),
            (
                "tabs",
                json!({"session_id": SESSION, "action": "close", "page_id": PAGE}),
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
