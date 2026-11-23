//! SG-000108 decision 6: `orceld`'s profile gate. A live browser shape is
//! dispatched only for a local request whose envelope names the
//! `browser_structured` profile, and never for a remote one.
//!
//! The profile is the sender's own claim, not proof: anything that can
//! write `orceld`'s stdin can also write `"profile":"browser_structured"`.
//! What the gate guarantees is that the MCP edge, which sends that profile
//! only when local configuration selected it, cannot reach a live shape
//! otherwise, and that no remote request reaches one at all. Every
//! consequential live action still needs a broker approval from the user.
//!
//! The live shapes are listed here, in the MCP tool contract
//! (`LIVE_BROWSER_TOOLS` in `apps/orcel-mcp/src/tool_contract.ts`) and in
//! `orcel-browser-host`'s `LIVE_BROWSER_MCP_TOOLS`; a cross-language test
//! (`apps/orcel-mcp/src/browser-exposure.test.ts`) fails if they differ.
//! Slice 3c exposes six shapes, in development builds only (decision 7).
//!
//! SG-000122 slice A2 added the live form shapes, gated the same way: local
//! only, `browser_structured` only, dispatched only in development builds on
//! Windows (decision 7). Slice A3 gave fill, the text wait and the verifier
//! MCP tools and slice A4 gives select, check and Enter theirs, so every
//! one of the grain's shapes is now in `LIVE_BROWSER_SHAPES` and the
//! cross-language agreement. The separate table slice A2 kept for the
//! shapes without a tool (`LIVE_FORM_SHAPES`) is gone: no live shape is
//! reachable without an MCP tool any more.
//!
//! SG-000135 OB-02 adds the `browser_full` profile: its shapes
//! (`BROWSER_FULL_SHAPES`, capability `browser.session`) run through the
//! Orcel Browser Session Broker, are dispatched only for a local request
//! naming `browser_full`, and never for a remote one (remote browser
//! mapping stays disabled). The two profiles never share a shape: a
//! `browser_structured` live shape under `browser_full` is refused, and a
//! `browser_full` shape under `browser_structured` is refused. The table
//! agrees with `BROWSER_FULL_TOOLS` in `apps/orcel-mcp/src/tool_contract.ts`
//! and `BROWSER_FULL_MCP_TOOLS` in `orcel-browser-host`'s exposure list
//! (`apps/orcel-mcp/src/browser-full.test.ts`).
//!
//! SG-000135 OB-09 lifts SG-000079's "no remote mapping" for `browser_full`
//! only (the founder's 2026-11-17 directive of a remote browser profile;
//! remote lease coverage is PENDING FOUNDER CONFIRMATION, see
//! `browser_lease::REMOTE_LEASE_COVERAGE_CONFIRMED`): a remote request may reach the remote-safe broker shapes
//! (`REMOTE_BROWSER_FULL_SHAPES`) when its authenticated remote context
//! names the `browser_full` tool-surface profile. The gate admits the shape
//! only; the SG-000055 STRONG remote-session lease for that profile is
//! checked next, before anything else (`remote_lease::gate_remote`), and
//! every approval the request raises is the owner's Windows dialog, marked
//! remote. The persistent profile shapes and a persistent profile named at
//! create stay local-only. `browser_structured`'s live shapes stay local
//! only.

use orcel_contracts::{FailureCode, RemoteContext, RequestEnvelope};

/// The profile that alone may reach a live browser shape.
pub const BROWSER_STRUCTURED_PROFILE: &str = "browser_structured";

/// SG-000135 OB-02: the profile that alone may reach a broker shape.
pub const BROWSER_FULL_PROFILE: &str = "browser_full";

/// SG-000135 OB-02: the broker shapes of the `browser_full` profile, one
/// per MCP tool: session create, open, snapshot, click, fill, select,
/// verify, extract, screenshot, tabs, close and task status. SG-000135
/// OB-03's screenshot is read-only with no approval; its tabs list asks
/// nothing, and a new tab to a URL is a navigation with its own SOFT
/// approval. Each but create, close, status, screenshot and tabs maps onto an existing live host action with that action's own
/// approval (SOFT for open, click, fill and select; none for snapshot,
/// verify and extract).
/// SG-000135 OB-04 adds the persistent Orcel-managed profiles: list
/// (read-only), create and delete (each a fresh SOFT approval first).
pub const BROWSER_FULL_SHAPES: &[(&str, &str)] = &[
    ("browser.session", "create"),
    ("browser.session", "open"),
    ("browser.session", "snapshot"),
    ("browser.session", "click"),
    ("browser.session", "fill"),
    ("browser.session", "select"),
    ("browser.session", "verify"),
    ("browser.session", "extract"),
    ("browser.session", "screenshot"),
    ("browser.session", "tabs"),
    ("browser.session", "close"),
    ("browser.session", "status"),
    ("browser.session", "profiles"),
    ("browser.session", "profile_create"),
    ("browser.session", "profile_delete"),
];

/// SG-000135 OB-09: the broker shapes a remote `browser_full` caller may
/// reach (after the SG-000055 remote-session lease), each with the remote
/// scope `orcel_policy::remote_session::required_browser_full_scopes`
/// gives it. Left out: the persistent profile shapes (list, create,
/// delete), which manage profiles that may be signed in to the owner's
/// accounts.
pub const REMOTE_BROWSER_FULL_SHAPES: &[(&str, &str)] = &[
    ("browser.session", "create"),
    ("browser.session", "open"),
    ("browser.session", "snapshot"),
    ("browser.session", "click"),
    ("browser.session", "fill"),
    ("browser.session", "select"),
    ("browser.session", "verify"),
    ("browser.session", "extract"),
    ("browser.session", "screenshot"),
    ("browser.session", "tabs"),
    ("browser.session", "close"),
    ("browser.session", "status"),
];

/// The live browser shapes, each with an MCP tool (capability, operation):
/// slice 3c's six, each one of SG-000079's qualified browser shapes, and
/// SG-000122's six, exactly the policy's `LIVE_FORM_SHAPES`: slice A3's
/// `browser.dom/fill` (promoted by the SG-000108 decision 4 amendment),
/// `browser.wait/text` and `browser.verify/check`, and slice A4's
/// `browser.form/select`, `/check` and `/enter` (the wait, the verifier and
/// the three form shapes admitted beside the twelve by the A13 amendment).
/// Their names never collide with the closed-grain denials
/// (`browser.dom/press` and `browser.dom/select` stay denied and STRONG on
/// the model-only path). The uploads stay model-only.
pub const LIVE_BROWSER_SHAPES: &[(&str, &str)] = &[
    ("browser.page", "open"),
    ("browser.navigation", "navigate"),
    ("browser.snapshot", "observe"),
    ("browser.dom", "click"),
    ("browser.download", "preview"),
    ("browser.download", "download"),
    ("browser.dom", "fill"),
    ("browser.wait", "text"),
    ("browser.verify", "check"),
    ("browser.form", "select"),
    ("browser.form", "check"),
    ("browser.form", "enter"),
];

/// SG-000122's shapes, every one with an MCP tool since slice A4 (A3's
/// three, then A4's three), all in `LIVE_BROWSER_SHAPES`; the tests check
/// them against it and against the policy's `LIVE_FORM_SHAPES`.
#[cfg(test)]
pub const SG122_MCP_SHAPES: &[(&str, &str)] = &[
    ("browser.dom", "fill"),
    ("browser.wait", "text"),
    ("browser.verify", "check"),
    ("browser.form", "select"),
    ("browser.form", "check"),
    ("browser.form", "enter"),
];

fn names(shapes: &[(&str, &str)], request: &RequestEnvelope) -> bool {
    shapes.iter().any(|(capability, operation)| {
        *capability == request.capability && *operation == request.operation
    })
}

/// Whether a request names one of the live browser shapes.
pub fn is_live_shape(request: &RequestEnvelope) -> bool {
    names(LIVE_BROWSER_SHAPES, request)
}

/// SG-000135 OB-02: whether a request names one of the broker shapes.
pub fn is_browser_full_shape(request: &RequestEnvelope) -> bool {
    names(BROWSER_FULL_SHAPES, request)
}

/// Refuse a live browser shape unless the request is local and names the
/// `browser_structured` profile, and a broker shape unless it is local and
/// names `browser_full`. Every other shape passes unchanged: the profile
/// field grants nothing by itself.
pub fn gate(
    request: &RequestEnvelope,
    profile: Option<&str>,
    remote: Option<&RemoteContext>,
) -> Result<(), (FailureCode, &'static str)> {
    gate_shapes(LIVE_BROWSER_SHAPES, request, profile, remote)?;
    gate_full(BROWSER_FULL_SHAPES, request, profile, remote)
}

fn gate_full(
    shapes: &[(&str, &str)],
    request: &RequestEnvelope,
    profile: Option<&str>,
    remote: Option<&RemoteContext>,
) -> Result<(), (FailureCode, &'static str)> {
    if !names(shapes, request) {
        return Ok(());
    }
    if let Some(remote) = remote {
        return gate_remote_full(request, profile, remote);
    }
    crate::browser_remote::check_local_client(&request.client_session_id)?;
    if profile != Some(BROWSER_FULL_PROFILE) {
        return Err((
            FailureCode::CapabilityDenied,
            "SG-000135 browser_full shapes require the browser_full profile, selected by local configuration",
        ));
    }
    Ok(())
}

/// SG-000135 OB-09: a remote broker request. Its authenticated remote
/// context must name `browser_full` (a request profile, which a remote
/// edge never sends, must not name another), the shape must be remote-safe,
/// and a new session must not name a persistent profile.
fn gate_remote_full(
    request: &RequestEnvelope,
    profile: Option<&str>,
    remote: &RemoteContext,
) -> Result<(), (FailureCode, &'static str)> {
    if remote.tool_surface_profile != BROWSER_FULL_PROFILE
        || profile.is_some_and(|profile| profile != BROWSER_FULL_PROFILE)
    {
        return Err((
            FailureCode::CapabilityDenied,
            "SG-000135 browser_full shapes reach a remote caller only under the remote browser_full profile",
        ));
    }
    if !names(REMOTE_BROWSER_FULL_SHAPES, request) {
        return Err((
            FailureCode::CapabilityDenied,
            "SG-000135 OB-09: persistent Orcel-managed browser profiles are local-only",
        ));
    }
    if request.operation == "create"
        && request
            .arguments
            .get("profile")
            .is_some_and(|profile| !profile.is_null())
    {
        return Err((
            FailureCode::CapabilityDenied,
            "SG-000135 OB-09: persistent Orcel-managed browser profiles are local-only; a remote caller gets an ephemeral session",
        ));
    }
    Ok(())
}

fn gate_shapes(
    shapes: &[(&str, &str)],
    request: &RequestEnvelope,
    profile: Option<&str>,
    remote: Option<&RemoteContext>,
) -> Result<(), (FailureCode, &'static str)> {
    if !names(shapes, request) {
        return Ok(());
    }
    if remote.is_some() {
        return Err((
            FailureCode::CapabilityDenied,
            "SG-000108 live browser shapes are local-only; remote browser mapping is disabled",
        ));
    }
    if profile != Some(BROWSER_STRUCTURED_PROFILE) {
        return Err((
            FailureCode::CapabilityDenied,
            "SG-000108 live browser shapes require the browser_structured profile, selected by local configuration",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_contracts::INTERNAL_PROTOCOL_VERSION;
    use serde_json::json;

    fn request(capability: &str, operation: &str) -> RequestEnvelope {
        RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "r".into(),
            client_session_id: "s".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: None,
            arguments: json!({}),
        }
    }

    fn remote() -> RemoteContext {
        RemoteContext {
            principal: "p".into(),
            remote_connection_id: "rc".into(),
            connection_id: "c".into(),
            device_id: "d".into(),
            device_epoch: 1,
            provider_kind: "generic".into(),
            client_profile_id: "cp".into(),
            client_profile_revision: 1,
            tool_surface_profile: "core".into(),
            scopes: Vec::new(),
        }
    }

    const SHAPES: &[(&str, &str)] = &[("browser.navigation", "navigate")];

    #[test]
    fn a_live_shape_needs_a_local_browser_structured_request() {
        let live = request("browser.navigation", "navigate");
        assert_eq!(
            gate_shapes(SHAPES, &live, Some(BROWSER_STRUCTURED_PROFILE), None),
            Ok(())
        );
        for profile in [None, Some("desktop_structured"), Some("core"), Some("")] {
            let refused = gate_shapes(SHAPES, &live, profile, None).unwrap_err();
            assert_eq!(refused.0, FailureCode::CapabilityDenied, "{profile:?}");
        }
        // Remote never reaches a live shape, whatever profile it names.
        let remote = remote();
        let refused = gate_shapes(
            SHAPES,
            &live,
            Some(BROWSER_STRUCTURED_PROFILE),
            Some(&remote),
        )
        .unwrap_err();
        assert_eq!(refused.0, FailureCode::CapabilityDenied);
        assert!(refused.1.contains("local-only"));
    }

    #[test]
    fn other_shapes_pass_whatever_the_profile_names() {
        let other = request("fs.read", "read");
        for profile in [None, Some(BROWSER_STRUCTURED_PROFILE), Some("anything")] {
            assert_eq!(gate_shapes(SHAPES, &other, profile, None), Ok(()));
        }
    }

    /// Slice 3c's six and SG-000122's six (slices A3 and A4): exactly the
    /// live shapes, each with an MCP tool, and the real table gates them.
    #[test]
    fn the_live_mcp_shapes_are_gated() {
        assert_eq!(LIVE_BROWSER_SHAPES.len(), 12);
        for (capability, operation) in LIVE_BROWSER_SHAPES {
            let live = request(capability, operation);
            assert!(is_live_shape(&live));
            assert!(gate(&live, None, None).is_err(), "{capability}/{operation}");
            assert_eq!(gate(&live, Some(BROWSER_STRUCTURED_PROFILE), None), Ok(()));
        }
        // The uploads stay model-only (decision 4, as SG-000122 amends it),
        // and so do the closed-grain press and select.
        for (capability, operation) in [
            ("browser.upload", "preview"),
            ("browser.upload", "submit"),
            ("browser.dom", "press"),
            ("browser.dom", "select"),
        ] {
            let model = request(capability, operation);
            assert!(!is_live_shape(&model));
            assert_eq!(gate(&model, None, None), Ok(()));
        }
    }

    /// SG-000135 OB-02: the broker shapes need a local `browser_full`
    /// request; the two browser profiles never reach each other's shapes;
    /// no remote request reaches either.
    #[test]
    fn ob02_browser_full_shapes_need_a_local_browser_full_request() {
        assert_eq!(BROWSER_FULL_SHAPES.len(), 15);
        let remote = remote();
        for (capability, operation) in BROWSER_FULL_SHAPES {
            let full = request(capability, operation);
            assert!(is_browser_full_shape(&full));
            assert!(!is_live_shape(&full), "{capability}/{operation}");
            assert_eq!(gate(&full, Some(BROWSER_FULL_PROFILE), None), Ok(()));
            for profile in [
                None,
                Some(BROWSER_STRUCTURED_PROFILE),
                Some("desktop_structured"),
                Some("core"),
                Some("Browser_Full"),
                Some(""),
            ] {
                let refused = gate(&full, profile, None).unwrap_err();
                assert_eq!(refused.0, FailureCode::CapabilityDenied, "{profile:?}");
                assert!(refused.1.contains("browser_full profile"));
            }
            // SG-000135 OB-09: a remote caller under the core profile never
            // reaches a broker shape (only the remote browser_full profile
            // does; see the OB-09 tests).
            let refused = gate(&full, Some(BROWSER_FULL_PROFILE), Some(&remote)).unwrap_err();
            assert_eq!(refused.0, FailureCode::CapabilityDenied);
            assert!(refused.1.contains("remote browser_full profile"));
            // A broker shape is never one of the denied model-only shapes.
            assert!(
                !orcel_provider_browser::DENIED_BROWSER_SHAPES.contains(&(*capability, *operation))
            );
        }
        // browser_structured's live shapes stay out of browser_full.
        for (capability, operation) in LIVE_BROWSER_SHAPES {
            let live = request(capability, operation);
            assert!(!is_browser_full_shape(&live));
            assert!(gate(&live, Some(BROWSER_FULL_PROFILE), None).is_err());
        }
        // Distinct, and W2-03's outline and extract_schema have no shape.
        let unique: std::collections::HashSet<_> = BROWSER_FULL_SHAPES.iter().collect();
        assert_eq!(unique.len(), BROWSER_FULL_SHAPES.len());
        for (capability, operation) in [
            ("browser.session", "outline"),
            ("browser.session", "extract_schema"),
            ("browser.page", "outline"),
            ("browser.session", "evaluate"),
        ] {
            assert!(!is_browser_full_shape(&request(capability, operation)));
        }
    }

    /// SG-000122: the form shapes are live and gated like the six: local
    /// `browser_structured` only, never remote. Since slice A4 every one of
    /// the policy's live form shapes is in the MCP table, exactly once, and
    /// the rest of that table is slice 3c's six; no name collides with a
    /// closed-grain denial.
    #[test]
    fn sg122_the_form_shapes_are_gated_like_the_six() {
        let policy = orcel_policy::live_browser::LIVE_FORM_SHAPES;
        assert_eq!(policy.len(), 6);
        assert_eq!(SG122_MCP_SHAPES.len(), policy.len());
        for shape in policy {
            assert!(SG122_MCP_SHAPES.contains(shape), "{shape:?}");
            let in_table = LIVE_BROWSER_SHAPES.iter().filter(|s| *s == shape).count();
            assert_eq!(in_table, 1, "{shape:?} is in the MCP table exactly once");
        }
        for shape in SG122_MCP_SHAPES {
            assert!(policy.contains(shape), "{shape:?} is a policy live form");
        }
        assert_eq!(
            LIVE_BROWSER_SHAPES
                .iter()
                .filter(|shape| !policy.contains(shape))
                .count(),
            6,
            "slice 3c's six"
        );
        // Fill, select, check and Enter each need a fresh SOFT approval;
        // the wait and the verifier none.
        for (capability, operation) in SG122_MCP_SHAPES {
            let class = orcel_policy::live_browser::live_approval_class(capability, operation);
            let read_only = matches!(*capability, "browser.wait" | "browser.verify");
            let expected = (!read_only).then_some(orcel_policy::ApprovalClass::Soft);
            assert_eq!(class, Some(expected), "{capability}/{operation}");
        }
        let remote = remote();
        for (capability, operation) in policy {
            let live = request(capability, operation);
            assert!(is_live_shape(&live));
            assert!(
                !orcel_provider_browser::DENIED_BROWSER_SHAPES.contains(&(*capability, *operation)),
                "{capability}/{operation}"
            );
            for profile in [None, Some("desktop_structured"), Some("core")] {
                let refused = gate(&live, profile, None).unwrap_err();
                assert_eq!(refused.0, FailureCode::CapabilityDenied, "{profile:?}");
            }
            let refused = gate(&live, Some(BROWSER_STRUCTURED_PROFILE), Some(&remote)).unwrap_err();
            assert!(refused.1.contains("local-only"));
            assert_eq!(gate(&live, Some(BROWSER_STRUCTURED_PROFILE), None), Ok(()));
        }
    }

    fn browser_remote() -> RemoteContext {
        RemoteContext {
            tool_surface_profile: BROWSER_FULL_PROFILE.into(),
            ..remote()
        }
    }

    /// SG-000135 OB-09: a remote caller reaches exactly the remote-safe
    /// broker shapes, and only under the remote browser_full profile; the
    /// remote-session lease is checked after this gate.
    #[test]
    fn ob09_remote_browser_full_reaches_only_the_remote_safe_shapes() {
        assert_eq!(REMOTE_BROWSER_FULL_SHAPES.len(), 12);
        let browser = browser_remote();
        for (capability, operation) in BROWSER_FULL_SHAPES {
            let full = request(capability, operation);
            let remote_safe = REMOTE_BROWSER_FULL_SHAPES.contains(&(*capability, *operation));
            // Every remote-safe shape has a remote scope; the rest none.
            assert_eq!(
                orcel_policy::remote_session::required_browser_full_scopes(capability, operation)
                    .is_some(),
                remote_safe,
                "{capability}/{operation}"
            );
            for profile in [None, Some(BROWSER_FULL_PROFILE)] {
                let gated = gate(&full, profile, Some(&browser));
                if remote_safe {
                    assert_eq!(gated, Ok(()), "{capability}/{operation}");
                } else {
                    let refused = gated.unwrap_err();
                    assert_eq!(refused.0, FailureCode::CapabilityDenied);
                    assert!(refused.1.contains("local-only"), "{}", refused.1);
                }
            }
            // A request profile naming another profile is refused.
            for profile in [Some(BROWSER_STRUCTURED_PROFILE), Some("core"), Some("")] {
                assert!(gate(&full, profile, Some(&browser)).is_err());
            }
            // Any other remote profile is refused.
            for profile in ["core", "browser_structured", "desktop_structured", ""] {
                let other = RemoteContext {
                    tool_surface_profile: profile.into(),
                    ..remote()
                };
                let refused = gate(&full, None, Some(&other)).unwrap_err();
                assert_eq!(refused.0, FailureCode::CapabilityDenied, "{profile}");
            }
        }
        for (capability, operation) in REMOTE_BROWSER_FULL_SHAPES {
            assert!(BROWSER_FULL_SHAPES.contains(&(*capability, *operation)));
        }
        // browser_structured's live shapes stay local-only, whatever the
        // remote profile.
        for (capability, operation) in LIVE_BROWSER_SHAPES {
            let live = request(capability, operation);
            for profile in [
                None,
                Some(BROWSER_STRUCTURED_PROFILE),
                Some(BROWSER_FULL_PROFILE),
            ] {
                let refused = gate(&live, profile, Some(&browser)).unwrap_err();
                assert!(refused.1.contains("local-only"));
            }
        }
    }

    #[test]
    fn ob09_a_remote_session_never_names_a_persistent_profile() {
        let browser = browser_remote();
        let mut named = request("browser.session", "create");
        named.arguments = json!({"profile": "work"});
        let refused = gate(&named, None, Some(&browser)).unwrap_err();
        assert_eq!(refused.0, FailureCode::CapabilityDenied);
        assert!(refused.1.contains("ephemeral"));
        // Locally the same request passes the gate (OB-04 asks the owner).
        assert_eq!(gate(&named, Some(BROWSER_FULL_PROFILE), None), Ok(()));
        let mut ephemeral = request("browser.session", "create");
        ephemeral.arguments = json!({"task": "Book a table", "mode": "visible"});
        assert_eq!(gate(&ephemeral, None, Some(&browser)), Ok(()));
    }

    /// SG-000135 OB-09: local behaviour is unchanged, except that a local
    /// MCP session id may not pose as a remote caller's broker client.
    #[test]
    fn ob09_local_browser_full_is_unchanged() {
        for (capability, operation) in BROWSER_FULL_SHAPES {
            let full = request(capability, operation);
            assert_eq!(gate(&full, Some(BROWSER_FULL_PROFILE), None), Ok(()));
            let mut posing = request(capability, operation);
            posing.client_session_id =
                format!("{}rc-x:rp-y:s", crate::browser_remote::REMOTE_CLIENT_PREFIX);
            let refused = gate(&posing, Some(BROWSER_FULL_PROFILE), None).unwrap_err();
            assert_eq!(refused.0, FailureCode::InvalidRequest);
        }
    }
}
