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

use orcel_contracts::{FailureCode, RemoteContext, RequestEnvelope};

/// The profile that alone may reach a live browser shape.
pub const BROWSER_STRUCTURED_PROFILE: &str = "browser_structured";

/// The live browser shapes (capability, operation): slice 3c's six, each
/// one of SG-000079's qualified browser shapes. `browser.dom/fill` and the
/// uploads stay model-only (decision 4).
pub const LIVE_BROWSER_SHAPES: &[(&str, &str)] = &[
    ("browser.page", "open"),
    ("browser.navigation", "navigate"),
    ("browser.snapshot", "observe"),
    ("browser.dom", "click"),
    ("browser.download", "preview"),
    ("browser.download", "download"),
];

/// Whether a request names one of the live browser shapes.
pub fn is_live_shape(request: &RequestEnvelope) -> bool {
    LIVE_BROWSER_SHAPES.iter().any(|(capability, operation)| {
        *capability == request.capability && *operation == request.operation
    })
}

/// Refuse a live browser shape unless the request is local and names the
/// `browser_structured` profile. Every other shape passes unchanged: the
/// profile field grants nothing by itself.
pub fn gate(
    request: &RequestEnvelope,
    profile: Option<&str>,
    remote: Option<&RemoteContext>,
) -> Result<(), (FailureCode, &'static str)> {
    gate_shapes(LIVE_BROWSER_SHAPES, request, profile, remote)
}

fn gate_shapes(
    shapes: &[(&str, &str)],
    request: &RequestEnvelope,
    profile: Option<&str>,
    remote: Option<&RemoteContext>,
) -> Result<(), (FailureCode, &'static str)> {
    let live = shapes.iter().any(|(capability, operation)| {
        *capability == request.capability && *operation == request.operation
    });
    if !live {
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

    /// Slice 3c: exactly the six live shapes, and the real table gates them.
    #[test]
    fn the_six_live_shapes_are_gated() {
        assert_eq!(LIVE_BROWSER_SHAPES.len(), 6);
        for (capability, operation) in LIVE_BROWSER_SHAPES {
            let live = request(capability, operation);
            assert!(is_live_shape(&live));
            assert!(gate(&live, None, None).is_err(), "{capability}/{operation}");
            assert_eq!(gate(&live, Some(BROWSER_STRUCTURED_PROFILE), None), Ok(()));
        }
        // Fill and the uploads stay model-only (decision 4).
        for (capability, operation) in [
            ("browser.dom", "fill"),
            ("browser.upload", "preview"),
            ("browser.upload", "submit"),
        ] {
            let model = request(capability, operation);
            assert!(!is_live_shape(&model));
            assert_eq!(gate(&model, None, None), Ok(()));
        }
    }
}
