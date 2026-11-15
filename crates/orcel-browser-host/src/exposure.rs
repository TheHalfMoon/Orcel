//! SG-000079 explicit browser tool exposure contract.
//!
//! The explicit `browser_structured` profile names the maximum admissible
//! set: exactly the twelve already-qualified closed-registry browser
//! shapes, nothing more. SG-000108 slice 3c makes six of them live MCP
//! tools under that profile only (decision 4: navigate, observe, link
//! activation and staged download, with the page and the download preview
//! they need); the uploads stay model-only. SG-000122 slice A3 adds three
//! live tools under the same profile: fill (`browser.dom/fill`, promoted by
//! the SG-000108 decision 4 amendment), the text wait and the verifier
//! (`browser.wait/text` and `browser.verify/check`, admitted beside the
//! twelve by the A13 amendment, `SG122_ADMITTED_SHAPES`). SG-000122 slice
//! A4 adds the last three, admitted the same way: select, check and Enter
//! (`browser.form/select`, `/check` and `/enter`). Existing
//! profiles are not widened, remote browser mapping stays disabled, and the
//! denied set (evaluation, arbitrary JavaScript, generic CDP, personal
//! profiles, raw process control, generic filesystem authority) stays
//! unreachable. Discovery, documentation, profile tables, OAuth scope
//! tables, and runtime agree mechanically on the same live set
//! (`apps/orcel-mcp/src/browser-exposure.test.ts`).

use crate::error::HostError;

/// The explicit live browser profile. No caller reaches it implicitly.
pub const BROWSER_STRUCTURED_PROFILE: &str = "browser_structured";

/// Profiles that existed before this grain. Neither may gain browser
/// shapes implicitly through this grain.
pub const PREEXISTING_PROFILES: &[&str] = &["core", "desktop_structured"];

/// Maximum admissible set: exactly the twelve already-qualified
/// closed-registry browser shapes. Admission here is not exposure: the
/// live set below is what MCP callers can actually reach.
pub const QUALIFIED_BROWSER_SHAPES: &[(&str, &str)] = &[
    ("browser.profile", "status"),
    ("browser.destination", "validate"),
    ("browser.page", "open"),
    ("browser.navigation", "preview"),
    ("browser.navigation", "navigate"),
    ("browser.snapshot", "observe"),
    ("browser.dom", "click"),
    ("browser.dom", "fill"),
    ("browser.download", "preview"),
    ("browser.download", "download"),
    ("browser.upload", "preview"),
    ("browser.upload", "submit"),
];

/// Shapes that must never appear under any profile.
pub const DENIED_BROWSER_SHAPES: &[&str] = &[
    "browser_evaluate",
    "browser.evaluate",
    "browser.script",
    "browser.cdp",
    "browser.devtools",
    "browser.profile.use_personal",
    "browser.profile.attach",
    "browser.process.launch",
    "browser.process.attach",
    "browser.fs.read",
    "browser.fs.list",
    "browser.remote.map",
];

/// SG-000122 (the amendment of SG-000108 A13): the form-grain shapes
/// admitted beside the twelve. Admission is not exposure: slice A3 exposes
/// the text wait and the verifier, and slice A4 select, check and Enter.
/// Every one stays local-only, development builds only, Windows only.
pub const SG122_ADMITTED_SHAPES: &[(&str, &str)] = &[
    ("browser.form", "select"),
    ("browser.form", "check"),
    ("browser.form", "enter"),
    ("browser.wait", "text"),
    ("browser.verify", "check"),
];

/// Live MCP tools (SG-000108 slice 3c's six, SG-000122 slice A3's three
/// and slice A4's three), served only under `browser_structured` and
/// reaching a real host only in `live-browser-dev` builds on Windows. The
/// host's own worker-mode vocabulary stays a private piped channel, not an
/// MCP surface.
pub const LIVE_BROWSER_MCP_TOOLS: &[&str] = &[
    "browser_page_open",
    "browser_navigate",
    "browser_observe",
    "browser_click",
    "browser_download_preview",
    "browser_download",
    "browser_fill",
    "browser_wait_text",
    "browser_verify",
    "browser_select",
    "browser_check",
    "browser_enter",
];

/// The shape each live tool forwards (tool, capability, operation).
pub const LIVE_BROWSER_TOOL_SHAPES: &[(&str, &str, &str)] = &[
    ("browser_page_open", "browser.page", "open"),
    ("browser_navigate", "browser.navigation", "navigate"),
    ("browser_observe", "browser.snapshot", "observe"),
    ("browser_click", "browser.dom", "click"),
    ("browser_download_preview", "browser.download", "preview"),
    ("browser_download", "browser.download", "download"),
    ("browser_fill", "browser.dom", "fill"),
    ("browser_wait_text", "browser.wait", "text"),
    ("browser_verify", "browser.verify", "check"),
    ("browser_select", "browser.form", "select"),
    ("browser_check", "browser.form", "check"),
    ("browser_enter", "browser.form", "enter"),
];

/// Whether a capability and operation pair is within the maximum
/// admissible set. Admission is necessary but not sufficient for live
/// exposure.
pub fn is_qualified_shape(capability: &str, operation: &str) -> bool {
    QUALIFIED_BROWSER_SHAPES
        .iter()
        .any(|(cap, op)| *cap == capability && *op == operation)
}

/// Whether a shape may be live: one of the twelve, or one SG-000122
/// admitted beside them.
pub fn is_admissible_live_shape(capability: &str, operation: &str) -> bool {
    is_qualified_shape(capability, operation)
        || SG122_ADMITTED_SHAPES
            .iter()
            .any(|(cap, op)| *cap == capability && *op == operation)
}

/// Whether a tool name is denied under every profile.
pub fn is_denied_shape(tool: &str) -> bool {
    DENIED_BROWSER_SHAPES.contains(&tool)
}

/// Whether a tool name is live-reachable through MCP (under
/// `browser_structured` only).
pub fn is_live_exposed(tool: &str) -> bool {
    LIVE_BROWSER_MCP_TOOLS.contains(&tool)
}

/// Remote browser mapping stays disabled in this grain.
pub fn remote_browser_mapping_enabled() -> bool {
    false
}

/// Resolve the tool set for a profile name. Unknown profiles, including
/// future ones, fail closed instead of inheriting a default set.
pub fn profile_tools(profile: &str) -> Result<&'static [&'static str], HostError> {
    if profile == BROWSER_STRUCTURED_PROFILE {
        return Ok(LIVE_BROWSER_MCP_TOOLS);
    }
    Err(HostError::Invalid(
        "tool surface profile is not mapped for live browser".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn qualified_set_is_exactly_twelve_closed_shapes() {
        assert_eq!(QUALIFIED_BROWSER_SHAPES.len(), 12);
        let unique: HashSet<(&str, &str)> = QUALIFIED_BROWSER_SHAPES.iter().copied().collect();
        assert_eq!(unique.len(), 12);
        assert!(is_qualified_shape("browser.snapshot", "observe"));
        assert!(is_qualified_shape("browser.dom", "click"));
        assert!(!is_qualified_shape("browser.dom", "evaluate"));
        assert!(!is_qualified_shape("browser.cdp", "command"));
    }

    #[test]
    fn the_live_set_is_twelve_admissible_shapes_and_denied_shapes_stay_absent() {
        assert_eq!(LIVE_BROWSER_MCP_TOOLS.len(), 12);
        let tools: Vec<&str> = LIVE_BROWSER_TOOL_SHAPES
            .iter()
            .map(|(t, _, _)| *t)
            .collect();
        assert_eq!(tools, LIVE_BROWSER_MCP_TOOLS);
        for (tool, capability, operation) in LIVE_BROWSER_TOOL_SHAPES {
            assert!(is_live_exposed(tool));
            assert!(is_admissible_live_shape(capability, operation), "{tool}");
        }
        // Slice 3c's six are qualified shapes; of SG-000122's, fill is one
        // of the twelve, and the wait, the verifier (A3), select, check and
        // Enter (A4) are admitted beside.
        for (tool, capability, operation) in &LIVE_BROWSER_TOOL_SHAPES[..7] {
            assert!(is_qualified_shape(capability, operation), "{tool}");
        }
        for (tool, capability, operation) in &LIVE_BROWSER_TOOL_SHAPES[7..] {
            assert!(!is_qualified_shape(capability, operation), "{tool}");
            assert!(SG122_ADMITTED_SHAPES.contains(&(*capability, *operation)));
        }
        // Every admitted shape now has exactly one tool.
        for (capability, operation) in SG122_ADMITTED_SHAPES {
            assert_eq!(
                LIVE_BROWSER_TOOL_SHAPES
                    .iter()
                    .filter(|(_, c, o)| c == capability && o == operation)
                    .count(),
                1,
                "{capability}/{operation}"
            );
        }
        // The uploads stay model-only (decision 4), and the closed-grain
        // press and select keep no tool.
        for (capability, operation) in [
            ("browser.upload", "preview"),
            ("browser.upload", "submit"),
            ("browser.dom", "press"),
            ("browser.dom", "select"),
        ] {
            assert!(!LIVE_BROWSER_TOOL_SHAPES
                .iter()
                .any(|(_, c, o)| *c == capability && *o == operation));
        }
        for denied in DENIED_BROWSER_SHAPES {
            assert!(!is_live_exposed(denied), "{denied}");
        }
        for (capability, operation) in QUALIFIED_BROWSER_SHAPES {
            let tool = format!("{capability}/{operation}");
            assert!(!is_live_exposed(&tool), "{tool}");
        }
        assert!(!is_live_exposed("browser_evaluate"));
        // SG-000122's admitted shapes are new names, none of the twelve.
        for (capability, operation) in SG122_ADMITTED_SHAPES {
            assert!(!is_qualified_shape(capability, operation));
        }
    }

    #[test]
    fn preexisting_profiles_gain_no_browser_shapes() {
        assert_eq!(PREEXISTING_PROFILES, &["core", "desktop_structured"]);
        assert!(!PREEXISTING_PROFILES.contains(&BROWSER_STRUCTURED_PROFILE));
    }

    #[test]
    fn remote_mapping_stays_disabled_and_unknown_profiles_fail_closed() {
        assert!(!remote_browser_mapping_enabled());
        assert_eq!(
            profile_tools(BROWSER_STRUCTURED_PROFILE).unwrap(),
            LIVE_BROWSER_MCP_TOOLS
        );
        assert!(profile_tools("core").is_err());
        assert!(profile_tools("browser_evaluate").is_err());
        assert!(profile_tools("").is_err());
    }
}
