// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! The allowlisted adapter over the vendored Cua Driver tools (XP-06).
//!
//! [`CuaCall`] is the whole surface: five read-only tools and, since XP-11,
//! one semantic action tool. Each variant
//! holds the typed `cua-driver-contract` input, validated before dispatch,
//! and its tool name is that input's `TOOL_NAME` constant. Nothing in a
//! request names a tool, so no other Cua tool (click, type_text, launch_app,
//! clipboard writes, ...) can be reached from the protocol.
//!
//! The semantic action tool is `orcel_semantic_action`, added to the vendored
//! crates by patch P-09. It is not one of Cua's tools: upstream's `click`,
//! `set_value` and `scroll` fall back to pointer events, key events, Apple
//! Events and menu-opening when the accessibility route fails, and the host
//! must never reach those. The P-09 tool calls only Cua's accessibility
//! primitives (AX actions and AXValue writes on macOS, AT-SPI `doAction` and
//! `setValue` on Linux) on the exact element a fresh `get_window_state`
//! snapshot of the same process resolved, and has no other route.
//!
//! The registry is built the way Cua's own embedders build it, with
//! `cursor_overlay_available = false` and `host_owns_permission_ux = true`
//! on macOS (patch P-04 forces the latter anyway). The adapter never holds a
//! `ToolState`, so it cannot overwrite either field after construction.
//!
//! XP-07 adds one entry outside the registry: [`CuaRuntime::capture_window`],
//! Cua's own window capture for one window id (patch P-08: in process, no
//! pointer, no subprocess). No capture tool is registered, so Cua's display,
//! region and Wayland output captures stay unreachable; the worker applies
//! the scope, protected-surface, exposure and size rules of `capture.rs`
//! around the call.

use crate::protocol::MAX_TEXT_BYTES;
use crate::semantic::Verb;
use cua_driver_contract::{
    GetCursorPositionInput, GetScreenSizeInput, GetWindowStateInput, ListWindowsInput, ToolInput,
};
use serde_json::Value;

/// Tool name of the permission probe. It has no contract input type; its
/// only argument is `prompt`, which the host always sends as `false`.
pub const CHECK_PERMISSIONS: &str = "check_permissions";

/// The tool names the vendored registry keeps after construction (patch
/// P-07): exactly the tools [`CuaCall`] names. Every other tool the platform
/// registers is dropped, so even a name that bypassed the enum is unknown.
pub const ALLOWED_TOOLS: [&str; 6] = [
    ListWindowsInput::TOOL_NAME,
    GetWindowStateInput::TOOL_NAME,
    GetCursorPositionInput::TOOL_NAME,
    GetScreenSizeInput::TOOL_NAME,
    CHECK_PERMISSIONS,
    SEMANTIC_ACTION_TOOL,
];

/// Tool name of the P-09 accessibility-only action tool.
pub const SEMANTIC_ACTION_TOOL: &str = "orcel_semantic_action";

/// Longest `element_token` the host sends (`s` + 8 hex digits + `:` + index).
const MAX_TOKEN_BYTES: usize = 40;

/// One accessibility action on one element of a fresh snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticCall {
    pub pid: u32,
    pub window_id: u64,
    /// The token the fresh `get_window_state` of this very process minted
    /// for the element the runtime id located.
    pub element_token: String,
    pub verb: Verb,
    /// The role Cua listed for that element a moment ago; the tool refuses
    /// when the live element's role differs.
    pub expect_role: String,
    pub value: Option<String>,
    /// The state a toggle asks for. The tool reads the live state first and
    /// refuses as stale when the element is already there.
    pub toggle_to: Option<bool>,
}

/// The only Cua tools the host calls.
#[derive(Debug, Clone, PartialEq)]
pub enum CuaCall {
    ListWindows(ListWindowsInput),
    GetWindowState(GetWindowStateInput),
    GetCursorPosition(GetCursorPositionInput),
    GetScreenSize(GetScreenSizeInput),
    /// macOS only: TCC state, read without prompting.
    CheckPermissions,
    /// XP-11: one accessibility action (patch P-09).
    SemanticAction(SemanticCall),
}

impl CuaCall {
    pub fn tool_name(&self) -> &'static str {
        match self {
            Self::ListWindows(_) => ListWindowsInput::TOOL_NAME,
            Self::GetWindowState(_) => GetWindowStateInput::TOOL_NAME,
            Self::GetCursorPosition(_) => GetCursorPositionInput::TOOL_NAME,
            Self::GetScreenSize(_) => GetScreenSizeInput::TOOL_NAME,
            Self::CheckPermissions => CHECK_PERMISSIONS,
            Self::SemanticAction(_) => SEMANTIC_ACTION_TOOL,
        }
    }

    /// The validated argument object.
    pub fn arguments(&self) -> Result<Value, CuaFailure> {
        fn typed<T: ToolInput>(input: &T) -> Result<Value, CuaFailure> {
            input.validate().map_err(CuaFailure::invalid)?;
            serde_json::to_value(input).map_err(|error| CuaFailure::invalid(error.to_string()))
        }
        match self {
            Self::ListWindows(input) => typed(input),
            Self::GetWindowState(input) => typed(input),
            Self::GetCursorPosition(input) => typed(input),
            Self::GetScreenSize(input) => typed(input),
            Self::CheckPermissions => Ok(serde_json::json!({ "prompt": false })),
            Self::SemanticAction(call) => call.arguments(),
        }
    }

    /// The tree-only observation of one exact window: no screenshot (window
    /// capture is XP-07), the structured element list, bounded walk.
    pub fn observe(pid: u32, window_id: u64, max_elements: u32, max_depth: u32) -> Self {
        Self::GetWindowState(GetWindowStateInput {
            pid,
            window_id,
            session: None,
            query: None,
            include_accessibility_tree: Some(true),
            include_screenshot: Some(false),
            screenshot_out_file: None,
            max_elements: Some(max_elements.max(1)),
            max_depth: Some(max_depth.max(1)),
            max_dimension: None,
            max_image_dimension: None,
            timeout_ms: Some(OBSERVE_WALK_TIMEOUT_MS),
            tree_format: Some("elements".to_owned()),
            since: None,
            verbose: None,
            full_output: None,
        })
    }

    pub fn list_windows(pid: Option<u32>) -> Self {
        Self::ListWindows(ListWindowsInput {
            pid,
            on_screen_only: None,
        })
    }
}

impl SemanticCall {
    /// The validated argument object: an exact window, an element token, a
    /// verb and, for `set_value`, the text. There is no coordinate, key,
    /// button, count, modifier or delivery-mode field to send.
    pub fn arguments(&self) -> Result<Value, CuaFailure> {
        if self.pid == 0 || self.window_id == 0 {
            return Err(CuaFailure::invalid(
                "a semantic action needs an exact window",
            ));
        }
        if self.element_token.is_empty()
            || self.element_token.len() > MAX_TOKEN_BYTES
            || !self.element_token.starts_with('s')
            || !self.element_token.contains(':')
        {
            return Err(CuaFailure::invalid("the element token is malformed"));
        }
        if self.expect_role.is_empty() || self.expect_role.len() > 128 {
            return Err(CuaFailure::invalid(
                "the element role is missing or too long",
            ));
        }
        let mut arguments = serde_json::json!({
            "pid": self.pid,
            "window_id": self.window_id,
            "element_token": self.element_token,
            "verb": self.verb.as_str(),
            "expect_role": self.expect_role,
        });
        match (self.verb, self.toggle_to) {
            (Verb::Toggle, Some(wanted)) => arguments["toggle_to"] = Value::Bool(wanted),
            (Verb::Toggle, None) => {
                return Err(CuaFailure::invalid("toggle needs the state it asks for"))
            }
            (_, None) => {}
            (_, Some(_)) => return Err(CuaFailure::invalid("only toggle takes toggle_to")),
        }
        match (self.verb, &self.value) {
            (Verb::SetValue, Some(value)) if value.len() <= MAX_TEXT_BYTES => {
                arguments["value"] = Value::String(value.clone());
            }
            (Verb::SetValue, _) => {
                return Err(CuaFailure::invalid("set_value needs a bounded value"));
            }
            (_, None) => {}
            (_, Some(_)) => return Err(CuaFailure::invalid("only set_value carries a value")),
        }
        Ok(arguments)
    }
}

/// The AX/AT-SPI walk budget, inside the worker's 8 s deadline.
pub const OBSERVE_WALK_TIMEOUT_MS: u32 = 5000;

/// A Cua tool refusal or an argument the contract rejected.
#[derive(Debug, Clone, PartialEq)]
pub struct CuaFailure {
    pub message: String,
    pub structured: Option<Value>,
}

impl CuaFailure {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            structured: None,
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod imp {
    use super::{CuaCall, CuaFailure};
    use cua_driver_core::protocol::{Content, ToolResult};
    use cua_driver_core::tool::ToolRegistry;
    use serde_json::Value;

    /// The vendored registry. Only [`CuaCall`] reaches it.
    pub struct CuaRuntime {
        registry: ToolRegistry,
    }

    impl CuaRuntime {
        pub fn new() -> Self {
            #[cfg(target_os = "macos")]
            let registry = {
                let mut registry = ToolRegistry::new();
                // compat = false, cursor_overlay_available = false,
                // host_owns_permission_ux = true, no host bundle id.
                platform_macos::tools::register_all(&mut registry, false, false, true, None);
                registry
            };
            #[cfg(target_os = "linux")]
            let mut registry = platform_linux::tools::build_registry(false);
            #[cfg(target_os = "macos")]
            let mut registry = registry;
            registry.retain_tools(&super::ALLOWED_TOOLS);
            Self { registry }
        }

        pub async fn call(&self, call: &CuaCall) -> Result<Value, CuaFailure> {
            let arguments = call.arguments()?;
            let result = self.registry.invoke(call.tool_name(), arguments).await;
            settle(result)
        }

        /// The PNG of exactly one window, from Cua's capture module:
        /// ScreenCaptureKit's desktop-independent window filter on macOS,
        /// MIT-SHM or `XGetImage` of the X11 window on Linux (P-08).
        pub fn capture_window(&self, window_id: u64) -> Result<Vec<u8>, CuaFailure> {
            fn failed(error: impl std::fmt::Display) -> CuaFailure {
                CuaFailure {
                    message: format!("{error:#}"),
                    structured: None,
                }
            }
            #[cfg(target_os = "macos")]
            let png = {
                let window_id = u32::try_from(window_id)
                    .map_err(|_| CuaFailure::invalid("window id is not a CGWindowID"))?;
                platform_macos::capture::screenshot_window_bytes(window_id).map_err(failed)?
            };
            #[cfg(target_os = "linux")]
            let png =
                platform_linux::capture::screenshot_window_bytes(window_id).map_err(failed)?;
            Ok(png)
        }

        /// Test-only raw dispatch, to show what the registered tools do
        /// with arguments the adapter itself never sends.
        #[cfg(test)]
        pub async fn invoke_for_test(
            &self,
            name: &str,
            arguments: Value,
        ) -> Result<Value, CuaFailure> {
            settle(self.registry.invoke(name, arguments).await)
        }

        /// The names the vendored registry holds, for the reachability test.
        #[cfg(test)]
        pub fn registered_tools(&self) -> Vec<String> {
            self.registry.tool_names().map(str::to_owned).collect()
        }
    }

    fn settle(result: ToolResult) -> Result<Value, CuaFailure> {
        let message = result
            .content
            .iter()
            .filter_map(|content| match content {
                Content::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        if result.is_error == Some(true) {
            return Err(CuaFailure {
                message,
                structured: result.structured_content,
            });
        }
        result.structured_content.ok_or(CuaFailure {
            message: "the Cua tool returned no structured result".to_owned(),
            structured: None,
        })
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod imp {
    use super::{CuaCall, CuaFailure};
    use serde_json::Value;

    /// No Cua platform backend exists for this OS; every call fails closed.
    pub struct CuaRuntime;

    impl CuaRuntime {
        pub fn new() -> Self {
            Self
        }

        pub async fn call(&self, call: &CuaCall) -> Result<Value, CuaFailure> {
            call.arguments()?;
            Err(CuaFailure {
                message: format!(
                    "no Cua platform backend on this OS for {}",
                    call.tool_name()
                ),
                structured: None,
            })
        }

        pub fn capture_window(&self, _window_id: u64) -> Result<Vec<u8>, CuaFailure> {
            Err(CuaFailure {
                message: "no Cua platform backend on this OS for window capture".to_owned(),
                structured: None,
            })
        }
    }
}

pub use imp::CuaRuntime;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_call_names_an_allowlisted_tool_from_its_typed_input() {
        let calls = [
            CuaCall::list_windows(None),
            CuaCall::observe(10, 20, 256, 8),
            CuaCall::GetCursorPosition(GetCursorPositionInput::default()),
            CuaCall::GetScreenSize(GetScreenSizeInput { session: None }),
            CuaCall::CheckPermissions,
            CuaCall::SemanticAction(semantic_call(Verb::Invoke, None)),
        ];
        let names: Vec<_> = calls.iter().map(CuaCall::tool_name).collect();
        assert_eq!(
            names,
            vec![
                "list_windows",
                "get_window_state",
                "get_cursor_position",
                "get_screen_size",
                "check_permissions",
                "orcel_semantic_action"
            ]
        );
        assert_eq!(names, ALLOWED_TOOLS.to_vec());
        for call in &calls {
            assert!(call.arguments().is_ok(), "{call:?}");
        }
    }

    fn semantic_call(verb: Verb, value: Option<&str>) -> SemanticCall {
        SemanticCall {
            pid: 10,
            window_id: 20,
            element_token: "s00000001:7".into(),
            verb,
            expect_role: "AXButton".into(),
            value: value.map(str::to_owned),
            toggle_to: (verb == Verb::Toggle).then_some(true),
        }
    }

    /// XP-11: the action tool is addressed by window and element token and
    /// carries no coordinate, key, button, count, modifier, delivery mode or
    /// scope, so no argument of the host can ask the tool for pointer input.
    #[test]
    fn semantic_arguments_carry_no_position_key_or_delivery_field() {
        let arguments = semantic_call(Verb::SetValue, Some("hello"))
            .arguments()
            .unwrap();
        let mut keys: Vec<_> = arguments.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "element_token",
                "expect_role",
                "pid",
                "value",
                "verb",
                "window_id"
            ]
        );
        assert_eq!(arguments["verb"], "set_value");
        let invoke = semantic_call(Verb::Invoke, None).arguments().unwrap();
        assert!(invoke.get("value").is_none());
        assert_eq!(invoke["verb"], "invoke");
    }

    #[test]
    fn semantic_arguments_are_validated_before_dispatch() {
        let mut call = semantic_call(Verb::Invoke, None);
        call.pid = 0;
        assert!(call.arguments().is_err());
        let mut call = semantic_call(Verb::Invoke, None);
        call.window_id = 0;
        assert!(call.arguments().is_err());
        for token in ["", "7", "x00000001:7", "s00000001", &"s".repeat(41)] {
            let mut call = semantic_call(Verb::Invoke, None);
            call.element_token = token.into();
            assert!(call.arguments().is_err(), "{token:?}");
        }
        let mut call = semantic_call(Verb::Invoke, None);
        call.expect_role = String::new();
        assert!(call.arguments().is_err());
        // A value belongs to set_value alone, and set_value needs one.
        assert!(semantic_call(Verb::Invoke, Some("x")).arguments().is_err());
        assert!(semantic_call(Verb::Toggle, Some("x")).arguments().is_err());
        assert!(semantic_call(Verb::SetValue, None).arguments().is_err());
        let long = "a".repeat(MAX_TEXT_BYTES + 1);
        assert!(semantic_call(Verb::SetValue, Some(&long))
            .arguments()
            .is_err());
        assert!(semantic_call(Verb::SetValue, Some("")).arguments().is_ok());
    }

    #[test]
    fn observation_never_asks_for_pixels_or_files() {
        let arguments = CuaCall::observe(10, 20, 256, 8).arguments().unwrap();
        assert_eq!(arguments["include_screenshot"], false);
        assert_eq!(arguments["tree_format"], "elements");
        assert!(arguments.get("screenshot_out_file").is_none());
        assert_eq!(arguments["max_elements"], 256);
        assert_eq!(arguments["max_depth"], 8);
    }

    #[test]
    fn permission_probe_never_asks_for_a_prompt() {
        assert_eq!(
            CuaCall::CheckPermissions.arguments().unwrap(),
            serde_json::json!({ "prompt": false })
        );
    }

    /// The adapter never reads or writes `ToolState`'s public
    /// `host_owns_permission_ux` (XP-05 review): it holds no `ToolState`.
    #[test]
    fn host_source_never_touches_the_permission_ux_field() {
        let field = [".host_owns", "_permission_ux"].concat();
        for (name, source) in [
            ("main.rs", include_str!("main.rs")),
            ("protocol.rs", include_str!("protocol.rs")),
            ("supervisor.rs", include_str!("supervisor.rs")),
            ("worker.rs", include_str!("worker.rs")),
            ("cua_adapter.rs", include_str!("cua_adapter.rs")),
            ("map.rs", include_str!("map.rs")),
            ("capture.rs", include_str!("capture.rs")),
            ("semantic.rs", include_str!("semantic.rs")),
        ] {
            assert!(!source.contains(&field), "{name} touches {field}");
        }
    }

    /// XP-07: the host reaches Cua's window capture and nothing broader. No
    /// host source names a display, root-region, probe-frame or Wayland
    /// output capture, the capture consent prompt flow, or a capture tool.
    #[test]
    fn host_source_reaches_only_exact_window_capture() {
        let forbidden = [
            ["screenshot", "_display"].concat(),
            ["screenshot_root", "_region"].concat(),
            ["capture_probe", "_frame"].concat(),
            ["screenshot_via", "_ext_copy"].concat(),
            ["wayland::", "capture"].concat(),
            ["request_screen", "_recording"].concat(),
            ["capture_blocked", "_reason"].concat(),
        ];
        for (name, source) in [
            ("main.rs", include_str!("main.rs")),
            ("protocol.rs", include_str!("protocol.rs")),
            ("supervisor.rs", include_str!("supervisor.rs")),
            ("worker.rs", include_str!("worker.rs")),
            ("cua_adapter.rs", include_str!("cua_adapter.rs")),
            ("map.rs", include_str!("map.rs")),
            ("capture.rs", include_str!("capture.rs")),
            ("semantic.rs", include_str!("semantic.rs")),
        ] {
            for word in &forbidden {
                assert!(!source.contains(word.as_str()), "{name} names {word}");
            }
        }
        assert!(!ALLOWED_TOOLS.iter().any(|tool| tool.contains("screenshot")));
    }

    /// P-04 on the registry the host builds: `check_permissions` answers as
    /// a direct runtime, so even an explicit prompt request reads state only
    /// and never reaches the TCC request calls or the capture probe.
    #[cfg(target_os = "macos")]
    #[test]
    fn registered_check_permissions_is_a_direct_runtime_that_never_prompts() {
        let runtime = CuaRuntime::new();
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let status = executor
            .block_on(
                runtime.invoke_for_test(CHECK_PERMISSIONS, serde_json::json!({"prompt": true})),
            )
            .unwrap();
        assert_eq!(status["source"]["direct_runtime"], true, "{status}");
        assert_eq!(status["source"]["attribution"], "host", "{status}");
        assert_eq!(status["direct_capture_status"], "not_checked", "{status}");
        assert!(status["accessibility"].is_boolean());
        assert!(status["screen_recording"].is_boolean());
    }

    /// The code a refusal carries: the tool's own (`code`) or the registry's
    /// envelope (`refusal.code`).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn refusal_code(failure: &CuaFailure) -> Option<&str> {
        failure.structured.as_ref().and_then(|value| {
            value
                .get("code")
                .or_else(|| value.pointer("/refusal/code"))
                .and_then(Value::as_str)
        })
    }

    /// P-09 (Linux): a toggle acts on a state it read. Checked or pressed is
    /// on; a failed or missing read is an error, never "off", so a checked
    /// box is never turned off for want of a state.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unreadable_toggle_state_is_an_error_never_off() {
        use platform_linux::atspi::native::toggled_from_state_read as read;
        assert!(read::<String>(Some(Ok((true, false)))).unwrap());
        assert!(read::<String>(Some(Ok((false, true)))).unwrap());
        assert!(!read::<String>(Some(Ok((false, false)))).unwrap());
        assert!(read(Some(Err("bus error".to_owned()))).is_err());
        assert!(read::<String>(None).is_err());
    }

    /// XP-11 / P-09: the action tool takes an element and a verb. Every name
    /// that could carry a position, a key, a button, a count, a modifier, a
    /// delivery mode or a scope is refused before any accessibility call,
    /// and so is a token that is not one `get_window_state` minted. None of
    /// this needs a desktop session or a permission.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn the_action_tool_refuses_every_argument_that_could_address_a_pixel() {
        let runtime = CuaRuntime::new();
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let base = serde_json::json!({
            "pid": 4242,
            "window_id": 77,
            "element_token": "s00000001:3",
            "verb": "invoke",
            "expect_role": "push button",
        });
        // Each argument that could address a pixel, with the exact refusal
        // the registry gives it on this OS. The registry rejects an unknown
        // argument itself (`invalid_arguments`); the one that differs is
        // `scope`, which macOS refuses in its action-target normalisation
        // (`invalid_action_target`) and Linux rewrites to a desktop
        // `coordinate_frame`, which is then an unknown argument.
        let scope_code = if cfg!(target_os = "macos") {
            "invalid_action_target"
        } else {
            "invalid_arguments"
        };
        for (name, extra, expected) in [
            ("x", serde_json::json!(10), "invalid_arguments"),
            ("y", serde_json::json!(10), "invalid_arguments"),
            ("button", serde_json::json!("left"), "invalid_arguments"),
            ("count", serde_json::json!(2), "invalid_arguments"),
            ("modifier", serde_json::json!(["cmd"]), "invalid_arguments"),
            (
                "delivery_mode",
                serde_json::json!("foreground"),
                "invalid_arguments",
            ),
            ("scope", serde_json::json!("desktop"), scope_code),
            (
                "coordinate_frame",
                serde_json::json!("desktop"),
                "invalid_arguments",
            ),
            ("capture_id", serde_json::json!("c1"), "invalid_arguments"),
            ("text", serde_json::json!("typed"), "invalid_arguments"),
            ("action", serde_json::json!("press"), "invalid_arguments"),
            ("from_zoom", serde_json::json!(true), "invalid_arguments"),
        ] {
            let mut arguments = base.clone();
            arguments[name] = extra;
            let refused = executor
                .block_on(runtime.invoke_for_test(SEMANTIC_ACTION_TOOL, arguments))
                .unwrap_err();
            assert_eq!(
                refusal_code(&refused),
                Some(expected),
                "{name}: {refused:?}"
            );
        }
        // A bare row number or a malformed token is not an element token.
        for token in ["3", "x:3", "s0000000g:3", ""] {
            let mut arguments = base.clone();
            arguments["element_token"] = serde_json::json!(token);
            let refused = executor
                .block_on(runtime.invoke_for_test(SEMANTIC_ACTION_TOOL, arguments))
                .unwrap_err();
            assert_eq!(
                refusal_code(&refused),
                Some("invalid_request"),
                "{token:?}: {refused:?}"
            );
        }
        // Verbs outside the closed set, scroll included.
        for verb in ["scroll", "click", "type", "drag", "press", ""] {
            let mut arguments = base.clone();
            arguments["verb"] = serde_json::json!(verb);
            let refused = executor
                .block_on(runtime.invoke_for_test(SEMANTIC_ACTION_TOOL, arguments))
                .unwrap_err();
            assert_eq!(
                refusal_code(&refused),
                Some("invalid_request"),
                "{verb:?}: {refused:?}"
            );
        }
        // A toggle names the state it asks for, and nothing else may.
        for (verb, extra) in [("toggle", None), ("invoke", Some(true))] {
            let mut arguments = base.clone();
            arguments["verb"] = serde_json::json!(verb);
            if let Some(wanted) = extra {
                arguments["toggle_to"] = serde_json::json!(wanted);
            }
            let refused = executor
                .block_on(runtime.invoke_for_test(SEMANTIC_ACTION_TOOL, arguments))
                .unwrap_err();
            assert_eq!(
                refusal_code(&refused),
                Some("invalid_request"),
                "{verb:?}: {refused:?}"
            );
        }
        // A well-formed call for a snapshot this process never took is stale.
        let stale = executor
            .block_on(runtime.invoke_for_test(SEMANTIC_ACTION_TOOL, base.clone()))
            .unwrap_err();
        let text = format!("{stale:?}").to_ascii_lowercase();
        assert!(
            text.contains("stale") || text.contains("unknown") || text.contains("snapshot"),
            "{text}"
        );
        // Upstream's own tools are not in this registry to be reached by name.
        for name in [
            "click",
            "set_value",
            "scroll",
            "type_text",
            "press_key",
            "hotkey",
        ] {
            let refused = executor
                .block_on(runtime.invoke_for_test(name, base.clone()))
                .unwrap_err();
            assert!(
                refused.message.to_ascii_lowercase().contains("unknown"),
                "{name}: {refused:?}"
            );
        }
    }

    /// The registry the host builds holds the five tools the adapter calls
    /// and none of the surfaces P-03 compiles out or Orcel never allows: no
    /// script engine, no page or browser engine tools, no kill_app, no
    /// recording, history or expression-evaluating drag.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn registry_holds_the_allowlist_and_no_compiled_out_tool() {
        let mut names = CuaRuntime::new().registered_tools();
        names.sort();
        let mut allowed: Vec<String> = ALLOWED_TOOLS.iter().map(|n| n.to_string()).collect();
        allowed.sort();
        // P-07 narrows the platform's whole set to exactly the allowlist:
        // no run_script, page, kill_app, browser, input, clipboard or
        // recording tool is registered.
        assert_eq!(names, allowed);
    }

    #[test]
    fn contract_validation_runs_before_dispatch() {
        assert!(CuaCall::observe(0, 20, 256, 8).arguments().is_err());
        assert!(CuaCall::list_windows(Some(0)).arguments().is_err());
    }
}
