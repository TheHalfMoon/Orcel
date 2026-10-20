// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! The allowlisted adapter over the vendored Cua Driver tools (XP-06).
//!
//! [`CuaCall`] is the whole surface: five read-only tools. Each variant
//! holds the typed `cua-driver-contract` input, validated before dispatch,
//! and its tool name is that input's `TOOL_NAME` constant. Nothing in a
//! request names a tool, so no other Cua tool (click, type_text, launch_app,
//! clipboard writes, ...) can be reached from the protocol.
//!
//! The registry is built the way Cua's own embedders build it, with
//! `cursor_overlay_available = false` and `host_owns_permission_ux = true`
//! on macOS (patch P-04 forces the latter anyway). The adapter never holds a
//! `ToolState`, so it cannot overwrite either field after construction.

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
pub const ALLOWED_TOOLS: [&str; 5] = [
    ListWindowsInput::TOOL_NAME,
    GetWindowStateInput::TOOL_NAME,
    GetCursorPositionInput::TOOL_NAME,
    GetScreenSizeInput::TOOL_NAME,
    CHECK_PERMISSIONS,
];

/// The only Cua tools the host calls.
#[derive(Debug, Clone, PartialEq)]
pub enum CuaCall {
    ListWindows(ListWindowsInput),
    GetWindowState(GetWindowStateInput),
    GetCursorPosition(GetCursorPositionInput),
    GetScreenSize(GetScreenSizeInput),
    /// macOS only: TCC state, read without prompting.
    CheckPermissions,
}

impl CuaCall {
    pub fn tool_name(&self) -> &'static str {
        match self {
            Self::ListWindows(_) => ListWindowsInput::TOOL_NAME,
            Self::GetWindowState(_) => GetWindowStateInput::TOOL_NAME,
            Self::GetCursorPosition(_) => GetCursorPositionInput::TOOL_NAME,
            Self::GetScreenSize(_) => GetScreenSizeInput::TOOL_NAME,
            Self::CheckPermissions => CHECK_PERMISSIONS,
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

        /// Test-only raw dispatch, to show what the registered tools do
        /// with arguments the adapter itself never sends.
        #[cfg(all(test, target_os = "macos"))]
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
    }
}

pub use imp::CuaRuntime;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_call_names_a_read_only_tool_from_its_typed_input() {
        let calls = [
            CuaCall::list_windows(None),
            CuaCall::observe(10, 20, 256, 8),
            CuaCall::GetCursorPosition(GetCursorPositionInput::default()),
            CuaCall::GetScreenSize(GetScreenSizeInput { session: None }),
            CuaCall::CheckPermissions,
        ];
        let names: Vec<_> = calls.iter().map(CuaCall::tool_name).collect();
        assert_eq!(
            names,
            vec![
                "list_windows",
                "get_window_state",
                "get_cursor_position",
                "get_screen_size",
                "check_permissions"
            ]
        );
        assert_eq!(names, ALLOWED_TOOLS.to_vec());
        for call in &calls {
            assert!(call.arguments().is_ok(), "{call:?}");
        }
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
        ] {
            assert!(!source.contains(&field), "{name} touches {field}");
        }
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
