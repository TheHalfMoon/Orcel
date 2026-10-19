// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! `orcel-computer-host/2` frames for the macOS and Linux host (XP-06).
//!
//! The wire shapes mirror `apps/orcel-computer-host/protocol.go` and the
//! specification in
//! `docs/orcel/implementation-readiness/protocol/ORCEL_COMPUTER_HOST_2.md`.
//! This host speaks only `/2`: it has no `/1` history to keep. A `/1` frame
//! is refused with `invalid_request` in `/1` framing, the answer the adapter
//! never falls back on outside Windows.
//!
//! The host is observation only. `hello`, `ping` and `shutdown` are answered
//! by the supervisor; `list_windows`, `observe_window` and `cursor_position`
//! run in a one-shot worker. Every other operation of the closed set of 16 is
//! refused with `capability_denied`, and the hello capability table says so
//! up front.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;

pub const PROTOCOL_V1: &str = "orcel-computer-host/1";
pub const PROTOCOL_V2: &str = "orcel-computer-host/2";
/// The host identity every response echoes. The kernel adapter requires it
/// on macOS and Linux (`host_protocol::expected_host_identity`).
pub const HOST_IDENTITY: &str = "orcel-native-host";

/// Bounds shared with the Windows host (`protocol.go`).
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_WINDOWS: usize = 64;
pub const MAX_TREE_NODES: usize = 256;
pub const MAX_TREE_DEPTH: usize = 8;
pub const MAX_TEXT_BYTES: usize = 16 * 1024;
pub const MAX_KEY_BYTES: usize = 64;
pub const MAX_RUNTIME_ID_BYTES: usize = 512;
pub const WORKER_TIMEOUT: Duration = Duration::from_millis(8000);
pub const WORKER_ATTEMPTS: usize = 2;

/// The closed operation set, identical to `/1`.
pub const OPERATIONS: [&str; 16] = [
    "hello",
    "ping",
    "shutdown",
    "list_windows",
    "observe_window",
    "cursor_position",
    "capture_window",
    "semantic_action",
    "window_action",
    "input_move",
    "input_click",
    "input_drag",
    "input_scroll",
    "input_type_text",
    "input_key",
    "input_hotkey",
];

/// Platform facts the hello reports. `kind` is the only window-reference
/// kind this host serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostPlatform {
    pub platform: &'static str,
    pub backend: &'static str,
    pub kind: &'static str,
}

pub const MACOS: HostPlatform = HostPlatform {
    platform: "macos",
    backend: "ax",
    kind: "cgwindow",
};
pub const LINUX_X11: HostPlatform = HostPlatform {
    platform: "linux",
    backend: "atspi-x11",
    kind: "x11",
};
pub const LINUX_WAYLAND: HostPlatform = HostPlatform {
    platform: "linux",
    backend: "atspi-wayland",
    kind: "wl_toplevel",
};

impl HostPlatform {
    /// The platform this process serves. On Linux a session that exports
    /// `WAYLAND_DISPLAY` is served as Wayland, even when it also exports
    /// `DISPLAY` for XWayland. Off macOS and Linux the host builds only for
    /// its tests and reports Linux X11.
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            MACOS
        } else if std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty()) {
            LINUX_WAYLAND
        } else {
            LINUX_X11
        }
    }
}

/// The `/2` platform-tagged window reference (spec section 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowRef {
    pub kind: String,
    pub id: u64,
    #[serde(default)]
    pub expected_pid: Option<u32>,
    #[serde(default)]
    pub expected_start_generation: Option<u64>,
    #[serde(default)]
    pub expected_window_nonce: Option<u64>,
}

/// One `/2` request frame. Unknown fields are refused. The `/1` binding
/// fields are part of the shape, so they decode, but this host refuses them:
/// a bound request must name its window kind.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: u64,
    pub protocol: String,
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hwnd: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_start_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_window_nonce: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_nodes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub element_runtime_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_x: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_y: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub button: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub click_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scroll_x: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scroll_y: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_last_input_tick: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<WindowRef>,
}

impl Request {
    /// The tree node bound: the request's value when given, never above 256.
    pub fn node_limit(&self) -> usize {
        bounded(self.max_nodes, MAX_TREE_NODES)
    }

    /// The tree depth bound: the request's value when given, never above 8.
    pub fn depth_limit(&self) -> usize {
        bounded(self.max_depth, MAX_TREE_DEPTH)
    }
}

fn bounded(requested: Option<u64>, ceiling: usize) -> usize {
    match requested {
        Some(0) | None => ceiling,
        Some(value) => usize::try_from(value).map_or(ceiling, |value| value.min(ceiling)),
    }
}

/// The exact window binding of a bound request, after validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowBinding {
    pub id: u64,
    pub pid: u32,
    pub start_generation: u64,
    pub window_nonce: u64,
}

impl WindowRef {
    pub fn binding(&self) -> Option<WindowBinding> {
        Some(WindowBinding {
            id: self.id,
            pid: self.expected_pid?,
            start_generation: self.expected_start_generation?,
            window_nonce: self.expected_window_nonce?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessFact {
    pub pid: u32,
    pub exe_name: String,
    pub exe_id: String,
    pub session_id: u32,
    pub session_verified: bool,
    pub start_generation: u64,
    pub generation_source: String,
}

/// One listed window. The field is named `hwnd` on every OS because the
/// response shape is shared with `/1`; here it carries the opaque id of the
/// served window kind (CGWindowID, X11 window id or Wayland toplevel id).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowFact {
    pub process: ProcessFact,
    pub hwnd: u64,
    pub title: String,
    pub class: String,
    pub visible: bool,
    pub window_nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementFact {
    pub runtime_id: String,
    pub control_type: String,
    pub automation_id: String,
    pub name: String,
    pub enabled: bool,
    pub selected: bool,
    pub toggled: bool,
    pub scroll_horizontal_percent: u8,
    pub scroll_vertical_percent: u8,
    pub patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub value_is_password: bool,
    pub children: Vec<ElementFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorFact {
    pub x: i32,
    pub y: i32,
    pub screen_width: i32,
    pub screen_height: i32,
    /// The Windows human-input tick. Raw input is not served here, so the
    /// host reports 0 and the adapter never binds input to it.
    pub last_input_tick: u32,
}

/// One `/2` capability table entry. Advisory: it only lets the adapter skip
/// a call that cannot work; the kernel registry still enforces everything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityFact {
    pub support: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    pub ok: bool,
    pub protocol: String,
    pub host: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pong: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows: Option<Vec<WindowFact>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elements: Option<Vec<ElementFact>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<CursorFact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<HostError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<BTreeMap<String, CapabilityFact>>,
    /// Informational hello fields reserved for this host (spec section 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub donor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<BTreeMap<String, bool>>,
}

impl Response {
    pub fn success(id: u64) -> Self {
        Self {
            id,
            ok: true,
            protocol: PROTOCOL_V2.to_owned(),
            host: HOST_IDENTITY.to_owned(),
            ..Self::default()
        }
    }

    pub fn failure(id: u64, code: &str, message: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            protocol: PROTOCOL_V2.to_owned(),
            host: HOST_IDENTITY.to_owned(),
            error: Some(HostError {
                code: code.to_owned(),
                message: message.into(),
            }),
            ..Self::default()
        }
    }

    fn failure_v1(id: u64, code: &str, message: &str) -> Self {
        let mut response = Self::failure(id, code, message);
        response.protocol = PROTOCOL_V1.to_owned();
        response
    }
}

/// The closed refusal codes of spec section 7 this host emits.
pub mod code {
    pub const INVALID_REQUEST: &str = "invalid_request";
    pub const CAPABILITY_DENIED: &str = "capability_denied";
    pub const TARGET_STALE: &str = "target_stale";
    pub const PERMISSION_MISSING: &str = "permission_missing";
    pub const PROTECTED_SURFACE: &str = "protected_surface";
    pub const OUTPUT_LIMIT: &str = "output_limit";
    pub const TIMEOUT: &str = "timeout";
    pub const PROVIDER_UNAVAILABLE: &str = "provider_unavailable";
}

/// Why the worker operations are or are not usable on this machine, as the
/// worker measured it for the hello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Availability {
    /// `None` when usable, otherwise a refusal code.
    pub list_windows: Option<String>,
    pub observe_window: Option<String>,
    pub cursor_position: Option<String>,
    /// Permission facts reported informationally (macOS).
    #[serde(default)]
    pub permissions: BTreeMap<String, bool>,
}

impl Availability {
    /// Every worker operation unavailable for one reason.
    pub fn none(reason: &str) -> Self {
        Self {
            list_windows: Some(reason.to_owned()),
            observe_window: Some(reason.to_owned()),
            cursor_position: Some(reason.to_owned()),
            permissions: BTreeMap::new(),
        }
    }

    pub fn refusal_for(&self, op: &str) -> Option<&str> {
        match op {
            "list_windows" => self.list_windows.as_deref(),
            "observe_window" => self.observe_window.as_deref(),
            "cursor_position" => self.cursor_position.as_deref(),
            _ => Some(code::CAPABILITY_DENIED),
        }
    }
}

fn entry(support: &str, reason: Option<&str>) -> CapabilityFact {
    CapabilityFact {
        support: support.to_owned(),
        delivery: None,
        reason: reason.map(str::to_owned),
    }
}

/// The `/2` capability table: exactly one entry for each of the 16
/// operations. Observation follows `availability`; capture waits for XP-07
/// and every mutation is refused, because this host is read-only.
pub fn capability_table(availability: &Availability) -> BTreeMap<String, CapabilityFact> {
    let mut table = BTreeMap::new();
    for op in OPERATIONS {
        let fact = match op {
            "hello" | "ping" | "shutdown" => entry("delivered", None),
            "list_windows" | "observe_window" | "cursor_position" => {
                match availability.refusal_for(op) {
                    None => entry("delivered", None),
                    Some(reason) => entry("unavailable", Some(reason)),
                }
            }
            "capture_window" => entry("unavailable", Some(code::PROVIDER_UNAVAILABLE)),
            _ => entry("refused", Some(code::CAPABILITY_DENIED)),
        };
        table.insert(op.to_owned(), fact);
    }
    table
}

/// The `/2` hello answer.
pub fn hello(id: u64, platform: HostPlatform, availability: &Availability) -> Response {
    let mut response = Response::success(id);
    response.platform = Some(platform.platform.to_owned());
    response.backend = Some(platform.backend.to_owned());
    response.capabilities = Some(capability_table(availability));
    response.host_version = Some(env!("CARGO_PKG_VERSION").to_owned());
    response.donor = Some("cua@a802eaf26ca97616a6bf0de6a29729a9346fbb1f".to_owned());
    if !availability.permissions.is_empty() {
        response.permissions = Some(availability.permissions.clone());
    }
    response
}

/// A frame the host refuses before any native work, already in the framing
/// of the generation the caller spoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub Box<Response>);

fn refuse(id: u64, code: &str, message: &str) -> Refusal {
    Refusal(Box::new(Response::failure(id, code, message)))
}

/// Parses and validates one request line for `platform`.
pub fn decode_request(line: &[u8], platform: HostPlatform) -> Result<Request, Refusal> {
    let Ok(Value::Object(raw)) = serde_json::from_slice::<Value>(line) else {
        return Err(Refusal(Box::new(Response::failure_v1(
            0,
            code::INVALID_REQUEST,
            "request is not valid JSON",
        ))));
    };
    let id = raw.get("id").and_then(Value::as_u64).unwrap_or(0);
    if raw.get("protocol").and_then(Value::as_str) != Some(PROTOCOL_V2) {
        return Err(Refusal(Box::new(Response::failure_v1(
            id,
            code::INVALID_REQUEST,
            "protocol generation mismatch: this host speaks orcel-computer-host/2 only",
        ))));
    }
    let request: Request = serde_json::from_value(Value::Object(raw)).map_err(|_| {
        refuse(
            id,
            code::INVALID_REQUEST,
            "request contains an unknown or malformed field",
        )
    })?;
    validate(&request, platform)?;
    Ok(request)
}

fn requires_window_binding(op: &str) -> bool {
    matches!(
        op,
        "observe_window"
            | "capture_window"
            | "semantic_action"
            | "window_action"
            | "input_move"
            | "input_click"
            | "input_drag"
            | "input_scroll"
            | "input_type_text"
            | "input_key"
            | "input_hotkey"
    )
}

fn validate(request: &Request, platform: HostPlatform) -> Result<(), Refusal> {
    let id = request.id;
    if !OPERATIONS.contains(&request.op.as_str()) {
        return Err(refuse(
            id,
            code::CAPABILITY_DENIED,
            "operation is not exposed by the private host",
        ));
    }
    if request.hwnd.is_some()
        || request.expected_pid.is_some()
        || request.expected_start_generation.is_some()
        || request.expected_window_nonce.is_some()
    {
        return Err(refuse(
            id,
            code::INVALID_REQUEST,
            "legacy window fields are not served by this host; send the window reference",
        ));
    }
    if let Some(window) = &request.window {
        if window.kind != platform.kind {
            return Err(refuse(
                id,
                code::INVALID_REQUEST,
                "window reference kind is not served by this host",
            ));
        }
    }
    if requires_window_binding(&request.op) {
        let Some(window) = &request.window else {
            return Err(refuse(
                id,
                code::INVALID_REQUEST,
                "exact window binding is required",
            ));
        };
        if window.id == 0 || window.binding().is_none() {
            return Err(refuse(
                id,
                code::INVALID_REQUEST,
                "exact window binding is required",
            ));
        }
    }
    let text_too_long = |field: &Option<String>, limit: usize| {
        field.as_ref().is_some_and(|value| value.len() > limit)
    };
    if text_too_long(&request.text, MAX_TEXT_BYTES) || text_too_long(&request.value, MAX_TEXT_BYTES)
    {
        return Err(refuse(
            id,
            code::INVALID_REQUEST,
            "text input exceeds the bounded limit",
        ));
    }
    if text_too_long(&request.key, MAX_KEY_BYTES) {
        return Err(refuse(
            id,
            code::INVALID_REQUEST,
            "key input exceeds the bounded limit",
        ));
    }
    if text_too_long(&request.element_runtime_id, MAX_RUNTIME_ID_BYTES) {
        return Err(refuse(
            id,
            code::INVALID_REQUEST,
            "element runtime id exceeds the bounded limit",
        ));
    }
    if !matches!(
        request.op.as_str(),
        "hello" | "ping" | "shutdown" | "list_windows" | "observe_window" | "cursor_position"
    ) {
        return Err(refuse(
            id,
            code::CAPABILITY_DENIED,
            "operation is not served by the observation-only native host",
        ));
    }
    Ok(())
}

/// Serializes one response line, replacing it with `output_limit` when it
/// would exceed the response bound.
pub fn encode_bounded(response: &Response) -> Vec<u8> {
    match serde_json::to_vec(response) {
        Ok(raw) if raw.len() <= MAX_RESPONSE_BYTES => raw,
        _ => {
            let mut limited = Response::failure(
                response.id,
                code::OUTPUT_LIMIT,
                "host response exceeds the bounded private IPC size",
            );
            limited.protocol = response.protocol.clone();
            serde_json::to_vec(&limited).unwrap_or_default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(line: &str) -> Result<Request, Box<Response>> {
        decode_request(line.as_bytes(), LINUX_X11).map_err(|refusal| refusal.0)
    }

    fn refusal_code(line: &str) -> String {
        decode(line).unwrap_err().error.unwrap().code
    }

    #[test]
    fn hello_reports_platform_backend_and_one_entry_per_operation() {
        let available = Availability {
            list_windows: None,
            observe_window: None,
            cursor_position: None,
            permissions: BTreeMap::new(),
        };
        let response = hello(1, MACOS, &available);
        assert!(response.ok);
        assert_eq!(response.protocol, PROTOCOL_V2);
        assert_eq!(response.host, HOST_IDENTITY);
        assert_eq!(response.platform.as_deref(), Some("macos"));
        assert_eq!(response.backend.as_deref(), Some("ax"));
        let table = response.capabilities.unwrap();
        assert_eq!(table.len(), OPERATIONS.len());
        for op in OPERATIONS {
            let support = table[op].support.as_str();
            let expected = match op {
                "hello" | "ping" | "shutdown" | "list_windows" | "observe_window"
                | "cursor_position" => "delivered",
                "capture_window" => "unavailable",
                _ => "refused",
            };
            assert_eq!(support, expected, "{op}");
        }
    }

    #[test]
    fn missing_permission_marks_observation_unavailable_with_a_reason() {
        let mut availability = Availability::none(code::PERMISSION_MISSING);
        availability.cursor_position = None;
        let table = capability_table(&availability);
        for op in ["list_windows", "observe_window"] {
            assert_eq!(table[op].support, "unavailable");
            assert_eq!(table[op].reason.as_deref(), Some("permission_missing"));
        }
        assert_eq!(table["cursor_position"].support, "delivered");
    }

    #[test]
    fn unknown_op_and_mutations_are_refused() {
        assert_eq!(
            refusal_code(r#"{"id":3,"protocol":"orcel-computer-host/2","op":"run_script"}"#),
            "capability_denied"
        );
        let mutation = r#"{"id":4,"protocol":"orcel-computer-host/2","op":"input_click","x":1,"y":1,"button":"left","click_count":1,"expected_last_input_tick":1,"window":{"kind":"x11","id":9,"expected_pid":1,"expected_start_generation":2,"expected_window_nonce":3}}"#;
        assert_eq!(refusal_code(mutation), "capability_denied");
        let capture = r#"{"id":5,"protocol":"orcel-computer-host/2","op":"capture_window","window":{"kind":"x11","id":9,"expected_pid":1,"expected_start_generation":2,"expected_window_nonce":3}}"#;
        assert_eq!(refusal_code(capture), "capability_denied");
    }

    #[test]
    fn unknown_fields_foreign_kinds_and_partial_bindings_are_refused() {
        assert_eq!(
            refusal_code(r#"{"id":1,"protocol":"orcel-computer-host/2","op":"ping","extra":1}"#),
            "invalid_request"
        );
        let foreign = r#"{"id":1,"protocol":"orcel-computer-host/2","op":"observe_window","window":{"kind":"hwnd","id":9,"expected_pid":1,"expected_start_generation":2,"expected_window_nonce":3}}"#;
        assert_eq!(refusal_code(foreign), "invalid_request");
        let partial = r#"{"id":1,"protocol":"orcel-computer-host/2","op":"observe_window","window":{"kind":"x11","id":9,"expected_pid":1}}"#;
        assert_eq!(refusal_code(partial), "invalid_request");
        let missing = r#"{"id":1,"protocol":"orcel-computer-host/2","op":"observe_window"}"#;
        assert_eq!(refusal_code(missing), "invalid_request");
        let legacy = r#"{"id":1,"protocol":"orcel-computer-host/2","op":"observe_window","hwnd":9,"expected_pid":1,"expected_start_generation":2,"expected_window_nonce":3}"#;
        assert_eq!(refusal_code(legacy), "invalid_request");
        let unknown_ref_field = r#"{"id":1,"protocol":"orcel-computer-host/2","op":"observe_window","window":{"kind":"x11","id":9,"expected_pid":1,"expected_start_generation":2,"expected_window_nonce":3,"title":"x"}}"#;
        assert_eq!(refusal_code(unknown_ref_field), "invalid_request");
    }

    #[test]
    fn v1_frames_and_corrupt_json_are_refused_in_v1_framing() {
        let v1 = decode(r#"{"id":2,"protocol":"orcel-computer-host/1","op":"hello"}"#).unwrap_err();
        assert_eq!(v1.protocol, PROTOCOL_V1);
        assert_eq!(v1.id, 2);
        assert_eq!(v1.error.unwrap().code, "invalid_request");
        let corrupt = decode("{not json").unwrap_err();
        assert_eq!(corrupt.id, 0);
        assert_eq!(corrupt.protocol, PROTOCOL_V1);
    }

    #[test]
    fn bound_observation_decodes_and_tree_bounds_are_capped() {
        let line = r#"{"id":7,"protocol":"orcel-computer-host/2","op":"observe_window","max_nodes":100000,"max_depth":0,"window":{"kind":"x11","id":1312,"expected_pid":4410,"expected_start_generation":133702,"expected_window_nonce":9}}"#;
        let request = decode(line).unwrap();
        assert_eq!(request.node_limit(), MAX_TREE_NODES);
        assert_eq!(request.depth_limit(), MAX_TREE_DEPTH);
        assert_eq!(
            request.window.unwrap().binding(),
            Some(WindowBinding {
                id: 1312,
                pid: 4410,
                start_generation: 133702,
                window_nonce: 9
            })
        );
    }

    #[test]
    fn oversize_text_is_refused() {
        let text = "a".repeat(MAX_TEXT_BYTES + 1);
        let line =
            format!(r#"{{"id":1,"protocol":"orcel-computer-host/2","op":"ping","text":"{text}"}}"#);
        assert_eq!(refusal_code(&line), "invalid_request");
    }

    #[test]
    fn oversize_response_is_replaced_with_output_limit() {
        let mut response = Response::success(9);
        response.elements = Some(vec![ElementFact {
            runtime_id: "1:1".into(),
            control_type: "Text".into(),
            automation_id: String::new(),
            name: "x".repeat(MAX_RESPONSE_BYTES),
            enabled: true,
            selected: false,
            toggled: false,
            scroll_horizontal_percent: 0,
            scroll_vertical_percent: 0,
            patterns: Vec::new(),
            value: None,
            value_is_password: false,
            children: Vec::new(),
        }]);
        let encoded = encode_bounded(&response);
        assert!(encoded.len() < 1024);
        let decoded: Response = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.id, 9);
        assert_eq!(decoded.error.unwrap().code, "output_limit");
    }
}
