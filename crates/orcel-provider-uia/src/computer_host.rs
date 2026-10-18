// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//
// SG-000094 private Windows Computer Host adapter. The adapter is deliberately
// not the default NativeAdapter and adds no caller-facing MCP surface. It only
// translates host OS facts/pixels into the existing UiaAdapter contract.

#[cfg(windows)]
use crate::CapturedImage;
use crate::{NativeElement, NativeProcess, NativeWindow, UiaAdapter, UiaError};
use orcel_contracts::FailureCode;
#[cfg(any(windows, test))]
use serde::Deserialize;
#[cfg(windows)]
use serde::Serialize;
use std::path::{Path, PathBuf};

/// One live cursor snapshot from the private Windows Computer Host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopCursorPosition {
    pub x: i32,
    pub y: i32,
    pub screen_width: i32,
    pub screen_height: i32,
    pub last_input_tick: u32,
}

/// The bounded Full User foreground-input vocabulary. Coordinates are
/// relative to the exact typed target window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopInputAction {
    Move {
        x: i32,
        y: i32,
    },
    Click {
        x: i32,
        y: i32,
        button: String,
        count: u8,
    },
    Drag {
        x: i32,
        y: i32,
        to_x: i32,
        to_y: i32,
    },
    Scroll {
        x: i32,
        y: i32,
        scroll_x: i32,
        scroll_y: i32,
    },
    TypeText {
        text: String,
    },
    Key {
        key: String,
    },
    Hotkey {
        key: String,
    },
}

/// Frozen execution-state projection for one private-host mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopActionResult {
    pub state: String,
    pub action: String,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopWindowAction {
    Focus,
    Minimize,
    Maximize,
    Restore,
    Close,
}

#[cfg(windows)]
impl DesktopWindowAction {
    fn as_host_str(self) -> &'static str {
        match self {
            Self::Focus => "focus",
            Self::Minimize => "minimize",
            Self::Maximize => "maximize",
            Self::Restore => "restore",
            Self::Close => "close",
        }
    }
}

#[cfg(windows)]
use crate::host_protocol::{
    map_refusal_code, negotiate, HelloFrame, NegotiatedHost, ProtocolGeneration, HOST_IDENTITY,
    PROTOCOL_V1,
};

#[cfg(windows)]
const MAX_HOST_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[cfg(windows)]
#[derive(Debug, Serialize)]
struct HostRequest<'a> {
    id: u64,
    protocol: &'a str,
    op: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hwnd: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_start_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_window_nonce: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_nodes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_depth: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    element_runtime_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic_action: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    window_action: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    y: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to_x: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to_y: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    button: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    click_count: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scroll_x: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scroll_y: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_last_input_tick: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    window: Option<HostWindowRef>,
}

/// The `/2` platform-tagged window reference. This adapter serves `hwnd`.
#[cfg(windows)]
#[derive(Debug, Serialize)]
struct HostWindowRef {
    kind: &'static str,
    id: u64,
    expected_pid: u32,
    expected_start_generation: u64,
    expected_window_nonce: u64,
}

#[cfg(windows)]
impl<'a> HostRequest<'a> {
    fn new(op: &'a str) -> Self {
        Self {
            id: 0,
            protocol: PROTOCOL_V1,
            op,
            hwnd: None,
            expected_pid: None,
            expected_start_generation: None,
            expected_window_nonce: None,
            max_nodes: None,
            max_depth: None,
            element_runtime_id: None,
            semantic_action: None,
            window_action: None,
            value: None,
            x: None,
            y: None,
            to_x: None,
            to_y: None,
            button: None,
            click_count: None,
            scroll_x: None,
            scroll_y: None,
            text: None,
            key: None,
            expected_last_input_tick: None,
            window: None,
        }
    }

    /// Frames the request in the negotiated generation. Under `/2` a complete
    /// exact binding travels as the platform-tagged window reference.
    fn frame_for(&mut self, generation: ProtocolGeneration) {
        self.protocol = generation.as_str();
        if generation != ProtocolGeneration::V2 {
            return;
        }
        if let (
            Some(id),
            Some(expected_pid),
            Some(expected_start_generation),
            Some(expected_window_nonce),
        ) = (
            self.hwnd,
            self.expected_pid,
            self.expected_start_generation,
            self.expected_window_nonce,
        ) {
            self.window = Some(HostWindowRef {
                kind: "hwnd",
                id,
                expected_pid,
                expected_start_generation,
                expected_window_nonce,
            });
            self.hwnd = None;
            self.expected_pid = None;
            self.expected_start_generation = None;
            self.expected_window_nonce = None;
        }
    }

    fn bind_window(&mut self, hwnd: u64, binding: HostTargetBinding) {
        self.hwnd = Some(hwnd);
        self.expected_pid = Some(binding.pid);
        self.expected_start_generation = Some(binding.start_generation);
        self.expected_window_nonce = Some(binding.window_nonce);
    }
}

#[cfg(windows)]
#[derive(Debug, Deserialize)]
struct HostError {
    code: String,
    message: String,
    /// The generation of the session that received this refusal. Set by the
    /// session after decoding; it selects the refusal mapping.
    #[serde(skip)]
    generation: ProtocolGeneration,
}

#[cfg(windows)]
#[derive(Debug, Deserialize, Clone)]
struct HostProcess {
    pid: u32,
    exe_name: String,
    exe_id: String,
    session_id: u32,
    session_verified: bool,
    start_generation: u64,
    generation_source: String,
}

#[cfg(windows)]
#[derive(Debug, Deserialize, Clone)]
struct HostWindow {
    process: HostProcess,
    hwnd: u64,
    title: String,
    class: String,
    visible: bool,
    window_nonce: u64,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
struct HostTargetBinding {
    pid: u32,
    start_generation: u64,
    window_nonce: u64,
}

#[cfg(any(windows, test))]
#[derive(Debug, Deserialize)]
struct HostElement {
    runtime_id: String,
    control_type: String,
    automation_id: String,
    name: String,
    enabled: bool,
    selected: bool,
    toggled: bool,
    scroll_horizontal_percent: u8,
    scroll_vertical_percent: u8,
    patterns: Vec<String>,
    value: Option<String>,
    value_is_password: bool,
    children: Vec<HostElement>,
}

#[cfg(windows)]
#[derive(Debug, Deserialize)]
struct HostCapture {
    width: u32,
    height: u32,
    pixel_format: String,
    pixels_b64: String,
}

#[cfg(windows)]
#[derive(Debug, Deserialize)]
struct HostCursor {
    x: i32,
    y: i32,
    screen_width: i32,
    screen_height: i32,
    last_input_tick: u32,
}

#[cfg(windows)]
#[derive(Debug, Deserialize)]
struct HostAction {
    state: String,
    action: String,
}

#[cfg(windows)]
#[derive(Debug, Deserialize)]
struct HostResponse {
    id: u64,
    ok: bool,
    protocol: String,
    host: String,
    #[serde(default)]
    windows: Vec<HostWindow>,
    #[serde(default)]
    elements: Vec<HostElement>,
    capture: Option<HostCapture>,
    cursor: Option<HostCursor>,
    action: Option<HostAction>,
    error: Option<HostError>,
}

#[cfg(windows)]
fn map_host_error(error: HostError) -> UiaError {
    UiaError::new(
        map_refusal_code(error.generation, &error.code),
        error.message,
    )
}

#[cfg(any(windows, test))]
fn decode_base64(input: &str, max_bytes: usize) -> Result<Vec<u8>, UiaError> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() % 4 != 0 {
        return Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            "computer host returned malformed base64 pixels",
        ));
    }
    let estimated = bytes.len() / 4 * 3;
    if estimated > max_bytes.saturating_add(2) {
        return Err(UiaError::new(
            FailureCode::OutputLimit,
            "computer host pixel payload exceeds the bounded size",
        ));
    }

    let mut out = Vec::with_capacity(estimated.min(max_bytes));
    for (chunk_index, chunk) in bytes.chunks_exact(4).enumerate() {
        let last = chunk_index + 1 == bytes.len() / 4;
        let pad2 = chunk[2] == b'=';
        let pad3 = chunk[3] == b'=';
        if pad2 && !pad3 {
            return Err(UiaError::new(
                FailureCode::ProviderUnavailable,
                "computer host returned invalid base64 padding",
            ));
        }
        if (pad2 || pad3) && !last {
            return Err(UiaError::new(
                FailureCode::ProviderUnavailable,
                "computer host returned non-final base64 padding",
            ));
        }
        let a = value(chunk[0]);
        let b = value(chunk[1]);
        let c = if pad2 { Some(0) } else { value(chunk[2]) };
        let d = if pad3 { Some(0) } else { value(chunk[3]) };
        let (Some(a), Some(b), Some(c), Some(d)) = (a, b, c, d) else {
            return Err(UiaError::new(
                FailureCode::ProviderUnavailable,
                "computer host returned non-base64 pixel bytes",
            ));
        };
        out.push((a << 2) | (b >> 4));
        if !pad2 {
            out.push((b << 4) | (c >> 2));
        }
        if !pad3 {
            out.push((c << 6) | d);
        }
        if out.len() > max_bytes {
            return Err(UiaError::new(
                FailureCode::OutputLimit,
                "computer host pixel payload exceeds the bounded size",
            ));
        }
    }
    Ok(out)
}

#[cfg(any(windows, test))]
fn convert_element(element: HostElement) -> NativeElement {
    NativeElement {
        runtime_id: element.runtime_id,
        control_type: element.control_type,
        automation_id: element.automation_id,
        name: element.name,
        enabled: element.enabled,
        selected: element.selected,
        toggled: element.toggled,
        scroll_horizontal_percent: element.scroll_horizontal_percent.min(100),
        scroll_vertical_percent: element.scroll_vertical_percent.min(100),
        patterns: element.patterns.into_iter().take(16).collect(),
        value: if element.value_is_password {
            None
        } else {
            element.value
        },
        value_is_password: element.value_is_password,
        children: element.children.into_iter().map(convert_element).collect(),
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
    use std::sync::Mutex;

    struct HostSession {
        child: Child,
        stdin: ChildStdin,
        stdout: BufReader<ChildStdout>,
        next_id: u64,
        negotiated: NegotiatedHost,
    }

    impl HostSession {
        fn spawn(path: &Path) -> Result<Self, UiaError> {
            let mut command = Command::new(path);
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .env_clear();
            for name in ["SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP", "PATH"] {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
            let mut child = command.spawn().map_err(|error| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    format!("computer host could not start: {error}"),
                )
            })?;
            let stdin = child.stdin.take().ok_or_else(|| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host stdin is unavailable",
                )
            })?;
            let stdout = child.stdout.take().ok_or_else(|| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host stdout is unavailable",
                )
            })?;
            let mut session = Self {
                child,
                stdin,
                stdout: BufReader::new(stdout),
                next_id: 1,
                negotiated: NegotiatedHost::v1(),
            };
            let negotiated = negotiate(crate::host_protocol::current_platform(), |protocol| {
                session.hello(protocol)
            })?;
            session.negotiated = negotiated;
            Ok(session)
        }

        fn request(
            &mut self,
            op: &str,
            hwnd: Option<u64>,
            binding: Option<HostTargetBinding>,
            max_nodes: Option<usize>,
            max_depth: Option<usize>,
        ) -> Result<HostResponse, UiaError> {
            let mut request = HostRequest::new(op);
            request.hwnd = hwnd;
            if let (Some(hwnd), Some(binding)) = (hwnd, binding) {
                request.bind_window(hwnd, binding);
            }
            request.max_nodes = max_nodes;
            request.max_depth = max_depth;
            self.send_checked(request)
        }

        /// One hello exchange in an explicit generation, used only while
        /// negotiating. The caller checks protocol and host identity.
        fn hello(&mut self, protocol: &'static str) -> Result<HelloFrame, UiaError> {
            let mut request = HostRequest::new("hello");
            request.protocol = protocol;
            let (id, line) = self.roundtrip(request)?;
            let frame: HelloFrame = serde_json::from_str(&line).map_err(|_| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host returned corrupt JSON",
                )
            })?;
            if frame.id != id {
                return Err(UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host response binding mismatch",
                ));
            }
            Ok(frame)
        }

        fn exchange(&mut self, mut request: HostRequest<'_>) -> Result<HostResponse, UiaError> {
            self.negotiated.require(request.op)?;
            let generation = self.negotiated.generation();
            request.frame_for(generation);
            let (id, line) = self.roundtrip(request)?;
            let response: HostResponse = serde_json::from_str(&line).map_err(|_| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host returned corrupt JSON",
                )
            })?;
            if response.id != id
                || response.protocol != generation.as_str()
                || response.host != HOST_IDENTITY
            {
                return Err(UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host response binding mismatch",
                ));
            }
            let mut response = response;
            if let Some(error) = response.error.as_mut() {
                error.generation = generation;
            }
            Ok(response)
        }

        fn roundtrip(&mut self, mut request: HostRequest<'_>) -> Result<(u64, String), UiaError> {
            let id = self.next_id;
            self.next_id = self.next_id.checked_add(1).ok_or_else(|| {
                UiaError::new(
                    FailureCode::InternalError,
                    "computer host request id overflow",
                )
            })?;
            request.id = id;
            let raw = serde_json::to_vec(&request).map_err(|_| {
                UiaError::new(
                    FailureCode::InternalError,
                    "computer host request serialization failed",
                )
            })?;
            self.stdin.write_all(&raw).map_err(|_| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host request pipe is unavailable",
                )
            })?;
            self.stdin.write_all(b"\n").map_err(|_| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host request framing failed",
                )
            })?;
            self.stdin.flush().map_err(|_| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host request flush failed",
                )
            })?;

            let mut line = String::new();
            let read = self.stdout.read_line(&mut line).map_err(|_| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host response pipe is unavailable",
                )
            })?;
            if read == 0 {
                return Err(UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host exited before returning a response",
                ));
            }
            if line.len() > MAX_HOST_RESPONSE_BYTES {
                return Err(UiaError::new(
                    FailureCode::OutputLimit,
                    "computer host response exceeds the bounded size",
                ));
            }
            Ok((id, line))
        }

        fn send_checked(&mut self, request: HostRequest<'_>) -> Result<HostResponse, UiaError> {
            let response = self.exchange(request)?;
            if !response.ok {
                return Err(response.error.map(map_host_error).unwrap_or_else(|| {
                    UiaError::new(
                        FailureCode::ProviderUnavailable,
                        "computer host failed without typed error",
                    )
                }));
            }
            Ok(response)
        }
    }

    impl Drop for HostSession {
        fn drop(&mut self) {
            let _ = self.request("shutdown", None, None, None, None);
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    pub struct ComputerHostAdapter {
        path: PathBuf,
        session: Mutex<HostSession>,
        bindings: Mutex<BTreeMap<u64, HostTargetBinding>>,
    }

    impl ComputerHostAdapter {
        pub fn from_path(path: impl Into<PathBuf>) -> Result<Self, UiaError> {
            let path = path.into();
            let session = HostSession::spawn(&path)?;
            Ok(Self {
                path,
                session: Mutex::new(session),
                bindings: Mutex::new(BTreeMap::new()),
            })
        }

        pub fn from_env() -> Result<Self, UiaError> {
            let path = std::env::var_os("ORCEL_COMPUTER_HOST_BIN").ok_or_else(|| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "ORCEL_COMPUTER_HOST_BIN is not configured",
                )
            })?;
            Self::from_path(PathBuf::from(path))
        }

        pub fn executable(&self) -> &Path {
            &self.path
        }

        #[cfg(test)]
        pub(crate) fn negotiated_generation_for_test(&self) -> ProtocolGeneration {
            self.session
                .lock()
                .map(|session| session.negotiated.generation())
                .unwrap_or(ProtocolGeneration::V1)
        }

        #[cfg(test)]
        pub(crate) fn ping_for_test(&self) -> Result<(), UiaError> {
            self.request("ping", None, None, None, None).map(|_| ())
        }

        fn request(
            &self,
            op: &str,
            hwnd: Option<u64>,
            binding: Option<HostTargetBinding>,
            max_nodes: Option<usize>,
            max_depth: Option<usize>,
        ) -> Result<HostResponse, UiaError> {
            let mut session = self.session.lock().map_err(|_| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host session lock is poisoned",
                )
            })?;
            session.request(op, hwnd, binding, max_nodes, max_depth)
        }

        fn list_window_facts(&self) -> Result<Vec<HostWindow>, UiaError> {
            let response = self.request("list_windows", None, None, None, None)?;
            let mut bindings = self.bindings.lock().map_err(|_| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host binding cache is poisoned",
                )
            })?;
            bindings.clear();
            for window in &response.windows {
                bindings.insert(
                    window.hwnd,
                    HostTargetBinding {
                        pid: window.process.pid,
                        start_generation: window.process.start_generation,
                        window_nonce: window.window_nonce,
                    },
                );
            }
            Ok(response.windows)
        }

        fn bound_request(
            &self,
            op: &str,
            hwnd: u64,
            max_nodes: Option<usize>,
            max_depth: Option<usize>,
        ) -> Result<HostResponse, UiaError> {
            let binding = self
                .bindings
                .lock()
                .map_err(|_| {
                    UiaError::new(
                        FailureCode::ProviderUnavailable,
                        "computer host binding cache is poisoned",
                    )
                })?
                .get(&hwnd)
                .copied()
                .ok_or_else(|| {
                    UiaError::new(
                        FailureCode::TargetStale,
                        "computer host has no live binding for the requested window; list windows again",
                    )
                })?;
            self.request(op, Some(hwnd), Some(binding), max_nodes, max_depth)
        }

        fn exact_binding(&self, hwnd: u64) -> Result<HostTargetBinding, UiaError> {
            self.bindings
                .lock()
                .map_err(|_| {
                    UiaError::new(
                        FailureCode::ProviderUnavailable,
                        "computer host binding cache is poisoned",
                    )
                })?
                .get(&hwnd)
                .copied()
                .ok_or_else(|| {
                    UiaError::new(
                        FailureCode::TargetStale,
                        "computer host has no live binding for the requested window; list windows again",
                    )
                })
        }

        fn exchange_host(&self, request: HostRequest<'_>) -> Result<HostResponse, UiaError> {
            let mut session = self.session.lock().map_err(|_| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host session lock is poisoned",
                )
            })?;
            session.exchange(request)
        }

        fn checked_host(&self, request: HostRequest<'_>) -> Result<HostResponse, UiaError> {
            let mut session = self.session.lock().map_err(|_| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host session lock is poisoned",
                )
            })?;
            session.send_checked(request)
        }

        pub fn cursor_position(&self) -> Result<DesktopCursorPosition, UiaError> {
            let response = self.checked_host(HostRequest::new("cursor_position"))?;
            let cursor = response.cursor.ok_or_else(|| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host omitted cursor payload",
                )
            })?;
            Ok(DesktopCursorPosition {
                x: cursor.x,
                y: cursor.y,
                screen_width: cursor.screen_width,
                screen_height: cursor.screen_height,
                last_input_tick: cursor.last_input_tick,
            })
        }

        pub fn execute_raw_input(
            &self,
            hwnd: u64,
            action: &DesktopInputAction,
            expected_last_input_tick: u32,
        ) -> Result<DesktopActionResult, UiaError> {
            let binding = self.exact_binding(hwnd)?;
            let mut request = match action {
                DesktopInputAction::Move { x, y } => {
                    let mut request = HostRequest::new("input_move");
                    request.x = Some(*x);
                    request.y = Some(*y);
                    request
                }
                DesktopInputAction::Click {
                    x,
                    y,
                    button,
                    count,
                } => {
                    let mut request = HostRequest::new("input_click");
                    request.x = Some(*x);
                    request.y = Some(*y);
                    request.button = Some(button.as_str());
                    request.click_count = Some(*count);
                    request
                }
                DesktopInputAction::Drag { x, y, to_x, to_y } => {
                    let mut request = HostRequest::new("input_drag");
                    request.x = Some(*x);
                    request.y = Some(*y);
                    request.to_x = Some(*to_x);
                    request.to_y = Some(*to_y);
                    request
                }
                DesktopInputAction::Scroll {
                    x,
                    y,
                    scroll_x,
                    scroll_y,
                } => {
                    let mut request = HostRequest::new("input_scroll");
                    request.x = Some(*x);
                    request.y = Some(*y);
                    request.scroll_x = Some(*scroll_x);
                    request.scroll_y = Some(*scroll_y);
                    request
                }
                DesktopInputAction::TypeText { text } => {
                    let mut request = HostRequest::new("input_type_text");
                    request.text = Some(text.as_str());
                    request
                }
                DesktopInputAction::Key { key } => {
                    let mut request = HostRequest::new("input_key");
                    request.key = Some(key.as_str());
                    request
                }
                DesktopInputAction::Hotkey { key } => {
                    let mut request = HostRequest::new("input_hotkey");
                    request.key = Some(key.as_str());
                    request
                }
            };
            request.bind_window(hwnd, binding);
            request.expected_last_input_tick = Some(expected_last_input_tick);
            let operation = request.op.to_owned();
            let response = self.exchange_host(request)?;
            if response.ok {
                let action = response.action.ok_or_else(|| {
                    UiaError::new(
                        FailureCode::ProviderUnavailable,
                        "computer host omitted action outcome",
                    )
                })?;
                return Ok(DesktopActionResult {
                    state: action.state,
                    action: action.action,
                    message: None,
                });
            }
            let error = response.error.ok_or_else(|| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host failed without typed error",
                )
            })?;
            if matches!(error.code.as_str(), "cancelled" | "outcome_unknown") {
                return Ok(DesktopActionResult {
                    state: error.code,
                    action: operation,
                    message: Some(error.message),
                });
            }
            Err(map_host_error(error))
        }

        pub fn execute_window_action(
            &self,
            hwnd: u64,
            action: DesktopWindowAction,
            expected_last_input_tick: u32,
        ) -> Result<DesktopActionResult, UiaError> {
            let binding = self.exact_binding(hwnd)?;
            let mut request = HostRequest::new("window_action");
            request.bind_window(hwnd, binding);
            request.window_action = Some(action.as_host_str());
            request.expected_last_input_tick = Some(expected_last_input_tick);
            let response = self.exchange_host(request)?;
            if response.ok {
                let action = response.action.ok_or_else(|| {
                    UiaError::new(
                        FailureCode::ProviderUnavailable,
                        "computer host omitted window action outcome",
                    )
                })?;
                return Ok(DesktopActionResult {
                    state: action.state,
                    action: action.action,
                    message: None,
                });
            }
            let error = response.error.ok_or_else(|| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host failed without typed error",
                )
            })?;
            if matches!(error.code.as_str(), "cancelled" | "outcome_unknown") {
                return Ok(DesktopActionResult {
                    state: error.code,
                    action: format!("window_{}", action.as_host_str()),
                    message: Some(error.message),
                });
            }
            Err(map_host_error(error))
        }

        fn semantic_action(
            &self,
            hwnd: u64,
            runtime_id: &str,
            action: &str,
            value: Option<&str>,
            scroll_x: i32,
            scroll_y: i32,
        ) -> Result<(), UiaError> {
            let binding = self.exact_binding(hwnd)?;
            let mut request = HostRequest::new("semantic_action");
            request.bind_window(hwnd, binding);
            request.element_runtime_id = Some(runtime_id);
            request.semantic_action = Some(action);
            request.value = value;
            if scroll_x != 0 {
                request.scroll_x = Some(scroll_x);
            }
            if scroll_y != 0 {
                request.scroll_y = Some(scroll_y);
            }
            let response = self.checked_host(request)?;
            let action = response.action.ok_or_else(|| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host omitted semantic action outcome",
                )
            })?;
            if action.state != "completed" {
                return Err(UiaError::new(
                    FailureCode::PostconditionFailed,
                    "computer host did not complete the semantic action",
                ));
            }
            Ok(())
        }
    }

    impl UiaAdapter for ComputerHostAdapter {
        fn list_processes(&self) -> Result<Vec<NativeProcess>, UiaError> {
            let windows = self.list_window_facts()?;
            let mut processes = BTreeMap::<u32, HostProcess>::new();
            for window in windows {
                processes
                    .entry(window.process.pid)
                    .or_insert(window.process);
            }
            Ok(processes
                .into_values()
                .map(|process| NativeProcess {
                    pid: process.pid,
                    exe_name: process.exe_name,
                    exe_id: process.exe_id,
                    session_id: process.session_id,
                    session_verified: process.session_verified,
                    start_generation: process.start_generation,
                    generation_source: if process.generation_source == "win32-creation-time" {
                        "win32-creation-time"
                    } else {
                        "computer-host"
                    },
                })
                .collect())
        }

        fn list_windows(&self, pid: u32) -> Result<Vec<NativeWindow>, UiaError> {
            let windows = self.list_window_facts()?;
            Ok(windows
                .into_iter()
                .filter(|window| window.process.pid == pid)
                .map(|window| NativeWindow {
                    hwnd: window.hwnd,
                    title: window.title,
                    class: window.class,
                    visible: window.visible,
                    window_nonce: window.window_nonce,
                })
                .collect())
        }

        fn read_tree(&self, hwnd: u64) -> Result<Vec<NativeElement>, UiaError> {
            let response = self.bound_request(
                "observe_window",
                hwnd,
                Some(crate::MAX_TREE_NODES),
                Some(crate::MAX_TREE_DEPTH),
            )?;
            Ok(response.elements.into_iter().map(convert_element).collect())
        }

        fn invoke_element(&self, hwnd: u64, runtime_id: &str) -> Result<(), UiaError> {
            self.semantic_action(hwnd, runtime_id, "invoke", None, 0, 0)
        }

        fn set_value_element(
            &self,
            hwnd: u64,
            runtime_id: &str,
            value: &str,
        ) -> Result<(), UiaError> {
            self.semantic_action(hwnd, runtime_id, "set_value", Some(value), 0, 0)
        }

        fn select_element(
            &self,
            hwnd: u64,
            runtime_id: &str,
            selected: bool,
        ) -> Result<(), UiaError> {
            if !selected {
                return Err(UiaError::new(
                    FailureCode::CapabilityDenied,
                    "computer host semantic select does not widen to deselection",
                ));
            }
            self.semantic_action(hwnd, runtime_id, "select", None, 0, 0)
        }

        fn toggle_element(
            &self,
            hwnd: u64,
            runtime_id: &str,
            _toggled: bool,
        ) -> Result<(), UiaError> {
            self.semantic_action(hwnd, runtime_id, "toggle", None, 0, 0)
        }

        fn scroll_element(
            &self,
            hwnd: u64,
            runtime_id: &str,
            direction: &str,
            amount: u64,
        ) -> Result<(), UiaError> {
            let amount = i32::try_from(amount).map_err(|_| {
                UiaError::new(FailureCode::InvalidRequest, "scroll amount is out of range")
            })?;
            let (scroll_x, scroll_y) = match direction {
                "up" => (0, -amount),
                "down" => (0, amount),
                "left" => (-amount, 0),
                "right" => (amount, 0),
                _ => {
                    return Err(UiaError::new(
                        FailureCode::InvalidRequest,
                        "scroll direction is not mapped",
                    ))
                }
            };
            self.semantic_action(hwnd, runtime_id, "scroll", None, scroll_x, scroll_y)
        }

        fn capture_window(&self, hwnd: u64) -> Result<CapturedImage, UiaError> {
            let response = self.bound_request("capture_window", hwnd, None, None)?;
            let capture = response.capture.ok_or_else(|| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host omitted capture payload",
                )
            })?;
            if capture.pixel_format != "rgba8" {
                return Err(UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host returned an unsupported pixel format",
                ));
            }
            let bytes = decode_base64(&capture.pixels_b64, crate::MAX_CAPTURE_BYTES)?;
            Ok(CapturedImage {
                width: capture.width,
                height: capture.height,
                bytes,
            })
        }
    }
}

#[cfg(windows)]
pub use platform::ComputerHostAdapter;

#[cfg(not(windows))]
pub struct ComputerHostAdapter {
    path: PathBuf,
}

#[cfg(not(windows))]
impl ComputerHostAdapter {
    pub fn from_path(path: impl Into<PathBuf>) -> Result<Self, UiaError> {
        Ok(Self { path: path.into() })
    }

    pub fn from_env() -> Result<Self, UiaError> {
        Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            "computer host is available only on Windows",
        ))
    }

    pub fn executable(&self) -> &Path {
        &self.path
    }

    // The Windows-only methods remain type-visible on other hosts but never
    // acquire desktop, input, or authority capabilities.
    pub fn cursor_position(&self) -> Result<DesktopCursorPosition, UiaError> {
        Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            "computer host is available only on Windows",
        ))
    }

    pub fn execute_raw_input(
        &self,
        _hwnd: u64,
        _action: &DesktopInputAction,
        _expected_last_input_tick: u32,
    ) -> Result<DesktopActionResult, UiaError> {
        Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            "computer host is available only on Windows",
        ))
    }

    pub fn execute_window_action(
        &self,
        _hwnd: u64,
        _action: DesktopWindowAction,
        _expected_last_input_tick: u32,
    ) -> Result<DesktopActionResult, UiaError> {
        Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            "computer host is available only on Windows",
        ))
    }
}

#[cfg(not(windows))]
impl UiaAdapter for ComputerHostAdapter {
    fn list_processes(&self) -> Result<Vec<NativeProcess>, UiaError> {
        Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            "computer host is available only on Windows",
        ))
    }

    fn list_windows(&self, _pid: u32) -> Result<Vec<NativeWindow>, UiaError> {
        Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            "computer host is available only on Windows",
        ))
    }

    fn read_tree(&self, _hwnd: u64) -> Result<Vec<NativeElement>, UiaError> {
        Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            "computer host is available only on Windows",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn windows_desktop_control_fails_closed_on_other_platforms() {
        let adapter = ComputerHostAdapter::from_path("not-a-windows-host").unwrap();
        assert!(adapter.cursor_position().is_err());
        assert!(adapter
            .execute_raw_input(1, &DesktopInputAction::Move { x: 1, y: 1 }, 0)
            .is_err());
        assert!(adapter
            .execute_window_action(1, DesktopWindowAction::Focus, 0)
            .is_err());
    }

    #[test]
    fn base64_decoder_is_bounded_and_strict() {
        assert_eq!(decode_base64("AQIDBA==", 4).unwrap(), vec![1, 2, 3, 4]);
        assert!(decode_base64("AQIDBA==", 3).is_err());
        assert!(decode_base64("AQI*", 4).is_err());
        assert!(decode_base64("A===", 4).is_err());
    }

    #[test]
    fn password_values_are_never_projected() {
        let element = HostElement {
            runtime_id: "1.2".into(),
            control_type: "Edit".into(),
            automation_id: "password".into(),
            name: "Password".into(),
            enabled: true,
            selected: false,
            toggled: false,
            scroll_horizontal_percent: 0,
            scroll_vertical_percent: 0,
            patterns: vec!["Value".into()],
            value: Some("secret".into()),
            value_is_password: true,
            children: Vec::new(),
        };
        assert_eq!(convert_element(element).value, None);
    }

    #[cfg(windows)]
    #[test]
    fn bound_requests_are_framed_per_negotiated_generation() {
        let binding = HostTargetBinding {
            pid: 12,
            start_generation: 13,
            window_nonce: 14,
        };
        let mut v1 = HostRequest::new("observe_window");
        v1.bind_window(11, binding);
        v1.frame_for(ProtocolGeneration::V1);
        assert_eq!(
            serde_json::to_string(&v1).unwrap(),
            r#"{"id":0,"protocol":"orcel-computer-host/1","op":"observe_window","hwnd":11,"expected_pid":12,"expected_start_generation":13,"expected_window_nonce":14}"#
        );
        let mut v2 = HostRequest::new("observe_window");
        v2.bind_window(11, binding);
        v2.frame_for(ProtocolGeneration::V2);
        assert_eq!(
            serde_json::to_string(&v2).unwrap(),
            r#"{"id":0,"protocol":"orcel-computer-host/2","op":"observe_window","window":{"kind":"hwnd","id":11,"expected_pid":12,"expected_start_generation":13,"expected_window_nonce":14}}"#
        );
        let mut unbound = HostRequest::new("cursor_position");
        unbound.frame_for(ProtocolGeneration::V2);
        assert_eq!(
            serde_json::to_string(&unbound).unwrap(),
            r#"{"id":0,"protocol":"orcel-computer-host/2","op":"cursor_position"}"#
        );
    }

    #[cfg(windows)]
    #[test]
    fn configured_host_handshake_is_exact() {
        let Some(path) = std::env::var_os("ORCEL_COMPUTER_HOST_BIN") else {
            return;
        };
        let adapter = ComputerHostAdapter::from_path(PathBuf::from(path)).unwrap();
        assert!(adapter.executable().ends_with("orcel-computer-host.exe"));
        assert_eq!(
            adapter.negotiated_generation_for_test(),
            ProtocolGeneration::V2
        );
        adapter.ping_for_test().unwrap();
    }
}
