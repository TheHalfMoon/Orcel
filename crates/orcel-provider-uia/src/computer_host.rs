// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//
// SG-000094 private Computer Host adapter. The adapter is deliberately not the
// default NativeAdapter and adds no caller-facing MCP surface. It only
// translates host OS facts/pixels into the existing UiaAdapter contract.
//
// XP-06: the same adapter serves the Windows host (`orcel-computer-host`) and
// the macOS and Linux host (`orcel-native-host`), selected by
// ORCEL_COMPUTER_HOST_BIN on every OS. The negotiated hello fixes the host
// identity every response must echo and the window kind bound requests carry;
// the capability table makes the adapter refuse, before sending anything, an
// operation the host does not deliver (the native host is observation only).

use crate::{CapturedImage, NativeElement, NativeProcess, NativeWindow, UiaAdapter, UiaError};
use orcel_contracts::FailureCode;
use serde::{Deserialize, Serialize};
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

use crate::host_protocol::{
    map_refusal_code, negotiate, HelloFrame, NegotiatedHost, ProtocolGeneration, PROTOCOL_V1,
};

const MAX_HOST_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

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

/// The `/2` platform-tagged window reference, of the kind the negotiated
/// backend serves (`hwnd`, `cgwindow`, `x11` or `wl_toplevel`).
#[derive(Debug, Serialize)]
struct HostWindowRef {
    kind: &'static str,
    id: u64,
    expected_pid: u32,
    expected_start_generation: u64,
    expected_window_nonce: u64,
}

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
    fn frame_for(&mut self, generation: ProtocolGeneration, kind: &'static str) {
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
                kind,
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

#[derive(Debug, Deserialize)]
struct HostError {
    code: String,
    message: String,
    /// The generation of the session that received this refusal. Set by the
    /// session after decoding; it selects the refusal mapping.
    #[serde(skip)]
    generation: ProtocolGeneration,
}

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

#[derive(Debug, Deserialize, Clone)]
struct HostWindow {
    process: HostProcess,
    hwnd: u64,
    title: String,
    class: String,
    visible: bool,
    window_nonce: u64,
}

#[derive(Debug, Clone, Copy)]
struct HostTargetBinding {
    pid: u32,
    start_generation: u64,
    window_nonce: u64,
}

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

#[derive(Debug, Deserialize)]
struct HostCapture {
    width: u32,
    height: u32,
    pixel_format: String,
    pixels_b64: String,
}

#[derive(Debug, Deserialize)]
struct HostCursor {
    x: i32,
    y: i32,
    screen_width: i32,
    screen_height: i32,
    last_input_tick: u32,
}

#[derive(Debug, Deserialize)]
struct HostAction {
    state: String,
    action: String,
}

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

fn map_host_error(error: HostError) -> UiaError {
    UiaError::new(
        map_refusal_code(error.generation, &error.code),
        error.message,
    )
}

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

mod platform {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, Command, Stdio};
    use std::sync::Mutex;

    /// The environment the host inherits, by name; everything else is
    /// cleared. Windows is unchanged from `/1`. On Linux these are what X11,
    /// Wayland and AT-SPI clients read; on macOS only the basics.
    #[cfg(windows)]
    const HOST_ENV: &[&str] = &["SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP", "PATH"];
    #[cfg(target_os = "macos")]
    const HOST_ENV: &[&str] = &["PATH", "LANG", "TMPDIR"];
    #[cfg(not(any(windows, target_os = "macos")))]
    const HOST_ENV: &[&str] = &[
        "PATH",
        "LANG",
        "HOME",
        "DISPLAY",
        "XAUTHORITY",
        "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_SESSION_TYPE",
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_DESKTOP",
        "DESKTOP_SESSION",
        "SWAYSOCK",
        "KDE_FULL_SESSION",
    ];

    pub(super) type HostWriter = Box<dyn Write + Send>;
    pub(super) type HostReader = Box<dyn BufRead + Send>;

    struct HostSession {
        child: Option<Child>,
        stdin: HostWriter,
        stdout: HostReader,
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
            for name in HOST_ENV {
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
            Self::over(
                Some(child),
                Box::new(stdin),
                Box::new(BufReader::new(stdout)),
                crate::host_protocol::current_platform(),
            )
        }

        /// Negotiates over an established transport. A failed handshake
        /// drops the session, which ends the host.
        fn over(
            child: Option<Child>,
            stdin: HostWriter,
            stdout: HostReader,
            platform: &str,
        ) -> Result<Self, UiaError> {
            let mut session = Self {
                child,
                stdin,
                stdout,
                next_id: 1,
                negotiated: NegotiatedHost::v1(),
            };
            let negotiated = negotiate(platform, |protocol| session.hello(protocol))?;
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
            request.frame_for(generation, self.negotiated.window_kind());
            let (id, line) = self.roundtrip(request)?;
            let response: HostResponse = serde_json::from_str(&line).map_err(|_| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host returned corrupt JSON",
                )
            })?;
            if response.id != id
                || response.protocol != generation.as_str()
                || response.host != self.negotiated.identity()
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
            if let Some(child) = self.child.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
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

        /// An adapter over a scripted transport, negotiated for `platform`.
        #[cfg(test)]
        pub(crate) fn over_transport(
            stdin: HostWriter,
            stdout: HostReader,
            platform: &str,
        ) -> Result<Self, UiaError> {
            let session = HostSession::over(None, stdin, stdout, platform)?;
            Ok(Self {
                path: PathBuf::from("scripted-host"),
                session: Mutex::new(session),
                bindings: Mutex::new(BTreeMap::new()),
            })
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
                    generation_source: match process.generation_source.as_str() {
                        "win32-creation-time" => "win32-creation-time",
                        "linux-proc-starttime" => "linux-proc-starttime",
                        "macos-bsd-start-time" => "macos-bsd-start-time",
                        _ => "computer-host",
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

pub use platform::ComputerHostAdapter;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::io::{BufRead, Read, Write};
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::sync::{Arc, Mutex};

    #[test]
    fn missing_host_binary_is_unavailable() {
        let error = ComputerHostAdapter::from_path("definitely-not-an-orcel-host-binary")
            .err()
            .expect("spawn fails");
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
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

    #[test]
    fn bound_requests_are_framed_per_negotiated_generation() {
        let binding = HostTargetBinding {
            pid: 12,
            start_generation: 13,
            window_nonce: 14,
        };
        let mut v1 = HostRequest::new("observe_window");
        v1.bind_window(11, binding);
        v1.frame_for(ProtocolGeneration::V1, "hwnd");
        assert_eq!(
            serde_json::to_string(&v1).unwrap(),
            r#"{"id":0,"protocol":"orcel-computer-host/1","op":"observe_window","hwnd":11,"expected_pid":12,"expected_start_generation":13,"expected_window_nonce":14}"#
        );
        let mut v2 = HostRequest::new("observe_window");
        v2.bind_window(11, binding);
        v2.frame_for(ProtocolGeneration::V2, "hwnd");
        assert_eq!(
            serde_json::to_string(&v2).unwrap(),
            r#"{"id":0,"protocol":"orcel-computer-host/2","op":"observe_window","window":{"kind":"hwnd","id":11,"expected_pid":12,"expected_start_generation":13,"expected_window_nonce":14}}"#
        );
        for kind in ["cgwindow", "x11", "wl_toplevel"] {
            let mut native = HostRequest::new("observe_window");
            native.bind_window(11, binding);
            native.frame_for(ProtocolGeneration::V2, kind);
            assert_eq!(
                serde_json::to_string(&native).unwrap(),
                format!(
                    r#"{{"id":0,"protocol":"orcel-computer-host/2","op":"observe_window","window":{{"kind":"{kind}","id":11,"expected_pid":12,"expected_start_generation":13,"expected_window_nonce":14}}}}"#
                )
            );
        }
        let mut unbound = HostRequest::new("cursor_position");
        unbound.frame_for(ProtocolGeneration::V2, "x11");
        assert_eq!(
            serde_json::to_string(&unbound).unwrap(),
            r#"{"id":0,"protocol":"orcel-computer-host/2","op":"cursor_position"}"#
        );
    }

    /// The adapter's end of an in-memory pipe to a scripted host thread.
    struct PipeWriter(Sender<Vec<u8>>);

    impl Write for PipeWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .send(buf.to_vec())
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct PipeReader {
        receiver: Receiver<Vec<u8>>,
        buffer: Vec<u8>,
        position: usize,
    }

    impl Read for PipeReader {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let available = self.fill_buf()?;
            let count = available.len().min(out.len());
            out[..count].copy_from_slice(&available[..count]);
            self.consume(count);
            Ok(count)
        }
    }

    impl BufRead for PipeReader {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            if self.position >= self.buffer.len() {
                self.buffer = self.receiver.recv().unwrap_or_default();
                self.position = 0;
            }
            Ok(&self.buffer[self.position..])
        }

        fn consume(&mut self, amount: usize) {
            self.position += amount;
        }
    }

    type Frames = Arc<Mutex<Vec<Value>>>;

    /// Connects an adapter, negotiated for `platform`, to a host thread that
    /// answers each frame with `answer` (`None` hangs up).
    fn scripted(
        platform: &str,
        mut answer: impl FnMut(&Value) -> Option<String> + Send + 'static,
    ) -> (Result<ComputerHostAdapter, UiaError>, Frames) {
        let (to_host, from_adapter) = channel::<Vec<u8>>();
        let (to_adapter, from_host) = channel::<Vec<u8>>();
        let frames: Frames = Arc::new(Mutex::new(Vec::new()));
        let seen = frames.clone();
        std::thread::spawn(move || {
            let mut pending = Vec::new();
            while let Ok(chunk) = from_adapter.recv() {
                pending.extend_from_slice(&chunk);
                while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                    let line: Vec<u8> = pending.drain(..=end).collect();
                    let frame: Value = serde_json::from_slice(&line[..end]).unwrap();
                    seen.lock().unwrap().push(frame.clone());
                    let Some(mut reply) = answer(&frame) else {
                        return;
                    };
                    reply.push('\n');
                    if to_adapter.send(reply.into_bytes()).is_err() {
                        return;
                    }
                }
            }
        });
        let adapter = ComputerHostAdapter::over_transport(
            Box::new(PipeWriter(to_host)),
            Box::new(PipeReader {
                receiver: from_host,
                buffer: Vec::new(),
                position: 0,
            }),
            platform,
        );
        (adapter, frames)
    }

    fn native_reply(frame: &Value, body: Value) -> String {
        let mut reply = json!({
            "id": frame["id"],
            "ok": true,
            "protocol": "orcel-computer-host/2",
            "host": "orcel-native-host",
        });
        if let (Some(reply), Some(body)) = (reply.as_object_mut(), body.as_object()) {
            reply.extend(body.clone());
        }
        reply.to_string()
    }

    fn native_refusal(frame: &Value, code: &str) -> String {
        json!({
            "id": frame["id"],
            "ok": false,
            "protocol": "orcel-computer-host/2",
            "host": "orcel-native-host",
            "error": {"code": code, "message": format!("refused: {code}")},
        })
        .to_string()
    }

    /// The table `orcel-native-host` reports when observation works.
    fn observing_table(observation: &str) -> Value {
        let mut table = serde_json::Map::new();
        for op in crate::host_protocol::V1_OPERATIONS {
            let entry = match op {
                "hello" | "ping" | "shutdown" | "cursor_position" => {
                    json!({"support": "delivered"})
                }
                "list_windows" | "observe_window" if observation == "delivered" => {
                    json!({"support": "delivered"})
                }
                "list_windows" | "observe_window" => {
                    json!({"support": "unavailable", "reason": observation})
                }
                "capture_window" => {
                    json!({"support": "unavailable", "reason": "provider_unavailable"})
                }
                _ => json!({"support": "refused", "reason": "capability_denied"}),
            };
            table.insert(op.to_owned(), entry);
        }
        Value::Object(table)
    }

    fn native_hello(frame: &Value, observation: &str) -> String {
        native_reply(
            frame,
            json!({
                "platform": "linux",
                "backend": "atspi-x11",
                "capabilities": observing_table(observation),
            }),
        )
    }

    const SECRET: &str = "hunter2-xp06-secret";

    fn window_fact(hwnd: u64, title: &str) -> Value {
        json!({
            "process": {
                "pid": 4410,
                "exe_name": "gedit",
                "exe_id": "00112233445566778899aabbccddeeff",
                "session_id": 0,
                "session_verified": false,
                "start_generation": 133702,
                "generation_source": "linux-proc-starttime"
            },
            "hwnd": hwnd,
            "title": title,
            "class": "gedit",
            "visible": true,
            "window_nonce": 99
        })
    }

    fn element(
        runtime_id: &str,
        control_type: &str,
        name: &str,
        value: Option<&str>,
        password: bool,
        children: Vec<Value>,
    ) -> Value {
        json!({
            "runtime_id": runtime_id,
            "control_type": control_type,
            "automation_id": "",
            "name": name,
            "enabled": true,
            "selected": false,
            "toggled": false,
            "scroll_horizontal_percent": 0,
            "scroll_vertical_percent": 0,
            "patterns": [],
            "value": value,
            "value_is_password": password,
            "children": children
        })
    }

    /// A Linux native host: two windows (one a protected Orcel surface), a
    /// tree with a plain field and a password field, and a cursor.
    fn linux_desktop(frame: &Value) -> Option<String> {
        match frame["op"].as_str().unwrap_or_default() {
            "hello" => Some(native_hello(frame, "delivered")),
            "list_windows" => Some(native_reply(
                frame,
                json!({"windows": [window_fact(11, "Editor"), window_fact(12, "Orcel Approval Probe 7")]}),
            )),
            "observe_window" => Some(native_reply(
                frame,
                json!({"elements": [element("1:0", "Window", "Editor", None, false, vec![
                    element("1:1", "Edit", "Name", Some("visible text"), false, Vec::new()),
                    element("1:2", "Edit", "Sign in", Some(SECRET), true, Vec::new()),
                ])]}),
            )),
            "cursor_position" => Some(native_reply(
                frame,
                json!({"cursor": {"x": 5, "y": 6, "screen_width": 1280, "screen_height": 800, "last_input_tick": 0}}),
            )),
            "ping" | "shutdown" => Some(native_reply(frame, json!({}))),
            _ => Some(native_refusal(frame, "capability_denied")),
        }
    }

    fn ops(frames: &Frames) -> Vec<String> {
        frames
            .lock()
            .unwrap()
            .iter()
            .map(|frame| frame["op"].as_str().unwrap_or_default().to_owned())
            .collect()
    }

    #[test]
    fn native_host_observation_is_bound_redacted_and_excludes_protected_surfaces() {
        let (adapter, frames) = scripted("linux", linux_desktop);
        let adapter = adapter.unwrap();
        assert_eq!(
            adapter.negotiated_generation_for_test(),
            ProtocolGeneration::V2
        );
        let mut registry = crate::UiaRegistry::new();
        let listing = registry
            .list_windows(&adapter, "xp06-ws", "xp06-policy")
            .unwrap();
        assert!(listing["protected_omitted"].as_u64().unwrap() >= 1);
        let windows = listing["windows"].as_array().unwrap();
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0]["title"], "Editor");
        let window_id = windows[0]["window_id"].as_str().unwrap().to_owned();
        let generation = windows[0]["window_generation"].as_u64().unwrap();
        let tree = registry
            .observe_tree(
                &adapter,
                &window_id,
                generation,
                None,
                None,
                "xp06-ws",
                "xp06-policy",
            )
            .unwrap();
        let rendered = tree.to_string();
        assert!(!rendered.contains(SECRET), "{rendered}");
        let nodes = tree["nodes"].as_array().unwrap();
        assert!(nodes.iter().any(|node| node["value"] == "visible text"));
        let hidden = nodes
            .iter()
            .find(|node| node["value_is_password"] == true)
            .unwrap();
        assert_eq!(hidden["redacted"], true);
        assert!(hidden["value"].is_null());

        // The bound frame carried the native window kind, not legacy fields.
        let frames = frames.lock().unwrap();
        let observe = frames
            .iter()
            .find(|frame| frame["op"] == "observe_window")
            .unwrap();
        assert_eq!(observe["protocol"], "orcel-computer-host/2");
        assert_eq!(
            observe["window"],
            json!({"kind": "x11", "id": 11, "expected_pid": 4410, "expected_start_generation": 133702, "expected_window_nonce": 99})
        );
        assert!(observe.get("hwnd").is_none());
    }

    #[test]
    fn native_host_mutations_and_capture_are_refused_before_any_frame() {
        let (adapter, frames) = scripted("linux", linux_desktop);
        let adapter = adapter.unwrap();
        assert_eq!(adapter.list_processes().unwrap().len(), 1);
        let refused = [
            adapter
                .execute_raw_input(11, &DesktopInputAction::Move { x: 1, y: 1 }, 0)
                .unwrap_err(),
            adapter
                .execute_window_action(11, DesktopWindowAction::Focus, 0)
                .unwrap_err(),
            adapter.invoke_element(11, "1:1").unwrap_err(),
            adapter.capture_window(11).unwrap_err(),
        ];
        for error in &refused {
            assert_eq!(error.code, FailureCode::ProviderUnavailable, "{error:?}");
            assert!(error.message.contains("does not deliver"), "{error:?}");
        }
        let cursor = adapter.cursor_position().unwrap();
        assert_eq!((cursor.x, cursor.y, cursor.screen_width), (5, 6, 1280));
        let sent = ops(&frames);
        assert!(
            sent.iter()
                .all(|op| matches!(op.as_str(), "hello" | "list_windows" | "cursor_position")),
            "{sent:?}"
        );
    }

    #[test]
    fn missing_permission_makes_observation_unavailable_without_a_frame() {
        let (adapter, frames) = scripted("linux", |frame| match frame["op"].as_str() {
            Some("hello") => Some(native_hello(frame, "permission_missing")),
            _ => Some(native_reply(frame, json!({}))),
        });
        let adapter = adapter.unwrap();
        let error = adapter.list_processes().unwrap_err();
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
        assert!(error.message.contains("permission_missing"), "{error:?}");
        assert_eq!(ops(&frames), vec!["hello"]);
    }

    #[test]
    fn native_refusals_map_onto_existing_failure_codes() {
        for (code, expected) in [
            ("target_stale", FailureCode::TargetStale),
            ("timeout", FailureCode::ProcessTimeout),
            ("permission_missing", FailureCode::ProviderUnavailable),
            ("protected_surface", FailureCode::CapabilityDenied),
            ("output_limit", FailureCode::OutputLimit),
            ("provider_unavailable", FailureCode::ProviderUnavailable),
        ] {
            let (adapter, _) = scripted("linux", move |frame| match frame["op"].as_str() {
                Some("observe_window") => Some(native_refusal(frame, code)),
                _ => linux_desktop(frame),
            });
            let adapter = adapter.unwrap();
            adapter.list_processes().unwrap();
            assert_eq!(adapter.read_tree(11).unwrap_err().code, expected, "{code}");
        }
    }

    #[test]
    fn responses_must_echo_the_native_identity() {
        let (adapter, _) = scripted("linux", |frame| match frame["op"].as_str() {
            Some("list_windows") => Some(
                native_reply(frame, json!({"windows": []}))
                    .replace("orcel-native-host", "orcel-windows-computer-host"),
            ),
            _ => linux_desktop(frame),
        });
        let error = adapter.unwrap().list_processes().unwrap_err();
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
        assert!(error.message.contains("binding mismatch"), "{error:?}");
    }

    #[test]
    fn oversize_native_response_is_output_limit() {
        let (adapter, _) = scripted("linux", |frame| match frame["op"].as_str() {
            Some("list_windows") => Some(native_reply(
                frame,
                json!({"windows": [], "padding": "x".repeat(MAX_HOST_RESPONSE_BYTES)}),
            )),
            _ => linux_desktop(frame),
        });
        let error = adapter.unwrap().list_processes().unwrap_err();
        assert_eq!(error.code, FailureCode::OutputLimit);
    }

    #[test]
    fn native_host_that_refuses_v2_is_unavailable_without_v1_fallback() {
        let (adapter, frames) = scripted("linux", |frame| {
            Some(
                json!({
                    "id": frame["id"], "ok": false, "protocol": "orcel-computer-host/1",
                    "host": "orcel-native-host",
                    "error": {"code": "invalid_request", "message": "protocol generation mismatch"}
                })
                .to_string(),
            )
        });
        let error = adapter.err().expect("handshake fails");
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
        let hellos: Vec<_> = frames
            .lock()
            .unwrap()
            .iter()
            .filter(|frame| frame["op"] == "hello")
            .map(|frame| frame["protocol"].as_str().unwrap_or_default().to_owned())
            .collect();
        assert_eq!(hellos, vec!["orcel-computer-host/2"]);
    }

    #[test]
    fn host_crash_during_hello_is_unavailable() {
        let (adapter, _) = scripted("macos", |_| None);
        assert_eq!(
            adapter.err().expect("no host").code,
            FailureCode::ProviderUnavailable
        );
    }

    #[test]
    fn windows_v1_host_keeps_its_legacy_framing() {
        let (adapter, frames) = scripted("windows", |frame| {
            let protocol = frame["protocol"].as_str().unwrap_or_default();
            let mut reply = json!({
                "id": frame["id"], "ok": true, "protocol": "orcel-computer-host/1",
                "host": "orcel-windows-computer-host",
            });
            if protocol == "orcel-computer-host/2" {
                reply["ok"] = json!(false);
                reply["error"] =
                    json!({"code": "invalid_request", "message": "protocol generation mismatch"});
            } else if frame["op"] == "list_windows" {
                let mut window = window_fact(11, "Editor");
                window["process"]["generation_source"] = json!("win32-creation-time");
                reply["windows"] = json!([window]);
            } else if frame["op"] == "observe_window" {
                reply["elements"] = json!([]);
            }
            Some(reply.to_string())
        });
        let adapter = adapter.unwrap();
        assert_eq!(
            adapter.negotiated_generation_for_test(),
            ProtocolGeneration::V1
        );
        adapter.list_processes().unwrap();
        adapter.read_tree(11).unwrap();
        let frames = frames.lock().unwrap();
        let observe = frames
            .iter()
            .find(|frame| frame["op"] == "observe_window")
            .unwrap();
        assert_eq!(observe["hwnd"], 11);
        assert!(observe.get("window").is_none());
    }

    #[test]
    fn os_authentication_and_lock_surfaces_are_protected_per_platform() {
        assert!(crate::is_protected_window("Orcel Approval", "any"));
        assert_eq!(
            crate::is_protected_window("Authenticate", "polkit-gnome-authentication-agent-1"),
            cfg!(all(unix, not(target_os = "macos")))
        );
        assert_eq!(
            crate::is_protected_window("", "SecurityAgent"),
            cfg!(target_os = "macos")
        );
        assert!(!crate::is_protected_window("Editor", "gedit"));
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

    #[cfg(not(windows))]
    #[test]
    fn configured_native_host_handshake_is_exact() {
        let Some(path) = std::env::var_os("ORCEL_COMPUTER_HOST_BIN") else {
            return;
        };
        let adapter = ComputerHostAdapter::from_path(PathBuf::from(path)).unwrap();
        assert!(adapter.executable().ends_with("orcel-native-host"));
        assert_eq!(
            adapter.negotiated_generation_for_test(),
            ProtocolGeneration::V2
        );
        adapter.ping_for_test().unwrap();
        let error = adapter
            .execute_raw_input(1, &DesktopInputAction::Move { x: 1, y: 1 }, 0)
            .unwrap_err();
        assert_ne!(error.code, FailureCode::InternalError);
    }
}
