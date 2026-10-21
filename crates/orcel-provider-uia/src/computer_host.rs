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
// operation the host does not deliver.
//
// XP-11: the native host also delivers semantic actions, but only while an
// approval bound to the exact target is armed (`authorize_semantic`). The
// adapter takes the armed approval for each action, so one approval covers
// one action, and compares the window's binding (pid, start generation and
// nonce) with the one the approval was armed on. Windows is unchanged.

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

/// XP-12: the most characters one native `input_type_text` types.
pub const NATIVE_MAX_TYPED_CHARS: usize = 256;
/// XP-12: the most wheel lines one native `input_scroll` turns.
pub const NATIVE_MAX_SCROLL_LINES: i32 = 20;
/// XP-12: the most clicks one native `input_click` makes.
pub const NATIVE_MAX_CLICK_COUNT: u8 = 3;
/// XP-12: the shortest time between two native raw input sequences.
pub const NATIVE_MIN_INPUT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// The wire operation a raw input travels as.
fn input_operation(action: &DesktopInputAction) -> &'static str {
    match action {
        DesktopInputAction::Move { .. } => "input_move",
        DesktopInputAction::Click { .. } => "input_click",
        DesktopInputAction::Drag { .. } => "input_drag",
        DesktopInputAction::Scroll { .. } => "input_scroll",
        DesktopInputAction::TypeText { .. } => "input_type_text",
        DesktopInputAction::Key { .. } => "input_key",
        DesktopInputAction::Hotkey { .. } => "input_hotkey",
    }
}

/// XP-12: SHA-256 digest of one exact input sequence (operation and every
/// argument). The approval is armed on it and the adapter spends it against
/// the input it is about to send, so an approval covers exactly one input.
pub fn input_sequence_digest(action: &DesktopInputAction) -> String {
    let material = match action {
        DesktopInputAction::Move { x, y } => format!("move|{x}|{y}"),
        DesktopInputAction::Click {
            x,
            y,
            button,
            count,
        } => format!("click|{x}|{y}|{button}|{count}"),
        DesktopInputAction::Drag { x, y, to_x, to_y } => format!("drag|{x}|{y}|{to_x}|{to_y}"),
        DesktopInputAction::Scroll {
            x,
            y,
            scroll_x,
            scroll_y,
        } => format!("scroll|{x}|{y}|{scroll_x}|{scroll_y}"),
        DesktopInputAction::TypeText { text } => format!("type_text|{}|{text}", text.len()),
        DesktopInputAction::Key { key } => format!("key|{}|{key}", key.len()),
        DesktopInputAction::Hotkey { key } => format!("hotkey|{}|{key}", key.len()),
    };
    crate::digest_hex(&format!("orcel-xp12-input-v1|{material}"), 64)
}

/// XP-12: the limits a native host's raw input stays inside, judged before an
/// approval is armed or spent. Coordinates are window-relative and must not
/// be negative; the host refuses a point outside the live window frame. A
/// hover and a key chord have no bounded native delivery, so they are
/// `capability_denied`; the host holds the list of keys it types.
pub fn check_native_input_limits(action: &DesktopInputAction) -> Result<(), UiaError> {
    let invalid = |message: &str| Err(UiaError::new(FailureCode::InvalidRequest, message));
    let point_ok = |x: i32, y: i32| x >= 0 && y >= 0;
    match action {
        DesktopInputAction::Move { .. } | DesktopInputAction::Hotkey { .. } => Err(UiaError::new(
            FailureCode::CapabilityDenied,
            "a hover and a key chord are not delivered on this platform",
        )),
        DesktopInputAction::Click {
            x,
            y,
            button,
            count,
        } => {
            if !point_ok(*x, *y) {
                return invalid("input coordinates are relative to the window and not negative");
            }
            if !matches!(button.as_str(), "left" | "right") {
                return invalid("native input clicks with the left or right button");
            }
            if !(1..=NATIVE_MAX_CLICK_COUNT).contains(count) {
                return invalid("native input clicks one to three times");
            }
            Ok(())
        }
        DesktopInputAction::Drag { x, y, to_x, to_y } => {
            if !point_ok(*x, *y) || !point_ok(*to_x, *to_y) {
                return invalid("input coordinates are relative to the window and not negative");
            }
            Ok(())
        }
        DesktopInputAction::Scroll {
            x,
            y,
            scroll_x,
            scroll_y,
        } => {
            if !point_ok(*x, *y) {
                return invalid("input coordinates are relative to the window and not negative");
            }
            let one_axis = (*scroll_x == 0) != (*scroll_y == 0);
            let bounded = scroll_x.abs() <= NATIVE_MAX_SCROLL_LINES
                && scroll_y.abs() <= NATIVE_MAX_SCROLL_LINES;
            if !one_axis || !bounded {
                return invalid("native scroll turns one axis by one to twenty lines");
            }
            Ok(())
        }
        DesktopInputAction::TypeText { text } => {
            let count = text.chars().count();
            if count == 0 || count > NATIVE_MAX_TYPED_CHARS || text.chars().any(char::is_control) {
                return invalid(
                    "native typed text is one to 256 characters with no control character",
                );
            }
            Ok(())
        }
        DesktopInputAction::Key { key } => {
            if key.is_empty() || key.len() > 32 || key.contains(['+', '-', ' ']) {
                return invalid("native key input names one key, never a chord");
            }
            Ok(())
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    const HOST_ENV: &[&str] = &["PATH", "LANG", "TMPDIR", "ORCEL_MACOS_BACKGROUND_SPI"];
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

    /// What an approval covered, handed to the adapter by the caller that
    /// consumed it (XP-11). The caller derives every field from the
    /// registry's server-resolved binding, never from the request.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ApprovedSemantic {
        pub hwnd: u64,
        pub runtime_id: String,
        /// `invoke`, `set_value`, `select` or `toggle`.
        pub verb: String,
        /// `value_content_digest` of the text a `set_value` writes.
        pub value_digest: Option<String>,
    }

    /// XP-12: the approval for one raw input sequence on a native host: the
    /// window and the digest of the exact input (`input_sequence_digest`).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ApprovedInput {
        pub hwnd: u64,
        pub digest: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ArmedInput {
        approved: ApprovedInput,
        binding: HostTargetBinding,
    }

    /// An approval armed on the binding the window had when it was granted.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ArmedSemantic {
        approved: ApprovedSemantic,
        binding: HostTargetBinding,
    }

    pub struct ComputerHostAdapter {
        path: PathBuf,
        session: Mutex<HostSession>,
        bindings: Mutex<BTreeMap<u64, HostTargetBinding>>,
        armed: Mutex<Option<ArmedSemantic>>,
        armed_input: Mutex<Option<ArmedInput>>,
        last_input: Mutex<Option<std::time::Instant>>,
    }

    impl ComputerHostAdapter {
        pub fn from_path(path: impl Into<PathBuf>) -> Result<Self, UiaError> {
            let path = path.into();
            let session = HostSession::spawn(&path)?;
            Ok(Self {
                path,
                session: Mutex::new(session),
                bindings: Mutex::new(BTreeMap::new()),
                armed: Mutex::new(None),
                armed_input: Mutex::new(None),
                last_input: Mutex::new(None),
            })
        }

        /// Starts the pinned host the XP-06 path check accepted. The file
        /// is opened and verified (identity, size, digest, owner, mode)
        /// right before the start; on Linux the host is started from that
        /// descriptor, so the path is not resolved again.
        #[cfg(unix)]
        pub fn from_trusted(binary: &crate::TrustedHostBinary) -> Result<Self, UiaError> {
            let path = binary.path().to_path_buf();
            let verified = binary.open_verified()?;
            #[cfg(target_os = "linux")]
            let program = {
                use std::os::fd::AsRawFd;
                PathBuf::from(format!("/proc/self/fd/{}", verified.as_raw_fd()))
            };
            #[cfg(not(target_os = "linux"))]
            let program = path.clone();
            let session = HostSession::spawn(&program)?;
            drop(verified);
            Ok(Self {
                path,
                session: Mutex::new(session),
                bindings: Mutex::new(BTreeMap::new()),
                armed: Mutex::new(None),
                armed_input: Mutex::new(None),
                last_input: Mutex::new(None),
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
                armed: Mutex::new(None),
                armed_input: Mutex::new(None),
                last_input: Mutex::new(None),
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

        /// XP-12 (#404): the route raw input takes on this host, as the
        /// kernel checked it at the handshake (on macOS, the hello's
        /// `macos_background_spi` against orceld's own opt-in). The approval
        /// prompt names it.
        pub fn input_route(&self) -> Result<&'static str, UiaError> {
            let session = self.session.lock().map_err(|_| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host session lock is poisoned",
                )
            })?;
            Ok(session.negotiated.input_route().describe())
        }

        fn require_native_capability(&self, op: &str) -> Result<(), UiaError> {
            self.session
                .lock()
                .map_err(|_| {
                    UiaError::new(
                        FailureCode::ProviderUnavailable,
                        "computer host session lock is poisoned",
                    )
                })?
                .negotiated
                .require(op)
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

        fn is_native(&self) -> Result<bool, UiaError> {
            self.session
                .lock()
                .map(|session| session.negotiated.is_native())
                .map_err(|_| {
                    UiaError::new(
                        FailureCode::ProviderUnavailable,
                        "computer host session lock is poisoned",
                    )
                })
        }

        /// XP-11: arms the one approval that lets the next semantic action
        /// through to a native host. Called after the approval for this exact
        /// target was consumed. The armed approval records the window's host
        /// binding (pid, start generation, nonce) as it is now, replaces any
        /// earlier one, and is used up by the next action whether or not that
        /// action succeeds. A Windows host needs no arming.
        pub fn authorize_semantic(&self, approved: ApprovedSemantic) -> Result<(), UiaError> {
            let binding = self.exact_binding(approved.hwnd)?;
            let mut armed = self.armed.lock().map_err(|_| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host approval slot is poisoned",
                )
            })?;
            *armed = Some(ArmedSemantic { approved, binding });
            Ok(())
        }

        /// Clears any armed approval. The caller that armed it calls this once
        /// the registry call returns, success or not, so an approval whose
        /// action never reached the adapter (a revalidation failure, a lock
        /// error) is not left in the process-wide slot.
        pub fn disarm_semantic(&self) {
            if let Ok(mut armed) = self.armed.lock() {
                *armed = None;
            }
        }

        /// XP-12: arms the one approval that lets the next raw input through
        /// to a native host. It records the digest of the exact input the
        /// approval covers and the window's host binding (pid, start
        /// generation, nonce) as it is now. It replaces any earlier approval
        /// and is used up by the next input whether or not that input
        /// succeeds. A Windows host needs no arming. An input the native
        /// limits refuse is not armed.
        pub fn authorize_input(
            &self,
            hwnd: u64,
            action: &DesktopInputAction,
        ) -> Result<(), UiaError> {
            check_native_input_limits(action)?;
            let binding = self.exact_binding(hwnd)?;
            let approved = ApprovedInput {
                hwnd,
                digest: input_sequence_digest(action),
            };
            let mut armed = self.armed_input.lock().map_err(|_| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host approval slot is poisoned",
                )
            })?;
            *armed = Some(ArmedInput { approved, binding });
            Ok(())
        }

        /// Stamps the end of a raw input sequence for the pacing check.
        fn mark_input_done(&self) {
            if let Ok(mut last) = self.last_input.lock() {
                if last.is_some() {
                    *last = Some(std::time::Instant::now());
                }
            }
        }

        /// Clears any armed input approval; see `disarm_semantic`.
        pub fn disarm_input(&self) {
            if let Ok(mut armed) = self.armed_input.lock() {
                *armed = None;
            }
        }

        /// Spends the armed input approval against the input about to be
        /// sent, then applies the rate limit.
        fn spend_input(
            &self,
            hwnd: u64,
            action: &DesktopInputAction,
            binding: HostTargetBinding,
        ) -> Result<(), UiaError> {
            let armed = self
                .armed_input
                .lock()
                .map_err(|_| {
                    UiaError::new(
                        FailureCode::ProviderUnavailable,
                        "computer host approval slot is poisoned",
                    )
                })?
                .take()
                .ok_or_else(|| {
                    UiaError::new(
                        FailureCode::CapabilityDenied,
                        "raw input on this platform needs an approval bound to its exact target and input",
                    )
                })?;
            if armed.approved.hwnd != hwnd || armed.approved.digest != input_sequence_digest(action)
            {
                return Err(UiaError::new(
                    FailureCode::CapabilityDenied,
                    "the approval covers another window or another input sequence than this input",
                ));
            }
            if armed.binding != binding {
                return Err(UiaError::new(
                    FailureCode::TargetStale,
                    "the window was replaced after the approval was granted",
                ));
            }
            let mut last = self.last_input.lock().map_err(|_| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host input pacing is poisoned",
                )
            })?;
            let now = std::time::Instant::now();
            if last.is_some_and(|earlier| now.duration_since(earlier) < NATIVE_MIN_INPUT_INTERVAL) {
                return Err(UiaError::new(
                    FailureCode::CapabilityDenied,
                    "raw input is rate limited: wait before the next input sequence",
                ));
            }
            *last = Some(now);
            Ok(())
        }

        /// Spends the armed approval against the action about to be sent.
        fn spend_semantic(
            &self,
            hwnd: u64,
            runtime_id: &str,
            verb: &str,
            value: Option<&str>,
            binding: HostTargetBinding,
        ) -> Result<(), UiaError> {
            let armed = self
                .armed
                .lock()
                .map_err(|_| {
                    UiaError::new(
                        FailureCode::ProviderUnavailable,
                        "computer host approval slot is poisoned",
                    )
                })?
                .take()
                .ok_or_else(|| {
                    UiaError::new(
                        FailureCode::CapabilityDenied,
                        "a semantic action on this platform needs an approval bound to its exact target",
                    )
                })?;
            if armed.approved.hwnd != hwnd
                || armed.approved.runtime_id != runtime_id
                || armed.approved.verb != verb
                || armed.approved.value_digest != value.map(crate::value_content_digest)
            {
                return Err(UiaError::new(
                    FailureCode::CapabilityDenied,
                    "the approval covers another window, element, action or value than this action",
                ));
            }
            if armed.binding != binding {
                return Err(UiaError::new(
                    FailureCode::TargetStale,
                    "the window was replaced after the approval was granted",
                ));
            }
            Ok(())
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
            if self.is_native()? {
                // The limits are judged before the capability table and the
                // approval, so a refused input never consumes an approval.
                check_native_input_limits(action)?;
                self.require_native_capability(input_operation(action))?;
                self.spend_input(hwnd, action, binding)?;
            }
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
            let response = self.exchange_host(request);
            // The pacing runs from the end of the last sequence, not from its
            // start: a sequence that took longer than the interval must not
            // let the next one in at once.
            self.mark_input_done();
            let response = response?;
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
            if self.is_native()? {
                // A wheel event at a screen position is the pixel-addressed
                // `input_scroll`, under its own approval; the host refuses it too.
                if action == "scroll" {
                    return Err(UiaError::new(
                        FailureCode::CapabilityDenied,
                        "scroll is delivered as a wheel event at a screen position on this platform; it is pixel-addressed",
                    ));
                }
                // The capability table is checked first, so a host that does
                // not deliver actions never consumes an approval.
                self.require_native_capability("semantic_action")?;
                self.spend_semantic(hwnd, runtime_id, action, value, binding)?;
            }
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
            toggled: bool,
        ) -> Result<(), UiaError> {
            // A native host is told the state the approval asks for, so it
            // acts only when the live element is not already there. The
            // Windows host keeps its frame.
            let wanted = if self.is_native()? {
                Some(if toggled { "true" } else { "false" })
            } else {
                None
            };
            self.semantic_action(hwnd, runtime_id, "toggle", wanted, 0, 0)
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

pub use platform::{ApprovedInput, ApprovedSemantic, ComputerHostAdapter};

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

    /// The table `orcel-native-host` reports when observation works. XP-11:
    /// `semantic_action` is delivered along with observation.
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
                // XP-07: capture follows the window list it is bound by.
                "capture_window" | "semantic_action" if observation == "delivered" => {
                    json!({"support": "delivered", "delivery": "background"})
                }
                "capture_window" | "semantic_action" => {
                    json!({"support": "unavailable", "reason": observation})
                }
                // XP-12: five raw input operations follow the window list.
                "input_click" | "input_drag" | "input_scroll" | "input_type_text" | "input_key"
                    if observation == "delivered" =>
                {
                    json!({"support": "delivered", "delivery": "background"})
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
            // Two RGBA pixels: (224, 17, 157, 255) and (1, 2, 3, 255).
            "capture_window" => Some(native_reply(
                frame,
                json!({"capture": {"width": 2, "height": 1, "pixel_format": "rgba8", "pixels_b64": "4BGd/wECA/8="}}),
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

    /// XP-07: the registry captures one exact window through the native
    /// host. The frame carries the native window kind and binding, the
    /// pixels arrive as sent, and nothing but list and capture is framed.
    #[test]
    fn native_host_capture_is_bound_and_decoded() {
        let (adapter, frames) = scripted("linux", linux_desktop);
        let adapter = adapter.unwrap();
        let mut registry = crate::UiaRegistry::new();
        let listing = registry
            .list_windows(&adapter, "xp07-ws", "xp07-policy")
            .unwrap();
        let window = &listing["windows"][0];
        assert_eq!(window["title"], "Editor");
        let window_id = window["window_id"].as_str().unwrap().to_owned();
        let generation = window["window_generation"].as_u64().unwrap();
        // Display scope never reaches the host.
        let display = registry
            .capture_window(
                &adapter,
                &window_id,
                generation,
                "display",
                "xp07-ws",
                "xp07-policy",
            )
            .unwrap_err();
        assert_eq!(display.code, FailureCode::CapabilityDenied);
        let frame = registry
            .capture_window(
                &adapter,
                &window_id,
                generation,
                crate::CAPTURE_SCOPE_TARGET_WINDOW,
                "xp07-ws",
                "xp07-policy",
            )
            .unwrap();
        assert_eq!(
            (frame["width"].as_u64(), frame["height"].as_u64()),
            (Some(2), Some(1))
        );
        assert_eq!(frame["pixel_format"], "rgba8");
        assert_eq!(frame["pixels_b64"], "4BGd/wECA/8=");
        assert_eq!(frame["scope"], crate::CAPTURE_SCOPE_TARGET_WINDOW);
        let frames = frames.lock().unwrap();
        let capture = frames
            .iter()
            .find(|frame| frame["op"] == "capture_window")
            .unwrap();
        assert_eq!(
            capture["window"],
            json!({"kind": "x11", "id": 11, "expected_pid": 4410, "expected_start_generation": 133702, "expected_window_nonce": 99})
        );
        assert!(capture.get("hwnd").is_none());
        let sent: Vec<_> = frames
            .iter()
            .map(|frame| frame["op"].as_str().unwrap_or_default())
            .collect();
        assert!(
            sent.iter()
                .all(|op| matches!(*op, "hello" | "list_windows" | "capture_window")),
            "{sent:?}"
        );
        assert_eq!(sent.iter().filter(|op| **op == "capture_window").count(), 1);
    }

    /// A native frame in another pixel format, or whose pixels do not match
    /// its geometry, is refused; nothing is converted or scaled.
    #[test]
    fn native_capture_with_foreign_format_or_size_is_refused() {
        for capture in [
            json!({"width": 2, "height": 1, "pixel_format": "bgra8", "pixels_b64": "4BGd/wECA/8="}),
            json!({"width": 7681, "height": 1, "pixel_format": "rgba8", "pixels_b64": "4BGd/wECA/8="}),
            json!({"width": 3, "height": 1, "pixel_format": "rgba8", "pixels_b64": "4BGd/wECA/8="}),
        ] {
            let (adapter, _frames) = scripted("linux", move |frame| match frame["op"].as_str() {
                Some("capture_window") => {
                    Some(native_reply(frame, json!({ "capture": capture.clone() })))
                }
                _ => linux_desktop(frame),
            });
            let adapter = adapter.unwrap();
            let mut registry = crate::UiaRegistry::new();
            let listing = registry.list_windows(&adapter, "ws", "policy").unwrap();
            let window = &listing["windows"][0];
            let error = registry
                .capture_window(
                    &adapter,
                    window["window_id"].as_str().unwrap(),
                    window["window_generation"].as_u64().unwrap(),
                    crate::CAPTURE_SCOPE_TARGET_WINDOW,
                    "ws",
                    "policy",
                )
                .unwrap_err();
            assert!(
                matches!(
                    error.code,
                    FailureCode::ProviderUnavailable
                        | FailureCode::InvalidRequest
                        | FailureCode::OutputLimit
                ),
                "{error:?}"
            );
        }
    }

    #[test]
    fn native_host_mutations_are_refused_before_any_frame() {
        let (adapter, frames) = scripted("linux", linux_desktop);
        let adapter = adapter.unwrap();
        assert_eq!(adapter.list_processes().unwrap().len(), 1);
        // A hover and a chord have no bounded native delivery.
        for action in [
            DesktopInputAction::Move { x: 1, y: 1 },
            DesktopInputAction::Hotkey {
                key: "ctrl+c".into(),
            },
        ] {
            let error = adapter.execute_raw_input(11, &action, 0).unwrap_err();
            assert_eq!(error.code, FailureCode::CapabilityDenied, "{error:?}");
        }
        let error = adapter
            .execute_window_action(11, DesktopWindowAction::Focus, 0)
            .unwrap_err();
        assert_eq!(error.code, FailureCode::ProviderUnavailable, "{error:?}");
        assert!(error.message.contains("does not deliver"), "{error:?}");
        // XP-12: raw input is delivered, but not without an approval armed on
        // the exact window and input.
        let unapproved = adapter.execute_raw_input(11, &click(1, 1), 0).unwrap_err();
        assert_eq!(unapproved.code, FailureCode::CapabilityDenied);
        assert!(unapproved.message.contains("approval"), "{unapproved:?}");
        // XP-11: the host delivers semantic actions, but not without an
        // approval armed on the exact target.
        let unapproved = adapter.invoke_element(11, "1:1").unwrap_err();
        assert_eq!(unapproved.code, FailureCode::CapabilityDenied);
        assert!(unapproved.message.contains("approval"), "{unapproved:?}");
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
        // XP-07 review: the XP-09 SOFT approval is an untitled
        // UserNotificationCenter alert, refused by its owner alone; the
        // other system alert and authentication agents likewise.
        for class in [
            "UserNotificationCenter",
            "com.apple.UserNotificationCenter",
            "universalAccessAuthWarn",
            "CoreServicesUIAgent",
            "LocalAuthenticationRemoteService",
            "coreautha",
            "loginwindow",
        ] {
            assert_eq!(
                crate::is_protected_window("", class),
                cfg!(target_os = "macos"),
                "{class}"
            );
        }
        assert!(!crate::is_protected_window("Editor", "gedit"));
    }

    /// The registry never lists an untitled UserNotificationCenter alert,
    /// so it can be neither observed nor captured (macOS).
    #[cfg(target_os = "macos")]
    #[test]
    fn user_notification_center_alerts_are_omitted_from_the_registry() {
        let (adapter, _frames) = scripted("macos", |frame| match frame["op"].as_str() {
            Some("hello") => Some(native_reply(
                frame,
                json!({"platform": "macos", "backend": "ax", "capabilities": observing_table("delivered")}),
            )),
            Some("list_windows") => {
                let mut alert = window_fact(13, "");
                alert["class"] = json!("UserNotificationCenter");
                alert["process"]["exe_name"] = json!("UserNotificationCenter");
                Some(native_reply(
                    frame,
                    json!({"windows": [window_fact(11, "Editor"), alert]}),
                ))
            }
            _ => linux_desktop(frame),
        });
        let adapter = adapter.unwrap();
        let mut registry = crate::UiaRegistry::new();
        let listing = registry.list_windows(&adapter, "ws", "policy").unwrap();
        let windows = listing["windows"].as_array().unwrap();
        assert_eq!(windows.len(), 1, "{listing}");
        assert_eq!(windows[0]["title"], "Editor");
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

    /// A Linux desktop whose host also delivers semantic actions. `nonce`
    /// is the window nonce the listing reports, so a test can replace the
    /// window between the approval and the action.
    fn acting_desktop(
        nonce: Arc<std::sync::atomic::AtomicU64>,
    ) -> impl FnMut(&Value) -> Option<String> + Send + 'static {
        move |frame| match frame["op"].as_str().unwrap_or_default() {
            "list_windows" => {
                let mut window = window_fact(11, "Editor");
                window["window_nonce"] = json!(nonce.load(std::sync::atomic::Ordering::SeqCst));
                Some(native_reply(frame, json!({ "windows": [window] })))
            }
            "semantic_action" => Some(native_reply(
                frame,
                json!({"action": {
                    "state": "completed",
                    "action": format!("semantic_{}", frame["semantic_action"].as_str().unwrap_or_default())
                }}),
            )),
            "input_click" | "input_drag" | "input_scroll" | "input_type_text" | "input_key" => {
                Some(native_reply(
                    frame,
                    json!({"action": {
                        "state": "completed",
                        "action": frame["op"].as_str().unwrap_or_default()
                    }}),
                ))
            }
            _ => linux_desktop(frame),
        }
    }

    fn input_ops(frames: &Frames) -> Vec<Value> {
        frames
            .lock()
            .unwrap()
            .iter()
            .filter(|frame| {
                frame["op"]
                    .as_str()
                    .is_some_and(|op| op.starts_with("input_"))
            })
            .cloned()
            .collect()
    }

    fn click(x: i32, y: i32) -> DesktopInputAction {
        DesktopInputAction::Click {
            x,
            y,
            button: "left".into(),
            count: 1,
        }
    }

    /// XP-12: a raw input reaches a native host only under an approval armed
    /// on the exact window and the exact input; one approval is one input;
    /// another input, window or replaced window does not carry over; and a
    /// hover or chord is never delivered.
    #[test]
    fn native_raw_input_is_sent_only_under_an_armed_exact_approval() {
        let nonce = Arc::new(std::sync::atomic::AtomicU64::new(99));
        let (adapter, frames) = scripted("linux", acting_desktop(nonce.clone()));
        let adapter = adapter.unwrap();
        assert_eq!(adapter.list_processes().unwrap().len(), 1);

        // Unapproved: refused before any frame.
        let error = adapter.execute_raw_input(11, &click(4, 5), 7).unwrap_err();
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        assert!(input_ops(&frames).is_empty());

        // The approval for exactly this input lets one frame through, with
        // the human-input tick bound and window-relative coordinates.
        adapter.authorize_input(11, &click(4, 5)).unwrap();
        let done = adapter.execute_raw_input(11, &click(4, 5), 7).unwrap();
        assert_eq!(done.state, "completed");
        let sent = input_ops(&frames);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["op"], "input_click");
        assert_eq!(
            (sent[0]["x"].as_i64(), sent[0]["y"].as_i64()),
            (Some(4), Some(5))
        );
        assert_eq!(sent[0]["expected_last_input_tick"], 7);
        assert_eq!(
            sent[0]["window"],
            json!({"kind": "x11", "id": 11, "expected_pid": 4410, "expected_start_generation": 133702, "expected_window_nonce": 99})
        );

        // A replayed approval is refused: one approval, one input.
        std::thread::sleep(NATIVE_MIN_INPUT_INTERVAL);
        let replay = adapter.execute_raw_input(11, &click(4, 5), 7).unwrap_err();
        assert_eq!(replay.code, FailureCode::CapabilityDenied);
        assert_eq!(input_ops(&frames).len(), 1);

        // An approval for another point, button, input or window does not
        // carry over, and a refused attempt still uses the approval up.
        let other_button = DesktopInputAction::Click {
            x: 4,
            y: 5,
            button: "right".into(),
            count: 1,
        };
        for (armed_for, run) in [
            (click(4, 5), click(4, 6)),
            (click(4, 5), other_button),
            (
                click(4, 5),
                DesktopInputAction::Key {
                    key: "Enter".into(),
                },
            ),
            (
                DesktopInputAction::TypeText { text: "ab".into() },
                DesktopInputAction::TypeText { text: "abc".into() },
            ),
        ] {
            adapter.authorize_input(11, &armed_for).unwrap();
            let error = adapter.execute_raw_input(11, &run, 7).unwrap_err();
            assert_eq!(error.code, FailureCode::CapabilityDenied, "{run:?}");
            let spent = adapter.execute_raw_input(11, &armed_for, 7).unwrap_err();
            assert_eq!(spent.code, FailureCode::CapabilityDenied);
        }
        // An unlisted window cannot be armed.
        assert_eq!(
            adapter.authorize_input(12, &click(4, 5)).unwrap_err().code,
            FailureCode::TargetStale
        );
        assert_eq!(input_ops(&frames).len(), 1);

        // A window replaced after the approval voids it.
        std::thread::sleep(NATIVE_MIN_INPUT_INTERVAL);
        adapter.authorize_input(11, &click(4, 5)).unwrap();
        nonce.store(100, std::sync::atomic::Ordering::SeqCst);
        adapter.list_processes().unwrap();
        let stale = adapter.execute_raw_input(11, &click(4, 5), 7).unwrap_err();
        assert_eq!(stale.code, FailureCode::TargetStale);
        assert_eq!(input_ops(&frames).len(), 1);

        // Disarming leaves nothing to spend.
        adapter.authorize_input(11, &click(4, 5)).unwrap();
        adapter.disarm_input();
        let none = adapter.execute_raw_input(11, &click(4, 5), 7).unwrap_err();
        assert_eq!(none.code, FailureCode::CapabilityDenied);
    }

    /// XP-12: an over-cap or malformed input is refused before an approval is
    /// armed, so it consumes nothing, and a hover and a chord are not served.
    #[test]
    fn native_raw_input_limits_are_judged_before_any_approval() {
        let (adapter, frames) = scripted(
            "linux",
            acting_desktop(Arc::new(std::sync::atomic::AtomicU64::new(99))),
        );
        let adapter = adapter.unwrap();
        adapter.list_processes().unwrap();
        let long = "a".repeat(NATIVE_MAX_TYPED_CHARS + 1);
        let refused = [
            (click(-1, 5), FailureCode::InvalidRequest),
            (click(5, -1), FailureCode::InvalidRequest),
            (
                DesktopInputAction::Click {
                    x: 1,
                    y: 1,
                    button: "middle".into(),
                    count: 1,
                },
                FailureCode::InvalidRequest,
            ),
            (
                DesktopInputAction::Click {
                    x: 1,
                    y: 1,
                    button: "left".into(),
                    count: 4,
                },
                FailureCode::InvalidRequest,
            ),
            (
                DesktopInputAction::Click {
                    x: 1,
                    y: 1,
                    button: "left".into(),
                    count: 0,
                },
                FailureCode::InvalidRequest,
            ),
            (
                DesktopInputAction::Drag {
                    x: 1,
                    y: 1,
                    to_x: -3,
                    to_y: 4,
                },
                FailureCode::InvalidRequest,
            ),
            (
                DesktopInputAction::Scroll {
                    x: 1,
                    y: 1,
                    scroll_x: 0,
                    scroll_y: 21,
                },
                FailureCode::InvalidRequest,
            ),
            (
                DesktopInputAction::Scroll {
                    x: 1,
                    y: 1,
                    scroll_x: 1,
                    scroll_y: 1,
                },
                FailureCode::InvalidRequest,
            ),
            (
                DesktopInputAction::Scroll {
                    x: 1,
                    y: 1,
                    scroll_x: 0,
                    scroll_y: 0,
                },
                FailureCode::InvalidRequest,
            ),
            (
                DesktopInputAction::TypeText { text: long },
                FailureCode::InvalidRequest,
            ),
            (
                DesktopInputAction::TypeText {
                    text: String::new(),
                },
                FailureCode::InvalidRequest,
            ),
            (
                DesktopInputAction::TypeText {
                    text: "a\nb".into(),
                },
                FailureCode::InvalidRequest,
            ),
            (
                DesktopInputAction::Key {
                    key: "cmd+q".into(),
                },
                FailureCode::InvalidRequest,
            ),
            (
                DesktopInputAction::Key {
                    key: "ctrl-alt-delete".into(),
                },
                FailureCode::InvalidRequest,
            ),
            (
                DesktopInputAction::Key { key: String::new() },
                FailureCode::InvalidRequest,
            ),
            (
                DesktopInputAction::Move { x: 1, y: 1 },
                FailureCode::CapabilityDenied,
            ),
            (
                DesktopInputAction::Hotkey {
                    key: "cmd+c".into(),
                },
                FailureCode::CapabilityDenied,
            ),
        ];
        for (action, code) in refused {
            assert_eq!(
                adapter.authorize_input(11, &action).unwrap_err().code,
                code,
                "{action:?}"
            );
            assert_eq!(
                adapter.execute_raw_input(11, &action, 1).unwrap_err().code,
                code,
                "{action:?}"
            );
        }
        // The largest bounded text is accepted.
        let longest = "é".repeat(NATIVE_MAX_TYPED_CHARS);
        adapter
            .authorize_input(
                11,
                &DesktopInputAction::TypeText {
                    text: longest.clone(),
                },
            )
            .unwrap();
        adapter
            .execute_raw_input(11, &DesktopInputAction::TypeText { text: longest }, 1)
            .unwrap();
        assert_eq!(input_ops(&frames).len(), 1);
    }

    /// XP-12: raw input is paced; a second sequence inside the interval is
    /// refused even with its own approval, and nothing is framed for it.
    #[test]
    fn native_raw_input_is_rate_limited() {
        let (adapter, frames) = scripted(
            "linux",
            acting_desktop(Arc::new(std::sync::atomic::AtomicU64::new(99))),
        );
        let adapter = adapter.unwrap();
        adapter.list_processes().unwrap();
        adapter.authorize_input(11, &click(1, 1)).unwrap();
        adapter.execute_raw_input(11, &click(1, 1), 1).unwrap();
        adapter.authorize_input(11, &click(2, 2)).unwrap();
        let error = adapter.execute_raw_input(11, &click(2, 2), 1).unwrap_err();
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        assert!(error.message.contains("rate limited"), "{error:?}");
        assert_eq!(input_ops(&frames).len(), 1);
        std::thread::sleep(NATIVE_MIN_INPUT_INTERVAL);
        adapter.authorize_input(11, &click(2, 2)).unwrap();
        adapter.execute_raw_input(11, &click(2, 2), 1).unwrap();
        assert_eq!(input_ops(&frames).len(), 2);
    }

    /// XP-12: a native host that does not deliver input (its hello refuses
    /// it, or lists the window system as unavailable) never consumes an
    /// approval and never gets a frame.
    #[test]
    fn a_native_host_that_refuses_input_gets_no_frame() {
        let (adapter, frames) = scripted("linux", |frame| match frame["op"].as_str() {
            Some("hello") => {
                let mut table = observing_table("delivered");
                table["input_click"] =
                    json!({"support": "unavailable", "reason": "provider_unavailable"});
                Some(native_reply(
                    frame,
                    json!({"platform": "linux", "backend": "atspi-x11", "capabilities": table}),
                ))
            }
            _ => linux_desktop(frame),
        });
        let adapter = adapter.unwrap();
        adapter.list_processes().unwrap();
        adapter.authorize_input(11, &click(1, 1)).unwrap();
        let error = adapter.execute_raw_input(11, &click(1, 1), 1).unwrap_err();
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
        assert!(input_ops(&frames).is_empty());
    }

    /// #404: the adapter names the route the handshake settled, for the
    /// approval prompt; a macOS host whose SPI report the kernel could not
    /// match names none and delivers no raw input.
    #[test]
    fn the_adapter_names_the_negotiated_input_route() {
        let (adapter, _) = scripted("linux", |frame| match frame["op"].as_str() {
            Some("hello") => Some(native_hello(frame, "delivered")),
            _ => linux_desktop(frame),
        });
        let route = adapter.unwrap().input_route().unwrap();
        assert!(route.starts_with("x11-"), "{route}");
        let (adapter, frames) = scripted("macos", |frame| match frame["op"].as_str() {
            Some("hello") => Some(native_reply(
                frame,
                json!({"platform": "macos", "backend": "ax", "capabilities": observing_table("delivered")}),
            )),
            _ => linux_desktop(frame),
        });
        let adapter = adapter.unwrap();
        assert_eq!(adapter.input_route().unwrap(), "none");
        adapter.list_processes().unwrap();
        adapter.authorize_input(11, &click(1, 1)).unwrap();
        let error = adapter.execute_raw_input(11, &click(1, 1), 1).unwrap_err();
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
        assert!(
            error.message.contains("macos_background_spi_unreported"),
            "{error:?}"
        );
        assert!(input_ops(&frames).is_empty());
    }

    #[test]
    fn the_input_digest_separates_every_argument() {
        let base = input_sequence_digest(&click(4, 5));
        for other in [
            click(5, 4),
            DesktopInputAction::Click {
                x: 4,
                y: 5,
                button: "right".into(),
                count: 1,
            },
            DesktopInputAction::Click {
                x: 4,
                y: 5,
                button: "left".into(),
                count: 2,
            },
            DesktopInputAction::Key {
                key: "Enter".into(),
            },
            DesktopInputAction::TypeText {
                text: "Enter".into(),
            },
        ] {
            assert_ne!(input_sequence_digest(&other), base, "{other:?}");
        }
        assert_eq!(input_sequence_digest(&click(4, 5)), base);
        // A text that imitates the fields of another input stays distinct.
        assert_ne!(
            input_sequence_digest(&DesktopInputAction::TypeText { text: "x|y".into() }),
            input_sequence_digest(&DesktopInputAction::Key { key: "x|y".into() })
        );
    }

    fn semantic_ops(frames: &Frames) -> Vec<Value> {
        frames
            .lock()
            .unwrap()
            .iter()
            .filter(|frame| frame["op"] == "semantic_action")
            .cloned()
            .collect()
    }

    fn approved(hwnd: u64, runtime_id: &str, verb: &str, value: Option<&str>) -> ApprovedSemantic {
        ApprovedSemantic {
            hwnd,
            runtime_id: runtime_id.to_owned(),
            verb: verb.to_owned(),
            value_digest: value.map(crate::value_content_digest),
        }
    }

    /// XP-11: on a native host a semantic action is sent only while an
    /// approval bound to that exact window, element, verb and value is armed;
    /// the frame names the window and element and nothing pixel-addressed.
    #[test]
    fn native_semantic_action_is_sent_only_under_an_armed_exact_approval() {
        let nonce = Arc::new(std::sync::atomic::AtomicU64::new(99));
        let (adapter, frames) = scripted("linux", acting_desktop(nonce));
        let adapter = adapter.unwrap();
        assert_eq!(adapter.list_processes().unwrap().len(), 1);

        // No approval: refused before any frame.
        let error = adapter.invoke_element(11, "1:1").unwrap_err();
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        assert!(semantic_ops(&frames).is_empty());

        // The approval for exactly this action lets one frame through.
        adapter
            .authorize_semantic(approved(11, "1:1", "invoke", None))
            .unwrap();
        adapter.invoke_element(11, "1:1").unwrap();
        let sent = semantic_ops(&frames);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["semantic_action"], "invoke");
        assert_eq!(sent[0]["element_runtime_id"], "1:1");
        assert_eq!(
            sent[0]["window"],
            json!({"kind": "x11", "id": 11, "expected_pid": 4410, "expected_start_generation": 133702, "expected_window_nonce": 99})
        );
        for field in [
            "x",
            "y",
            "to_x",
            "to_y",
            "button",
            "click_count",
            "text",
            "key",
        ] {
            assert!(sent[0].get(field).is_none(), "{field}");
        }

        // One approval is one action.
        let again = adapter.invoke_element(11, "1:1").unwrap_err();
        assert_eq!(again.code, FailureCode::CapabilityDenied);
        assert_eq!(semantic_ops(&frames).len(), 1);

        // An approval for another element, verb or window does not carry
        // over, and a refused attempt still uses the approval up.
        for (arm, run) in [
            (approved(11, "1:2", "invoke", None), "invoke:1:1"),
            (approved(11, "1:1", "toggle", None), "invoke:1:1"),
            (approved(12, "1:1", "invoke", None), "invoke:1:1"),
        ] {
            if arm.hwnd == 11 {
                adapter.authorize_semantic(arm).unwrap();
                let error = adapter.invoke_element(11, "1:1").unwrap_err();
                assert_eq!(error.code, FailureCode::CapabilityDenied, "{run}");
                let spent = adapter.invoke_element(11, "1:1").unwrap_err();
                assert!(spent.message.contains("approval"), "{spent:?}");
            } else {
                // A window the adapter has never listed cannot be armed.
                let error = adapter.authorize_semantic(arm).unwrap_err();
                assert_eq!(error.code, FailureCode::TargetStale);
            }
        }
        assert_eq!(semantic_ops(&frames).len(), 1);
    }

    #[test]
    fn a_set_value_approval_covers_exactly_the_approved_text() {
        let nonce = Arc::new(std::sync::atomic::AtomicU64::new(99));
        let (adapter, frames) = scripted("linux", acting_desktop(nonce));
        let adapter = adapter.unwrap();
        adapter.list_processes().unwrap();
        adapter
            .authorize_semantic(approved(11, "1:1", "set_value", Some("approved text")))
            .unwrap();
        let error = adapter
            .set_value_element(11, "1:1", "different text")
            .unwrap_err();
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        assert!(semantic_ops(&frames).is_empty());
        adapter
            .authorize_semantic(approved(11, "1:1", "set_value", Some("approved text")))
            .unwrap();
        adapter
            .set_value_element(11, "1:1", "approved text")
            .unwrap();
        let sent = semantic_ops(&frames);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["semantic_action"], "set_value");
        assert_eq!(sent[0]["value"], "approved text");
        // An approval for another verb never covers a value write, and a
        // value approval never covers a click.
        adapter
            .authorize_semantic(approved(11, "1:1", "invoke", None))
            .unwrap();
        assert_eq!(
            adapter
                .set_value_element(11, "1:1", "approved text")
                .unwrap_err()
                .code,
            FailureCode::CapabilityDenied
        );
        adapter
            .authorize_semantic(approved(11, "1:1", "set_value", Some("approved text")))
            .unwrap();
        assert_eq!(
            adapter.invoke_element(11, "1:1").unwrap_err().code,
            FailureCode::CapabilityDenied
        );
        assert_eq!(semantic_ops(&frames).len(), 1);
    }

    /// The approval is armed on the window as the host bound it. If the
    /// window is replaced (a new nonce) before the action, the action fails
    /// closed as `TargetStale` and is not sent.
    #[test]
    fn a_replaced_window_voids_the_armed_approval() {
        let nonce = Arc::new(std::sync::atomic::AtomicU64::new(99));
        let (adapter, frames) = scripted("linux", acting_desktop(nonce.clone()));
        let adapter = adapter.unwrap();
        adapter.list_processes().unwrap();
        adapter
            .authorize_semantic(approved(11, "1:1", "toggle", Some("true")))
            .unwrap();
        // The window id is reused by another window; a listing sees it.
        nonce.store(100, std::sync::atomic::Ordering::SeqCst);
        adapter.list_processes().unwrap();
        let error = adapter.toggle_element(11, "1:1", true).unwrap_err();
        assert_eq!(error.code, FailureCode::TargetStale, "{error:?}");
        assert!(semantic_ops(&frames).is_empty());
        // Re-arming on the new window works.
        adapter
            .authorize_semantic(approved(11, "1:1", "toggle", Some("true")))
            .unwrap();
        adapter.toggle_element(11, "1:1", true).unwrap();
        let sent = semantic_ops(&frames);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["window"]["expected_window_nonce"], 100);
    }

    /// Scroll is a wheel event at a position on these platforms: refused by
    /// the adapter without a frame, approval or not (XP-12).
    #[test]
    fn native_scroll_is_refused_without_a_frame() {
        let nonce = Arc::new(std::sync::atomic::AtomicU64::new(99));
        let (adapter, frames) = scripted("linux", acting_desktop(nonce));
        let adapter = adapter.unwrap();
        adapter.list_processes().unwrap();
        adapter
            .authorize_semantic(approved(11, "1:1", "scroll", None))
            .unwrap();
        let error = adapter.scroll_element(11, "1:1", "down", 3).unwrap_err();
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        assert!(error.message.contains("pixel-addressed"), "{error:?}");
        assert!(semantic_ops(&frames).is_empty());
    }

    /// A native host that does not deliver actions never sees one, and the
    /// refusal does not spend an approval.
    #[test]
    fn a_native_host_that_does_not_deliver_actions_gets_no_frame() {
        let (adapter, frames) = scripted("linux", |frame| match frame["op"].as_str() {
            Some("hello") => Some(native_hello(frame, "permission_missing")),
            _ => Some(native_reply(frame, json!({}))),
        });
        let adapter = adapter.unwrap();
        let error = adapter.invoke_element(11, "1:1").unwrap_err();
        // Without a live binding the window is unknown before anything else.
        assert_eq!(error.code, FailureCode::TargetStale);
        assert_eq!(ops(&frames), vec!["hello"]);
    }

    /// Windows keeps its behavior: no approval is armed, and the action goes
    /// to the host as before.
    #[test]
    fn windows_semantic_actions_need_no_arming() {
        let windows_reply = |frame: &Value, body: Value| {
            let mut reply = json!({
                "id": frame["id"],
                "ok": true,
                "protocol": "orcel-computer-host/2",
                "host": "orcel-windows-computer-host",
            });
            if let (Some(reply), Some(body)) = (reply.as_object_mut(), body.as_object()) {
                reply.extend(body.clone());
            }
            reply.to_string()
        };
        let (adapter, frames) = scripted("windows", move |frame| match frame["op"].as_str() {
            Some("hello") => Some(windows_reply(
                frame,
                json!({
                    "platform": "windows",
                    "backend": "uia",
                    "capabilities": {
                        "list_windows": {"support": "delivered"},
                        "semantic_action": {"support": "delivered", "delivery": "background"}
                    }
                }),
            )),
            Some("list_windows") => Some(windows_reply(
                frame,
                json!({"windows": [window_fact(11, "Editor")]}),
            )),
            Some("semantic_action") => Some(windows_reply(
                frame,
                json!({"action": {"state": "completed", "action": "semantic_invoke"}}),
            )),
            _ => Some(windows_reply(frame, json!({}))),
        });
        let adapter = adapter.unwrap();
        adapter.list_processes().unwrap();
        adapter.invoke_element(11, "1.2.3").unwrap();
        let sent = semantic_ops(&frames);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["window"]["kind"], "hwnd");
    }

    /// A toggle names the state it asks for, the approval covers exactly
    /// that state, and the frame carries it so the host never flips blindly.
    #[test]
    fn a_toggle_approval_covers_the_requested_state_and_the_frame_carries_it() {
        let nonce = Arc::new(std::sync::atomic::AtomicU64::new(99));
        let (adapter, frames) = scripted("linux", acting_desktop(nonce));
        let adapter = adapter.unwrap();
        adapter.list_processes().unwrap();
        adapter
            .authorize_semantic(approved(11, "1:1", "toggle", Some("true")))
            .unwrap();
        let error = adapter.toggle_element(11, "1:1", false).unwrap_err();
        assert_eq!(error.code, FailureCode::CapabilityDenied, "{error:?}");
        assert!(semantic_ops(&frames).is_empty());
        adapter
            .authorize_semantic(approved(11, "1:1", "toggle", Some("true")))
            .unwrap();
        adapter.toggle_element(11, "1:1", true).unwrap();
        let sent = semantic_ops(&frames);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["semantic_action"], "toggle");
        assert_eq!(sent[0]["value"], "true");
    }

    /// The caller that armed an approval clears it when the registry call
    /// fails before the adapter is reached, so nothing is left armed.
    #[test]
    fn a_disarmed_approval_cannot_be_spent() {
        let nonce = Arc::new(std::sync::atomic::AtomicU64::new(99));
        let (adapter, frames) = scripted("linux", acting_desktop(nonce));
        let adapter = adapter.unwrap();
        adapter.list_processes().unwrap();
        adapter
            .authorize_semantic(approved(11, "1:1", "invoke", None))
            .unwrap();
        // The registry refused the call (a stale tree, say): nothing reached
        // the adapter. The caller disarms.
        adapter.disarm_semantic();
        let error = adapter.invoke_element(11, "1:1").unwrap_err();
        assert_eq!(error.code, FailureCode::CapabilityDenied, "{error:?}");
        assert!(error.message.contains("approval"), "{error:?}");
        assert!(semantic_ops(&frames).is_empty());
        // Disarming with nothing armed is harmless.
        adapter.disarm_semantic();
    }

    /// A registry refusal leaves an armed approval behind unless the caller
    /// disarms it: this is the sequence orceld runs.
    #[test]
    fn a_registry_failure_followed_by_disarm_leaves_nothing_armed() {
        let nonce = Arc::new(std::sync::atomic::AtomicU64::new(99));
        let (adapter, frames) = scripted("linux", acting_desktop(nonce));
        let adapter = adapter.unwrap();
        let mut registry = crate::UiaRegistry::new();
        registry.list_windows(&adapter, "ws", "pol").unwrap();
        adapter
            .authorize_semantic(approved(11, "1:1", "invoke", None))
            .unwrap();
        let refused = registry
            .invoke_element(&adapter, "no-such-element", 1, "Button", "ws", "pol")
            .unwrap_err();
        assert_ne!(refused.code, FailureCode::ProviderUnavailable);
        adapter.disarm_semantic();
        assert_eq!(
            adapter.invoke_element(11, "1:1").unwrap_err().code,
            FailureCode::CapabilityDenied
        );
        assert!(semantic_ops(&frames).is_empty());
    }
}
