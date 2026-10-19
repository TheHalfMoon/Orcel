// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! The one-shot sacrificial worker (`orcel-native-host --worker`).
//!
//! It reads one request the supervisor already validated, validates it
//! again, runs exactly one observation through [`crate::cua_adapter`],
//! writes one response line and exits. All AX and AT-SPI work happens here,
//! so a hang or crash in the accessibility stack costs one worker, never
//! the supervisor. The worker never retries and never falls back to another
//! route.
//!
//! The worker answers `hello` too: the supervisor forwards it so the
//! permission and session probes run here, never in the supervisor.

use crate::cua_adapter::{CuaCall, CuaFailure, CuaRuntime};
use crate::map::{self, Omission, ProcessIdentity};
use crate::protocol::{
    self, code, Availability, CursorFact, HostPlatform, ProcessFact, Request, Response,
    MAX_REQUEST_BYTES,
};
use cua_driver_contract::{
    GetCursorPositionInput, GetScreenSizeInput, ListWindowsOutput, WindowElement,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::process::ExitCode;

/// Longest refusal message the worker sends.
const MAX_MESSAGE_CHARS: usize = 512;

pub fn main() -> ExitCode {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    match run(stdin.lock(), stdout.lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(2),
    }
}

/// Reads one request line, answers it and returns.
pub fn run(input: impl BufRead, mut output: impl Write) -> std::io::Result<()> {
    let mut line = Vec::new();
    input
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_until(b'\n', &mut line)?;
    if line.len() > MAX_REQUEST_BYTES {
        return Err(std::io::Error::other("worker request exceeds the bound"));
    }
    let platform = HostPlatform::current();
    let response = match protocol::decode_request(trim_line(&line), platform) {
        Err(refusal) => *refusal.0,
        Ok(request) => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(answer(&request, platform))
        }
    };
    let mut raw = protocol::encode_bounded(&response);
    raw.push(b'\n');
    output.write_all(&raw)?;
    output.flush()
}

fn trim_line(line: &[u8]) -> &[u8] {
    let end = line
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(0, |index| index + 1);
    &line[..end]
}

fn bounded_message(message: &str) -> String {
    map::bound_chars(message, MAX_MESSAGE_CHARS)
}

async fn answer(request: &Request, platform: HostPlatform) -> Response {
    let runtime = CuaRuntime::new();
    let availability = probe(&runtime, platform).await;
    if request.op == "hello" {
        return protocol::hello(request.id, platform, &availability);
    }
    if let Some(reason) = availability.refusal_for(&request.op) {
        return Response::failure(
            request.id,
            reason,
            format!("{} is unavailable on this machine ({reason})", request.op),
        );
    }
    match request.op.as_str() {
        "list_windows" => list_windows(&runtime, request, platform).await,
        "observe_window" => observe_window(&runtime, request, platform).await,
        "cursor_position" => cursor_position(&runtime, request).await,
        _ => Response::failure(
            request.id,
            code::CAPABILITY_DENIED,
            "supervisor-only operation is not executable in a native worker",
        ),
    }
}

/// Which observations can work here. macOS needs Accessibility and Screen
/// Recording for window listing and trees (titles are Screen Recording
/// gated, and protected-surface checks need them); the cursor needs neither.
/// Linux needs a display, and a session bus for AT-SPI. Nothing prompts.
async fn probe(runtime: &CuaRuntime, platform: HostPlatform) -> Availability {
    if platform == protocol::MACOS {
        return match runtime.call(&CuaCall::CheckPermissions).await {
            Ok(status) => macos_availability(&status),
            Err(_) => {
                let mut availability = Availability::none(code::PROVIDER_UNAVAILABLE);
                availability.cursor_position = None;
                availability
            }
        };
    }
    linux_availability(platform, &LinuxSession::from_env())
}

/// macOS availability from Cua's `check_permissions` structured result.
pub fn macos_availability(status: &Value) -> Availability {
    let granted = |key: &str| status.get(key).and_then(Value::as_bool) == Some(true);
    let accessibility = granted("accessibility");
    let screen_recording = granted("screen_recording");
    let observation = if accessibility && screen_recording {
        None
    } else {
        Some(code::PERMISSION_MISSING.to_owned())
    };
    let mut permissions = BTreeMap::new();
    permissions.insert("accessibility".to_owned(), accessibility);
    permissions.insert("screen_recording".to_owned(), screen_recording);
    Availability {
        list_windows: observation.clone(),
        observe_window: observation,
        cursor_position: None,
        permissions,
    }
}

/// The session facts the Linux probe reads from the worker's environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinuxSession {
    pub display: bool,
    pub wayland_display: bool,
    pub session_bus: bool,
}

impl LinuxSession {
    fn from_env() -> Self {
        let set = |name: &str| std::env::var_os(name).is_some_and(|value| !value.is_empty());
        Self {
            display: set("DISPLAY"),
            wayland_display: set("WAYLAND_DISPLAY"),
            session_bus: set("DBUS_SESSION_BUS_ADDRESS"),
        }
    }
}

/// Linux availability: no display means nothing works; no session bus
/// means no AT-SPI, so no window list or tree. On Wayland the pointer
/// position is not observable by a client (Cua reports only its own
/// synthetic moves), so the cursor is unavailable there.
pub fn linux_availability(platform: HostPlatform, session: &LinuxSession) -> Availability {
    let display = if platform == protocol::LINUX_WAYLAND {
        session.wayland_display
    } else {
        session.display
    };
    if !display {
        return Availability::none(code::PROVIDER_UNAVAILABLE);
    }
    let tree = (!session.session_bus).then(|| code::PROVIDER_UNAVAILABLE.to_owned());
    Availability {
        list_windows: tree.clone(),
        observe_window: tree,
        cursor_position: (platform == protocol::LINUX_WAYLAND)
            .then(|| code::PROVIDER_UNAVAILABLE.to_owned()),
        permissions: BTreeMap::new(),
    }
}

/// Why the live facts of a pid cannot back a window binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityRefusal {
    /// The process exited, or its pid now names another instance.
    Gone,
    /// The process runs as another user, or is a protected executable.
    Excluded,
    /// The facts could not be read.
    Unreadable,
}

fn process_identity(pid: u32) -> Result<ProcessIdentity, IdentityRefusal> {
    use orcel_platform::PlatformError;
    let generation = |pid| {
        orcel_platform::process::start_generation(pid).map_err(|error| match error {
            PlatformError::ProcessGone(_) => IdentityRefusal::Gone,
            _ => IdentityRefusal::Unreadable,
        })
    };
    let before = generation(pid)?;
    if facts::owner_uid(pid)? != orcel_platform::session::effective_uid() {
        return Err(IdentityRefusal::Excluded);
    }
    let path = facts::executable_path(pid).ok_or(IdentityRefusal::Unreadable)?;
    // The path and uid must describe the instance the generation names.
    if generation(pid)? != before {
        return Err(IdentityRefusal::Gone);
    }
    let exe_name = std::path::Path::new(&path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    if exe_name.is_empty() {
        return Err(IdentityRefusal::Unreadable);
    }
    if map::is_protected_executable(&exe_name) {
        return Err(IdentityRefusal::Excluded);
    }
    let (session_id, session_verified) = facts::session_of(pid);
    Ok(ProcessIdentity {
        fact: ProcessFact {
            pid,
            exe_name: map::bound_chars(&exe_name, map::MAX_NAME_CHARS),
            exe_id: map::exe_id(&path),
            session_id,
            session_verified,
            start_generation: before.generation,
            generation_source: before.source.to_owned(),
        },
        boot_id: before.boot_id,
    })
}

#[cfg(target_os = "linux")]
mod facts {
    use super::IdentityRefusal;

    pub(super) fn owner_uid(pid: u32) -> Result<Option<u32>, IdentityRefusal> {
        orcel_platform::process::effective_uid_of(pid)
            .map(Some)
            .map_err(|error| match error {
                orcel_platform::PlatformError::ProcessGone(_) => IdentityRefusal::Gone,
                _ => IdentityRefusal::Unreadable,
            })
    }

    pub(super) fn executable_path(pid: u32) -> Option<String> {
        let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        let path = path.to_string_lossy().into_owned();
        Some(
            path.strip_suffix(" (deleted)")
                .map(str::to_owned)
                .unwrap_or(path),
        )
    }

    /// The target's audit session, verified when it is this host's own.
    pub(super) fn session_of(pid: u32) -> (u32, bool) {
        const UNSET: u32 = u32::MAX;
        let read = |path: String| {
            std::fs::read_to_string(path)
                .ok()
                .and_then(|text| text.trim().parse::<u32>().ok())
                .filter(|session| *session != UNSET)
        };
        match read(format!("/proc/{pid}/sessionid")) {
            Some(session) => (
                session,
                read("/proc/self/sessionid".to_owned()) == Some(session),
            ),
            None => (0, false),
        }
    }
}

#[cfg(target_os = "macos")]
mod facts {
    use super::IdentityRefusal;

    pub(super) fn owner_uid(pid: u32) -> Result<Option<u32>, IdentityRefusal> {
        orcel_platform::process::effective_uid_of(pid)
            .map(Some)
            .map_err(|error| match error {
                orcel_platform::PlatformError::ProcessGone(_) => IdentityRefusal::Gone,
                _ => IdentityRefusal::Unreadable,
            })
    }

    pub(super) fn executable_path(pid: u32) -> Option<String> {
        let raw_pid = libc::pid_t::try_from(pid).ok()?;
        let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: the buffer is live, writable and exactly `buffer.len()`
        // bytes long, the size passed; proc_pidpath writes at most that many
        // bytes and reads no other memory of this process.
        let written =
            unsafe { libc::proc_pidpath(raw_pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
        if written <= 0 {
            return None;
        }
        buffer.truncate(written as usize);
        String::from_utf8(buffer).ok()
    }

    /// macOS has no per-pid audit session read without privileges; the
    /// same-user check above is the binding.
    pub(super) fn session_of(_pid: u32) -> (u32, bool) {
        (0, false)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod facts {
    use super::IdentityRefusal;

    pub(super) fn owner_uid(_pid: u32) -> Result<Option<u32>, IdentityRefusal> {
        Err(IdentityRefusal::Unreadable)
    }

    pub(super) fn executable_path(_pid: u32) -> Option<String> {
        None
    }

    pub(super) fn session_of(_pid: u32) -> (u32, bool) {
        (0, false)
    }
}

fn cua_unavailable(id: u64, failure: &CuaFailure) -> Response {
    Response::failure(
        id,
        code::PROVIDER_UNAVAILABLE,
        bounded_message(&failure.message),
    )
}

async fn live_windows(
    runtime: &CuaRuntime,
    pid: Option<u32>,
) -> Result<ListWindowsOutput, CuaFailure> {
    let value = runtime.call(&CuaCall::list_windows(pid)).await?;
    serde_json::from_value(value).map_err(|error| CuaFailure {
        message: format!("the Cua window list did not match its contract: {error}"),
        structured: None,
    })
}

async fn list_windows(runtime: &CuaRuntime, request: &Request, platform: HostPlatform) -> Response {
    let listed = match live_windows(runtime, None).await {
        Ok(listed) => listed,
        Err(failure) => return cua_unavailable(request.id, &failure),
    };
    let (windows, omitted) =
        map::map_windows(&listed.windows, platform.kind, std::process::id(), |pid| {
            process_identity(pid).ok()
        });
    if windows.is_empty()
        && !omitted.is_empty()
        && omitted
            .iter()
            .all(|reason| *reason == Omission::NoAttestedOwner)
    {
        // GNOME or KDE Wayland without Cua's compositor helper: the tree
        // exists, but no window identity does (XP-12).
        return Response::failure(
            request.id,
            code::PROVIDER_UNAVAILABLE,
            "compositor_helper_missing: window identity is unavailable on this compositor",
        );
    }
    let mut response = Response::success(request.id);
    response.windows = Some(windows);
    response
}

/// Whether a Cua refusal says the target is gone or no longer the same.
fn is_stale(failure: &CuaFailure) -> bool {
    let message = failure.message.to_ascii_lowercase();
    let structured_code = failure
        .structured
        .as_ref()
        .and_then(|value| value.get("code").or_else(|| value.pointer("/error/code")))
        .and_then(Value::as_str)
        .unwrap_or_default();
    message.contains("stale")
        || message.contains("no longer running")
        || message.contains("not found")
        || structured_code.contains("not_found")
        || structured_code.contains("stale")
}

async fn observe_window(
    runtime: &CuaRuntime,
    request: &Request,
    platform: HostPlatform,
) -> Response {
    let id = request.id;
    let Some(binding) = request.window.as_ref().and_then(|window| window.binding()) else {
        return Response::failure(
            id,
            code::INVALID_REQUEST,
            "exact window binding is required",
        );
    };
    let stale = |message: &str| Response::failure(id, code::TARGET_STALE, message.to_owned());
    if binding.pid == 0 || binding.pid == std::process::id() {
        return Response::failure(id, code::CAPABILITY_DENIED, "window is not a target");
    }
    let process = match process_identity(binding.pid) {
        Ok(process) => process,
        Err(IdentityRefusal::Gone) => return stale("window owner exited; list windows again"),
        Err(IdentityRefusal::Excluded) => {
            return Response::failure(
                id,
                code::PROTECTED_SURFACE,
                "window owner is excluded from observation",
            )
        }
        Err(IdentityRefusal::Unreadable) => {
            return Response::failure(
                id,
                code::PROVIDER_UNAVAILABLE,
                "window owner facts are unreadable",
            )
        }
    };
    let listed = match live_windows(runtime, Some(binding.pid)).await {
        Ok(listed) => listed,
        Err(failure) => return cua_unavailable(id, &failure),
    };
    let Some(window) = listed
        .windows
        .iter()
        .find(|window| window.window_id == binding.id && window.pid == Some(binding.pid))
    else {
        return stale("window is stale or closed; list windows again");
    };
    let class = map::bound_chars(&window.app_name, map::MAX_NAME_CHARS);
    let nonce = map::window_nonce(platform.kind, binding.id, &process, &class);
    if process.fact.start_generation != binding.start_generation || nonce != binding.window_nonce {
        return stale("window binding is stale");
    }
    let node_limit = request.node_limit();
    let depth_limit = request.depth_limit();
    let observed = runtime
        .call(&CuaCall::observe(
            binding.pid,
            binding.id,
            node_limit as u32,
            depth_limit as u32,
        ))
        .await;
    let state = match observed {
        Ok(state) => state,
        Err(failure) if is_stale(&failure) => return stale("window closed while it was observed"),
        Err(failure) => return cua_unavailable(id, &failure),
    };
    // The walk took time: the pid must still name the bound instance.
    match orcel_platform::process::start_generation(binding.pid) {
        Ok(now) if now.generation == binding.start_generation => {}
        _ => return stale("window owner changed while it was observed"),
    }
    let elements: Vec<WindowElement> = match state.get("elements").cloned() {
        None => Vec::new(),
        Some(elements) => match serde_json::from_value(elements) {
            Ok(elements) => elements,
            Err(error) => {
                return Response::failure(
                    id,
                    code::PROVIDER_UNAVAILABLE,
                    bounded_message(&format!(
                        "the Cua element list did not match its contract: {error}"
                    )),
                )
            }
        },
    };
    let mut response = Response::success(id);
    response.elements = Some(map::element_tree(&elements, node_limit, depth_limit));
    response
}

fn coordinate(value: &Value, key: &str) -> Option<i32> {
    let number = value.get(key)?.as_f64()?;
    if !number.is_finite() || number.abs() > f64::from(i32::MAX) {
        return None;
    }
    Some(number.round() as i32)
}

async fn cursor_position(runtime: &CuaRuntime, request: &Request) -> Response {
    let id = request.id;
    let position = match runtime
        .call(&CuaCall::GetCursorPosition(
            GetCursorPositionInput::default(),
        ))
        .await
    {
        Ok(position) => position,
        Err(failure) => return cua_unavailable(id, &failure),
    };
    // Cua reports Wayland positions it synthesized itself; those are not
    // the real pointer.
    if position.get("available").and_then(Value::as_bool) == Some(false)
        || position.get("source").and_then(Value::as_str) == Some("synthetic")
    {
        return Response::failure(
            id,
            code::PROVIDER_UNAVAILABLE,
            "the pointer position is not observable on this session",
        );
    }
    let screen = match runtime
        .call(&CuaCall::GetScreenSize(GetScreenSizeInput {
            session: None,
        }))
        .await
    {
        Ok(screen) => screen,
        Err(failure) => return cua_unavailable(id, &failure),
    };
    let (Some(x), Some(y), Some(screen_width), Some(screen_height)) = (
        coordinate(&position, "x"),
        coordinate(&position, "y"),
        coordinate(&screen, "width"),
        coordinate(&screen, "height"),
    ) else {
        return Response::failure(
            id,
            code::PROVIDER_UNAVAILABLE,
            "the pointer position or screen size is unreadable",
        );
    };
    let mut response = Response::success(id);
    response.cursor = Some(CursorFact {
        x,
        y,
        screen_width,
        screen_height,
        last_input_tick: 0,
    });
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_macos_permission_is_unavailable_with_a_reason() {
        let missing = macos_availability(&json!({
            "accessibility": false,
            "screen_recording": true,
            "source": {"direct_runtime": true}
        }));
        assert_eq!(missing.list_windows.as_deref(), Some("permission_missing"));
        assert_eq!(
            missing.observe_window.as_deref(),
            Some("permission_missing")
        );
        assert_eq!(missing.cursor_position, None);
        assert!(!missing.permissions["accessibility"]);
        let no_screen_recording =
            macos_availability(&json!({"accessibility": true, "screen_recording": false}));
        assert_eq!(
            no_screen_recording.list_windows.as_deref(),
            Some("permission_missing")
        );
        let granted = macos_availability(&json!({"accessibility": true, "screen_recording": true}));
        assert_eq!(granted.list_windows, None);
        assert_eq!(granted.observe_window, None);
        // A malformed answer never counts as granted.
        let malformed = macos_availability(&json!({"accessibility": "yes"}));
        assert_eq!(
            malformed.list_windows.as_deref(),
            Some("permission_missing")
        );
    }

    #[test]
    fn linux_without_display_or_session_bus_is_unavailable() {
        let none = linux_availability(protocol::LINUX_X11, &LinuxSession::default());
        assert_eq!(none, Availability::none("provider_unavailable"));
        let no_bus = linux_availability(
            protocol::LINUX_X11,
            &LinuxSession {
                display: true,
                ..LinuxSession::default()
            },
        );
        assert_eq!(no_bus.list_windows.as_deref(), Some("provider_unavailable"));
        assert_eq!(no_bus.cursor_position, None);
        let full = LinuxSession {
            display: true,
            wayland_display: true,
            session_bus: true,
        };
        let x11 = linux_availability(protocol::LINUX_X11, &full);
        assert_eq!(x11.list_windows, None);
        assert_eq!(x11.cursor_position, None);
        let wayland = linux_availability(protocol::LINUX_WAYLAND, &full);
        assert_eq!(wayland.list_windows, None);
        assert_eq!(
            wayland.cursor_position.as_deref(),
            Some("provider_unavailable")
        );
        // XWayland's DISPLAY alone does not make a Wayland session usable.
        let xwayland_only = linux_availability(
            protocol::LINUX_WAYLAND,
            &LinuxSession {
                display: true,
                wayland_display: false,
                session_bus: true,
            },
        );
        assert_eq!(xwayland_only, Availability::none("provider_unavailable"));
    }

    #[test]
    fn stale_cua_refusals_are_recognised() {
        let failure = |message: &str, structured: Option<Value>| CuaFailure {
            message: message.to_owned(),
            structured,
        };
        assert!(is_stale(&failure(
            "Window target pid 4, window_id 9 is stale or no longer running; refresh list_windows.",
            None
        )));
        assert!(is_stale(&failure(
            "x",
            Some(json!({"error": {"code": "window_not_found"}}))
        )));
        assert!(!is_stale(&failure("AT-SPI bus unavailable", None)));
    }

    #[test]
    fn worker_refuses_a_frame_it_cannot_decode_without_native_work() {
        let mut out = Vec::new();
        run(
            &b"{\"id\":5,\"protocol\":\"orcel-computer-host/2\",\"op\":\"run_script\"}\n"[..],
            &mut out,
        )
        .unwrap();
        let response: Response = serde_json::from_slice(trim_line(&out)).unwrap();
        assert_eq!(response.id, 5);
        assert_eq!(response.error.unwrap().code, "capability_denied");
    }
}
