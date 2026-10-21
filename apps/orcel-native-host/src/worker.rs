// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! The one-shot sacrificial worker (`orcel-native-host --worker`).
//!
//! It reads one request the supervisor already validated, validates it
//! again, runs exactly one observation, capture, semantic action or raw input
//! sequence through [`crate::cua_adapter`], writes one response line and
//! exits. All AX,
//! AT-SPI, ScreenCaptureKit and X11 work happens here, so a hang or crash in
//! those stacks costs one worker, never the supervisor. The worker never
//! retries and never falls back to another route.
//!
//! The worker answers `hello` too: the supervisor forwards it so the
//! permission and session probes run here, never in the supervisor.

use crate::capture::{self, FrameRefusal};
use crate::cua_adapter::{CuaCall, CuaFailure, CuaRuntime, InputCall, SemanticCall};
use crate::input;
use crate::map::{self, Omission, ProcessIdentity};
use crate::protocol::{
    self, code, Availability, CursorFact, HostPlatform, ProcessFact, Request, Response,
    WindowBinding, MAX_REQUEST_BYTES,
};
use crate::semantic;
use cua_driver_contract::{
    GetCursorPositionInput, GetScreenSizeInput, ListWindowsOutput, WindowElement, WindowInfo,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::process::ExitCode;

/// How long a delivered input unit gets to be processed before the
/// human-input baseline is read again.
const INPUT_SETTLE: std::time::Duration = std::time::Duration::from_millis(40);

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
        let detail = match (request.op.as_str(), platform) {
            ("capture_window", protocol::MACOS) => {
                "; capture needs Accessibility, Screen Recording and, from macOS 15, \
                 the direct-capture consent already recorded, and the host never prompts"
            }
            ("capture_window", protocol::LINUX_WAYLAND) => {
                "; Wayland exposes no exact-window capture to this host"
            }
            ("semantic_action", protocol::MACOS) => {
                "; actions need Accessibility and Screen Recording, and the host never prompts"
            }
            (op, protocol::MACOS) if input::is_input_operation(op) => {
                "; raw input needs Accessibility, Screen Recording and the direct-capture consent, and the host never prompts"
            }
            (op, protocol::LINUX_WAYLAND) if input::is_input_operation(op) => {
                "; Wayland offers this host no non-interactive way to target one window"
            }
            _ => "",
        };
        return Response::failure(
            request.id,
            reason,
            format!(
                "{} is unavailable on this machine ({reason}){detail}",
                request.op
            ),
        );
    }
    match request.op.as_str() {
        "list_windows" => list_windows(&runtime, request, platform).await,
        "observe_window" => observe_window(&runtime, request, platform).await,
        "capture_window" => capture_window(&runtime, request, platform).await,
        "semantic_action" => semantic_action(&runtime, request, platform).await,
        op if input::is_input_operation(op) => input_action(&runtime, request, platform).await,
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
/// Capture needs what listing needs (the binding is checked against the
/// live list) and, on macOS 15 and later, replayd's direct-capture consent
/// already recorded. Linux needs a display, and a session bus for AT-SPI.
/// Nothing prompts.
async fn probe(runtime: &CuaRuntime, platform: HostPlatform) -> Availability {
    if platform == protocol::MACOS {
        return match runtime.call(&CuaCall::CheckPermissions).await {
            Ok(status) => {
                let mut availability = macos_availability(&status);
                if availability.capture_window.is_none() {
                    let consent = direct_capture_consent();
                    availability
                        .permissions
                        .insert("direct_capture_consent".to_owned(), consent.is_ok());
                    if consent.is_err() {
                        availability.capture_window = Some(code::PERMISSION_MISSING.to_owned());
                        // Input scales its points by what a capture measures.
                        availability.input = Some(code::PERMISSION_MISSING.to_owned());
                    }
                }
                // The human-input binding needs a readable idle clock.
                if availability.input.is_none() && input::tick::current().is_err() {
                    availability.input = Some(code::PROVIDER_UNAVAILABLE.to_owned());
                }
                availability
            }
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
        observe_window: observation.clone(),
        cursor_position: None,
        capture_window: observation.clone(),
        semantic_action: observation.clone(),
        // Raw input needs what observation needs: it lists the window again
        // before each unit, and scales points by a capture of the window.
        input: observation,
        input_keys: None,
        permissions,
    }
}

/// Whether a capture can run without replayd's consent alert (macOS).
#[cfg(target_os = "macos")]
fn direct_capture_consent() -> Result<(), String> {
    capture::macos::direct_capture_consent()
}

#[cfg(not(target_os = "macos"))]
fn direct_capture_consent() -> Result<(), String> {
    Ok(())
}

/// The session facts the Linux probe reads from the worker's environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinuxSession {
    pub display: bool,
    pub wayland_display: bool,
    pub session_bus: bool,
    /// The X server answers the idle query the human-input binding reads.
    pub input_clock: bool,
    /// The session has the real input backend Cua's background keyboard
    /// route needs on X11: an Xorg server (not Xvfb) and a uinput device this
    /// user can open.
    pub real_input_backend: bool,
}

impl LinuxSession {
    fn from_env() -> Self {
        let set = |name: &str| std::env::var_os(name).is_some_and(|value| !value.is_empty());
        Self {
            display: set("DISPLAY"),
            wayland_display: set("WAYLAND_DISPLAY"),
            session_bus: set("DBUS_SESSION_BUS_ADDRESS"),
            input_clock: set("DISPLAY") && input::tick::current().is_ok(),
            real_input_backend: set("DISPLAY") && real_input_backend(),
        }
    }
}

/// Whether Cua's real pointer and keyboard backend is usable on this X
/// session (Xorg with a writable uinput device, not Xvfb).
#[cfg(target_os = "linux")]
fn real_input_backend() -> bool {
    platform_linux::input::real_pointer_input_available()
}

#[cfg(not(target_os = "linux"))]
fn real_input_backend() -> bool {
    false
}

/// Linux availability: no display means nothing works; no session bus
/// means no AT-SPI, so no window list or tree. On Wayland the pointer
/// position is not observable by a client (Cua reports only its own
/// synthetic moves), so the cursor is unavailable there. Capture follows
/// the window list on X11. On Wayland it is unavailable: Cua captures whole
/// outputs only, which would include other windows, and a portal capture
/// asks the user (XP-12).
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
    let wayland = platform == protocol::LINUX_WAYLAND;
    // Raw input: X11 only. A Wayland client cannot read the human-input clock
    // or address one window non-interactively; the portal and libei routes
    // ask the user, which this host never does.
    let input = tree.clone().or_else(|| {
        (wayland || !session.input_clock).then(|| code::PROVIDER_UNAVAILABLE.to_owned())
    });
    // The keyboard operations also need Cua's virtual master keyboard.
    let input_keys = (!session.real_input_backend).then(|| code::PROVIDER_UNAVAILABLE.to_owned());
    Availability {
        list_windows: tree.clone(),
        observe_window: tree.clone(),
        cursor_position: wayland.then(|| code::PROVIDER_UNAVAILABLE.to_owned()),
        capture_window: if wayland {
            Some(code::PROVIDER_UNAVAILABLE.to_owned())
        } else {
            tree.clone()
        },
        // AT-SPI actions need the tree and a window id, as observation does.
        semantic_action: tree,
        input,
        input_keys,
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

/// The executable path of a live pid, for the macOS responsible-app lookup.
#[cfg(target_os = "macos")]
pub(crate) fn executable_path(pid: u32) -> Option<String> {
    facts::executable_path(pid)
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

/// The live window an exact binding names, after every identity check:
/// the owner is the same process instance, not the host, not excluded, and
/// still lists this window id under the same application, so the nonce
/// matches. Any drift is `target_stale`; nothing is retargeted.
struct BoundWindow {
    binding: WindowBinding,
    process: ProcessIdentity,
    window: WindowInfo,
}

async fn bound_window(
    runtime: &CuaRuntime,
    request: &Request,
    platform: HostPlatform,
) -> Result<BoundWindow, Response> {
    let id = request.id;
    let Some(binding) = request.window.as_ref().and_then(|window| window.binding()) else {
        return Err(Response::failure(
            id,
            code::INVALID_REQUEST,
            "exact window binding is required",
        ));
    };
    let stale = |message: &str| Response::failure(id, code::TARGET_STALE, message.to_owned());
    if binding.pid == 0 || binding.pid == std::process::id() {
        return Err(Response::failure(
            id,
            code::CAPABILITY_DENIED,
            "window is not a target",
        ));
    }
    let process = match process_identity(binding.pid) {
        Ok(process) => process,
        Err(IdentityRefusal::Gone) => return Err(stale("window owner exited; list windows again")),
        Err(IdentityRefusal::Excluded) => {
            return Err(Response::failure(
                id,
                code::PROTECTED_SURFACE,
                "window owner is excluded from observation",
            ))
        }
        Err(IdentityRefusal::Unreadable) => {
            return Err(Response::failure(
                id,
                code::PROVIDER_UNAVAILABLE,
                "window owner facts are unreadable",
            ))
        }
    };
    let listed = match live_windows(runtime, Some(binding.pid)).await {
        Ok(listed) => listed,
        Err(failure) => return Err(cua_unavailable(id, &failure)),
    };
    let Some(window) = listed
        .windows
        .into_iter()
        .find(|window| window.window_id == binding.id && window.pid == Some(binding.pid))
    else {
        return Err(stale("window is stale or closed; list windows again"));
    };
    let class = map::bound_chars(&window.app_name, map::MAX_NAME_CHARS);
    let nonce = map::window_nonce(platform.kind, binding.id, &process, &class);
    if process.fact.start_generation != binding.start_generation || nonce != binding.window_nonce {
        return Err(stale("window binding is stale"));
    }
    Ok(BoundWindow {
        binding,
        process,
        window,
    })
}

async fn observe_window(
    runtime: &CuaRuntime,
    request: &Request,
    platform: HostPlatform,
) -> Response {
    let id = request.id;
    let stale = |message: &str| Response::failure(id, code::TARGET_STALE, message.to_owned());
    let binding = match bound_window(runtime, request, platform).await {
        Ok(bound) => bound.binding,
        Err(refusal) => return refusal,
    };
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

/// XP-07: one frame of exactly the bound window. Every refusal comes before
/// any pixel is read, except a change seen after the capture (another owner
/// instance, or a window now covered), which discards the frame. The window
/// is never raised, focused, restored or moved.
async fn capture_window(
    runtime: &CuaRuntime,
    request: &Request,
    platform: HostPlatform,
) -> Response {
    let id = request.id;
    let refuse = |code: &str, message: &str| Response::failure(id, code, message.to_owned());
    let bound = match bound_window(runtime, request, platform).await {
        Ok(bound) => bound,
        Err(refusal) => return refusal,
    };
    let window = &bound.window;
    let class = format!("{} {}", window.app_name, bound.process.fact.exe_name);
    if capture::is_protected_window(&window.title, &class) {
        return refuse(
            code::PROTECTED_SURFACE,
            "window is a protected surface; capture is denied before any pixel is read",
        );
    }
    if !window.is_on_screen || window.minimized == Some(true) {
        return refuse(
            code::PROVIDER_UNAVAILABLE,
            "window is minimized, hidden or on another Space; the host never restores, raises or focuses it",
        );
    }
    if capture::reported_size_exceeds_bounds(window.bounds.width, window.bounds.height) {
        return refuse(
            code::OUTPUT_LIMIT,
            "window exceeds the 7680x4320, 8 MiB capture bound; frames are never scaled down",
        );
    }
    if let Some(refusal) = exposure_refusal(id, platform, bound.binding.id) {
        return refusal;
    }
    let png = match runtime.capture_window(bound.binding.id) {
        Ok(png) => png,
        Err(failure) if is_stale(&failure) => {
            return refuse(code::TARGET_STALE, "window closed while it was captured")
        }
        Err(failure) => return cua_unavailable(id, &failure),
    };
    // The frame leaves only if the bound owner instance still holds the
    // window and nothing came to cover it meanwhile.
    match orcel_platform::process::start_generation(bound.binding.pid) {
        Ok(now) if now.generation == bound.binding.start_generation => {}
        _ => {
            return refuse(
                code::TARGET_STALE,
                "window owner changed while it was captured",
            )
        }
    }
    if let Some(refusal) = exposure_refusal(id, platform, bound.binding.id) {
        return refusal;
    }
    match capture::frame_from_png(&png) {
        Ok(frame) => {
            let mut response = Response::success(id);
            response.capture = Some(frame);
            response
        }
        Err(FrameRefusal::TooLarge(message)) => {
            Response::failure(id, code::OUTPUT_LIMIT, bounded_message(&message))
        }
        Err(FrameRefusal::Unreadable(message)) => {
            Response::failure(id, code::PROVIDER_UNAVAILABLE, bounded_message(&message))
        }
    }
}

/// How a failure of the P-09 action tool maps onto the closed codes. The tool
/// states its own code in the structured result; anything else is the
/// backend failing.
fn action_failure(id: u64, failure: &CuaFailure) -> Response {
    let structured = failure
        .structured
        .as_ref()
        .and_then(|value| value.get("code").or_else(|| value.pointer("/refusal/code")))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mapped = match structured {
        "target_stale" | "stale_element_token" => code::TARGET_STALE,
        "protected_surface" => code::PROTECTED_SURFACE,
        "capability_denied" => code::CAPABILITY_DENIED,
        "invalid_request" => code::INVALID_REQUEST,
        "timeout" => code::TIMEOUT,
        // Raw input (XP-12): the tool would have to take the foreground, or
        // the point is covered. Typed, so the caller sees why, and never
        // retried in the foreground.
        "background_unavailable" => code::BACKGROUND_UNAVAILABLE,
        "target_occluded" | "background_occluded" => code::BACKGROUND_OCCLUDED,
        _ if is_stale(failure) => code::TARGET_STALE,
        _ => code::PROVIDER_UNAVAILABLE,
    };
    Response::failure(id, mapped, bounded_message(&failure.message))
}

/// XP-11: one accessibility action on one element of one exact window.
///
/// Nothing the kernel said is taken on trust. In this worker, in this order:
/// the window binding and owner identity are re-proved (`bound_window`); the
/// window must not be a protected surface and must be on screen; the window's
/// tree is listed again and the element is found by its stable runtime id,
/// among the nodes a bounded observation returns, or the action is
/// `target_stale`; the verb must suit the live element and the element must
/// not be a password or secret (`semantic::plan`); the owner's start
/// generation is read again; and only then one action is delivered through
/// the P-09 tool, which has accessibility routes only. The host never
/// retries (the supervisor runs this worker once), and the kernel registry
/// observes the window again after every action.
async fn semantic_action(
    runtime: &CuaRuntime,
    request: &Request,
    platform: HostPlatform,
) -> Response {
    let id = request.id;
    let refuse = |code: &str, message: &str| Response::failure(id, code, message.to_owned());
    let verb = match semantic::parse_verb(request.semantic_action.as_deref().unwrap_or_default()) {
        Ok(verb) => verb,
        Err(refusal) => return refuse(refusal.code, &refusal.message),
    };
    let Some(wanted) = request.element_runtime_id.as_deref() else {
        return refuse(code::INVALID_REQUEST, "the element runtime id is required");
    };
    let bound = match bound_window(runtime, request, platform).await {
        Ok(bound) => bound,
        Err(refusal) => return refusal,
    };
    let window = &bound.window;
    let class = format!("{} {}", window.app_name, bound.process.fact.exe_name);
    if capture::is_protected_window(&window.title, &class) {
        return refuse(
            code::PROTECTED_SURFACE,
            "window is a protected surface; no action is delivered to it",
        );
    }
    if !window.is_on_screen || window.minimized == Some(true) {
        return refuse(
            code::PROVIDER_UNAVAILABLE,
            "window is minimized, hidden or on another Space; the host acts only on a window the user can see",
        );
    }
    let node_limit = protocol::MAX_TREE_NODES;
    let depth_limit = protocol::MAX_TREE_DEPTH;
    let observed = runtime
        .call(&CuaCall::observe(
            bound.binding.pid,
            bound.binding.id,
            node_limit as u32,
            depth_limit as u32,
        ))
        .await;
    let state = match observed {
        Ok(state) => state,
        Err(failure) if is_stale(&failure) => {
            return refuse(code::TARGET_STALE, "window closed while it was observed")
        }
        Err(failure) => return cua_unavailable(id, &failure),
    };
    let elements: Vec<WindowElement> = match state.get("elements").cloned() {
        None => Vec::new(),
        Some(elements) => match serde_json::from_value(elements) {
            Ok(elements) => elements,
            Err(error) => {
                return refuse(
                    code::PROVIDER_UNAVAILABLE,
                    &bounded_message(&format!(
                        "the Cua element list did not match its contract: {error}"
                    )),
                )
            }
        },
    };
    let ids = map::runtime_ids(&elements);
    let observable = map::observable_elements(&elements, node_limit, depth_limit);
    let Some(element) = semantic::locate(&observable, &ids, wanted) else {
        return refuse(
            code::TARGET_STALE,
            "the element is not in the window's tree as observed; observe the window again",
        );
    };
    let fact = map::element_fact(element, wanted);
    if let Err(refusal) = semantic::plan(verb, element, &fact, request.value.as_deref()) {
        return refuse(refusal.code, &refusal.message);
    }
    let Some(token) = element.element_token.clone() else {
        return refuse(
            code::TARGET_STALE,
            "the element has no token in this snapshot",
        );
    };
    // The listing and the walk took time: the owner must still be the
    // instance the binding names, immediately before the action.
    match orcel_platform::process::start_generation(bound.binding.pid) {
        Ok(now) if now.generation == bound.binding.start_generation => {}
        _ => return refuse(code::TARGET_STALE, "window owner changed before the action"),
    }
    let call = CuaCall::SemanticAction(SemanticCall {
        pid: bound.binding.pid,
        window_id: bound.binding.id,
        element_token: token,
        verb,
        expect_role: element.role.clone(),
        value: (verb == semantic::Verb::SetValue)
            .then(|| request.value.clone())
            .flatten(),
        toggle_to: (verb == semantic::Verb::Toggle)
            .then(|| request.value.as_deref() == Some("true")),
    });
    match runtime.call(&call).await {
        Ok(_) => {
            let mut response = Response::success(id);
            response.action = Some(protocol::ActionFact {
                state: "completed".to_owned(),
                action: format!("semantic_{}", verb.as_str()),
            });
            response
        }
        Err(failure) => action_failure(id, &failure),
    }
}

/// XP-12: why a raw input unit is not delivered now, judged on the live facts
/// of the bound window immediately before the unit. Everything the approval
/// bound is proved again here, because a unit can follow its predecessor by
/// seconds:
///
/// - the window binding and owner identity (`bound_window`: same process
///   instance, same window id, same application, so the nonce matches);
/// - not a protected surface (owner-based, as in XP-07 and XP-11);
/// - on screen, not minimized, on the current Space;
/// - still the frame the points were checked against (a window that moved or
///   resized would turn the same relative point into another place);
/// - not covered: the XP-07 X11 exposure check, or on macOS the stacking
///   order of every window at each point the unit touches;
/// - the person has not touched the keyboard or pointer since the kernel
///   read the tick (`cancelled`).
async fn input_gate(
    runtime: &CuaRuntime,
    request: &Request,
    platform: HostPlatform,
    planned: Option<&input::Frame>,
    points: &[(i64, i64)],
    expected_tick: u32,
) -> Result<BoundWindow, Response> {
    let id = request.id;
    let refuse = |code: &str, message: &str| Response::failure(id, code, message.to_owned());
    let bound = bound_window(runtime, request, platform).await?;
    let window = &bound.window;
    let class = format!("{} {}", window.app_name, bound.process.fact.exe_name);
    if capture::is_protected_window(&window.title, &class) {
        return Err(refuse(
            code::PROTECTED_SURFACE,
            "window is a protected surface; no input is delivered to it",
        ));
    }
    if !window.is_on_screen
        || window.minimized == Some(true)
        || window.on_current_space == Some(false)
    {
        return Err(refuse(
            code::PROVIDER_UNAVAILABLE,
            "window is minimized, hidden or on another Space; the host never restores, raises or focuses it",
        ));
    }
    let live = input::Frame::of(window);
    if planned.is_some_and(|planned| !planned.matches(&live)) {
        return Err(refuse(
            code::TARGET_STALE,
            "the window moved or resized since the input was planned",
        ));
    }
    if let Some(refusal) = exposure_refusal(id, platform, bound.binding.id) {
        return Err(refusal);
    }
    if platform == protocol::MACOS {
        let listed = match live_windows(runtime, None).await {
            Ok(listed) => listed,
            Err(failure) => return Err(cua_unavailable(id, &failure)),
        };
        for (x, y) in points {
            let (sx, sy) = live.screen_point(*x, *y);
            match input::occluded_at(window, &listed.windows, sx, sy) {
                input::Occlusion::Clear => {}
                input::Occlusion::Covered => {
                    return Err(refuse(
                        code::PROVIDER_UNAVAILABLE,
                        "window_obscured: another window covers the point, and the host never raises it",
                    ))
                }
                input::Occlusion::Unknown => {
                    return Err(refuse(
                        code::PROVIDER_UNAVAILABLE,
                        "the stacking order cannot prove the point is clear of other windows",
                    ))
                }
            }
        }
    }
    // The owner must still be the instance the binding names, immediately
    // before the unit.
    match orcel_platform::process::start_generation(bound.binding.pid) {
        Ok(now) if now.generation == bound.binding.start_generation => {}
        _ => {
            return Err(refuse(
                code::TARGET_STALE,
                "window owner changed before the input",
            ))
        }
    }
    match input::tick::current() {
        Ok(now) if input::tick_is_fresh(expected_tick, now) => {}
        Ok(_) => {
            return Err(refuse(
                code::CANCELLED,
                "human input arrived after the bound tick, so the input was not sent",
            ))
        }
        Err(message) => {
            return Err(refuse(
                code::PROVIDER_UNAVAILABLE,
                &bounded_message(&format!("the human-input clock is unreadable: {message}")),
            ))
        }
    }
    Ok(bound)
}

/// The window's observed tree, or the refusal that says why it cannot be used.
async fn observe_elements(
    runtime: &CuaRuntime,
    id: u64,
    bound: &BoundWindow,
) -> Result<Vec<WindowElement>, Response> {
    let observed = runtime
        .call(&CuaCall::observe(
            bound.binding.pid,
            bound.binding.id,
            protocol::MAX_TREE_NODES as u32,
            protocol::MAX_TREE_DEPTH as u32,
        ))
        .await;
    match observed {
        Ok(state) => match state.get("elements").cloned() {
            None => Ok(Vec::new()),
            Some(elements) => serde_json::from_value(elements).map_err(|error| {
                Response::failure(
                    id,
                    code::PROVIDER_UNAVAILABLE,
                    bounded_message(&format!(
                        "the Cua element list did not match its contract: {error}"
                    )),
                )
            }),
        },
        Err(failure) if is_stale(&failure) => Err(Response::failure(
            id,
            code::TARGET_STALE,
            "window closed while it was observed",
        )),
        Err(failure) => Err(cua_unavailable(id, &failure)),
    }
}

/// Typed text and keys land in whatever control holds the focus, which the host
/// cannot see. They are delivered only to a window whose accessibility tree
/// can be read and shows no secure field; a window with no readable tree (Tk,
/// a bare Xlib or SDL program) cannot be shown to have none, so it takes no
/// keyboard input.
fn keyboard_tree_refusal(id: u64, elements: &[WindowElement]) -> Option<Response> {
    if input::shows_secure_field(elements) {
        return Some(Response::failure(
            id,
            code::PROTECTED_SURFACE,
            "the window shows a password or secure field; no input is delivered to it",
        ));
    }
    if elements.is_empty() {
        return Some(Response::failure(
            id,
            code::PROTECTED_SURFACE,
            "the window exposes no accessibility tree, so a secure field cannot be excluded; typed input is not delivered to it",
        ));
    }
    None
}

/// Physical window pixels per point: what a capture of the window measures
/// on macOS, where a Retina window captures at twice its point size; 1 on X11.
async fn input_scale(
    runtime: &CuaRuntime,
    platform: HostPlatform,
    window: &cua_driver_contract::WindowInfo,
) -> Result<f64, String> {
    if platform != protocol::MACOS {
        return Ok(1.0);
    }
    let png = runtime
        .capture_window(window.window_id)
        .map_err(|failure| bounded_message(&failure.message))?;
    let decoded = image::load_from_memory(&png)
        .map_err(|error| bounded_message(&format!("the window capture is unreadable: {error}")))?;
    input::backing_scale(
        window.bounds.width,
        window.bounds.height,
        decoded.width(),
        decoded.height(),
    )
    .ok_or_else(|| "the window capture and its frame disagree on the scale".to_owned())
}

/// The vendored call for one planned unit. Points become physical pixels.
fn input_call(unit: &input::Unit, pid: u32, window_id: u64, scale: f64) -> InputCall {
    let px = |value: i64| value as f64 * scale;
    match unit {
        input::Unit::Click {
            x,
            y,
            button,
            count,
        } => InputCall::Click {
            pid,
            window_id,
            x: px(*x),
            y: px(*y),
            right: *button == input::Button::Right,
            count: *count,
        },
        input::Unit::Drag { x, y, to_x, to_y } => InputCall::Drag {
            pid,
            window_id,
            from: (px(*x), px(*y)),
            to: (px(*to_x), px(*to_y)),
        },
        input::Unit::Scroll {
            x,
            y,
            direction,
            lines,
        } => InputCall::Scroll {
            pid,
            window_id,
            x: px(*x),
            y: px(*y),
            direction,
            lines: *lines,
        },
        input::Unit::Text(text) => InputCall::TypeText {
            pid,
            window_id,
            text: text.clone(),
        },
        input::Unit::Key(key) => InputCall::PressKey {
            pid,
            window_id,
            key,
        },
    }
}

/// XP-12: bounded raw input to one exact window.
///
/// Nothing the kernel said is taken on trust. In this worker, in this order:
/// the window binding and owner identity are proved (`input_gate`); the frame
/// shape and every point are judged against the window's live frame (a point
/// outside it is refused, never clamped); the window's observed tree must show
/// no secure text field (a click may focus one and typed text then lands in
/// it); the backing scale is measured; and then each delivery unit, a click,
/// a drag, a scroll, a key or at most eight typed characters, is preceded by
/// the whole gate again and delivered through the vendored background route
/// (`InputCall`: exact `pid` and `window_id`, background delivery, no
/// foreground, no raise). The host never retries (the supervisor runs this
/// worker once). A unit refused after an earlier one was delivered is
/// `outcome_unknown`: part of the input landed and the rest did not.
async fn input_action(runtime: &CuaRuntime, request: &Request, platform: HostPlatform) -> Response {
    let id = request.id;
    let refuse = |code: &str, message: &str| Response::failure(id, code, message.to_owned());
    let Some(expected_tick) = request.expected_last_input_tick else {
        return refuse(
            code::INVALID_REQUEST,
            "raw input needs the human-input tick",
        );
    };
    let first = match input_gate(runtime, request, platform, None, &[], expected_tick).await {
        Ok(first) => first,
        Err(refusal) => return refusal,
    };
    let frame = input::Frame::of(&first.window);
    let plan = match input::plan(request, &frame) {
        Ok(plan) => plan,
        Err(refusal) => return refuse(refusal.code, &refusal.message),
    };
    let keyboard = plan
        .units
        .iter()
        .any(|unit| matches!(unit, input::Unit::Text(_) | input::Unit::Key(_)));
    let elements = match observe_elements(runtime, id, &first).await {
        Ok(elements) => elements,
        Err(refusal) => return refusal,
    };
    if input::shows_secure_field(&elements) {
        return refuse(
            code::PROTECTED_SURFACE,
            "the window shows a password or secure field; no input is delivered to it",
        );
    }
    if keyboard {
        if let Some(refusal) = keyboard_tree_refusal(id, &elements) {
            return refusal;
        }
    }
    let scale = match input_scale(runtime, platform, &first.window).await {
        Ok(scale) => scale,
        Err(message) => return refuse(code::PROVIDER_UNAVAILABLE, &message),
    };
    let total = plan.units.len();
    // The person must have been quiet before the first unit. The kernel read
    // its baseline right after the Approve click, so a person still typing or
    // moving then has the tick moving under the wait below, and the input is
    // cancelled.
    if let (Ok(clock), Ok(last)) = (input::tick::clock_ms(), input::tick::current()) {
        let remaining = input::quiet_remaining_ms(clock, last);
        if remaining > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(u64::from(remaining))).await;
            match input::tick::current() {
                Ok(now) if input::tick_is_fresh(last, now) => {}
                _ => {
                    return refuse(
                        code::CANCELLED,
                        "human input continued after the approval, so the input was not sent",
                    )
                }
            }
        }
    }
    // The tick the person is held to. The host's own events move the X
    // server's idle clock, so after each unit the tick is read again and must
    // be explained by that unit's own delivery time (or not have moved). The
    // person's keystrokes between units are neither, so they cancel the rest;
    // they are never adopted as the new baseline.
    let mut baseline = expected_tick;
    for (index, unit) in plan.units.iter().enumerate() {
        let mut points = unit.points();
        if points.is_empty() {
            points.push(((frame.width / 2.0) as i64, (frame.height / 2.0) as i64));
        }
        let bound =
            match input_gate(runtime, request, platform, Some(&frame), &points, baseline).await {
                Ok(bound) => bound,
                Err(refusal) if index == 0 => return refusal,
                Err(refusal) => return partial_input(id, index, total, refusal),
            };
        // Each keyboard unit re-reads the tree: a secure field may have
        // appeared, or the window changed what it shows.
        if index > 0 && matches!(unit, input::Unit::Text(_) | input::Unit::Key(_)) {
            let refusal = match observe_elements(runtime, id, &bound).await {
                Ok(elements) => keyboard_tree_refusal(id, &elements),
                Err(refusal) => Some(refusal),
            };
            if let Some(refusal) = refusal {
                return partial_input(id, index, total, refusal);
            }
        }
        let started = input::tick::clock_ms();
        let call = CuaCall::Input(input_call(unit, bound.binding.pid, bound.binding.id, scale));
        if let Err(failure) = runtime.call(&call).await {
            if index == 0 {
                return action_failure(id, &failure);
            }
            return partial_input(id, index, total, action_failure(id, &failure));
        }
        if index + 1 < total {
            tokio::time::sleep(INPUT_SETTLE).await;
            let ended = input::tick::clock_ms();
            match (started, ended, input::tick::current()) {
                (Ok(start), Ok(end), Ok(after))
                    if input::explained_by_own_events(baseline, after, start, end) =>
                {
                    baseline = after;
                }
                _ => {
                    return partial_input(
                        id,
                        index + 1,
                        total,
                        refuse(
                            code::CANCELLED,
                            "human input arrived between units, so the rest was not sent",
                        ),
                    )
                }
            }
        }
    }
    let mut response = Response::success(id);
    response.action = Some(protocol::ActionFact {
        state: "completed".to_owned(),
        action: request.op.clone(),
    });
    response
}

/// The answer when a later delivery unit was refused after earlier ones landed.
fn partial_input(id: u64, delivered: usize, total: usize, cause: Response) -> Response {
    let why = cause
        .error
        .map(|error| error.message)
        .unwrap_or_else(|| "a later unit was not delivered".to_owned());
    Response::failure(
        id,
        code::OUTCOME_UNKNOWN,
        bounded_message(&format!(
            "{delivered} of {total} input units were delivered before the rest was refused ({why}); do not repeat the input"
        )),
    )
}

/// X11 capture reads the screen's copy of the window, so the window must be
/// wholly its own on screen (see `capture::x11`). `None` lets it through.
#[cfg(target_os = "linux")]
fn exposure_refusal(id: u64, platform: HostPlatform, window_id: u64) -> Option<Response> {
    use capture::x11::Exposure;
    let refuse = |message: &str| {
        Some(Response::failure(
            id,
            code::PROVIDER_UNAVAILABLE,
            message.to_owned(),
        ))
    };
    if platform != protocol::LINUX_X11 {
        return refuse("this session exposes no exact-window capture");
    }
    match capture::x11::exposure(window_id) {
        Ok(Exposure::Exposed) => None,
        Ok(Exposure::Covered) => refuse(
            "window_obscured: another window covers part of it, and the host never raises it",
        ),
        Ok(Exposure::Clipped) => {
            refuse("window_clipped: part of the window is off screen or outside its frame")
        }
        Ok(Exposure::NotViewable) => {
            refuse("window is minimized or hidden; the host never restores, raises or focuses it")
        }
        Err(error) => refuse(&bounded_message(&format!(
            "the window's X11 exposure is unreadable: {error}"
        ))),
    }
}

/// ScreenCaptureKit's desktop-independent window filter reads the window's
/// own buffer, so covering windows never reach the frame.
#[cfg(not(target_os = "linux"))]
fn exposure_refusal(_id: u64, _platform: HostPlatform, _window_id: u64) -> Option<Response> {
    None
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
        // The human-input tick raw input is bound to; 0 when unreadable, a
        // value no live tick is within tolerance of.
        last_input_tick: input::tick::current().unwrap_or(0),
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
        assert_eq!(
            no_screen_recording.capture_window.as_deref(),
            Some("permission_missing")
        );
        // Actions need what observation needs, and nothing more.
        assert_eq!(
            missing.semantic_action.as_deref(),
            Some("permission_missing")
        );
        assert_eq!(missing.input.as_deref(), Some("permission_missing"));
        assert_eq!(
            no_screen_recording.input.as_deref(),
            Some("permission_missing")
        );
        assert_eq!(
            no_screen_recording.semantic_action.as_deref(),
            Some("permission_missing")
        );
        let granted = macos_availability(&json!({"accessibility": true, "screen_recording": true}));
        assert_eq!(granted.list_windows, None);
        assert_eq!(granted.observe_window, None);
        assert_eq!(granted.semantic_action, None);
        assert_eq!(granted.input, None);
        // The direct-capture consent is read separately, in the probe.
        assert_eq!(granted.capture_window, None);
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
        assert_eq!(
            no_bus.capture_window.as_deref(),
            Some("provider_unavailable")
        );
        assert_eq!(
            no_bus.semantic_action.as_deref(),
            Some("provider_unavailable")
        );
        assert_eq!(no_bus.cursor_position, None);
        let full = LinuxSession {
            display: true,
            wayland_display: true,
            session_bus: true,
            input_clock: true,
            real_input_backend: true,
        };
        let x11 = linux_availability(protocol::LINUX_X11, &full);
        assert_eq!(x11.list_windows, None);
        assert_eq!(x11.cursor_position, None);
        assert_eq!(x11.capture_window, None);
        assert_eq!(x11.semantic_action, None);
        assert_eq!(x11.input, None);
        assert_eq!(x11.refusal_for("input_key"), None);
        // X11 without the real input backend (Xvfb, or no uinput) serves the
        // pointer operations and not the keyboard ones.
        let headless = linux_availability(
            protocol::LINUX_X11,
            &LinuxSession {
                real_input_backend: false,
                ..full.clone()
            },
        );
        assert_eq!(headless.refusal_for("input_click"), None);
        assert_eq!(headless.refusal_for("input_drag"), None);
        assert_eq!(headless.refusal_for("input_scroll"), None);
        assert_eq!(
            headless.refusal_for("input_type_text"),
            Some("provider_unavailable")
        );
        assert_eq!(
            headless.refusal_for("input_key"),
            Some("provider_unavailable")
        );
        // X11 without a readable human-input clock serves no raw input.
        let no_clock = linux_availability(
            protocol::LINUX_X11,
            &LinuxSession {
                input_clock: false,
                ..full.clone()
            },
        );
        assert_eq!(no_clock.input.as_deref(), Some("provider_unavailable"));
        assert_eq!(no_clock.semantic_action, None);
        let wayland = linux_availability(protocol::LINUX_WAYLAND, &full);
        assert_eq!(wayland.list_windows, None);
        // Wayland has no exact-window capture for this host, but AT-SPI
        // actions work wherever a window is attested (Sway).
        assert_eq!(
            wayland.capture_window.as_deref(),
            Some("provider_unavailable")
        );
        assert_eq!(wayland.semantic_action, None);
        // Wayland: unavailable, with no non-interactive path to a window.
        assert_eq!(wayland.input.as_deref(), Some("provider_unavailable"));
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
                input_clock: true,
                real_input_backend: true,
            },
        );
        assert_eq!(xwayland_only, Availability::none("provider_unavailable"));
    }

    #[test]
    fn action_tool_failures_map_onto_the_closed_codes() {
        let failure = |message: &str, code: &str| CuaFailure {
            message: message.to_owned(),
            structured: Some(json!({ "code": code })),
        };
        for (tool_code, expected) in [
            ("target_stale", "target_stale"),
            ("stale_element_token", "target_stale"),
            ("protected_surface", "protected_surface"),
            ("capability_denied", "capability_denied"),
            ("invalid_request", "invalid_request"),
            ("timeout", "timeout"),
            ("background_unavailable", "background_unavailable"),
            ("target_occluded", "background_occluded"),
            ("background_occluded", "background_occluded"),
            ("ax_failed", "provider_unavailable"),
            ("anything else", "provider_unavailable"),
        ] {
            let response = action_failure(5, &failure("the tool said no", tool_code));
            assert!(!response.ok);
            assert_eq!(response.error.unwrap().code, expected, "{tool_code}");
        }
        // The core's own refusal envelope, and a bare stale message.
        let envelope = CuaFailure {
            message: "x".into(),
            structured: Some(json!({"refusal": {"code": "stale_element_token"}})),
        };
        assert_eq!(
            action_failure(5, &envelope).error.unwrap().code,
            "target_stale"
        );
        let bare = CuaFailure {
            message: "the element is stale".into(),
            structured: None,
        };
        assert_eq!(action_failure(5, &bare).error.unwrap().code, "target_stale");
        let long = CuaFailure {
            message: "m".repeat(5000),
            structured: None,
        };
        assert_eq!(
            action_failure(5, &long)
                .error
                .unwrap()
                .message
                .chars()
                .count(),
            MAX_MESSAGE_CHARS
        );
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
