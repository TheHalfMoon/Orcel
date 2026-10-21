// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! The long-lived supervisor (the same shape as the Windows host's
//! `main_windows.go` and `worker_windows.go`).
//!
//! It reads `/2` request lines from the stdin pipe orceld gave it and writes
//! one response line each to stdout. It has no listener, socket, network
//! client or telemetry. It never touches AX or AT-SPI: `hello`'s probe and
//! every observation run in a one-shot worker child (`--worker`) with a
//! scrubbed environment and an 8 s deadline, tried at most twice, and the
//! worker's answer must echo the request id, protocol and host identity.
//! Nothing is retried in process and nothing falls back to another route.

use crate::protocol::{
    self, code, Availability, HostPlatform, Request, Response, HOST_IDENTITY, MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES, MUTATION_ATTEMPTS, PROTOCOL_V2, WORKER_ATTEMPTS, WORKER_TIMEOUT,
};
use std::ffi::OsString;
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Environment a worker inherits, by name. Everything else, including any
/// `CUA_*` switch, is dropped. On Linux these are what AT-SPI, X11 and
/// Wayland clients read; on macOS only the basics (no `HOME`, so Cua reads
/// no per-user config file).
#[cfg(target_os = "macos")]
const WORKER_ENV: &[&str] = &["PATH", "LANG", "TMPDIR", "ORCEL_MACOS_BACKGROUND_SPI"];
#[cfg(not(target_os = "macos"))]
const WORKER_ENV: &[&str] = &[
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

/// Cua's opt-in for its native Wayland routes. The host sets it for a worker
/// exactly when it serves the session as Wayland, so Cua and the host agree.
const CUA_WAYLAND_OPT_IN: &str = "CUA_DRIVER_RS_ENABLE_WAYLAND";

/// Runs one observation for the supervisor.
pub trait Dispatch {
    fn dispatch(&mut self, request: &Request) -> Response;
}

/// The worker environment for `platform`, read from this process's own.
pub fn worker_environment(platform: HostPlatform) -> Vec<(OsString, OsString)> {
    let mut environment: Vec<(OsString, OsString)> = WORKER_ENV
        .iter()
        .filter_map(|name| {
            std::env::var_os(name)
                .filter(|value| !value.is_empty())
                .map(|value| (OsString::from(name), value))
        })
        .collect();
    if platform == protocol::LINUX_WAYLAND {
        environment.push((CUA_WAYLAND_OPT_IN.into(), "1".into()));
    }
    environment
}

/// Spawns one worker per attempt.
pub struct WorkerDispatch {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub environment: Vec<(OsString, OsString)>,
    pub timeout: Duration,
}

enum Attempt {
    Answer(Box<Response>),
    TimedOut,
    Oversized,
    Failed(String),
}

impl WorkerDispatch {
    /// Workers run this very binary. On Linux it is named through
    /// `/proc/self/exe`, the file this process was started from, so a binary
    /// replaced on disk afterwards is never the worker.
    pub fn for_current_exe(platform: HostPlatform) -> std::io::Result<Self> {
        #[cfg(target_os = "linux")]
        let program = PathBuf::from("/proc/self/exe");
        #[cfg(not(target_os = "linux"))]
        let program = std::env::current_exe()?;
        Ok(Self {
            program,
            args: vec!["--worker".into()],
            environment: worker_environment(platform),
            timeout: WORKER_TIMEOUT,
        })
    }

    fn attempt(&self, request: &Request, payload: &[u8]) -> Attempt {
        let mut child = match Command::new(&self.program)
            .args(&self.args)
            .env_clear()
            .envs(self.environment.iter().map(|(name, value)| (name, value)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => return Attempt::Failed("native worker could not start".to_owned()),
        };
        if let Some(mut stdin) = child.stdin.take() {
            // A worker that exits early closes its end; that shows up below.
            let _ = stdin.write_all(payload);
        }
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Attempt::Failed("native worker stdout is unavailable".to_owned());
        };
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let mut raw = Vec::new();
            let read = stdout
                .take(MAX_RESPONSE_BYTES as u64 + 2)
                .read_to_end(&mut raw);
            let _ = sender.send(read.map(|_| raw));
        });
        // Typed text is delivered in checked chunks, each preceded by a fresh
        // window listing, so a raw input gets a longer deadline.
        let timeout = if crate::input::is_input_operation(&request.op) {
            self.timeout * INPUT_TIMEOUT_FACTOR
        } else {
            self.timeout
        };
        let raw = match receiver.recv_timeout(timeout) {
            Ok(Ok(raw)) => raw,
            Ok(Err(_)) => {
                let _ = child.kill();
                let _ = child.wait();
                return Attempt::Failed("native worker output is unreadable".to_owned());
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Attempt::TimedOut;
            }
        };
        if raw.len() > MAX_RESPONSE_BYTES + 1 {
            let _ = child.kill();
            let _ = child.wait();
            return Attempt::Oversized;
        }
        match child.wait() {
            Ok(status) if status.success() => {}
            _ => return Attempt::Failed("native worker exited unsuccessfully".to_owned()),
        }
        match decode_worker_response(request, &raw) {
            Ok(response) => Attempt::Answer(Box::new(response)),
            Err(reason) => Attempt::Failed(reason.to_owned()),
        }
    }
}

impl Dispatch for WorkerDispatch {
    fn dispatch(&mut self, request: &Request) -> Response {
        let Ok(mut payload) = serde_json::to_vec(request) else {
            return Response::failure(
                request.id,
                code::INVALID_REQUEST,
                "request serialization failed",
            );
        };
        payload.push(b'\n');
        let mut last = Attempt::Failed("native worker unavailable".to_owned());
        // A mutation is tried once: a second worker could deliver it twice.
        let attempts = if is_mutation(&request.op) {
            MUTATION_ATTEMPTS
        } else {
            WORKER_ATTEMPTS
        };
        for _ in 0..attempts {
            match self.attempt(request, &payload) {
                Attempt::Answer(response) => return *response,
                Attempt::Oversized => {
                    return Response::failure(
                        request.id,
                        code::OUTPUT_LIMIT,
                        "native worker response exceeds the bounded size",
                    )
                }
                other => last = other,
            }
        }
        let unknown = if is_mutation(&request.op) {
            "; the action may have been delivered, so observe the window again and do not repeat it"
        } else {
            ""
        };
        match last {
            Attempt::TimedOut => Response::failure(
                request.id,
                code::TIMEOUT,
                format!("native worker timed out and was killed{unknown}"),
            ),
            Attempt::Failed(reason) => Response::failure(
                request.id,
                code::PROVIDER_UNAVAILABLE,
                format!("{reason}{unknown}"),
            ),
            Attempt::Answer(response) => *response,
            Attempt::Oversized => Response::failure(
                request.id,
                code::OUTPUT_LIMIT,
                "native worker response exceeds the bounded size",
            ),
        }
    }
}

/// A raw input may take this many worker deadlines (XP-12).
const INPUT_TIMEOUT_FACTOR: u32 = 4;

/// Operations that change the target. The host never retries them.
fn is_mutation(op: &str) -> bool {
    op == "semantic_action" || crate::input::is_input_operation(op)
}

/// The worker's last output line, which must answer exactly this request.
/// Earlier lines (anything a library printed) are ignored.
pub fn decode_worker_response(request: &Request, raw: &[u8]) -> Result<Response, &'static str> {
    if raw.contains(&0) {
        return Err("native worker returned a NUL-contaminated response");
    }
    let line = raw
        .split(|byte| *byte == b'\n')
        .map(|line| line.trim_ascii())
        .rfind(|line| !line.is_empty())
        .ok_or("native worker returned an empty response")?;
    if line.len() > MAX_RESPONSE_BYTES {
        return Err("native worker returned an oversized response");
    }
    let response: Response =
        serde_json::from_slice(line).map_err(|_| "native worker returned corrupt JSON")?;
    if response.id != request.id
        || response.protocol != PROTOCOL_V2
        || response.host != HOST_IDENTITY
    {
        return Err("native worker response binding mismatch");
    }
    Ok(response)
}

/// Answers one request line. `stop` reports a completed shutdown.
pub fn handle_frame(
    line: &[u8],
    platform: HostPlatform,
    dispatch: &mut impl Dispatch,
) -> (Response, bool) {
    let request = match protocol::decode_request(line, platform) {
        Ok(request) => request,
        Err(refusal) => return (*refusal.0, false),
    };
    match request.op.as_str() {
        "ping" => {
            let mut response = Response::success(request.id);
            response.pong = true;
            (response, false)
        }
        "shutdown" => (Response::success(request.id), true),
        "hello" => (hello(&request, platform, dispatch), false),
        _ => {
            let mut response = dispatch.dispatch(&request);
            // A worker answers in /2 framing with no hello fields.
            response.platform = None;
            response.backend = None;
            response.capabilities = None;
            response.host_version = None;
            response.donor = None;
            response.permissions = None;
            (response, false)
        }
    }
}

/// The hello answer: the worker's probe when it agrees with this
/// supervisor's platform, otherwise every observation unavailable. A failed
/// probe never fails the handshake; it only narrows the table.
fn hello(request: &Request, platform: HostPlatform, dispatch: &mut impl Dispatch) -> Response {
    let probed = dispatch.dispatch(request);
    let agrees = probed.ok
        && probed.platform.as_deref() == Some(platform.platform)
        && probed.backend.as_deref() == Some(platform.backend)
        && probed.capabilities.is_some();
    if agrees {
        let mut response = probed;
        // Keep the table this host defines for the probed availability.
        let availability = availability_from(&response);
        response.capabilities = Some(protocol::capability_table(&availability));
        return response;
    }
    protocol::hello(
        request.id,
        platform,
        &Availability::none(code::PROVIDER_UNAVAILABLE),
    )
}

/// Reads back the availability a worker's hello table states.
fn availability_from(response: &Response) -> Availability {
    let reason = |op: &str| -> Option<String> {
        let entry = response
            .capabilities
            .as_ref()
            .and_then(|table| table.get(op));
        match entry {
            Some(entry) if entry.support == "delivered" => None,
            Some(entry) => Some(
                entry
                    .reason
                    .clone()
                    .filter(|reason| protocol_refusal_code(reason))
                    .unwrap_or_else(|| code::PROVIDER_UNAVAILABLE.to_owned()),
            ),
            None => Some(code::PROVIDER_UNAVAILABLE.to_owned()),
        }
    };
    Availability {
        list_windows: reason("list_windows"),
        observe_window: reason("observe_window"),
        cursor_position: reason("cursor_position"),
        capture_window: reason("capture_window"),
        semantic_action: reason("semantic_action"),
        // The pointer operations share one reason; the keyboard operations
        // may add their own.
        input: crate::input::POINTER_OPERATIONS
            .iter()
            .find_map(|op| reason(op)),
        input_keys: crate::input::KEYBOARD_OPERATIONS
            .iter()
            .find_map(|op| reason(op)),
        permissions: response.permissions.clone().unwrap_or_default(),
    }
}

fn protocol_refusal_code(reason: &str) -> bool {
    matches!(
        reason,
        code::PERMISSION_MISSING | code::PROVIDER_UNAVAILABLE | code::CAPABILITY_DENIED
    )
}

/// Serves request lines until shutdown, end of input, or a line longer than
/// the request bound (which ends the read loop, as on Windows).
pub fn serve(
    mut input: impl BufRead,
    mut output: impl Write,
    platform: HostPlatform,
    dispatch: &mut impl Dispatch,
) -> std::io::Result<()> {
    loop {
        let mut line = Vec::new();
        let read = (&mut input)
            .take(MAX_REQUEST_BYTES as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(());
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.len() > MAX_REQUEST_BYTES {
            return Err(std::io::Error::other("request line exceeds the bound"));
        }
        let (response, stop) = handle_frame(line.trim_ascii(), platform, dispatch);
        let mut raw = protocol::encode_bounded(&response);
        raw.push(b'\n');
        output.write_all(&raw)?;
        output.flush()?;
        if stop {
            return Ok(());
        }
    }
}

pub fn main() -> ExitCode {
    let platform = HostPlatform::current();
    let mut dispatch = match WorkerDispatch::for_current_exe(platform) {
        Ok(dispatch) => dispatch,
        Err(_) => return ExitCode::from(1),
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    match serve(stdin.lock(), stdout.lock(), platform, &mut dispatch) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{LINUX_X11, MACOS};

    /// Records what reached the worker side and answers from a script.
    struct Scripted {
        seen: Vec<String>,
        answer: Box<dyn FnMut(&Request) -> Response>,
    }

    impl Dispatch for Scripted {
        fn dispatch(&mut self, request: &Request) -> Response {
            self.seen.push(request.op.clone());
            (self.answer)(request)
        }
    }

    fn scripted(answer: impl FnMut(&Request) -> Response + 'static) -> Scripted {
        Scripted {
            seen: Vec::new(),
            answer: Box::new(answer),
        }
    }

    fn exchange(lines: &str, dispatch: &mut Scripted) -> Vec<Response> {
        let mut out = Vec::new();
        serve(lines.as_bytes(), &mut out, LINUX_X11, dispatch).unwrap();
        out.split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect()
    }

    #[test]
    fn ping_and_shutdown_never_reach_a_worker() {
        let mut dispatch = scripted(|request| Response::success(request.id));
        let responses = exchange(
            concat!(
                r#"{"id":1,"protocol":"orcel-computer-host/2","op":"ping"}"#,
                "\n",
                r#"{"id":2,"protocol":"orcel-computer-host/2","op":"shutdown"}"#,
                "\n",
                r#"{"id":3,"protocol":"orcel-computer-host/2","op":"ping"}"#,
                "\n"
            ),
            &mut dispatch,
        );
        assert!(dispatch.seen.is_empty());
        assert_eq!(responses.len(), 2, "shutdown ends the loop");
        assert!(responses[0].pong);
        assert!(responses[1].ok);
    }

    #[test]
    fn refused_frames_never_reach_a_worker() {
        let mut dispatch = scripted(|request| Response::success(request.id));
        let responses = exchange(
            concat!(
                r#"{"id":1,"protocol":"orcel-computer-host/2","op":"input_hotkey","key":"a","expected_last_input_tick":1,"window":{"kind":"x11","id":3,"expected_pid":1,"expected_start_generation":2,"expected_window_nonce":3}}"#,
                "\n",
                r#"{"id":2,"protocol":"orcel-computer-host/2","op":"list_windows","surprise":true}"#,
                "\n",
                "not json\n"
            ),
            &mut dispatch,
        );
        assert!(dispatch.seen.is_empty());
        let codes: Vec<_> = responses
            .iter()
            .map(|response| response.error.as_ref().unwrap().code.as_str())
            .collect();
        assert_eq!(
            codes,
            vec!["capability_denied", "invalid_request", "invalid_request"]
        );
    }

    #[test]
    fn hello_uses_the_worker_probe_and_survives_a_failed_one() {
        let mut probe = scripted(|request| {
            let mut availability = Availability::none("permission_missing");
            availability.cursor_position = None;
            protocol::hello(request.id, LINUX_X11, &availability)
        });
        let responses = exchange(
            concat!(
                r#"{"id":1,"protocol":"orcel-computer-host/2","op":"hello"}"#,
                "\n"
            ),
            &mut probe,
        );
        let table = responses[0].capabilities.as_ref().unwrap();
        assert_eq!(probe.seen, vec!["hello"]);
        assert_eq!(table["list_windows"].support, "unavailable");
        assert_eq!(
            table["list_windows"].reason.as_deref(),
            Some("permission_missing")
        );
        assert_eq!(table["cursor_position"].support, "delivered");

        // A crashed probe still answers hello, with observation unavailable.
        let mut crashed = scripted(|request| {
            Response::failure(request.id, "provider_unavailable", "native worker exited")
        });
        let responses = exchange(
            concat!(
                r#"{"id":1,"protocol":"orcel-computer-host/2","op":"hello"}"#,
                "\n"
            ),
            &mut crashed,
        );
        assert!(responses[0].ok);
        let table = responses[0].capabilities.as_ref().unwrap();
        assert_eq!(table["observe_window"].support, "unavailable");

        // A probe for another platform is not trusted.
        let mut foreign = scripted(|request| {
            protocol::hello(request.id, MACOS, &Availability::none("permission_missing"))
        });
        let responses = exchange(
            concat!(
                r#"{"id":1,"protocol":"orcel-computer-host/2","op":"hello"}"#,
                "\n"
            ),
            &mut foreign,
        );
        assert_eq!(responses[0].platform.as_deref(), Some("linux"));
        assert_eq!(
            responses[0].capabilities.as_ref().unwrap()["list_windows"]
                .reason
                .as_deref(),
            Some("provider_unavailable")
        );
    }

    #[test]
    fn oversize_request_line_ends_the_read_loop() {
        let mut dispatch = scripted(|request| Response::success(request.id));
        let big = format!(
            "{{\"id\":1,\"protocol\":\"orcel-computer-host/2\",\"op\":\"ping\",\"text\":\"{}\"}}\n",
            "a".repeat(MAX_REQUEST_BYTES)
        );
        let mut out = Vec::new();
        assert!(serve(big.as_bytes(), &mut out, LINUX_X11, &mut dispatch).is_err());
        assert!(out.is_empty());
    }

    #[test]
    fn worker_responses_must_echo_the_binding() {
        let request = Request {
            id: 9,
            protocol: PROTOCOL_V2.into(),
            op: "list_windows".into(),
            ..Request::default()
        };
        let good = serde_json::to_vec(&Response::success(9)).unwrap();
        let mut noisy = b"library chatter\n".to_vec();
        noisy.extend_from_slice(&good);
        noisy.push(b'\n');
        assert!(decode_worker_response(&request, &noisy).is_ok());
        let wrong_id = serde_json::to_vec(&Response::success(8)).unwrap();
        assert!(decode_worker_response(&request, &wrong_id).is_err());
        let mut wrong_host = Response::success(9);
        wrong_host.host = "orcel-windows-computer-host".into();
        assert!(
            decode_worker_response(&request, &serde_json::to_vec(&wrong_host).unwrap()).is_err()
        );
        assert!(decode_worker_response(&request, b"").is_err());
        assert!(decode_worker_response(&request, b"{\0}").is_err());
    }

    #[test]
    fn worker_environment_drops_everything_not_allowlisted() {
        let environment = worker_environment(LINUX_X11);
        for (name, _) in &environment {
            let name = name.to_string_lossy();
            assert!(WORKER_ENV.contains(&name.as_ref()), "{name}");
            assert!(!name.starts_with("CUA_"), "{name}");
        }
        let wayland = worker_environment(protocol::LINUX_WAYLAND);
        assert!(wayland
            .iter()
            .any(|(name, value)| name == CUA_WAYLAND_OPT_IN && value == "1"));
    }

    #[cfg(unix)]
    fn shell(script: &str, timeout_ms: u64) -> WorkerDispatch {
        WorkerDispatch {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            environment: Vec::new(),
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    #[cfg(unix)]
    fn list_request() -> Request {
        Request {
            id: 4,
            protocol: PROTOCOL_V2.into(),
            op: "list_windows".into(),
            ..Request::default()
        }
    }

    #[cfg(unix)]
    #[test]
    fn worker_killed_at_timeout_returns_a_typed_error() {
        let started = std::time::Instant::now();
        let response = shell("sleep 30", 300).dispatch(&list_request());
        assert_eq!(response.error.unwrap().code, "timeout");
        // Two attempts, each killed at the deadline.
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[cfg(unix)]
    #[test]
    fn worker_crash_is_provider_unavailable_for_that_call_only() {
        let response = shell("exit 3", 2000).dispatch(&list_request());
        assert_eq!(response.error.unwrap().code, "provider_unavailable");
        let answered = shell(
            r#"cat >/dev/null; printf '%s\n' '{"id":4,"ok":true,"protocol":"orcel-computer-host/2","host":"orcel-native-host","windows":[]}'"#,
            2000,
        )
        .dispatch(&list_request());
        assert!(answered.ok);
        assert_eq!(answered.windows, Some(Vec::new()));
    }

    #[cfg(unix)]
    #[test]
    fn oversized_worker_output_is_output_limit() {
        let response = shell(
            "cat >/dev/null; head -c 17000000 /dev/zero | tr '\\0' 'a'",
            5000,
        )
        .dispatch(&list_request());
        assert_eq!(response.error.unwrap().code, "output_limit");
    }

    #[test]
    fn only_semantic_actions_and_raw_input_are_mutations() {
        for op in protocol::OPERATIONS {
            let expected = op == "semantic_action" || op.starts_with("input_");
            let served = !matches!(op, "input_move" | "input_hotkey");
            assert_eq!(is_mutation(op), expected && served, "{op}");
        }
        assert_eq!(MUTATION_ATTEMPTS, 1);
    }

    /// XP-11: an action is delivered at most once. A crashed or timed-out
    /// worker is not run again (it may already have acted), and the answer
    /// says the outcome is unknown.
    #[cfg(unix)]
    #[test]
    fn a_failed_semantic_action_is_never_retried() {
        let counter = std::env::temp_dir().join(format!(
            "orcel-xp11-attempts-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let script = format!(
            "cat >/dev/null; echo ran >> '{}'; exit 3",
            counter.display()
        );
        let action = Request {
            id: 4,
            protocol: PROTOCOL_V2.into(),
            op: "semantic_action".into(),
            ..Request::default()
        };
        let response = shell(&script, 2000).dispatch(&action);
        let error = response.error.unwrap();
        assert_eq!(error.code, "provider_unavailable");
        assert!(error.message.contains("do not repeat"), "{}", error.message);
        assert_eq!(
            std::fs::read_to_string(&counter).unwrap().lines().count(),
            1
        );
        // The same crash on an observation is tried twice.
        let _ = std::fs::remove_file(&counter);
        shell(&script, 2000).dispatch(&list_request());
        assert_eq!(
            std::fs::read_to_string(&counter).unwrap().lines().count(),
            2
        );
        let _ = std::fs::remove_file(&counter);
        // A timed-out action is killed once, too.
        let started = std::time::Instant::now();
        let response = shell("sleep 30", 300).dispatch(&action);
        assert_eq!(response.error.as_ref().unwrap().code, "timeout");
        assert!(response.error.unwrap().message.contains("do not repeat"));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn semantic_frames_that_name_a_position_or_key_never_reach_a_worker() {
        let mut dispatch = scripted(|request| Response::success(request.id));
        let bound = r#""window":{"kind":"x11","id":3,"expected_pid":1,"expected_start_generation":2,"expected_window_nonce":3}"#;
        let frames = [
            format!(
                r#"{{"id":1,"protocol":"orcel-computer-host/2","op":"semantic_action","semantic_action":"invoke","element_runtime_id":"e1-00","x":4,"y":4,{bound}}}"#
            ),
            format!(
                r#"{{"id":2,"protocol":"orcel-computer-host/2","op":"semantic_action","semantic_action":"scroll","element_runtime_id":"e1-00",{bound}}}"#
            ),
            format!(
                r#"{{"id":3,"protocol":"orcel-computer-host/2","op":"window_action","window_action":"close","expected_last_input_tick":1,{bound}}}"#
            ),
            format!(
                r#"{{"id":4,"protocol":"orcel-computer-host/2","op":"input_move","x":4,"y":4,"expected_last_input_tick":1,{bound}}}"#
            ),
        ];
        let responses = exchange(
            &(frames.join(
                "
",
            ) + "
"),
            &mut dispatch,
        );
        assert!(dispatch.seen.is_empty());
        let codes: Vec<_> = responses
            .iter()
            .map(|response| response.error.as_ref().unwrap().code.as_str())
            .collect();
        assert_eq!(
            codes,
            vec![
                "invalid_request",
                "capability_denied",
                "capability_denied",
                "capability_denied"
            ]
        );
    }

    /// XP-12: a raw input frame reaches a worker only with exactly the fields
    /// its operation uses, window-relative and bound to the human-input tick;
    /// a hover and a chord never do.
    #[test]
    fn only_well_formed_raw_input_frames_reach_a_worker() {
        let mut dispatch = scripted(|request| Response::success(request.id));
        let bound = r#""window":{"kind":"x11","id":3,"expected_pid":1,"expected_start_generation":2,"expected_window_nonce":3}"#;
        let frame = |id: u64, op: &str, fields: &str| {
            format!(
                r#"{{"id":{id},"protocol":"orcel-computer-host/2","op":"{op}",{fields}{bound}}}"#
            )
        };
        let frames = [
            frame(
                1,
                "input_click",
                r#""x":4,"y":4,"expected_last_input_tick":9,"#,
            ),
            frame(
                2,
                "input_click",
                r#""x":4,"y":4,"text":"x","expected_last_input_tick":9,"#,
            ),
            frame(3, "input_click", r#""x":4,"y":4,"#),
            frame(4, "input_key", r#""key":"a","expected_last_input_tick":9,"#),
            frame(
                5,
                "input_hotkey",
                r#""key":"a","expected_last_input_tick":9,"#,
            ),
            frame(
                6,
                "input_type_text",
                r#""text":"hi","expected_last_input_tick":9,"#,
            ),
            frame(
                7,
                "input_click",
                r#""x":-4,"y":4,"expected_last_input_tick":9,"#,
            ),
        ];
        let responses = exchange(
            &(frames.join(
                "
",
            ) + "
"),
            &mut dispatch,
        );
        assert_eq!(
            dispatch.seen,
            vec![
                "input_click".to_owned(),
                "input_key".to_owned(),
                "input_type_text".to_owned()
            ]
        );
        let outcome: Vec<_> = responses
            .iter()
            .map(|response| match &response.error {
                None => "ok",
                Some(error) => error.code.as_str(),
            })
            .collect();
        assert_eq!(
            outcome,
            vec![
                "ok",
                "invalid_request",
                "invalid_request",
                "ok",
                "capability_denied",
                "ok",
                "invalid_request"
            ]
        );
    }

    #[test]
    fn a_valid_semantic_frame_reaches_the_worker_with_its_answer_unchanged() {
        let mut dispatch = scripted(|request| {
            let mut response = Response::success(request.id);
            response.action = Some(protocol::ActionFact {
                state: "completed".into(),
                action: "semantic_invoke".into(),
            });
            // A worker must not smuggle hello fields into an action answer.
            response.platform = Some("linux".into());
            response
        });
        let line = r#"{"id":7,"protocol":"orcel-computer-host/2","op":"semantic_action","semantic_action":"invoke","element_runtime_id":"e1-00","window":{"kind":"x11","id":3,"expected_pid":1,"expected_start_generation":2,"expected_window_nonce":3}}"#;
        let responses = exchange(
            &format!(
                "{line}
"
            ),
            &mut dispatch,
        );
        assert_eq!(dispatch.seen, vec!["semantic_action".to_owned()]);
        let action = responses[0].action.as_ref().unwrap();
        assert_eq!(
            (action.state.as_str(), action.action.as_str()),
            ("completed", "semantic_invoke")
        );
        assert!(responses[0].platform.is_none());
    }
}
