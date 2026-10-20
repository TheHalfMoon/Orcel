// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! XP-06 protocol conformance of the real `orcel-native-host` binary over
//! stdio (spec: docs/orcel/implementation-readiness/protocol/
//! ORCEL_COMPUTER_HOST_2.md). These need no desktop session: what a session
//! gives the host is checked by `live_observation.rs`.

mod support;

use serde_json::{json, Value};
use support::{error_code, Host};

const OPERATIONS: [&str; 16] = [
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

fn expected_platform() -> (&'static str, &'static str) {
    if cfg!(target_os = "macos") {
        ("macos", "ax")
    } else if std::env::var_os("WAYLAND_DISPLAY").is_some_and(|value| !value.is_empty()) {
        ("linux", "atspi-wayland")
    } else {
        ("linux", "atspi-x11")
    }
}

#[test]
fn version_flag_prints_the_protocol() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_orcel-native-host"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "orcel-computer-host/2"
    );
}

#[test]
fn hello_reports_platform_backend_and_exactly_one_entry_per_operation() {
    let mut host = Host::spawn();
    let hello = host.hello();
    assert_eq!(hello["ok"], true);
    let (platform, backend) = expected_platform();
    assert_eq!(hello["platform"], platform);
    assert_eq!(hello["backend"], backend);
    let table = hello["capabilities"].as_object().unwrap();
    assert_eq!(table.len(), OPERATIONS.len());
    for op in OPERATIONS {
        let support = table[op]["support"].as_str().unwrap();
        match op {
            "hello" | "ping" | "shutdown" => assert_eq!(support, "delivered"),
            "list_windows" | "observe_window" | "cursor_position" => {
                assert!(matches!(support, "delivered" | "unavailable"), "{op}");
                if support == "unavailable" {
                    let reason = table[op]["reason"].as_str().unwrap();
                    assert!(
                        matches!(reason, "permission_missing" | "provider_unavailable"),
                        "{op}: {reason}"
                    );
                }
            }
            // XP-07 and XP-11: delivered in the background where the session
            // allows it, otherwise unavailable with a reason.
            "capture_window" | "semantic_action" => match support {
                "delivered" => assert_eq!(table[op]["delivery"], "background"),
                "unavailable" => {
                    let reason = table[op]["reason"].as_str().unwrap();
                    assert!(
                        matches!(reason, "permission_missing" | "provider_unavailable"),
                        "{op}: {reason}"
                    );
                }
                other => panic!("{op} support {other}"),
            },
            _ => {
                assert_eq!(support, "refused", "{op}");
                assert_eq!(table[op]["reason"], "capability_denied", "{op}");
            }
        }
    }
    assert!(host.shutdown().success());
}

#[test]
fn session_ops_unknown_ops_and_mutations_are_answered_without_native_work() {
    let mut host = Host::spawn();
    assert_eq!(host.request("ping", json!({}))["pong"], true);
    let unknown = host.request("run_script", json!({}));
    assert_eq!(error_code(&unknown), "capability_denied");
    let binding = json!({"window": {"kind": support::window_kind(), "id": 9, "expected_pid": 1,
        "expected_start_generation": 2, "expected_window_nonce": 3}});
    for (op, extra) in [
        (
            "window_action",
            json!({"window_action": "focus", "expected_last_input_tick": 1}),
        ),
        (
            "input_click",
            json!({"x": 1, "y": 1, "button": "left", "click_count": 1, "expected_last_input_tick": 1}),
        ),
        (
            "input_type_text",
            json!({"text": "x", "expected_last_input_tick": 1}),
        ),
    ] {
        let mut fields = binding.clone();
        fields
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let reply = host.request(op, fields);
        assert_eq!(reply["ok"], false, "{op}");
        assert_eq!(error_code(&reply), "capability_denied", "{op}");
    }
    assert!(host.shutdown().success());
}

/// XP-11: a semantic action names a window and an element and nothing else.
/// A frame that names a point, a key or text, a scroll (a wheel event) and an
/// unbound frame are refused before any native work; a bound frame no live
/// window of this user holds is refused with a typed code and acts on
/// nothing.
#[test]
fn semantic_actions_are_element_addressed_and_refused_without_a_live_target() {
    let mut host = Host::spawn();
    let binding = json!({"window": {"kind": support::window_kind(), "id": 9, "expected_pid": 1,
        "expected_start_generation": 2, "expected_window_nonce": 3}});
    let with = |extra: Value| {
        let mut fields = binding.clone();
        fields
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        fields
    };
    for extra in [
        json!({"semantic_action": "invoke", "element_runtime_id": "e1-00", "x": 1, "y": 1}),
        json!({"semantic_action": "invoke", "element_runtime_id": "e1-00", "button": "left"}),
        json!({"semantic_action": "invoke", "element_runtime_id": "e1-00", "text": "typed"}),
        json!({"semantic_action": "invoke", "element_runtime_id": "e1-00", "key": "enter"}),
        json!({"semantic_action": "invoke", "element_runtime_id": "e1-00", "expected_last_input_tick": 0}),
        json!({"semantic_action": "invoke", "element_runtime_id": "e1-00", "value": "not a set_value"}),
        json!({"semantic_action": "click", "element_runtime_id": "e1-00"}),
        json!({"semantic_action": "invoke"}),
        json!({"element_runtime_id": "e1-00"}),
    ] {
        let reply = host.request("semantic_action", with(extra.clone()));
        assert_eq!(error_code(&reply), "invalid_request", "{extra}: {reply}");
    }
    let unbound = host.request(
        "semantic_action",
        json!({"semantic_action": "invoke", "element_runtime_id": "e1-00"}),
    );
    assert_eq!(error_code(&unbound), "invalid_request", "{unbound}");
    let scroll = host.request(
        "semantic_action",
        with(json!({"semantic_action": "scroll", "element_runtime_id": "e1-00"})),
    );
    assert_eq!(error_code(&scroll), "capability_denied", "{scroll}");
    // A binding no live window holds: never delivered.
    for extra in [
        json!({"semantic_action": "invoke", "element_runtime_id": "e1-0011223344556677"}),
        json!({"semantic_action": "set_value", "element_runtime_id": "e1-0011223344556677", "value": "x"}),
        json!({"semantic_action": "select", "element_runtime_id": "e1-0011223344556677"}),
        json!({"semantic_action": "toggle", "element_runtime_id": "e1-0011223344556677", "value": "true"}),
    ] {
        let reply = host.request("semantic_action", with(extra.clone()));
        assert_eq!(reply["ok"], false, "{extra}: {reply}");
        assert!(reply.get("action").is_none(), "{reply}");
        assert!(
            matches!(
                error_code(&reply),
                "target_stale"
                    | "provider_unavailable"
                    | "permission_missing"
                    | "protected_surface"
            ),
            "{extra}: {reply}"
        );
    }
    assert!(host.shutdown().success());
}

/// XP-07: capture is served as an observation. A binding no live window of
/// this user holds is refused with a typed code and no pixels; it is never
/// `capability_denied`, and never answered with a frame.
#[test]
fn capture_of_a_window_that_is_not_a_target_is_refused_without_pixels() {
    let mut host = Host::spawn();
    let hello = host.hello();
    let entry = hello["capabilities"]["capture_window"].clone();
    for pid in [1u64, 4_000_000] {
        let reply = host.request(
            "capture_window",
            json!({"window": {"kind": support::window_kind(), "id": 9, "expected_pid": pid,
                "expected_start_generation": 2, "expected_window_nonce": 3}}),
        );
        assert_eq!(reply["ok"], false, "{reply}");
        assert!(reply.get("capture").is_none(), "{reply}");
        let code = error_code(&reply);
        if entry["support"] == "delivered" {
            // pid 1 runs as another user (excluded); no process holds the
            // other pid (stale).
            assert!(
                matches!(code, "protected_surface" | "target_stale"),
                "{pid}: {reply}"
            );
        } else {
            assert_eq!(code, entry["reason"].as_str().unwrap(), "{reply}");
        }
    }
    assert!(host.shutdown().success());
}

#[test]
fn malformed_frames_are_refused_with_typed_errors() {
    let mut host = Host::spawn();
    let corrupt = host.send_raw("{not json").unwrap();
    assert_eq!(corrupt["id"], 0);
    assert_eq!(corrupt["protocol"], "orcel-computer-host/1");
    assert_eq!(error_code(&corrupt), "invalid_request");
    let v1 = host
        .send_raw(r#"{"id":5,"protocol":"orcel-computer-host/1","op":"hello"}"#)
        .unwrap();
    assert_eq!(v1["protocol"], "orcel-computer-host/1");
    assert_eq!(error_code(&v1), "invalid_request");
    for fields in [
        json!({"surprise": true}),
        json!({"hwnd": 9, "expected_pid": 1, "expected_start_generation": 2, "expected_window_nonce": 3}),
        json!({"window": {"kind": "hwnd", "id": 9, "expected_pid": 1, "expected_start_generation": 2, "expected_window_nonce": 3}}),
        json!({"window": {"kind": support::window_kind(), "id": 9, "expected_pid": 1}}),
        json!({}),
    ] {
        let reply = host.request("observe_window", fields.clone());
        assert_eq!(error_code(&reply), "invalid_request", "{fields}");
    }
    assert!(host.shutdown().success());
}

#[test]
fn oversize_request_ends_the_session_without_an_answer() {
    let mut host = Host::spawn();
    let line = format!(
        r#"{{"id":1,"protocol":"orcel-computer-host/2","op":"ping","text":"{}"}}"#,
        "a".repeat(70 * 1024)
    );
    assert!(host.send_raw(&line).is_none());
    let status = host.child.wait().unwrap();
    assert!(!status.success());
}

#[test]
fn a_stale_binding_never_observes() {
    let mut host = Host::spawn();
    let hello = host.hello();
    if hello["capabilities"]["observe_window"]["support"] != "delivered" {
        // Without a session the worker refuses before any binding check.
        let reply = host.request(
            "observe_window",
            json!({"window": {"kind": support::window_kind(), "id": 9, "expected_pid": 1,
                "expected_start_generation": 2, "expected_window_nonce": 3}}),
        );
        assert_eq!(reply["ok"], false);
        let reason = hello["capabilities"]["observe_window"]["reason"].clone();
        assert_eq!(reply["error"]["code"], reason);
        return;
    }
    // A pid that no process holds is a stale binding.
    let reply = host.request(
        "observe_window",
        json!({"window": {"kind": support::window_kind(), "id": 9, "expected_pid": 4_000_000,
            "expected_start_generation": 2, "expected_window_nonce": 3}}),
    );
    assert_eq!(error_code(&reply), "target_stale", "{reply}");
}

/// Unavailability is reported, never prompted for, and every observation
/// refuses with the reason the hello stated.
#[test]
fn missing_session_or_permission_is_unavailable_with_its_reason() {
    #[cfg(target_os = "macos")]
    let environment: Vec<(String, std::ffi::OsString)> = Vec::new();
    // No DISPLAY, WAYLAND_DISPLAY or session bus.
    #[cfg(not(target_os = "macos"))]
    let environment: Vec<(String, std::ffi::OsString)> = std::env::var_os("PATH")
        .map(|path| ("PATH".to_owned(), path))
        .into_iter()
        .collect();
    let mut host = Host::spawn_with(environment);
    let hello = host.hello();
    let table = hello["capabilities"].clone();
    if cfg!(not(target_os = "macos")) {
        for op in [
            "list_windows",
            "observe_window",
            "cursor_position",
            "capture_window",
        ] {
            assert_eq!(table[op]["support"], "unavailable", "{op}");
            assert_eq!(table[op]["reason"], "provider_unavailable", "{op}");
        }
    }
    let permissions = hello["permissions"].clone();
    if cfg!(target_os = "macos") {
        let granted =
            permissions["accessibility"] == true && permissions["screen_recording"] == true;
        let expected = if granted { "delivered" } else { "unavailable" };
        assert_eq!(table["list_windows"]["support"], expected, "{hello}");
        if !granted {
            assert_eq!(table["list_windows"]["reason"], "permission_missing");
            assert_eq!(table["capture_window"]["reason"], "permission_missing");
        }
        // XP-07: capture also needs the direct-capture consent recorded.
        if permissions["direct_capture_consent"] == false {
            assert_eq!(table["capture_window"]["support"], "unavailable");
            assert_eq!(table["capture_window"]["reason"], "permission_missing");
        }
        eprintln!("XP-06 macOS permissions on this runner: {permissions}");
    }
    let listed = host.request("list_windows", json!({}));
    match table["list_windows"]["support"].as_str() {
        Some("unavailable") => {
            assert_eq!(listed["ok"], false);
            assert_eq!(listed["error"]["code"], table["list_windows"]["reason"]);
        }
        _ => assert_eq!(listed["ok"], true, "{listed}"),
    }
    assert!(host.shutdown().success());
}

/// S-02 and release acceptance 3: the host holds only its inherited stdio
/// (pipes and /dev/null), no socket of any kind.
#[cfg(target_os = "linux")]
#[test]
fn host_holds_only_inherited_stdio() {
    let mut host = Host::spawn();
    host.hello();
    host.request("list_windows", json!({}));
    let pid = host.child.id();
    let mut targets = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd")).unwrap() {
        let target = std::fs::read_link(entry.unwrap().path()).unwrap();
        targets.push(target.to_string_lossy().into_owned());
    }
    for target in &targets {
        assert!(
            target.starts_with("pipe:") || target == "/dev/null",
            "unexpected descriptor {target} in {targets:?}"
        );
    }
    assert!(host.shutdown().success());
}

/// Descriptors of `pid` numbered 0..1023, one `lsof` line each.
#[cfg(target_os = "macos")]
fn descriptors(pid: u32) -> Vec<String> {
    let output = std::process::Command::new("lsof")
        .args(["-n", "-P", "-a", "-p", &pid.to_string(), "-d", "0-1023"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip(1)
        .map(str::to_owned)
        .collect()
}

/// A NetworkStatistics kernel-control socket. On the macOS runner every
/// process gets these from libSystem's own start-up: in the XP-06 diagnostic
/// (run 39352665447, job 118400225275) a C program linking nothing but
/// libSystem held the same two as the host, and linking any of the host's
/// frameworks added none. They carry no route, address or connection.
#[cfg(target_os = "macos")]
fn is_netsrc_control(line: &str) -> bool {
    line.split_whitespace().nth(4) == Some("systm") && line.contains("[ctl com.apple.netsrc ")
}

#[cfg(target_os = "macos")]
#[test]
fn host_holds_only_inherited_stdio() {
    let mut host = Host::spawn();
    host.hello();
    let pid = host.child.id();
    let listing = descriptors(pid);
    let mut netsrc = 0;
    for line in &listing {
        if is_netsrc_control(line) {
            netsrc += 1;
            continue;
        }
        let kind = line.split_whitespace().nth(4).unwrap_or_default();
        assert!(
            matches!(kind, "PIPE" | "CHR" | "REG" | "DIR"),
            "unexpected descriptor: {line}
{listing:#?}"
        );
        assert!(
            !line.contains("TCP") && !line.contains("UDP") && kind != "unix",
            "{line}"
        );
    }
    // The host may hold no more of those sockets than a plain system
    // process started the same way: anything beyond the baseline would be
    // the host's own.
    let mut baseline = std::process::Command::new("/bin/sleep")
        .arg("5")
        .stdin(std::process::Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let baseline_netsrc = descriptors(baseline.id())
        .iter()
        .filter(|line| is_netsrc_control(line))
        .count();
    let _ = baseline.kill();
    let _ = baseline.wait();
    assert!(
        netsrc <= baseline_netsrc,
        "host holds {netsrc} netsrc control sockets, a plain process {baseline_netsrc}: {listing:#?}"
    );
    eprintln!("XP-06 macOS descriptors: netsrc host={netsrc} baseline={baseline_netsrc}; others pipes/devices only");
    assert!(host.shutdown().success());
}

/// The registry never sees a response it cannot bound: a response line is
/// at most 16 MiB (checked in unit tests); here the frame log stays JSON.
#[test]
fn every_response_line_is_one_json_object() {
    let mut host = Host::spawn();
    host.hello();
    host.request("ping", json!({}));
    for line in &host.log {
        let value: Value = serde_json::from_str(line).unwrap();
        assert!(value.is_object());
    }
}
