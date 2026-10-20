// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! XP-12 raw input, measured against an application that journals what it
//! receives, through the real host.
//!
//! Runs only with `ORCEL_XP12_LIVE=1` and fails, rather than skipping, when
//! the session cannot deliver input. CI runs it on Linux under Xvfb and
//! Openbox with the Tk probe (`fixtures/tk_input_probe.py`) and on the
//! hosted macOS session with the AppKit probe
//! (`fixtures/appkit_input_probe.swift`, compiled here with `swiftc`).
//!
//! The probe writes a state file with every pointer, scroll and key event it
//! received, in window-relative coordinates, and with the window's screen
//! origin and size. Nothing in an assertion is the host's own claim of
//! success: a delivered cell is read from the probe's journal, and a refused
//! cell must leave the journal exactly as it was.

mod support;

use serde_json::{json, Value};
#[cfg(target_os = "linux")]
use std::process::Command;
use std::time::{Duration, Instant};
use support::{error_code, events, read_state, spawn_probe, wait_for, window_ref, Host, Probe};

fn find_window(host: &mut Host, title: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let listed = host.request("list_windows", json!({}));
        assert_eq!(listed["ok"], true, "{listed}");
        if let Some(window) = listed["windows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|window| window["title"] == title)
        {
            return window.clone();
        }
        assert!(Instant::now() < deadline, "{title} never listed: {listed}");
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// The human-input tick the kernel would read right before arming a unit.
fn tick(host: &mut Host) -> u64 {
    let cursor = host.request("cursor_position", json!({}));
    assert_eq!(cursor["ok"], true, "{cursor}");
    let tick = cursor["cursor"]["last_input_tick"].as_u64().unwrap();
    assert_ne!(
        tick, 0,
        "the session has no readable human-input clock: {cursor}"
    );
    tick
}

/// Sends one input with a fresh tick.
fn input(host: &mut Host, reference: &Value, op: &str, mut fields: Value) -> Value {
    fields["window"] = reference.clone();
    fields["expected_last_input_tick"] = json!(tick(host));
    host.request(op, fields)
}

fn assert_refused(reply: &Value, code: &str, what: &str) {
    assert_eq!(reply["ok"], false, "{what} was not refused: {reply}");
    assert_eq!(error_code(reply), code, "{what}: {reply}");
    assert!(reply.get("action").is_none(), "{what}: {reply}");
}

/// A refused frame leaves the journal exactly as it was, after an event had
/// time to arrive.
fn assert_unchanged(probe: &Probe, before: &Value, what: &str) {
    std::thread::sleep(Duration::from_millis(400));
    let after = read_state(&probe.state).expect("the probe keeps its state file");
    assert_eq!(
        events(before),
        events(&after),
        "{what}: the application received input it should not have"
    );
}

fn near(value: &Value, expected: f64, what: &str) {
    let got = value.as_f64().unwrap_or(f64::NAN);
    assert!(
        (got - expected).abs() <= 2.0,
        "{what}: expected {expected} got {got}"
    );
}

/// The journal entries after the first `skip`.
fn new_events(probe: &Probe, skip: usize) -> Vec<Value> {
    events(&read_state(&probe.state).unwrap())
        .into_iter()
        .skip(skip)
        .collect()
}

fn wait_for_events(probe: &Probe, skip: usize, wanted: usize, what: &str) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let fresh = new_events(probe, skip);
        if fresh.len() >= wanted {
            // Let a trailing event arrive before the cell is judged.
            std::thread::sleep(Duration::from_millis(300));
            return new_events(probe, skip);
        }
        assert!(
            Instant::now() < deadline,
            "{what}: the application received {fresh:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A session that cannot deliver: every raw input operation is unavailable
/// with a reason, a frame is refused with that reason and the probe receives
/// nothing. The host never prompts for the missing permission.
fn report_only(host: &mut Host, probe: &Probe, hello: &Value, nonce: &str) {
    let mut reasons = Vec::new();
    for op in [
        "input_click",
        "input_drag",
        "input_scroll",
        "input_type_text",
        "input_key",
    ] {
        assert_eq!(hello["capabilities"][op]["support"], "unavailable", "{op}");
        let reason = hello["capabilities"][op]["reason"]
            .as_str()
            .unwrap_or_default();
        assert!(
            matches!(reason, "permission_missing" | "provider_unavailable"),
            "{op}: {hello}"
        );
        reasons.push(reason.to_owned());
    }
    let window = find_window(host, &format!("Orcel XP12 Input {nonce}"));
    let reference = window_ref(&window);
    wait_for(&probe.state, "state", |state| state["size"][0].is_number());
    let before = read_state(&probe.state).unwrap();
    for (op, fields, reason) in [
        (
            "input_click",
            json!({"x": 10, "y": 10, "button": "left", "click_count": 1}),
            &reasons[0],
        ),
        ("input_type_text", json!({"text": "refused"}), &reasons[3]),
        ("input_key", json!({"key": "tab"}), &reasons[4]),
    ] {
        let mut fields = fields;
        fields["window"] = reference.clone();
        fields["expected_last_input_tick"] = json!(1);
        let reply = host.request(op, fields);
        assert_refused(&reply, reason, op);
    }
    assert_unchanged(probe, &before, "an unavailable session");
}

#[test]
fn xp12_raw_input_lands_where_approved_and_nowhere_else() {
    if std::env::var_os("ORCEL_XP12_LIVE").is_none() {
        eprintln!("XP-12 live input not run: ORCEL_XP12_LIVE is not set");
        return;
    }
    let nonce = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let probe = spawn_probe(&nonce);
    let mut host = Host::spawn();
    let hello = host.hello();
    // `report` mode is for a session that cannot deliver (the hosted macOS
    // runner has no recorded direct-capture consent, which Cua's pixel tools
    // need to measure a window's scale): the five operations must say so, with
    // the reason, and a frame must deliver nothing.
    let delivered = hello["capabilities"]["input_click"]["support"] == "delivered";
    if !delivered {
        assert_eq!(
            std::env::var("ORCEL_XP12_LIVE").as_deref(),
            Ok("report"),
            "this session cannot deliver input: {hello}"
        );
        report_only(&mut host, &probe, &hello, &nonce);
        return;
    }
    for op in [
        "input_click",
        "input_drag",
        "input_scroll",
        "input_type_text",
        "input_key",
    ] {
        assert_eq!(
            hello["capabilities"][op]["support"], "delivered",
            "{op}: this session cannot deliver input: {hello}"
        );
        assert_eq!(hello["capabilities"][op]["delivery"], "background", "{op}");
    }
    for op in ["input_move", "input_hotkey", "window_action"] {
        assert_eq!(hello["capabilities"][op]["support"], "refused", "{op}");
    }

    let window = find_window(&mut host, &format!("Orcel XP12 Input {nonce}"));
    assert_eq!(window["process"]["pid"], probe.child.id(), "{window}");
    let reference = window_ref(&window);
    let approval = find_window(&mut host, &format!("Orcel Approval Probe {nonce}"));
    let approval_reference = window_ref(&approval);
    let state = wait_for(&probe.state, "state", |state| {
        state["size"][0].as_f64().unwrap_or(0.0) > 0.0
    });
    let (width, height) = (
        state["size"][0].as_f64().unwrap(),
        state["size"][1].as_f64().unwrap(),
    );
    assert!(events(&state).is_empty(), "{state}");

    // ---- delivered: each lands where the frame named, in window-relative
    // coordinates, and as the kind of input asked for.
    let mut seen = 0usize;
    let reply = input(
        &mut host,
        &reference,
        "input_click",
        json!({"x": 120, "y": 90, "button": "left", "click_count": 1}),
    );
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["action"]["state"], "completed", "{reply}");
    assert_eq!(reply["action"]["action"], "input_click", "{reply}");
    let got = wait_for_events(&probe, seen, 2, "left click");
    assert_eq!(got[0]["kind"], "down", "{got:?}");
    near(&got[0]["x"], 120.0, "left click x");
    near(&got[0]["y"], 90.0, "left click y");
    assert_eq!(got[0]["button"], 1, "{got:?}");
    assert_eq!(got.last().unwrap()["kind"], "up", "{got:?}");
    seen += got.len();

    let reply = input(
        &mut host,
        &reference,
        "input_click",
        json!({"x": 200, "y": 150, "button": "right", "click_count": 1}),
    );
    assert_eq!(reply["ok"], true, "{reply}");
    let got = wait_for_events(&probe, seen, 2, "right click");
    assert_eq!(got[0]["button"], 3, "{got:?}");
    near(&got[0]["x"], 200.0, "right click x");
    near(&got[0]["y"], 150.0, "right click y");
    seen += got.len();

    let reply = input(
        &mut host,
        &reference,
        "input_click",
        json!({"x": 60, "y": 70, "button": "left", "click_count": 2}),
    );
    assert_eq!(reply["ok"], true, "{reply}");
    let got = wait_for_events(&probe, seen, 4, "double click");
    let downs: Vec<_> = got.iter().filter(|event| event["kind"] == "down").collect();
    assert!(downs.len() >= 2, "{got:?}");
    assert!(
        got.iter().any(|event| event["clicks"] == 2),
        "the application saw no double click: {got:?}"
    );
    seen += got.len();

    let reply = input(
        &mut host,
        &reference,
        "input_drag",
        json!({"x": 50, "y": 60, "to_x": 250, "to_y": 160}),
    );
    assert_eq!(reply["ok"], true, "{reply}");
    let got = wait_for_events(&probe, seen, 3, "drag");
    assert_eq!(got.first().unwrap()["kind"], "down", "{got:?}");
    near(&got.first().unwrap()["x"], 50.0, "drag start x");
    near(&got.first().unwrap()["y"], 60.0, "drag start y");
    assert_eq!(got.last().unwrap()["kind"], "up", "{got:?}");
    near(&got.last().unwrap()["x"], 250.0, "drag end x");
    near(&got.last().unwrap()["y"], 160.0, "drag end y");
    assert!(got.iter().any(|event| event["kind"] == "motion"), "{got:?}");
    seen += got.len();

    let reply = input(
        &mut host,
        &reference,
        "input_scroll",
        json!({"x": 100, "y": 100, "scroll_x": 0, "scroll_y": 3}),
    );
    assert_eq!(reply["ok"], true, "{reply}");
    let got = wait_for_events(&probe, seen, 1, "scroll down");
    assert!(got.iter().all(|event| event["kind"] == "scroll"), "{got:?}");
    let down = got.iter().any(|event| {
        event["direction"] == "down" || event["dy"].as_f64().is_some_and(|dy| dy != 0.0)
    });
    assert!(down, "{got:?}");
    seen += got.len();

    let text = "hello 12";
    let reply = input(
        &mut host,
        &reference,
        "input_type_text",
        json!({ "text": text }),
    );
    assert_eq!(reply["ok"], true, "{reply}");
    let got = wait_for_events(&probe, seen, text.chars().count(), "typed text");
    let typed: String = got
        .iter()
        .filter(|event| event["kind"] == "key")
        .map(|event| event["string"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(typed, text, "{got:?}");
    seen += got.len();

    let reply = input(&mut host, &reference, "input_key", json!({"key": "tab"}));
    assert_eq!(reply["ok"], true, "{reply}");
    let got = wait_for_events(&probe, seen, 1, "tab");
    assert!(got.iter().all(|event| event["kind"] == "key"), "{got:?}");
    seen += got.len();

    // ---- refused, with the journal untouched.
    let before = read_state(&probe.state).unwrap();
    assert_eq!(events(&before).len(), seen, "{before}");

    // A point outside the window is refused, never clamped onto its edge.
    for (x, y) in [
        (width as i64, 10),
        (10, height as i64),
        (width as i64 + 500, height as i64 + 500),
        (1_000_000, 1),
    ] {
        let reply = input(
            &mut host,
            &reference,
            "input_click",
            json!({"x": x, "y": y, "button": "left", "click_count": 1}),
        );
        assert_refused(&reply, "invalid_request", &format!("click at {x},{y}"));
    }
    let reply = input(
        &mut host,
        &reference,
        "input_drag",
        json!({"x": 10, "y": 10, "to_x": width as i64 + 40, "to_y": 20}),
    );
    assert_refused(&reply, "invalid_request", "a drag that ends outside");
    let reply = input(
        &mut host,
        &reference,
        "input_scroll",
        json!({"x": 10, "y": height as i64 + 5, "scroll_x": 0, "scroll_y": 1}),
    );
    assert_refused(&reply, "invalid_request", "a scroll outside");
    assert_unchanged(&probe, &before, "points outside the window");

    // Bounded text and scroll, and no key that reaches a system shortcut.
    let reply = input(
        &mut host,
        &reference,
        "input_type_text",
        json!({"text": "a".repeat(257)}),
    );
    assert_refused(&reply, "invalid_request", "over-long text");
    let reply = input(
        &mut host,
        &reference,
        "input_type_text",
        json!({"text": "line\nbreak"}),
    );
    assert_refused(&reply, "invalid_request", "text with a control character");
    let reply = input(
        &mut host,
        &reference,
        "input_scroll",
        json!({"x": 10, "y": 10, "scroll_x": 0, "scroll_y": 21}),
    );
    assert_refused(&reply, "invalid_request", "an over-large scroll");
    for key in [
        "ctrl+alt+delete",
        "ctrl+alt+l",
        "alt+f4",
        "super",
        "cmd+q",
        "cmd+space",
        "ctrl+cmd+q",
        "f1",
        "ctrl",
    ] {
        let reply = input(&mut host, &reference, "input_key", json!({ "key": key }));
        assert_refused(&reply, "capability_denied", key);
    }
    for (op, fields) in [
        ("input_move", json!({"x": 10, "y": 10})),
        ("input_hotkey", json!({"key": "ctrl+a"})),
        ("window_action", json!({"window_action": "close"})),
    ] {
        let reply = input(&mut host, &reference, op, fields);
        assert_refused(&reply, "capability_denied", op);
    }
    assert_unchanged(&probe, &before, "limits and shortcuts");

    // An unapproved shape: no human-input tick, a foreign field.
    let reply = host.request(
        "input_click",
        json!({"window": reference, "x": 10, "y": 10, "button": "left", "click_count": 1}),
    );
    assert_refused(&reply, "invalid_request", "a click without a tick");
    let reply = host.request(
        "input_click",
        json!({"window": reference, "x": 10, "y": 10, "text": "x", "expected_last_input_tick": 1}),
    );
    assert_refused(&reply, "invalid_request", "a click carrying text");

    // A tick that is not the live one: someone touched the machine, or the
    // kernel never read it.
    let stale = (tick(&mut host) as u32).wrapping_sub(60_000);
    let reply = host.request(
        "input_click",
        json!({"window": reference, "x": 10, "y": 10, "button": "left",
               "click_count": 1, "expected_last_input_tick": stale}),
    );
    assert_refused(&reply, "cancelled", "a click on a stale tick");
    let reply = host.request(
        "input_type_text",
        json!({"window": reference, "text": "abc", "expected_last_input_tick": 1}),
    );
    assert_refused(&reply, "cancelled", "typing on a stale tick");
    assert_unchanged(&probe, &before, "stale ticks");

    // A binding that does not name the live window.
    let mut wrong_nonce = reference.clone();
    wrong_nonce["expected_window_nonce"] = json!(1);
    let reply = input(
        &mut host,
        &wrong_nonce,
        "input_click",
        json!({"x": 10, "y": 10, "button": "left", "click_count": 1}),
    );
    assert_refused(&reply, "target_stale", "a click on another nonce");
    let mut wrong_generation = reference.clone();
    wrong_generation["expected_start_generation"] = json!(1);
    let reply = input(
        &mut host,
        &wrong_generation,
        "input_key",
        json!({"key": "a"}),
    );
    assert_refused(&reply, "target_stale", "a key on another generation");
    assert_unchanged(&probe, &before, "stale bindings");

    // An Orcel approval surface takes no input: an agent can never press
    // Approve with a pixel.
    for (op, fields) in [
        (
            "input_click",
            json!({"x": 20, "y": 20, "button": "left", "click_count": 1}),
        ),
        ("input_type_text", json!({"text": "approve"})),
        ("input_key", json!({"key": "enter"})),
        (
            "input_scroll",
            json!({"x": 20, "y": 20, "scroll_x": 0, "scroll_y": 1}),
        ),
        (
            "input_drag",
            json!({"x": 5, "y": 5, "to_x": 50, "to_y": 50}),
        ),
    ] {
        let reply = input(&mut host, &approval_reference, op, fields);
        assert_refused(&reply, "protected_surface", op);
    }
    assert_unchanged(&probe, &before, "the protected approval window");

    // A covered window takes no input. The cover goes over the target; the
    // host never raises the target to get past it.
    std::fs::write(&probe.flag, b"cover").unwrap();
    wait_for(&probe.state, "the cover", |state| state["cover"] == true);
    std::thread::sleep(Duration::from_millis(800));
    let covered_before = read_state(&probe.state).unwrap();
    for (op, fields) in [
        (
            "input_click",
            json!({"x": 100, "y": 100, "button": "left", "click_count": 1}),
        ),
        ("input_key", json!({"key": "a"})),
        ("input_type_text", json!({"text": "covered"})),
    ] {
        let reply = input(&mut host, &reference, op, fields);
        assert_eq!(reply["ok"], false, "{op} reached a covered window: {reply}");
        assert_eq!(error_code(&reply), "provider_unavailable", "{op}: {reply}");
        let message = reply["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("obscured") || message.contains("covers"),
            "{op}: {reply}"
        );
    }
    assert_unchanged(&probe, &covered_before, "the covered window");
    std::fs::remove_file(&probe.flag).unwrap();
    wait_for(&probe.state, "the cover to go", |state| {
        state["cover"] == false
    });
    std::thread::sleep(Duration::from_millis(800));
    let reply = input(
        &mut host,
        &reference,
        "input_click",
        json!({"x": 100, "y": 100, "button": "left", "click_count": 1}),
    );
    assert_eq!(reply["ok"], true, "uncovered again: {reply}");
    let after_cover = wait_for_events(&probe, events(&covered_before).len(), 2, "uncovered");
    assert_eq!(after_cover[0]["kind"], "down", "{after_cover:?}");

    #[cfg(target_os = "linux")]
    human_input_cancels(&mut host, &reference, &probe);

    for line in &host.log {
        assert!(!line.contains("\"pixels_b64\""), "no frame is read back");
    }
    drop(probe);
    assert!(host.shutdown().success());
}

/// The person touches the pointer after the kernel read the tick: the input
/// is cancelled and the application receives nothing. `xdotool` stands in for
/// the person; its XTest motion moves the X server's idle clock the way a
/// real device does.
#[cfg(target_os = "linux")]
fn human_input_cancels(host: &mut Host, reference: &Value, probe: &Probe) {
    let before = read_state(&probe.state).unwrap();
    let read = tick(host);
    std::thread::sleep(Duration::from_millis(1500));
    let moved = Command::new("xdotool")
        .args(["mousemove_relative", "--", "1", "1"])
        .status()
        .expect("xdotool runs");
    assert!(moved.success());
    std::thread::sleep(Duration::from_millis(500));
    let reply = host.request(
        "input_click",
        json!({"window": reference, "x": 30, "y": 30, "button": "left",
               "click_count": 1, "expected_last_input_tick": read}),
    );
    assert_refused(&reply, "cancelled", "a click after human input");
    let reply = host.request(
        "input_type_text",
        json!({"window": reference, "text": "typed over a person", "expected_last_input_tick": read}),
    );
    assert_refused(&reply, "cancelled", "typing after human input");
    assert_unchanged(probe, &before, "human input");
    // With the tick read again, the same click goes through.
    let reply = input(
        host,
        reference,
        "input_click",
        json!({"x": 30, "y": 30, "button": "left", "click_count": 1}),
    );
    assert_eq!(reply["ok"], true, "{reply}");
}
