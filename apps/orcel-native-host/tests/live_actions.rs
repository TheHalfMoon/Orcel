// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! XP-11 live refusals and one real action, through the real host.
//!
//! Runs only with `ORCEL_XP11_LIVE=1` and fails, rather than skipping, when
//! the session cannot observe. CI runs it on Linux under Xvfb, Openbox and
//! the AT-SPI bus with the GTK3 probe of XP-06 (`fixtures/gtk3_probe.py`:
//! a plain entry, a password entry named "Sign in", a button, and a second
//! window titled as an Orcel approval surface). On macOS it is a manual check
//! with the AppKit probe (`fixtures/appkit_probe_native.swift`); the commands are in
//! SECURITY_INTEGRATION.md.
//!
//! It checks what the measured conformance cells (`conformance_native.rs`)
//! cannot: a password field takes no action, an Orcel approval window takes
//! no action (an agent can never press Approve), a pixel-addressed frame on
//! a stale human-input tick delivers nothing, and the secret never appears in
//! a frame.

mod support;

use serde_json::{json, Value};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use support::{error_code, flatten, window_ref, Host};

struct Probe(Child);

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_probe(nonce: &str, secret: &str) -> Probe {
    let fixtures = std::env::var("ORCEL_NATIVE_TEST_FIXTURES")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures").to_string());
    let mut command = if cfg!(target_os = "macos") {
        let bin = std::env::var_os("ORCEL_MACOS_AX_PROBE_BIN")
            .expect("macOS real-hardware live tests require ORCEL_MACOS_AX_PROBE_BIN pointing to the compiled native Swift AppKit fixture");
        Command::new(bin)
    } else {
        let mut command = Command::new("python3");
        command.arg(format!("{fixtures}/gtk3_probe.py"));
        command
    };
    Probe(
        command
            .args([nonce, secret])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .expect("the probe starts"),
    )
}

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

fn action(host: &mut Host, reference: &Value, verb: &str, id: &str, value: Option<&str>) -> Value {
    let mut fields = json!({
        "window": reference,
        "semantic_action": verb,
        "element_runtime_id": id,
    });
    if let Some(value) = value {
        fields["value"] = json!(value);
    }
    host.request("semantic_action", fields)
}

#[test]
fn xp11_live_refusals_and_one_real_action() {
    if std::env::var_os("ORCEL_XP11_LIVE").is_none() {
        eprintln!("XP-11 live actions not run: ORCEL_XP11_LIVE is not set");
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
    let secret = format!("xp11-secret-{nonce}");
    let probe = spawn_probe(&nonce, &secret);
    let mut host = Host::spawn();
    let hello = host.hello();
    assert_eq!(
        hello["capabilities"]["semantic_action"]["support"], "delivered",
        "this session cannot act: {hello}"
    );
    assert_eq!(
        hello["capabilities"]["semantic_action"]["delivery"],
        "background"
    );

    let window = find_window(&mut host, &format!("Orcel XP06 Probe {nonce}"));
    assert_eq!(window["process"]["pid"], probe.0.id(), "{window}");
    let reference = window_ref(&window);
    let approval = find_window(&mut host, &format!("Orcel Approval Probe {nonce}"));
    let approval_reference = window_ref(&approval);

    // The accessibility tree can trail the window by a moment.
    let visible = format!("visible-{nonce}");
    let deadline = Instant::now() + Duration::from_secs(30);
    let nodes = loop {
        let tree = host.request(
            "observe_window",
            json!({"window": reference, "max_nodes": 256, "max_depth": 8}),
        );
        assert_eq!(tree["ok"], true, "{tree}");
        let nodes = flatten(&tree["elements"]);
        if nodes.iter().any(|node| node["value"] == visible.as_str())
            && nodes.iter().any(|node| node["value_is_password"] == true)
            && nodes.iter().any(|node| node["name"] == "Submit")
        {
            break nodes;
        }
        assert!(Instant::now() < deadline, "probe tree incomplete: {tree}");
        std::thread::sleep(Duration::from_millis(500));
    };
    let id_of = |predicate: &dyn Fn(&Value) -> bool| {
        nodes
            .iter()
            .find(|node| predicate(node))
            .and_then(|node| node["runtime_id"].as_str())
            .unwrap_or_else(|| panic!("no such element in {nodes:?}"))
            .to_owned()
    };
    let password = id_of(&|node| node["value_is_password"] == true);
    let plain = id_of(&|node| node["value"] == visible.as_str());
    let submit = id_of(&|node| node["name"] == "Submit");

    // A password field takes no action of any kind, and nothing is typed.
    for (verb, value) in [
        ("set_value", Some("typed-into-a-password-field")),
        ("invoke", None),
        ("toggle", Some("true")),
        ("select", None),
    ] {
        let reply = action(&mut host, &reference, verb, &password, value);
        assert_eq!(reply["ok"], false, "{verb}: {reply}");
        assert_eq!(error_code(&reply), "protected_surface", "{verb}: {reply}");
        assert!(reply.get("action").is_none(), "{reply}");
    }

    // An Orcel approval surface takes no action: an agent can never press
    // Approve. The window is listed and bound exactly, and the refusal comes
    // before its tree is read.
    for (verb, value) in [
        ("invoke", None),
        ("set_value", Some("x")),
        ("toggle", Some("true")),
    ] {
        let reply = action(
            &mut host,
            &approval_reference,
            verb,
            "e0-0000000000000000",
            value,
        );
        assert_eq!(reply["ok"], false, "{verb}: {reply}");
        assert_eq!(error_code(&reply), "protected_surface", "{verb}: {reply}");
    }

    // A verb that does not suit the element, and a pixel-addressed frame.
    let reply = action(&mut host, &reference, "toggle", &submit, Some("true"));
    assert_eq!(error_code(&reply), "capability_denied", "{reply}");
    let reply = action(&mut host, &reference, "invoke", &plain, None);
    assert_eq!(error_code(&reply), "capability_denied", "{reply}");
    // XP-12 serves raw input, but never on a tick the person has moved past:
    // tick 0 is not the live one, so the frame is cancelled (or the window
    // cannot be proved clear), and nothing is delivered.
    let pixel = host.request(
        "input_click",
        json!({"window": reference, "x": 20, "y": 20, "button": "left",
               "click_count": 1, "expected_last_input_tick": 0}),
    );
    assert_eq!(pixel["ok"], false, "{pixel}");
    assert!(pixel.get("action").is_none(), "{pixel}");
    // If the host advertises a missing permission, the refusal must match
    // that exact typed reason. With raw input available, a stale human-input
    // tick must still cancel or fail unavailable without delivering anything.
    let click_reason = error_code(&pixel);
    if hello["capabilities"]["input_click"]["support"] == "unavailable" {
        assert_eq!(
            click_reason,
            hello["capabilities"]["input_click"]["reason"]
                .as_str()
                .expect("unavailable raw input has a typed reason"),
            "{pixel}"
        );
    } else {
        assert!(
            matches!(click_reason, "cancelled" | "provider_unavailable"),
            "{pixel}"
        );
    }

    // One real action each: the plain field takes a value, the button a press.
    let typed = format!("typed-by-host-{nonce}");
    let reply = action(&mut host, &reference, "set_value", &plain, Some(&typed));
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["action"]["state"], "completed", "{reply}");
    assert_eq!(reply["action"]["action"], "semantic_set_value", "{reply}");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let tree = host.request("observe_window", json!({ "window": reference }));
        if flatten(&tree["elements"])
            .iter()
            .any(|node| node["value"] == typed.as_str())
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the entry never held the value: {tree}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let submit_id = {
        let tree = host.request("observe_window", json!({ "window": reference }));
        flatten(&tree["elements"])
            .iter()
            .find(|node| node["name"] == "Submit")
            .and_then(|node| node["runtime_id"].as_str())
            .expect("the button is still there")
            .to_owned()
    };
    let reply = action(&mut host, &reference, "invoke", &submit_id, None);
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["action"]["action"], "semantic_invoke", "{reply}");

    // The secret never left the host.
    for line in &host.log {
        assert!(!line.contains(&secret), "secret left the host: {line}");
    }
    drop(probe);
    assert!(host.shutdown().success());
}
