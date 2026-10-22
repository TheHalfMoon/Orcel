// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! XP-06 live observation of a real window through the real host.
//!
//! Runs only with `ORCEL_XP06_LIVE=1` and fails, rather than skipping, when
//! the session cannot observe. CI runs it on Linux under Xvfb, Openbox and
//! the AT-SPI bus with the GTK3 probe (`fixtures/gtk3_probe.py`). On macOS it
//! needs Accessibility and Screen Recording granted to the host binary, so
//! it is a manual check with the AppKit probe (`fixtures/appkit_probe.js`);
//! the commands are in the XP-06 pull request.
//!
//! Every raw response line is kept, and none may contain the probe's secret.

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
        let mut command = Command::new("osascript");
        command.args(["-l", "JavaScript", &format!("{fixtures}/appkit_probe.js")]);
        command
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

fn percentile(samples: &mut [Duration], percent: usize) -> u128 {
    samples.sort();
    let index = (samples.len() * percent).div_ceil(100).saturating_sub(1);
    samples[index.min(samples.len() - 1)].as_millis()
}

fn find_window(host: &mut Host, title: &str, timings: &mut Vec<Duration>) -> Value {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let started = Instant::now();
        let listed = host.request("list_windows", json!({}));
        timings.push(started.elapsed());
        assert_eq!(listed["ok"], true, "{listed}");
        let windows = listed["windows"].as_array().unwrap();
        assert!(windows.len() <= 64);
        if let Some(window) = windows.iter().find(|window| window["title"] == title) {
            return window.clone();
        }
        assert!(
            Instant::now() < deadline,
            "probe window never listed: {listed}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[test]
fn xp06_live_observation_of_a_probe_window() {
    if std::env::var_os("ORCEL_XP06_LIVE").is_none() {
        eprintln!("XP-06 live observation not run: ORCEL_XP06_LIVE is not set");
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
    let secret = format!("xp06-secret-{nonce}");
    let probe = spawn_probe(&nonce, &secret);
    let mut host = Host::spawn();
    let hello = host.hello();
    for op in ["list_windows", "observe_window"] {
        assert_eq!(
            hello["capabilities"][op]["support"], "delivered",
            "this session cannot observe: {hello}"
        );
    }

    let mut list_timings = Vec::new();
    let title = format!("Orcel XP06 Probe {nonce}");
    let window = find_window(&mut host, &title, &mut list_timings);
    assert_eq!(window["process"]["pid"], probe.0.id(), "{window}");
    let source = window["process"]["generation_source"].as_str().unwrap();
    assert!(
        matches!(source, "linux-proc-starttime" | "macos-bsd-start-time"),
        "{source}"
    );
    let reference = window_ref(&window);

    // The accessibility tree can trail the window by a moment.
    let visible = format!("visible-{nonce}");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut observe_timings = Vec::new();
    let nodes = loop {
        let started = Instant::now();
        let tree = host.request(
            "observe_window",
            json!({"window": reference, "max_nodes": 256, "max_depth": 8}),
        );
        observe_timings.push(started.elapsed());
        assert_eq!(tree["ok"], true, "{tree}");
        let nodes = flatten(&tree["elements"]);
        assert!(nodes.len() <= 256);
        if nodes.iter().any(|node| node["value"] == visible.as_str())
            && nodes.iter().any(|node| node["value_is_password"] == true)
        {
            break nodes;
        }
        assert!(Instant::now() < deadline, "probe tree incomplete: {tree}");
        std::thread::sleep(Duration::from_millis(500));
    };
    let hidden = nodes
        .iter()
        .find(|node| node["value_is_password"] == true)
        .unwrap();
    assert!(hidden.get("value").is_none(), "{hidden}");
    assert_eq!(hidden["control_type"], "Edit");

    // Identity binding rejects a recycled window.
    for (field, delta) in [
        ("expected_window_nonce", 1u64),
        ("expected_start_generation", 1),
    ] {
        let mut stale = reference.clone();
        stale[field] = json!(stale[field].as_u64().unwrap().wrapping_add(delta));
        let reply = host.request("observe_window", json!({ "window": stale }));
        assert_eq!(error_code(&reply), "target_stale", "{field}: {reply}");
    }

    // Bounds hold for a small request.
    let small = host.request(
        "observe_window",
        json!({"window": reference, "max_nodes": 2, "max_depth": 1}),
    );
    assert!(flatten(&small["elements"]).len() <= 2, "{small}");

    for _ in 0..10 {
        list_timings.push({
            let started = Instant::now();
            host.request("list_windows", json!({}));
            started.elapsed()
        });
        observe_timings.push({
            let started = Instant::now();
            host.request("observe_window", json!({ "window": reference }));
            started.elapsed()
        });
    }

    if hello["capabilities"]["cursor_position"]["support"] == "delivered" {
        let cursor = host.request("cursor_position", json!({}));
        assert_eq!(cursor["ok"], true, "{cursor}");
        assert!(cursor["cursor"]["screen_width"].as_i64().unwrap() > 0);
    }

    // The window closes between list and observe.
    drop(probe);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let reply = host.request("observe_window", json!({ "window": reference }));
        if error_code(&reply) == "target_stale" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "closed window still observed: {reply}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }

    for line in &host.log {
        assert!(!line.contains(&secret), "secret left the host: {line}");
    }
    eprintln!(
        "XP-06 M-NAT-01 {}: list_windows p50={}ms p95={}ms (n={}); observe_window p50={}ms p95={}ms (n={}); frames={} with no secret",
        hello["backend"],
        percentile(&mut list_timings, 50),
        percentile(&mut list_timings, 95),
        list_timings.len(),
        percentile(&mut observe_timings, 50),
        percentile(&mut observe_timings, 95),
        observe_timings.len(),
        host.log.len()
    );
    assert!(host.shutdown().success());
}
