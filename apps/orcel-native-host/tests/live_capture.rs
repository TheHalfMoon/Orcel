// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! XP-07 live exact-window capture through the real host.
//!
//! Runs only with `ORCEL_XP07_LIVE` set:
//! - `deliver`: the session must capture; anything else fails. CI runs this
//!   on Linux under Xvfb and Openbox with the GTK3 probe
//!   (`fixtures/gtk3_capture_probe.py`).
//! - `report`: when the hello says capture is unavailable, the test checks
//!   that the reason is typed, that a capture request is refused with that
//!   reason and that nothing prompted, and prints the evidence; when capture
//!   is delivered, it runs the whole check. CI runs this on the macOS runner,
//!   where the direct-capture consent of the runner's responsible process
//!   cannot be read. The full macOS check is manual, with the AppKit probe
//!   (`fixtures/appkit_capture_probe.js`); see SECURITY_INTEGRATION.md.
//!
//! What a delivered session must show:
//! - the probe window's frame is RGBA8 within the bounds, and its centre is
//!   the marker colour;
//! - the protected Orcel surface is refused with `protected_surface`;
//! - a binding to another window id is `target_stale`;
//! - on X11 a covered window is refused (`window_obscured`) and captured
//!   again once uncovered; on macOS the cover never reaches the frame;
//! - a minimized window is refused as unavailable and stays minimized;
//! - every response line stays under the 16 MiB bound.

mod support;

use base64::Engine as _;
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use support::{error_code, window_ref, Host};

const MARKER: [u8; 3] = [224, 17, 157];
const COVER: [u8; 3] = [16, 200, 32];
/// Seconds after which the AppKit probe minimizes its capture window; the
/// GTK probe is told on stdin instead.
const MACOS_MINIMIZE_AFTER: &str = "30";

struct Probe(Child);

impl Probe {
    fn send(&mut self, command: &str) {
        let stdin = self.0.stdin.as_mut().expect("probe stdin");
        stdin
            .write_all(format!("{command}\n").as_bytes())
            .and_then(|()| stdin.flush())
            .expect("probe takes a command");
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_probe(nonce: &str) -> Probe {
    let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    let mut command = if cfg!(target_os = "macos") {
        let mut command = Command::new("osascript");
        command.args([
            "-l",
            "JavaScript",
            &format!("{fixtures}/appkit_capture_probe.js"),
            nonce,
            MACOS_MINIMIZE_AFTER,
        ]);
        command
    } else {
        let mut command = Command::new("python3");
        command.args([&format!("{fixtures}/gtk3_capture_probe.py"), nonce]);
        command
    };
    Probe(
        command
            .stdin(Stdio::piped())
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
        assert!(
            Instant::now() < deadline,
            "probe window never listed: {listed}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Decoded RGBA pixels of a capture reply, checked against its geometry
/// and the wire bounds.
fn pixels(reply: &Value) -> (u32, u32, Vec<u8>) {
    let capture = &reply["capture"];
    assert_eq!(capture["pixel_format"], "rgba8", "{reply}");
    let width = capture["width"].as_u64().unwrap() as u32;
    let height = capture["height"].as_u64().unwrap() as u32;
    assert!(width > 0 && width <= 7680 && height > 0 && height <= 4320);
    let raw = base64::engine::general_purpose::STANDARD
        .decode(capture["pixels_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(raw.len(), width as usize * height as usize * 4);
    assert!(raw.len() <= 8 * 1024 * 1024);
    (width, height, raw)
}

fn pixel(raw: &[u8], width: u32, x: u32, y: u32) -> [u8; 4] {
    let offset = (y as usize * width as usize + x as usize) * 4;
    [
        raw[offset],
        raw[offset + 1],
        raw[offset + 2],
        raw[offset + 3],
    ]
}

/// macOS may convert sRGB to the display profile; X11 is exact.
fn near(actual: [u8; 4], expected: [u8; 3]) -> bool {
    let tolerance = if cfg!(target_os = "macos") { 24 } else { 0 };
    actual[3] == 255
        && actual
            .iter()
            .zip(expected)
            .all(|(a, e)| (i16::from(*a) - i16::from(e)).abs() <= tolerance)
}

/// The share of pixels with the cover colour.
fn cover_share(raw: &[u8]) -> f64 {
    let covered = raw
        .chunks_exact(4)
        .filter(|px| near([px[0], px[1], px[2], px[3]], COVER))
        .count();
    covered as f64 / (raw.len() / 4) as f64
}

fn capture(host: &mut Host, reference: &Value) -> Value {
    host.request("capture_window", json!({ "window": reference }))
}

/// Retries a capture until `accept` holds, for state the window manager
/// applies asynchronously.
fn capture_until(
    host: &mut Host,
    reference: &Value,
    what: &str,
    accept: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let reply = capture(host, reference);
        if accept(&reply) {
            return reply;
        }
        assert!(Instant::now() < deadline, "{what}: {}", summary(&reply));
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// A reply without its pixels: the error, or the frame size and centre.
fn summary(reply: &Value) -> String {
    if reply["ok"] != true || reply.get("capture").is_none() {
        return reply.to_string();
    }
    let (width, height, raw) = pixels(reply);
    format!(
        "{width}x{height} frame, centre pixel {:?}",
        pixel(&raw, width, width / 2, height / 2)
    )
}

#[test]
fn xp07_live_capture_of_a_probe_window() {
    let Some(mode) = std::env::var_os("ORCEL_XP07_LIVE") else {
        eprintln!("XP-07 live capture not run: ORCEL_XP07_LIVE is not set");
        return;
    };
    let mode = mode.to_string_lossy().into_owned();
    assert!(matches!(mode.as_str(), "deliver" | "report"), "{mode}");
    let mut host = Host::spawn();
    let hello = host.hello();
    let entry = hello["capabilities"]["capture_window"].clone();
    if entry["support"] != "delivered" {
        assert_eq!(mode, "report", "this session cannot capture: {hello}");
        let reason = entry["reason"].as_str().unwrap().to_owned();
        assert!(
            matches!(
                reason.as_str(),
                "permission_missing" | "provider_unavailable"
            ),
            "{entry}"
        );
        let reply = host.request(
            "capture_window",
            json!({"window": {"kind": support::window_kind(), "id": 9, "expected_pid": 1,
                "expected_start_generation": 2, "expected_window_nonce": 3}}),
        );
        assert_eq!(error_code(&reply), reason, "{reply}");
        eprintln!(
            "XP-07 capture unavailable on this runner: reason={reason} permissions={} refusal={}",
            hello["permissions"], reply["error"]["message"]
        );
        assert!(host.shutdown().success());
        return;
    }
    assert_eq!(entry["delivery"], "background", "{entry}");

    let nonce = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let mut probe = spawn_probe(&nonce);
    let title = format!("Orcel XP07 Capture {nonce}");
    let window = find_window(&mut host, &title);
    assert_eq!(window["process"]["pid"], probe.0.id(), "{window}");
    let reference = window_ref(&window);

    // The frame is the probe window: marker colour at its centre. The
    // window can be listed a moment before it is first painted.
    let mut timings = Vec::new();
    let first = capture_until(&mut host, &reference, "probe never captured", |reply| {
        if reply["ok"] != true {
            return false;
        }
        let (width, height, raw) = pixels(reply);
        near(pixel(&raw, width, width / 2, height / 2), MARKER)
    });
    let (width, height, raw) = pixels(&first);
    if cfg!(target_os = "macos") {
        // Points times the backing scale; the title bar is part of the window.
        assert!(width >= 320 && height >= 200, "{width}x{height}");
    } else {
        assert_eq!((width, height), (320, 200), "client area only");
        let marker = raw
            .chunks_exact(4)
            .filter(|px| near([px[0], px[1], px[2], px[3]], MARKER))
            .count();
        assert_eq!(marker, raw.len() / 4, "every pixel is the probe's own");
    }
    for _ in 0..10 {
        let started = Instant::now();
        let reply = capture(&mut host, &reference);
        timings.push(started.elapsed());
        assert_eq!(reply["ok"], true, "{}", summary(&reply));
    }

    // A protected Orcel surface is refused before any pixel is read.
    let protected = find_window(&mut host, &format!("Orcel Approval Probe {nonce}"));
    let reply = capture(&mut host, &window_ref(&protected));
    assert_eq!(
        error_code(&reply),
        "protected_surface",
        "{}",
        summary(&reply)
    );
    assert!(reply.get("capture").is_none());

    // A binding is one exact window: the target's binding with another
    // window id (here the probe's own cover) is stale, never retargeted.
    let cover = find_window(&mut host, &format!("Orcel XP07 Cover {nonce}"));
    let mut other = reference.clone();
    other["id"] = cover["hwnd"].clone();
    let reply = capture(&mut host, &other);
    assert_eq!(error_code(&reply), "target_stale", "{}", summary(&reply));

    if cfg!(target_os = "macos") {
        // The cover sits over the target from the start; ScreenCaptureKit's
        // window filter never shows it.
        assert!(cover_share(&raw) < 0.01, "the cover reached the frame");
    } else {
        // A covered X11 window is refused, then captured again once clear.
        probe.send("cover");
        let refused = capture_until(&mut host, &reference, "covered window captured", |reply| {
            reply["ok"] == false
        });
        assert_eq!(error_code(&refused), "provider_unavailable", "{refused}");
        assert!(
            refused["error"]["message"]
                .as_str()
                .unwrap()
                .contains("window_obscured"),
            "{refused}"
        );
        probe.send("uncover");
        let clear = capture_until(&mut host, &reference, "uncovered window refused", |reply| {
            reply["ok"] == true
        });
        let (_, _, raw) = pixels(&clear);
        assert_eq!(cover_share(&raw), 0.0);
        probe.send("minimize");
    }

    // A minimized window is unavailable, and the host never restores it.
    let minimized = capture_until(
        &mut host,
        &reference,
        "minimized window captured",
        |reply| reply["ok"] == false,
    );
    assert_eq!(
        error_code(&minimized),
        "provider_unavailable",
        "{minimized}"
    );
    std::thread::sleep(Duration::from_secs(1));
    let listed = host.request("list_windows", json!({}));
    assert!(
        !listed["windows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|window| window["title"] == title.as_str()),
        "the minimized window came back: {listed}"
    );

    for line in &host.log {
        assert!(line.len() <= 16 * 1024 * 1024);
    }
    eprintln!(
        "XP-07 M-NAT-02 {}: capture_window {}x{} p50={}ms p95={}ms (n={})",
        hello["backend"],
        width,
        height,
        percentile(&mut timings, 50),
        percentile(&mut timings, 95),
        timings.len()
    );
    assert!(host.shutdown().success());
}
