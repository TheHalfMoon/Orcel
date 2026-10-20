// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! XP-12 end to end on macOS and Linux: the kernel adapter delivers raw input
//! to a real probe window through `ComputerHostAdapter` and the real
//! `orcel-native-host`, which ORCEL_COMPUTER_HOST_BIN names.
//!
//! Runs only with `ORCEL_XP12_LIVE=1`, and then fails rather than skips. CI
//! runs it on Linux under Xvfb and Openbox with the GTK3 input probe
//! (`apps/orcel-native-host/tests/fixtures/gtk3_input_probe.py`), which
//! journals every event it receives; on macOS it is a manual check (the
//! AppKit probe is compiled with `swiftc`, and Accessibility and Screen
//! Recording must be granted to the host binary).
//!
//! What it shows: without an approval armed on the exact window and the exact
//! input the adapter sends nothing; with one it delivers exactly one input,
//! where the frame named it; the approval is spent by that input; another
//! input, a replay, an over-cap input, a hover, a chord and a rate-limited
//! second input are refused and the application receives nothing; and an
//! input on a human-input tick the person has moved past is `cancelled`.

#![cfg(unix)]

use orcel_contracts::FailureCode;
use orcel_provider_uia::{ComputerHostAdapter, DesktopInputAction, UiaAdapter};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Probe {
    child: Child,
    state: PathBuf,
    dir: PathBuf,
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn spawn_probe(nonce: &str) -> Probe {
    let fixtures = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../apps/orcel-native-host/tests/fixtures"
    );
    let dir = std::env::temp_dir().join(format!("orcel-xp12-kernel-{nonce}"));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let state = dir.join("state.json");
    let flag = dir.join("cover.flag");
    let mut command = if cfg!(target_os = "macos") {
        let binary = dir.join("appkit_input_probe");
        let built = Command::new("swiftc")
            .args(["-O", &format!("{fixtures}/appkit_input_probe.swift"), "-o"])
            .arg(&binary)
            .status()
            .expect("swiftc runs");
        assert!(built.success(), "the AppKit probe did not compile");
        Command::new(binary)
    } else {
        let mut command = Command::new("python3");
        command.arg(format!("{fixtures}/gtk3_input_probe.py"));
        command.env("GDK_BACKEND", "x11");
        command
    };
    let child = command
        .arg(nonce)
        .arg(&state)
        .arg(&flag)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .expect("the probe starts");
    Probe { child, state, dir }
}

fn events(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|state| state["events"].as_array().cloned())
        .unwrap_or_default()
}

fn wait_for_events(path: &Path, at_least: usize, what: &str) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let seen = events(path);
        if seen.len() >= at_least {
            std::thread::sleep(Duration::from_millis(300));
            return events(path);
        }
        assert!(Instant::now() < deadline, "{what}: the probe saw {seen:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn click(x: i32, y: i32) -> DesktopInputAction {
    DesktopInputAction::Click {
        x,
        y,
        button: "left".into(),
        count: 1,
    }
}

/// Past the kernel's own pacing, so a test that is not about the rate limit
/// is not refused by it.
fn pace() {
    std::thread::sleep(Duration::from_millis(400));
}

fn assert_nothing_arrived(path: &Path, count: usize, what: &str) {
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        events(path).len(),
        count,
        "{what}: the probe received input"
    );
}

#[test]
fn xp12_the_adapter_delivers_one_approved_input_and_nothing_else() {
    if std::env::var_os("ORCEL_XP12_LIVE").is_none() {
        eprintln!("XP-12 kernel input not run: ORCEL_XP12_LIVE is not set");
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
    let adapter = ComputerHostAdapter::from_env().expect("the configured host starts");
    let title = format!("Orcel XP12 Input {nonce}");
    let deadline = Instant::now() + Duration::from_secs(45);
    let hwnd = loop {
        let found = adapter
            .list_processes()
            .expect("process list")
            .into_iter()
            .filter(|process| process.pid == probe.child.id())
            .flat_map(|process| adapter.list_windows(process.pid).unwrap_or_default())
            .find(|window| window.title == title)
            .map(|window| window.hwnd);
        if let Some(hwnd) = found {
            break hwnd;
        }
        assert!(Instant::now() < deadline, "{title} never listed");
        std::thread::sleep(Duration::from_millis(500));
    };
    let tick = || adapter.cursor_position().expect("cursor").last_input_tick;
    assert_ne!(tick(), 0, "the session has no human-input clock");
    let path = probe.state.clone();
    wait_for_events(&path, 0, "state");
    let mut seen = events(&path).len();

    // Nothing armed: nothing sent.
    let error = adapter
        .execute_raw_input(hwnd, &click(100, 80), tick())
        .unwrap_err();
    assert_eq!(error.code, FailureCode::CapabilityDenied, "{error:?}");
    assert!(error.message.contains("approval"), "{error:?}");
    assert_nothing_arrived(&path, seen, "an unapproved click");

    // The approval for exactly this input lets exactly one through.
    adapter.authorize_input(hwnd, &click(100, 80)).unwrap();
    let done = adapter
        .execute_raw_input(hwnd, &click(100, 80), tick())
        .unwrap();
    assert_eq!(done.state, "completed", "{done:?}");
    let got = wait_for_events(&path, seen + 2, "the approved click");
    let first = &got[seen];
    assert_eq!(first["kind"], "down", "{got:?}");
    assert!(
        (first["x"].as_f64().unwrap() - 100.0).abs() <= 2.0,
        "{first}"
    );
    assert!(
        (first["y"].as_f64().unwrap() - 80.0).abs() <= 2.0,
        "{first}"
    );
    seen = got.len();

    // A replayed approval is refused.
    pace();
    let replay = adapter
        .execute_raw_input(hwnd, &click(100, 80), tick())
        .unwrap_err();
    assert_eq!(replay.code, FailureCode::CapabilityDenied, "{replay:?}");
    assert_nothing_arrived(&path, seen, "a replayed approval");

    // An approval for another input does not carry over, and is used up.
    adapter.authorize_input(hwnd, &click(10, 10)).unwrap();
    let other = adapter
        .execute_raw_input(hwnd, &click(11, 10), tick())
        .unwrap_err();
    assert_eq!(other.code, FailureCode::CapabilityDenied, "{other:?}");
    let spent = adapter
        .execute_raw_input(hwnd, &click(10, 10), tick())
        .unwrap_err();
    assert_eq!(spent.code, FailureCode::CapabilityDenied, "{spent:?}");
    assert_nothing_arrived(&path, seen, "another input");

    // Over-cap and malformed inputs are refused before an approval is armed.
    for action in [
        DesktopInputAction::TypeText {
            text: "a".repeat(257),
        },
        DesktopInputAction::TypeText {
            text: "line\nbreak".into(),
        },
        DesktopInputAction::Scroll {
            x: 1,
            y: 1,
            scroll_x: 0,
            scroll_y: 21,
        },
        DesktopInputAction::Key {
            key: "cmd+q".into(),
        },
        DesktopInputAction::Key {
            key: "ctrl+alt+delete".into(),
        },
        click(-1, 4),
    ] {
        let error = adapter.authorize_input(hwnd, &action).unwrap_err();
        assert_eq!(error.code, FailureCode::InvalidRequest, "{action:?}");
    }
    for action in [
        DesktopInputAction::Move { x: 5, y: 5 },
        DesktopInputAction::Hotkey {
            key: "ctrl+a".into(),
        },
    ] {
        let error = adapter.authorize_input(hwnd, &action).unwrap_err();
        assert_eq!(error.code, FailureCode::CapabilityDenied, "{action:?}");
        let error = adapter
            .execute_raw_input(hwnd, &action, tick())
            .unwrap_err();
        assert_eq!(error.code, FailureCode::CapabilityDenied, "{action:?}");
    }

    // A point outside the window passes the kernel's own checks (it does not
    // know the frame) and the host refuses it; the application sees nothing.
    pace();
    adapter.authorize_input(hwnd, &click(5000, 5000)).unwrap();
    let outside = adapter
        .execute_raw_input(hwnd, &click(5000, 5000), tick())
        .unwrap_err();
    assert_eq!(outside.code, FailureCode::InvalidRequest, "{outside:?}");
    assert_nothing_arrived(&path, seen, "a point outside the window");

    // Human input after the tick the kernel read: cancelled, not sent.
    pace();
    adapter.authorize_input(hwnd, &click(100, 80)).unwrap();
    let stale = tick().wrapping_sub(60_000);
    let cancelled = adapter
        .execute_raw_input(hwnd, &click(100, 80), stale)
        .unwrap();
    assert_eq!(cancelled.state, "cancelled", "{cancelled:?}");
    assert_nothing_arrived(&path, seen, "a stale tick");

    // The kernel paces raw input: a second sequence inside the interval is
    // refused even with its own approval.
    pace();
    adapter.authorize_input(hwnd, &click(60, 60)).unwrap();
    adapter
        .execute_raw_input(hwnd, &click(60, 60), tick())
        .unwrap();
    adapter.authorize_input(hwnd, &click(61, 61)).unwrap();
    let paced = adapter
        .execute_raw_input(hwnd, &click(61, 61), tick())
        .unwrap_err();
    assert_eq!(paced.code, FailureCode::CapabilityDenied, "{paced:?}");
    assert!(paced.message.contains("rate limited"), "{paced:?}");
    let got = wait_for_events(&path, seen + 2, "the paced click");
    assert_eq!(got.len(), seen + 2, "only one of the two arrived: {got:?}");
    drop(probe);
}
