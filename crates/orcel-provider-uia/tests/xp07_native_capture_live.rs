// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! XP-07 end to end on macOS and Linux: the kernel registry captures a real
//! probe window through `ComputerHostAdapter` and the real
//! `orcel-native-host`, which ORCEL_COMPUTER_HOST_BIN names.
//!
//! Runs only with `ORCEL_XP07_LIVE=deliver`, and then fails rather than
//! skips. CI runs it on Linux under Xvfb and Openbox; on macOS it is a
//! manual check. The probe scripts live in
//! `apps/orcel-native-host/tests/fixtures`.

#![cfg(unix)]

use orcel_contracts::FailureCode;
use orcel_provider_uia::{ComputerHostAdapter, UiaRegistry, CAPTURE_SCOPE_TARGET_WINDOW};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const WORKSPACE: &str = "xp07-live-workspace";
const POLICY: &str = "xp07-live-policy";

struct Probe(Child);

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_probe(nonce: &str) -> Probe {
    let fixtures = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../apps/orcel-native-host/tests/fixtures"
    );
    let mut command = if cfg!(target_os = "macos") {
        let mut command = Command::new("osascript");
        command.args([
            "-l",
            "JavaScript",
            &format!("{fixtures}/appkit_capture_probe.js"),
        ]);
        command
    } else {
        let mut command = Command::new("python3");
        command.arg(format!("{fixtures}/gtk3_capture_probe.py"));
        command
    };
    Probe(
        command
            .arg(nonce)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("the probe starts"),
    )
}

/// The standard base64 alphabet, decoded strictly enough for a test.
fn decode_base64(text: &str) -> Vec<u8> {
    let value = |byte: u8| match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => 0,
    };
    let bytes: Vec<u8> = text.bytes().filter(|byte| *byte != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut word = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            word |= u32::from(value(*byte)) << (18 - 6 * index);
        }
        let take = chunk.len() - 1;
        for index in 0..take {
            out.push((word >> (16 - 8 * index)) as u8);
        }
    }
    out
}

#[test]
fn xp07_registry_captures_through_the_native_host() {
    if std::env::var("ORCEL_XP07_LIVE").as_deref() != Ok("deliver") {
        eprintln!("XP-07 registry live capture not run: ORCEL_XP07_LIVE is not deliver");
        return;
    }
    let host = std::env::var_os("ORCEL_COMPUTER_HOST_BIN")
        .expect("ORCEL_COMPUTER_HOST_BIN names orcel-native-host");
    let nonce = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let _probe = spawn_probe(&nonce);
    let adapter = ComputerHostAdapter::from_path(host).expect("orcel-computer-host/2 negotiated");
    let mut registry = UiaRegistry::new();
    let title = format!("Orcel XP07 Capture {nonce}");
    let protected = format!("Orcel Approval Probe {nonce}");

    let deadline = Instant::now() + Duration::from_secs(45);
    let (listing, entry) = loop {
        let listing = registry
            .list_windows(&adapter, WORKSPACE, POLICY)
            .expect("window list");
        let entry = listing["windows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|window| window["title"] == title.as_str())
            .cloned();
        if let Some(entry) = entry {
            if listing["protected_omitted"].as_u64().unwrap() >= 1 {
                break (listing, entry);
            }
        }
        assert!(Instant::now() < deadline, "probe never listed: {listing}");
        std::thread::sleep(Duration::from_millis(500));
    };
    for window in listing["windows"].as_array().unwrap() {
        assert_ne!(window["title"], protected.as_str());
    }
    let window_id = entry["window_id"].as_str().unwrap().to_owned();
    let generation = entry["window_generation"].as_u64().unwrap();

    for scope in ["display", "monitor", "region"] {
        let error = registry
            .capture_window(&adapter, &window_id, generation, scope, WORKSPACE, POLICY)
            .unwrap_err();
        assert_eq!(error.code, FailureCode::CapabilityDenied, "{scope}");
    }

    let deadline = Instant::now() + Duration::from_secs(20);
    let frame = loop {
        let frame = registry.capture_window(
            &adapter,
            &window_id,
            generation,
            CAPTURE_SCOPE_TARGET_WINDOW,
            WORKSPACE,
            POLICY,
        );
        match frame {
            Ok(frame) => {
                let width = frame["width"].as_u64().unwrap() as usize;
                let height = frame["height"].as_u64().unwrap() as usize;
                let raw = decode_base64(frame["pixels_b64"].as_str().unwrap());
                assert_eq!(raw.len(), width * height * 4);
                let centre = ((height / 2) * width + width / 2) * 4;
                if raw[centre..centre + 3] == [224, 17, 157] {
                    break frame;
                }
                assert!(
                    Instant::now() < deadline,
                    "probe frame never showed the marker: {}x{}",
                    width,
                    height
                );
            }
            Err(error) => assert!(Instant::now() < deadline, "probe never captured: {error:?}"),
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    assert_eq!(frame["scope"], CAPTURE_SCOPE_TARGET_WINDOW);
    assert_eq!(frame["pixel_format"], "rgba8");
    assert_eq!(frame["truncated"], false);
    if cfg!(target_os = "linux") {
        assert_eq!(
            (frame["width"].as_u64(), frame["height"].as_u64()),
            (Some(320), Some(200))
        );
    }
    let frame_id = frame["frame_id"].as_str().unwrap();
    let described = registry
        .describe_frame(
            frame_id,
            frame["capture_generation"].as_u64().unwrap(),
            WORKSPACE,
            POLICY,
        )
        .expect("the frame is known");
    assert!(described.get("pixels_b64").is_none());
    eprintln!(
        "XP-07 registry live evidence: windows={} protected_omitted={} frame={}x{} digest={}",
        listing["window_count"],
        listing["protected_omitted"],
        frame["width"],
        frame["height"],
        frame["payload_digest"]
    );
}
