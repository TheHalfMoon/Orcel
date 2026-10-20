// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! XP-06 end to end on macOS and Linux: the kernel registry observes a real
//! probe window through `ComputerHostAdapter` and the real
//! `orcel-native-host`, which ORCEL_COMPUTER_HOST_BIN names.
//!
//! Runs only with `ORCEL_XP06_LIVE=1`, and then fails rather than skips. CI
//! runs it on Linux under Xvfb, Openbox and the AT-SPI bus; on macOS it is a
//! manual check (Accessibility and Screen Recording must be granted to the
//! host binary). The probe scripts live in
//! `apps/orcel-native-host/tests/fixtures`.

#![cfg(unix)]

use orcel_contracts::FailureCode;
use orcel_provider_uia::{ComputerHostAdapter, DesktopInputAction, UiaAdapter, UiaRegistry};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const WORKSPACE: &str = "xp06-live-workspace";
const POLICY: &str = "xp06-live-policy";

struct Probe(Child);

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_probe(nonce: &str, secret: &str) -> Probe {
    let fixtures = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../apps/orcel-native-host/tests/fixtures"
    );
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

#[test]
fn xp06_registry_observes_through_the_native_host() {
    if std::env::var_os("ORCEL_XP06_LIVE").is_none() {
        eprintln!("XP-06 registry live check not run: ORCEL_XP06_LIVE is not set");
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
    let secret = format!("xp06-registry-secret-{nonce}");
    let _probe = spawn_probe(&nonce, &secret);
    let adapter = ComputerHostAdapter::from_path(host).expect("orcel-computer-host/2 negotiated");
    let mut registry = UiaRegistry::new();
    let title = format!("Orcel XP06 Probe {nonce}");
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
            // The protected surface is shown by the same probe; wait until
            // the registry has seen and omitted it too.
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
    let deadline = Instant::now() + Duration::from_secs(30);
    let tree = loop {
        let tree = registry
            .observe_tree(
                &adapter, &window_id, generation, None, None, WORKSPACE, POLICY,
            )
            .expect("bounded tree");
        if tree["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|node| node["value_is_password"] == true)
        {
            break tree;
        }
        assert!(Instant::now() < deadline, "probe tree incomplete: {tree}");
        std::thread::sleep(Duration::from_millis(500));
    };
    let rendered = tree.to_string();
    assert!(!rendered.contains(&secret), "secret reached the registry");
    let hidden = tree["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["value_is_password"] == true)
        .unwrap();
    assert_eq!(hidden["redacted"], true);
    assert!(hidden["value"].is_null());

    // Observation only: the host's table refuses every mutation before a
    // frame is sent.
    let hwnd_listing = adapter.list_processes().expect("processes");
    assert!(!hwnd_listing.is_empty());
    let refused = adapter
        .execute_raw_input(1, &DesktopInputAction::Move { x: 1, y: 1 }, 0)
        .unwrap_err();
    assert!(matches!(
        refused.code,
        FailureCode::ProviderUnavailable | FailureCode::TargetStale
    ));
    eprintln!(
        "XP-06 registry live evidence: windows={} protected_omitted={} nodes={}",
        listing["window_count"], listing["protected_omitted"], tree["node_count"]
    );
}
