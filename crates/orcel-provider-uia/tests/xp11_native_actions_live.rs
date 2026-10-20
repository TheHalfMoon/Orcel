// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! XP-11 end to end on macOS and Linux: the kernel registry acts on a real
//! probe window through `ComputerHostAdapter` and the real
//! `orcel-native-host`, which ORCEL_COMPUTER_HOST_BIN names.
//!
//! Runs only with `ORCEL_XP11_LIVE=1`, and then fails rather than skips. CI
//! runs it on Linux under Xvfb, Openbox and the AT-SPI bus; on macOS it is a
//! manual check (Accessibility and Screen Recording must be granted to the
//! host binary). The probe scripts are the XP-06 ones, in
//! `apps/orcel-native-host/tests/fixtures`.
//!
//! What it shows: without an approval armed on the exact target the adapter
//! sends no semantic action; with one it delivers exactly one; the approval
//! is spent by that action; a password field is refused by the registry and,
//! if the registry were bypassed, by the adapter and the host.

#![cfg(unix)]

use orcel_contracts::FailureCode;
use orcel_provider_uia::{ApprovedSemantic, ComputerHostAdapter, UiaRegistry};
use serde_json::Value;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const WORKSPACE: &str = "xp11-live-workspace";
const POLICY: &str = "xp11-live-policy";

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

fn approve(binding_hwnd: u64, runtime_id: &str, verb: &str, value: Option<&str>) -> ApprovedSemantic {
    ApprovedSemantic {
        hwnd: binding_hwnd,
        runtime_id: runtime_id.to_owned(),
        verb: verb.to_owned(),
        value_digest: value.map(orcel_provider_uia::value_content_digest),
    }
}

struct Tree {
    window_id: String,
    window_generation: u64,
    tree_generation: u64,
    nodes: Vec<Value>,
}

impl Tree {
    fn element(&self, control_type: &str, name: &str) -> String {
        self.nodes
            .iter()
            .find(|node| node["control_type"] == control_type && node["name"] == name)
            .and_then(|node| node["element_id"].as_str())
            .unwrap_or_else(|| panic!("no {control_type} named {name} in {:?}", self.nodes))
            .to_owned()
    }

    fn value_of(&self, element_id: &str) -> Option<String> {
        self.nodes
            .iter()
            .find(|node| node["element_id"] == element_id)
            .and_then(|node| node["value"].as_str())
            .map(str::to_owned)
    }
}

fn observe(registry: &mut UiaRegistry, adapter: &ComputerHostAdapter, title: &str) -> Tree {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let listing = registry
            .list_windows(adapter, WORKSPACE, POLICY)
            .expect("window list");
        let window = listing["windows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|window| window["title"] == title)
            .cloned();
        if let Some(window) = window {
            let window_id = window["window_id"].as_str().unwrap().to_owned();
            let window_generation = window["window_generation"].as_u64().unwrap();
            let tree = registry
                .observe_tree(
                    adapter,
                    &window_id,
                    window_generation,
                    None,
                    None,
                    WORKSPACE,
                    POLICY,
                )
                .expect("bounded tree");
            let nodes = tree["nodes"].as_array().unwrap().clone();
            if nodes.iter().any(|node| node["name"] == "Submit")
                && nodes.iter().any(|node| node["name"] == "Plain field")
                && nodes.iter().any(|node| node["redacted"] == true)
            {
                return Tree {
                    window_id,
                    window_generation,
                    tree_generation: tree["tree_generation"].as_u64().unwrap(),
                    nodes,
                };
            }
        }
        assert!(Instant::now() < deadline, "probe tree incomplete");
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[test]
fn xp11_registry_acts_through_the_native_host_only_under_an_armed_approval() {
    if std::env::var_os("ORCEL_XP11_LIVE").is_none() {
        eprintln!("XP-11 registry live check not run: ORCEL_XP11_LIVE is not set");
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
    let secret = format!("xp11-registry-secret-{nonce}");
    let _probe = spawn_probe(&nonce, &secret);
    let adapter = ComputerHostAdapter::from_path(host).expect("orcel-computer-host/2 negotiated");
    let mut registry = UiaRegistry::new();
    let title = format!("Orcel XP06 Probe {nonce}");

    // 1. No approval armed: the adapter sends nothing, and says why.
    let tree = observe(&mut registry, &adapter, &title);
    let submit = tree.element("Button", "Submit");
    let error = registry
        .invoke_element(&adapter, &submit, tree.tree_generation, "Button", WORKSPACE, POLICY)
        .unwrap_err();
    assert_eq!(error.code, FailureCode::CapabilityDenied, "{error:?}");
    assert!(error.message.contains("approval"), "{error:?}");

    // 2. An approval armed from the registry's own binding delivers exactly
    //    one action, and the registry regenerates the tree.
    let binding = registry
        .invoke_binding(&submit, tree.tree_generation, "Button", WORKSPACE, POLICY)
        .expect("invoke binding");
    adapter
        .authorize_semantic(approve(binding.hwnd, &binding.runtime_id, "invoke", None))
        .expect("armed on the live window");
    let evidence = registry
        .invoke_element(&adapter, &submit, tree.tree_generation, "Button", WORKSPACE, POLICY)
        .expect("one approved invoke");
    assert_eq!(evidence["action"], "invoke");
    assert_ne!(evidence["new_tree_generation"], evidence["prior_tree_generation"]);

    // 3. The approval is spent, and the old tree generation is stale.
    let stale = registry
        .invoke_element(&adapter, &submit, tree.tree_generation, "Button", WORKSPACE, POLICY)
        .unwrap_err();
    assert_eq!(stale.code, FailureCode::TargetStale, "{stale:?}");
    let tree = observe(&mut registry, &adapter, &title);
    let submit = tree.element("Button", "Submit");
    let again = registry
        .invoke_element(&adapter, &submit, tree.tree_generation, "Button", WORKSPACE, POLICY)
        .unwrap_err();
    assert_eq!(again.code, FailureCode::CapabilityDenied, "{again:?}");

    // 4. A value write is approved for exactly its text.
    let plain = tree.element("Edit", "Plain field");
    let typed = format!("typed-through-the-registry-{nonce}");
    let binding = registry
        .value_binding(&plain, tree.tree_generation, "Edit", &typed, WORKSPACE, POLICY)
        .expect("value binding");
    adapter
        .authorize_semantic(approve(binding.hwnd, &binding.runtime_id, "set_value", Some(&typed)))
        .unwrap();
    let wrong = registry
        .set_value_element(
            &adapter,
            &plain,
            tree.tree_generation,
            "Edit",
            "text that was not approved",
            WORKSPACE,
            POLICY,
        )
        .unwrap_err();
    assert_eq!(wrong.code, FailureCode::CapabilityDenied, "{wrong:?}");
    adapter
        .authorize_semantic(approve(binding.hwnd, &binding.runtime_id, "set_value", Some(&typed)))
        .unwrap();
    registry
        .set_value_element(
            &adapter,
            &plain,
            tree.tree_generation,
            "Edit",
            &typed,
            WORKSPACE,
            POLICY,
        )
        .expect("the approved value is written");
    let deadline = Instant::now() + Duration::from_secs(15);
    let tree = loop {
        let tree = observe(&mut registry, &adapter, &title);
        if tree.value_of(&plain).as_deref() == Some(typed.as_str()) {
            break tree;
        }
        assert!(Instant::now() < deadline, "the entry never held the value");
        std::thread::sleep(Duration::from_millis(300));
    };

    // 5. A password field: the registry refuses it, and so would the adapter
    //    and the host if the registry were bypassed.
    let hidden = tree
        .nodes
        .iter()
        .find(|node| node["redacted"] == true)
        .and_then(|node| node["element_id"].as_str())
        .unwrap()
        .to_owned();
    let refused = registry
        .value_binding(&hidden, tree.tree_generation, "Edit", "x", WORKSPACE, POLICY)
        .unwrap_err();
    assert_eq!(refused.code, FailureCode::CapabilityDenied, "{refused:?}");
    assert!(!tree.nodes.iter().any(|node| node.to_string().contains(&secret)));
    assert!(tree.window_generation > 0 && !tree.window_id.is_empty());
    eprintln!("XP-11 registry live evidence: nodes={}", tree.nodes.len());
}
