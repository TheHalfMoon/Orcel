// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! XP-08 native toolkit conformance: Cua's GTK3 (Linux) and AppKit (macOS)
//! harnesses (`tests/native-fixtures/apps`, T-CUA-07) observed through the
//! real host over `orcel-computer-host/2`.
//!
//! Each harness runs in its task mode (`CUA_GTK3_TASK_STATE`,
//! `CUA_APPKIT_TASK_STATE`). In that mode it rewrites an app-owned JSON
//! state file, with its pid and a sequence number, on launch and on every
//! change. That file is the fixture oracle: the window the host lists must
//! belong to the pid the file names, the checked state of "I agree" and of
//! the Small/Medium/Large radios in the tree must be the `agreed` and `size`
//! the file holds, and the file must not change while the suite
//! observes or is refused.
//!
//! The input cells follow upstream's harness matrix
//! (`harness_gtk3_test.rs`, `harness_appkit_test.rs`): click, double and
//! right click, drag, scroll, set value, type and key, element-addressed
//! (`ax`, XP-11) and pixel-addressed (`px`, XP-12), each a typed skip until
//! its task lands.

mod conformance;
mod support;

use conformance::{InputCell, Report, Target};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use support::Host;

/// The task controls both harnesses label alike (their task modes share
/// candidate ids across platforms). Both hosts' trees hold interactive
/// elements only, so a static label such as `counter=0` is never observed.
const TASK_CONTROLS: &[&str] = &[
    "Increment",
    "Reset",
    "I agree",
    "Small",
    "Medium",
    "Large",
    "Save note",
];

struct NativeHarness {
    name: &'static str,
    title: &'static str,
    state_env: &'static str,
    command: Command,
    markers: &'static [&'static str],
}

fn harness(fixtures: &Path) -> NativeHarness {
    if cfg!(target_os = "macos") {
        NativeHarness {
            name: "appkit",
            title: "CuaTestHarness AppKit",
            state_env: "CUA_APPKIT_TASK_STATE",
            command: Command::new(fixtures.join(
                "harness-appkit/CuaTestHarness.AppKit.app/Contents/MacOS/CuaTestHarness.AppKit",
            )),
            markers: TASK_CONTROLS,
        }
    } else {
        let mut command = Command::new("python3");
        command.arg(fixtures.join("gtk3/main.py"));
        if conformance::window_system() == "x11" {
            command.env("GDK_BACKEND", "x11");
        } else {
            command.env("GDK_BACKEND", "wayland");
        }
        NativeHarness {
            name: "gtk3",
            title: "CuaTestHarness GTK3 Tasks",
            state_env: "CUA_GTK3_TASK_STATE",
            command,
            markers: TASK_CONTROLS,
        }
    }
}

/// The task-state file once the harness has written it.
fn read_state(path: &PathBuf) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn wait_state(path: &PathBuf) -> Value {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(state) = read_state(path) {
            return state;
        }
        assert!(
            Instant::now() < deadline,
            "harness never wrote {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Upstream's harness matrix as `/2` frames. Element-addressed cells use the
/// closed semantic verbs; pixel cells name the point.
fn cells(nodes: &[Value], point: (i64, i64)) -> Vec<InputCell> {
    let (x, y) = point;
    let tick = json!(0);
    let element = |needle: &str| conformance::element_for(nodes, needle);
    let mut cells = Vec::new();
    for delivery in ["background", "foreground"] {
        let mut push = |action: &str, addressing: &str, op: &'static str, fields: Value| {
            cells.push(InputCell {
                case: format!("{action}/{addressing}/{delivery}"),
                op,
                fields,
            });
        };
        push(
            "click",
            "ax",
            "semantic_action",
            json!({"semantic_action": "invoke", "element_runtime_id": element("Increment")}),
        );
        push(
            "toggle",
            "ax",
            "semantic_action",
            json!({"semantic_action": "toggle", "element_runtime_id": element("I agree")}),
        );
        push(
            "select",
            "ax",
            "semantic_action",
            json!({"semantic_action": "select", "element_runtime_id": element("Small")}),
        );
        push(
            "set-value",
            "ax",
            "semantic_action",
            json!({"semantic_action": "set_value", "element_runtime_id": element("Note"), "value": "conformance"}),
        );
        push(
            "click",
            "px",
            "input_click",
            json!({"x": x, "y": y, "button": "left", "click_count": 1, "expected_last_input_tick": tick}),
        );
        push(
            "double-click",
            "px",
            "input_click",
            json!({"x": x, "y": y, "button": "left", "click_count": 2, "expected_last_input_tick": tick}),
        );
        push(
            "right-click",
            "px",
            "input_click",
            json!({"x": x, "y": y, "button": "right", "click_count": 1, "expected_last_input_tick": tick}),
        );
        push(
            "drag",
            "px",
            "input_drag",
            json!({"x": x, "y": y, "to_x": x + 80, "to_y": y, "button": "left", "expected_last_input_tick": tick}),
        );
        push(
            "scroll",
            "px",
            "input_scroll",
            json!({"x": x, "y": y, "scroll_x": 0, "scroll_y": -3, "expected_last_input_tick": tick}),
        );
        push(
            "type-text",
            "px",
            "input_type_text",
            json!({"text": "conformance", "expected_last_input_tick": tick}),
        );
        push(
            "press-key",
            "px",
            "input_key",
            json!({"key": "enter", "expected_last_input_tick": tick}),
        );
        push(
            "hotkey",
            "px",
            "input_hotkey",
            json!({"key": "ctrl+a", "expected_last_input_tick": tick}),
        );
        push(
            "move",
            "px",
            "input_move",
            json!({"x": x, "y": y, "expected_last_input_tick": tick}),
        );
    }
    cells
}

#[test]
fn xp08_native_harness_is_conformant() {
    let Some(fixtures) = conformance::fixtures() else {
        eprintln!("XP-08 native conformance not run: ORCEL_XP08_FIXTURES is not set");
        return;
    };
    let mut spec = harness(&fixtures);
    let prefix = format!("native/{}/{}", conformance::window_system(), spec.name);
    let mut report = Report::new();
    let scratch = conformance::scratch(spec.name);
    let state_path = scratch.join("task-state.json");
    spec.command
        .env(spec.state_env, &state_path)
        .env("ACCESSIBILITY_ENABLED", "1")
        .env("NO_AT_BRIDGE", "0");
    let harness = conformance::Harness::spawn(spec.name, &mut spec.command);

    wait_state(&state_path);
    // Let launch-time widget signals settle before the baseline is taken.
    std::thread::sleep(Duration::from_secs(1));
    let initial = wait_state(&state_path);
    assert_eq!(
        initial["pid"],
        harness.pid(),
        "the state file is not this harness's: {initial}"
    );
    assert_eq!(initial["counter"], 0, "{initial}");
    assert_eq!(initial["note_saved"], Value::Null, "{initial}");
    let state = || read_state(&state_path).expect("the harness keeps its state file");

    let mut host = Host::spawn();
    conformance::check_hello(&mut host, &mut report, &prefix);
    let target = Target {
        prefix: prefix.clone(),
        title: spec.title,
        pid: harness.pid(),
        markers: spec.markers,
    };
    let window = conformance::find_window(&mut host, &mut report, &target);
    // Fixture-owned identity: the listed owner is the pid the app wrote.
    assert_eq!(window["process"]["pid"], initial["pid"], "{window}");
    let observed = conformance::observe_markers(&mut host, &mut report, &target, &window);
    // Fixture agreement: what the tree shows checked is what the app wrote.
    let now = state();
    let agreed = now["agreed"].as_bool().expect("agreed is a boolean");
    assert_eq!(
        conformance::checked(&observed.nodes, "I agree"),
        agreed,
        "I agree vs {now}"
    );
    for size in ["Small", "Medium", "Large"] {
        let expected = now["size"] == size.to_ascii_lowercase();
        assert_eq!(
            conformance::checked(&observed.nodes, size),
            expected,
            "{size} vs {now}"
        );
    }
    conformance::identity_and_bounds(&mut host, &mut report, &prefix, &observed.reference);
    conformance::observation_has_no_effect(
        &mut host,
        &mut report,
        &prefix,
        &observed.reference,
        state,
    );

    let point = conformance::screen_centre(&mut host);
    let cells = cells(&observed.nodes, point);
    assert_eq!(cells.len(), 26);
    conformance::pending_input_cells(
        &mut host,
        &mut report,
        &prefix,
        &observed.reference,
        &cells,
        state,
    );
    assert_eq!(
        state(),
        initial,
        "the harness state changed during the suite"
    );

    drop(harness);
    conformance::closed_window_is_stale(&mut host, &mut report, &prefix, &observed.reference);
    assert!(host.shutdown().success());
    report.write(&format!(
        "native.{}.{}",
        std::env::consts::OS,
        conformance::window_system()
    ));
    let _ = std::fs::remove_dir_all(scratch);
}

#[test]
fn native_cells_cover_upstreams_matrix_per_delivery() {
    let nodes = vec![json!({"runtime_id": "r:1", "name": "Increment"})];
    let cells = cells(&nodes, (5, 5));
    assert_eq!(cells.len(), 26);
    for action in [
        "click",
        "double-click",
        "right-click",
        "drag",
        "scroll",
        "set-value",
        "type-text",
        "press-key",
    ] {
        assert!(
            cells
                .iter()
                .any(|cell| cell.case.starts_with(&format!("{action}/"))),
            "{action}"
        );
    }
    for cell in &cells {
        assert!(conformance::INPUT_OPS.contains(&cell.op), "{}", cell.op);
        let addressing = cell.case.split('/').nth(1).unwrap();
        assert_eq!(
            addressing == "ax",
            cell.op == "semantic_action",
            "{}",
            cell.case
        );
    }
}
