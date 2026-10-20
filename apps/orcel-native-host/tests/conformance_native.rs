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
//! (`harness_gtk3_test.rs`, `harness_appkit_test.rs`): click, toggle,
//! select and set value, element-addressed (`ax`, XP-11), and double and
//! right click, drag, scroll, set value, type and key, pixel-addressed
//! (`px`, XP-12). The `ax` cells are measured: each action is delivered in
//! the background and read back from the task-state file, and focus,
//! stacking and the pointer must not move. Their foreground rung has
//! nothing to measure (semantic actions never take the foreground). The
//! `px` cells are measured on X11 and macOS against the XP-12 input probe,
//! an application that journals the pointer, scroll and key events it
//! receives (the harness exposes no control geometry to aim at); a hover and
//! a key chord are refused by policy, and Wayland says unavailable.

mod conformance;
mod support;

use conformance::{InputCell, Report, Target};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use support::spawn_probe;
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

/// The pixel-addressed part of upstream's harness matrix as `/2` frames
/// (XP-12). The element-addressed part runs as measured cells in
/// [`run_ax_cells`]. Pixel cells name a window-relative point. The frames
/// carry the human-input tick 0: they are the ones that must be refused.
fn cells(point: (i64, i64)) -> Vec<InputCell> {
    let (x, y) = point;
    let tick = json!(0);
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

/// The measured `ax` cells (XP-11): background delivery of click, toggle,
/// select and set value, each checked against the task-state file the
/// harness rewrites on every change. The foreground rung is reported as
/// background-only. Set value is read back through "Save note": the entry's
/// text reaches the state file only when the harness saves it.
fn run_ax_cells(
    host: &mut Host,
    report: &mut Report,
    prefix: &str,
    reference: &Value,
    mut state: impl FnMut() -> Value,
) {
    let cell = |case: &str, verb: &'static str, element: &'static str, control: &'static str| {
        conformance::ActionCell {
            case: format!("{case}/ax/background"),
            verb,
            element,
            control: Some(control),
            value: None,
            holds_desktop: true,
        }
    };
    conformance::run_action(
        host,
        report,
        prefix,
        reference,
        &cell("click", "invoke", "Increment", "Button"),
        &mut state,
        |now| now["counter"] == 1,
    );
    conformance::run_action(
        host,
        report,
        prefix,
        reference,
        &conformance::ActionCell {
            value: Some("true"),
            ..cell("toggle", "toggle", "I agree", "CheckBox")
        },
        &mut state,
        |now| now["agreed"] == true,
    );
    conformance::run_action(
        host,
        report,
        prefix,
        reference,
        &cell("select", "select", "Small", "RadioButton"),
        &mut state,
        |now| now["size"] == "small",
    );
    // Set value: the text is in the entry, not yet in the state file.
    let note = conformance::ActionCell {
        case: "set-value/ax/background".to_owned(),
        verb: "set_value",
        element: "Note",
        control: Some("Edit"),
        value: Some("conformance"),
        holds_desktop: true,
    };
    let mut saved = cell("save-note", "invoke", "Save note", "Button");
    saved.case = "set-value/ax/background/save".to_owned();
    // Written by the first action and read by the second one: the entry
    // holds the text, and the state file still has no note.
    let before = state();
    assert_eq!(before["note_saved"], Value::Null, "{before}");
    {
        let nodes = conformance::fresh_nodes(host, reference);
        let id = conformance::strict_element_id(&nodes, note.element, note.control);
        let reply = host.request(
            "semantic_action",
            json!({
                "window": reference,
                "semantic_action": "set_value",
                "element_runtime_id": id,
                "value": "conformance",
            }),
        );
        assert_eq!(reply["ok"], true, "{reply}");
        assert_eq!(reply["action"]["action"], "semantic_set_value", "{reply}");
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(
            state()["note_saved"],
            Value::Null,
            "set_value alone saved the note"
        );
    }
    conformance::run_action(host, report, prefix, reference, &saved, &mut state, |now| {
        now["note_saved"] == "conformance"
    });
    for action in ["click", "toggle", "select", "set-value"] {
        report.background_only(format!("{prefix}/{action}/ax/foreground"));
    }
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

    // XP-11: refusals first, while the fixture is untouched, then the
    // measured actions.
    conformance::negative_action_cells(
        &mut host,
        &mut report,
        &prefix,
        &observed.reference,
        &conformance::NegativeTargets {
            button: "Increment",
            check_box: "I agree",
        },
        state,
    );
    assert_eq!(
        state(),
        initial,
        "a refused action changed the harness state"
    );
    run_ax_cells(&mut host, &mut report, &prefix, &observed.reference, state);

    // XP-12: the pixel cells. A hover and a key chord are refused by policy
    // on every window system; Wayland serves no raw input; X11 and macOS
    // deliver, measured on the input probe.
    let cells = cells((20, 20));
    assert_eq!(cells.len(), 18);
    let left_by_ax = state();
    let (policy, others): (Vec<_>, Vec<_>) = cells
        .into_iter()
        .partition(|cell| conformance::POLICY_REFUSED_OPS.contains(&cell.op));
    conformance::refused_input_cells(
        &mut host,
        &mut report,
        &prefix,
        &observed.reference,
        &policy,
        "capability_denied",
        "refused",
        state,
    );
    if conformance::host_serves_input() {
        let nonce = format!("{}-{}", std::process::id(), harness.pid());
        let probe = spawn_probe(&nonce);
        let window = conformance::probe_window(&mut host, &nonce);
        assert_eq!(window["process"]["pid"], probe.child.id(), "{window}");
        conformance::run_probe_cells(
            &mut host,
            &mut report,
            &prefix,
            &support::window_ref(&window),
            &probe,
        );
        drop(probe);
    } else {
        conformance::refused_input_cells(
            &mut host,
            &mut report,
            &prefix,
            &observed.reference,
            &others,
            "provider_unavailable",
            "unavailable",
            state,
        );
    }
    assert_eq!(
        state(),
        left_by_ax,
        "a pixel frame changed the harness state"
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
fn native_pixel_cells_cover_upstreams_matrix_per_delivery() {
    let cells = cells((5, 5));
    assert_eq!(cells.len(), 18);
    for action in [
        "click",
        "double-click",
        "right-click",
        "drag",
        "scroll",
        "type-text",
        "press-key",
        "hotkey",
        "move",
    ] {
        for delivery in ["background", "foreground"] {
            assert!(
                cells
                    .iter()
                    .any(|cell| cell.case == format!("{action}/px/{delivery}")),
                "{action}/px/{delivery}"
            );
        }
    }
    for cell in &cells {
        assert!(
            conformance::POLICY_REFUSED_OPS.contains(&cell.op)
                || conformance::INPUT_OPS.contains(&cell.op),
            "{} is not a pixel- or key-addressed operation",
            cell.op
        );
        assert!(cell.case.contains("/px/"), "{}", cell.case);
    }
}
