// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! XP-08 shared web conformance: Cua's 40-cell catalog
//! (`cua-driver-e2e/tests/cross_platform_behavior_test.rs` at trycua/cua
//! a802eaf2, T-CUA-08) ported onto `orcel-computer-host/2` requests.
//!
//! Every host loads the same page (`tests/native-fixtures/shared/web`):
//! Electron on Linux and macOS, WKWebView on macOS. The page journals its own
//! DOM state to a loopback listener in this test, so every assertion about
//! the fixture reads state the host cannot write. Upstream's cell ids,
//! actions, targeting and delivery are kept exactly. Each cell is checked
//! against the fixture journal plus the focus, z-order, cursor and
//! no-input-leak oracles in `conformance/mod.rs`.
//!
//! Today the host observes only, so the observation cells are measured and
//! all 40 action cells are typed skips: `ax` cells wait for XP-11
//! (`semantic_action`), `px` cells for XP-12 (raw input). Each skip still
//! sends its frame and requires the exact refusal with every oracle
//! unchanged.

mod conformance;
mod support;

use conformance::{InputCell, Journal, Report, Target};
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use support::Host;

/// One upstream catalog cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cell {
    action: &'static str,
    addressing: &'static str,
    delivery: &'static str,
}

/// The catalog in upstream's order (`shared_web_action_matrix_is_state_verified`):
/// three pointer actions and six others in ax/px x background/foreground,
/// the px drag, and the ax editor save.
fn catalog() -> Vec<Cell> {
    let mut cells = Vec::new();
    let both = ["ax", "px"];
    let deliveries = ["background", "foreground"];
    for action in [
        "left_click",
        "right_click",
        "double_click",
        "type_text",
        "type_submit",
        "press_key",
        "hotkey",
        "scroll",
        "child_window",
    ] {
        for addressing in both {
            for delivery in deliveries {
                cells.push(Cell {
                    action,
                    addressing,
                    delivery,
                });
            }
        }
    }
    for delivery in deliveries {
        cells.push(Cell {
            action: "drag",
            addressing: "px",
            delivery,
        });
    }
    for delivery in deliveries {
        cells.push(Cell {
            action: "editor_save",
            addressing: "ax",
            delivery,
        });
    }
    cells
}

/// The page element (accessible name) each action addresses upstream.
fn element_name(action: &str) -> &'static str {
    match action {
        "left_click" | "right_click" | "double_click" => "border-click-target",
        "type_text" | "type_submit" => "txt-input",
        "press_key" | "hotkey" => "keyboard-input",
        "scroll" => "scroll-tall",
        "child_window" => "Open child window",
        "drag" => "drag-source",
        "editor_save" => "editor-save",
        other => panic!("unknown action {other}"),
    }
}

/// The `/2` frame of a cell. `ax` cells name the element; `/2`'s closed
/// semantic verbs are invoke, set_value, select, toggle and scroll, and a
/// cell whose action has no verb yet (right and double click, keys) carries
/// upstream's action name, which XP-11 must map or refuse. `px` cells name
/// the point (`conformance::screen_centre`).
fn frame(cell: &Cell, element: &str, point: (i64, i64)) -> (&'static str, Value) {
    let (x, y) = point;
    if cell.addressing == "ax" {
        let (verb, value) = match cell.action {
            "left_click" | "child_window" | "editor_save" => ("invoke", None),
            "type_text" => ("set_value", Some("conformance")),
            "type_submit" => ("set_value", Some("submitted")),
            "scroll" => ("scroll", None),
            other => (other, None),
        };
        let mut fields = json!({"semantic_action": verb, "element_runtime_id": element});
        if let Some(value) = value {
            fields["value"] = json!(value);
        }
        return ("semantic_action", fields);
    }
    let tick = json!(0);
    match cell.action {
        "left_click" | "child_window" => (
            "input_click",
            json!({"x": x, "y": y, "button": "left", "click_count": 1, "expected_last_input_tick": tick}),
        ),
        "right_click" => (
            "input_click",
            json!({"x": x, "y": y, "button": "right", "click_count": 1, "expected_last_input_tick": tick}),
        ),
        "double_click" => (
            "input_click",
            json!({"x": x, "y": y, "button": "left", "click_count": 2, "expected_last_input_tick": tick}),
        ),
        "type_text" | "type_submit" => (
            "input_type_text",
            json!({"text": "conformance", "expected_last_input_tick": tick}),
        ),
        "press_key" => (
            "input_key",
            json!({"key": "enter", "expected_last_input_tick": tick}),
        ),
        "hotkey" => (
            "input_hotkey",
            json!({"key": "ctrl+shift+h", "expected_last_input_tick": tick}),
        ),
        "scroll" => (
            "input_scroll",
            json!({"x": x, "y": y, "scroll_x": 0, "scroll_y": -3, "expected_last_input_tick": tick}),
        ),
        "drag" => (
            "input_drag",
            json!({"x": x, "y": y, "to_x": x + 120, "to_y": y, "button": "left", "expected_last_input_tick": tick}),
        ),
        other => panic!("no px frame for {other}"),
    }
}

/// Upstream's cell id: `<os>-<host>-<action>-<addressing>-<delivery>`.
fn upstream_cell_id(host: &str, cell: &Cell) -> String {
    format!(
        "{}-{host}-{}_{}_{}",
        std::env::consts::OS,
        cell.action,
        cell.addressing,
        cell.delivery
    )
    .replace('_', "-")
}

struct WebHost {
    name: &'static str,
    title: String,
    program: std::path::PathBuf,
    args: Vec<String>,
}

fn web_hosts(fixtures: &Path, cdp_port: u16) -> Vec<WebHost> {
    let read_binary = || {
        let recorded = fixtures.join("electron/orcel-binary");
        let text = std::fs::read_to_string(&recorded)
            .unwrap_or_else(|error| panic!("{}: {error} (run orcel-stage.sh)", recorded.display()));
        std::path::PathBuf::from(text.trim())
    };
    let electron_args = if cfg!(target_os = "macos") {
        vec!["--force-renderer-accessibility".to_owned()]
    } else {
        vec![
            "--no-sandbox".to_owned(),
            "--disable-gpu".to_owned(),
            "--force-renderer-accessibility".to_owned(),
        ]
    };
    let mut args = vec![fixtures.join("electron").display().to_string()];
    args.extend(electron_args);
    let mut hosts = vec![WebHost {
        name: "electron",
        title: format!("CuaTestHarness Electron [cdp={cdp_port}]"),
        program: read_binary(),
        args,
    }];
    if cfg!(target_os = "macos") {
        hosts.push(WebHost {
            name: "wkwebview",
            title: "CuaTestHarness WKWebView".to_owned(),
            program: fixtures
                .join("harness-wkwebview/CuaTestHarness.WKWebView.app/Contents/MacOS/CuaTestHarness.WKWebView"),
            args: Vec::new(),
        });
    }
    hosts
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn run_host(spec: &WebHost, report: &mut Report, cdp_port: u16) {
    let prefix = format!("shared-web/{}/{}", conformance::window_system(), spec.name);
    let journal = Journal::start();
    let profile = conformance::scratch(spec.name);
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .env("CUA_E2E_FIXTURE_JOURNAL_URL", journal.url())
        .env("CUA_ELECTRON_CDP_PORT", cdp_port.to_string())
        .env("CUA_E2E_USER_DATA_DIR", &profile)
        .env("ACCESSIBILITY_ENABLED", "1")
        .env("NO_AT_BRIDGE", "0");
    let harness = conformance::Harness::spawn(spec.name, &mut command);

    let initial = journal.wait_ready(Duration::from_secs(90));
    // The page's own initial state, before the host has looked at it.
    for (id, text) in [
        ("page-marker", "WEB_HARNESS_MARKER_v1"),
        ("lbl-counter", "counter=0"),
        ("lbl-last-action", "last_action=none"),
        ("keyboard-status", "key_state=none"),
        ("editor-status", "editor_status=draft"),
        ("lbl-child-window-state", "child_windows=0"),
        ("drag-status", "drag_status=idle"),
    ] {
        assert_eq!(
            conformance::journal_text(&initial, id),
            text,
            "{id}: {initial}"
        );
    }

    let mut host = Host::spawn();
    conformance::check_hello(&mut host, report, &prefix);
    let target = Target {
        prefix: prefix.clone(),
        title: &spec.title,
        pid: harness.pid(),
        markers: &["Increment", "Reset"],
    };
    let window = conformance::find_window(&mut host, report, &target);
    let observed = conformance::observe_markers(&mut host, report, &target, &window);
    // The tree agrees with the page's own journal, not just with itself:
    // the buttons the host names are the ones the DOM holds. The hosts'
    // trees carry interactive elements only, so static text is not compared.
    let state = journal.settled();
    for id in ["btn-increment", "btn-reset"] {
        let text = conformance::journal_text(&state, id);
        assert!(
            observed
                .nodes
                .iter()
                .any(|node| node["control_type"] == "Button" && node["name"] == text),
            "{id}={text} is not a button in the observed tree"
        );
    }
    conformance::identity_and_bounds(&mut host, report, &prefix, &observed.reference);
    conformance::observation_has_no_effect(&mut host, report, &prefix, &observed.reference, || {
        journal.settled()
    });

    let point = conformance::screen_centre(&mut host);
    let cells: Vec<InputCell> = catalog()
        .iter()
        .map(|cell| {
            let element = conformance::element_for(&observed.nodes, element_name(cell.action));
            let (op, fields) = frame(cell, &element, point);
            InputCell {
                case: format!(
                    "{}/{}/{}",
                    conformance::segment(cell.action),
                    cell.addressing,
                    cell.delivery
                ),
                op,
                fields,
            }
        })
        .collect();
    conformance::pending_input_cells(
        &mut host,
        report,
        &prefix,
        &observed.reference,
        &cells,
        || journal.settled(),
    );
    // Nothing the suite sent reached the page.
    assert_eq!(
        journal.settled(),
        initial,
        "the page state changed during the suite"
    );

    drop(harness);
    conformance::closed_window_is_stale(&mut host, report, &prefix, &observed.reference);
    assert!(host.shutdown().success());
    let _ = std::fs::remove_dir_all(profile);
}

#[test]
fn xp08_shared_web_catalog_is_conformant() {
    let Some(fixtures) = conformance::fixtures() else {
        eprintln!("XP-08 shared web conformance not run: ORCEL_XP08_FIXTURES is not set");
        return;
    };
    let mut report = Report::new();
    let cdp_port = free_port();
    for spec in web_hosts(&fixtures, cdp_port) {
        run_host(&spec, &mut report, cdp_port);
    }
    // Tauri is the third upstream host; Orcel does not build it (ORCEL.md).
    report.not_run(format!(
        "shared-web/{}/tauri/catalog",
        conformance::window_system()
    ));
    let skipped = report
        .rows()
        .iter()
        .filter(|row| row["status"] == "skip" && row["observed"] == "refused")
        .count();
    let hosts = if cfg!(target_os = "macos") { 2 } else { 1 };
    assert_eq!(skipped, 40 * hosts, "every catalog cell must be reported");
    report.write(&format!(
        "shared-web.{}.{}",
        std::env::consts::OS,
        conformance::window_system()
    ));
}

#[test]
fn catalog_is_upstreams_forty_cells() {
    let cells = catalog();
    assert_eq!(cells.len(), 40);
    let ids: std::collections::BTreeSet<_> = cells
        .iter()
        .map(|cell| upstream_cell_id("electron", cell))
        .collect();
    assert_eq!(ids.len(), 40, "cell ids are unique");
    let os = std::env::consts::OS;
    for id in [
        "left-click-ax-background",
        "drag-px-foreground",
        "editor-save-ax-background",
        "child-window-px-foreground",
    ] {
        assert!(ids.contains(&format!("{os}-electron-{id}")), "{id}");
    }
    // Upstream has no ax drag and no px editor save.
    assert!(!cells
        .iter()
        .any(|cell| cell.action == "drag" && cell.addressing == "ax"));
    assert!(!cells
        .iter()
        .any(|cell| cell.action == "editor_save" && cell.addressing == "px"));
}

#[test]
fn frames_use_the_closed_v2_vocabulary() {
    let semantic_verbs = ["invoke", "set_value", "select", "toggle", "scroll"];
    for cell in catalog() {
        let (op, fields) = frame(&cell, "1:2", (10, 20));
        assert!(conformance::INPUT_OPS.contains(&op), "{op}");
        if cell.addressing == "ax" {
            assert_eq!(op, "semantic_action");
            assert_eq!(fields["element_runtime_id"], "1:2");
            let verb = fields["semantic_action"].as_str().unwrap();
            let unmapped = matches!(
                cell.action,
                "right_click" | "double_click" | "press_key" | "hotkey"
            );
            assert_eq!(semantic_verbs.contains(&verb), !unmapped, "{cell:?}");
            assert_eq!(conformance::Pending::for_op(op).task(), "XP-11");
        } else {
            assert!(op.starts_with("input_"), "{op}");
            assert_eq!(fields["expected_last_input_tick"], 0);
            assert_eq!(conformance::Pending::for_op(op).task(), "XP-12");
        }
    }
}

#[test]
fn journal_reads_one_posted_state() {
    let journal = Journal::start();
    let url = journal
        .url()
        .strip_prefix("http://")
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .to_owned();
    let body = r#"{"lbl-counter":{"text":"counter=0"}}"#;
    let mut stream = std::net::TcpStream::connect(url).unwrap();
    use std::io::{Read, Write};
    write!(
        stream,
        "POST /journal HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    assert!(reply.starts_with("HTTP/1.1 204"), "{reply}");
    let state = journal.wait_ready(Duration::from_secs(5));
    assert_eq!(
        conformance::journal_text(&state, "lbl-counter"),
        "counter=0"
    );
    assert_eq!(journal.posts(), 1);
}

#[test]
fn a_journal_post_without_length_or_json_is_ignored() {
    let mut no_length = std::io::Cursor::new(b"POST / HTTP/1.1\r\nHost: x\r\n\r\n{}".to_vec());
    assert!(conformance::read_http_body(&mut no_length).is_none());
    let mut oversize =
        std::io::Cursor::new(b"POST / HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n".to_vec());
    assert!(conformance::read_http_body(&mut oversize).is_none());
    let mut exact =
        std::io::Cursor::new(b"POST / HTTP/1.1\r\ncontent-length: 2\r\n\r\n{}".to_vec());
    assert_eq!(conformance::read_http_body(&mut exact).unwrap(), b"{}");
}

#[test]
fn sway_oracle_reads_focus_and_order_from_the_tree() {
    let tree = json!({"id": 1, "nodes": [
        {"id": 4, "nodes": [{"id": 7, "pid": 70, "focused": false}],
         "floating_nodes": [{"id": 9, "pid": 90, "focused": true}]}
    ]});
    let (focus, order) = conformance::sway_focus_and_order(&tree);
    assert_eq!(focus.as_deref(), Some("9"));
    assert_eq!(order, "7,9");
}
