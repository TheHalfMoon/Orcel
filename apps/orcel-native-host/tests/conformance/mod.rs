// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! XP-08 native conformance support, shared by `conformance_shared_web.rs`
//! and `conformance_native.rs`.
//!
//! The suites drive the real host over `orcel-computer-host/2` against the
//! harness apps copied from Cua (`tests/native-fixtures`, T-CUA-07). They
//! never take the host's answer as proof of an effect. Every cell is checked
//! against oracles the host cannot write:
//! - fixture state: the shared web page's loopback journal, or the GTK3 or
//!   AppKit task-state file the harness rewrites on every change;
//! - focus and z-order: the window system's own view (`xprop` on X11,
//!   `swaymsg` on Sway, `lsappinfo` on macOS);
//! - cursor: `xdotool` on X11; on macOS the host's `cursor_position`,
//!   reported as `cursor-host` so the report does not overstate it. Wayland
//!   gives no client the pointer position, so the host does not serve
//!   `cursor_position` there and Sway cells carry no cursor oracle.
//!
//! Input cells exist for every action of the catalog, but `semantic_action`
//! waits for XP-11 and raw `input_*` for XP-12. Until then each input cell
//! sends its `/2` frame, requires the exact `capability_denied` refusal with
//! every oracle unchanged, and is reported as a typed skip
//! ([`Pending`]) that names the task. When the hello stops refusing an
//! operation, the cell fails: the task that landed must port it.
//!
//! The suites run only when `ORCEL_XP08_FIXTURES` names a directory staged by
//! `tests/native-fixtures/orcel-stage.sh`; then nothing may be missing.
//! `ORCEL_XP08_REPORT_DIR` receives one `orcel-benchmark-report/1` file per
//! suite and window system.

#![allow(dead_code)]

use crate::support::{error_code, flatten, window_ref, Host};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The staged harness directory, when the suite must run.
pub fn fixtures() -> Option<PathBuf> {
    std::env::var_os("ORCEL_XP08_FIXTURES")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// The window system this run measures, as a report path segment.
pub fn window_system() -> &'static str {
    let set = |name: &str| std::env::var_os(name).is_some_and(|value| !value.is_empty());
    if cfg!(target_os = "macos") {
        "quartz"
    } else if !set("WAYLAND_DISPLAY") {
        "x11"
    } else if set("SWAYSOCK") {
        "sway"
    } else {
        "wayland"
    }
}

/// A harness process, killed on drop.
pub struct Harness {
    pub child: Child,
    pub name: &'static str,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Harness {
    pub fn spawn(name: &'static str, command: &mut Command) -> Self {
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|error| panic!("{name} harness does not start: {error}"));
        Self { child, name }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

/// A unique scratch directory under the system temp directory.
pub fn scratch(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("orcel-xp08-{label}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// Fixture journal: the shared web page POSTs its whole data-cua-id state to a
// loopback URL on every mutation and every 250 ms (shared/web/index.html,
// startFixtureJournal).

#[derive(Default)]
struct JournalState {
    posts: u64,
    latest: Option<Value>,
}

pub struct Journal {
    url: String,
    state: Arc<Mutex<JournalState>>,
}

/// The body of one HTTP/1.1 request with a Content-Length, or `None`.
pub fn read_http_body(reader: &mut impl BufRead) -> Option<Vec<u8>> {
    let mut length = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse::<usize>().ok();
            }
        }
    }
    let length = length?;
    if length > 1024 * 1024 {
        return None;
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    Some(body)
}

fn serve_journal_connection(stream: TcpStream, state: &Mutex<JournalState>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut reader = BufReader::new(&stream);
    let body = read_http_body(&mut reader);
    let mut writer = &stream;
    let _ = writer
        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    if let Some(value) = body.and_then(|body| serde_json::from_slice::<Value>(&body).ok()) {
        if value.is_object() {
            let mut state = state.lock().unwrap();
            state.posts += 1;
            state.latest = Some(value);
        }
    }
}

impl Journal {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("journal listener");
        let url = format!("http://{}/journal", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(JournalState::default()));
        let shared = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                serve_journal_connection(stream, &shared);
            }
        });
        Self { url, state }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn posts(&self) -> u64 {
        self.state.lock().unwrap().posts
    }

    pub fn latest(&self) -> Option<Value> {
        self.state.lock().unwrap().latest.clone()
    }

    /// The first journaled state, once the page is publishing.
    pub fn wait_ready(&self, timeout: Duration) -> Value {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(state) = self.latest() {
                return state;
            }
            assert!(
                Instant::now() < deadline,
                "the fixture never published its journal"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The journaled state after at least two further publications, so a
    /// mutation the page saw is in it.
    pub fn settled(&self) -> Value {
        let start = self.posts();
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.posts() < start + 2 {
            assert!(
                Instant::now() < deadline,
                "the fixture journal stopped publishing"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        self.latest().unwrap()
    }
}

/// The text the journal holds for a data-cua-id.
pub fn journal_text<'a>(state: &'a Value, id: &str) -> &'a str {
    state[id]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("journal has no {id}: {state}"))
}

// ---------------------------------------------------------------------------
// External desktop oracles.

/// What the window system itself says about focus, stacking and the
/// pointer. Fields are `None` where this window system has no external
/// source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desktop {
    pub focus: Option<String>,
    pub stacking: Option<String>,
    pub cursor: Option<String>,
}

fn tool(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error| panic!("{program} is required for the XP-08 oracles: {error}"));
    assert!(
        output.status.success(),
        "{program} {args:?} failed: {output:?}"
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// Sway tree nodes that hold a client, in tree order (sway's stacking order
/// within each container), and the focused one.
pub fn sway_focus_and_order(tree: &Value) -> (Option<String>, String) {
    fn walk(node: &Value, focus: &mut Option<String>, order: &mut Vec<String>) {
        if node.get("pid").and_then(Value::as_u64).is_some() {
            let id = node["id"].to_string();
            if node["focused"] == true {
                *focus = Some(id.clone());
            }
            order.push(id);
        }
        for key in ["nodes", "floating_nodes"] {
            for child in node[key].as_array().into_iter().flatten() {
                walk(child, focus, order);
            }
        }
    }
    let mut focus = None;
    let mut order = Vec::new();
    walk(tree, &mut focus, &mut order);
    (focus, order.join(","))
}

pub fn desktop() -> Desktop {
    match window_system() {
        "x11" => {
            let props = tool(
                "xprop",
                &["-root", "_NET_ACTIVE_WINDOW", "_NET_CLIENT_LIST_STACKING"],
            );
            let mut lines = props.lines();
            Desktop {
                focus: lines.next().map(str::to_owned),
                stacking: lines.next().map(str::to_owned),
                cursor: Some(tool("xdotool", &["getmouselocation"])),
            }
        }
        "sway" => {
            let tree: Value = serde_json::from_str(&tool("swaymsg", &["-r", "-t", "get_tree"]))
                .expect("swaymsg prints JSON");
            let (focus, stacking) = sway_focus_and_order(&tree);
            Desktop {
                focus: Some(focus.unwrap_or_else(|| "none".to_owned())),
                stacking: Some(stacking),
                cursor: None,
            }
        }
        "quartz" => Desktop {
            focus: Some(tool("lsappinfo", &["front"])),
            stacking: Some(tool("lsappinfo", &["visibleProcessList"])),
            cursor: None,
        },
        other => panic!("no external desktop oracle for {other}"),
    }
}

/// The oracle names a refusal or observation cell is checked against.
pub fn oracle_names(desktop: &Desktop) -> Vec<&'static str> {
    let mut names = vec!["fixture-state", "no-leak"];
    if desktop.focus.is_some() {
        names.push("focus");
    }
    if desktop.stacking.is_some() {
        names.push("z-order");
    }
    if desktop.cursor.is_some() {
        names.push("cursor");
    } else if host_serves_cursor() {
        names.push("cursor-host");
    }
    names
}

/// Whether the host serves `cursor_position` here: not on Wayland, where no
/// client can read the pointer (the worker's documented availability).
pub fn host_serves_cursor() -> bool {
    !matches!(window_system(), "sway" | "wayland")
}

// ---------------------------------------------------------------------------
// The report (orcel-benchmark-report/1, BM-01).

/// Why an input cell is not run yet. The variant names the backlog task
/// whose landing turns the cell into a delivered-or-refused measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pending {
    /// `semantic_action` (accessibility-addressed actions): XP-11.
    Xp11SemanticActions,
    /// Raw `input_*` (pixel-addressed delivery): XP-12.
    Xp12RawInput,
}

impl Pending {
    pub fn task(self) -> &'static str {
        match self {
            Self::Xp11SemanticActions => "XP-11",
            Self::Xp12RawInput => "XP-12",
        }
    }

    pub fn for_op(op: &str) -> Self {
        if op == "semantic_action" {
            Self::Xp11SemanticActions
        } else {
            Self::Xp12RawInput
        }
    }
}

pub struct Report {
    started: Instant,
    rows: Vec<Value>,
}

fn percentile(samples: &[Duration], percent: usize) -> u128 {
    let mut sorted = samples.to_vec();
    sorted.sort();
    let index = (sorted.len() * percent).div_ceil(100).saturating_sub(1);
    sorted[index.min(sorted.len() - 1)].as_millis()
}

/// A report path segment: lower case, `[a-z0-9._-]`.
pub fn segment(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

impl Default for Report {
    fn default() -> Self {
        Self::new()
    }
}

impl Report {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            rows: Vec::new(),
        }
    }

    fn push(
        &mut self,
        case: String,
        status: &str,
        observed: &str,
        samples: &[Duration],
        steps: usize,
    ) {
        let mut row = json!({
            "case": case,
            "status": status,
            "observed": observed,
            "steps": steps,
            "model_calls": 0,
            "tokens_in": 0,
            "tokens_out": 0,
        });
        if !samples.is_empty() {
            row["latency_ms"] =
                json!({"p50": percentile(samples, 50), "p95": percentile(samples, 95)});
        }
        if let Some(run) = std::env::var("GITHUB_RUN_ID")
            .ok()
            .filter(|run| run.bytes().all(|b| b.is_ascii_digit()))
        {
            row["evidence"] = json!(run);
        }
        eprintln!("XP-08 {status:<4} {observed:<10} {case}");
        self.rows.push(row);
    }

    pub fn pass(&mut self, case: String, observed: &str, samples: &[Duration], steps: usize) {
        self.push(case, "pass", observed, samples, steps);
    }

    /// A typed skip: the cell's frame was sent and refused exactly, with
    /// every oracle unchanged, and the cell waits for `pending`.
    pub fn pending(&mut self, case: String, pending: Pending) {
        eprintln!("XP-08 skip: pending {} for {case}", pending.task());
        self.push(case, "skip", "refused", &[], 1);
    }

    /// An observation the `/2` bounds do not reach on this window system.
    pub fn not_observable(&mut self, case: String) {
        self.push(case, "skip", "beyond-depth-bound", &[], 0);
    }

    /// A harness this runner does not build (`ORCEL.md` says why).
    pub fn not_run(&mut self, case: String) {
        self.push(case, "skip", "not_run", &[], 0);
    }

    pub fn rows(&self) -> &[Value] {
        &self.rows
    }

    /// Writes `<ORCEL_XP08_REPORT_DIR>/<name>.report.json` when the
    /// directory is set.
    pub fn write(&self, name: &str) {
        eprintln!(
            "XP-08 {name}: {} rows in {:.1}s",
            self.rows.len(),
            self.started.elapsed().as_secs_f64()
        );
        let Some(dir) = std::env::var_os("ORCEL_XP08_REPORT_DIR").filter(|dir| !dir.is_empty())
        else {
            return;
        };
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        let report = json!({
            "schema": "orcel-benchmark-report/1",
            "orcel_commit": commit(),
            "suite": "native-conformance",
            "machine": {"os": machine_os(), "os_version": os_version(), "arch": arch()},
            "planner": {"kind": "deterministic", "name": "orcel-xp08-conformance", "version": env!("CARGO_PKG_VERSION")},
            "rows": self.rows,
        });
        let path = dir.join(format!("{name}.report.json"));
        std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap() + "\n").unwrap();
        eprintln!("XP-08 report: {}", path.display());
    }
}

fn commit() -> String {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("git rev-parse");
    let commit = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    assert!(
        commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()),
        "{commit}"
    );
    commit
}

fn machine_os() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

fn os_version() -> String {
    let raw = if cfg!(target_os = "macos") {
        tool("sw_vers", &["-productVersion"])
    } else {
        std::fs::read_to_string("/etc/os-release")
            .unwrap_or_default()
            .lines()
            .find_map(|line| line.strip_prefix("VERSION_ID="))
            .map(|value| value.trim_matches('"').to_owned())
            .unwrap_or_else(|| "unknown".to_owned())
    };
    let token: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || ".+-_".contains(*c))
        .take(64)
        .collect();
    if token.is_empty() {
        "unknown".to_owned()
    } else {
        token
    }
}

fn arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x86_64"
    }
}

// ---------------------------------------------------------------------------
// Observation cells, common to both suites.

/// A node of the observed tree whose name or value is exactly `text`.
pub fn has_text(nodes: &[Value], text: &str) -> bool {
    nodes
        .iter()
        .any(|node| node["name"] == text || node["value"] == text)
}

/// Whether the control named `name` is checked: AX reports a checkbox or
/// radio button as value `1`, AT-SPI as the toggled state.
pub fn checked(nodes: &[Value], name: &str) -> bool {
    let node = nodes
        .iter()
        .find(|node| node["name"] == name)
        .unwrap_or_else(|| panic!("{name} is not in the observed tree"));
    node["toggled"] == true || node["value"] == "1"
}

/// The runtime id of the first node whose name or value contains `needle`,
/// else of the tree's first node.
pub fn element_for(nodes: &[Value], needle: &str) -> String {
    nodes
        .iter()
        .find(|node| {
            node["name"]
                .as_str()
                .is_some_and(|name| name.contains(needle))
                || node["value"]
                    .as_str()
                    .is_some_and(|value| value.contains(needle))
        })
        .or_else(|| nodes.first())
        .and_then(|node| node["runtime_id"].as_str())
        .unwrap_or_else(|| panic!("observed tree is empty"))
        .to_owned()
}

/// What an observation suite needs from its harness.
pub struct Target<'a> {
    /// `<suite>/<window system>/<harness>`.
    pub prefix: String,
    pub title: &'a str,
    pub pid: u32,
    /// Texts the observed tree must hold, each checked against the
    /// fixture-owned state by the caller's `state` closure.
    pub markers: &'a [&'a str],
}

pub struct Observed {
    pub reference: Value,
    pub nodes: Vec<Value>,
}

/// The hello must serve observation and refuse every mutation. A refused
/// operation is what makes the input cells pending; if one is served, the
/// task that landed it has to port its cells.
pub fn check_hello(host: &mut Host, report: &mut Report, prefix: &str) -> Value {
    let started = Instant::now();
    let hello = host.hello();
    let elapsed = started.elapsed();
    let table = &hello["capabilities"];
    for op in ["list_windows", "observe_window"] {
        assert_eq!(
            table[op]["support"], "delivered",
            "{op} is not served here: {hello}"
        );
    }
    if host_serves_cursor() {
        assert_eq!(table["cursor_position"]["support"], "delivered", "{hello}");
    } else {
        assert_eq!(
            table["cursor_position"]["support"], "unavailable",
            "{hello}"
        );
        assert_eq!(
            table["cursor_position"]["reason"], "provider_unavailable",
            "{hello}"
        );
    }
    for op in INPUT_OPS {
        assert_eq!(
            table[op]["support"], "refused",
            "{op} is no longer refused: {} landed, so port its XP-08 cells from pending to measured. {hello}",
            Pending::for_op(op).task()
        );
        assert_eq!(table[op]["reason"], "capability_denied", "{op}: {hello}");
    }
    report.pass(
        format!("{prefix}/observe/hello"),
        "delivered",
        &[elapsed],
        1,
    );
    hello
}

pub const INPUT_OPS: [&str; 9] = [
    "semantic_action",
    "window_action",
    "input_move",
    "input_click",
    "input_drag",
    "input_scroll",
    "input_type_text",
    "input_key",
    "input_hotkey",
];

/// The listed title is the harness title, exactly or followed by the
/// ` [app id]` suffix Cua's Wayland listing appends (first Sway CI run).
pub fn title_matches(listed: &str, title: &str) -> bool {
    listed == title
        || listed.strip_prefix(title).is_some_and(|rest| {
            rest.starts_with(" [")
                && rest.ends_with(']')
                && !rest[2..rest.len() - 1].contains(['[', ']'])
        })
}

/// list_windows until the harness window appears; its owner must be the
/// harness process with a live start generation.
pub fn find_window(host: &mut Host, report: &mut Report, target: &Target) -> Value {
    let mut samples = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    let window = loop {
        let started = Instant::now();
        let listed = host.request("list_windows", json!({}));
        samples.push(started.elapsed());
        assert_eq!(listed["ok"], true, "{listed}");
        let windows = listed["windows"].as_array().unwrap();
        assert!(windows.len() <= 64, "{listed}");
        if let Some(window) = windows.iter().find(|window| {
            window["title"]
                .as_str()
                .is_some_and(|title| title_matches(title, target.title))
        }) {
            break window.clone();
        }
        assert!(
            Instant::now() < deadline,
            "{} never listed: {listed}",
            target.title
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    assert_eq!(
        window["process"]["pid"], target.pid,
        "window owner is not the harness: {window}"
    );
    let source = window["process"]["generation_source"]
        .as_str()
        .unwrap_or_default();
    assert!(
        matches!(source, "linux-proc-starttime" | "macos-bsd-start-time"),
        "{window}"
    );
    assert_ne!(window["process"]["start_generation"], 0, "{window}");
    let steps = samples.len();
    report.pass(
        format!("{}/observe/list-windows", target.prefix),
        "delivered",
        &samples,
        steps,
    );
    window
}

/// observe_window until every marker is in the bounded tree.
pub fn observe_markers(
    host: &mut Host,
    report: &mut Report,
    target: &Target,
    window: &Value,
) -> Observed {
    let reference = window_ref(window);
    let mut samples = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(45);
    let nodes = loop {
        let started = Instant::now();
        let tree = host.request(
            "observe_window",
            json!({"window": reference, "max_nodes": 256, "max_depth": 8}),
        );
        samples.push(started.elapsed());
        assert_eq!(tree["ok"], true, "{tree}");
        let nodes = flatten(&tree["elements"]);
        assert!(nodes.len() <= 256, "node bound broken: {}", nodes.len());
        if target.markers.iter().all(|marker| has_text(&nodes, marker)) {
            break nodes;
        }
        assert!(
            Instant::now() < deadline,
            "{} tree never held {:?}: {tree}",
            target.title,
            target.markers
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    let steps = samples.len();
    report.pass(
        format!("{}/observe/tree-markers", target.prefix),
        "delivered",
        &samples,
        steps,
    );
    Observed { reference, nodes }
}

/// A recycled window or process is refused, and the bounds hold.
pub fn identity_and_bounds(host: &mut Host, report: &mut Report, prefix: &str, reference: &Value) {
    for (field, delta) in [
        ("expected_window_nonce", 1u64),
        ("expected_start_generation", 1),
    ] {
        let mut stale = reference.clone();
        stale[field] = json!(stale[field].as_u64().unwrap().wrapping_add(delta));
        let reply = host.request("observe_window", json!({ "window": stale }));
        assert_eq!(error_code(&reply), "target_stale", "{field}: {reply}");
    }
    report.pass(format!("{prefix}/observe/stale-binding"), "refused", &[], 2);
    // The node bound cuts a non-empty tree to at most two nodes. The depth
    // bound can leave nothing (GTK nests its controls below depth 1), but
    // never more than the full-depth tree holds.
    let small = host.request(
        "observe_window",
        json!({"window": reference, "max_nodes": 2, "max_depth": 8}),
    );
    assert_eq!(small["ok"], true, "{small}");
    let count = flatten(&small["elements"]).len();
    assert!(
        (1..=2).contains(&count),
        "node-bounded observation returned {count} nodes: {small}"
    );
    let full = host.request("observe_window", json!({ "window": reference }));
    let shallow = host.request(
        "observe_window",
        json!({"window": reference, "max_depth": 1}),
    );
    assert_eq!(shallow["ok"], true, "{shallow}");
    assert!(
        flatten(&shallow["elements"]).len() <= flatten(&full["elements"]).len(),
        "depth bound grew the tree: {shallow}"
    );
    report.pass(format!("{prefix}/observe/bounds"), "delivered", &[], 3);
}

/// The cursor as the host reports it, checked against the screen it states.
pub fn host_cursor(host: &mut Host) -> (i64, i64, i64, i64) {
    let reply = host.request("cursor_position", json!({}));
    assert_eq!(reply["ok"], true, "{reply}");
    let cursor = &reply["cursor"];
    let value = |key: &str| {
        cursor[key]
            .as_i64()
            .unwrap_or_else(|| panic!("{key}: {reply}"))
    };
    let (x, y, width, height) = (
        value("x"),
        value("y"),
        value("screen_width"),
        value("screen_height"),
    );
    assert!(width > 0 && height > 0, "{reply}");
    (x, y, width, height)
}

/// Everything that must not change while the suite only observes or is
/// refused: fixture state, the window system's focus and stacking, and the
/// pointer.
#[derive(Debug, Clone, PartialEq)]
pub struct Oracles {
    pub fixture: Value,
    pub desktop: Desktop,
    pub cursor: Option<(i64, i64)>,
}

pub fn oracles(host: &mut Host, fixture: Value) -> Oracles {
    let cursor = host_serves_cursor().then(|| {
        let (x, y, _, _) = host_cursor(host);
        (x, y)
    });
    Oracles {
        fixture,
        desktop: desktop(),
        cursor,
    }
}

/// Repeated observation leaves every oracle as it was.
pub fn observation_has_no_effect(
    host: &mut Host,
    report: &mut Report,
    prefix: &str,
    reference: &Value,
    mut state: impl FnMut() -> Value,
) {
    let before = oracles(host, state());
    let mut samples = Vec::new();
    for _ in 0..10 {
        let started = Instant::now();
        let listed = host.request("list_windows", json!({}));
        assert_eq!(listed["ok"], true, "{listed}");
        let tree = host.request("observe_window", json!({ "window": reference }));
        assert_eq!(tree["ok"], true, "{tree}");
        samples.push(started.elapsed());
    }
    let after = oracles(host, state());
    assert_eq!(
        before, after,
        "observation changed fixture, focus, stacking or the pointer"
    );
    let names = oracle_names(&before.desktop).join(".");
    report.pass(
        format!("{prefix}/observe/no-effect/{names}"),
        "unchanged",
        &samples,
        20,
    );
}

/// One input cell: the `/2` frame it will send once its task lands.
pub struct InputCell {
    /// `<action>/<targeting>/<delivery>`.
    pub case: String,
    pub op: &'static str,
    pub fields: Value,
}

/// Sends each input cell's frame. Every one must be refused with
/// `capability_denied` and leave every oracle unchanged; it is then a typed
/// skip naming the task it waits for.
pub fn pending_input_cells(
    host: &mut Host,
    report: &mut Report,
    prefix: &str,
    reference: &Value,
    cells: &[InputCell],
    mut state: impl FnMut() -> Value,
) {
    for cell in cells {
        let before = oracles(host, state());
        let mut fields = cell.fields.clone();
        fields["window"] = reference.clone();
        let reply = host.request(cell.op, fields);
        assert_eq!(reply["ok"], false, "{} was not refused: {reply}", cell.case);
        assert_eq!(
            error_code(&reply),
            "capability_denied",
            "{}: {reply}",
            cell.case
        );
        // Give a leaked event time to reach the fixture before comparing.
        std::thread::sleep(Duration::from_millis(250));
        let after = oracles(host, state());
        assert_eq!(
            before, after,
            "{}: a refused frame changed an oracle",
            cell.case
        );
        let names = oracle_names(&before.desktop).join(".");
        report.pending(
            format!("{prefix}/{}/{names}", cell.case),
            Pending::for_op(cell.op),
        );
    }
}

/// After the harness exits, its window is stale, never observed.
pub fn closed_window_is_stale(
    host: &mut Host,
    report: &mut Report,
    prefix: &str,
    reference: &Value,
) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut steps = 0;
    loop {
        steps += 1;
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
    report.pass(
        format!("{prefix}/observe/closed-window"),
        "refused",
        &[],
        steps,
    );
}

/// The screen centre, the point every pixel-addressed pending frame names.
/// The host refuses the operation before it resolves any coordinate.
/// On Sway the output geometry comes from the compositor.
pub fn screen_centre(host: &mut Host) -> (i64, i64) {
    if host_serves_cursor() {
        let (_, _, width, height) = host_cursor(host);
        return (width / 2, height / 2);
    }
    let outputs: Value = serde_json::from_str(&tool("swaymsg", &["-r", "-t", "get_outputs"]))
        .expect("swaymsg prints JSON");
    let rect = &outputs[0]["rect"];
    let value = |key: &str| {
        rect[key]
            .as_i64()
            .unwrap_or_else(|| panic!("{key}: {outputs}"))
    };
    (
        value("x") + value("width") / 2,
        value("y") + value("height") / 2,
    )
}
