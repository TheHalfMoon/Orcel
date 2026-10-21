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
//! Input cells exist for every action of the catalog. The accessibility-
//! addressed (`ax`) cells run through `semantic_action` (XP-11): the verb is
//! delivered in the background, the effect is read from the fixture's own
//! state, and focus, stacking and the pointer must not move. A delivery mode
//! the host does not have (foreground) and an action with no semantic verb
//! are typed skips that say so.
//!
//! The pixel-addressed (`px`) cells (XP-12) are measured on X11 and macOS
//! against an application that journals what it receives
//! ([`run_probe_cells`]): the event must arrive where the frame named, in
//! window-relative coordinates, and focus, stacking and the pointer must not
//! move. A hover and a key chord are refused by policy and a Wayland session
//! offers no non-interactive way to address one window; those frames are
//! sent and must be refused exactly, with every oracle unchanged. The shared
//! web page does not expose its controls' geometry to the host, so its
//! pixel cells are reported as skips (`no-geometry`) and the raw input they
//! stand for is measured on the probe.
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
    /// every oracle unchanged, for the stated reason (`refused` by policy,
    /// `unavailable` on this window system).
    pub fn refused_with(&mut self, case: String, observed: &str) {
        self.push(case, "skip", observed, &[], 1);
    }

    /// A cell this fixture cannot measure: it exposes no geometry to aim at.
    pub fn no_geometry(&mut self, case: String) {
        self.push(case, "skip", "no-geometry", &[], 0);
    }

    /// A delivery mode the host does not have: semantic actions are
    /// delivered in the background and never take the foreground, so the
    /// foreground rung of the matrix has nothing to measure.
    pub fn background_only(&mut self, case: String) {
        self.push(case, "skip", "background-only", &[], 0);
    }

    /// An action that has no semantic verb, or that the host refuses on
    /// purpose; the cell sent its frame and saw the exact refusal.
    pub fn refused_by_design(&mut self, case: String) {
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

/// The hello must serve observation and semantic actions, serve the five raw
/// input operations in the background where the window system allows (X11 and
/// macOS) and say `provider_unavailable` where it does not (Wayland), and
/// refuse a window command, a hover and a key chord by policy.
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
    assert_eq!(
        table["semantic_action"]["support"], "delivered",
        "semantic_action is not served here: {hello}"
    );
    assert_eq!(
        table["semantic_action"]["delivery"], "background",
        "{hello}"
    );
    for op in POLICY_REFUSED_OPS {
        assert_eq!(table[op]["support"], "refused", "{op} is served: {hello}");
        assert_eq!(table[op]["reason"], "capability_denied", "{op}: {hello}");
    }
    for op in INPUT_OPS {
        match (window_system(), table[op]["support"].as_str()) {
            ("x11", Some("delivered")) | ("quartz", Some("delivered")) => {
                assert_eq!(table[op]["delivery"], "background", "{op}: {hello}");
            }
            // X11 without Cua's real input backend (Xvfb) serves the pointer
            // operations only.
            ("x11", Some("unavailable")) if matches!(op, "input_type_text" | "input_key") => {
                assert_eq!(table[op]["reason"], "provider_unavailable", "{op}: {hello}");
            }
            // The hosted macOS runner has no recorded direct-capture consent,
            // which Cua's pixel tools need: unavailable, with the reason.
            ("quartz", Some("unavailable")) => {
                assert_eq!(table[op]["reason"], "permission_missing", "{op}: {hello}");
            }
            // A Wayland client has no non-interactive way to address a window.
            (_, Some("unavailable")) if window_system() != "x11" => {
                assert_eq!(table[op]["reason"], "provider_unavailable", "{op}: {hello}");
            }
            (system, support) => panic!("{op} is {support:?} on {system}: {hello}"),
        }
    }
    report.pass(
        format!("{prefix}/observe/hello"),
        "delivered",
        &[elapsed],
        1,
    );
    hello
}

/// The operations the host refuses by policy: a window-manager command, a
/// hover (no effect the kernel can verify) and a key chord (it can reach a
/// system shortcut).
pub const POLICY_REFUSED_OPS: [&str; 3] = ["window_action", "input_move", "input_hotkey"];

/// The raw input operations the host delivers (XP-12).
pub const INPUT_OPS: [&str; 5] = [
    "input_click",
    "input_drag",
    "input_scroll",
    "input_type_text",
    "input_key",
];

/// Whether the hello serves raw input (X11, and macOS with the capture
/// consent recorded). A Wayland client has no non-interactive way to address
/// one window, so the host says unavailable there.
pub fn input_delivered(hello: &Value) -> bool {
    hello["capabilities"]["input_click"]["support"] == "delivered"
}

/// The reason the hello gives for raw input being unavailable, which is also
/// the code a raw input frame is refused with.
pub fn input_unavailable_reason(hello: &Value) -> String {
    hello["capabilities"]["input_click"]["reason"]
        .as_str()
        .unwrap_or("provider_unavailable")
        .to_owned()
}

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

/// Sends each input cell's frame. Every one must be refused with the code
/// `expected` and leave every oracle unchanged; the cell is then a typed skip
/// reporting `observed` (`refused` by policy, `unavailable` on Wayland). The
/// frames carry the human-input tick 0, a value no live tick is within
/// tolerance of, so even a frame that reached delivery would be cancelled.
#[allow(clippy::too_many_arguments)]
pub fn refused_input_cells(
    host: &mut Host,
    report: &mut Report,
    prefix: &str,
    reference: &Value,
    cells: &[InputCell],
    expected: &str,
    observed: &str,
    mut state: impl FnMut() -> Value,
) {
    for cell in cells {
        let before = oracles(host, state());
        let mut fields = cell.fields.clone();
        fields["window"] = reference.clone();
        let reply = host.request(cell.op, fields);
        assert_eq!(reply["ok"], false, "{} was not refused: {reply}", cell.case);
        assert!(reply.get("action").is_none(), "{}: {reply}", cell.case);
        assert_eq!(error_code(&reply), expected, "{}: {reply}", cell.case);
        // Give a leaked event time to reach the fixture before comparing.
        std::thread::sleep(Duration::from_millis(250));
        let after = oracles(host, state());
        assert_eq!(
            before, after,
            "{}: a refused frame changed an oracle",
            cell.case
        );
        let names = oracle_names(&before.desktop).join(".");
        report.refused_with(format!("{prefix}/{}/{names}", cell.case), observed);
    }
}

/// The window the input probe opened, by its nonce.
pub fn probe_window(host: &mut Host, nonce: &str) -> Value {
    let title = format!("Orcel XP12 Input {nonce}");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let listed = host.request("list_windows", json!({}));
        assert_eq!(listed["ok"], true, "{listed}");
        if let Some(window) = listed["windows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|window| window["title"] == title.as_str())
        {
            return window.clone();
        }
        assert!(Instant::now() < deadline, "{title} never listed: {listed}");
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// The human-input tick the kernel would read before arming a cell.
fn live_tick(host: &mut Host) -> u64 {
    let cursor = host.request("cursor_position", json!({}));
    assert_eq!(cursor["ok"], true, "{cursor}");
    let tick = cursor["cursor"]["last_input_tick"].as_u64().unwrap_or(0);
    assert_ne!(tick, 0, "the session has no human-input clock: {cursor}");
    tick
}

fn near(value: &Value, expected: f64) -> bool {
    value
        .as_f64()
        .is_some_and(|got| (got - expected).abs() <= 2.0)
}

/// One measured pixel cell: the frame, how many journal entries to wait for
/// and what the application must have received.
struct ProbeCell {
    case: &'static str,
    op: &'static str,
    fields: Value,
    wanted: usize,
    check: fn(&[Value]) -> bool,
}

fn probe_cells() -> Vec<ProbeCell> {
    vec![
        ProbeCell {
            case: "click",
            op: "input_click",
            fields: json!({"x": 120, "y": 90, "button": "left", "click_count": 1}),
            wanted: 2,
            check: |got| {
                got[0]["kind"] == "down"
                    && got[0]["button"] == 1
                    && near(&got[0]["x"], 120.0)
                    && near(&got[0]["y"], 90.0)
                    && got.last().is_some_and(|last| last["kind"] == "up")
            },
        },
        ProbeCell {
            case: "double-click",
            op: "input_click",
            fields: json!({"x": 60, "y": 70, "button": "left", "click_count": 2}),
            wanted: 4,
            check: |got| {
                got.iter().filter(|event| event["kind"] == "down").count() >= 2
                    && got.iter().any(|event| event["clicks"] == 2)
                    && near(&got[0]["x"], 60.0)
                    && near(&got[0]["y"], 70.0)
            },
        },
        ProbeCell {
            case: "right-click",
            op: "input_click",
            fields: json!({"x": 200, "y": 150, "button": "right", "click_count": 1}),
            wanted: 2,
            check: |got| {
                got[0]["button"] == 3 && near(&got[0]["x"], 200.0) && near(&got[0]["y"], 150.0)
            },
        },
        ProbeCell {
            case: "drag",
            op: "input_drag",
            fields: json!({"x": 50, "y": 60, "to_x": 250, "to_y": 160}),
            wanted: 3,
            check: |got| {
                let (first, last) = (&got[0], got.last().unwrap());
                first["kind"] == "down"
                    && near(&first["x"], 50.0)
                    && near(&first["y"], 60.0)
                    && last["kind"] == "up"
                    && near(&last["x"], 250.0)
                    && near(&last["y"], 160.0)
                    && got.iter().any(|event| event["kind"] == "motion")
            },
        },
        ProbeCell {
            case: "scroll",
            op: "input_scroll",
            fields: json!({"x": 100, "y": 100, "scroll_x": 0, "scroll_y": 3}),
            wanted: 1,
            check: |got| {
                got.iter().all(|event| event["kind"] == "scroll")
                    && got.iter().any(|event| {
                        event["direction"] == "down"
                            || event["dy"].as_f64().is_some_and(|dy| dy != 0.0)
                    })
            },
        },
        ProbeCell {
            case: "type-text",
            op: "input_type_text",
            fields: json!({"text": "conformance"}),
            wanted: 11,
            check: |got| {
                got.iter()
                    .filter(|event| event["kind"] == "key")
                    .map(|event| event["string"].as_str().unwrap_or_default())
                    .collect::<String>()
                    == "conformance"
            },
        },
        ProbeCell {
            case: "press-key",
            op: "input_key",
            fields: json!({"key": "tab"}),
            wanted: 1,
            check: |got| got.iter().all(|event| event["kind"] == "key"),
        },
    ]
}

/// The measured pixel cells (XP-12) on X11 and macOS: each frame goes to the
/// probe window with a fresh human-input tick; the application's own journal
/// must show the event where the frame named it, and the window system's
/// focus, stacking and pointer must be where they were (no raise, no focus
/// change, no real pointer move). The foreground rung has nothing to measure:
/// raw input is delivered in the background and never takes the foreground.
pub fn run_probe_cells(
    host: &mut Host,
    report: &mut Report,
    prefix: &str,
    reference: &Value,
    probe: &crate::support::Probe,
    hello: &Value,
) {
    let state = || crate::support::read_state(&probe.state).expect("the probe keeps its state");
    for cell in probe_cells() {
        let case = format!("{}/px/background", cell.case);
        let before = oracles(host, state());
        let served = &hello["capabilities"][cell.op];
        if served["support"] != "delivered" {
            // The keyboard operations are unavailable on a session with no
            // real input backend (Xvfb): the frame is refused with the
            // hello's reason and the application receives nothing.
            let mut fields = cell.fields.clone();
            fields["window"] = reference.clone();
            fields["expected_last_input_tick"] = json!(0);
            let reply = host.request(cell.op, fields);
            assert_eq!(reply["ok"], false, "{case} was not refused: {reply}");
            assert_eq!(
                error_code(&reply),
                served["reason"].as_str().unwrap_or("provider_unavailable"),
                "{case}: {reply}"
            );
            std::thread::sleep(Duration::from_millis(250));
            let after = oracles(host, state());
            assert_eq!(before, after, "{case}: a refused frame changed an oracle");
            let names = oracle_names(&before.desktop).join(".");
            report.refused_with(format!("{prefix}/{case}/{names}"), "unavailable");
            report.background_only(format!("{prefix}/{}/px/foreground", cell.case));
            continue;
        }
        let seen = crate::support::events(&before.fixture).len();
        let mut fields = cell.fields.clone();
        fields["window"] = reference.clone();
        fields["expected_last_input_tick"] = json!(live_tick(host));
        let started = Instant::now();
        let reply = host.request(cell.op, fields);
        let elapsed = started.elapsed();
        assert_eq!(reply["ok"], true, "{case}: {reply}");
        assert_eq!(reply["action"]["state"], "completed", "{case}: {reply}");
        assert_eq!(reply["action"]["action"], cell.op, "{case}: {reply}");
        let deadline = Instant::now() + Duration::from_secs(10);
        let got = loop {
            let all = crate::support::events(&state());
            let got: Vec<Value> = all.into_iter().skip(seen).collect();
            if got.len() >= cell.wanted {
                // Let a trailing event arrive before the cell is judged.
                std::thread::sleep(Duration::from_millis(300));
                break crate::support::events(&state())
                    .into_iter()
                    .skip(seen)
                    .collect::<Vec<_>>();
            }
            assert!(
                Instant::now() < deadline,
                "{case}: the application received {got:?}"
            );
            std::thread::sleep(Duration::from_millis(100));
        };
        assert!(
            (cell.check)(&got),
            "{case}: the application received {got:?}"
        );
        let after = oracles(host, state());
        assert_eq!(before.cursor, after.cursor, "{case}: the pointer moved");
        assert_eq!(
            before.desktop, after.desktop,
            "{case}: focus or stacking changed"
        );
        let names = oracle_names(&before.desktop).join(".");
        report.pass(
            format!("{prefix}/{case}/{names}"),
            "delivered",
            &[elapsed],
            1,
        );
        report.background_only(format!("{prefix}/{}/px/foreground", cell.case));
    }
}

/// The runtime id of the one node named `needle` (exactly, else containing
/// it), of control type `control` when given. Panics with the tree when no
/// node matches: an action cell never falls back to another element.
pub fn strict_element_id(nodes: &[Value], needle: &str, control: Option<&str>) -> String {
    let matches = |node: &Value, exact: bool| {
        let text = |field: &str| node[field].as_str().unwrap_or_default().to_owned();
        let name = text("name");
        let named = if exact {
            name == needle
        } else {
            name.contains(needle)
        };
        named && control.is_none_or(|control| node["control_type"] == control)
    };
    nodes
        .iter()
        .find(|node| matches(node, true))
        .or_else(|| nodes.iter().find(|node| matches(node, false)))
        .and_then(|node| node["runtime_id"].as_str())
        .unwrap_or_else(|| {
            let names: Vec<_> = nodes
                .iter()
                .map(|node| format!("{}:{}", node["control_type"], node["name"]))
                .collect();
            panic!("no {control:?} element named {needle:?} in {names:?}")
        })
        .to_owned()
}

/// A fresh bounded observation of the window, flattened.
pub fn fresh_nodes(host: &mut Host, reference: &Value) -> Vec<Value> {
    let tree = host.request(
        "observe_window",
        json!({"window": reference, "max_nodes": 256, "max_depth": 8}),
    );
    assert_eq!(tree["ok"], true, "{tree}");
    flatten(&tree["elements"])
}

/// What an `ax` cell expects of its fixture.
pub struct ActionCell<'a> {
    /// `<action>/ax/background`.
    pub case: String,
    pub verb: &'static str,
    /// The accessible name of the element, and its control type.
    pub element: &'a str,
    pub control: Option<&'static str>,
    pub value: Option<&'a str>,
    /// Whether focus and stacking must stay exactly as they were. An action
    /// that opens a window the app raises itself (a child window) says no.
    pub holds_desktop: bool,
}

/// Delivers one accessibility-addressed action and checks it against the
/// oracles the host cannot write: the fixture's own state must show the
/// effect (`done`), and the window system's focus and stacking and the
/// pointer must be where they were. The reply must be the typed completion.
pub fn run_action(
    host: &mut Host,
    report: &mut Report,
    prefix: &str,
    reference: &Value,
    cell: &ActionCell,
    mut state: impl FnMut() -> Value,
    done: impl Fn(&Value) -> bool,
) {
    let nodes = fresh_nodes(host, reference);
    let id = strict_element_id(&nodes, cell.element, cell.control);
    let before = oracles(host, state());
    assert!(
        !done(&before.fixture),
        "{}: the fixture already shows the effect: {}",
        cell.case,
        before.fixture
    );
    let mut fields = json!({
        "window": reference,
        "semantic_action": cell.verb,
        "element_runtime_id": id,
    });
    if let Some(value) = cell.value {
        fields["value"] = json!(value);
    }
    let started = Instant::now();
    let reply = host.request("semantic_action", fields);
    let elapsed = started.elapsed();
    assert_eq!(reply["ok"], true, "{}: {reply}", cell.case);
    assert_eq!(
        reply["action"]["state"], "completed",
        "{}: {reply}",
        cell.case
    );
    assert_eq!(
        reply["action"]["action"],
        format!("semantic_{}", cell.verb),
        "{}: {reply}",
        cell.case
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let now = state();
        if done(&now) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{}: the fixture never showed the effect: {now}",
            cell.case
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // Give a leaked or late event time to reach the desktop.
    std::thread::sleep(Duration::from_millis(300));
    let after = oracles(host, state());
    assert_eq!(
        before.cursor, after.cursor,
        "{}: the pointer moved",
        cell.case
    );
    if cell.holds_desktop {
        assert_eq!(
            before.desktop, after.desktop,
            "{}: focus or stacking changed",
            cell.case
        );
    }
    let mut names = oracle_names(&before.desktop);
    if !cell.holds_desktop {
        names.retain(|name| !matches!(*name, "focus" | "z-order"));
    }
    report.pass(
        format!("{prefix}/{}/{}", cell.case, names.join(".")),
        "delivered",
        &[elapsed],
        1,
    );
}

/// Sends `fields` as a `semantic_action` and requires the exact refusal
/// `expected`, with every oracle, fixture state included, unchanged.
pub fn refused_action(
    host: &mut Host,
    report: &mut Report,
    prefix: &str,
    case: &str,
    fields: Value,
    expected: &str,
    mut state: impl FnMut() -> Value,
) {
    let before = oracles(host, state());
    let reply = host.request("semantic_action", fields);
    assert_eq!(reply["ok"], false, "{case} was not refused: {reply}");
    assert!(reply.get("action").is_none(), "{case}: {reply}");
    assert_eq!(error_code(&reply), expected, "{case}: {reply}");
    std::thread::sleep(Duration::from_millis(250));
    let after = oracles(host, state());
    assert_eq!(before, after, "{case}: a refused action changed an oracle");
    let names = oracle_names(&before.desktop).join(".");
    report.pass(format!("{prefix}/{case}/{names}"), "refused", &[], 1);
}

/// The negative cells every host must pass, whatever the toolkit: a forged,
/// altered or stale target, a verb that does not suit the element, scroll
/// (a wheel event), and a frame that smuggles a position or a key. Every
/// one is refused with a typed code and moves no oracle. `wrong_verb` names
/// a button, a check box and a radio button of the fixture.
pub struct NegativeTargets<'a> {
    pub button: &'a str,
    pub check_box: &'a str,
}

pub fn negative_action_cells(
    host: &mut Host,
    report: &mut Report,
    prefix: &str,
    reference: &Value,
    targets: &NegativeTargets,
    mut state: impl FnMut() -> Value,
) {
    let nodes = fresh_nodes(host, reference);
    let button = strict_element_id(&nodes, targets.button, Some("Button"));
    let check_box = strict_element_id(&nodes, targets.check_box, Some("CheckBox"));
    let frame = |verb: &str, id: &str| {
        let mut fields =
            json!({"window": reference, "semantic_action": verb, "element_runtime_id": id});
        if verb == "toggle" {
            fields["value"] = json!("true");
        }
        fields
    };
    let mut refuse = |host: &mut Host, case: &str, fields: Value, expected: &str| {
        refused_action(host, report, prefix, case, fields, expected, &mut state);
    };

    // A target the tree never held, and a real one with one digit changed.
    refuse(
        host,
        "invoke/forged-element/refused",
        frame("invoke", "e999-0000000000000000"),
        "target_stale",
    );
    let mut altered = button.clone();
    let last = altered.pop().unwrap();
    altered.push(if last == '0' { '1' } else { '0' });
    refuse(
        host,
        "invoke/altered-element/refused",
        frame("invoke", &altered),
        "target_stale",
    );
    // A window binding that no longer matches.
    for (field, name) in [
        ("expected_window_nonce", "stale-window"),
        ("expected_start_generation", "stale-process"),
    ] {
        let mut stale = reference.clone();
        stale[field] = json!(stale[field].as_u64().unwrap().wrapping_add(1));
        let mut fields = frame("invoke", &button);
        fields["window"] = stale;
        refuse(
            host,
            &format!("invoke/{name}/refused"),
            fields,
            "target_stale",
        );
    }
    // A verb that does not suit the element.
    refuse(
        host,
        "toggle/button/refused",
        frame("toggle", &button),
        "capability_denied",
    );
    refuse(
        host,
        "select/button/refused",
        frame("select", &button),
        "capability_denied",
    );
    let mut value = frame("set_value", &button);
    value["value"] = json!("typed into a button");
    refuse(host, "set-value/button/refused", value, "capability_denied");
    refuse(
        host,
        "invoke/check-box/refused",
        frame("invoke", &check_box),
        "capability_denied",
    );
    // A toggle never flips blindly: asking for the state the live element
    // already has is refused as stale, and a toggle without a state is
    // malformed.
    let mut already = frame("toggle", &check_box);
    already["value"] = json!("false");
    refuse(host, "toggle/already/refused", already, "target_stale");
    let mut stateless = frame("toggle", &check_box);
    stateless.as_object_mut().unwrap().remove("value");
    refuse(
        host,
        "toggle/stateless/refused",
        stateless,
        "invalid_request",
    );
    // Scroll is a wheel event at a position: pixel-addressed (input_scroll).
    refuse(
        host,
        "scroll/ax/refused",
        frame("scroll", &button),
        "capability_denied",
    );
    // A semantic frame cannot carry a point, a key, text or a button.
    for (field, extra) in [
        ("x", json!(10)),
        ("button", json!("left")),
        ("text", json!("typed")),
        ("key", json!("enter")),
        ("expected_last_input_tick", json!(0)),
    ] {
        let mut fields = frame("invoke", &button);
        fields[field] = extra;
        refuse(
            host,
            &format!("invoke/with-{}/refused", segment(field)),
            fields,
            "invalid_request",
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
