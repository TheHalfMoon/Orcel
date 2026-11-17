//! SG-000119 A5 native Windows qualification: accessibility, layout,
//! hardening against browser keys, and the renderer's reach.
//!
//! The test binary is its own driver (`harness = false`), as `native_shell`
//! is: each window runs in a child process, either the shell binary itself or
//! this binary with `--sg119-scenario`, which runs the same `run` with an
//! after-show hook.
//!
//! **Two kinds of case.**
//!
//! - **Read-only (always).** They open a window of their own and read it: the
//!   rendered page through scripts evaluated from Rust (nothing is added to
//!   the page's own code), the UI Automation tree through PowerShell's
//!   managed client, process tokens through Win32. No keystroke, mouse event
//!   or focus change is sent anywhere, so they may run on a developer's PC.
//!   The layout case resizes and zooms its own test window and sets `dir` on
//!   its own document.
//! - **Input (only with `ORCEL_ALLOW_INPUT_TESTS=1`).** They bring the test
//!   window to the foreground and send real keystrokes and a right-click with
//!   `SendInput`, so they run only on a disposable runner: the CI job
//!   `control-room-shell` (windows-latest) sets the variable for this test.
//!   Without it they report themselves ignored and inject nothing; the child
//!   scenarios refuse too. Even there, every key press and the right-click
//!   is sent only while the test's own window is the foreground window
//!   (checked before each event), and the click only where the window under
//!   the point belongs to the shell's process tree; otherwise the scenario
//!   stops and closes its window.
//!
//! Adapted from PR #282's UI Automation checks (the WPF preview's
//! `tests/e2e.ps1`), those that apply to a read-only view: the window
//! appears and belongs to the launched process; the connection line reports
//! orceld's real state (unavailable when none answers) instead of inventing
//! one; the task list invents no task; there is no edit box or acting
//! control; every keyboard stop has an accessible name; the status line is a
//! polite live region; no process is started beyond WebView2's own; the
//! window closes cleanly. Memory and start time are measured by
//! `tests/measure.ps1`.

#[path = "support/qualify.rs"]
mod qualify;

use orcel_control_room_shell::{run, shell, Hooks};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CLOSE};

const SCENARIO: &str = "--sg119-scenario";
const SHELL: &str = env!("CARGO_BIN_EXE_orcel-control-room-shell");
/// Input cases run only when this is exactly `1` (a disposable runner).
const INPUT_GATE: &str = "ORCEL_ALLOW_INPUT_TESTS";

fn input_allowed() -> bool {
    std::env::var(INPUT_GATE).is_ok_and(|value| value == "1")
}

/// Whether this user's own orceld answers (on a developer's PC it may; on a
/// CI runner it does not).
fn this_users_orceld_answers() -> bool {
    orcel_app_api_client::AppApiClient::for_this_user()
        .map(|client| client.status().is_ok())
        .unwrap_or(false)
}

type Case = fn();

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(at) = args.iter().position(|arg| arg == SCENARIO) {
        let code = match args.get(at + 1).map(String::as_str) {
            Some("a11y") => scenario(drive_a11y),
            Some("keys") if input_allowed() => scenario(drive_keys),
            Some("tabs") if input_allowed() => scenario(drive_tabs),
            Some("keys" | "tabs") => {
                eprintln!("refused: input scenarios need {INPUT_GATE}=1 (a disposable runner)");
                65
            }
            other => {
                eprintln!("unknown scenario {other:?}");
                64
            }
        };
        std::process::exit(code);
    }
    if args.iter().any(|arg| arg == "--list") {
        return;
    }
    let cases: [(&str, bool, Case); 4] = [
        (
            "the_view_reads_well_to_ui_automation_and_scales_and_mirrors",
            false,
            view_accessibility,
        ),
        (
            "the_renderer_cannot_open_a_pipe_secured_as_orcelds",
            false,
            renderer_cannot_open_the_pipe,
        ),
        (
            "f12_ctrl_shift_i_ctrl_p_and_right_click_do_nothing",
            true,
            browser_keys_do_nothing,
        ),
        (
            "the_keyboard_alone_reaches_every_stop_in_order",
            true,
            keyboard_order,
        ),
    ];
    let (mut passed, mut failed, mut ignored) = (0, Vec::new(), 0);
    for (name, injects_input, case) in cases {
        if injects_input && !input_allowed() {
            println!(
                "test {name} ... ignored (injects keyboard and mouse input; runs only where \
                 {INPUT_GATE}=1, the CI job control-room-shell on windows-latest)"
            );
            ignored += 1;
            continue;
        }
        println!("test {name} ...");
        match std::panic::catch_unwind(case) {
            Ok(()) => {
                println!("test {name} ... ok");
                passed += 1;
            }
            Err(_) => {
                println!("test {name} ... FAILED");
                failed.push(name);
            }
        }
    }
    println!(
        "test result: {}. {passed} passed; {} failed; {ignored} ignored",
        if failed.is_empty() { "ok" } else { "FAILED" },
        failed.len()
    );
    if !failed.is_empty() {
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Child processes

fn scenario(drive: fn(tauri::WebviewWindow)) -> i32 {
    run(Hooks {
        after_apply: None,
        after_show: Some(Box::new(move |window| {
            std::thread::spawn(move || drive(window));
        })),
    })
}

fn without_webview2_variables(command: &mut Command) -> &mut Command {
    for (name, _) in std::env::vars_os() {
        if orcel_control_room_shell::environment::names_webview2(&name) {
            command.env_remove(name);
        }
    }
    command
}

struct Live {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    seen: Vec<String>,
    stderr: Option<std::thread::JoinHandle<String>>,
}

impl Live {
    fn spawn(command: &mut Command) -> Self {
        let mut child = without_webview2_variables(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the child");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("stdout");
        let mut stderr = child.stderr.take().expect("stderr");
        let (sender, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let stderr = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stderr.read_to_string(&mut text);
            text
        });
        Live {
            child: Some(child),
            stdin,
            lines,
            seen: Vec::new(),
            stderr: Some(stderr),
        }
    }

    fn pid(&self) -> u32 {
        self.child.as_ref().expect("the child").id()
    }

    /// The rest of the first line starting with `prefix`, waiting up to
    /// `limit`.
    fn wait(&mut self, prefix: &str, limit: Duration) -> String {
        let deadline = Instant::now() + limit;
        if let Some(line) = self.seen.iter().find(|line| line.starts_with(prefix)) {
            return line[prefix.len()..].to_owned();
        }
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    println!("    | {line}");
                    let hit = line.starts_with(prefix);
                    self.seen.push(line.clone());
                    if hit {
                        return line[prefix.len()..].to_owned();
                    }
                }
                Err(_) => panic!(
                    "no {prefix:?} line within {limit:?}; seen:\n{:#?}",
                    self.seen
                ),
            }
        }
    }

    fn say(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("the child's stdin");
        writeln!(stdin, "{line}").expect("write to the child");
        stdin.flush().expect("flush");
    }

    /// Waits for the exit, collecting every remaining line.
    fn finish(&mut self, limit: Duration) -> (Option<i32>, String) {
        let mut child = self.child.take().expect("the child");
        let start = Instant::now();
        let status = loop {
            while let Ok(line) = self.lines.try_recv() {
                println!("    | {line}");
                self.seen.push(line);
            }
            if let Some(status) = child.try_wait().expect("poll the child") {
                break Some(status);
            }
            if start.elapsed() > limit {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        std::thread::sleep(Duration::from_millis(200));
        while let Ok(line) = self.lines.try_recv() {
            println!("    | {line}");
            self.seen.push(line);
        }
        let stderr = self
            .stderr
            .take()
            .and_then(|handle| handle.join().ok())
            .unwrap_or_default();
        for line in stderr.lines() {
            println!("    ! {line}");
        }
        assert!(status.is_some(), "the child did not exit within {limit:?}");
        (status.and_then(|status| status.code()), stderr)
    }

    fn lines(&self, prefix: &str) -> Vec<String> {
        self.seen
            .iter()
            .filter(|line| line.starts_with(prefix))
            .map(|line| line[prefix.len()..].to_owned())
            .collect()
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn scenario_command(name: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("this test binary"));
    command.args([SCENARIO, name]);
    command
}

fn json_of(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|error| panic!("not JSON ({error}): {text}"))
}

/// `SG119-IPC commands=<n> web_messages=0` must be present, web messages 0.
fn assert_no_web_messages(live: &Live) {
    let ipc = live.lines("SG119-IPC ");
    assert_eq!(ipc.len(), 1, "{:?}", live.seen);
    assert!(ipc[0].ends_with(" web_messages=0"), "{}", ipc[0]);
}

// ---------------------------------------------------------------------------
// Evaluating in the page (from Rust; nothing is added to the page's code)

fn evaluate(window: &tauri::WebviewWindow, script: &str) -> Option<Value> {
    let (sender, receiver) = channel();
    window
        .eval_with_callback(script, move |answer| {
            let _ = sender.send(answer);
        })
        .ok()?;
    let answer = receiver.recv_timeout(Duration::from_secs(10)).ok()?;
    // The callback gets the evaluated value as JSON: our scripts evaluate to a
    // string holding JSON.
    let outer: Value = serde_json::from_str(&answer).ok()?;
    match outer {
        Value::String(inner) => serde_json::from_str(&inner).ok(),
        other => Some(other),
    }
}

fn evaluate_until(
    window: &tauri::WebviewWindow,
    script: &str,
    limit: Duration,
    ready: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = Instant::now() + limit;
    let mut last = Value::Null;
    while Instant::now() < deadline {
        if let Some(value) = evaluate(window, script) {
            if ready(&value) {
                return value;
            }
            last = value;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    last
}

/// The view has drawn its first answers (the connection line moved on from
/// "Starting" and the status panel has content).
const SETTLED: &str = r#"JSON.stringify({
  connection: (document.getElementById('connection') || {}).textContent || '',
  status: ((document.getElementById('status-body') || {}).textContent || '').length
})"#;

fn settle(window: &tauri::WebviewWindow) -> Value {
    evaluate_until(window, SETTLED, Duration::from_secs(30), |value| {
        value["connection"]
            .as_str()
            .is_some_and(|text| text != "Starting")
            && value["status"].as_u64().unwrap_or(0) > 0
    })
}

/// Names, roles, keyboard stops and contrast of the rendered page, as the
/// page itself reports them.
const AUDIT: &str = r#"(function () {
  function squash(s) { return (s || '').replace(/\s+/g, ' ').trim(); }
  function nameOf(e) {
    var label = e.getAttribute('aria-label');
    if (label) { return squash(label); }
    var by = e.getAttribute('aria-labelledby');
    if (by) { var t = document.getElementById(by); if (t) { return squash(t.textContent); } }
    return squash(e.textContent).slice(0, 160);
  }
  function shown(e) { return !e.closest('[hidden]') && e.getClientRects().length > 0; }
  var natively = 'a[href],button,input,select,textarea,summary,iframe,[contenteditable=""],[contenteditable="true"]';
  var stops = Array.prototype.filter.call(document.querySelectorAll(natively + ',[tabindex]'), function (e) {
    var t = e.getAttribute('tabindex');
    return shown(e) && !(t !== null && Number(t) < 0);
  }).map(function (e) {
    return { tag: e.tagName.toLowerCase(), id: e.id || e.getAttribute('data-task') || '', role: e.getAttribute('role') || '', name: nameOf(e) };
  });
  function rgb(s) {
    var m = /rgba?\(([^)]+)\)/.exec(s || '');
    if (!m) { return null; }
    var p = m[1].split(/[ ,\/]+/).filter(Boolean).map(parseFloat);
    return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
  }
  function lum(c) {
    function ch(v) { v = v / 255; return v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }
    return 0.2126 * ch(c.r) + 0.7152 * ch(c.g) + 0.0722 * ch(c.b);
  }
  function backgroundOf(e) {
    while (e) { var c = rgb(getComputedStyle(e).backgroundColor); if (c && c.a > 0) { return c; } e = e.parentElement; }
    return { r: 255, g: 255, b: 255, a: 1 };
  }
  var worst = null, checked = 0;
  var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT), node;
  while ((node = walker.nextNode())) {
    if (!/\S/.test(node.nodeValue)) { continue; }
    var e = node.parentElement;
    if (!e || !shown(e)) { continue; }
    var fg = rgb(getComputedStyle(e).color), bg = backgroundOf(e);
    if (!fg) { continue; }
    var a = lum(fg), b = lum(bg), ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
    checked++;
    if (!worst || ratio < worst.ratio) {
      worst = { ratio: Math.round(ratio * 100) / 100, element: e.tagName.toLowerCase() + (e.className ? '.' + e.className : ''), text: squash(node.nodeValue).slice(0, 40) };
    }
  }
  var connection = document.getElementById('connection');
  var headings = Array.prototype.map.call(document.querySelectorAll('h1,h2,h3,h4'), function (h) { return h.tagName.toLowerCase() + ' ' + squash(h.textContent); });
  return JSON.stringify({
    lang: document.documentElement.lang,
    title: document.title,
    scheme: matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light',
    forced_colors: matchMedia('(forced-colors: active)').matches,
    h1: document.querySelectorAll('h1').length,
    headings: headings,
    stops: stops,
    status: { role: connection.getAttribute('role'), live: connection.getAttribute('aria-live'), text: squash(connection.textContent) },
    tasks_note: squash((document.getElementById('tasks-body') || {}).textContent),
    task_items: document.querySelectorAll('#task-list > li').length,
    acting: document.querySelectorAll('a,button,input,select,textarea,form,iframe,img,object,embed').length,
    contrast: { checked: checked, worst: worst },
    dpr: devicePixelRatio
  });
})()"#;

/// Horizontal overflow and anything drawn outside the viewport.
const LAYOUT: &str = r#"(function () {
  var d = document.documentElement, outside = [];
  document.querySelectorAll('h1,h2,h3,p,section,table,dl,li,summary').forEach(function (e) {
    var r = e.getBoundingClientRect();
    if (r.width > 0 && (r.right > d.clientWidth + 1 || r.left < -1)) {
      outside.push(e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + (e.className ? '.' + e.className : ''));
    }
  });
  return JSON.stringify({ dpr: devicePixelRatio, css_width: d.clientWidth, scroll_width: d.scrollWidth,
    overflow: d.scrollWidth > d.clientWidth + 1, outside: outside.slice(0, 12) });
})()"#;

/// Where the h1's text sits inside the header's content box, and how table
/// headers align, in the document's current direction.
const DIRECTION: &str = r#"(function () {
  var top = document.querySelector('.top'), h1 = document.querySelector('h1');
  var cs = getComputedStyle(top), box = top.getBoundingClientRect();
  var left = box.left + parseFloat(cs.paddingLeft), right = box.right - parseFloat(cs.paddingRight);
  var range = document.createRange(); range.selectNodeContents(h1);
  var text = range.getBoundingClientRect();
  var d = document.documentElement;
  var aligns = Array.prototype.map.call(document.querySelectorAll('th,caption'), function (e) { return getComputedStyle(e).textAlign; });
  return JSON.stringify({ dir: getComputedStyle(d).direction,
    h1_gap_start: Math.round(getComputedStyle(d).direction === 'rtl' ? right - text.right : text.left - left),
    h1_gap_end: Math.round(getComputedStyle(d).direction === 'rtl' ? text.left - left : right - text.right),
    overflow: d.scrollWidth > d.clientWidth + 1, aligns: aligns });
})()"#;

// ---------------------------------------------------------------------------
// Case 1 (read-only): names, roles, keyboard stops, contrast; UI Automation;
// scaling and right-to-left layout.

fn drive_a11y(window: tauri::WebviewWindow) {
    std::thread::sleep(Duration::from_millis(500));
    let settled = settle(&window);
    println!("SG119-A11Y-SETTLED {settled}");
    std::thread::sleep(Duration::from_millis(400));
    let audit = evaluate(&window, AUDIT).unwrap_or(Value::Null);
    println!("SG119-A11Y-DOM {audit}");
    println!("SG119-A11Y-READY");
    // The parent reads the UI Automation tree now, then says "layout".
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    for (width, height) in [(960.0, 640.0), (480.0, 320.0)] {
        let _ = window.set_size(tauri::LogicalSize::new(width, height));
        for zoom in [1.0, 1.5, 2.0] {
            let _ = window.set_zoom(zoom);
            std::thread::sleep(Duration::from_millis(900));
            let layout = evaluate(&window, LAYOUT).unwrap_or(Value::Null);
            println!("SG119-SCALE size={width}x{height} zoom={zoom} {layout}");
        }
    }
    let _ = window.set_zoom(1.0);
    let _ = window.set_size(tauri::LogicalSize::new(960.0, 640.0));
    std::thread::sleep(Duration::from_millis(600));
    let ltr = evaluate(&window, DIRECTION).unwrap_or(Value::Null);
    let _ = window.eval("document.documentElement.dir = 'rtl';");
    std::thread::sleep(Duration::from_millis(600));
    let rtl = evaluate(&window, DIRECTION).unwrap_or(Value::Null);
    let rtl_layout = evaluate(&window, LAYOUT).unwrap_or(Value::Null);
    let _ = window.eval("document.documentElement.removeAttribute('dir');");
    println!(
        "SG119-RTL {}",
        json!({ "ltr": ltr, "rtl": rtl, "rtl_layout": rtl_layout })
    );
    std::thread::sleep(Duration::from_millis(300));
    if let Err(error) = window.close() {
        eprintln!("close failed: {error}");
    }
}

fn view_accessibility() {
    let mut live = Live::spawn(&mut scenario_command("a11y"));
    let pid = live.pid();
    let audit = json_of(&live.wait("SG119-A11Y-DOM ", Duration::from_secs(90)));
    live.wait("SG119-A11Y-READY", Duration::from_secs(10));
    let orceld_answers = this_users_orceld_answers();

    // The page, as it reports itself.
    assert_eq!(audit["lang"], "en", "{audit}");
    assert_eq!(audit["title"], shell::TITLE, "{audit}");
    assert_eq!(audit["h1"], 1, "{audit}");
    let headings: Vec<&str> = audit["headings"]
        .as_array()
        .expect("headings")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let h2: Vec<&str> = headings
        .iter()
        .filter_map(|heading| heading.strip_prefix("h2 "))
        .collect();
    assert_eq!(headings.first(), Some(&"h1 Orcel Control Room"));
    assert_eq!(
        h2,
        ["orceld", "Capabilities", "Report tasks", "Live events"]
    );
    assert_eq!(audit["status"]["role"], "status");
    assert_eq!(audit["status"]["live"], "polite");
    let connection = audit["status"]["text"].as_str().unwrap_or_default();
    assert!(
        !connection.is_empty() && connection != "Starting",
        "{connection}"
    );
    if !orceld_answers {
        // PR #282: an absent runtime is reported, not invented.
        assert!(
            connection.starts_with("Unavailable: orceld is not running"),
            "{connection}"
        );
        assert_eq!(audit["task_items"], 0, "no task invented: {audit}");
    }
    assert_eq!(audit["acting"], 0, "no acting element: {audit}");
    let stops = audit["stops"].as_array().expect("stops").clone();
    assert!(
        !stops.is_empty(),
        "at least the timeline is a keyboard stop"
    );
    for stop in &stops {
        assert!(
            !stop["name"].as_str().unwrap_or_default().is_empty(),
            "every keyboard stop is named: {stop}"
        );
    }
    assert!(
        stops
            .iter()
            .any(|stop| stop["name"] == "Live events list, scrollable"),
        "{stops:?}"
    );
    let checked = audit["contrast"]["checked"].as_u64().unwrap_or(0);
    let worst = audit["contrast"]["worst"]["ratio"].as_f64().unwrap_or(0.0);
    assert!(checked > 0, "{audit}");
    assert!(
        worst >= 4.5,
        "every visible text meets 4.5:1 in the {} scheme: {audit}",
        audit["scheme"]
    );

    // The same window through UI Automation (read-only).
    let tree = qualify::uia_tree(pid, shell::TITLE, 10_000);
    let elements = tree
        .as_array()
        .expect("the window is found by UI Automation");
    let window = &elements[0];
    assert_eq!(window["ct"], "Window", "{window}");
    assert_eq!(
        window["pid"], pid,
        "the window belongs to the launched process"
    );
    let document = elements
        .iter()
        .position(|element| element["ct"] == "Document" && element["name"] == shell::TITLE)
        .unwrap_or_else(|| panic!("a Document named {:?} in {tree}", shell::TITLE));
    let depth = elements[document]["depth"].as_u64().unwrap_or(0);
    let inside: Vec<&Value> = elements[document + 1..]
        .iter()
        .take_while(|element| element["depth"].as_u64().unwrap_or(0) > depth)
        .collect();
    let named = |kind: &str| -> Vec<String> {
        inside
            .iter()
            .filter(|element| element["lct"] == kind)
            .map(|element| element["name"].as_str().unwrap_or_default().to_owned())
            .collect()
    };
    let uia_headings = named("heading");
    for heading in [
        "Orcel Control Room",
        "orceld",
        "Capabilities",
        "Report tasks",
        "Live events",
    ] {
        assert!(
            uia_headings.iter().any(|name| name == heading),
            "UI Automation heading {heading:?} in {uia_headings:?}"
        );
    }
    assert!(
        inside
            .iter()
            .any(|element| element["name"].as_str() == Some(connection)),
        "the connection line is read as {connection:?}"
    );
    // No edit box and nothing that acts; a Button is admitted only as a
    // disclosure (a task's summary, which expands its details).
    for element in &inside {
        let ct = element["ct"].as_str().unwrap_or_default();
        assert!(
            !matches!(
                ct,
                "Edit"
                    | "Hyperlink"
                    | "CheckBox"
                    | "RadioButton"
                    | "ComboBox"
                    | "MenuItem"
                    | "Slider"
                    | "Spinner"
                    | "SplitButton"
            ),
            "an acting control: {element}"
        );
        if ct == "Button" {
            assert_eq!(
                element["expand"], true,
                "a button that is not a disclosure: {element}"
            );
        }
    }
    // Keyboard stops, in order, named as the page names them.
    let uia_stops: Vec<String> = inside
        .iter()
        .filter(|element| element["focusable"] == true)
        .map(|element| element["name"].as_str().unwrap_or_default().to_owned())
        .collect();
    let page_stops: Vec<String> = stops
        .iter()
        .map(|stop| stop["name"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(
        uia_stops, page_stops,
        "UI Automation's keyboard stops, in order"
    );
    for element in inside.iter().filter(|element| element["ct"] == "Table") {
        assert!(
            !element["name"].as_str().unwrap_or_default().is_empty(),
            "a table is named by its caption: {element}"
        );
    }
    // PR #282: nothing is started beyond WebView2's own processes.
    let procs = qualify::tree(pid);
    for proc in &procs {
        assert!(
            proc.pid == pid || proc.exe.eq_ignore_ascii_case("msedgewebview2.exe"),
            "an unexpected process under the shell: {}",
            proc.exe
        );
    }
    let roles: Vec<String> = inside
        .iter()
        .filter(|element| !element["lct"].as_str().unwrap_or_default().is_empty())
        .map(|element| {
            format!(
                "{}{}",
                element["lct"].as_str().unwrap_or_default(),
                if element["focusable"] == true {
                    "*"
                } else {
                    ""
                }
            )
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    println!(
        "SG119-A11Y uia_elements={} headings={} keyboard_stops={:?} roles={:?} contrast_min={worst} \
         over={checked} scheme={} forced_colors={} processes={}",
        inside.len(),
        uia_headings.len(),
        uia_stops,
        roles,
        audit["scheme"],
        audit["forced_colors"],
        procs.len()
    );

    // Scaling and right-to-left, in the same window.
    live.say("layout");
    let (code, _) = live.finish(Duration::from_secs(90));
    assert_eq!(code, Some(0));
    let scales = live.lines("SG119-SCALE ");
    assert_eq!(scales.len(), 6, "{scales:?}");
    for scale in &scales {
        let (_, layout) = scale.split_at(scale.find('{').expect("a layout"));
        let layout = json_of(layout);
        assert_eq!(layout["overflow"], false, "a horizontal scroll at {scale}");
        assert_eq!(
            layout["outside"].as_array().map(Vec::len),
            Some(0),
            "drawn outside the window at {scale}"
        );
    }
    let rtl = json_of(&live.lines("SG119-RTL ")[0]);
    assert_eq!(rtl["ltr"]["dir"], "ltr", "{rtl}");
    assert_eq!(rtl["rtl"]["dir"], "rtl", "{rtl}");
    for side in ["ltr", "rtl"] {
        let start = rtl[side]["h1_gap_start"].as_i64().unwrap_or(99);
        let end = rtl[side]["h1_gap_end"].as_i64().unwrap_or(0);
        assert!(
            start.abs() <= 2 && end > 50,
            "{side}: the heading starts at the start edge: {rtl}"
        );
        assert_eq!(rtl[side]["overflow"], false, "{side}: {rtl}");
        for align in rtl[side]["aligns"].as_array().into_iter().flatten() {
            assert_eq!(
                align, "start",
                "{side}: table headers align to the start: {rtl}"
            );
        }
    }
    assert_eq!(rtl["rtl_layout"]["overflow"], false, "{rtl}");
    assert_eq!(
        rtl["rtl_layout"]["outside"].as_array().map(Vec::len),
        Some(0),
        "{rtl}"
    );
    assert_no_web_messages(&live);
}

// ---------------------------------------------------------------------------
// Case 2 (read-only): the renderer cannot open a pipe secured as orceld's.

fn renderer_cannot_open_the_pipe() {
    let mut live = Live::spawn(&mut Command::new(SHELL));
    let pid = live.pid();
    let start = Instant::now();
    let hwnd = loop {
        let found = qualify::windows_of(&[pid])
            .into_iter()
            .find(|window| window.visible && window.title == shell::TITLE);
        if let Some(window) = found {
            break window.hwnd;
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "no visible window"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    // Let the page finish loading so its renderer exists.
    std::thread::sleep(Duration::from_millis(1500));
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!(
        r"\\.\pipe\orcel-sg119-a5-{}-{:x}",
        std::process::id(),
        nanos % 0xffff_ffff_ffff
    );
    let pipe = qualify::OrceldStylePipe::create(&name);
    let (lines, probes) = qualify::probe_tree(pid, &name);
    for line in &lines {
        println!("    SG119-PROCESS {line}");
    }
    // Control: this test, at Medium integrity as orceld's clients run, opens
    // the same pipe.
    let control = qualify::open_pipe_as_self(&name);
    drop(pipe);
    // SAFETY: posting WM_CLOSE to the shell's own window.
    assert_ne!(unsafe { PostMessageW(hwnd, WM_CLOSE, 0, 0) }, 0);
    let (code, _) = live.finish(Duration::from_secs(30));
    assert_eq!(code, Some(0));
    assert_eq!(
        control,
        0,
        "the test itself opens the pipe: {}",
        qualify::error_name(control)
    );
    let renderers: Vec<_> = probes
        .iter()
        .filter(|(kind, _, _)| kind == "renderer")
        .collect();
    assert!(
        !renderers.is_empty(),
        "a renderer below Medium integrity was probed: {lines:#?}"
    );
    for (kind, facts, probe) in &probes {
        assert!(
            probe.thread.integrity == facts.integrity && probe.thread.integrity < qualify::MEDIUM,
            "{kind}: the probe ran at the process's own integrity: {lines:#?}"
        );
        assert_eq!(
            probe.open,
            qualify::ACCESS_DENIED,
            "{kind}: opening the pipe under its token is refused: {lines:#?}"
        );
    }
    let (kind, facts, probe) = renderers[0];
    println!(
        "SG119-RENDERER {kind} integrity={} appcontainer={} restricted={} open={}; sandboxed processes \
         probed={} all refused; the test process opened the same pipe",
        qualify::rid_name(facts.integrity),
        facts.app_container,
        facts.restricted,
        qualify::error_name(probe.open),
        probes.len()
    );
}

// ---------------------------------------------------------------------------
// Input (ORCEL_ALLOW_INPUT_TESTS=1 only): keystrokes and a right-click.

mod input {
    use std::time::Duration;
    use windows_sys::Win32::Foundation::POINT;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        MapVirtualKeyW, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT,
        KEYEVENTF_KEYUP, MAPVK_VK_TO_VSC, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEINPUT,
        VK_CONTROL, VK_F12, VK_RETURN, VK_SHIFT, VK_TAB,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowRect, GetWindowThreadProcessId, SetCursorPos,
        SetForegroundWindow, WindowFromPoint,
    };

    pub const CTRL: u16 = VK_CONTROL;
    pub const SHIFT: u16 = VK_SHIFT;
    pub const F12: u16 = VK_F12;
    pub const TAB: u16 = VK_TAB;
    pub const ENTER: u16 = VK_RETURN;
    pub const KEY_I: u16 = 0x49;
    pub const KEY_P: u16 = 0x50;

    fn refuse_without_gate() {
        assert!(
            super::input_allowed(),
            "input is sent only where {}=1",
            super::INPUT_GATE
        );
    }

    /// Refuses unless the test's own window is the foreground window right
    /// now: checked before every injected press and click, so a window that
    /// lost the foreground (to anything) receives nothing more.
    fn still_front(hwnd: isize) -> Result<(), String> {
        refuse_without_gate();
        // SAFETY: a plain query.
        let front = unsafe { GetForegroundWindow() };
        if hwnd != 0 && front == hwnd {
            Ok(())
        } else {
            Err("the test window is no longer the foreground window".into())
        }
    }

    fn key(vk: u16, up: bool) -> INPUT {
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    // SAFETY: a pure table lookup.
                    wScan: unsafe { MapVirtualKeyW(u32::from(vk), MAPVK_VK_TO_VSC) } as u16,
                    dwFlags: if up { KEYEVENTF_KEYUP } else { 0 },
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    fn send_one(input: &INPUT) -> bool {
        refuse_without_gate();
        // SAFETY: one initialised INPUT.
        unsafe { SendInput(1, input, std::mem::size_of::<INPUT>() as i32) == 1 }
    }

    /// Presses `keys` in order, each only while `hwnd` is the foreground
    /// window, then releases what was pressed in reverse. A release is sent
    /// even after a failed check, so no key stays held down on the runner.
    pub fn chord(hwnd: isize, keys: &[u16]) -> Result<(), String> {
        let mut pressed = Vec::new();
        let mut outcome = Ok(());
        for vk in keys {
            if let Err(error) = still_front(hwnd) {
                outcome = Err(error);
                break;
            }
            if !send_one(&key(*vk, false)) {
                outcome = Err("SendInput did not send a key press".into());
                break;
            }
            pressed.push(*vk);
        }
        for vk in pressed.iter().rev() {
            send_one(&key(*vk, true));
        }
        outcome
    }

    /// A right-click two thirds down the middle of `hwnd` (inside the page),
    /// only while `hwnd` is the foreground window and the window under that
    /// point belongs to this process's tree (the shell and its WebView2).
    pub fn right_click(hwnd: isize) -> Result<(), String> {
        still_front(hwnd)?;
        // SAFETY: a plain query on the test's own window.
        let mut rect = unsafe { std::mem::zeroed() };
        if unsafe { GetWindowRect(hwnd, &mut rect) } == 0 {
            return Err("the window's rectangle is unreadable".into());
        }
        let point = POINT {
            x: (rect.left + rect.right) / 2,
            y: rect.top + (rect.bottom - rect.top) * 2 / 3,
        };
        // SAFETY: plain queries.
        let under = unsafe { WindowFromPoint(point) };
        let mut owner = 0u32;
        unsafe { GetWindowThreadProcessId(under, &mut owner) };
        let tree: Vec<u32> = super::qualify::tree(std::process::id())
            .iter()
            .map(|proc| proc.pid)
            .collect();
        if under == 0 || !tree.contains(&owner) {
            return Err("the window under the click point is not the shell's".into());
        }
        still_front(hwnd)?;
        // SAFETY: moves the cursor of a disposable runner.
        if unsafe { SetCursorPos(point.x, point.y) } == 0 {
            return Err("SetCursorPos failed".into());
        }
        std::thread::sleep(Duration::from_millis(200));
        let mouse = |flags| INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx: 0,
                    dy: 0,
                    mouseData: 0,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        still_front(hwnd)?;
        if !send_one(&mouse(MOUSEEVENTF_RIGHTDOWN)) {
            return Err("SendInput did not send the right button press".into());
        }
        // The release follows the press whatever happens, so no button stays
        // held down on the runner.
        send_one(&mouse(MOUSEEVENTF_RIGHTUP));
        Ok(())
    }

    /// Brings `window` to the foreground and the web view to keyboard focus,
    /// with no injected input: only Tauri's `set_focus` and
    /// `SetForegroundWindow` on the test's own window. False when it cannot
    /// take the foreground.
    pub fn focus(window: &tauri::WebviewWindow) -> bool {
        refuse_without_gate();
        let hwnd = window.hwnd().map(|hwnd| hwnd.0 as isize).unwrap_or(0);
        let front = || hwnd != 0 && unsafe { GetForegroundWindow() } == hwnd;
        let _ = window.set_focus();
        for attempt in 0..40 {
            if front() {
                break;
            }
            if attempt == 10 {
                // SAFETY: the test's own window.
                unsafe { SetForegroundWindow(hwnd) };
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if !front() {
            return false;
        }
        let _ = window.with_webview(|webview| {
            use webview2_com::Microsoft::Web::WebView2::Win32::COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC;
            // SAFETY: a COM call on the web view's own thread.
            let _ = unsafe {
                webview
                    .controller()
                    .MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC)
            };
        });
        front()
    }
}

/// Ends an input scenario that may not go on: reports why and closes the
/// window, so nothing more is sent.
fn abort(window: &tauri::WebviewWindow, reason: &str) {
    println!("SG119-INPUT-ERROR {reason}");
    let _ = window.close();
}

/// Records what reaches the page: each keydown, context menu and print event.
const RECORDER: &str = r#"(function () {
  var r = window.__sg119Input = { keydown: [], contextmenu: 0, beforeprint: 0 };
  addEventListener('keydown', function (e) {
    r.keydown.push((e.ctrlKey ? 'Ctrl+' : '') + (e.shiftKey ? 'Shift+' : '') + (e.key.length === 1 ? e.key.toUpperCase() : e.key));
  }, true);
  addEventListener('contextmenu', function () { r.contextmenu++; }, true);
  addEventListener('beforeprint', function () { r.beforeprint++; });
  return JSON.stringify(true);
})()"#;

const STATE: &str = r#"JSON.stringify({ input: window.__sg119Input || null, focused: document.hasFocus(), url: location.href })"#;

/// Takes the foreground and focuses the page; on failure reports it, closes
/// the window and answers false, so no keystroke is sent to another window.
fn focus_or_close(window: &tauri::WebviewWindow) -> bool {
    if !input::focus(window) {
        abort(window, "the test window could not take the foreground");
        return false;
    }
    let focused = evaluate_until(window, STATE, Duration::from_secs(5), |state| {
        state["focused"] == true
    });
    println!("SG119-INPUT-FOCUS {focused}");
    if focused["focused"] != true {
        abort(window, "the page did not take keyboard focus");
        return false;
    }
    true
}

fn drive_keys(window: tauri::WebviewWindow) {
    std::thread::sleep(Duration::from_millis(500));
    settle(&window);
    let _ = evaluate(&window, RECORDER);
    if !focus_or_close(&window) {
        return;
    }
    let pid = std::process::id();
    let hwnd = window.hwnd().map(|hwnd| hwnd.0 as isize).unwrap_or(0);
    let steps: [(&str, &[u16]); 3] = [
        ("F12", &[input::F12]),
        ("Ctrl+Shift+I", &[input::CTRL, input::SHIFT, input::KEY_I]),
        ("Ctrl+P", &[input::CTRL, input::KEY_P]),
    ];
    let mut results = Vec::new();
    for (label, keys) in steps {
        if let Err(reason) = input::chord(hwnd, keys) {
            return abort(&window, &reason);
        }
        std::thread::sleep(Duration::from_millis(2000));
        let state = evaluate(&window, STATE).unwrap_or(Value::Null);
        results.push(
            json!({ "step": label, "windows": qualify::visible_windows(pid), "state": state }),
        );
    }
    if let Err(reason) = input::right_click(hwnd) {
        return abort(&window, &reason);
    }
    std::thread::sleep(Duration::from_millis(2000));
    let state = evaluate(&window, STATE).unwrap_or(Value::Null);
    results.push(
        json!({ "step": "right-click", "windows": qualify::visible_windows(pid), "state": state }),
    );
    println!("SG119-KEYS {}", Value::Array(results));
    let _ = window.close();
}

fn browser_keys_do_nothing() {
    let mut live = Live::spawn(&mut scenario_command("keys"));
    let (code, _) = live.finish(Duration::from_secs(120));
    assert!(
        live.lines("SG119-INPUT-ERROR").is_empty(),
        "{:?}",
        live.seen
    );
    assert_eq!(code, Some(0));
    let keys = live.lines("SG119-KEYS ");
    assert_eq!(keys.len(), 1, "{:?}", live.seen);
    let steps = json_of(&keys[0]);
    let steps = steps.as_array().expect("steps");
    assert_eq!(steps.len(), 4);
    for step in steps {
        let windows = step["windows"].as_array().map(Vec::len).unwrap_or(0);
        assert_eq!(
            windows, 1,
            "{}: no devtools, print dialog, context menu or other window: {step}",
            step["step"]
        );
        assert_eq!(
            step["state"]["url"], "https://tauri.localhost/index.html",
            "{}: the page stayed: {step}",
            step["step"]
        );
        assert_eq!(step["state"]["input"]["beforeprint"], 0, "no print: {step}");
    }
    let last = &steps[3]["state"]["input"];
    let pressed: Vec<&str> = last["keydown"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    // The keys reached the page (so "nothing happened" is not a missed key).
    for wanted in ["F12", "Ctrl+Shift+I", "Ctrl+P"] {
        assert!(
            pressed.contains(&wanted),
            "{wanted} reached the page: {pressed:?}"
        );
    }
    assert!(
        last["contextmenu"].as_u64().unwrap_or(0) >= 1,
        "the right-click reached the page: {last}"
    );
    assert_eq!(
        live.lines("SG119-NEWWINDOW "),
        ["requests=0 denied=0"],
        "no new window was even requested"
    );
    assert_eq!(live.lines("SG119-NAV "), ["refused=0"]);
    assert_no_web_messages(&live);
    println!(
        "SG119-HARDENING F12, Ctrl+Shift+I, Ctrl+P and a right-click reached the page ({pressed:?}, \
         contextmenu={}) and opened no devtools, print dialog, context menu or window",
        last["contextmenu"]
    );
}

/// The keyboard stops in order, and where focus is now.
const FOCUS: &str = r#"(function () {
  function id(e) { return e ? (e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + (e.getAttribute('data-task') ? '[' + e.getAttribute('data-task') + ']' : '')) : null; }
  var a = document.activeElement, cs = a ? getComputedStyle(a) : null;
  var stops = Array.prototype.filter.call(document.querySelectorAll('summary,[tabindex]'), function (e) {
    var t = e.getAttribute('tabindex');
    return !e.closest('[hidden]') && e.getClientRects().length > 0 && !(t !== null && Number(t) < 0);
  }).map(id);
  return JSON.stringify({ stops: stops, active: id(a), visible: a ? a.matches(':focus-visible') : false,
    outline: cs ? cs.outlineStyle + ' ' + cs.outlineWidth : '',
    open: Array.prototype.map.call(document.querySelectorAll('details[open]'), function (d) { return d.getAttribute('data-task'); }) });
})()"#;

fn drive_tabs(window: tauri::WebviewWindow) {
    std::thread::sleep(Duration::from_millis(500));
    settle(&window);
    std::thread::sleep(Duration::from_millis(500));
    if !focus_or_close(&window) {
        return;
    }
    let hwnd = window.hwnd().map(|hwnd| hwnd.0 as isize).unwrap_or(0);
    let first = evaluate(&window, FOCUS).unwrap_or(Value::Null);
    let count = first["stops"].as_array().map(Vec::len).unwrap_or(0);
    let mut forward = Vec::new();
    for _ in 0..count {
        if let Err(reason) = input::chord(hwnd, &[input::TAB]) {
            return abort(&window, &reason);
        }
        std::thread::sleep(Duration::from_millis(400));
        forward.push(evaluate(&window, FOCUS).unwrap_or(Value::Null));
    }
    let mut backward = Vec::new();
    for _ in 1..count {
        if let Err(reason) = input::chord(hwnd, &[input::SHIFT, input::TAB]) {
            return abort(&window, &reason);
        }
        std::thread::sleep(Duration::from_millis(400));
        backward.push(evaluate(&window, FOCUS).unwrap_or(Value::Null));
    }
    // On a task's summary, Enter opens its details (with an orceld that
    // reports tasks; a CI runner has none).
    let mut opened = Value::Null;
    let at = evaluate(&window, FOCUS).unwrap_or(Value::Null);
    if at["active"]
        .as_str()
        .is_some_and(|id| id.starts_with("summary"))
    {
        if let Err(reason) = input::chord(hwnd, &[input::ENTER]) {
            return abort(&window, &reason);
        }
        std::thread::sleep(Duration::from_millis(600));
        opened = evaluate(&window, FOCUS).unwrap_or(Value::Null);
    }
    println!(
        "SG119-TABS {}",
        json!({ "first": first, "forward": forward, "backward": backward, "opened": opened })
    );
    let _ = window.close();
}

fn keyboard_order() {
    let mut live = Live::spawn(&mut scenario_command("tabs"));
    let (code, _) = live.finish(Duration::from_secs(120));
    assert!(
        live.lines("SG119-INPUT-ERROR").is_empty(),
        "{:?}",
        live.seen
    );
    assert_eq!(code, Some(0));
    let tabs = json_of(&live.lines("SG119-TABS ")[0]);
    let stops: Vec<Value> = tabs["first"]["stops"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!stops.is_empty(), "{tabs}");
    let forward: Vec<Value> = tabs["forward"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|step| step["active"].clone())
        .collect();
    assert_eq!(
        forward, stops,
        "Tab visits every stop in document order: {tabs}"
    );
    for step in tabs["forward"].as_array().into_iter().flatten() {
        assert_eq!(step["visible"], true, "a visible focus indicator: {step}");
        assert!(
            step["outline"]
                .as_str()
                .is_some_and(|outline| outline.starts_with("solid 2px")),
            "a 2px focus ring: {step}"
        );
    }
    let mut back: Vec<Value> = tabs["backward"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|step| step["active"].clone())
        .collect();
    back.reverse();
    assert_eq!(
        back,
        stops[..stops.len() - 1],
        "Shift+Tab walks back: {tabs}"
    );
    if !tabs["opened"].is_null() {
        assert!(
            tabs["opened"]["open"]
                .as_array()
                .is_some_and(|open| !open.is_empty()),
            "Enter on a summary opens its details: {tabs}"
        );
    }
    assert_no_web_messages(&live);
    println!(
        "SG119-KEYBOARD Tab reached {} stop(s) in order with a 2px focus ring, Shift+Tab walked back{}",
        stops.len(),
        if tabs["opened"].is_null() { "" } else { ", Enter opened a task's details" }
    );
}
