//! SG-000119 A3 native Windows test: the real shell window against a live
//! orceld, through the five commands.
//!
//! **Opt-in.** It runs only when `SG119_LIVE_ORCELD` names an `orceld.exe`
//! built from the same branch; otherwise it reports itself ignored (the
//! `control-room-shell` CI job builds no orceld). The shell has no endpoint
//! override by design, so this test starts that orceld on this user's real
//! endpoint, `\\.\pipe\orcel-<SID>-app`, with its own workspace, audit file
//! and state root (`USERPROFILE` pointed at a sandbox), and refuses to go on
//! unless orceld logs that it listens there (so no other orceld of this user
//! is answering). It creates one report task through orceld's stdio channel
//! (observe only: nothing reaches orceld's approval broker, so no dialog can
//! appear), then runs the real shell (this test binary with
//! `--sg119-scenario live`, the same `run` as the shell binary plus an
//! after-show hook). No founder interaction: the window is opened and closed
//! programmatically.
//!
//! The scenario evaluates a script from Rust (nothing is added to the page)
//! that calls the five commands as the page would, an unknown command, a
//! core command and malformed arguments, subscribes twice, reads status
//! again, and stores what came back; Rust reads it back and prints one
//! `SG119-LIVE` line, then `window.open` is tried and the window is closed.
//! The parent checks every answer is the sanitiser's shape (no pid, no SID,
//! no title, workspace-relative paths only), that the second subscription
//! replaced the first (orceld counts two clients: one subscription and the
//! status request), that the window's close released orceld's slots, and the
//! exit report's `SG119-IPC commands=<n> web_messages=0` with `n` the served
//! calls.

use orcel_app_api_client::AppApiClient;
use orcel_control_room_shell::{run, Hooks};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SCENARIO: &str = "--sg119-scenario";
const TITLE: &str = "Q3 revenue for the board";
const Q3_CSV: &str = "region,quarter,revenue_cents\nnorth,Q3,1250000\nsouth,Q3,980050\n";
/// Served command calls the scenario's script makes before it polls status
/// (the unknown and core commands are refused by the ACL and never reach a
/// handler); each status poll adds one.
const SERVED_BEFORE_POLLS: u64 = 8;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(at) = args.iter().position(|arg| arg == SCENARIO) {
        let code = match (args.get(at + 1).map(String::as_str), args.get(at + 2)) {
            (Some("live"), Some(task_id)) => scenario_live(task_id.clone()),
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
    let name = "the_shell_reads_a_live_orceld_through_the_five_commands";
    let Some(orceld) = std::env::var_os("SG119_LIVE_ORCELD") else {
        println!("test {name} ... ignored (set SG119_LIVE_ORCELD to an orceld.exe built from this branch)");
        println!("test result: ok. 0 passed; 0 failed; 1 ignored");
        return;
    };
    println!("test {name} ...");
    match std::panic::catch_unwind(|| live(PathBuf::from(orceld))) {
        Ok(()) => {
            println!("test {name} ... ok");
            println!("test result: ok. 1 passed; 0 failed");
        }
        Err(_) => {
            println!("test {name} ... FAILED");
            println!("test result: FAILED. 0 passed; 1 failed");
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// The live orceld

struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "a3l-{}-{:x}",
            std::process::id(),
            nanos % 0xff_ffff_ffff
        ));
        for dir in ["h", "a", "ws/data", "ws/reports"] {
            std::fs::create_dir_all(base.join(dir)).expect("sandbox dir");
        }
        std::fs::write(base.join("ws").join("data").join("q3.csv"), Q3_CSV).unwrap();
        Self(base)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Orceld {
    child: Child,
    replies: Receiver<String>,
    logs: Receiver<String>,
    _sandbox: Sandbox,
}

impl Drop for Orceld {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn lines_of(source: impl Read + Send + 'static) -> Receiver<String> {
    let (sender, receiver) = channel();
    std::thread::spawn(move || {
        for line in BufReader::new(source).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    receiver
}

fn wait_line(lines: &Receiver<String>, needle: &str, what: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut seen = Vec::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match lines.recv_timeout(left) {
            Ok(line) if line.contains(needle) => return line,
            Ok(line) => seen.push(line),
            Err(_) => break,
        }
    }
    panic!(
        "{what}: never saw {needle:?}; saw {}",
        redact(&format!("{seen:?}"))
    );
}

/// `text` with this user's SID replaced by `<SID>`: orceld's logs name its
/// endpoint, which carries the SID, and test output must not.
fn redact(text: &str) -> String {
    match orcel_app_api_client::this_user_sid() {
        Ok(sid) if !sid.is_empty() => text.replace(&sid, "<SID>"),
        _ => text.to_owned(),
    }
}

fn start_orceld(binary: PathBuf) -> Orceld {
    let sandbox = Sandbox::new();
    let mut command = Command::new(binary);
    command
        .env("ORCEL_WORKSPACE_ROOT", sandbox.0.join("ws"))
        .env("ORCEL_WORKSPACE_ID", "default")
        .env("ORCEL_AUDIT_PATH", sandbox.0.join("a").join("audit.jsonl"))
        .env("USERPROFILE", sandbox.0.join("h"))
        .env_remove("ORCEL_APP_API_INSTANCE")
        .env_remove("ORCEL_APP_API")
        .env_remove("ORCEL_WORKSPACES_JSON")
        .env_remove("ORCEL_MCP_TRANSPORT")
        .env_remove("ORCEL_REPORT_JOURNAL_PATH")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn orceld");
    let replies = lines_of(child.stdout.take().unwrap());
    let logs = lines_of(child.stderr.take().unwrap());
    Orceld {
        child,
        replies,
        logs,
        _sandbox: sandbox,
    }
}

impl Orceld {
    fn start_report(&mut self) -> String {
        let envelope = json!({
            "version": 1, "request_id": "a3-start", "client_session_id": "a3",
            "workspace_id": "default", "capability": "report", "operation": "start",
            "target": null,
            "arguments": { "title": TITLE, "sources": ["data/q3.csv"], "folder": "reports" },
        });
        let stdin = self.child.stdin.as_mut().expect("orceld stdin");
        writeln!(stdin, "{envelope}").unwrap();
        stdin.flush().unwrap();
        let reply: Value =
            serde_json::from_str(&wait_line(&self.replies, "a3-start", "orceld's reply")).unwrap();
        assert_eq!(reply["ok"], true, "{reply}");
        reply["result"]["task_id"].as_str().unwrap().to_owned()
    }
}

// ---------------------------------------------------------------------------
// The parent

struct Finished {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn finish(mut child: Child, limit: Duration) -> Finished {
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = out.read_to_string(&mut text);
        text
    });
    let err = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = err.read_to_string(&mut text);
        text
    });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let finished = Finished {
        code: status.and_then(|status| status.code()),
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    };
    println!("--- live scenario: exit {:?}", finished.code);
    for line in finished.stdout.lines().chain(finished.stderr.lines()) {
        let shown: String = line.chars().take(400).collect();
        println!("    {shown}");
    }
    assert!(
        status.is_some(),
        "the scenario did not exit within {limit:?}"
    );
    finished
}

fn line<'a>(finished: &'a Finished, prefix: &str) -> &'a str {
    let lines: Vec<&str> = finished
        .stdout
        .lines()
        .filter(|line| line.starts_with(prefix))
        .collect();
    assert_eq!(lines.len(), 1, "one {prefix} line expected");
    &lines[0][prefix.len()..]
}

fn shown<'a>(value: &'a Value, what: &str) -> &'a Value {
    assert_eq!(value["state"], "shown", "{what}: {value}");
    &value["value"]
}

fn live(binary: PathBuf) {
    let sid = orcel_app_api_client::this_user_sid().expect("this user's SID");
    let endpoint = format!(r"\\.\pipe\orcel-{sid}-app");
    let mut orceld = start_orceld(binary);
    let listening = wait_line(
        &orceld.logs,
        "orceld app api: listening on ",
        "orceld on this user's endpoint",
    );
    assert!(
        listening.trim_end().ends_with(&endpoint),
        "orceld must listen on this user's real endpoint, which the shell alone can reach: {}",
        redact(&listening)
    );
    let task_id = orceld.start_report();
    println!("    orceld listens on this user's endpoint; report task {task_id} observed");

    // The parent's own view through the A1 client: one client (itself).
    let client = AppApiClient::for_this_user().expect("client");
    let before = client.status().expect("status before the shell");
    assert_eq!(before.clients.shown().unwrap().active, 1);

    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args([SCENARIO, "live", &task_id]);
    for (name, _) in std::env::vars_os() {
        if orcel_control_room_shell::environment::names_webview2(&name) {
            command.env_remove(name);
        }
    }
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the live scenario");
    let finished = finish(child, Duration::from_secs(180));
    assert_eq!(finished.code, Some(0), "{}", finished.stderr);

    let results: Value = serde_json::from_str(line(&finished, "SG119-LIVE ")).expect("results");
    let text = results.to_string();
    // Nothing orceld must not show reached the page.
    assert!(!text.contains(&sid), "the SID reached the page");
    assert!(!text.contains(TITLE), "the task title reached the page");
    assert!(
        !text.contains("\"title\""),
        "a title field reached the page"
    );
    assert!(!text.contains("\"pid\""), "a pid field reached the page");
    assert!(
        !text.contains("\"endpoint\""),
        "the endpoint reached the page"
    );
    assert!(
        !text.contains("\"methods\""),
        "the method list reached the page"
    );
    assert!(
        !text.contains("q3.csv\\n") && !text.contains("1250000"),
        "source content reached the page"
    );

    let status = &results["status"]["ok"];
    assert_eq!(shown(&status["app_api"], "app_api"), "orcel-app-api/1");
    assert_eq!(shown(&status["os"], "os"), "windows");
    assert_eq!(shown(&status["mode"], "mode"), "SG-000039_CLIPBOARD_WRITE");

    let capabilities = &results["capabilities"]["ok"];
    let rows = capabilities["capabilities"]
        .as_array()
        .expect("capability rows");
    assert!(!rows.is_empty());
    assert!(rows
        .iter()
        .all(|row| row["state"] == "available" || row["state"] == "unavailable"));

    let tasks = results["tasks"]["ok"]["tasks"].as_array().expect("tasks");
    assert!(
        tasks.iter().any(|task| task["task_id"] == task_id.as_str()),
        "{tasks:?}"
    );

    let task = &results["task"]["ok"];
    assert_eq!(task["task_id"], task_id.as_str());
    assert_eq!(task["kind"], "report");
    assert_eq!(shown(&task["folder"], "folder"), "reports");
    assert_eq!(
        shown(&task["sources"][0]["path"], "source path"),
        "data/q3.csv"
    );
    let sha = shown(&task["sources"][0]["sha256"], "source hash")
        .as_str()
        .unwrap();
    assert!(
        sha.len() == 64
            && sha
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );

    assert_eq!(
        results["bad_task"]["err"],
        json!({ "error": "invalid_task_id" })
    );
    assert_eq!(
        results["extra"]["err"],
        json!({ "error": "invalid_arguments" })
    );
    for refused in ["unknown", "plugin"] {
        let message = results[refused]["err"].as_str().unwrap_or_default();
        assert!(
            message.contains("not allowed"),
            "{refused}: {}",
            results[refused]
        );
    }

    assert_eq!(results["events1"], json!({ "ok": null }));
    assert_eq!(results["events2"], json!({ "ok": null }));
    let first = results["first"].as_array().expect("first channel");
    let second = results["second"].as_array().expect("second channel");
    assert!(
        first.iter().any(|item| item["type"] == "event"),
        "the first subscription delivered events: {first:?}"
    );
    assert_eq!(
        first.last(),
        Some(&json!({ "type": "ended" })),
        "the first channel ended"
    );
    assert!(
        second.iter().any(|item| item["type"] == "event"),
        "the second subscription delivered events: {second:?}"
    );
    assert!(!second.contains(&json!({ "type": "ended" })));
    // One subscription and the status request itself: two of orceld's
    // client slots. orceld notices a closed subscription connection only when
    // it next writes to it (its 15 s heartbeat at the latest), so the script
    // polls status until orceld counts two; the replaced subscription's slot
    // may still be counted at first, so never more than three.
    let actives: Vec<u64> = results["actives"]
        .as_array()
        .expect("status polls")
        .iter()
        .map(|active| active.as_u64().expect("an active count"))
        .collect();
    assert_eq!(actives.last(), Some(&2), "orceld's clients: {actives:?}");
    assert!(actives.iter().all(|active| *active <= 3), "{actives:?}");
    let served = SERVED_BEFORE_POLLS + actives.len() as u64;

    // window.open from the page opened nothing.
    assert_eq!(line(&finished, "SG119-NEWWINDOW "), "requests=1 denied=1");
    // Every served call went through the custom protocol; no web message.
    // Not counted: Tauri's own `plugin:__TAURI_CHANNEL__|fetch`, which the
    // page's channel uses to collect a channel message of 8 KiB or more.
    // Tauri 2.12.5 exempts it from the ACL (a hard-coded check in
    // `Webview::on_message`) and it only reads back Tauri's own buffer of
    // messages the shell already sent on that channel; it reaches no
    // command handler and nothing in orceld.
    assert_eq!(
        line(&finished, "SG119-IPC "),
        format!("commands={served} web_messages=0")
    );
    let version = line(&finished, "SG119-WEBVIEW2 version=").to_owned();

    // The window's close ended the subscription: orceld counts only the
    // parent's own request again (after its next heartbeat at the latest).
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        let active = client.status().unwrap().clients.shown().unwrap().active;
        if active == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "orceld still counts {active} clients"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    println!(
        "SG119-EVIDENCE A3 shell on windows (WebView2 {version}): app_status, app_capabilities, \
         app_events, app_tasks and app_task answered from a live orceld on this user's endpoint \
         through the real window, sanitised (no pid, SID, title or content; report task {task_id} \
         as metadata), unknown and core commands refused by the ACL, malformed arguments refused \
         typed, a second app_events replaced the first (orceld clients {actives:?}), \
         window.open denied, the close released orceld's slots, SG119-IPC \
         commands={served} web_messages=0"
    );
}

// ---------------------------------------------------------------------------
// The scenario (in a child process): the real shell plus an after-show hook

fn scenario_live(task_id: String) -> i32 {
    run(Hooks {
        after_apply: None,
        after_show: Some(Box::new(move |window| {
            std::thread::spawn(move || drive(window, task_id));
        })),
    })
}

/// The page-side calls, as the page itself would make them, evaluated from
/// Rust; the answers are kept in a page variable that Rust reads back.
const SCRIPT: &str = r#"(async function () {
  var core = window.__TAURI__.core;
  var out = { first: [], second: [] };
  function grab(name, promise) {
    return promise.then(function (v) { out[name] = { ok: v === undefined ? null : v }; },
                        function (e) { out[name] = { err: e }; });
  }
  function pause(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  await grab('status', core.invoke('app_status'));
  await grab('capabilities', core.invoke('app_capabilities'));
  await grab('tasks', core.invoke('app_tasks'));
  await grab('task', core.invoke('app_task', { task_id: TASK_ID }));
  await grab('bad_task', core.invoke('app_task', { task_id: '../x' }));
  await grab('extra', core.invoke('app_status', { method: 'task.stop' }));
  await grab('unknown', core.invoke('task_stop', { task_id: TASK_ID }));
  await grab('plugin', core.invoke('plugin:event|listen', { event: 'x', target: { kind: 'Any' }, handler: 1 }));
  var first = new core.Channel();
  first.onmessage = function (m) { out.first.push(m); };
  await grab('events1', core.invoke('app_events', { channel: first }));
  await pause(2000);
  var second = new core.Channel();
  second.onmessage = function (m) { out.second.push(m); };
  await grab('events2', core.invoke('app_events', { channel: second }));
  await pause(2000);
  out.actives = [];
  var deadline = Date.now() + 40000;
  while (true) {
    await grab('status_after', core.invoke('app_status'));
    var clients = out.status_after.ok ? out.status_after.ok.clients : null;
    var active = clients && clients.state === 'shown' ? clients.value.active : -1;
    out.actives.push(active);
    if (active === 2 || Date.now() > deadline) { break; }
    await pause(1000);
  }
  window.__sg119Live = out;
})();"#;

fn drive(window: tauri::WebviewWindow, task_id: String) {
    std::thread::sleep(Duration::from_millis(800));
    let script = SCRIPT.replace("TASK_ID", &json!(task_id).to_string());
    if let Err(error) = window.eval(script) {
        eprintln!("eval failed: {error}");
    }
    let deadline = Instant::now() + Duration::from_secs(90);
    let results = loop {
        let (sender, receiver) = channel();
        let _ = window.eval_with_callback(
            "JSON.stringify(window.__sg119Live || null)",
            move |answer| {
                let _ = sender.send(answer);
            },
        );
        if let Ok(answer) = receiver.recv_timeout(Duration::from_secs(5)) {
            // The callback gets the evaluated value as JSON: here a string
            // holding JSON.
            let inner = serde_json::from_str::<Value>(&answer)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned));
            if let Some(results) = inner.filter(|text| text != "null") {
                break results;
            }
        }
        if Instant::now() > deadline {
            eprintln!("the page's calls did not finish");
            break "null".to_owned();
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    println!("SG119-LIVE {results}");
    if let Err(error) = window.eval("window.open('https://tauri.localhost/index.html');") {
        eprintln!("eval failed: {error}");
    }
    std::thread::sleep(Duration::from_millis(1500));
    // Programmatic close, as WM_CLOSE would: the subscription ends with the
    // window and the shell exits with its report.
    if let Err(error) = window.close() {
        eprintln!("close failed: {error}");
    }
}
