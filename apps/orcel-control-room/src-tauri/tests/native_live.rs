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
//! exit report's `SG119-IPC commands=<n> web_messages=0` with `n` at least
//! the served calls (SG-000119 A4: the view itself also reads orceld when it
//! loads, and its task list again as task events arrive).
//!
//! **SG-000119 A4, the view.** A second test runs the real shell with only an
//! after-show hook that reads the page's text back (evaluated from Rust,
//! nothing added to the page) and opens one task's details as a user would
//! (a click on its summary). It checks that the view renders the five data
//! sources from the live orceld (status, capabilities and the device list,
//! the task list, the task's detail, live events) as text, with no title, no
//! SID and no element that acts; then the parent stops orceld mid-session,
//! the view must say orceld is unavailable (and show no status as live), and
//! after the parent starts orceld again in the same sandbox the view must
//! recover from orceld's snapshot. The window is closed programmatically and
//! its exit report must show `web_messages=0`.
//!
//! **SG-000119 A5.** A third test runs the real shell binary (no hook)
//! against the live orceld with a report task, reads its UI Automation tree
//! (read-only: no keystroke, click or focus change) until the task's summary
//! is a named keyboard stop with an expand pattern, then opens orceld's real
//! pipe under the token of each WebView2 process below Medium integrity
//! (the renderer among them): each open must be refused, while this test, at
//! Medium as orceld's clients run, reads status through the A1 client. The
//! pipe's name carries this user's SID and is never printed.

#[path = "support/qualify.rs"]
mod qualify;

use orcel_app_api_client::AppApiClient;
use orcel_control_room_shell::{run, Hooks};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SCENARIO: &str = "--sg119-scenario";
/// One live test: given the orceld binary, panics on failure.
type LiveTest = fn(PathBuf);
const TITLE: &str = "Q3 revenue for the board";
const Q3_CSV: &str = "region,quarter,revenue_cents\nnorth,Q3,1250000\nsouth,Q3,980050\n";
/// Served command calls the scenario's script makes before it polls status
/// (the unknown and core commands are refused by the ACL and never reach a
/// handler); each status poll adds one.
const SERVED_BEFORE_POLLS: u64 = 8;
/// SG-000119 A4: the view's own calls when it loads (app_status,
/// app_capabilities, app_tasks, app_events). It may also read the task list
/// again as task events arrive, so the exit report counts at least these.
const PAGE_CALLS: u64 = 4;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(at) = args.iter().position(|arg| arg == SCENARIO) {
        let code = match (args.get(at + 1).map(String::as_str), args.get(at + 2)) {
            (Some("live"), Some(task_id)) => scenario_live(task_id.clone()),
            (Some("view"), Some(task_id)) => scenario_view(task_id.clone()),
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
    let tests: [(&str, LiveTest); 3] = [
        (
            "the_shell_reads_a_live_orceld_through_the_five_commands",
            live,
        ),
        (
            "the_view_renders_a_live_orceld_and_recovers_after_it_restarts",
            live_view,
        ),
        (
            "the_renderer_cannot_open_a_live_orcelds_pipe_and_tasks_read_well",
            live_renderer_and_tasks,
        ),
    ];
    let Some(orceld) = std::env::var_os("SG119_LIVE_ORCELD") else {
        for (name, _) in tests {
            println!("test {name} ... ignored (set SG119_LIVE_ORCELD to an orceld.exe built from this branch)");
        }
        println!(
            "test result: ok. 0 passed; 0 failed; {} ignored",
            tests.len()
        );
        return;
    };
    let (mut passed, mut failed) = (0, 0);
    for (name, test) in tests {
        println!("test {name} ...");
        let binary = PathBuf::from(&orceld);
        match std::panic::catch_unwind(move || test(binary)) {
            Ok(()) => {
                println!("test {name} ... ok");
                passed += 1;
            }
            Err(_) => {
                println!("test {name} ... FAILED");
                failed += 1;
            }
        }
    }
    if failed > 0 {
        println!("test result: FAILED. {passed} passed; {failed} failed");
        std::process::exit(1);
    }
    println!("test result: ok. {passed} passed; 0 failed");
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
        std::fs::create_dir_all(&base).expect("sandbox dir");
        make_private(&base);
        for dir in ["h", "a", "ws/data", "ws/reports"] {
            std::fs::create_dir_all(base.join(dir)).expect("sandbox dir");
        }
        std::fs::write(base.join("ws").join("data").join("q3.csv"), Q3_CSV).unwrap();
        Self(base)
    }
}

/// orceld refuses an audit or state location another account can reach. The
/// temp folder may inherit a grant to another account (a sandbox group, say),
/// so the sandbox drops inherited entries and grants only this user and
/// SYSTEM, which its folders then inherit. Only the test's own folder changes.
fn make_private(base: &std::path::Path) {
    let sid = orcel_app_api_client::this_user_sid().expect("this user's SID");
    let status = Command::new("icacls")
        .arg(base)
        .args(["/inheritance:r", "/grant:r"])
        .arg(format!("*{sid}:(OI)(CI)F"))
        .args(["/grant:r", "*S-1-5-18:(OI)(CI)F", "/Q"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run icacls on the sandbox");
    assert!(status.success(), "the sandbox could not be made private");
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
    binary: PathBuf,
    sandbox: Sandbox,
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
    let (child, replies, logs) = spawn_orceld(&binary, &sandbox);
    Orceld {
        child,
        replies,
        logs,
        binary,
        sandbox,
    }
}

fn spawn_orceld(
    binary: &PathBuf,
    sandbox: &Sandbox,
) -> (Child, Receiver<String>, Receiver<String>) {
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
    (child, replies, logs)
}

impl Orceld {
    /// Stops this orceld (as a crash would: the process is terminated).
    fn stop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Starts orceld again in the same sandbox, on the same endpoint.
    fn restart(&mut self) {
        let (child, replies, logs) = spawn_orceld(&self.binary, &self.sandbox);
        self.child = child;
        self.replies = replies;
        self.logs = logs;
    }

    /// Waits until this orceld logs that it listens on this user's endpoint.
    fn wait_listening(&self, endpoint: &str) {
        let listening = wait_line(
            &self.logs,
            "orceld app api: listening on ",
            "orceld on this user's endpoint",
        );
        assert!(
            listening.trim_end().ends_with(endpoint),
            "orceld must listen on this user's real endpoint, which the shell alone can reach: {}",
            redact(&listening)
        );
    }

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
        let shown: String = redact(line).chars().take(400).collect();
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
    // SG-000119 A4: the view subscribes when it loads, so the script's first
    // app_events replaced the view's subscription and its second replaced
    // the first: until orceld's next write, two closed subscriptions may
    // still be counted, never more.
    assert!(actives.iter().all(|active| *active <= 4), "{actives:?}");
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
    // SG-000119 A4: the view's own reads come on top of the script's.
    let commands = ipc_commands(line(&finished, "SG119-IPC "));
    assert!(
        commands >= served + PAGE_CALLS,
        "commands={commands}: at least {} expected",
        served + PAGE_CALLS
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
         commands={commands} web_messages=0"
    );
}

/// `n` from `commands=<n> web_messages=0`; any web message fails.
fn ipc_commands(rest: &str) -> u64 {
    rest.strip_prefix("commands=")
        .and_then(|rest| rest.strip_suffix(" web_messages=0"))
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("SG119-IPC {rest}"))
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

// ---------------------------------------------------------------------------
// SG-000119 A4: the view against a live orceld, stopped and started again

/// The page's text and structure, read back from Rust (nothing is added to
/// the page): each part's textContent (bounded), the counts the parent
/// checks, and anything that could act (links, buttons, inputs, forms,
/// frames, images, inline handlers, scripts other than the view's module).
const SNAPSHOT: &str = r#"(function () {
  function text(selector) {
    var e = document.querySelector(selector);
    if (!e) { return null; }
    var parts = [], walker = document.createTreeWalker(e, NodeFilter.SHOW_TEXT), node;
    while ((node = walker.nextNode())) { parts.push(node.nodeValue); }
    return parts.join(' | ').slice(0, 6000);
  }
  var handlers = 0;
  document.querySelectorAll('*').forEach(function (e) {
    for (var i = 0; i < e.attributes.length; i++) { if (/^on/i.test(e.attributes[i].name)) { handlers++; } }
  });
  return JSON.stringify({
    url: location.href,
    connection: text('#connection'),
    data_hidden: document.getElementById('data').hidden,
    status: text('#status-body'),
    capabilities: text('#capabilities-body'),
    capability_rows: document.querySelectorAll('#capabilities-body tbody tr').length,
    devices: text('#devices-body'),
    tasks_note: text('#tasks-body'),
    tasks: text('#task-list'),
    task_ids: Array.prototype.map.call(document.querySelectorAll('details[data-task]'), function (d) { return d.getAttribute('data-task'); }),
    detail: text('details[open] .task-detail'),
    timeline: text('#timeline-body'),
    events: document.querySelectorAll('#timeline-body li').length,
    acting: document.querySelectorAll('a,button,input,select,textarea,form,iframe,img,object,embed').length,
    handlers: handlers,
    scripts: Array.prototype.map.call(document.scripts, function (s) { return s.getAttribute('src') || 'inline'; })
  });
})()"#;

fn snapshot(window: &tauri::WebviewWindow) -> Option<Value> {
    let (sender, receiver) = channel();
    window
        .eval_with_callback(SNAPSHOT, move |answer| {
            let _ = sender.send(answer);
        })
        .ok()?;
    let answer = receiver.recv_timeout(Duration::from_secs(5)).ok()?;
    // The callback gets the evaluated value as JSON: here a string holding JSON.
    let inner = serde_json::from_str::<Value>(&answer).ok()?;
    serde_json::from_str(inner.as_str()?).ok()
}

/// Reads the page until `ready` holds (or `limit` passes), then returns it.
fn until(window: &tauri::WebviewWindow, limit: Duration, ready: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + limit;
    let mut last = Value::Null;
    while Instant::now() < deadline {
        if let Some(page) = snapshot(window) {
            if ready(&page) {
                return page;
            }
            last = page;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    last
}

fn text<'a>(page: &'a Value, part: &str) -> &'a str {
    page[part].as_str().unwrap_or_default()
}

fn scenario_view(task_id: String) -> i32 {
    run(Hooks {
        after_apply: None,
        after_show: Some(Box::new(move |window| {
            std::thread::spawn(move || drive_view(window, task_id));
        })),
    })
}

/// Reads the view through three phases and prints one `SG119-VIEW <phase>`
/// line each; the parent stops orceld after `live` and starts it after `down`.
fn drive_view(window: tauri::WebviewWindow, task_id: String) {
    let wait = Duration::from_secs(60);
    let live = until(&window, wait, |page| {
        text(page, "connection").starts_with("Connected")
            && text(page, "status").contains("orcel-app-api/1")
            && page["capability_rows"].as_u64().unwrap_or(0) > 0
            && page["task_ids"]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|id| id == task_id.as_str()))
            && page["events"].as_u64().unwrap_or(0) > 0
    });
    // Open the task's details as a user would: a click on its summary.
    let open = format!(
        "(function () {{ var s = document.querySelector('summary[data-task={}]'); if (s) {{ s.click(); }} }})();",
        json!(task_id)
    );
    if let Err(error) = window.eval(open) {
        eprintln!("eval failed: {error}");
    }
    let opened = until(&window, wait, |page| {
        text(page, "detail").contains("data/q3.csv")
    });
    println!(
        "SG119-VIEW live {}",
        json!({ "page": live, "opened": opened })
    );

    // The parent stops orceld now.
    let down = until(&window, wait, |page| {
        text(page, "connection").starts_with("Unavailable: orceld is not running")
            && text(page, "status").contains("orceld is unavailable")
    });
    println!("SG119-VIEW down {down}");

    // The parent starts orceld again now.
    let recovered = until(&window, Duration::from_secs(90), |page| {
        text(page, "connection").starts_with("Connected")
            && text(page, "timeline").contains("recovered from its snapshot")
            && text(page, "status").contains("orcel-app-api/1")
            && page["capability_rows"].as_u64().unwrap_or(0) > 0
    });
    println!("SG119-VIEW recovered {recovered}");
    std::thread::sleep(Duration::from_millis(500));
    if let Err(error) = window.close() {
        eprintln!("close failed: {error}");
    }
}

fn live_view(binary: PathBuf) {
    let sid = orcel_app_api_client::this_user_sid().expect("this user's SID");
    let endpoint = format!(r"\\.\pipe\orcel-{sid}-app");
    let mut orceld = start_orceld(binary);
    orceld.wait_listening(&endpoint);
    let task_id = orceld.start_report();
    println!("    orceld listens on this user's endpoint; report task {task_id} observed");

    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args([SCENARIO, "view", &task_id]);
    for (name, _) in std::env::vars_os() {
        if orcel_control_room_shell::environment::names_webview2(&name) {
            command.env_remove(name);
        }
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the view scenario");
    let lines = lines_of(child.stdout.take().unwrap());
    let mut err = child.stderr.take().unwrap();
    let stderr = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = err.read_to_string(&mut text);
        text
    });

    // Follow the scenario: stop orceld after the live phase, start it again
    // after the down phase.
    let mut stdout = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        match lines.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                if line.starts_with("SG119-VIEW live ") {
                    orceld.stop();
                    println!("    orceld stopped mid-session");
                } else if line.starts_with("SG119-VIEW down ") {
                    orceld.restart();
                    orceld.wait_listening(&endpoint);
                    println!("    orceld started again in the same sandbox");
                }
                stdout.push(line);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
        assert!(Instant::now() < deadline, "the view scenario did not end");
    }
    let status = child.wait().expect("the scenario's exit");
    let stderr = stderr.join().unwrap_or_default();
    println!("--- view scenario: exit {:?}", status.code());
    for shown in stdout
        .iter()
        .chain(stderr.lines().map(str::to_owned).collect::<Vec<_>>().iter())
    {
        let shown: String = redact(shown).chars().take(600).collect();
        println!("    {shown}");
    }
    assert_eq!(status.code(), Some(0), "{}", redact(&stderr));
    let finished = Finished {
        code: status.code(),
        stdout: stdout.join("\n"),
        stderr,
    };

    let phase = |name: &str| -> Value {
        serde_json::from_str(line(&finished, &format!("SG119-VIEW {name} "))).expect(name)
    };
    let live = phase("live");
    let down = phase("down");
    let recovered = phase("recovered");
    for page in [&live, &down, &recovered] {
        let all = page.to_string();
        assert!(!all.contains(&sid), "the SID reached the page");
        assert!(!all.contains(TITLE), "the task title reached the page");
        assert!(!all.contains("1250000"), "source content reached the page");
    }

    // Live: the five sources rendered as text.
    let opened = &live["opened"];
    let live = &live["page"];
    assert_eq!(text(live, "url"), "https://tauri.localhost/index.html");
    assert!(
        text(live, "connection").starts_with("Connected to orceld"),
        "{live}"
    );
    assert!(
        text(live, "status").contains("orcel-app-api/1"),
        "status: {live}"
    );
    assert!(
        text(live, "status").contains("SG-000039_CLIPBOARD_WRITE"),
        "mode: {live}"
    );
    assert!(text(live, "status").contains("windows"), "os: {live}");
    let capability_rows = live["capability_rows"].as_u64().unwrap_or(0);
    assert!(capability_rows > 0, "capabilities: {live}");
    assert!(
        text(live, "devices").contains("devices.list"),
        "device list unavailable: {live}"
    );
    assert!(text(live, "tasks").contains(&task_id), "tasks: {live}");
    let events = live["events"].as_u64().unwrap_or(0);
    assert!(events > 0, "events: {live}");
    let detail = text(opened, "detail");
    assert!(detail.contains("data/q3.csv"), "detail: {opened}");
    assert!(detail.contains("reports"), "folder: {opened}");
    assert!(
        detail
            .split(|c: char| !c.is_ascii_hexdigit())
            .any(|word| word.len() == 64),
        "a source hash: {opened}"
    );
    for page in [live, opened, &down, &recovered] {
        assert_eq!(page["acting"], 0, "no element that acts: {page}");
        assert_eq!(page["handlers"], 0, "no inline handler: {page}");
        assert_eq!(page["scripts"], json!(["js/view/main.js"]), "{page}");
    }

    // Down: a truthful unavailable, no status shown as live.
    assert!(
        text(&down, "connection").starts_with("Unavailable: orceld is not running"),
        "{down}"
    );
    assert!(
        text(&down, "status").contains("orceld is unavailable"),
        "{down}"
    );
    assert!(!text(&down, "status").contains("orcel-app-api/1"), "{down}");

    // Recovered: from orceld's snapshot after the restart.
    assert!(
        text(&recovered, "connection").starts_with("Connected to orceld"),
        "{recovered}"
    );
    assert!(
        text(&recovered, "timeline")
            .contains("orceld restarted; the view recovered from its snapshot"),
        "{recovered}"
    );
    assert!(
        text(&recovered, "status").contains("orcel-app-api/1"),
        "{recovered}"
    );

    let commands = ipc_commands(line(&finished, "SG119-IPC "));
    assert!(commands >= PAGE_CALLS, "commands={commands}");
    let version = line(&finished, "SG119-WEBVIEW2 version=").to_owned();
    let down_text: String = text(&down, "connection").chars().take(60).collect();
    println!(
        "SG119-EVIDENCE A4 view on windows (WebView2 {version}): the view rendered status, \
         {capability_rows} capabilities with the device list unavailable, report task {task_id} \
         as metadata with its details (folder, source path and hash; no title) and {events} live \
         events from a live orceld through the five commands, as text only (no acting element, \
         no inline handler, one module script); orceld stopped mid-session showed \
         \"{down_text}...\" with no status shown as live, and after orceld started again the view \
         recovered from its snapshot; SG119-IPC commands={commands} web_messages=0"
    );
}

// ---------------------------------------------------------------------------
// SG-000119 A5: the renderer and a live orceld's pipe; the task summary as a
// screen reader reads it

fn live_renderer_and_tasks(binary: PathBuf) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CLOSE};
    let sid = orcel_app_api_client::this_user_sid().expect("this user's SID");
    let endpoint = format!(r"\\.\pipe\orcel-{sid}-app");
    let mut orceld = start_orceld(binary);
    orceld.wait_listening(&endpoint);
    let task_id = orceld.start_report();
    println!("    orceld listens on this user's endpoint; report task {task_id} observed");

    let mut command = Command::new(env!("CARGO_BIN_EXE_orcel-control-room-shell"));
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
        .expect("spawn the shell");
    let child = KillOnDrop(Some(child));
    let pid = child.0.as_ref().expect("the shell").id();
    let start = Instant::now();
    let hwnd = loop {
        let found = qualify::windows_of(&[pid])
            .into_iter()
            .find(|window| window.visible && window.title == "Orcel Control Room");
        if let Some(window) = found {
            break window.hwnd;
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "no visible window"
        );
        std::thread::sleep(Duration::from_millis(100));
    };

    // The task's summary through UI Automation (read-only).
    let wanted = format!("report task {task_id}");
    let deadline = Instant::now() + Duration::from_secs(30);
    let (stops, summary) = loop {
        let tree = qualify::uia_tree(pid, "Orcel Control Room", 10_000);
        let elements = tree.as_array().cloned().unwrap_or_default();
        let stops: Vec<Value> = elements
            .iter()
            .filter(|element| element["focusable"] == true && element["ct"] != "Document")
            .cloned()
            .collect();
        let summary = stops
            .iter()
            .find(|element| {
                element["name"]
                    .as_str()
                    .is_some_and(|name| name.contains(&wanted))
            })
            .cloned();
        if summary.is_some() || Instant::now() > deadline {
            break (stops, summary);
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let names: Vec<&str> = stops
        .iter()
        .filter_map(|element| element["name"].as_str())
        .collect();
    let summary =
        summary.unwrap_or_else(|| panic!("no keyboard stop named for the task: {names:?}"));
    let name = summary["name"].as_str().unwrap_or_default().to_owned();
    assert!(
        name.contains(", owner: ") && name.contains("; updated ") && !name.contains(TITLE),
        "the summary is named by state, kind, id, owner and time, never the title: {name}"
    );
    assert_eq!(
        summary["expand"], true,
        "the summary expands its details: {summary}"
    );
    assert_eq!(
        names.last().copied(),
        Some("Live events list, scrollable"),
        "the task summaries come before the timeline: {names:?}"
    );

    // The renderer against orceld's real pipe; the name is never printed.
    let (lines, probes) = qualify::probe_tree(pid, &endpoint);
    for line in &lines {
        println!("    SG119-PROCESS {}", redact(line));
    }
    let control = AppApiClient::for_this_user()
        .expect("the client")
        .status()
        .is_ok();
    // SAFETY: posting WM_CLOSE to the shell's own window.
    assert_ne!(unsafe { PostMessageW(hwnd, WM_CLOSE, 0, 0) }, 0);
    let finished = finish(child.take(), Duration::from_secs(30));
    assert_eq!(finished.code, Some(0));
    assert!(
        control,
        "this test, at Medium integrity, reads orceld's status"
    );
    let renderers: Vec<_> = probes
        .iter()
        .filter(|(kind, _, _)| kind == "renderer")
        .collect();
    assert!(
        !renderers.is_empty(),
        "a renderer was probed: {}",
        redact(&format!("{lines:#?}"))
    );
    for (kind, facts, probe) in &probes {
        assert!(
            probe.thread.integrity == facts.integrity && facts.integrity < qualify::MEDIUM,
            "{kind}: the probe ran at the process's own integrity"
        );
        assert_eq!(
            probe.open,
            qualify::ACCESS_DENIED,
            "{kind}: opening orceld's pipe under its token is refused"
        );
    }
    let (_, facts, probe) = renderers[0];
    let version = line(&finished, "SG119-WEBVIEW2 version=");
    println!(
        "SG119-EVIDENCE A5 renderer on windows (WebView2 {version}): with a live orceld on this \
         user's endpoint, opening its pipe (read and write, identification-only, as its clients \
         do) under the WebView2 renderer's own token (integrity {}, appcontainer {}, restricted \
         {}) gave {}; all {} sandboxed WebView2 processes were refused; this test at Medium \
         integrity read status through the A1 client; the task's summary read to UI Automation \
         as {:?} (an expandable keyboard stop, before the timeline)",
        qualify::rid_name(facts.integrity),
        facts.app_container,
        facts.restricted,
        qualify::error_name(probe.open),
        probes.len(),
        name.replace(&task_id, "<task>")
    );
}

/// Kills the shell if a check fails before the test closes it, so no test
/// window outlives its test.
struct KillOnDrop(Option<Child>);

impl KillOnDrop {
    fn take(mut self) -> Child {
        self.0.take().expect("the shell")
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
