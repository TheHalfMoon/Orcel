//! SG-000119 A3 ACL tests: the shell's real ACL (the context generated from
//! `tauri.conf.json`, the capability file and `build.rs`'s app manifest) and
//! its real five command handlers, driven through Tauri's mock runtime
//! (`tauri::test`, tauri's `test` feature, dev-dependencies only).
//!
//! The commands read from a stand-in [`Source`] that answers with the A1
//! sanitiser's own output for orceld-shaped fixtures, so these tests never
//! open this user's real orceld endpoint. The live orceld run is
//! `tests/native_live.rs`.
//!
//! Proven here: the manifest, the handler list, the constant and the
//! capability name the same five commands; each of the five works with its
//! permission; an unknown command, a core or plugin command without a
//! permission, a window the capability does not name and a remote origin
//! are refused by the ACL before any handler runs; an extra argument, a raw
//! body and a malformed `task_id`, channel or cursor are refused with typed
//! errors before anything is read; two `app_events` calls leave one
//! subscription; the channel ends when the window closes.

use orcel_app_api_client::sanitize::capabilities::{self, Capabilities};
use orcel_app_api_client::sanitize::events;
use orcel_app_api_client::sanitize::status::{self, Status};
use orcel_app_api_client::sanitize::tasks::{self, TaskDetail, TaskList};
use orcel_app_api_client::{ClientError, Cursor, Next, StreamItem, TaskId};
use orcel_control_room_shell::commands::{self, Events, Source, COMMANDS};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::ipc::{CallbackFn, InvokeBody, InvokeResponseBody};
use tauri::test::{get_ipc_response, mock_builder, MockRuntime, INVOKE_KEY};
use tauri::webview::InvokeRequest;
use tauri::{App, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const SID_PIPE: &str = r"\\.\pipe\orcel-S-1-5-21-1111111111-2222222222-3333333333-1001-app";
const TITLE: &str = "Q3 revenue summary for the board";
const TASK_ID: &str = "r-0001-6a2f";
const LOCAL: &str = "https://tauri.localhost/";
const WAIT: Duration = Duration::from_secs(10);

fn epoch() -> String {
    format!("{:x}-{:x}", 13_572u32, 1_763_301_234_567_890_123u128)
}

// ---------------------------------------------------------------------------
// orceld-shaped fixtures (the shapes `crates/orcel-app-api-client`'s own
// sanitiser tests use), sanitised by the A1 sanitiser itself.

fn orceld_status() -> Value {
    json!({
        "name": "orceld", "version": "0.2.0", "app_api": "orcel-app-api/1",
        "read_only": true, "internal_protocol_version": "1", "os": "windows",
        "arch": "x86_64", "pid": 13572, "mode": "SG-000039_CLIPBOARD_WRITE",
        "policy_revision": "sg-000039-v1", "started_at_ms": 1_763_301_234_567u64,
        "uptime_ms": 4_200, "endpoint": SID_PIPE,
        "events": { "epoch": epoch(), "head_seq": 12, "oldest_seq": 1, "ring_capacity": 1024 },
        "clients": { "active": 1, "max": 8 },
        "peer": { "pid": 777, "source": "win32-named-pipe-client" },
    })
}

fn orceld_capabilities() -> Value {
    json!({
        "os": "windows", "read_only": true,
        "methods": ["status.get", "task.stop", "approval.history", "clients.list"],
        "reserved_methods": ["devices.list"],
        "capabilities": [
            { "id": "fs", "state": "available", "reason": null },
            { "id": "approval.presence", "state": "unavailable", "reason": "no platform presence surface is available to orceld" },
        ],
    })
}

fn summary() -> Value {
    json!({
        "task_id": TASK_ID, "kind": "report", "title": TITLE, "state": "verified",
        "workspace_id": "default", "created_at_ms": 1_763_301_000_000u64,
        "updated_at_ms": 1_763_301_100_000u64, "owner": "this_session",
    })
}

fn detail() -> Value {
    let mut value = summary();
    let object = value.as_object_mut().unwrap();
    object.insert("folder".into(), json!("reports"));
    object.insert(
        "sources".into(),
        json!([{ "path": "data/q3.csv", "sha256": SHA, "bytes": 61 },
               { "path": "C:\\Users\\someone\\secret.csv", "sha256": SHA, "bytes": 9 }]),
    );
    object.insert(
        "report".into(),
        json!({ "name": "q3.md", "destination": "reports/q3.md", "sha256": SHA, "bytes": 120 }),
    );
    object.insert(
        "steps".into(),
        json!([{ "step_id": "s1", "kind": "observe", "outcome": "ok", "at_ms": 1 }]),
    );
    value
}

fn sample_event() -> StreamItem {
    let raw = json!({
        "seq": 1, "epoch": epoch(), "run_id": null, "step_id": null,
        "kind": "daemon.started", "at_ms": 1_763_301_234_999u64,
        "data": { "pid": 13572, "mode": "SG-000039_CLIPBOARD_WRITE" },
    });
    StreamItem::Event {
        event: Box::new(events::sanitize(&raw).unwrap().unwrap()),
    }
}

// ---------------------------------------------------------------------------
// The stand-in source

/// One fake subscription: a few items, then idle until ended.
struct FakeFeed {
    items: Mutex<VecDeque<StreamItem>>,
    ended: AtomicBool,
}

impl Events for FakeFeed {
    fn next(&self, wait: Duration) -> Next {
        let deadline = Instant::now() + wait;
        loop {
            if self.ended.load(Ordering::SeqCst) {
                return Next::Ended;
            }
            if let Some(item) = self.items.lock().unwrap().pop_front() {
                return Next::Item(item);
            }
            if Instant::now() >= deadline {
                return Next::Idle;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[derive(Default)]
struct Fake {
    /// Every read, by orceld method name.
    reads: Mutex<Vec<String>>,
    current: Mutex<Option<Arc<FakeFeed>>>,
    /// Subscriptions opened and the most ever live at once.
    opened: AtomicUsize,
    live: AtomicUsize,
    most_live: AtomicUsize,
}

impl Fake {
    fn read(&self, method: &str) {
        self.reads.lock().unwrap().push(method.to_owned());
    }

    fn reads(&self) -> Vec<String> {
        self.reads.lock().unwrap().clone()
    }

    fn end_current(&self) {
        if let Some(feed) = self.current.lock().unwrap().take() {
            feed.ended.store(true, Ordering::SeqCst);
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl Source for Fake {
    fn status(&self) -> Result<Status, ClientError> {
        self.read("status.get");
        Ok(status::sanitize(&orceld_status()).unwrap())
    }

    fn capabilities(&self) -> Result<Capabilities, ClientError> {
        self.read("capabilities.get");
        Ok(capabilities::sanitize(&orceld_capabilities()).unwrap())
    }

    fn tasks(&self) -> Result<TaskList, ClientError> {
        self.read("task.list");
        Ok(tasks::list(
            &json!({ "tasks": [summary()], "max_tasks": 64 }),
        ))
    }

    fn task(&self, task_id: &TaskId) -> Result<TaskDetail, ClientError> {
        self.read(&format!("task.get {}", task_id.as_str()));
        if task_id.as_str() == TASK_ID {
            tasks::detail(&detail()).map_err(|_| ClientError::TaskWithheld)
        } else {
            Err(ClientError::Refused("TASK_NOT_FOUND".into()))
        }
    }

    fn subscribe(&self, from: Option<Cursor>) -> Result<Arc<dyn Events>, ClientError> {
        self.read(&match &from {
            Some(cursor) => format!("events.subscribe {} {}", cursor.epoch(), cursor.after_seq()),
            None => "events.subscribe".to_owned(),
        });
        // As the client's Window does: the earlier subscription ends first.
        self.end_current();
        let feed = Arc::new(FakeFeed {
            items: Mutex::new(VecDeque::from([sample_event(), StreamItem::Withheld])),
            ended: AtomicBool::new(false),
        });
        *self.current.lock().unwrap() = Some(Arc::clone(&feed));
        self.opened.fetch_add(1, Ordering::SeqCst);
        let live = self.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.most_live.fetch_max(live, Ordering::SeqCst);
        Ok(feed)
    }

    fn unsubscribe(&self) {
        self.end_current();
    }
}

// ---------------------------------------------------------------------------
// The app under test

/// Channel messages the shell sent, by channel id, as JSON.
type Sent = Arc<Mutex<Vec<(u32, Value)>>>;

struct Harness {
    app: App<MockRuntime>,
    main: WebviewWindow<MockRuntime>,
    fake: Arc<Fake>,
    sent: Sent,
}

fn harness() -> Harness {
    let fake = Arc::new(Fake::default());
    let sent: Sent = Arc::default();
    let recorder = Arc::clone(&sent);
    let builder = mock_builder().channel_interceptor(move |_, callback, _, body| {
        if let InvokeResponseBody::Json(text) = body {
            let value = serde_json::from_str(text).expect("channel JSON");
            recorder.lock().unwrap().push((callback.0, value));
        }
        true
    });
    let source: Arc<dyn Source> = fake.clone();
    let app = commands::register(builder, source)
        .build(commands::context())
        .expect("the shell's app on the mock runtime");
    let main = WebviewWindowBuilder::new(&app, "main", WebviewUrl::App("index.html".into()))
        .build()
        .expect("the main window");
    Harness {
        app,
        main,
        fake,
        sent,
    }
}

fn request(cmd: &str, url: &str, body: InvokeBody) -> InvokeRequest {
    InvokeRequest {
        cmd: cmd.into(),
        callback: CallbackFn(0),
        error: CallbackFn(1),
        url: url.parse().unwrap(),
        body,
        headers: Default::default(),
        invoke_key: INVOKE_KEY.to_string(),
    }
}

fn invoke_from(
    window: &WebviewWindow<MockRuntime>,
    cmd: &str,
    url: &str,
    body: InvokeBody,
) -> Result<Value, Value> {
    get_ipc_response(window, request(cmd, url, body))
        .map(|body| body.deserialize::<Value>().expect("JSON answer"))
}

fn invoke(h: &Harness, cmd: &str, args: Value) -> Result<Value, Value> {
    invoke_from(&h.main, cmd, LOCAL, InvokeBody::Json(args))
}

fn assert_acl_refused(result: Result<Value, Value>, what: &str) {
    match result {
        Err(Value::String(message)) => assert!(
            message.contains("not allowed"),
            "{what}: refused, but not by the ACL: {message}"
        ),
        other => panic!("{what}: not refused by the ACL: {other:?}"),
    }
}

fn sent_on(sent: &Sent, channel: u32) -> Vec<Value> {
    sent.lock()
        .unwrap()
        .iter()
        .filter(|(id, _)| *id == channel)
        .map(|(_, value)| value.clone())
        .collect()
}

fn wait_for(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
        .replace("\r\n", "\n")
}

/// The quoted names between `open` and the next `close` in `source`.
fn quoted_list(source: &str, open: &str, close: &str) -> Vec<String> {
    let start = source.find(open).unwrap_or_else(|| panic!("no {open}")) + open.len();
    let rest = &source[start..];
    let list = &rest[..rest.find(close).unwrap_or_else(|| panic!("no {close}"))];
    list.split(',')
        .map(|item| item.trim().trim_matches('"').to_owned())
        .filter(|item| !item.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests

#[test]
fn the_manifest_the_handler_the_constant_and_the_capability_name_the_same_five() {
    let expected = [
        "app_status",
        "app_capabilities",
        "app_events",
        "app_tasks",
        "app_task",
    ];
    assert_eq!(COMMANDS, expected);
    // build.rs's AppManifest list.
    let manifest = quoted_list(&read("build.rs"), ".commands(&[", "]");
    assert_eq!(manifest, expected, "build.rs AppManifest commands");
    // The invoke handler's list.
    let handler = quoted_list(&read("src/commands.rs"), "tauri::generate_handler![", "]");
    assert_eq!(handler, expected, "generate_handler! list");
    // The capability grants exactly each command's own allow permission.
    let capability: Value = serde_json::from_str(&read("capabilities/main.json")).unwrap();
    let granted: Vec<String> = expected
        .iter()
        .map(|command| format!("allow-{}", command.replace('_', "-")))
        .collect();
    assert_eq!(capability["permissions"], json!(granted));
    assert_eq!(capability["windows"], json!(["main"]));
    assert!(capability.get("remote").is_none());
    // tauri-build generated exactly the five permission files from build.rs,
    // and no hand-written permission file exists beside them.
    let permissions = Path::new(env!("CARGO_MANIFEST_DIR")).join("permissions");
    let top: Vec<String> = std::fs::read_dir(&permissions)
        .expect("permissions")
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(top, ["autogenerated"]);
    let mut generated: Vec<String> = std::fs::read_dir(permissions.join("autogenerated"))
        .expect("permissions/autogenerated")
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    generated.sort();
    let mut files: Vec<String> = expected.iter().map(|c| format!("{c}.toml")).collect();
    files.sort();
    assert_eq!(generated, files);
    for command in expected {
        let toml = read(&format!("permissions/autogenerated/{command}.toml"));
        let slug = command.replace('_', "-");
        assert!(toml.contains(&format!("identifier = \"allow-{slug}\"\n")));
        assert!(toml.contains(&format!("commands.allow = [\"{command}\"]\n")));
        assert!(toml.contains(&format!("commands.deny = [\"{command}\"]\n")));
    }
}

#[test]
fn each_command_works_with_its_permission_and_answers_sanitised() {
    let h = harness();

    let status = invoke(&h, "app_status", json!({})).expect("app_status");
    assert_eq!(status["app_api"]["value"], "orcel-app-api/1");
    assert_eq!(status["mode"]["value"], "SG-000039_CLIPBOARD_WRITE");
    let text = status.to_string();
    assert!(!text.contains("13572") && !text.contains("S-1-5-21") && !text.contains("peer"));
    assert!(status.get("pid").is_none() && status.get("endpoint").is_none());

    let capabilities = invoke(&h, "app_capabilities", json!({})).expect("app_capabilities");
    assert_eq!(capabilities["capabilities"].as_array().unwrap().len(), 2);
    assert!(capabilities.get("methods").is_none());
    assert!(!capabilities.to_string().contains("task.stop"));

    let list = invoke(&h, "app_tasks", json!({})).expect("app_tasks");
    assert_eq!(list["tasks"][0]["task_id"], TASK_ID);
    assert!(!list.to_string().contains(TITLE) && !list.to_string().contains("title"));

    let task = invoke(&h, "app_task", json!({ "task_id": TASK_ID })).expect("app_task");
    assert_eq!(task["task_id"], TASK_ID);
    assert_eq!(task["sources"][0]["path"]["value"], "data/q3.csv");
    assert_eq!(task["sources"][1]["path"]["state"], "withheld");
    let text = task.to_string();
    assert!(!text.contains(TITLE) && !text.contains("secret.csv") && !text.contains("someone"));

    // A refusal from orceld comes back typed, with its code only.
    assert_eq!(
        invoke(&h, "app_task", json!({ "task_id": "r-unknown" })),
        Err(json!({ "error": "refused", "code": "TASK_NOT_FOUND" }))
    );

    let channel = 7;
    let epoch = epoch();
    assert_eq!(
        invoke(
            &h,
            "app_events",
            json!({ "channel": format!("__CHANNEL__:{channel}"), "from": { "after_seq": 3, "epoch": epoch } }),
        ),
        Ok(Value::Null)
    );
    wait_for("two items on the channel", || {
        sent_on(&h.sent, channel).len() >= 2
    });
    let items = sent_on(&h.sent, channel);
    assert_eq!(items[0]["type"], "event");
    assert_eq!(items[0]["event"]["kind"], "daemon.started");
    assert!(!items[0].to_string().contains("13572"));
    assert_eq!(items[1], json!({ "type": "withheld" }));

    assert_eq!(
        h.fake.reads(),
        [
            "status.get".to_owned(),
            "capabilities.get".to_owned(),
            "task.list".to_owned(),
            format!("task.get {TASK_ID}"),
            "task.get r-unknown".to_owned(),
            format!("events.subscribe {epoch} 3"),
        ]
    );
    // Served calls are counted for the exit report.
    let ipc = orcel_control_room_shell::report::lines()
        .into_iter()
        .find(|line| line.starts_with("SG119-IPC "))
        .unwrap();
    let served: u64 = ipc["SG119-IPC commands=".len()..]
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(served >= 6, "{ipc}");
    drop(h.app);
}

#[test]
fn an_unknown_command_is_refused_by_the_acl() {
    let h = harness();
    for cmd in [
        "app_api_call",
        "task_stop",
        "approval_history",
        "clients_list",
        "app_status2",
        "APP_STATUS",
        "sg119_native_probe",
        "",
    ] {
        assert_acl_refused(invoke(&h, cmd, json!({})), cmd);
    }
    assert!(h.fake.reads().is_empty(), "{:?}", h.fake.reads());
}

#[test]
fn commands_without_a_permission_are_refused() {
    let h = harness();
    // Core and plugin commands: the capability grants none of them.
    for cmd in [
        "plugin:event|listen",
        "plugin:event|emit",
        "plugin:window|close",
        "plugin:window|create",
        "plugin:webview|create_webview_window",
        "plugin:path|resolve_directory",
        "plugin:app|version",
        "plugin:image|new",
        "plugin:resources|close",
        "plugin:menu|new",
        "plugin:tray|new",
        "plugin:shell|execute",
        "plugin:fs|read_file",
        "plugin:opener|open_url",
    ] {
        assert_acl_refused(invoke(&h, cmd, json!({})), cmd);
    }
    // The five, from a window the capability does not name.
    let other = WebviewWindowBuilder::new(&h.app, "other", WebviewUrl::App("index.html".into()))
        .build()
        .expect("another window");
    for cmd in COMMANDS {
        assert_acl_refused(
            invoke_from(&other, cmd, LOCAL, InvokeBody::Json(json!({}))),
            &format!("{cmd} from the window 'other'"),
        );
    }
    // The five, from a remote origin in the main window (no remote section).
    for url in [
        "https://example.invalid/",
        "https://tauri.localhost.evil/",
        "http://127.0.0.1/",
    ] {
        for cmd in COMMANDS {
            assert_acl_refused(
                invoke_from(&h.main, cmd, url, InvokeBody::Json(json!({}))),
                &format!("{cmd} from {url}"),
            );
        }
    }
    assert!(h.fake.reads().is_empty(), "{:?}", h.fake.reads());
}

#[test]
fn extra_arguments_and_malformed_task_ids_are_refused_typed() {
    let h = harness();
    let invalid_arguments = Err(json!({ "error": "invalid_arguments" }));
    let invalid_task_id = Err(json!({ "error": "invalid_task_id" }));
    for cmd in ["app_status", "app_capabilities", "app_tasks"] {
        assert_eq!(
            invoke(&h, cmd, json!({ "x": 1 })),
            invalid_arguments,
            "{cmd}"
        );
        assert_eq!(invoke(&h, cmd, json!([1])), invalid_arguments, "{cmd}");
        assert_eq!(
            invoke(&h, cmd, json!("status.get")),
            invalid_arguments,
            "{cmd}"
        );
        assert_eq!(
            invoke_from(&h.main, cmd, LOCAL, InvokeBody::Raw(b"{}".to_vec())),
            invalid_arguments,
            "{cmd} raw body"
        );
        // No argument at all is the command's own shape.
        assert!(
            invoke(&h, cmd, Value::Null).is_ok(),
            "{cmd} without arguments"
        );
    }
    for bad in [
        json!({ "task_id": "../x" }),
        json!({ "task_id": "" }),
        json!({ "task_id": "a".repeat(129) }),
        json!({ "task_id": "r 1" }),
        json!({ "task_id": "r/1" }),
        json!({ "task_id": "r\u{202e}1" }),
        json!({ "task_id": 5 }),
        json!({ "task_id": null }),
    ] {
        assert_eq!(
            invoke(&h, "app_task", bad.clone()),
            invalid_task_id,
            "{bad}"
        );
    }
    for bad in [
        json!({}),
        json!({ "task_id": TASK_ID, "method": "task.stop" }),
        json!({ "taskId": TASK_ID }),
        Value::Null,
    ] {
        assert_eq!(
            invoke(&h, "app_task", bad.clone()),
            invalid_arguments,
            "{bad}"
        );
    }
    let epoch = epoch();
    for bad in [
        json!({}),
        json!({ "channel": "not-a-channel" }),
        json!({ "channel": 7 }),
        json!({ "channel": "__CHANNEL__:7", "method": "task.stop" }),
        json!({ "channel": "__CHANNEL__:7", "from": { "after_seq": 1, "epoch": "not-an-epoch" } }),
        json!({ "channel": "__CHANNEL__:7", "from": { "after_seq": -1, "epoch": epoch } }),
        json!({ "channel": "__CHANNEL__:7", "from": { "after_seq": 1, "epoch": epoch, "x": 1 } }),
        json!({ "channel": "__CHANNEL__:7", "from": 3 }),
    ] {
        assert_eq!(
            invoke(&h, "app_events", bad.clone()),
            invalid_arguments,
            "{bad}"
        );
    }
    // Nothing reached the source except the three argument-free reads.
    assert_eq!(
        h.fake.reads(),
        ["status.get", "capabilities.get", "task.list"]
    );
}

#[test]
fn two_app_events_calls_leave_one_subscription() {
    let h = harness();
    for channel in [11, 12] {
        assert_eq!(
            invoke(
                &h,
                "app_events",
                json!({ "channel": format!("__CHANNEL__:{channel}") })
            ),
            Ok(Value::Null)
        );
    }
    assert_eq!(h.fake.opened.load(Ordering::SeqCst), 2);
    assert_eq!(h.fake.live.load(Ordering::SeqCst), 1);
    assert_eq!(h.fake.most_live.load(Ordering::SeqCst), 1);
    // The first channel ended; the second carries the live subscription.
    wait_for("the first channel's end", || {
        sent_on(&h.sent, 11).last() == Some(&json!({ "type": "ended" }))
    });
    wait_for("items on the second channel", || {
        sent_on(&h.sent, 12).len() >= 2
    });
    assert!(!sent_on(&h.sent, 12).contains(&json!({ "type": "ended" })));
}

#[test]
fn the_channel_ends_when_the_window_closes() {
    let h = harness();
    assert_eq!(
        invoke(&h, "app_events", json!({ "channel": "__CHANNEL__:21" })),
        Ok(Value::Null)
    );
    wait_for("items on the channel", || sent_on(&h.sent, 21).len() >= 2);
    assert_eq!(h.fake.live.load(Ordering::SeqCst), 1);
    let main = h.main.clone();
    let closer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        main.close().expect("close the main window");
    });
    // The mock event loop delivers the close to the run loop, which the
    // shell forwards to `commands::on_run_event`, as `shell::run` does; with
    // no window left the loop exits.
    let _ = h
        .app
        .run_return(|handle, event| commands::on_run_event(handle, &event));
    closer.join().unwrap();
    assert_eq!(
        h.fake.live.load(Ordering::SeqCst),
        0,
        "the subscription ended"
    );
    wait_for("the channel's end", || {
        sent_on(&h.sent, 21).last() == Some(&json!({ "type": "ended" }))
    });
}
