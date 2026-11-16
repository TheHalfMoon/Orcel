//! Live tests: the client against a real orceld, started with its own app
//! API instance, workspace, audit file and state root, so the tests talk to
//! the same endpoint code users get. Only this crate's tests can name an
//! instance (`AppApiClient::with_instance`); the shell has no such path.
//!
//! orceld is the binary `cargo test --workspace` builds beside this test
//! (`target/<profile>/orceld`). When it is missing the live tests return
//! early, unless `ORCEL_REQUIRE_LIVE_ORCELD=1`, which makes that a failure.
//! Nothing here reaches orceld's approval broker, so no dialog can appear.

use crate::client::AppApiClient;
use crate::cursor::Cursor;
use crate::error::{ClientError, Unavailable};
use crate::method::TaskId;
use crate::sanitize::events::{EventBody, SnapshotReason};
use crate::sanitize::tasks::{Known, StepKind, StepOutcome, TaskState};
use crate::sanitize::Field;
use crate::subscription::{Feed, Next, StreamItem, Window};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const START_TIMEOUT: Duration = Duration::from_secs(30);
const WAIT: Duration = Duration::from_secs(20);
const Q3_CSV: &str = "region,quarter,revenue_cents\nnorth,Q3,1250000\nsouth,Q3,980050\n";

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos()
}

/// A short instance name of 1-32 of `a-z`, `0-9` and `-`, unique per test.
pub(crate) fn instance(label: &str) -> String {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    format!(
        "a1{label}-{:x}-{}",
        nanos() % 0xff_ffff,
        COUNT.fetch_add(1, Ordering::Relaxed)
    )
}

fn orceld_binary() -> Option<PathBuf> {
    let exe = if cfg!(windows) {
        "orceld.exe"
    } else {
        "orceld"
    };
    // target/<profile>/deps/<this test> -> target/<profile>/orceld
    let found = std::env::current_exe()
        .ok()?
        .parent()?
        .parent()
        .map(|dir| dir.join(exe))
        .filter(|path| path.is_file());
    if found.is_none() && std::env::var_os("ORCEL_REQUIRE_LIVE_ORCELD").is_some_and(|v| v == "1") {
        panic!("ORCEL_REQUIRE_LIVE_ORCELD=1 but no orceld binary beside the tests; build it with cargo build -p orceld");
    }
    found
}

struct Sandbox {
    base: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let parent = if cfg!(unix) {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        let base = parent.join(format!(
            "a1c-{}-{:x}",
            std::process::id(),
            nanos() % 0xff_ffff_ffff
        ));
        for dir in ["", "h", "r", "a", "ws/data", "ws/reports"] {
            let path = base.join(dir);
            std::fs::create_dir_all(&path).expect("create sandbox dir");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod");
            }
        }
        std::fs::write(base.join("ws").join("data").join("q3.csv"), Q3_CSV).unwrap();
        Self { base }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// One real orceld serving the app API instance `instance`. Its stdio is
/// read on threads so every wait is bounded; it is killed on drop.
struct Orceld {
    child: Child,
    stdin: Option<ChildStdin>,
    replies: Arc<Mutex<Vec<String>>>,
    replied: Arc<AtomicUsize>,
    logs: Receiver<String>,
    sent: usize,
    /// The endpoint orceld logged it listens on.
    endpoint: String,
    _sandbox: Sandbox,
}

impl Orceld {
    fn start(instance: &str) -> Option<Self> {
        let binary = orceld_binary()?;
        let sandbox = Sandbox::new();
        let mut command = Command::new(binary);
        command
            .env("ORCEL_WORKSPACE_ROOT", sandbox.base.join("ws"))
            .env("ORCEL_WORKSPACE_ID", "default")
            .env(
                "ORCEL_AUDIT_PATH",
                sandbox.base.join("a").join("audit.jsonl"),
            )
            .env("ORCEL_APP_API_INSTANCE", instance)
            .env_remove("ORCEL_APP_API")
            .env_remove("ORCEL_WORKSPACES_JSON")
            .env_remove("ORCEL_MCP_TRANSPORT")
            .env_remove("ORCEL_REPORT_JOURNAL_PATH")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if cfg!(windows) {
            command.env("USERPROFILE", sandbox.base.join("h"));
        } else if cfg!(target_os = "macos") {
            command.env("HOME", sandbox.base.join("h"));
        } else {
            command
                .env("XDG_STATE_HOME", sandbox.base.join("h"))
                .env("XDG_RUNTIME_DIR", sandbox.base.join("r"));
        }
        let mut child = command.spawn().expect("spawn orceld");
        let stdin = child.stdin.take();
        let replies = Arc::new(Mutex::new(Vec::new()));
        let replied = Arc::new(AtomicUsize::new(0));
        {
            let stdout = child.stdout.take().expect("stdout");
            let replies = Arc::clone(&replies);
            let replied = Arc::clone(&replied);
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                    replies.lock().unwrap().push(line);
                    replied.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
        let (log_tx, logs) = channel();
        {
            let stderr = child.stderr.take().expect("stderr");
            std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    if log_tx.send(line).is_err() {
                        break;
                    }
                }
            });
        }
        let mut orceld = Self {
            child,
            stdin,
            replies,
            replied,
            logs,
            sent: 0,
            endpoint: String::new(),
            _sandbox: sandbox,
        };
        let listening = orceld.wait_log("orceld app api: listening on ");
        orceld.endpoint = listening
            .split_once("listening on ")
            .map(|(_, endpoint)| endpoint.trim().to_owned())
            .expect("endpoint");
        Some(orceld)
    }

    fn wait_log(&self, needle: &str) -> String {
        let deadline = Instant::now() + START_TIMEOUT;
        let mut seen = Vec::new();
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.logs.recv_timeout(left) {
                Ok(line) if line.contains(needle) => return line,
                Ok(line) => seen.push(line),
                Err(_) => break,
            }
        }
        panic!("orceld never logged {needle:?}; it logged {seen:?}");
    }

    /// Writes `count` lines to orceld's stdio channel and waits for every
    /// answer; each publishes one `request.completed` event.
    fn send(&mut self, line: &str, count: usize) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        let mut batch = String::with_capacity((line.len() + 1) * count);
        for _ in 0..count {
            batch.push_str(line);
            batch.push('\n');
        }
        stdin.write_all(batch.as_bytes()).expect("write requests");
        stdin.flush().expect("flush");
        self.sent += count;
        let deadline = Instant::now() + WAIT;
        while self.replied.load(Ordering::SeqCst) < self.sent {
            assert!(
                Instant::now() < deadline,
                "orceld did not answer every request"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// One `request.completed` event with a null capability and operation:
    /// a line that is JSON but not a request envelope.
    fn events(&mut self, count: usize) {
        self.send("{}", count);
    }

    fn last_reply(&self) -> Value {
        let replies = self.replies.lock().unwrap();
        serde_json::from_str(replies.last().expect("a reply")).expect("reply json")
    }

    fn start_report(&mut self) -> String {
        let envelope = json!({
            "version": 1,
            "request_id": "a1-start",
            "client_session_id": "a1",
            "workspace_id": "default",
            "capability": "report",
            "operation": "start",
            "target": null,
            "arguments": { "title": "Q3 revenue for the board", "sources": ["data/q3.csv"], "folder": "reports" },
        });
        self.send(&envelope.to_string(), 1);
        let reply = self.last_reply();
        assert_eq!(reply["ok"], true, "{reply}");
        reply["result"]["task_id"]
            .as_str()
            .expect("task id")
            .to_owned()
    }
}

impl Drop for Orceld {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The next item within the wait, failing the test otherwise.
fn next(feed: &Feed) -> StreamItem {
    match feed.next(WAIT) {
        Next::Item(item) => item,
        other => panic!("no item from the subscription: {other:?}"),
    }
}

fn event_body(item: StreamItem) -> EventBody {
    match item {
        StreamItem::Event { event } => event.body,
        other => panic!("not an event: {other:?}"),
    }
}

fn live(label: &str) -> Option<(Orceld, Arc<AppApiClient>)> {
    let instance = instance(label);
    let orceld = Orceld::start(&instance)?;
    #[cfg(windows)]
    let client = {
        let client = AppApiClient::with_instance(&instance).expect("endpoint");
        // The client derives the same pipe name orceld serves.
        // Compared without printing either: the names carry the user's SID.
        assert!(
            client.endpoint().name == orceld.endpoint,
            "the client's pipe name differs from the one orceld serves"
        );
        client
    };
    #[cfg(unix)]
    let client = AppApiClient::with_socket(PathBuf::from(&orceld.endpoint));
    Some((orceld, Arc::new(client)))
}

#[test]
fn each_method_answers_against_a_real_orceld() {
    let Some((mut orceld, client)) = live("m") else {
        return;
    };
    let status = client.status().expect("status.get");
    assert_eq!(status.app_api, Field::Shown("orcel-app-api/1".into()));
    assert_eq!(status.name, Field::Shown("orceld".into()));
    assert!(status.mode.shown().is_some(), "{status:?}");
    assert!(status.events.shown().is_some(), "{status:?}");
    assert_eq!(status.withheld, 0, "{status:?}");
    let caps = client.capabilities().expect("capabilities.get");
    assert!(caps.capabilities.iter().any(|row| row.id == "report.task"));
    assert_eq!(caps.withheld, 0);
    assert!(client.tasks().expect("task.list").tasks.is_empty());
    let unknown = TaskId::parse("no-such-task").unwrap();
    assert_eq!(
        client.task(&unknown),
        Err(ClientError::Refused("UNKNOWN_TASK".into()))
    );

    let task_id = orceld.start_report();
    let list = client.tasks().expect("task.list");
    assert_eq!(list.tasks.len(), 1, "{list:?}");
    assert_eq!(list.tasks[0].task_id, task_id);
    assert_eq!(list.tasks[0].state, TaskState::Observed);
    assert_eq!(list.withheld, 0);
    let task = client
        .task(&TaskId::parse(&task_id).expect("task id rule"))
        .expect("task.get");
    assert_eq!(task.folder, Field::Shown("reports".into()));
    assert_eq!(task.sources.len(), 1);
    assert_eq!(task.sources[0].path, Field::Shown("data/q3.csv".into()));
    assert!(task.sources[0].sha256.shown().is_some());
    assert_eq!(task.sources[0].bytes, Field::Shown(Q3_CSV.len() as u64));
    assert_eq!(task.steps.len(), 1);
    assert_eq!(task.steps[0].kind, Known::Known(StepKind::Observe));
    assert_eq!(task.steps[0].outcome, Known::Known(StepOutcome::Ok));
    assert_eq!(task.withheld, 0, "{task:?}");
    let shown = serde_json::to_string(&task).unwrap() + &serde_json::to_string(&list).unwrap();
    assert!(
        !shown.contains("board") && !shown.contains("title"),
        "{shown}"
    );

    // events.subscribe from the start of the ring.
    let window = Window::new(Arc::clone(&client));
    let feed = window.subscribe(None);
    match event_body(next(&feed)) {
        EventBody::DaemonStarted { mode } => assert!(mode.shown().is_some()),
        other => panic!("first event: {other:?}"),
    }
    // The report start's request.completed and task.updated follow.
    let mut kinds = Vec::new();
    for _ in 0..2 {
        kinds.push(event_body(next(&feed)));
    }
    assert!(
        kinds.iter().any(|body| matches!(body, EventBody::TaskUpdated { run_id, state: TaskState::Observed, .. } if *run_id == task_id)),
        "{kinds:?}"
    );
    assert!(kinds.iter().any(|body| matches!(
        body,
        EventBody::RequestCompleted { capability: Field::Shown(c), .. } if c == "report"
    )));
    // A request with no shape: null capability and operation.
    orceld.events(1);
    assert_eq!(
        event_body(next(&feed)),
        EventBody::RequestCompleted {
            capability: Field::Absent,
            operation: Field::Absent,
            ok: Field::Shown(false),
            failure_code: Field::Shown("INVALID_REQUEST".into()),
        }
    );
    println!(
        "SG119-EVIDENCE A1 client on {}: status.get, capabilities.get, task.list, task.get and events.subscribe answered by a live orceld (a test instance) through the identity-checked endpoint; report task {} shown as sanitised metadata without its title",
        std::env::consts::OS,
        task_id
    );
}

#[test]
fn daemon_down_is_a_typed_unavailable() {
    let client = AppApiClient::with_instance(&instance("d")).unwrap();
    assert_eq!(
        client.status(),
        Err(ClientError::Unavailable(Unavailable::NotRunning))
    );
    let window = Window::new(Arc::new(client));
    let feed = window.subscribe(None);
    assert!(matches!(next(&feed), StreamItem::Unavailable { .. }));
}

#[test]
fn a_second_subscribe_cancels_the_first_and_orceld_sees_one_subscriber() {
    let Some((mut orceld, client)) = live("s") else {
        return;
    };
    let window = Window::new(Arc::clone(&client));
    let first = window.subscribe(None);
    assert!(matches!(next(&first), StreamItem::Event { .. }));
    let second = window.subscribe(None);
    assert_eq!(first.next(Duration::from_secs(1)), Next::Ended);
    assert!(matches!(next(&second), StreamItem::Event { .. }));
    // orceld releases the first subscription's slot when its next write to
    // the closed connection fails, so give it something to write.
    let deadline = Instant::now() + WAIT;
    loop {
        orceld.events(1);
        let active = client.status().unwrap().clients.shown().unwrap().active;
        // One subscriber plus this status request: one more connection,
        // never more.
        if active == 2 {
            break;
        }
        assert!(active <= 3, "{active} connections");
        assert!(Instant::now() < deadline, "orceld still counts {active}");
        std::thread::sleep(Duration::from_millis(100));
    }
    drop(window);
    let deadline = Instant::now() + WAIT;
    loop {
        orceld.events(1);
        if client.status().unwrap().clients.shown().unwrap().active == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the window's subscription outlived it"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_stalled_consumer_overflows_the_queue_which_clears_and_resubscribes_into_a_snapshot() {
    let Some((mut orceld, client)) = live("o") else {
        return;
    };
    let window = Window::new(Arc::clone(&client));
    let feed = window.subscribe(None);
    // Deliver daemon.started (seq 1), then stall.
    assert!(matches!(
        event_body(next(&feed)),
        EventBody::DaemonStarted { .. }
    ));
    let delivered = feed.delivered().expect("a delivered cursor");
    assert_eq!(delivered.after_seq(), 1);
    // More than the queue holds: it overflows and is cleared to one marker.
    orceld.events(300);
    let deadline = Instant::now() + WAIT;
    while !feed.overflowed() {
        assert!(
            Instant::now() < deadline,
            "no overflow; {} queued",
            feed.len()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // More than orceld's ring holds, so the delivered cursor (seq 1) can no
    // longer be served.
    orceld.events(1100);
    assert_eq!(feed.len(), 1);
    assert_eq!(next(&feed), StreamItem::Gap);
    match event_body(next(&feed)) {
        EventBody::Snapshot {
            reason,
            resubscribe,
            status,
            ..
        } => {
            assert_eq!(reason, SnapshotReason::Gap);
            assert_eq!(resubscribe.epoch, delivered.epoch());
            assert_eq!(resubscribe.after_seq, 1 + 300 + 1100);
            assert!(status.shown().is_some());
        }
        other => panic!("not a snapshot: {other:?}"),
    }
    // The stream resumes from the snapshot's cursor.
    orceld.events(1);
    assert!(matches!(
        event_body(next(&feed)),
        EventBody::RequestCompleted { .. }
    ));
    assert_eq!(feed.delivered().unwrap().after_seq(), 1 + 300 + 1100 + 1);
}

#[test]
fn a_cursor_of_another_epoch_clears_the_timeline_and_gets_a_snapshot() {
    let Some((mut orceld, client)) = live("e") else {
        return;
    };
    let epoch = client
        .status()
        .unwrap()
        .events
        .shown()
        .unwrap()
        .epoch
        .clone();
    let stale = Cursor::new(&format!("{:x}-{:x}", 1u32, 2u128), 5).unwrap();
    let window = Window::new(Arc::clone(&client));
    let feed = window.subscribe(Some(stale));
    assert_eq!(next(&feed), StreamItem::Cleared);
    match event_body(next(&feed)) {
        EventBody::Snapshot {
            reason,
            resubscribe,
            ..
        } => {
            assert_eq!(reason, SnapshotReason::Epoch);
            assert_eq!(resubscribe.epoch, epoch);
        }
        other => panic!("not a snapshot: {other:?}"),
    }
    orceld.events(1);
    assert!(matches!(
        event_body(next(&feed)),
        EventBody::RequestCompleted { .. }
    ));
}

#[test]
fn a_cursor_ahead_of_orcelds_head_gets_a_gap_snapshot() {
    let Some((mut orceld, client)) = live("g") else {
        return;
    };
    let events = client.status().unwrap().events.shown().unwrap().clone();
    let ahead = Cursor::new(&events.epoch, events.head_seq + 100).unwrap();
    let window = Window::new(Arc::clone(&client));
    let feed = window.subscribe(Some(ahead));
    match event_body(next(&feed)) {
        EventBody::Snapshot {
            reason,
            resubscribe,
            ..
        } => {
            assert_eq!(reason, SnapshotReason::Gap);
            assert_eq!(resubscribe.after_seq, events.head_seq);
        }
        other => panic!("not a snapshot: {other:?}"),
    }
    orceld.events(1);
    assert!(matches!(
        event_body(next(&feed)),
        EventBody::RequestCompleted { .. }
    ));
}

#[cfg(unix)]
#[test]
fn unsubscribe_returns_promptly_while_the_acknowledgement_is_awaited() {
    use std::io::Read;
    use std::os::unix::net::UnixListener;
    let dir = Sandbox::new();
    let path = dir.base.join("r").join("s.sock");
    let listener = UnixListener::bind(&path).expect("bind");
    let (got_request, request) = channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        let _ = got_request.send(());
        // Never acknowledge; read until the client goes away.
        while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
    });
    let client = Arc::new(AppApiClient::with_socket(path));
    let window = Window::new(Arc::clone(&client));
    let _feed = window.subscribe(None);
    request
        .recv_timeout(WAIT)
        .expect("the subscription request");
    let started = Instant::now();
    window.unsubscribe();
    let took = started.elapsed();
    assert!(took < Duration::from_secs(1), "unsubscribe took {took:?}");
    server.join().unwrap();
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::identity::IdentityRefusal;
    use crate::transport::Endpoint;
    use crate::win::{wide, Owned};
    use windows_sys::Win32::Foundation::{
        GetLastError, LocalFree, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        DuplicateTokenEx, GetLengthSid, SecurityImpersonation, SetTokenInformation,
        TokenIntegrityLevel, TokenPrimary, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    };
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile, PIPE_ACCESS_DUPLEX};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::SystemServices::SE_GROUP_INTEGRITY;
    use windows_sys::Win32::System::Threading::{
        CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
        TerminateProcess, WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION,
        STARTUPINFOW,
    };

    /// The environment variable that tells the helper test which instance
    /// to serve. Read by test code only.
    const HELPER_INSTANCE: &str = "ORCEL_A1_TEST_LOW_SERVER_INSTANCE";

    /// orceld's own pipe security: this user only, labeled Medium.
    fn orceld_sddl() -> String {
        let sid = crate::win::current_user_sid().unwrap();
        format!("D:P(A;;GA;;;{sid})S:(ML;;NWNR;;;ME)")
    }

    /// A plain blocking pipe server of `name`, with the security descriptor
    /// `sddl`, or the creator's default security (no label) when `None`.
    fn serve(name: &str, sddl: Option<&str>) -> Owned {
        let wide = wide(name);
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        if let Some(sddl) = sddl {
            let sddl = crate::win::wide(sddl);
            // SAFETY: `sddl` is NUL-terminated; `descriptor` is freed below.
            let made = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            };
            assert_ne!(made, 0, "the test pipe's security descriptor");
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        // SAFETY: `wide` is NUL-terminated; `attributes` and its descriptor
        // live through the call.
        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65_536,
                65_536,
                0,
                if descriptor.is_null() {
                    std::ptr::null()
                } else {
                    &attributes
                },
            )
        };
        if !descriptor.is_null() {
            // SAFETY: freed once, after the pipe copied it.
            unsafe { LocalFree(descriptor) };
        }
        assert_ne!(
            handle,
            INVALID_HANDLE_VALUE,
            "create the test pipe: {}",
            unsafe { GetLastError() }
        );
        Owned(handle)
    }

    /// Waits for a client, then reads until it closes; returns the bytes
    /// it wrote.
    fn received(pipe: &Owned) -> usize {
        // SAFETY: blocking connect on a live server handle.
        unsafe { ConnectNamedPipe(pipe.0, std::ptr::null_mut()) };
        let mut total = 0usize;
        let mut buf = [0u8; 4096];
        loop {
            let mut read = 0u32;
            // SAFETY: `buf` holds its length; blocking read.
            let ok = unsafe {
                ReadFile(
                    pipe.0,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || read == 0 {
                return total;
            }
            total += read as usize;
        }
    }

    #[test]
    fn no_environment_variable_changes_the_endpoint() {
        let sid = crate::win::current_user_sid().unwrap();
        std::env::set_var("ORCEL_APP_API_INSTANCE", "evil");
        std::env::set_var("ORCEL_APP_API", "off");
        let endpoint = Endpoint::for_this_user().unwrap();
        std::env::remove_var("ORCEL_APP_API_INSTANCE");
        std::env::remove_var("ORCEL_APP_API");
        // Compared without printing either: the name carries the user's SID.
        assert!(
            endpoint.name == format!(r"\\.\pipe\orcel-{sid}-app"),
            "the endpoint is not the fixed pipe name"
        );
        // The Windows endpoint code reads no environment at all.
        for (file, source) in [
            ("win.rs", include_str!("win.rs")),
            ("transport.rs", include_str!("transport.rs")),
            ("client.rs", include_str!("client.rs")),
        ] {
            for line in source
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
            {
                assert!(
                    !line.contains("env::var") && !line.contains("var_os"),
                    "{file} reads the environment: {line}"
                );
            }
        }
    }

    #[test]
    fn a_server_of_this_user_at_medium_is_accepted_and_an_over_cap_frame_is_refused() {
        let instance = instance("f");
        let client = AppApiClient::with_instance(&instance).unwrap();
        let pipe = serve(&client.endpoint().name, Some(&orceld_sddl()));
        let server = std::thread::spawn(move || {
            // SAFETY: blocking connect on a live server handle.
            unsafe { ConnectNamedPipe(pipe.0, std::ptr::null_mut()) };
            let mut buf = [0u8; 4096];
            let mut read = 0u32;
            // SAFETY: `buf` holds its length; blocking read of the request.
            unsafe {
                ReadFile(
                    pipe.0,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            let request = String::from_utf8_lossy(&buf[..read as usize]).into_owned();
            let mut over = vec![b' '; crate::frame::MAX_FRAME_BYTES + 10];
            over.push(b'\n');
            let mut written = 0u32;
            // SAFETY: `over` holds its length; blocking write.
            unsafe {
                WriteFile(
                    pipe.0,
                    over.as_ptr(),
                    over.len() as u32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            request
        });
        assert_eq!(client.status(), Err(ClientError::FrameTooLarge));
        let request = server.join().unwrap();
        // The identity check passed, so the request was written.
        assert!(request.contains("\"method\":\"status.get\""), "{request}");
    }

    /// The helper the next test runs at Low integrity: it serves the
    /// instance it is given and passes only when the client wrote nothing.
    /// Without the variable (every ordinary run) it does nothing.
    #[test]
    fn low_integrity_pipe_server_helper() {
        let Some(instance) = std::env::var_os(HELPER_INSTANCE) else {
            return;
        };
        let endpoint = Endpoint::with_instance(instance.to_str().unwrap()).unwrap();
        // Two connections, one at a time: the parent's probe, then the
        // client.
        let pipe = serve(&endpoint.name, None);
        assert_eq!(received(&pipe), 0, "the probe wrote to the helper");
        drop(pipe);
        let pipe = serve(&endpoint.name, None);
        assert_eq!(
            received(&pipe),
            0,
            "the client wrote to a Low integrity server"
        );
    }

    /// Runs this test binary's helper with a Low integrity copy of this
    /// process's token.
    fn spawn_low(instance: &str) -> Owned {
        let mut token: HANDLE = 0;
        // SAFETY: this process's pseudo handle; `token` is closed by `Owned`.
        let opened = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
                &mut token,
            )
        };
        assert_ne!(opened, 0, "open this process's token");
        let token = Owned(token);
        let mut low: HANDLE = 0;
        // SAFETY: `token` is live; `low` is closed by `Owned`.
        let duplicated = unsafe {
            DuplicateTokenEx(
                token.0,
                0,
                std::ptr::null(),
                SecurityImpersonation,
                TokenPrimary,
                &mut low,
            )
        };
        assert_ne!(duplicated, 0, "duplicate the token");
        let low = Owned(low);
        let mut sid = std::ptr::null_mut();
        let low_sid = wide("S-1-16-4096");
        // SAFETY: `low_sid` is NUL-terminated; `sid` is freed below.
        assert_ne!(
            unsafe { ConvertStringSidToSidW(low_sid.as_ptr(), &mut sid) },
            0
        );
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: SE_GROUP_INTEGRITY as u32,
            },
        };
        // SAFETY: `label` and the SID it names live through the call.
        let set = unsafe {
            SetTokenInformation(
                low.0,
                TokenIntegrityLevel,
                (&label as *const TOKEN_MANDATORY_LABEL).cast(),
                std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(sid),
            )
        };
        // SAFETY: freed once, after the token copied it.
        unsafe { LocalFree(sid) };
        assert_ne!(set, 0, "lower the token to Low integrity");

        let exe = std::env::current_exe().unwrap();
        let mut command_line = wide(&format!(
            "\"{}\" --exact live_tests::windows::low_integrity_pipe_server_helper --test-threads=1",
            exe.display()
        ));
        let mut environment: Vec<u16> = Vec::new();
        for (key, value) in std::env::vars_os() {
            if key.to_string_lossy().eq_ignore_ascii_case(HELPER_INSTANCE) {
                continue;
            }
            let entry = format!("{}={}", key.to_string_lossy(), value.to_string_lossy());
            environment.extend(entry.encode_utf16());
            environment.push(0);
        }
        environment.extend(format!("{HELPER_INSTANCE}={instance}").encode_utf16());
        environment.push(0);
        environment.push(0);
        // SAFETY: zeroed STARTUPINFOW with its size set is the documented
        // default.
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        // SAFETY: zeroed is a valid out value.
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let exe_wide = wide(&exe.display().to_string());
        // SAFETY: every pointer is live through the call; the command line is
        // writable as the API requires.
        let created = unsafe {
            CreateProcessAsUserW(
                low.0,
                exe_wide.as_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast(),
                std::ptr::null(),
                &startup,
                &mut info,
            )
        };
        assert_ne!(created, 0, "start the Low integrity helper: {}", unsafe {
            GetLastError()
        });
        drop(Owned(info.hThread));
        Owned(info.hProcess)
    }

    #[test]
    fn a_server_below_medium_integrity_is_refused_before_any_write() {
        let instance = instance("l");
        let client = AppApiClient::with_instance(&instance).unwrap();
        let helper = spawn_low(&instance);
        let deadline = Instant::now() + WAIT;
        // The pipe object a Low integrity process creates is labeled Low: the
        // object check refuses it on its own too.
        let (process, object) = loop {
            if let Some(facts) = crate::win::probe(&client.endpoint().name) {
                break facts;
            }
            assert!(
                Instant::now() < deadline,
                "the helper never served its pipe"
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(
            crate::identity::decide(&process),
            Err(IdentityRefusal::BelowMedium)
        );
        assert_eq!(
            crate::identity::decide_object(&object),
            Err(IdentityRefusal::PipeLabelBelowMedium)
        );
        let refused = loop {
            match client.status() {
                Err(ClientError::Unavailable(Unavailable::NotRunning)) => {
                    assert!(
                        Instant::now() < deadline,
                        "the helper never served its pipe"
                    );
                    std::thread::sleep(Duration::from_millis(50));
                }
                other => break other,
            }
        };
        assert_eq!(
            refused,
            Err(ClientError::NotYours(IdentityRefusal::BelowMedium))
        );
        // SAFETY: a live process handle.
        let waited = unsafe { WaitForSingleObject(helper.0, 20_000) };
        if waited != WAIT_OBJECT_0 {
            // SAFETY: a live process handle.
            unsafe { TerminateProcess(helper.0, 1) };
            panic!("the helper did not finish");
        }
        let mut code = 0u32;
        // SAFETY: a live, exited process handle.
        unsafe { GetExitCodeProcess(helper.0, &mut code) };
        assert_eq!(code, 0, "the helper saw bytes from the client (or failed)");
    }

    /// A same-user, Medium integrity server whose pipe object fails the
    /// object check: it must be refused before any byte is written.
    fn refused_by_the_pipe_object(
        sddl: Option<&str>,
    ) -> Result<crate::sanitize::status::Status, ClientError> {
        let instance = instance("p");
        let client = AppApiClient::with_instance(&instance).unwrap();
        let pipe = serve(&client.endpoint().name, sddl);
        let server = std::thread::spawn(move || received(&pipe));
        let answer = client.status();
        assert_eq!(server.join().unwrap(), 0, "the client wrote to the server");
        answer
    }

    #[test]
    fn a_pipe_labeled_below_medium_is_refused_before_any_write() {
        let sid = crate::win::current_user_sid().unwrap();
        let low = format!("D:P(A;;GA;;;{sid})S:(ML;;NWNR;;;LW)");
        assert_eq!(
            refused_by_the_pipe_object(Some(&low)),
            Err(ClientError::NotYours(IdentityRefusal::PipeLabelBelowMedium))
        );
    }

    #[test]
    fn an_unlabeled_pipe_is_refused_before_any_write() {
        assert_eq!(
            refused_by_the_pipe_object(None),
            Err(ClientError::NotYours(IdentityRefusal::PipeUnlabeled))
        );
    }

    #[test]
    fn unsubscribe_returns_promptly_while_the_acknowledgement_is_awaited() {
        let instance = instance("u");
        let client = Arc::new(AppApiClient::with_instance(&instance).unwrap());
        let pipe = serve(&client.endpoint().name, Some(&orceld_sddl()));
        let (got_request, request) = channel();
        let server = std::thread::spawn(move || {
            // SAFETY: blocking connect on a live server handle.
            unsafe { ConnectNamedPipe(pipe.0, std::ptr::null_mut()) };
            let mut buf = [0u8; 4096];
            let mut read = 0u32;
            // SAFETY: `buf` holds its length; blocking read of the request.
            unsafe {
                ReadFile(
                    pipe.0,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            let _ = got_request.send(());
            // Never acknowledge; read until the client goes away.
            received(&pipe)
        });
        let window = Window::new(Arc::clone(&client));
        let _feed = window.subscribe(None);
        request
            .recv_timeout(WAIT)
            .expect("the subscription request");
        let started = Instant::now();
        window.unsubscribe();
        let took = started.elapsed();
        assert!(took < Duration::from_secs(1), "unsubscribe took {took:?}");
        server.join().unwrap();
    }
}
