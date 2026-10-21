//! CR-01 contract and negative tests for the read-only app API. The
//! transport tests run a real endpoint in-process on each OS (a Unix socket
//! in a private directory, or a named pipe with the production DACL) and
//! talk to it over the OS transport.

use super::*;
use std::sync::atomic::AtomicU64;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn facts() -> DaemonFacts {
    DaemonFacts {
        mode: "CR-01_TEST",
        policy_revision: "test-revision".into(),
        internal_protocol_version: "1".into(),
        capabilities: vec![json!({ "id": "fs", "state": "available", "reason": null })],
    }
}

fn test_limits() -> Limits {
    Limits {
        max_clients: 4,
        ring_capacity: 64,
        max_events_per_second: 1_000,
        write_timeout: Duration::from_millis(500),
        idle_timeout: Duration::from_secs(30),
        heartbeat: Duration::from_millis(200),
    }
}

fn shared_with(limits: Limits) -> Arc<Shared> {
    let log = Arc::new(EventLog::new(limits.ring_capacity, new_epoch()));
    Arc::new(Shared::new(facts(), log, limits, "test".into()))
}

fn own_peer() -> PeerInfo {
    PeerInfo {
        process: process::current_instance().expect("own instance"),
        source: "test",
    }
}

fn request(method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({ "v": PROTOCOL, "id": "r1", "method": method, "params": params }))
        .unwrap()
}

fn reply_frame(reply: Reply) -> Value {
    match reply {
        Reply::Frame(frame) => frame,
        other => panic!("expected a frame, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Frames, methods and the event log (OS independent)
// ---------------------------------------------------------------------------

#[test]
fn cr01_frame_reader_accepts_64_kib_and_refuses_more() {
    let mut exact = vec![b' '; MAX_FRAME_BYTES - 1];
    exact.push(b'\n');
    let mut reader = FrameReader::default();
    let frame = reader.next(&mut exact.as_slice()).unwrap().unwrap();
    assert_eq!(frame.len(), MAX_FRAME_BYTES - 1);

    let over = vec![b'x'; MAX_FRAME_BYTES + 10];
    let mut reader = FrameReader::default();
    assert!(matches!(
        reader.next(&mut over.as_slice()),
        Err(FrameError::TooLarge)
    ));
    // The reader never buffers more than one frame's worth.
    assert!(reader.buf.len() <= MAX_FRAME_BYTES);

    let mut long_line = vec![b'y'; MAX_FRAME_BYTES];
    long_line.push(b'\n');
    let mut reader = FrameReader::default();
    assert!(matches!(
        reader.next(&mut long_line.as_slice()),
        Err(FrameError::TooLarge)
    ));

    let mut reader = FrameReader::default();
    let mut two = b"a\r\nb\n".as_slice();
    assert_eq!(reader.next(&mut two).unwrap().unwrap(), b"a");
    assert_eq!(reader.next(&mut two).unwrap().unwrap(), b"b");
    assert_eq!(reader.next(&mut two).unwrap(), None);
}

#[test]
fn cr01_methods_are_read_only_and_unknown_methods_are_refused() {
    let shared = shared_with(test_limits());
    let peer = own_peer();

    let status = reply_frame(handle_frame(
        &shared,
        &peer,
        &request("status.get", json!({})),
    ));
    assert_eq!(status["ok"], true);
    assert_eq!(status["id"], "r1");
    assert_eq!(status["v"], PROTOCOL);
    assert_eq!(status["result"]["app_api"], PROTOCOL);
    assert_eq!(status["result"]["read_only"], true);
    assert_eq!(status["result"]["peer"]["pid"], std::process::id());

    let caps = reply_frame(handle_frame(
        &shared,
        &peer,
        &request("capabilities.get", Value::Null),
    ));
    assert_eq!(caps["result"]["methods"], json!(METHODS));
    assert_eq!(caps["result"]["capabilities"][0]["id"], "fs");

    // Nothing that submits, approves or mutates exists.
    for method in [
        "task.submit",
        "approval.grant",
        "approval.approve",
        "approval.mint",
        "stop.request",
        "fs.write",
        "request.dispatch",
        "",
    ] {
        let frame = reply_frame(handle_frame(&shared, &peer, &request(method, json!({}))));
        assert_eq!(frame["ok"], false, "{method}");
        assert_eq!(frame["error"]["code"], "UNKNOWN_METHOD", "{method}");
    }
    for method in RESERVED_METHODS {
        let frame = reply_frame(handle_frame(&shared, &peer, &request(method, json!({}))));
        assert_eq!(frame["error"]["code"], "METHOD_UNAVAILABLE", "{method}");
    }

    let wrong_version = br#"{"v":"orcel-app-api/2","id":7,"method":"status.get"}"#;
    let frame = reply_frame(handle_frame(&shared, &peer, wrong_version));
    assert_eq!(frame["error"]["code"], "UNSUPPORTED_VERSION");
    assert_eq!(frame["id"], 7);
    for bad in [
        b"not json".as_slice(),
        b"[1,2]",
        br#"{"v":"orcel-app-api/1","id":{},"method":"status.get"}"#,
        br#"{"v":"orcel-app-api/1","method":"status.get","params":[]}"#,
        br#"{"v":"orcel-app-api/1","method":"events.subscribe","params":{"after_seq":-1}}"#,
        br#"{"v":"orcel-app-api/1","method":"events.subscribe","params":{"cursor":1}}"#,
        // #375 item 4: a cursor without the epoch it belongs to.
        br#"{"v":"orcel-app-api/1","method":"events.subscribe","params":{"after_seq":3}}"#,
        br#"{"v":"orcel-app-api/1","method":"events.subscribe","params":{"after_seq":3,"epoch":null}}"#,
        br#"{"v":"orcel-app-api/1"}"#,
    ] {
        let frame = reply_frame(handle_frame(&shared, &peer, bad));
        assert_eq!(
            frame["error"]["code"],
            "INVALID_REQUEST",
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    assert_eq!(
        handle_frame(
            &shared,
            &peer,
            &request("events.subscribe", json!({ "after_seq": 3, "epoch": "e" }))
        ),
        Reply::Subscribe {
            id: json!("r1"),
            after_seq: 3,
            epoch: Some("e".into()),
        }
    );
    // From the start, the epoch stays optional.
    assert_eq!(
        handle_frame(
            &shared,
            &peer,
            &request("events.subscribe", json!({ "after_seq": 0 }))
        ),
        Reply::Subscribe {
            id: json!("r1"),
            after_seq: 0,
            epoch: None,
        }
    );
}

#[test]
fn cr01_event_log_cursor_gap_and_bounds() {
    let log = EventLog::new(4, "epoch-a".into());
    assert_eq!(
        log.next_after(0, 10, Duration::ZERO),
        Batch::Idle { head: 0 }
    );
    for n in 1..=3 {
        assert_eq!(log.publish("tick", json!({ "n": n })), n);
    }
    let Batch::Events(events) = log.next_after(1, 10, Duration::ZERO) else {
        panic!("events expected");
    };
    assert_eq!(
        events.iter().map(|event| event.seq).collect::<Vec<_>>(),
        [2, 3]
    );
    assert_eq!(
        log.next_after(3, 10, Duration::ZERO),
        Batch::Idle { head: 3 }
    );
    // A cursor ahead of the head (another epoch) is a gap.
    assert_eq!(
        log.next_after(9, 10, Duration::ZERO),
        Batch::Gap { head: 3, oldest: 1 }
    );
    for n in 4..=10 {
        log.publish("tick", json!({ "n": n }));
    }
    // The ring holds 7..=10; cursors before 6 lost events.
    assert_eq!(
        log.next_after(5, 10, Duration::ZERO),
        Batch::Gap {
            head: 10,
            oldest: 7
        }
    );
    assert!(
        matches!(log.next_after(6, 10, Duration::ZERO), Batch::Events(events) if events.len() == 4)
    );
    assert!(
        matches!(log.next_after(6, 2, Duration::ZERO), Batch::Events(events) if events.len() == 2)
    );
    // Oversized data is replaced, so every event fits in a frame.
    log.publish("big", json!({ "blob": "x".repeat(MAX_FRAME_BYTES) }));
    let Batch::Events(events) = log.next_after(10, 1, Duration::ZERO) else {
        panic!("events expected");
    };
    assert_eq!(events[0].data["truncated"], true);
}

#[test]
fn cr01_a_waiting_subscriber_wakes_on_publish() {
    let log = Arc::new(EventLog::new(8, "e".into()));
    let waiter = {
        let log = Arc::clone(&log);
        std::thread::spawn(move || log.next_after(0, 8, Duration::from_secs(30)))
    };
    std::thread::sleep(Duration::from_millis(50));
    log.publish("tick", json!({}));
    assert!(matches!(waiter.join().unwrap(), Batch::Events(events) if events.len() == 1));
}

#[test]
fn cr01_instance_suffix_is_validated() {
    assert_eq!(instance_suffix(None).unwrap(), "");
    assert_eq!(instance_suffix(Some("ci-1".into())).unwrap(), "-ci-1");
    for bad in ["", "UPPER", "a/b", "..", "a b", &"x".repeat(33)] {
        assert!(instance_suffix(Some(bad.into())).is_err(), "{bad:?}");
    }
}

#[test]
fn cr01_request_events_carry_shape_and_outcome_only() {
    let response = orcel_contracts::ResponseEnvelope::failure(
        "req-1",
        orcel_contracts::FailureCode::InvalidRequest,
        "secret-looking detail",
    );
    let data = crate::request_event(&response, Some(("fs.read".into(), "read".into())));
    assert_eq!(data["request_id"], "req-1");
    assert_eq!(data["capability"], "fs.read");
    assert_eq!(data["ok"], false);
    assert!(data["failure_code"].is_string());
    assert!(!data.to_string().contains("secret-looking detail"));
}

#[test]
fn cr01_no_network_listener_in_the_app_api() {
    let source = include_str!("../app_api.rs");
    for needle in [
        "TcpListener",
        "TcpStream",
        "UdpSocket",
        "SocketAddr",
        "to_socket_addrs",
    ] {
        assert!(!source.contains(needle), "{needle} in app_api.rs");
    }
    // The module never reaches dispatch or the approval broker.
    for needle in [
        "handle_envelope",
        "handle_request",
        "ApprovalBroker",
        "dispatch_bridge",
    ] {
        assert!(!source.contains(needle), "{needle} in app_api.rs");
    }
}

// ---------------------------------------------------------------------------
// Peer admission (synthetic seams)
// ---------------------------------------------------------------------------

fn generation(pid: u32) -> ProcessGeneration {
    ProcessGeneration {
        pid,
        generation: 99,
        boot_id: None,
        source: "test",
    }
}

fn pipe_facts() -> PipeClientFacts {
    PipeClientFacts {
        pid: 4242,
        session: Some(1),
        our_session: Some(1),
        same_account: Ok(true),
        process: Ok(generation(4242)),
        still_connected: true,
    }
}

#[test]
fn cr01_pipe_client_admission() {
    assert_eq!(
        admit_pipe(pipe_facts()),
        Ok(PeerInfo {
            process: generation(4242),
            source: WIN32_PIPE_CLIENT,
        })
    );
    assert_eq!(
        admit_pipe(PipeClientFacts {
            pid: 0,
            ..pipe_facts()
        }),
        Err(Refusal::PeerGone(0))
    );
    assert!(matches!(
        admit_pipe(PipeClientFacts {
            session: Some(2),
            ..pipe_facts()
        }),
        Err(Refusal::OtherUser(_))
    ));
    assert!(matches!(
        admit_pipe(PipeClientFacts {
            session: None,
            ..pipe_facts()
        }),
        Err(Refusal::Unavailable(_))
    ));
    assert!(matches!(
        admit_pipe(PipeClientFacts {
            same_account: Ok(false),
            ..pipe_facts()
        }),
        Err(Refusal::OtherUser(_))
    ));
    assert_eq!(
        admit_pipe(PipeClientFacts {
            same_account: Err(PlatformError::ProcessGone(4242)),
            ..pipe_facts()
        }),
        Err(Refusal::PeerGone(4242))
    );
    assert_eq!(
        admit_pipe(PipeClientFacts {
            process: Err(PlatformError::ProcessGone(4242)),
            ..pipe_facts()
        }),
        Err(Refusal::PeerGone(4242))
    );
    assert_eq!(
        admit_pipe(PipeClientFacts {
            still_connected: false,
            ..pipe_facts()
        }),
        Err(Refusal::PeerGone(4242))
    );
}

#[cfg(unix)]
fn unix_identity(uid: u32, source: &'static str) -> orcel_platform::PeerIdentity {
    orcel_platform::PeerIdentity {
        process: generation(4242),
        uid,
        gid: 20,
        audit_session: None,
        source,
    }
}

/// Synthetic: a real peer of another uid needs root to create (and the
/// private directory keeps it from connecting at all; see
/// `cr01_other_user_cannot_reach_the_socket`).
#[cfg(unix)]
#[test]
fn cr01_unix_peer_admission() {
    assert_eq!(
        admit_unix(Ok(unix_identity(501, "linux-so-peerpidfd")), Some(501)),
        Ok(PeerInfo {
            process: generation(4242),
            source: "linux-so-peerpidfd",
        })
    );
    assert!(matches!(
        admit_unix(Ok(unix_identity(0, "macos-local-peertoken")), Some(501)),
        Err(Refusal::OtherUser(_))
    ));
    assert!(matches!(
        admit_unix(Ok(unix_identity(502, "linux-so-peerpidfd")), Some(501)),
        Err(Refusal::OtherUser(_))
    ));
    // #367 item 2: the pid-reuse-racy fallback source is refused.
    assert_eq!(
        admit_unix(Ok(unix_identity(501, "linux-so-peercred")), Some(501)),
        Err(Refusal::WeakIdentity("linux-so-peercred"))
    );
    // #367 item 1: gone, including pid 0, refuses the connection.
    assert_eq!(
        admit_unix(Err(PlatformError::ProcessGone(0)), Some(501)),
        Err(Refusal::PeerGone(0))
    );
    assert_eq!(
        admit_unix(Err(PlatformError::ProcessGone(77)), Some(501)),
        Err(Refusal::PeerGone(77))
    );
    assert!(matches!(
        admit_unix(
            Err(PlatformError::PeerRefused {
                peer_uid: 0,
                expected_uid: 501
            }),
            Some(501)
        ),
        Err(Refusal::OtherUser(_))
    ));
    assert!(matches!(
        admit_unix(
            Err(PlatformError::IdentityUnavailable("x".into())),
            Some(501)
        ),
        Err(Refusal::Unavailable(_))
    ));
    assert!(matches!(
        admit_unix(Ok(unix_identity(501, "linux-so-peerpidfd")), None),
        Err(Refusal::Unavailable(_))
    ));
}

// ---------------------------------------------------------------------------
// A real endpoint and client on each OS
// ---------------------------------------------------------------------------

struct TestServer {
    shared: Arc<Shared>,
    endpoint: String,
    #[cfg(unix)]
    dir: std::path::PathBuf,
}

#[cfg(unix)]
impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A fresh private directory for a test socket (short: `sun_path` limit).
#[cfg(unix)]
fn private_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("cr01-{}", unique()));
    let _ = std::fs::remove_dir_all(&dir);
    orcel_platform::paths::ensure_private_dir(&dir).expect("private test dir");
    dir
}

fn start_server(limits: Limits) -> TestServer {
    let shared = shared_with(limits);
    #[cfg(unix)]
    {
        let dir = private_dir();
        let path = dir.join("s");
        let (listener, bound) = unix::bind(&path).expect("bind test socket");
        let serving = Arc::clone(&shared);
        std::thread::spawn(move || {
            let _bound = bound;
            unix::serve(listener, &serving);
        });
        TestServer {
            shared,
            endpoint: path.display().to_string(),
            dir,
        }
    }
    #[cfg(windows)]
    {
        let name = format!(r"\\.\pipe\orcel-test-cr01-{}", unique());
        let first = win::create_first(&name).expect("create test pipe");
        let serving = Arc::clone(&shared);
        let serve_name = name.clone();
        std::thread::spawn(move || win::serve(&serve_name, first, &serving));
        TestServer {
            shared,
            endpoint: name,
        }
    }
}

struct TestClient {
    conn: Box<dyn Transport + Send>,
    reader: FrameReader,
}

#[cfg(windows)]
fn open_pipe(name: &str) -> io::Result<win::Pipe> {
    use windows_sys::Win32::Foundation::{
        ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
    };
    let wide = win::wide(name);
    for _ in 0..100 {
        // SAFETY: `wide` is NUL-terminated; the handle goes to `Pipe`.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                0,
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            return win::Pipe::from_handle(handle);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_PIPE_BUSY as i32) {
            return Err(error);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "pipe stayed busy"))
}

impl TestClient {
    fn connect(endpoint: &str) -> Self {
        #[cfg(unix)]
        let conn: Box<dyn Transport + Send> =
            Box::new(std::os::unix::net::UnixStream::connect(endpoint).expect("connect"));
        #[cfg(windows)]
        let conn: Box<dyn Transport + Send> = Box::new(open_pipe(endpoint).expect("open pipe"));
        let mut client = Self {
            conn,
            reader: FrameReader::default(),
        };
        client
            .conn
            .set_timeouts(Some(Duration::from_secs(20)), Some(Duration::from_secs(20)))
            .unwrap();
        client
    }

    fn send_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.conn.write_all(bytes)?;
        self.conn.flush()
    }

    fn send(&mut self, method: &str, params: Value) {
        let mut bytes = request(method, params);
        bytes.push(b'\n');
        self.send_raw(&bytes).expect("send request");
    }

    /// The next frame, or `None` once the server closed the connection.
    fn recv(&mut self) -> Option<Value> {
        match self.reader.next(&mut self.conn) {
            Ok(Some(frame)) => Some(serde_json::from_slice(&frame).expect("frame is JSON")),
            Ok(None) => None,
            Err(FrameError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                ) =>
            {
                None
            }
            Err(error) => panic!("receive failed: {error:?}"),
        }
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        self.send(method, params);
        self.recv().expect("a response")
    }

    /// The next frame that is not a heartbeat.
    fn recv_event(&mut self) -> Option<Value> {
        loop {
            let frame = self.recv()?;
            if frame.get("heartbeat").is_none() {
                return Some(frame);
            }
        }
    }
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn cr01_status_roundtrip_over_the_os_transport() {
    let server = start_server(test_limits());
    let mut client = TestClient::connect(&server.endpoint);
    let status = client.call("status.get", json!({}));
    assert_eq!(status["ok"], true, "{status}");
    assert_eq!(status["result"]["app_api"], PROTOCOL);
    assert_eq!(status["result"]["os"], std::env::consts::OS);
    assert_eq!(status["result"]["read_only"], true);
    // The peer the server admitted is this test process.
    assert_eq!(status["result"]["peer"]["pid"], std::process::id());
    assert_eq!(status["result"]["clients"]["active"], 1);
    let caps = client.call("capabilities.get", json!({}));
    assert_eq!(caps["result"]["read_only"], true);
    assert_eq!(caps["result"]["methods"], json!(METHODS));
    let unknown = client.call("approval.grant", json!({ "approval_id": "a" }));
    assert_eq!(unknown["error"]["code"], "UNKNOWN_METHOD");
    let reserved = client.call("task.list", json!({}));
    assert_eq!(reserved["error"]["code"], "METHOD_UNAVAILABLE");
    // The connection survives refused requests.
    assert_eq!(client.call("status.get", json!({}))["ok"], true);
    drop(client);
    wait_until("the slot to be released", || {
        server.shared.active.load(Ordering::Acquire) == 0
    });
}

#[test]
fn cr01_oversize_frame_is_refused_over_the_os_transport() {
    let server = start_server(test_limits());
    let mut client = TestClient::connect(&server.endpoint);
    // Exactly at the bound: served.
    let mut exact = request("status.get", json!({}));
    exact.resize(MAX_FRAME_BYTES - 1, b' ');
    exact.push(b'\n');
    client.send_raw(&exact).unwrap();
    assert_eq!(client.recv().unwrap()["ok"], true);
    // One byte over, without a newline: refused and closed.
    let _ = client.send_raw(&vec![b'x'; MAX_FRAME_BYTES + 1]);
    let refused = client.recv().expect("a refusal frame");
    assert_eq!(refused["error"]["code"], "FRAME_TOO_LARGE");
    assert_eq!(client.recv(), None);
}

#[test]
fn cr01_subscription_resumes_from_a_cursor() {
    let server = start_server(test_limits());
    let log = Arc::clone(&server.shared.log);
    for n in 1..=5 {
        log.publish("tick", json!({ "n": n }));
    }
    let mut client = TestClient::connect(&server.endpoint);
    let epoch = log.epoch().to_owned();
    client.send(
        "events.subscribe",
        json!({ "after_seq": 2, "epoch": epoch }),
    );
    let ack = client.recv().unwrap();
    assert_eq!(ack["ok"], true, "{ack}");
    assert_eq!(ack["result"]["head_seq"], 5);
    assert_eq!(ack["result"]["epoch"], epoch.as_str());
    for seq in 3..=5 {
        let frame = client.recv_event().unwrap();
        assert_eq!(frame["event"]["seq"], seq);
        assert_eq!(frame["event"]["kind"], "tick");
        assert_eq!(frame["event"]["epoch"], epoch.as_str());
        assert_eq!(frame["id"], "r1");
    }
    log.publish("tick", json!({ "n": 6 }));
    assert_eq!(client.recv_event().unwrap()["event"]["seq"], 6);
    // Idle subscriptions get heartbeats with the head.
    let heartbeat = client.recv().unwrap();
    assert_eq!(heartbeat["heartbeat"]["head_seq"], 6);
    drop(client);

    // Resume where the last connection stopped: only new events arrive.
    let mut client = TestClient::connect(&server.endpoint);
    client.send(
        "events.subscribe",
        json!({ "after_seq": 6, "epoch": epoch }),
    );
    assert_eq!(client.recv().unwrap()["ok"], true);
    log.publish("tick", json!({ "n": 7 }));
    let next = client.recv_event().unwrap();
    assert_eq!(next["event"]["seq"], 7);
    assert_eq!(next["event"]["data"]["n"], 7);
}

#[test]
fn cr01_gap_and_restart_answer_with_a_snapshot() {
    let server = start_server(Limits {
        ring_capacity: 4,
        ..test_limits()
    });
    let log = Arc::clone(&server.shared.log);
    for n in 1..=10 {
        log.publish("tick", json!({ "n": n }));
    }
    let epoch = log.epoch().to_owned();
    // Gap: events after 1 were dropped from the ring.
    let mut client = TestClient::connect(&server.endpoint);
    client.send(
        "events.subscribe",
        json!({ "after_seq": 1, "epoch": epoch }),
    );
    assert_eq!(client.recv().unwrap()["ok"], true);
    let snapshot = client.recv_event().unwrap();
    assert_eq!(snapshot["event"]["kind"], "snapshot", "{snapshot}");
    assert_eq!(snapshot["event"]["data"]["reason"], "gap");
    assert_eq!(snapshot["event"]["data"]["head_seq"], 10);
    assert_eq!(snapshot["event"]["data"]["oldest_seq"], 7);
    assert_eq!(snapshot["event"]["data"]["status"]["app_api"], PROTOCOL);
    assert_eq!(
        client.recv(),
        None,
        "the subscription ends after a snapshot"
    );

    // Restart: a cursor from another daemon epoch gets a snapshot.
    let mut client = TestClient::connect(&server.endpoint);
    client.send(
        "events.subscribe",
        json!({ "after_seq": 3, "epoch": "previous-daemon" }),
    );
    assert_eq!(client.recv().unwrap()["ok"], true);
    let snapshot = client.recv_event().unwrap();
    assert_eq!(snapshot["event"]["data"]["reason"], "epoch");
    let resume = snapshot["event"]["data"]["resubscribe"].clone();
    assert_eq!(resume["after_seq"], 10);
    assert_eq!(client.recv(), None);

    // A cursor past the head of this run is a gap too.
    let mut client = TestClient::connect(&server.endpoint);
    client.send(
        "events.subscribe",
        json!({ "after_seq": 500, "epoch": epoch }),
    );
    assert_eq!(client.recv().unwrap()["ok"], true);
    assert_eq!(
        client.recv_event().unwrap()["event"]["data"]["reason"],
        "gap"
    );

    // #375 item 4: a cursor without its epoch is refused, never served
    // from whatever run is current; the connection stays usable.
    let mut client = TestClient::connect(&server.endpoint);
    let refused = client.call("events.subscribe", json!({ "after_seq": 3 }));
    assert_eq!(refused["error"]["code"], "INVALID_REQUEST", "{refused}");
    assert_eq!(client.call("status.get", json!({}))["ok"], true);

    // Resubscribing from the snapshot resumes cleanly.
    let mut client = TestClient::connect(&server.endpoint);
    client.send("events.subscribe", resume);
    assert_eq!(client.recv().unwrap()["ok"], true);
    log.publish("tick", json!({ "n": 11 }));
    assert_eq!(client.recv_event().unwrap()["event"]["seq"], 11);
}

#[test]
fn cr01_a_slow_client_never_blocks_the_publisher() {
    let server = start_server(Limits {
        ring_capacity: 32,
        write_timeout: Duration::from_millis(300),
        ..test_limits()
    });
    let log = Arc::clone(&server.shared.log);
    let mut client = TestClient::connect(&server.endpoint);
    client.send("events.subscribe", json!({ "after_seq": 0 }));
    // The client stops reading. The publisher keeps going regardless.
    let payload = "p".repeat(1024);
    let started = Instant::now();
    for n in 0..20_000u32 {
        log.publish("bulk", json!({ "n": n, "payload": payload }));
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "publishing 20,000 events took {elapsed:?}"
    );
    assert_eq!(log.head(), 20_000);
    // The subscriber fell behind the ring (snapshot) or timed out writing;
    // either way its connection and slot are released.
    wait_until("the slow client to be dropped", || {
        server.shared.active.load(Ordering::Acquire) == 0
    });
    let mut frames = 0usize;
    let mut last = Value::Null;
    while let Some(frame) = client.recv() {
        frames += 1;
        last = frame;
    }
    assert!(frames < 20_000, "the server streamed {frames} frames");
    if last.get("event").is_some() && last["event"]["kind"] == "snapshot" {
        assert_eq!(last["event"]["data"]["reason"], "gap");
    }
    // The endpoint still serves new clients.
    let mut fresh = TestClient::connect(&server.endpoint);
    assert_eq!(fresh.call("status.get", json!({}))["ok"], true);
}

#[test]
fn cr01_concurrent_clients_are_bounded() {
    let server = start_server(Limits {
        max_clients: 2,
        ..test_limits()
    });
    let mut first = TestClient::connect(&server.endpoint);
    let mut second = TestClient::connect(&server.endpoint);
    assert_eq!(first.call("status.get", json!({}))["ok"], true);
    assert_eq!(second.call("status.get", json!({}))["ok"], true);
    let mut third = TestClient::connect(&server.endpoint);
    let busy = third.recv().expect("a busy frame");
    assert_eq!(busy["error"]["code"], "BUSY");
    assert_eq!(third.recv(), None);
    drop(first);
    wait_until("a slot to free up", || {
        server.shared.active.load(Ordering::Acquire) < 2
    });
    let mut fourth = TestClient::connect(&server.endpoint);
    assert_eq!(fourth.call("status.get", json!({}))["ok"], true);
}

// ---------------------------------------------------------------------------
// A peer that has gone away
// ---------------------------------------------------------------------------

const HELPER_ENDPOINT: &str = "CR01_APP_API_HELPER_ENDPOINT";

/// The child half of `cr01_a_peer_that_has_gone_away_is_refused`: it
/// connects and exits at once. Run on its own, without the variable, it
/// does nothing.
#[test]
fn cr01_peer_helper_child() {
    let Some(endpoint) = std::env::var_os(HELPER_ENDPOINT) else {
        return;
    };
    let endpoint = endpoint.into_string().unwrap();
    #[cfg(unix)]
    drop(std::os::unix::net::UnixStream::connect(endpoint).expect("connect"));
    #[cfg(windows)]
    drop(open_pipe(&endpoint).expect("open pipe"));
}

fn run_helper_child(endpoint: &str) {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "app_api::tests::cr01_peer_helper_child",
            "--test-threads=1",
        ])
        .env(HELPER_ENDPOINT, endpoint)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run helper");
    assert!(status.success());
}

#[cfg(unix)]
#[test]
fn cr01_a_peer_that_has_gone_away_is_refused() {
    let dir = private_dir();
    let path = dir.join("s");
    let (listener, _bound) = unix::bind(&path).unwrap();
    // The helper connects and exits before the server looks at it.
    run_helper_child(path.to_str().unwrap());
    let (stream, _) = listener.accept().unwrap();
    let admitted = admit_unix(
        orcel_platform::peer::unix_peer_credentials(&stream),
        orcel_platform::session::effective_uid(),
    );
    assert!(
        matches!(admitted, Err(Refusal::PeerGone(_))),
        "an exited peer was read as {admitted:?}"
    );
    drop((stream, listener));
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn cr01_a_peer_that_has_gone_away_is_refused() {
    let name = format!(r"\\.\pipe\orcel-test-cr01-{}", unique());
    let first = win::create_first(&name).unwrap();
    run_helper_child(&name);
    // The client connected and exited: either the connect itself reports
    // that it is gone, or the admission refuses it.
    match first.connect() {
        Err(error) => assert_eq!(
            error.raw_os_error(),
            Some(windows_sys::Win32::Foundation::ERROR_NO_DATA as i32),
            "{error}"
        ),
        Ok(()) => {
            let admitted = admit_pipe(win::client_facts(&first));
            assert!(
                matches!(admitted, Err(Refusal::PeerGone(_))),
                "an exited client was read as {admitted:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Unix endpoint location
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn our_uid() -> u32 {
    orcel_platform::session::effective_uid().unwrap()
}

#[cfg(unix)]
#[test]
fn cr01_socket_and_directory_are_private() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let dir = private_dir();
    let path = dir.join("s");
    let (_listener, _bound) = unix::bind(&path).unwrap();
    let socket = std::fs::symlink_metadata(&path).unwrap();
    assert_eq!(socket.permissions().mode() & 0o777, 0o600);
    assert_eq!(socket.uid(), our_uid());
    let parent = std::fs::symlink_metadata(&dir).unwrap();
    assert_eq!(parent.permissions().mode() & 0o777, 0o700);
    assert_eq!(parent.uid(), our_uid());
    drop((_listener, _bound));
    // Dropping the binding removes the socket it created.
    assert!(!path.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn cr01_a_directory_others_can_reach_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = private_dir();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let refused = unix::bind(&dir.join("s"));
    assert!(
        matches!(refused, Err(StartError::Refused(_))),
        "{:?}",
        refused.map(|_| ())
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn cr01_a_symlinked_socket_path_is_refused_and_left_alone() {
    let dir = private_dir();
    let target = dir.join("target");
    std::fs::write(&target, b"keep").unwrap();
    let path = dir.join("s");
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let refused = unix::bind(&path).map(|_| ());
    assert!(
        matches!(&refused, Err(StartError::Refused(reason)) if reason.contains("symbolic link")),
        "{refused:?}"
    );
    assert!(std::fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    // A symlink to a live socket is refused as well.
    let real = dir.join("real");
    let _live = std::os::unix::net::UnixListener::bind(&real).unwrap();
    let link = dir.join("l");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(matches!(unix::bind(&link), Err(StartError::Refused(_))));
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn cr02_a_socket_path_over_the_sun_path_limit_is_refused_with_its_reason() {
    let dir = private_dir();
    let name = "s".repeat(120);
    let path = dir.join(&name);
    let refused = unix::bind(&path).map(|_| ());
    assert!(
        matches!(&refused, Err(StartError::Refused(reason))
            if reason.contains("longer than the 100") && reason.contains("XDG_STATE_HOME")),
        "{refused:?}"
    );
    // Nothing was created or truncated to a shorter name.
    assert!(std::fs::symlink_metadata(&path).is_err());
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn cr01_a_path_that_is_not_a_socket_is_left_alone() {
    let dir = private_dir();
    let path = dir.join("s");
    std::fs::write(&path, b"data").unwrap();
    assert!(matches!(unix::bind(&path), Err(StartError::Refused(_))));
    assert_eq!(std::fs::read(&path).unwrap(), b"data");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn cr01_stale_sockets_are_replaced_and_live_ones_kept() {
    let dir = private_dir();
    let path = dir.join("s");
    // Stale: a socket of ours that nobody serves.
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    assert!(path.exists());
    let (listener, bound) = unix::bind(&path).expect("stale socket replaced");
    // Live: another server answers there; it is neither removed nor taken.
    let again = unix::bind(&path).map(|_| ());
    assert!(matches!(again, Err(StartError::InUse(_))), "{again:?}");
    assert!(std::fs::symlink_metadata(&path).is_ok());
    drop((listener, bound));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Synthetic: a socket owned by another user needs root to create.
#[cfg(unix)]
#[test]
fn cr01_a_socket_owned_by_another_user_is_refused() {
    use unix::{stale_decision, Existing, Stale};
    let ours = 501;
    let refused = stale_decision(Existing::Socket { owner: 0 }, ours, unreachable_probe);
    assert!(
        matches!(&refused, Err(StartError::Refused(reason)) if reason.contains("uid 0")),
        "{refused:?}"
    );
    assert!(matches!(
        stale_decision(Existing::Socket { owner: 502 }, ours, unreachable_probe),
        Err(StartError::Refused(_))
    ));
    assert_eq!(
        stale_decision(Existing::Socket { owner: ours }, ours, || false),
        Ok(Stale::RemoveThenBind)
    );
    assert!(matches!(
        stale_decision(Existing::Socket { owner: ours }, ours, || true),
        Err(StartError::InUse(_))
    ));
    assert_eq!(
        stale_decision(Existing::Missing, ours, unreachable_probe),
        Ok(Stale::Bind)
    );
    assert!(stale_decision(Existing::Symlink, ours, unreachable_probe).is_err());
    assert!(stale_decision(Existing::NotSocket, ours, unreachable_probe).is_err());
}

/// The liveness probe must not run for anything but a socket of ours.
#[cfg(unix)]
fn unreachable_probe() -> bool {
    panic!("the liveness probe ran for an endpoint that is not ours")
}

/// Real other-user evidence, run by CI (`ORCEL_APP_API_OTHER_USER_TEST=1`)
/// where passwordless sudo exists: `nobody` cannot connect to the socket,
/// because it cannot enter the private directory.
#[cfg(unix)]
#[test]
fn cr01_other_user_cannot_reach_the_socket() {
    if std::env::var_os("ORCEL_APP_API_OTHER_USER_TEST").is_none() {
        eprintln!("skipped: set ORCEL_APP_API_OTHER_USER_TEST=1 with passwordless sudo");
        return;
    }
    let sudo_ok = std::process::Command::new("sudo")
        .args(["-n", "-u", "nobody", "true"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    assert!(sudo_ok, "the other-user test needs `sudo -n -u nobody`");
    let server = start_server(test_limits());
    let probe = "import socket,sys\n\
                 s=socket.socket(socket.AF_UNIX)\n\
                 try:\n    s.connect(sys.argv[1])\n\
                 except PermissionError:\n    sys.exit(13)\n\
                 except OSError as e:\n    print(e); sys.exit(2)\n\
                 sys.exit(0)\n";
    let output = std::process::Command::new("sudo")
        .args([
            "-n",
            "-u",
            "nobody",
            "python3",
            "-c",
            probe,
            &server.endpoint,
        ])
        .output()
        .expect("run the probe as nobody");
    assert_eq!(
        output.status.code(),
        Some(13),
        "nobody's connect was not refused with EACCES: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    // Nothing reached the server.
    assert_eq!(server.shared.active.load(Ordering::Acquire), 0);
    // This user still can.
    let mut client = TestClient::connect(&server.endpoint);
    assert_eq!(client.call("status.get", json!({}))["ok"], true);
}

// ---------------------------------------------------------------------------
// Windows named pipe
// ---------------------------------------------------------------------------

#[cfg(windows)]
#[test]
fn cr01_pipe_dacl_is_the_current_user_only() {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

    let name = format!(r"\\.\pipe\orcel-test-cr01-{}", unique());
    let pipe = win::create_first(&name).unwrap();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the pipe handle is live; `descriptor` receives a LocalAlloc'd
    // descriptor freed below.
    let status = unsafe {
        GetSecurityInfo(
            pipe.handle.0,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    assert_eq!(status, 0, "GetSecurityInfo failed");
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: `descriptor` is live; `text` receives a LocalAlloc'd string.
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(converted, 0);
    // SAFETY: `text` is NUL-terminated; both allocations are freed once.
    let sddl = unsafe {
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let sddl = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        LocalFree(descriptor.cast());
        sddl
    };
    let sid = win::current_user_sid().unwrap();
    assert!(sddl.starts_with("D:P"), "not protected: {sddl}");
    assert_eq!(sddl.matches('(').count(), 1, "more than one ACE: {sddl}");
    assert!(sddl.contains("(A;"), "{sddl}");
    // SDDL may print a well-known account as an alias (the built-in
    // Administrator, RID 500, is "LA"), so the trustee is resolved to a SID
    // and compared as one.
    let trustee = sddl
        .rsplit(";;;")
        .next()
        .and_then(|rest| rest.strip_suffix(')'))
        .expect("an ACE trustee");
    assert_eq!(sid_string_of(trustee), sid, "{sddl}");
    for group in [
        ";WD)", ";AU)", ";BU)", ";AN)", ";IU)", ";NU)", ";SY)", ";BA)",
    ] {
        assert!(!sddl.contains(group), "{group} in {sddl}");
    }
    assert_eq!(
        win::sddl(&sid),
        format!("D:P(A;;GA;;;{sid})S:(ML;;NWNR;;;ME)")
    );
}

/// The `S-1-...` form of an SDDL trustee, which may be an alias like `LA`.
#[cfg(windows)]
fn sid_string_of(trustee: &str) -> String {
    use windows_sys::Win32::Foundation::{LocalFree, PSID};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSidToSidW,
    };
    let wide = win::wide(trustee);
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated; `sid` receives a LocalAlloc'd SID.
    assert_ne!(
        unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) },
        0,
        "unknown trustee {trustee}"
    );
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` is live; `text` receives a LocalAlloc'd string.
    assert_ne!(unsafe { ConvertSidToStringSidW(sid, &mut text) }, 0);
    // SAFETY: `text` is NUL-terminated; both allocations are freed once.
    unsafe {
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        LocalFree(sid);
        out
    }
}

#[test]
#[cfg(windows)]
fn cr01_sddl_aliases_resolve_to_their_sid() {
    // A well-known alias resolves to its SID, and a SID string to itself.
    assert_eq!(sid_string_of("WD"), "S-1-1-0");
    let sid = win::current_user_sid().unwrap();
    assert_eq!(sid_string_of(&sid), sid);
}

#[cfg(windows)]
#[test]
fn cr01_a_second_server_cannot_take_the_pipe_name() {
    let name = format!(r"\\.\pipe\orcel-test-cr01-{}", unique());
    let _first = win::create_first(&name).unwrap();
    let taken = win::create_first(&name).map(|_| ());
    // #375 item 1: the reason names who holds it; here, this account.
    assert!(
        matches!(&taken, Err(StartError::InUse(reason))
            if reason.contains("already exists") && reason.contains("runs as this account")),
        "{taken:?}"
    );
    // The owner can still add instances of its own pipe.
    let _more = win::create_instance(&name, false).unwrap();
}

#[cfg(windows)]
#[test]
fn cr01_the_default_pipe_name_carries_the_user_sid() {
    let sid = win::current_user_sid().unwrap();
    assert_eq!(
        win::pipe_name("").unwrap(),
        format!(r"\\.\pipe\orcel-{sid}-app")
    );
    assert_eq!(
        win::pipe_name("-ci").unwrap(),
        format!(r"\\.\pipe\orcel-{sid}-app-ci")
    );
}

// ---------------------------------------------------------------------------
// #375 items 1 and 5: endpoint waits and streaming peer re-checks
// ---------------------------------------------------------------------------

#[test]
fn cr375_an_endpoint_held_by_another_server_is_noted_once_and_reported() {
    let shared = shared_with(test_limits());
    let peer = own_peer();
    let status = reply_frame(handle_frame(
        &shared,
        &peer,
        &request("status.get", json!({})),
    ));
    assert_eq!(status["result"]["endpoint_wait"], Value::Null);
    // The first attempt is the one that logs; later ones only count.
    assert!(shared.note_in_use("the pipe name already exists; squatted"));
    assert!(!shared.note_in_use("the pipe name already exists; squatted"));
    assert!(!shared.note_in_use("something else"));
    let status = reply_frame(handle_frame(
        &shared,
        &peer,
        &request("status.get", json!({})),
    ));
    let wait = &status["result"]["endpoint_wait"];
    assert_eq!(wait["attempts"], 3, "{wait}");
    assert_eq!(wait["reason"], "the pipe name already exists; squatted");
    assert!(wait["since_ms"].as_u64().unwrap() > 0);
}

/// A connection that records what the server writes and never sends.
#[derive(Default)]
struct Recorder {
    written: Vec<u8>,
}

impl Read for Recorder {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl Write for Recorder {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Transport for Recorder {
    fn set_timeouts(
        &mut self,
        _read: Option<Duration>,
        _write: Option<Duration>,
    ) -> io::Result<()> {
        Ok(())
    }

    fn finish(&mut self) {}
}

#[test]
fn cr375_a_subscription_ends_once_its_peer_is_no_longer_the_admitted_instance() {
    let shared = shared_with(test_limits());
    // Our own pid with a start generation it never had: what a reused pid
    // looks like once the admitted peer exited.
    let mut process = process::current_instance().expect("own instance");
    process.generation = process.generation.wrapping_add(1);
    let stale = PeerInfo {
        process,
        source: "test",
    };
    let (done, finished) = std::sync::mpsc::channel();
    let streaming = Arc::clone(&shared);
    std::thread::spawn(move || {
        let mut conn = Recorder::default();
        stream_events(&mut conn, &streaming, &stale, &json!("s1"), 0, None);
        let _ = done.send(conn.written);
    });
    // The heartbeat is 200 ms: the first idle wake-up re-reads the peer.
    let written = finished
        .recv_timeout(Duration::from_secs(10))
        .expect("the subscription of a stale peer ended");
    let frames: Vec<Value> = written
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_eq!(frames[0]["ok"], true);
    assert!(frames.iter().all(|frame| frame.get("heartbeat").is_none()));

    // The same stream for the live peer keeps going with heartbeats.
    let (done, finished) = std::sync::mpsc::channel();
    let streaming = Arc::clone(&shared);
    std::thread::spawn(move || {
        struct Counted(Recorder, std::sync::mpsc::Sender<()>);
        impl Read for Counted {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.0.read(buf)
            }
        }
        impl Write for Counted {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if self.1.send(()).is_err() {
                    return Err(io::Error::from(io::ErrorKind::BrokenPipe));
                }
                self.0.write(buf)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl Transport for Counted {
            fn set_timeouts(
                &mut self,
                _read: Option<Duration>,
                _write: Option<Duration>,
            ) -> io::Result<()> {
                Ok(())
            }
            fn finish(&mut self) {}
        }
        let mut conn = Counted(Recorder::default(), done);
        stream_events(&mut conn, &streaming, &own_peer(), &json!("s2"), 0, None);
    });
    // The acknowledgement and then at least two heartbeats arrive.
    for _ in 0..3 {
        finished
            .recv_timeout(Duration::from_secs(10))
            .expect("a live peer keeps its subscription");
    }
    drop(finished);
}

// ---------------------------------------------------------------------------
// #381: a short socket location whatever HOME is
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn env_lookup(pairs: &[(&str, String)]) -> impl Fn(&str) -> Option<std::ffi::OsString> {
    let pairs: Vec<(String, String)> = pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), value.clone()))
        .collect();
    move |name: &str| {
        pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into())
    }
}

#[cfg(unix)]
fn long_home() -> String {
    format!("/home/{}", "a-very-long-home-directory-name".repeat(5))
}

#[cfg(unix)]
#[test]
fn cr381_the_socket_directory_does_not_depend_on_home() {
    use orcel_platform::paths::StateLayout;
    use std::path::PathBuf;
    let home = long_home();
    assert!(home.len() > unix::MAX_SOCKET_PATH);

    // macOS: the per-user temp directory confstr names, whatever HOME is.
    let darwin = Some(PathBuf::from(
        "/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T/",
    ));
    let lookup = env_lookup(&[("HOME", home.clone())]);
    let dir = unix::socket_dir(StateLayout::MacOs, &lookup, darwin, &|_| true).unwrap();
    assert_eq!(
        dir,
        PathBuf::from("/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T/orcel")
    );
    // The longest instance suffix still fits in sun_path there.
    let socket = dir.join(format!("app-api-{}.sock", "x".repeat(32)));
    assert!(
        socket.as_os_str().len() <= unix::MAX_SOCKET_PATH,
        "{socket:?}"
    );
    // Without an answer from confstr: the state root, as in CR-01.
    assert_eq!(
        unix::socket_dir(StateLayout::MacOs, &lookup, None, &|_| true).unwrap(),
        PathBuf::from(&home).join("Library/Application Support/Orcel/run")
    );

    // Linux: $XDG_RUNTIME_DIR/orcel, whatever HOME and XDG_STATE_HOME are.
    let lookup = env_lookup(&[
        ("HOME", home.clone()),
        ("XDG_STATE_HOME", format!("{home}/.state")),
        ("XDG_RUNTIME_DIR", "/run/user/1000".into()),
    ]);
    assert_eq!(
        unix::socket_dir(StateLayout::Xdg, &lookup, None, &|_| true).unwrap(),
        PathBuf::from("/run/user/1000/orcel")
    );
    // confstr is macOS only; it never decides a Linux location.
    assert_eq!(
        unix::socket_dir(
            StateLayout::Xdg,
            &lookup,
            Some(PathBuf::from("/x")),
            &|_| true
        )
        .unwrap(),
        PathBuf::from("/run/user/1000/orcel")
    );
    // A relative or dotted XDG_RUNTIME_DIR is ignored, as XDG requires.
    for bad in ["run/user/1000", "/run/user/../1000", ""] {
        let lookup = env_lookup(&[("HOME", "/home/a".into()), ("XDG_RUNTIME_DIR", bad.into())]);
        assert_eq!(
            unix::socket_dir(StateLayout::Xdg, &lookup, None, &|_| true).unwrap(),
            PathBuf::from("/home/a/.local/state/orcel/run"),
            "{bad:?}"
        );
    }
    // No runtime directory and no usable HOME: no location at all.
    assert!(unix::socket_dir(StateLayout::Xdg, &env_lookup(&[]), None, &|_| true).is_err());
}

/// The production location, resolved with a long HOME (and, on Linux, a
/// long XDG_STATE_HOME), binds, serves and is removed on exit.
#[cfg(unix)]
#[test]
fn cr381_a_long_home_still_gets_the_app_api() {
    use orcel_platform::paths::StateLayout;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let home = long_home();
    let layout = StateLayout::current().unwrap();
    #[cfg(target_os = "macos")]
    let (lookup, runtime, darwin) = {
        let darwin = orcel_platform::paths::macos_per_user_runtime_dir()
            .expect("confstr(_CS_DARWIN_USER_TEMP_DIR)");
        (
            env_lookup(&[("HOME", home.clone())]),
            None::<std::path::PathBuf>,
            Some(darwin),
        )
    };
    #[cfg(not(target_os = "macos"))]
    let (lookup, runtime, darwin) = {
        let runtime = private_dir();
        let lookup = env_lookup(&[
            ("HOME", home.clone()),
            ("XDG_STATE_HOME", format!("{home}/.state")),
            ("XDG_RUNTIME_DIR", runtime.display().to_string()),
        ]);
        (lookup, Some(runtime), None)
    };
    let dir = unix::socket_dir(layout, &lookup, darwin, &unix::runtime_dir_is_private).unwrap();
    assert!(!dir.starts_with(&home), "{dir:?} is below HOME");
    let path = dir.join(format!("app-api-t{}.sock", unique()));
    assert!(path.as_os_str().len() <= unix::MAX_SOCKET_PATH, "{path:?}");

    let shared = shared_with(test_limits());
    let (listener, bound) = unix::bind(&path).expect("bind under the runtime directory");
    let meta = std::fs::symlink_metadata(&dir).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    assert_eq!(meta.uid(), our_uid());
    let serving = Arc::clone(&shared);
    let server = std::thread::spawn(move || unix::serve(listener, &serving));
    let mut client = TestClient::connect(path.to_str().unwrap());
    assert_eq!(client.call("status.get", json!({}))["ok"], true);
    drop(client);
    drop(bound);
    assert!(!path.exists(), "the socket outlived its binding");
    drop(server);
    let _ = std::fs::remove_file(unix::lock_path(&path));
    if let Some(runtime) = runtime {
        let _ = std::fs::remove_dir_all(runtime);
    }
}

// ---------------------------------------------------------------------------
// #375 item 3: one endpoint per user
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn inode(path: &std::path::Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path).expect("the socket exists");
    (meta.dev(), meta.ino())
}

#[cfg(unix)]
#[test]
fn cr375_concurrent_instances_never_unlink_a_live_socket() {
    use std::os::unix::net::UnixStream;
    use std::sync::Barrier;
    const CONTENDERS: usize = 6;
    for round in 0..40 {
        let dir = private_dir();
        let path = dir.join("s");
        // Every round starts from a stale socket, the case where each
        // contender would decide to remove it.
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let barrier = Arc::new(Barrier::new(CONTENDERS));
        let contenders: Vec<_> = (0..CONTENDERS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let path = path.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    unix::bind(&path)
                })
            })
            .collect();
        let results: Vec<_> = contenders
            .into_iter()
            .map(|contender| contender.join().unwrap())
            .collect();
        let mut winners = Vec::new();
        for result in results {
            match result {
                Ok(won) => winners.push(won),
                Err(StartError::InUse(_)) => {}
                Err(error) => panic!("round {round}: {error}"),
            }
        }
        assert_eq!(winners.len(), 1, "round {round}: one endpoint per user");
        // The socket at the path is the winner's, and it answers.
        let (listener, bound) = winners.pop().unwrap();
        let (dev, ino) = inode(&path);
        let local = listener.local_addr().unwrap();
        assert_eq!(local.as_pathname(), Some(path.as_path()));
        assert!(UnixStream::connect(&path).is_ok(), "round {round}");
        // A late contender, after everyone else gave up, changes nothing.
        assert!(matches!(unix::bind(&path), Err(StartError::InUse(_))));
        assert_eq!(inode(&path), (dev, ino), "round {round}");
        assert!(UnixStream::connect(&path).is_ok(), "round {round}");
        drop((listener, bound));
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(unix)]
const BIND_HELPER_PATH: &str = "CR375_BIND_HELPER_PATH";

/// The child half of `cr375_a_second_process_never_unlinks_a_live_socket`:
/// it tries to take the endpoint while the parent holds it, and exits 3 if
/// it was told the endpoint is in use. Without the variable it does nothing.
#[cfg(unix)]
#[test]
fn cr375_bind_helper_child() {
    let Some(path) = std::env::var_os(BIND_HELPER_PATH) else {
        return;
    };
    match unix::bind(std::path::Path::new(&path)) {
        Err(StartError::InUse(_)) => std::process::exit(3),
        Err(StartError::Refused(reason)) => {
            eprintln!("refused: {reason}");
            std::process::exit(4)
        }
        Ok(_) => std::process::exit(5),
    }
}

#[cfg(unix)]
#[test]
fn cr375_a_second_process_never_unlinks_a_live_socket() {
    use std::os::unix::net::UnixStream;
    let dir = private_dir();
    let path = dir.join("s");
    let (listener, bound) = unix::bind(&path).unwrap();
    let before = inode(&path);
    for _ in 0..3 {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "app_api::tests::cr375_bind_helper_child",
                "--test-threads=1",
            ])
            .env(BIND_HELPER_PATH, &path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .status()
            .expect("run the bind helper");
        assert_eq!(
            status.code(),
            Some(3),
            "the second process was not told InUse"
        );
        assert_eq!(inode(&path), before, "the live socket was replaced");
        assert!(UnixStream::connect(&path).is_ok());
    }
    drop((listener, bound));
    // Once the holder is gone, the next process takes over.
    let (_listener, _bound) = unix::bind(&path).expect("taken over after the holder left");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn cr375_a_lock_path_that_is_not_a_regular_file_is_refused_and_left_alone() {
    let dir = private_dir();
    let path = dir.join("s");
    std::fs::create_dir(unix::lock_path(&path)).unwrap();
    let refused = unix::bind(&path).map(|_| ());
    assert!(
        matches!(&refused, Err(StartError::Refused(reason)) if reason.contains("lock path")),
        "{refused:?}"
    );
    assert!(unix::lock_path(&path).is_dir());
    assert!(std::fs::symlink_metadata(&path).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// #375 items 2 and 6: the pipe's integrity label and OpenProcess failures
// ---------------------------------------------------------------------------

/// The SDDL of `handle`'s security descriptor parts named by `info`.
#[cfg(windows)]
fn handle_sddl(handle: windows_sys::Win32::Foundation::HANDLE, info: u32) -> String {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `handle` is live; `descriptor` receives a LocalAlloc'd
    // descriptor freed below.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            info,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    assert_eq!(status, 0, "GetSecurityInfo failed");
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: `descriptor` is live; `text` receives a LocalAlloc'd string.
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            info,
            &mut text,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(converted, 0);
    // SAFETY: `text` is NUL-terminated; both allocations are freed once.
    unsafe {
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let sddl = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        LocalFree(descriptor.cast());
        sddl
    }
}

#[cfg(windows)]
#[test]
fn cr375_the_pipe_carries_an_explicit_medium_label() {
    use windows_sys::Win32::Security::LABEL_SECURITY_INFORMATION;
    let name = format!(r"\\.\pipe\orcel-test-cr375-{}", unique());
    let pipe = win::create_first(&name).unwrap();
    let label = handle_sddl(pipe.handle.0, LABEL_SECURITY_INFORMATION);
    // The system may add SACL control flags such as AI (auto-inherited);
    // the one ACE is the explicit Medium label with no-write-up and
    // no-read-up.
    assert!(label.starts_with("S:"), "{label}");
    assert_eq!(label.matches('(').count(), 1, "more than one ACE: {label}");
    assert!(label.ends_with("(ML;;NWNR;;;ME)"), "{label}");
}

/// Opens `name` the way the server's clients do, from the calling thread's
/// token, and returns the Win32 error of a failed open.
#[cfg(windows)]
fn try_open_pipe(name: &str, access: u32) -> Result<(), u32> {
    use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    let wide = win::wide(name);
    // SAFETY: `wide` is NUL-terminated; `Owned` closes the handle.
    let handle = win::Owned(unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            0,
        )
    });
    if handle.0 == INVALID_HANDLE_VALUE {
        // SAFETY: plain read of this thread's last error.
        Err(unsafe { GetLastError() })
    } else {
        Ok(())
    }
}

/// Real evidence for #375 item 2 on any Windows host, hosted runners
/// included: a thread of this process impersonates a Low-integrity copy of
/// this process's own token (same user, same session, same groups) and
/// cannot open the pipe for reading, writing or both. The same opens from
/// the process's own token succeed, so the label is what refuses them.
#[cfg(windows)]
#[test]
fn cr375_a_low_integrity_process_of_this_user_cannot_open_the_pipe() {
    use windows_sys::Win32::Foundation::{
        LocalFree, ERROR_ACCESS_DENIED, GENERIC_READ, GENERIC_WRITE, HANDLE, PSID,
    };
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows_sys::Win32::Security::{
        DuplicateTokenEx, GetLengthSid, RevertToSelf, SecurityImpersonation, SetTokenInformation,
        TokenImpersonation, TokenIntegrityLevel, SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT,
        TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcessToken, SetThreadToken,
    };
    /// `SE_GROUP_INTEGRITY` (winnt.h).
    const SE_GROUP_INTEGRITY: u32 = 0x20;

    let name = format!(r"\\.\pipe\orcel-test-cr375-{}", unique());
    let first = win::create_first(&name).unwrap();
    // Spare instances, so every open below finds a free one.
    let _spare: Vec<_> = (0..6)
        .map(|_| win::create_instance(&name, false).unwrap())
        .collect();
    let opener = name.clone();
    let low_results = std::thread::spawn(move || {
        let mut token: HANDLE = 0;
        // SAFETY: the pseudo handle needs no closing; `token` is closed by
        // `Owned`.
        assert_ne!(
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_DUPLICATE | TOKEN_QUERY,
                    &mut token,
                )
            },
            0
        );
        let token = win::Owned(token);
        let mut low: HANDLE = 0;
        // SAFETY: duplicates a live token into `low`, closed by `Owned`.
        assert_ne!(
            unsafe {
                DuplicateTokenEx(
                    token.0,
                    TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ADJUST_DEFAULT,
                    std::ptr::null(),
                    SecurityImpersonation,
                    TokenImpersonation,
                    &mut low,
                )
            },
            0
        );
        let low = win::Owned(low);
        let sid_text = win::wide("S-1-16-4096");
        let mut sid: PSID = std::ptr::null_mut();
        // SAFETY: `sid_text` is NUL-terminated; `sid` is LocalAlloc'd.
        assert_ne!(
            unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut sid) },
            0
        );
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: SE_GROUP_INTEGRITY,
            },
        };
        // SAFETY: `label` and the SID it points to live through the call.
        let lowered = unsafe {
            SetTokenInformation(
                low.0,
                TokenIntegrityLevel,
                std::ptr::addr_of!(label).cast(),
                std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(sid),
            )
        };
        assert_ne!(lowered, 0, "{}", io::Error::last_os_error());
        // SAFETY: impersonates on this thread only, reverted below.
        assert_ne!(unsafe { SetThreadToken(std::ptr::null(), low.0) }, 0);
        let results: Vec<_> = [GENERIC_READ, GENERIC_WRITE, GENERIC_READ | GENERIC_WRITE]
            .into_iter()
            .map(|access| try_open_pipe(&opener, access))
            .collect();
        // SAFETY: ends this thread's impersonation.
        unsafe { RevertToSelf() };
        // SAFETY: the SID was LocalAlloc'd above and is freed once.
        unsafe { LocalFree(sid) };
        results
    })
    .join()
    .unwrap();
    for result in low_results {
        assert_eq!(result, Err(ERROR_ACCESS_DENIED), "a Low-integrity open");
    }
    // Control: the same opens from this process's own token succeed.
    for access in [GENERIC_READ, GENERIC_WRITE, GENERIC_READ | GENERIC_WRITE] {
        assert_eq!(try_open_pipe(&name, access), Ok(()), "access {access:#x}");
    }
    drop(first);
}

#[cfg(windows)]
#[test]
fn cr375_open_process_failures_are_reported_as_what_they_are() {
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER};
    assert_eq!(
        win::open_process_failure(77, ERROR_INVALID_PARAMETER),
        PlatformError::ProcessGone(77)
    );
    let denied = win::open_process_failure(77, ERROR_ACCESS_DENIED);
    assert!(
        matches!(&denied, PlatformError::IdentityUnavailable(reason) if reason.contains("ACCESS_DENIED")),
        "{denied:?}"
    );
    // Either way the connection is refused; only a missing pid is "gone".
    assert!(matches!(refusal_from(denied), Refusal::Unavailable(_)));
    assert!(matches!(
        refusal_from(win::open_process_failure(77, 1450)),
        Refusal::Unavailable(_)
    ));
    assert_eq!(
        refusal_from(win::open_process_failure(77, ERROR_INVALID_PARAMETER)),
        Refusal::PeerGone(77)
    );
}

// ---------------------------------------------------------------------------
// #398: endpoint upkeep, idle re-check, shared runtime directory
// ---------------------------------------------------------------------------

/// #398 item 2: with a heartbeat far longer than [`PEER_RECHECK`], an idle
/// subscription still re-reads its peer about every second and ends without
/// ever sending a heartbeat.
#[test]
fn cr398_an_idle_subscription_rechecks_its_peer_every_second() {
    let shared = shared_with(Limits {
        heartbeat: Duration::from_secs(60),
        ..test_limits()
    });
    let mut process = process::current_instance().expect("own instance");
    process.generation = process.generation.wrapping_add(1);
    let stale = PeerInfo {
        process,
        source: "test",
    };
    let (done, finished) = std::sync::mpsc::channel();
    let streaming = Arc::clone(&shared);
    let started = Instant::now();
    std::thread::spawn(move || {
        let mut conn = Recorder::default();
        stream_events(&mut conn, &streaming, &stale, &json!("s1"), 0, None);
        let _ = done.send(conn.written);
    });
    let written = finished
        .recv_timeout(Duration::from_secs(10))
        .expect("the idle subscription of a stale peer ended");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );
    let text = String::from_utf8(written).unwrap();
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(!text.contains("heartbeat"), "{text}");
}

/// #398 item 3: a runtime directory that is not this user's private
/// directory (a shared sticky `/tmp`, or one readable by others) is passed
/// over for the state root.
#[cfg(unix)]
#[test]
fn cr398_a_shared_runtime_directory_falls_back_to_the_state_root() {
    use orcel_platform::paths::StateLayout;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    let private = private_dir();
    let open = private.join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(unix::runtime_dir_is_private(&private));
    assert!(!unix::runtime_dir_is_private(&open));
    assert!(!unix::runtime_dir_is_private(std::path::Path::new("/tmp")));
    assert!(!unix::runtime_dir_is_private(&private.join("missing")));
    let link = private.join("link");
    std::os::unix::fs::symlink(&private, &link).unwrap();
    assert!(!unix::runtime_dir_is_private(&link));

    for (runtime, expected) in [
        (private.display().to_string(), private.join("orcel")),
        (
            open.display().to_string(),
            PathBuf::from("/home/a/.local/state/orcel/run"),
        ),
        (
            "/tmp".to_owned(),
            PathBuf::from("/home/a/.local/state/orcel/run"),
        ),
    ] {
        let lookup = env_lookup(&[("HOME", "/home/a".into()), ("XDG_RUNTIME_DIR", runtime)]);
        assert_eq!(
            unix::socket_dir(
                StateLayout::Xdg,
                &lookup,
                None,
                &unix::runtime_dir_is_private
            )
            .unwrap(),
            expected
        );
    }
    // macOS: a confstr answer that is not private is passed over too.
    let lookup = env_lookup(&[("HOME", "/Users/a".into())]);
    assert_eq!(
        unix::socket_dir(
            StateLayout::MacOs,
            &lookup,
            Some(PathBuf::from("/tmp")),
            &unix::runtime_dir_is_private
        )
        .unwrap(),
        PathBuf::from("/Users/a/Library/Application Support/Orcel/run")
    );
    let _ = std::fs::remove_dir_all(&private);
}

/// Runs [`unix::serve_watched`] on a fresh binding with a short check
/// interval; returns the binding's slot and the receiver of its result.
#[cfg(unix)]
fn watched_server(
    path: &std::path::Path,
) -> (
    Arc<Mutex<Option<unix::Bound>>>,
    std::sync::mpsc::Receiver<String>,
) {
    let (listener, bound) = unix::bind(path).expect("bind test socket");
    let slot = Arc::new(Mutex::new(Some(bound)));
    let shared = shared_with(test_limits());
    let (done, finished) = std::sync::mpsc::channel();
    let watching = Arc::clone(&slot);
    std::thread::spawn(move || {
        let reason = unix::serve_watched(
            listener,
            &shared,
            &watching,
            Duration::from_millis(50),
            Duration::from_secs(3600),
        );
        let _ = done.send(reason);
    });
    (slot, finished)
}

/// #398 item 1: a socket or lock file removed under a running orceld (a
/// runtime directory clean-up) ends the watched serve loop with the reason,
/// and the endpoint can be bound again at once.
#[cfg(unix)]
#[test]
fn cr398_a_removed_socket_or_lock_file_is_noticed_and_bound_again() {
    let dir = private_dir();
    let path = dir.join("s");
    for removed in [path.clone(), unix::lock_path(&path)] {
        let (slot, finished) = watched_server(&path);
        let mut client = TestClient::connect(path.to_str().unwrap());
        assert_eq!(client.call("status.get", json!({}))["ok"], true);
        drop(client);
        assert!(finished.recv_timeout(Duration::from_millis(300)).is_err());

        std::fs::remove_file(&removed).unwrap();
        let reason = finished
            .recv_timeout(Duration::from_secs(10))
            .expect("the loss was noticed");
        let expected = if removed == path {
            "socket"
        } else {
            "lock file"
        };
        assert!(reason.contains(expected), "{reason}");
        // What orceld's start loop does next: release, then bind again.
        drop(slot.lock().unwrap().take());
        let (listener, bound) = unix::bind(&path).expect("bound again");
        drop(std::os::unix::net::UnixStream::connect(&path).expect("connect"));
        drop((listener, bound));
        assert!(!path.exists());
    }
    // A socket replaced by another file is noticed and left in place.
    let (slot, finished) = watched_server(&path);
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"not ours").unwrap();
    let reason = finished.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(reason.contains("socket"), "{reason}");
    drop(slot.lock().unwrap().take());
    assert_eq!(std::fs::read(&path).unwrap(), b"not ours");
    let _ = std::fs::remove_dir_all(&dir);
}

/// #398 item 1: touching sets the times of both files to now and never
/// follows a link.
#[cfg(unix)]
#[test]
fn cr398_touch_refreshes_the_socket_and_lock_times() {
    use std::os::unix::fs::MetadataExt;
    let dir = private_dir();
    let path = dir.join("s");
    let (_listener, bound) = unix::bind(&path).unwrap();
    let old = std::time::SystemTime::now() - Duration::from_secs(7 * 24 * 3600);
    std::fs::OpenOptions::new()
        .write(true)
        .open(unix::lock_path(&path))
        .unwrap()
        .set_times(
            std::fs::FileTimes::new()
                .set_accessed(old)
                .set_modified(old),
        )
        .unwrap();
    let before = std::fs::symlink_metadata(unix::lock_path(&path))
        .unwrap()
        .mtime();
    bound.touch().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    for file in [path.clone(), unix::lock_path(&path)] {
        let meta = std::fs::symlink_metadata(&file).unwrap();
        assert!(meta.mtime() >= now - 60, "{file:?}");
        assert!(meta.atime() >= now - 60, "{file:?}");
    }
    assert!(before < now - 3600);
    bound.intact().unwrap();
    drop(bound);
    let _ = std::fs::remove_dir_all(&dir);
}
