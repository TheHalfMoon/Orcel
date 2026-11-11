//! MC-01: several client sessions at once. Each local MCP session starts its own orceld, and
//! they share one user's state root. Three real orceld processes run against one isolated
//! sandbox and the test checks what keeps them apart: each session records itself and the
//! endpoint holder lists them all; a remote hello is never recorded; a remote request in one
//! session makes no other session remote; and a report task can be acted on only by the orceld
//! that started it. Nothing here reaches the approval broker, so no dialog can appear.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const START_TIMEOUT: Duration = Duration::from_secs(30);
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
const Q3_CSV: &str = "region,quarter,revenue_cents\nnorth,Q3,1250000\nsouth,Q3,980050\n";

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos()
}

/// A short base on Unix, where the runtime directory holds the socket.
fn base_dir() -> PathBuf {
    let parent = if cfg!(unix) {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    parent.join(format!(
        "mc01-{}-{}",
        std::process::id(),
        nanos() % 1_000_000
    ))
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).expect("create dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
}

struct Sandbox {
    base: PathBuf,
    instance: String,
}

impl Sandbox {
    fn new() -> Self {
        let base = base_dir();
        let _ = std::fs::remove_dir_all(&base);
        for dir in ["", "h", "r", "a"] {
            private_dir(&base.join(dir));
        }
        std::fs::create_dir_all(base.join("ws").join("data")).unwrap();
        std::fs::create_dir_all(base.join("ws").join("reports")).unwrap();
        std::fs::write(base.join("ws").join("data").join("q3.csv"), Q3_CSV).unwrap();
        Self {
            base,
            instance: format!("mc01-{:06x}", nanos() % 0xff_ffff),
        }
    }

    fn workspace(&self) -> PathBuf {
        self.base.join("ws")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// One orceld over stdio. Its stdout and stderr are read on threads, so every wait is bounded.
struct Orceld {
    child: Child,
    stdin: Option<ChildStdin>,
    replies: Receiver<String>,
    logs: Receiver<String>,
    session: String,
    count: usize,
}

impl Orceld {
    fn start(sandbox: &Sandbox, session: &str) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_orceld"));
        command
            .env("ORCEL_WORKSPACE_ROOT", sandbox.workspace())
            .env("ORCEL_WORKSPACE_ID", "default")
            .env(
                "ORCEL_AUDIT_PATH",
                sandbox.base.join("a").join("audit.jsonl"),
            )
            .env("ORCEL_APP_API_INSTANCE", &sandbox.instance)
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
        let (reply_tx, replies) = channel();
        let stdout = child.stdout.take().expect("stdout");
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if reply_tx.send(line).is_err() {
                    break;
                }
            }
        });
        let (log_tx, logs) = channel();
        let stderr = child.stderr.take().expect("stderr");
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if log_tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            replies,
            logs,
            session: session.to_owned(),
            count: 0,
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Waits for a stderr line containing `needle` and returns it.
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

    fn call(
        &mut self,
        capability: &str,
        operation: &str,
        arguments: Value,
        remote: Option<Value>,
    ) -> Value {
        self.count += 1;
        let mut envelope = json!({
            "version": 1,
            "request_id": format!("{}-{}", self.session, self.count),
            "client_session_id": self.session,
            "workspace_id": "default",
            "capability": capability,
            "operation": operation,
            "target": null,
            "arguments": arguments,
        });
        if let Some(remote) = remote {
            envelope["remote"] = remote;
        }
        let stdin = self.stdin.as_mut().expect("stdin open");
        writeln!(stdin, "{envelope}").expect("write request");
        stdin.flush().expect("flush");
        let line = self
            .replies
            .recv_timeout(REPLY_TIMEOUT)
            .unwrap_or_else(|_| {
                panic!("no reply from {} to {capability}/{operation}", self.session)
            });
        serde_json::from_str(&line).expect("response json")
    }

    fn hello(&mut self, remote: Option<Value>) -> Value {
        let name = format!("mc01-{}", self.session);
        self.call(
            "session",
            "hello",
            json!({ "client_name": name, "client_version": "1", "transport": "stdio" }),
            remote,
        )
    }

    /// Ends the session as a client does, by closing orceld's stdin, and waits for it to exit.
    fn close(mut self) {
        drop(self.stdin.take());
        let deadline = Instant::now() + REPLY_TIMEOUT;
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "orceld {} did not exit after its stdin closed",
            self.session
        );
    }
}

impl Drop for Orceld {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn code(response: &Value) -> &str {
    assert_eq!(response["ok"], false, "{response}");
    response["error"]["code"].as_str().expect("error code")
}

/// The remote context fix395 uses: a tunnel session with no lease in this sandbox.
fn tunnel_remote() -> Value {
    json!({
        "principal": "rp-182110eb5d85d5ccd3f34df5dba41e1a",
        "remoteConnectionId": "rc-8d11a8282860ff1df26aeee0949a7bf9",
        "connectionId": "tunnel-0123456789abcdef0123456789abcdef",
        "deviceId": "dev-0872269746857073deab118978d116a0",
        "deviceEpoch": 1,
        "providerKind": "openai",
        "clientProfileId": "chatgpt-secure-mcp-tunnel",
        "clientProfileRevision": 1,
        "toolSurfaceProfile": "core",
        "scopes": ["orcel.read", "orcel.write", "orcel.execute"],
    })
}

/// One read-only app API request to the endpoint the holder logged, with a bounded wait.
fn app_api(endpoint: &str, method: &str) -> Value {
    let frame = format!(
        "{}\n",
        json!({ "v": "orcel-app-api/1", "id": "mc01", "method": method, "params": {} })
    );
    let endpoint = endpoint.to_owned();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let result = (|| -> std::io::Result<String> {
            #[cfg(unix)]
            let mut stream = std::os::unix::net::UnixStream::connect(&endpoint)?;
            #[cfg(windows)]
            let mut stream = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&endpoint)?;
            stream.write_all(frame.as_bytes())?;
            stream.flush()?;
            let mut line = String::new();
            BufReader::new(stream).read_line(&mut line)?;
            Ok(line)
        })();
        let _ = tx.send(result);
    });
    let line = rx
        .recv_timeout(REPLY_TIMEOUT)
        .expect("app api answered in time")
        .expect("app api read");
    serde_json::from_str(&line).expect("app api json")
}

fn listed_pids(answer: &Value) -> Vec<u64> {
    assert_eq!(answer["ok"], true, "{answer}");
    assert_eq!(answer["result"]["registry"], "ok", "{answer}");
    let mut pids: Vec<u64> = answer["result"]["clients"]
        .as_array()
        .expect("clients")
        .iter()
        .map(|client| {
            assert_eq!(client["client"]["verified"], false, "{client}");
            client["pid"].as_u64().expect("pid")
        })
        .collect();
    pids.sort_unstable();
    pids
}

fn sorted(mut pids: Vec<u64>) -> Vec<u64> {
    pids.sort_unstable();
    pids
}

#[test]
fn mc01_concurrent_sessions_stay_apart() {
    let sandbox = Sandbox::new();
    let mut a = Orceld::start(&sandbox, "A");
    let holder = a.wait_log("orceld app api: listening on ");
    let endpoint = holder
        .split("listening on ")
        .nth(1)
        .expect("endpoint")
        .trim()
        .to_owned();
    let mut b = Orceld::start(&sandbox, "B");
    let mut c = Orceld::start(&sandbox, "C");
    b.wait_log("orceld app api: waiting for");
    c.wait_log("orceld app api: waiting for");

    // P1: each session's hello is its own record, and the endpoint holder lists them all.
    for orceld in [&mut a, &mut b, &mut c] {
        let said = orceld.hello(None);
        assert_eq!(said["ok"], true, "{said}");
        assert_eq!(said["result"]["registered"], true, "{said}");
    }
    let all = sorted(vec![a.pid().into(), b.pid().into(), c.pid().into()]);
    assert_eq!(listed_pids(&app_api(&endpoint, "clients.list")), all);
    assert_eq!(
        code(&b.hello(None)),
        "INVALID_REQUEST",
        "a second hello is refused"
    );

    // P2: a remote hello is never recorded; C's own record stays as it was.
    let fresh = Orceld::start(&sandbox, "D");
    fresh.wait_log("orceld app api: waiting for");
    let mut fresh = fresh;
    assert_eq!(
        code(&fresh.hello(Some(tunnel_remote()))),
        "CAPABILITY_DENIED"
    );
    assert_eq!(listed_pids(&app_api(&endpoint, "clients.list")), all);
    fresh.close();

    // P3: a remote request in one session makes no other session remote.
    let remote = b.call("system.status", "get", json!({}), Some(tunnel_remote()));
    assert_eq!(code(&remote), "REMOTE_SESSION_INACTIVE");
    for orceld in [&mut a, &mut c, &mut b] {
        let local = orceld.call("system.status", "get", json!({}), None);
        if local["ok"] == false {
            assert_ne!(code(&local), "REMOTE_SESSION_INACTIVE", "{local}");
        }
    }

    // P4: a report task can be acted on only by the orceld that started it.
    let started = a.call(
        "report",
        "start",
        json!({ "title": "Q3 revenue", "sources": ["data/q3.csv"], "folder": "reports" }),
        None,
    );
    assert_eq!(started["ok"], true, "{started}");
    let task = started["result"]["task_id"]
        .as_str()
        .expect("task id")
        .to_owned();
    let elsewhere = b.call(
        "report",
        "preview",
        json!({ "task_id": task, "name": "x.md", "content": "x" }),
        None,
    );
    assert_eq!(code(&elsewhere), "TARGET_STALE");
    assert!(!sandbox.workspace().join("reports").join("x.md").exists());
    let here = a.call(
        "report",
        "preview",
        json!({ "task_id": task, "name": "x.md", "content": "x" }),
        None,
    );
    assert_eq!(here["ok"], true, "{here}");
    assert!(
        !sandbox.workspace().join("reports").join("x.md").exists(),
        "a preview writes nothing"
    );

    // A session that ends takes its record with it.
    let b_pid: u64 = b.pid().into();
    b.close();
    let remaining: Vec<u64> = all.iter().copied().filter(|pid| *pid != b_pid).collect();
    assert_eq!(listed_pids(&app_api(&endpoint, "clients.list")), remaining);
    drop(c);
    drop(a);
}
