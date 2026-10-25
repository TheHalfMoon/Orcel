//! SG-000120 RJ-03 through the real `orceld` binary and its stdio protocol,
//! on every OS: a task is started and previewed, orceld is killed, a new
//! orceld starts on the same private state, and the client session that
//! started the task reads its resume summary; another session is refused.
//! Nothing here reaches the approval broker.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const Q3_CSV: &str =
    "region,quarter,revenue_cents\nnorth,Q3,1250000\nsouth,Q3,980050\neast,Q3,1500025\n";

fn unique(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "orcel-rj03-e2e-{label}-{}-{nanos}",
        std::process::id()
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

struct Orceld {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    count: usize,
}

impl Orceld {
    fn start(state: &Path, workspace: &Path) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_orceld"));
        command
            .env("ORCEL_WORKSPACE_ROOT", workspace)
            .env("ORCEL_WORKSPACE_ID", "default")
            .env("ORCEL_APP_API", "off")
            .env("ORCEL_AUDIT_PATH", state.join("audit").join("audit.jsonl"))
            .env_remove("ORCEL_WORKSPACES_JSON")
            .env_remove("ORCEL_MCP_TRANSPORT")
            .env_remove("ORCEL_REPORT_JOURNAL_PATH")
            .env_remove("ORCEL_MUTATION_JOURNAL_PATH")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if cfg!(windows) {
            command.env("LOCALAPPDATA", state);
        } else if cfg!(target_os = "linux") {
            command.env("XDG_STATE_HOME", state);
        } else {
            command.env("HOME", state);
        }
        let mut child = command.spawn().expect("spawn orceld");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        Self {
            child,
            stdin,
            stdout,
            count: 0,
        }
    }

    fn report(&mut self, session: &str, operation: &str, arguments: Value) -> Value {
        self.count += 1;
        writeln!(
            self.stdin,
            "{}",
            json!({
                "version": 1,
                "request_id": format!("rj03-{}", self.count),
                "client_session_id": session,
                "workspace_id": "default",
                "capability": "report",
                "operation": operation,
                "target": null,
                "arguments": arguments,
            })
        )
        .expect("write request");
        self.stdin.flush().expect("flush");
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read response");
        serde_json::from_str(&line).expect("response json")
    }

    /// A hard kill, as a crash: no clean shutdown runs.
    fn kill(mut self) {
        self.child.kill().expect("kill orceld");
        let _ = self.child.wait();
    }
}

#[test]
fn rj03_a_session_reads_its_task_after_orceld_was_killed_and_another_session_cannot() {
    let base = unique("binary");
    let state = base.join("state");
    let workspace = base.join("ws");
    private_dir(&base);
    private_dir(&state);
    std::fs::create_dir_all(workspace.join("data")).unwrap();
    std::fs::create_dir_all(workspace.join("reports")).unwrap();
    std::fs::write(workspace.join("data").join("q3.csv"), Q3_CSV).unwrap();

    let mut first = Orceld::start(&state, &workspace);
    let started = first.report(
        "rj03-session",
        "start",
        json!({"title": "Q3 revenue", "sources": ["data/q3.csv"], "folder": "reports"}),
    );
    assert_eq!(started["ok"], true, "{started}");
    let task = started["result"]["task_id"].as_str().unwrap().to_owned();
    let report = "# Q3 revenue summary\n\nTotal: 37300.75\n";
    let previewed = first.report(
        "rj03-session",
        "preview",
        json!({"task_id": task, "name": "q3.md", "content": report}),
    );
    assert_eq!(previewed["ok"], true, "{previewed}");
    first.kill();

    // The reconnecting session, on a new orceld over the same state.
    let mut second = Orceld::start(&state, &workspace);
    let summary = second.report("rj03-session", "resume_summary", json!({"task_id": task}));
    assert_eq!(summary["ok"], true, "{summary}");
    let result = &summary["result"];
    assert_eq!(result["schema"], "orcel-resume-summary/1");
    let kinds: Vec<&str> = result["completed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["observe", "preview"], "{result}");
    assert_eq!(result["unknown"], json!([]), "nothing was committed");
    assert!(result["note"].as_str().unwrap().contains("do NOT re-run"));
    let text = summary.to_string();
    assert!(
        !text.contains("north,Q3") && !text.contains("37300.75") && !text.contains("Q3 revenue"),
        "fingerprints only: {text}"
    );

    // Another session, and an id no session started, get one refusal.
    for (session, id) in [
        ("rj03-other", task.as_str()),
        ("rj03-session", "rpt-0123456789abcdef0123456789abcdef"),
    ] {
        let refused = second.report(session, "resume_summary", json!({"task_id": id}));
        assert_eq!(refused["ok"], false, "{refused}");
        assert_eq!(refused["error"]["code"], "CAPABILITY_DENIED", "{refused}");
    }
    // Only the task id is accepted.
    let extra = second.report(
        "rj03-session",
        "resume_summary",
        json!({"task_id": task, "session": "rj03-other"}),
    );
    assert_eq!(extra["error"]["code"], "INVALID_REQUEST", "{extra}");
    second.kill();
    let _ = std::fs::remove_dir_all(&base);
}
