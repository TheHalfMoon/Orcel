//! SG-000126 through the real `orceld` binary and its stdio protocol, on
//! every OS. Nothing here reaches the approval broker: every commit sent is
//! one orceld must refuse before it asks, so no platform dialog can appear.
//! The approved journey runs in-process on the real broker in
//! `src/report_task_tests.rs` and `src/app_api/tests.rs`.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const Q3_CSV: &str =
    "region,quarter,revenue_cents\nnorth,Q3,1250000\nsouth,Q3,980050\neast,Q3,1500025\n";

fn sha256(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn unique(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "orcel-sg126-e2e-{label}-{}-{nanos}",
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

fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).expect("read dir") {
            let path = entry.expect("entry").path();
            let relative = path
                .strip_prefix(root)
                .expect("prefix")
                .to_string_lossy()
                .replace('\\', "/");
            if path.is_dir() {
                out.insert(format!("{relative}/"), Vec::new());
                walk(root, &path, out);
            } else {
                out.insert(relative, std::fs::read(&path).expect("read"));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// One orceld over stdio, driven one request at a time.
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
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if cfg!(windows) {
            command.env("LOCALAPPDATA", state);
        } else if cfg!(target_os = "linux") {
            command.env("XDG_STATE_HOME", state);
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

    fn send(&mut self, envelope: Value) -> Value {
        writeln!(self.stdin, "{envelope}").expect("write request");
        self.stdin.flush().expect("flush");
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read response");
        serde_json::from_str(&line).expect("response json")
    }

    fn report(&mut self, operation: &str, arguments: Value) -> Value {
        self.count += 1;
        self.send(json!({
            "version": 1,
            "request_id": format!("sg126-{}", self.count),
            "client_session_id": "sg126-e2e",
            "workspace_id": "default",
            "capability": "report",
            "operation": operation,
            "target": null,
            "arguments": arguments,
        }))
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

#[test]
fn sg126_real_orceld_observes_previews_and_refuses_before_any_approval() {
    let base = unique("binary");
    let state = base.join("state");
    let workspace = base.join("ws");
    private_dir(&base);
    private_dir(&state);
    std::fs::create_dir_all(workspace.join("data")).unwrap();
    std::fs::create_dir_all(workspace.join("reports")).unwrap();
    std::fs::write(workspace.join("data").join("q3.csv"), Q3_CSV).unwrap();
    std::fs::write(
        workspace.join("reports").join("taken.md"),
        "the user's file",
    )
    .unwrap();
    let mut orceld = Orceld::start(&state, &workspace);

    let started = orceld.report(
        "start",
        json!({"title": "Q3 revenue", "sources": ["data/q3.csv"], "folder": "reports"}),
    );
    assert_eq!(started["ok"], true, "{started}");
    let result = &started["result"];
    let task = result["task_id"].as_str().unwrap().to_owned();
    assert!(task.starts_with("rpt-") && task.len() == 36, "{task}");
    assert_eq!(result["state"], "observed");
    assert_eq!(result["sources"][0]["sha256"], sha256(Q3_CSV));
    assert_eq!(result["sources"][0]["text"], Q3_CSV);

    let report = "# Q3 revenue summary\n\nTotal: 37300.75\n";
    let previewed = orceld.report(
        "preview",
        json!({"task_id": task, "name": "q3.md", "content": report}),
    );
    assert_eq!(previewed["ok"], true, "{previewed}");
    assert_eq!(previewed["result"]["destination"], "reports/q3.md");
    assert_eq!(previewed["result"]["sha256"], sha256(report));
    let before = tree(&workspace);

    // Overwrite: refused at preview.
    let taken = orceld.report(
        "preview",
        json!({"task_id": task, "name": "taken.md", "content": report}),
    );
    assert_eq!(code(&taken), "TARGET_STALE");
    // Out of scope: refused by policy.
    for (operation, arguments, expected) in [
        (
            "preview",
            json!({"task_id": task, "name": "../q3.md", "content": report}),
            "PATH_ESCAPE",
        ),
        (
            "preview",
            json!({"task_id": task, "name": "q3.exe", "content": report}),
            "PATH_ESCAPE",
        ),
        (
            "start",
            json!({"title": "t", "sources": ["data/q3.csv"], "folder": "../outside"}),
            "PATH_ESCAPE",
        ),
        (
            "start",
            json!({"title": "t", "sources": ["../secret.csv"], "folder": "reports"}),
            "PATH_ESCAPE",
        ),
        (
            "start",
            json!({"title": "t", "sources": ["data/q3.csv"], "folder": "missing"}),
            "PROVIDER_UNAVAILABLE",
        ),
        (
            "start",
            json!({"title": "t", "sources": ["data/q3.csv"], "folder": "data/q3.csv"}),
            "INVALID_REQUEST",
        ),
        ("overwrite", json!({"task_id": task}), "CAPABILITY_DENIED"),
    ] {
        let refused = orceld.report(operation, arguments.clone());
        assert_eq!(code(&refused), expected, "{operation} {arguments}");
    }
    // Commits orceld must refuse before it asks: other bytes than the
    // preview, and a destination that appeared after the preview.
    let other = "Total: 1.00\n";
    let unpreviewed = orceld.report(
        "commit",
        json!({"task_id": task, "name": "q3.md", "content": other, "expected_sha256": sha256(other)}),
    );
    assert_eq!(code(&unpreviewed), "TARGET_STALE");
    std::fs::write(workspace.join("reports").join("q3.md"), "appeared").unwrap();
    let appeared = orceld.report(
        "commit",
        json!({"task_id": task, "name": "q3.md", "content": report, "expected_sha256": sha256(report)}),
    );
    assert_eq!(code(&appeared), "TARGET_STALE");
    assert_eq!(
        std::fs::read(workspace.join("reports").join("q3.md")).unwrap(),
        b"appeared"
    );
    std::fs::remove_file(workspace.join("reports").join("q3.md")).unwrap();
    assert_eq!(tree(&workspace), before);

    // Stale source: the preview and every later commit are refused.
    std::fs::write(
        workspace.join("data").join("q3.csv"),
        format!("{Q3_CSV}west,Q3,1\n"),
    )
    .unwrap();
    let stale = orceld.report(
        "preview",
        json!({"task_id": task, "name": "q3.md", "content": report}),
    );
    assert_eq!(code(&stale), "TARGET_STALE");
    let stale_commit = orceld.report(
        "commit",
        json!({"task_id": task, "name": "q3.md", "content": report, "expected_sha256": sha256(report)}),
    );
    assert_eq!(code(&stale_commit), "TARGET_STALE");
    assert!(!workspace.join("reports").join("q3.md").exists());

    // A remote-context envelope never reaches policy or dispatch.
    let remote = orceld.send(json!({
        "version": 1,
        "request_id": "sg126-remote",
        "client_session_id": "sg126-e2e",
        "workspace_id": "default",
        "capability": "report",
        "operation": "start",
        "target": null,
        "arguments": {"title": "t", "sources": ["data/q3.csv"], "folder": "reports"},
        "remote": {
            "principal": "p",
            "remoteConnectionId": "rc",
            "connectionId": "c",
            "deviceId": "d",
            "deviceEpoch": 1,
            "providerKind": "generic",
            "clientProfileId": "cp",
            "clientProfileRevision": 1,
            "toolSurfaceProfile": "core",
            "scopes": ["orcel.local.write"]
        }
    }));
    assert_eq!(code(&remote), "CAPABILITY_DENIED");
    assert!(remote["error"]["message"]
        .as_str()
        .unwrap()
        .contains("local-only"));

    drop(orceld);
    let audit = std::fs::read_to_string(state.join("audit").join("audit.jsonl")).unwrap();
    assert!(audit.contains("\"capability\":\"report\""));
    assert!(audit.contains("REMOTE_DENIED"));
    assert!(!audit.contains("north,Q3") && !audit.contains("37300.75"));
    assert!(!audit.contains("APPROVAL"), "no request reached the broker");
    let _ = std::fs::remove_dir_all(&base);
}
