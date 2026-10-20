//! #395 end to end through the real `orceld` binary: a request carrying the
//! ChatGPT Secure MCP Tunnel's remote context (what `orcel-mcp-host` now
//! makes the MCP app send) is gated as remote. Without a remote-session lease
//! every shape is `REMOTE_SESSION_INACTIVE`, including the local-only desktop
//! shapes (clipboard, network fetch) that the tunnel used to reach. The same
//! request without a remote context is not lease-gated.
//!
//! The route values are those `orcel_lifecycle::tunnel_route::route` derives
//! for `tunnel_0123456789abcdefghijklmnopqrstuv`; the lifecycle and MCP tests
//! pin the same values.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn unique(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "orcel-fix395-{label}-{}-{nanos}",
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

fn run_orceld(state: &Path, workspace: &Path, requests: &[Value]) -> Vec<Value> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_orceld"));
    command
        .env("ORCEL_WORKSPACE_ROOT", workspace)
        .env("ORCEL_WORKSPACE_ID", "default")
        .env("ORCEL_APP_API", "off")
        .env("ORCEL_AUDIT_PATH", state.join("audit").join("audit.jsonl"))
        .env_remove("ORCEL_WORKSPACES_JSON")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if cfg!(windows) {
        command.env("LOCALAPPDATA", state);
    } else if cfg!(target_os = "linux") {
        command.env("XDG_STATE_HOME", state);
    }
    let mut child = command.spawn().expect("spawn orceld");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for request in requests {
            writeln!(stdin, "{request}").expect("write request");
        }
    }
    let responses = BufReader::new(child.stdout.take().expect("stdout"))
        .lines()
        .map(|line| serde_json::from_str(&line.expect("line")).expect("response json"))
        .collect();
    child.wait_with_output().expect("wait");
    responses
}

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

fn request(id: &str, capability: &str, operation: &str, remote: Option<Value>) -> Value {
    let mut request = json!({
        "version": 1,
        "request_id": id,
        "client_session_id": "fix395-e2e",
        "workspace_id": "default",
        "capability": capability,
        "operation": operation,
        "target": null,
        "arguments": {},
    });
    if let Some(remote) = remote {
        request["remote"] = remote;
    }
    request
}

fn code(response: &Value) -> &str {
    response["error"]["code"].as_str().unwrap_or("")
}

#[test]
fn tunnel_requests_are_lease_gated_in_orceld() {
    let state = unique("state");
    let workspace = unique("workspace");
    private_dir(&state);
    private_dir(&workspace);
    let responses = run_orceld(
        &state,
        &workspace,
        &[
            request(
                "status-remote",
                "system.status",
                "get",
                Some(tunnel_remote()),
            ),
            request(
                "clipboard-remote",
                "clipboard",
                "read",
                Some(tunnel_remote()),
            ),
            request("fetch-remote", "network", "fetch", Some(tunnel_remote())),
            request("status-local", "system.status", "get", None),
        ],
    );
    assert_eq!(responses.len(), 4, "{responses:?}");
    for response in &responses[..3] {
        assert_eq!(response["ok"], false, "{response}");
        assert_eq!(code(response), "REMOTE_SESSION_INACTIVE", "{response}");
    }
    assert_ne!(
        code(&responses[3]),
        "REMOTE_SESSION_INACTIVE",
        "{}",
        responses[3]
    );
    let _ = std::fs::remove_dir_all(&state);
    let _ = std::fs::remove_dir_all(&workspace);
}
