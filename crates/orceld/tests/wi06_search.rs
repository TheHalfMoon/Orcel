//! WI-06 end to end through the real `orceld` binary and its stdio protocol,
//! on every OS: search is off without configuration, a provider the user did
//! not enable is refused, a missing key (or, off Windows, the missing native
//! transport) is unavailable, `secret.get` never returns a search key, the
//! doctor reports health without secrets, and a canary key stored through
//! `secret.put` (Windows: DPAPI under a redirected `LOCALAPPDATA`) never
//! reaches stdout, stderr or the audit log. Nothing here reaches approval or
//! the network; the adapters' provider contracts are covered by the
//! loopback contract server tests in `src/search/tests.rs`.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos()
}

fn unique(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "orcel-wi06-e2e-{label}-{}-{}",
        std::process::id(),
        nanos()
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

struct Run {
    responses: Vec<Value>,
    stdout: String,
    stderr: String,
}

fn run_orceld(state: &Path, workspace: &Path, config: Option<&str>, requests: &[Value]) -> Run {
    run_orceld_env(state, workspace, config, &[], requests)
}

fn run_orceld_env(
    state: &Path,
    workspace: &Path,
    config: Option<&str>,
    extra: &[(&str, &str)],
    requests: &[Value],
) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_orceld"));
    command
        .env("ORCEL_WORKSPACE_ROOT", workspace)
        .env("ORCEL_WORKSPACE_ID", "default")
        .env("ORCEL_APP_API", "off")
        .env("ORCEL_AUDIT_PATH", state.join("audit").join("audit.jsonl"))
        .env_remove("ORCEL_WORKSPACES_JSON")
        .env_remove("ORCEL_SEARCH_PROVIDERS_JSON")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(config) = config {
        command.env("ORCEL_SEARCH_PROVIDERS_JSON", config);
    }
    command.env_remove("ORCEL_MCP_TRANSPORT");
    for (name, value) in extra {
        command.env(name, value);
    }
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
    let mut stdout = String::new();
    let responses = BufReader::new(child.stdout.take().expect("stdout"))
        .lines()
        .map(|line| {
            let line = line.expect("line");
            stdout.push_str(&line);
            serde_json::from_str(&line).expect("response json")
        })
        .collect();
    let output = child.wait_with_output().expect("wait");
    Run {
        responses,
        stdout,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn request(
    id: &str,
    capability: &str,
    operation: &str,
    target: Option<&str>,
    arguments: Value,
) -> Value {
    json!({
        "version": 1,
        "request_id": id,
        "client_session_id": "wi06-e2e",
        "workspace_id": "default",
        "capability": capability,
        "operation": operation,
        "target": target,
        "arguments": arguments,
    })
}

fn code(response: &Value) -> &str {
    response["error"]["code"].as_str().unwrap_or("")
}

#[test]
fn wi06_real_orceld_search_is_off_and_never_leaks_a_key() {
    let state = unique("state");
    let workspace = unique("workspace");
    private_dir(&state);
    private_dir(&state.join("audit"));
    std::fs::create_dir_all(&workspace).expect("workspace");
    let canary = format!("wi06-e2e-canary-{:x}", nanos());

    // No configuration: search is off.
    let run = run_orceld(
        &state,
        &workspace,
        None,
        &[
            request("q0", "search", "query", None, json!({"query": "rust"})),
            request("d0", "search", "doctor", None, json!({})),
            request(
                "bad",
                "search",
                "query",
                None,
                json!({"query": "q", "origin": "https://evil.example"}),
            ),
            request("op", "search", "configure", None, json!({})),
        ],
    );
    assert_eq!(run.responses.len(), 4, "{}", run.stderr);
    assert_eq!(
        code(&run.responses[0]),
        "PROVIDER_UNAVAILABLE",
        "{}",
        run.responses[0]
    );
    assert_eq!(run.responses[1]["ok"], true, "{}", run.responses[1]);
    assert_eq!(run.responses[1]["result"]["config"], "absent");
    assert_eq!(code(&run.responses[2]), "INVALID_REQUEST");
    assert_eq!(code(&run.responses[3]), "CAPABILITY_DENIED");

    // Brave enabled. On Windows a canary key is stored first.
    let config = r#"{"providers":{"brave":{"daily_query_cap":3}}}"#;
    let mut requests = Vec::new();
    if cfg!(windows) {
        requests.push(request(
            "put",
            "secret",
            "put",
            Some("search.brave.key"),
            json!({ "value": canary }),
        ));
    }
    requests.extend([
        request("doctor", "search", "doctor", None, json!({})),
        request(
            "disabled",
            "search",
            "query",
            None,
            json!({"query": "q", "provider": "exa"}),
        ),
        request("get", "secret", "get", Some("search.brave.key"), json!({})),
        request(
            "unknown",
            "secret",
            "get",
            Some("search.google.key"),
            json!({}),
        ),
        request(
            "malformed",
            "search",
            "query",
            None,
            json!({"query": "q\u{0}"}),
        ),
    ]);
    let run = run_orceld(&state, &workspace, Some(config), &requests);
    assert_eq!(run.responses.len(), requests.len(), "{}", run.stderr);
    let by_id = |id: &str| {
        run.responses
            .iter()
            .find(|response| response["request_id"] == id)
            .cloned()
            .unwrap_or_else(|| panic!("no response {id}"))
    };
    if cfg!(windows) {
        assert_eq!(by_id("put")["ok"], true, "{}", by_id("put"));
    }
    let doctor = by_id("doctor");
    assert_eq!(doctor["ok"], true, "{doctor}");
    let brave = doctor["result"]["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["provider"] == "brave")
        .cloned()
        .unwrap();
    assert_eq!(brave["enabled"], true);
    assert_eq!(brave["origin"], "https://api.search.brave.com");
    assert_eq!(brave["daily_query_cap"], 3);
    if cfg!(windows) {
        assert_eq!(brave["key"], "stored", "{brave}");
        assert_eq!(brave["status"], "ready", "{brave}");
    } else {
        // No native HTTPS transport off Windows in this build.
        assert_eq!(brave["status"], "unavailable", "{brave}");
    }
    assert_eq!(doctor["result"]["secrets_reported"], false);
    assert_eq!(code(&by_id("disabled")), "CAPABILITY_DENIED");
    assert_eq!(code(&by_id("get")), "CAPABILITY_DENIED", "{}", by_id("get"));
    assert_eq!(code(&by_id("unknown")), "INVALID_REQUEST");
    assert_eq!(code(&by_id("malformed")), "INVALID_REQUEST");

    // Missing key: delete it, then a query is unavailable (off Windows the
    // transport is unavailable first; either way nothing is sent).
    let mut requests = Vec::new();
    if cfg!(windows) {
        requests.push(request(
            "del",
            "secret",
            "delete",
            Some("search.brave.key"),
            json!({}),
        ));
    }
    requests.push(request(
        "nokey",
        "search",
        "query",
        None,
        json!({"query": "q"}),
    ));
    let after = run_orceld(&state, &workspace, Some(config), &requests);
    let nokey = after.responses.last().cloned().expect("nokey");
    assert_eq!(code(&nokey), "PROVIDER_UNAVAILABLE", "{nokey}");
    if cfg!(windows) {
        assert_eq!(after.responses[0]["result"]["deleted"], true);
        assert!(nokey["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no API key"));
    }

    // The tunnel host (orcel-mcp-host sets ORCEL_MCP_TRANSPORT=tunnel) refuses
    // search even with providers configured.
    let tunnel = run_orceld_env(
        &state,
        &workspace,
        Some(config),
        &[("ORCEL_MCP_TRANSPORT", "tunnel")],
        &[
            request("tq", "search", "query", None, json!({"query": "q"})),
            request("td", "search", "doctor", None, json!({})),
        ],
    );
    assert_eq!(tunnel.responses.len(), 2, "{}", tunnel.stderr);
    for response in &tunnel.responses {
        assert_eq!(code(response), "CAPABILITY_DENIED", "{response}");
    }

    // The canary never left orceld.
    let audit =
        std::fs::read_to_string(state.join("audit").join("audit.jsonl")).unwrap_or_default();
    for (what, text) in [
        ("stdout", &run.stdout),
        ("stderr", &run.stderr),
        ("stdout", &after.stdout),
        ("stderr", &after.stderr),
        ("audit", &audit),
    ] {
        assert!(!text.contains(&canary), "{what} holds the canary key");
    }
    if cfg!(windows) {
        for entry in walk(&state) {
            let bytes = std::fs::read(&entry).expect("read");
            assert!(
                !String::from_utf8_lossy(&bytes).contains(&canary),
                "{} holds the canary key in plaintext",
                entry.display()
            );
        }
    }
    let _ = std::fs::remove_dir_all(&state);
    let _ = std::fs::remove_dir_all(&workspace);
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
    }
    out
}
