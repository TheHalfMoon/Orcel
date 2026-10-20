//! XP-19 end to end through the real `orceld` binary and its stdio protocol:
//! store, load and delete the device key, migrate a legacy plaintext record,
//! and prove the value never reaches stderr, the audit log or a failure.
//!
//! Windows always runs it (DPAPI, with `LOCALAPPDATA` pointed at a fresh
//! directory). macOS and Linux run it when `ORCEL_REQUIRE_XP19_KEYRING` is
//! set (CI, with a temporary keychain or a headless gnome-keyring), because
//! it writes the real `device.key` item of the current user. On Linux with
//! `ORCEL_XP19_EXPECT_NO_KEYRING` set it checks the unavailable path instead.

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
        "orcel-xp19-e2e-{label}-{}-{nanos}",
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

struct Run {
    responses: Vec<Value>,
    stderr: String,
}

fn run_orceld(state: &Path, workspace: &Path, requests: &[Value]) -> Run {
    let lines: Vec<String> = requests.iter().map(Value::to_string).collect();
    run_orceld_lines(state, workspace, &lines)
}

fn run_orceld_lines(state: &Path, workspace: &Path, requests: &[String]) -> Run {
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
    let output = child.wait_with_output().expect("wait");
    Run {
        responses,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn request(id: &str, operation: &str, arguments: Value) -> Value {
    json!({
        "version": 1,
        "request_id": id,
        "client_session_id": "xp19-e2e",
        "workspace_id": "default",
        "capability": "secret",
        "operation": operation,
        "target": "device.key",
        "arguments": arguments,
    })
}

fn canary() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("xp19-e2e-canary-{nanos:x}")
}

fn assert_clean(run: &Run, state: &Path, secret: &str) {
    assert!(
        !run.stderr.contains(secret),
        "orceld stderr holds the secret"
    );
    let audit =
        std::fs::read_to_string(state.join("audit").join("audit.jsonl")).unwrap_or_default();
    assert!(!audit.contains(secret), "the audit log holds the secret");
    for response in &run.responses {
        if response["ok"] == false {
            assert!(
                !response.to_string().contains(secret),
                "a failure holds the secret"
            );
        }
    }
}

#[test]
fn xp19_real_orceld_stores_loads_deletes_and_migrates() {
    if std::env::var_os("ORCEL_XP19_EXPECT_NO_KEYRING").is_some() {
        return;
    }
    if !cfg!(windows) && std::env::var_os("ORCEL_REQUIRE_XP19_KEYRING").is_none() {
        eprintln!(
            "skipped: set ORCEL_REQUIRE_XP19_KEYRING=1 to use this user's real keychain or keyring"
        );
        return;
    }
    let state = unique("state");
    let workspace = unique("workspace");
    private_dir(&state);
    private_dir(&state.join("audit"));
    std::fs::create_dir_all(&workspace).expect("workspace");
    let secret = canary();

    let run = run_orceld(
        &state,
        &workspace,
        &[
            request("put", "put", json!({ "value": secret })),
            request("get", "get", json!({})),
            request("delete", "delete", json!({})),
            request("missing", "get", json!({})),
            request("again", "delete", json!({})),
        ],
    );
    assert_eq!(run.responses.len(), 5, "{}", run.stderr);
    for response in &run.responses {
        assert_eq!(response["ok"], true, "{response}");
    }
    assert_eq!(run.responses[1]["result"]["value"], secret.as_str());
    assert!(run.responses[3]["result"]["value"].is_null());
    assert_eq!(run.responses[4]["result"]["deleted"], false);
    assert_clean(&run, &state, &secret);
    if cfg!(windows) {
        // Nothing in the state root is plaintext.
        for entry in walk(&state) {
            let bytes = std::fs::read(&entry).expect("read");
            assert!(
                !String::from_utf8_lossy(&bytes).contains(&secret),
                "{} holds the secret",
                entry.display()
            );
        }
    }

    // Migration reads the legacy record from this state root only; macOS
    // would need a redirected HOME, which also moves the keychain search
    // list, so it is covered by the unit tests there.
    if cfg!(any(windows, target_os = "linux")) {
        let root = if cfg!(windows) {
            state.join("Orcel")
        } else {
            state.join("orcel")
        };
        let record_dir = root.join("state").join("device");
        private_dir(&root);
        private_dir(&root.join("state"));
        private_dir(&record_dir);
        let record = record_dir.join("device_key.json");
        let legacy = canary() + "-legacy";
        write_private(
            &record,
            &json!({
                "deviceId": format!("dev-{}", "d".repeat(32)),
                "publicKeyJwkBase64": "cHVibGlj",
                "privateKeyJwkBase64": legacy,
                "createdAtMs": 1,
                "epoch": 1,
            })
            .to_string(),
        );
        let run = run_orceld(
            &state,
            &workspace,
            &[
                request("m1", "migrate", json!({})),
                request("m2", "migrate", json!({})),
                request("g", "get", json!({})),
                request("d", "delete", json!({})),
            ],
        );
        assert_eq!(run.responses.len(), 4, "{}", run.stderr);
        assert_eq!(
            run.responses[0]["result"]["migration"], "migrated",
            "{}",
            run.responses[0]
        );
        assert_eq!(
            run.responses[1]["result"]["migration"],
            "nothing_to_migrate"
        );
        assert_eq!(run.responses[2]["result"]["value"], legacy.as_str());
        assert_eq!(run.responses[3]["result"]["deleted"], true);
        let left = std::fs::read_to_string(&record).expect("public record");
        assert!(!left.contains(&legacy), "plaintext left behind");
        assert!(left.contains("dev-"), "public identity kept");
        assert_clean(&run, &state, &legacy);
    }
    let _ = std::fs::remove_dir_all(&state);
    let _ = std::fs::remove_dir_all(&workspace);
}

/// Linux CI: with no session bus the real binary answers unavailable and
/// writes nothing.
#[test]
fn xp19_real_orceld_without_a_keyring_is_unavailable() {
    if std::env::var_os("ORCEL_XP19_EXPECT_NO_KEYRING").is_none() {
        return;
    }
    let state = unique("nokeyring");
    let workspace = unique("nokeyring-ws");
    private_dir(&state);
    private_dir(&state.join("audit"));
    std::fs::create_dir_all(&workspace).expect("workspace");
    let secret = canary();
    let run = run_orceld(
        &state,
        &workspace,
        &[
            request("put", "put", json!({ "value": secret })),
            request("get", "get", json!({})),
        ],
    );
    assert_eq!(run.responses.len(), 2, "{}", run.stderr);
    for response in &run.responses {
        assert_eq!(response["ok"], false, "{response}");
        assert_eq!(
            response["error"]["code"], "PROVIDER_UNAVAILABLE",
            "{response}"
        );
    }
    assert_clean(&run, &state, &secret);
    for entry in walk(&state) {
        let bytes = std::fs::read(&entry).expect("read");
        assert!(!String::from_utf8_lossy(&bytes).contains(&secret));
        assert!(
            !entry.to_string_lossy().contains("secrets"),
            "{}",
            entry.display()
        );
    }
    let _ = std::fs::remove_dir_all(&state);
    let _ = std::fs::remove_dir_all(&workspace);
}

fn write_private(path: &Path, text: &str) {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .expect("write record");
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

/// A request line that does not parse is answered without quoting it, so a
/// value in a malformed request never comes back in the failure.
#[test]
fn xp19_malformed_request_json_is_never_echoed() {
    let state = unique("malformed");
    let workspace = unique("malformed-ws");
    private_dir(&state);
    private_dir(&state.join("audit"));
    std::fs::create_dir_all(&workspace).expect("workspace");
    let secret = canary();
    let lines = vec![
        format!(r#"{{"version":"{secret}"}}"#),
        format!(r#"{{"version":1,"request_id":["{secret}"]}}"#),
        format!(r#"{{"value":"{secret}""#),
    ];
    let run = run_orceld_lines(&state, &workspace, &lines);
    assert_eq!(run.responses.len(), lines.len(), "{}", run.stderr);
    for response in &run.responses {
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"]["code"], "INVALID_REQUEST");
        assert!(!response.to_string().contains(&secret), "{response}");
    }
    assert!(!run.stderr.contains(&secret));
    let _ = std::fs::remove_dir_all(&state);
    let _ = std::fs::remove_dir_all(&workspace);
}
