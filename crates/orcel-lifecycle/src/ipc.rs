//! A local client for one request to the installed `orceld`, used by
//! `doctor` and by the human-invoked trust and approval commands. It speaks
//! the existing internal JSON-line protocol; every request goes through the
//! policy kernel and approval broker exactly as MCP-originated requests do.

use crate::config::Config;
use crate::LifecycleError;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// OS execution variables in the exact casing the closed `orcel-tunnel`
/// allowlist expects.
const OS_VARIABLES: &[&str] = &[
    "Path",
    "PATHEXT",
    "SystemRoot",
    "WINDIR",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "PROGRAMDATA",
    "ProgramFiles",
    "ProgramFiles(x86)",
];

/// The current environment with OS execution variable names normalized to
/// their canonical casing. Windows variable names are case-insensitive, but
/// some launchers (for example MSYS shells) export `SYSTEMROOT`; without
/// normalization the case-sensitive allowlist would drop `SystemRoot` and
/// children could not initialize Winsock.
pub fn host_environment() -> BTreeMap<String, String> {
    normalize_environment(std::env::vars())
}

pub fn normalize_environment(
    vars: impl IntoIterator<Item = (String, String)>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (name, value) in vars {
        let canonical = OS_VARIABLES
            .iter()
            .find(|known| known.eq_ignore_ascii_case(&name))
            .map(|known| (*known).to_string())
            .unwrap_or(name);
        out.entry(canonical).or_insert(value);
    }
    out
}

/// Environment for Orcel child processes: the closed `orcel-tunnel`
/// allowlist (OS execution variables and safe Orcel variables, with every
/// secret-like name removed) plus the configured workspaces.
pub fn child_environment(config: &Config) -> BTreeMap<String, String> {
    let mut env = orcel_tunnel::sanitized_env(&host_environment());
    env.remove("ORCEL_WORKSPACE_ROOT");
    env.remove("ORCEL_WORKSPACE_ID");
    env.insert("ORCEL_WORKSPACES_JSON".into(), config.workspaces_json());
    if let Some(default) = config.default_workspace() {
        env.insert("ORCEL_DEFAULT_WORKSPACE".into(), default.into());
    }
    env
}

pub fn request(workspace_id: &str, capability: &str, operation: &str, arguments: Value) -> Value {
    json!({
        "version": 1,
        "request_id": format!("orcel-cli-{}", crate::nonce()),
        "client_session_id": "orcel-cli",
        "workspace_id": workspace_id,
        "capability": capability,
        "operation": operation,
        "target": null,
        "arguments": arguments,
    })
}

/// Sends one request to a fresh `orceld` and returns the response envelope.
pub fn call(
    orceld: &Path,
    config: &Config,
    request: &Value,
    timeout: Duration,
) -> Result<Value, LifecycleError> {
    call_with_env(orceld, config, &[], request, timeout)
}

/// [`call`] with extra non-secret variables for this one local request
/// (WI-06: `orcel search status` passes the user's
/// `ORCEL_SEARCH_PROVIDERS_JSON`, which no tunnel launch ever carries).
pub fn call_with_env(
    orceld: &Path,
    config: &Config,
    extra: &[(&str, String)],
    request: &Value,
    timeout: Duration,
) -> Result<Value, LifecycleError> {
    let mut env = child_environment(config);
    for (name, value) in extra {
        env.insert((*name).to_string(), value.clone());
    }
    let mut child = Command::new(orceld)
        .env_clear()
        .envs(env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| LifecycleError::state(format!("start orceld: {error}")))?;
    // Keep a bounded tail of orceld's diagnostics for failure messages.
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| LifecycleError::internal("orceld stderr unavailable"))?;
    // Drain stderr in fixed-size chunks and keep only the last complete,
    // already-redacted line, so truncation can never cut a credential marker
    // away from its value. Over-long lines are dropped, not truncated. The
    // result is handed back over a channel so a descendant holding the pipe
    // can never block this call.
    let (diagnostics_sender, diagnostics) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        const MAX_LINE_BYTES: usize = 8 * 1024;
        let mut stderr = stderr;
        let mut line = Vec::<u8>::new();
        let mut oversized = false;
        let mut last = String::new();
        let finish_line = |line: &mut Vec<u8>, oversized: &mut bool, last: &mut String| {
            let text = String::from_utf8_lossy(line);
            if *oversized {
                *last = "[diagnostic line too long]".into();
            } else if !text.trim().is_empty() {
                *last = crate::logs::redact_line(text.trim_end_matches('\r'))
                    .chars()
                    .take(400)
                    .collect();
            }
            line.clear();
            *oversized = false;
        };
        let mut chunk = [0u8; 1024];
        while let Ok(read) = std::io::Read::read(&mut stderr, &mut chunk) {
            if read == 0 {
                break;
            }
            for &byte in &chunk[..read] {
                if byte == b'\n' {
                    finish_line(&mut line, &mut oversized, &mut last);
                } else if line.len() < MAX_LINE_BYTES {
                    line.push(byte);
                } else {
                    oversized = true;
                }
            }
        }
        finish_line(&mut line, &mut oversized, &mut last);
        let _ = diagnostics_sender.send(last);
    });
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| LifecycleError::internal("orceld stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| LifecycleError::internal("orceld stdout unavailable"))?;
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = sender.send(result);
    });
    let written = writeln!(stdin, "{request}").and_then(|()| stdin.flush());
    let response = match written {
        Ok(()) => receiver.recv_timeout(timeout),
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(LifecycleError::state(format!("write to orceld: {error}")));
        }
    };
    drop(stdin);
    let outcome = match response {
        Ok(Ok(line)) if !line.trim().is_empty() => serde_json::from_str::<Value>(line.trim())
            .map_err(|error| {
                LifecycleError::state(format!("orceld response is not JSON: {error}"))
            }),
        Ok(Ok(_)) => Err(LifecycleError::state("orceld exited without a response")),
        Ok(Err(error)) => Err(LifecycleError::state(format!(
            "read orceld response: {error}"
        ))),
        Err(_) => Err(LifecycleError::state(
            "orceld did not respond within the time limit",
        )),
    };
    // orceld exits on stdin EOF; make sure it does not outlive this call.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let exited = loop {
        match child.try_wait() {
            Ok(Some(_)) => break true,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            _ => {
                let _ = child.kill();
                break child.wait().is_ok();
            }
        }
    };
    let tail = if exited {
        diagnostics
            .recv_timeout(Duration::from_millis(500))
            .unwrap_or_default()
    } else {
        String::new()
    };
    outcome.map_err(|error| {
        if tail.is_empty() {
            error
        } else {
            LifecycleError::state(format!("{} (orceld: {tail})", error.message))
        }
    })
}

/// Returns the `result` of a successful response or the typed error.
pub fn expect_ok(response: &Value) -> Result<&Value, LifecycleError> {
    if response.get("ok").and_then(Value::as_bool) == Some(true) {
        return response
            .get("result")
            .ok_or_else(|| LifecycleError::state("orceld response has no result"));
    }
    let code = response
        .pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN");
    let message = response
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("unspecified failure");
    Err(LifecycleError::state(format!("orceld {code}: {message}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WorkspaceEntry;

    #[test]
    fn child_environment_carries_workspaces_and_no_secrets() {
        let config = Config {
            workspaces: vec![WorkspaceEntry {
                id: "default".into(),
                root: std::env::temp_dir(),
            }],
            ..Config::default()
        };
        let env = child_environment(&config);
        assert!(env.contains_key("ORCEL_WORKSPACES_JSON"));
        assert_eq!(env.get("ORCEL_DEFAULT_WORKSPACE").unwrap(), "default");
        for name in env.keys() {
            let upper = name.to_ascii_uppercase();
            for needle in [
                "SECRET",
                "TOKEN",
                "PASSWORD",
                "API_KEY",
                "TUNNEL_KEY",
                "CREDENTIAL",
            ] {
                assert!(!upper.contains(needle), "{name}");
            }
        }
    }

    #[test]
    fn os_variable_casing_is_normalized_before_the_allowlist() {
        let env = normalize_environment([
            ("SYSTEMROOT".to_string(), r"C:\Windows".to_string()),
            ("PATH".to_string(), r"C:\bin".to_string()),
            ("temp".to_string(), r"C:\t".to_string()),
            ("OPENAI_API_KEY".to_string(), "leak".to_string()),
        ]);
        let sanitized = orcel_tunnel::sanitized_env(&env);
        assert_eq!(sanitized.get("SystemRoot").unwrap(), r"C:\Windows");
        assert_eq!(sanitized.get("Path").unwrap(), r"C:\bin");
        assert_eq!(sanitized.get("TEMP").unwrap(), r"C:\t");
        assert!(!sanitized.contains_key("OPENAI_API_KEY"));
    }

    #[test]
    fn error_envelopes_are_typed() {
        let error = expect_ok(&json!({
            "ok": false,
            "error": {"code": "APPROVAL_DENIED", "message": "denied"}
        }))
        .unwrap_err();
        assert!(error.message.contains("APPROVAL_DENIED"));
        let ok = json!({"ok": true, "result": {"name": "orceld"}});
        assert_eq!(expect_ok(&ok).unwrap()["name"], "orceld");
    }
}
