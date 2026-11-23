//! The real `orceld` with a standard error that cannot be written: it serves
//! requests all the same. Its log lines are lost, nothing else.
#![cfg(unix)]

use serde_json::{json, Value};
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(label: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "orceld-stderr-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        for dir in [base.clone(), base.join("home"), base.join("workspace")] {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(base)
    }

    /// Runs `orceld` with `stderr`, asks for `system.status` once and
    /// returns the answer. `orceld` must also exit cleanly.
    fn status(&self, stderr: Stdio) -> Value {
        let mut child = Command::new(env!("CARGO_BIN_EXE_orceld"))
            .env_clear()
            .env("HOME", self.0.join("home"))
            .env("PATH", "/usr/bin:/bin")
            .env("ORCEL_WORKSPACE_ROOT", self.0.join("workspace"))
            .env("ORCEL_WORKSPACE_ID", "default")
            // Its "disabled" line is one more line that cannot be written.
            .env("ORCEL_APP_API", "off")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .expect("start orceld");
        let request = json!({
            "version": 1,
            "request_id": "stderr-unwritable",
            "client_session_id": "stderr-unwritable",
            "workspace_id": "default",
            "capability": "system.status",
            "operation": "get",
            "target": null,
            "arguments": {},
        });
        // An orceld that already died makes this write fail; the assertions
        // below then say what happened.
        let _ = writeln!(child.stdin.take().unwrap(), "{request}");
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let first = stdout.lines().next().expect("an answer");
        serde_json::from_str(first).expect("response json")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn orceld_serves_with_a_closed_stderr() {
    let sandbox = Sandbox::new("closed");
    let (ours, theirs) = UnixStream::pair().unwrap();
    // Every write to it fails (EPIPE) from here on.
    drop(ours);
    let answer = sandbox.status(Stdio::from(OwnedFd::from(theirs)));
    assert_eq!(answer["ok"], true, "{answer}");
    assert_eq!(answer["result"]["name"], "orceld", "{answer}");
}

/// A full disk: every write fails with ENOSPC. Linux has a device for it.
#[cfg(target_os = "linux")]
#[test]
fn orceld_serves_with_a_full_stderr() {
    let sandbox = Sandbox::new("full");
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let answer = sandbox.status(Stdio::from(full));
    assert_eq!(answer["ok"], true, "{answer}");
}
