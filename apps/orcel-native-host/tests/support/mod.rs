// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! Drives the real `orcel-native-host` binary over its stdio pipes, the way
//! orceld's adapter does, and keeps every raw response line.

#![allow(dead_code)]

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

/// The environment orceld passes the host on this OS
/// (`orcel-provider-uia/src/computer_host.rs`, `HOST_ENV`).
#[cfg(target_os = "macos")]
pub const HOST_ENV: &[&str] = &["PATH", "LANG", "TMPDIR"];
#[cfg(not(target_os = "macos"))]
pub const HOST_ENV: &[&str] = &[
    "PATH",
    "LANG",
    "HOME",
    "DISPLAY",
    "XAUTHORITY",
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP",
    "XDG_SESSION_DESKTOP",
    "DESKTOP_SESSION",
    "SWAYSOCK",
    "KDE_FULL_SESSION",
];

pub const PROTOCOL: &str = "orcel-computer-host/2";
/// One worker deadline is 8 s and an observation gets two attempts.
pub const RESPONSE_DEADLINE: Duration = Duration::from_secs(40);

pub struct Host {
    pub child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    next_id: u64,
    /// Every raw response line, for frame-log assertions.
    pub log: Vec<String>,
}

fn reader(stdout: ChildStdout) -> Receiver<String> {
    let (sender, receiver) = channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { return };
            if sender.send(line).is_err() {
                return;
            }
        }
    });
    receiver
}

impl Host {
    /// Spawns the host with orceld's environment allowlist.
    pub fn spawn() -> Self {
        Self::spawn_with(
            HOST_ENV
                .iter()
                .filter_map(|name| std::env::var_os(name).map(|value| (name.to_string(), value))),
        )
    }

    /// Spawns the host with exactly `environment`.
    pub fn spawn_with(environment: impl IntoIterator<Item = (String, std::ffi::OsString)>) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_orcel-native-host"))
            .env_clear()
            .envs(environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the host starts");
        let stdin = child.stdin.take().expect("stdin");
        let lines = reader(child.stdout.take().expect("stdout"));
        Self {
            child,
            stdin,
            lines,
            next_id: 1,
            log: Vec::new(),
        }
    }

    /// Sends one line; `None` when the host closed its pipes instead of
    /// answering.
    pub fn send_raw(&mut self, line: &str) -> Option<Value> {
        let written = self
            .stdin
            .write_all(format!("{line}\n").as_bytes())
            .and_then(|()| self.stdin.flush());
        if written.is_err() {
            return None;
        }
        let reply = self.lines.recv_timeout(RESPONSE_DEADLINE).ok()?;
        self.log.push(reply.clone());
        Some(serde_json::from_str(&reply).expect("one JSON response line"))
    }

    /// Sends `op` with `fields` and returns the response, checking that it
    /// echoes the id, protocol and host identity.
    pub fn request(&mut self, op: &str, fields: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let mut frame = json!({"id": id, "protocol": PROTOCOL, "op": op});
        if let (Some(frame), Some(fields)) = (frame.as_object_mut(), fields.as_object()) {
            frame.extend(fields.clone());
        }
        let reply = self
            .send_raw(&frame.to_string())
            .unwrap_or_else(|| panic!("no answer to {op}"));
        assert_eq!(reply["id"], id, "{reply}");
        assert_eq!(reply["protocol"], PROTOCOL, "{reply}");
        assert_eq!(reply["host"], "orcel-native-host", "{reply}");
        reply
    }

    pub fn hello(&mut self) -> Value {
        self.request("hello", json!({}))
    }

    pub fn shutdown(mut self) -> std::process::ExitStatus {
        let reply = self.request("shutdown", json!({}));
        assert_eq!(reply["ok"], true);
        self.child.wait().expect("host exits")
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The window kind this OS serves.
pub fn window_kind() -> &'static str {
    if cfg!(target_os = "macos") {
        "cgwindow"
    } else if std::env::var_os("WAYLAND_DISPLAY").is_some_and(|value| !value.is_empty()) {
        "wl_toplevel"
    } else {
        "x11"
    }
}

/// A `/2` window reference for a listed window fact.
pub fn window_ref(window: &Value) -> Value {
    json!({
        "kind": window_kind(),
        "id": window["hwnd"],
        "expected_pid": window["process"]["pid"],
        "expected_start_generation": window["process"]["start_generation"],
        "expected_window_nonce": window["window_nonce"],
    })
}

/// Every element of a tree, depth first.
pub fn flatten(elements: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    for element in elements.as_array().into_iter().flatten() {
        out.push(element.clone());
        out.extend(flatten(&element["children"]));
    }
    out
}

pub fn error_code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or_default()
}
