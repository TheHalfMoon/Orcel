// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! Drives the real `orcel-native-host` binary over its stdio pipes, the way
//! orceld's adapter does, and keeps every raw response line.

#![allow(dead_code)]

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    /// The highest resident memory seen so far, in KiB (M-NAT-04).
    peak_rss_kib: Arc<AtomicU64>,
    stop_sampling: Arc<AtomicBool>,
}

/// A process's resident memory in KiB, or `None` once it has gone.
fn rss_kib(pid: u32) -> Option<u64> {
    if cfg!(target_os = "linux") {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
        line.split_whitespace().nth(1)?.parse().ok()
    } else {
        let out = Command::new("ps")
            .args(["-o", "rss=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    }
}

/// Samples the host once a second, as M-NAT-04 asks, until told to stop or it exits.
fn sample_rss(pid: u32, peak: Arc<AtomicU64>, stop: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match rss_kib(pid) {
                Some(kib) => {
                    peak.fetch_max(kib, Ordering::Relaxed);
                }
                None => return,
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });
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
        let mut child = Command::new(
            std::env::var_os("ORCEL_NATIVE_TEST_HOST").unwrap_or_else(|| {
                std::ffi::OsString::from(env!("CARGO_BIN_EXE_orcel-native-host"))
            }),
        )
        .env_clear()
        .envs(environment)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the host starts");
        let stdin = child.stdin.take().expect("stdin");
        let lines = reader(child.stdout.take().expect("stdout"));
        let peak_rss_kib = Arc::new(AtomicU64::new(0));
        let stop_sampling = Arc::new(AtomicBool::new(false));
        sample_rss(
            child.id(),
            Arc::clone(&peak_rss_kib),
            Arc::clone(&stop_sampling),
        );
        Self {
            child,
            stdin,
            lines,
            next_id: 1,
            log: Vec::new(),
            peak_rss_kib,
            stop_sampling,
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

    /// The host's peak resident memory so far, in MiB, sampled once a second. Real
    /// memory of this one process: not the fixture apps, and a peak between samples
    /// isn't seen.
    #[allow(dead_code)]
    pub fn rss_mb_peak(&self) -> f64 {
        self.peak_rss_kib.load(Ordering::Relaxed) as f64 / 1024.0
    }

    pub fn shutdown(mut self) -> std::process::ExitStatus {
        let reply = self.request("shutdown", json!({}));
        assert_eq!(reply["ok"], true);
        self.child.wait().expect("host exits")
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.stop_sampling.store(true, Ordering::Relaxed);
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

// ---------------------------------------------------------------------------
// The XP-12 input probe: an application that journals what it receives.

pub struct Probe {
    pub child: Child,
    pub state: PathBuf,
    pub flag: PathBuf,
    dir: PathBuf,
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn probe_scratch(nonce: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("orcel-xp12-{nonce}"));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

pub fn spawn_probe(nonce: &str) -> Probe {
    let fixtures = std::env::var("ORCEL_NATIVE_TEST_FIXTURES")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures").to_string());
    let dir = probe_scratch(nonce);
    let state = dir.join("state.json");
    let flag = dir.join("cover.flag");
    let mut command = if cfg!(target_os = "macos") {
        let binary = dir.join("appkit_input_probe");
        let built = Command::new("swiftc")
            .args([
                "-O",
                "-swift-version",
                "5",
                &format!("{fixtures}/appkit_input_probe.swift"),
                "-o",
            ])
            .arg(&binary)
            .status()
            .expect("swiftc runs");
        assert!(built.success(), "the AppKit probe did not compile");
        Command::new(binary)
    } else {
        let mut command = Command::new("python3");
        command.arg(format!("{fixtures}/tk_input_probe.py"));
        command
    };
    let child = command
        .arg(nonce)
        .arg(&state)
        .arg(&flag)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .expect("the probe starts");
    Probe {
        child,
        state,
        flag,
        dir,
    }
}

pub fn read_state(path: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

pub fn wait_for(path: &Path, what: &str, ready: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Some(state) = read_state(path) {
            if ready(&state) {
                return state;
            }
        }
        assert!(
            Instant::now() < deadline,
            "{what}: the probe never got there"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn events(state: &Value) -> Vec<Value> {
    state["events"].as_array().cloned().unwrap_or_default()
}
