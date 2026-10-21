// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! #401: the live AT-SPI re-read the P-09 tool makes right before it acts
//! (`live_role_and_toggle_ref`, `platform-linux/src/tools/impl_.rs`), on a
//! real GTK3 session.
//!
//! The tool is called through the vendored registry exactly as the worker
//! calls it (`CuaCall::SemanticAction`), without the host's own check of the
//! observed state in front of it, so every refusal here is the tool's live
//! re-read. The oracles are fixture-owned: the task-state file of Cua's GTK3
//! harness (`tests/native-fixtures/apps/linux/gtk3/main.py`, task mode) and a
//! flag file a mixed check button writes when it is toggled.
//!
//! Runs only with `ORCEL_XP11_LIVE=1` and fails, rather than skipping, when
//! the session cannot observe. CI runs it in the Linux live leg under Xvfb,
//! Openbox and the AT-SPI bus.

use super::{CuaCall, CuaFailure, CuaRuntime, SemanticCall};
use crate::semantic::Verb;
use cua_driver_contract::{ListWindowsOutput, WindowElement};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const HARNESS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/native-fixtures/apps/linux/gtk3/main.py"
);
const HARNESS_TITLE: &str = "CuaTestHarness GTK3 Tasks";

/// A GTK3 window with one check button in the mixed (inconsistent) state.
/// GTK reports it to AT-SPI as `Indeterminate`. The button writes the flag
/// file if it is ever toggled.
const MIXED_PROBE: &str = r#"import sys
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

title, flag = sys.argv[1], sys.argv[2]
window = Gtk.Window(title=title)
box = Gtk.CheckButton(label="Mixed choice")
box.set_inconsistent(True)


def toggled(_button):
    with open(flag, "w", encoding="utf-8") as stream:
        stream.write("toggled")


box.connect("toggled", toggled)
window.add(box)
window.connect("destroy", Gtk.main_quit)
window.show_all()
Gtk.main()
"#;

struct Reaped(Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(command: &mut Command) -> Reaped {
    Reaped(
        command
            .env("GDK_BACKEND", "x11")
            .env("ACCESSIBILITY_ENABLED", "1")
            .env("NO_AT_BRIDGE", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .expect("python3 starts the GTK3 window"),
    )
}

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(future)
}

/// The window `pid` shows with `title`, once Cua lists it.
fn window_of(runtime: &CuaRuntime, pid: u32, title: &str) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Ok(value) = block_on(runtime.call(&CuaCall::list_windows(Some(pid)))) {
            let listed: ListWindowsOutput =
                serde_json::from_value(value).expect("the Cua window list contract");
            if let Some(window) = listed.windows.iter().find(|window| window.title == title) {
                return window.window_id;
            }
        }
        assert!(Instant::now() < deadline, "{title} was never listed");
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// A fresh snapshot's token and role for the element labelled `label`.
fn element(runtime: &CuaRuntime, pid: u32, window_id: u64, label: &str) -> (String, String) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let state = block_on(runtime.call(&CuaCall::observe(pid, window_id, 512, 16)));
        if let Ok(state) = state {
            let elements: Vec<WindowElement> =
                serde_json::from_value(state.get("elements").cloned().unwrap_or(Value::Null))
                    .unwrap_or_default();
            let found = elements.iter().find(|element| {
                element.label.as_deref() == Some(label) && element.element_token.is_some()
            });
            if let Some(found) = found {
                return (
                    found.element_token.clone().unwrap_or_default(),
                    found.role.clone(),
                );
            }
        }
        assert!(
            Instant::now() < deadline,
            "{label} never appeared in the accessibility tree"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// One toggle through the P-09 tool, on a fresh snapshot.
fn toggle(
    runtime: &CuaRuntime,
    pid: u32,
    window_id: u64,
    label: &str,
    to: bool,
) -> Result<Value, CuaFailure> {
    let (element_token, expect_role) = element(runtime, pid, window_id, label);
    block_on(runtime.call(&CuaCall::SemanticAction(SemanticCall {
        pid,
        window_id,
        element_token,
        verb: Verb::Toggle,
        expect_role,
        value: None,
        toggle_to: Some(to),
    })))
}

fn refusal(failure: &CuaFailure) -> (String, String) {
    let structured = failure.structured.as_ref();
    let code = structured
        .and_then(|value| value.get("code").or_else(|| value.pointer("/refusal/code")))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    (code, failure.message.clone())
}

fn read_state(path: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// The task-state file once `ready` holds for it.
fn wait_state(path: &Path, what: &str, ready: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(state) = read_state(path).filter(|state| ready(state)) {
            return state;
        }
        assert!(Instant::now() < deadline, "{what}: {:?}", read_state(path));
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "orcel-xp11-reread-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

#[test]
fn xp11_live_atspi_reread_acts_on_the_live_toggle_state() {
    if std::env::var_os("ORCEL_XP11_LIVE").is_none() {
        eprintln!("XP-11 live AT-SPI re-read not run: ORCEL_XP11_LIVE is not set");
        return;
    }
    let dir = scratch();
    let runtime = CuaRuntime::new();

    // Cua's GTK3 harness in task mode: "I agree" is a GTK3 check button, and
    // the harness rewrites its state file (with a sequence number) on every
    // change.
    let state_path = dir.join("task-state.json");
    let harness = spawn(
        Command::new("python3")
            .arg(HARNESS)
            .env("CUA_GTK3_TASK_STATE", &state_path),
    );
    let pid = harness.0.id();
    let launched = wait_state(&state_path, "the harness never wrote its state", |state| {
        state["pid"] == pid
    });
    assert_eq!(launched["agreed"], false, "{launched}");
    let window_id = window_of(&runtime, pid, HARNESS_TITLE);

    // Off, asked for on: the live re-read reads off, and the tool presses.
    let reply = toggle(&runtime, pid, window_id, "I agree", true);
    assert!(reply.is_ok(), "{reply:?}");
    let checked = wait_state(&state_path, "the box was never checked", |state| {
        state["agreed"] == true
    });

    // On, asked for on again: the re-read reads the live Checked state and
    // refuses. Nothing is pressed: the harness writes nothing.
    let failure = toggle(&runtime, pid, window_id, "I agree", true)
        .expect_err("a toggle to the state the box is already in");
    let (code, message) = refusal(&failure);
    assert_eq!(code, "target_stale", "{failure:?}");
    assert!(
        message.contains("already in the requested state"),
        "{failure:?}"
    );
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(read_state(&state_path), Some(checked.clone()));

    // On, asked for off: the re-read reads on, and the tool presses.
    let reply = toggle(&runtime, pid, window_id, "I agree", false);
    assert!(reply.is_ok(), "{reply:?}");
    wait_state(&state_path, "the box was never unchecked", |state| {
        state["agreed"] == false && state["seq"] != checked["seq"]
    });
    drop(harness);

    // P-12: a mixed box reaches no state either toggle names. Both are
    // refused by the live re-read, and the button is never toggled.
    let script = dir.join("mixed_probe.py");
    std::fs::write(&script, MIXED_PROBE).expect("the mixed probe is written");
    let flag = dir.join("toggled.flag");
    let title = format!("Orcel XP11 Mixed {}", std::process::id());
    let mixed = spawn(Command::new("python3").arg(&script).arg(&title).arg(&flag));
    let pid = mixed.0.id();
    let window_id = window_of(&runtime, pid, &title);
    for to in [true, false] {
        let failure = toggle(&runtime, pid, window_id, "Mixed choice", to)
            .expect_err("a toggle of a mixed box");
        let (code, message) = refusal(&failure);
        assert_eq!(code, "capability_denied", "toggle_to {to}: {failure:?}");
        assert!(
            message.contains("mixed state"),
            "toggle_to {to}: {failure:?}"
        );
    }
    std::thread::sleep(Duration::from_millis(500));
    assert!(!flag.exists(), "the mixed box was toggled");
    drop(mixed);
    let _ = std::fs::remove_dir_all(&dir);
}
