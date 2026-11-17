//! SG-000135 OB-04: Shadow mode never reaches the person's desktop.
//!
//! Every browser session, Shadow or Visible, is driven only over the
//! engine's debugging pipe (page-level input), never through the operating
//! system. This test scans the whole browser path (the browser host crate,
//! the session-state crate, the browser provider, orceld's broker,
//! profiles, live browser and dispatch, and the Node worker) for the Win32
//! calls that would move the person's foreground window, cursor, keyboard
//! focus or clipboard, and checks that the host crate cannot even compile
//! them (no keyboard-and-mouse, clipboard or windowing feature of
//! windows-sys). It complements the native check in the scripted end-to-end
//! mission (`scripts/browser-full-e2e.mjs`), which compares the foreground
//! window, cursor position and clipboard sequence number across a mission.

use std::path::{Path, PathBuf};

type Outcome = Result<(), Box<dyn std::error::Error>>;

/// Calls that would touch the person's desktop: foreground and activation,
/// synthesized OS input, the cursor, and the system clipboard.
const FORBIDDEN: &[&str] = &[
    "SetForegroundWindow",
    "AllowSetForegroundWindow",
    "LockSetForegroundWindow",
    "BringWindowToTop",
    "SetActiveWindow",
    "SwitchToThisWindow",
    "AttachThreadInput",
    "SetWindowPos",
    "ShowWindow(",
    "SendInput",
    "keybd_event",
    "mouse_event",
    "SetCursorPos",
    "OpenClipboard",
    "SetClipboardData",
    "GetClipboardData",
    "EmptyClipboard",
    "bringToFront",
    "navigator.clipboard",
];

/// windows-sys features that would let the host call those APIs.
const FORBIDDEN_FEATURES: &[&str] = &[
    "Win32_UI_Input_KeyboardAndMouse",
    "Win32_System_DataExchange",
    "Win32_UI_WindowsAndMessaging",
];

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn sources(dir: &Path, extension: &str, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            if path
                .file_name()
                .is_some_and(|name| name == "node_modules" || name == "dist")
            {
                continue;
            }
            sources(&path, extension, out)?;
        } else if path.extension().is_some_and(|ext| ext == extension) {
            out.push(path);
        }
    }
    Ok(())
}

/// Whether `line` is a comment (doc or line comment), which may name the
/// forbidden calls to say they are never made.
fn is_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*")
}

#[test]
fn ob04_no_browser_path_source_moves_focus_input_cursor_or_clipboard() -> Outcome {
    let root = repo();
    let mut files = Vec::new();
    for dir in [
        "crates/orcel-browser-host/src",
        "crates/orcel-browser-session/src",
        "crates/orcel-provider-browser/src",
    ] {
        sources(&root.join(dir), "rs", &mut files)?;
    }
    for file in [
        "browser_broker.rs",
        "browser_full.rs",
        "browser_profiles.rs",
        "live_browser.rs",
        "live_dispatch.rs",
        "takeover_gate.rs",
    ] {
        files.push(root.join("crates/orceld/src").join(file));
    }
    let worker = root.join("apps/orcel-browser-worker/src");
    let mut worker_files = Vec::new();
    sources(&worker, "ts", &mut worker_files)?;
    worker_files.retain(|path| {
        !path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().ends_with(".test.ts"))
    });
    assert!(worker_files.len() > 20, "the worker sources were found");
    files.extend(worker_files);
    assert!(files.len() > 60, "the browser path sources were found");
    let mut hits = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file)?;
        for (number, line) in text.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            for call in FORBIDDEN {
                if line.contains(call) {
                    hits.push(format!("{}:{}: {call}", file.display(), number + 1));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "desktop-touching calls on the browser path: {hits:#?}"
    );
    Ok(())
}

#[test]
fn ob04_the_browser_host_cannot_compile_input_clipboard_or_window_calls() -> Outcome {
    let manifest = std::fs::read_to_string(repo().join("crates/orcel-browser-host/Cargo.toml"))?;
    for feature in FORBIDDEN_FEATURES {
        assert!(
            !manifest.contains(feature),
            "orcel-browser-host enables {feature}"
        );
    }
    // The host does not depend on the crates that do drive the desktop.
    for crate_name in [
        "orcel-provider-clipboard",
        "orcel-provider-uia",
        "enigo",
        "rdev",
    ] {
        assert!(
            !manifest.contains(crate_name),
            "orcel-browser-host depends on {crate_name}"
        );
    }
    Ok(())
}

#[test]
fn ob04_shadow_is_the_default_and_visible_drops_only_headless() -> Outcome {
    let root = repo();
    // Line endings as checked out (a Windows checkout may use CRLF).
    let confinement =
        std::fs::read_to_string(root.join("crates/orcel-browser-host/src/confinement.rs"))?
            .replace("\r\n", "\n");
    assert!(confinement.contains("#[default]\n    Shadow,"));
    assert!(confinement.contains(
        "pub const VISIBLE_WINDOW_NAME_FLAG: &str = \"--window-name=Orcel agent session\";"
    ));
    let protocol = std::fs::read_to_string(root.join("apps/orcel-browser-worker/src/protocol.ts"))?;
    assert!(protocol.contains(
        "export const VISIBLE_WINDOW_NAME_FLAG = \"--window-name=Orcel agent session\";"
    ));
    // browser_structured never runs headed: its host launch is Shadow.
    let dispatch = std::fs::read_to_string(root.join("crates/orceld/src/live_dispatch.rs"))?;
    let structured = dispatch
        .split("mod full {")
        .next()
        .ok_or("live_dispatch.rs has a browser_structured part")?;
    assert!(structured.contains("mode: orcel_browser_host::EngineMode::Shadow,"));
    assert!(!structured.contains("EngineMode::Visible"));
    Ok(())
}
