//! XP-15 clipboard ownership-loss qualification (macOS and Linux).
//!
//! orceld speaks line-delimited JSON on stdout and holds the stdout lock
//! for its session, so the native clipboard adapter must never print. The
//! risky moment is when another client takes the clipboard: an X11
//! selection-server thread then receives `SelectionClear`. This test runs
//! without the libtest harness so the observed process owns its stdout
//! completely. It re-runs itself in two roles:
//!
//! - `scenario`, the observed process, with stdout captured: it places a
//!   marker, lets a second process take the clipboard, then places and
//!   reads back a new marker;
//! - `other-owner`, a second clipboard client in its own process, which
//!   places its own text and holds it until its stdin closes.
//!
//! The driver asserts the scenario succeeded and wrote nothing to stdout.
//! The other owner's stdout is sent to null and intentionally not
//! checked: it is a helper standing in for some other application, and
//! only the observed adapter process carries orceld's protocol.
//! Without a reachable clipboard it reports why and passes, unless
//! `ORCEL_REQUIRE_LIVE_CLIPBOARD=1` is set, as CI sets it on macOS and on
//! Linux under Xvfb. Other platforms report that the test does not apply.

use orcel_provider_clipboard::{
    read_bounded_text, write_bounded_text, ClipboardAdapter, NativeAdapter,
};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

const ROLE: &str = "ORCEL_XP15_OWNERSHIP_ROLE";
const WORKSPACE: &str = "xp15-ownership-workspace";
const POLICY: &str = "xp15-ownership-v1";
const FIRST: &str = "orcel-xp15-ownership-first";
const OTHER: &str = "orcel-xp15-ownership-other-owner";
const SECOND: &str = "orcel-xp15-ownership-second";
/// Scenario exit code for "no clipboard is reachable in this session".
const UNAVAILABLE: u8 = 2;

fn main() -> ExitCode {
    match std::env::var(ROLE).as_deref() {
        Ok("scenario") => scenario(),
        Ok("other-owner") => other_owner(),
        _ => driver(),
    }
}

/// Wait until the bounded read returns `expected`, or give up.
fn read_until(native: &NativeAdapter, expected: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last = String::from("nothing read");
    while Instant::now() < deadline {
        match native
            .sequence_number()
            .and_then(|sequence| read_bounded_text(native, Some(sequence), WORKSPACE, POLICY))
        {
            Ok(outcome) if outcome.text == expected => return Ok(()),
            Ok(outcome) => last = format!("read {} bytes of other text", outcome.text.len()),
            Err(error) => last = error.message,
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!("expected text never appeared ({last})"))
}

fn other_owner() -> ExitCode {
    let native = NativeAdapter::new();
    if let Err(error) = write_bounded_text(&native, OTHER, WORKSPACE, POLICY) {
        eprintln!("other owner could not place text: {}", error.message);
        return ExitCode::FAILURE;
    }
    // Hold the clipboard (an X11 selection lives with its owner) until the
    // scenario closes our stdin.
    let _ = std::io::copy(&mut std::io::stdin(), &mut std::io::sink());
    ExitCode::SUCCESS
}

fn scenario() -> ExitCode {
    let native = NativeAdapter::new();
    if let Err(error) = write_bounded_text(&native, FIRST, WORKSPACE, POLICY) {
        eprintln!("scenario unavailable: {}", error.message);
        return ExitCode::from(UNAVAILABLE);
    }
    let steps = || -> Result<(), String> {
        read_until(&native, FIRST)?;
        let exe = std::env::current_exe().map_err(|error| error.to_string())?;
        let mut other = Command::new(exe)
            .env(ROLE, "other-owner")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .map_err(|error| error.to_string())?;
        // The other process now owns the clipboard; ours lost it.
        let taken = read_until(&native, OTHER);
        drop(other.stdin.take());
        let _ = other.wait();
        taken.map_err(|error| format!("other owner never took the clipboard: {error}"))?;
        // After losing ownership the adapter still places and reads.
        write_bounded_text(&native, SECOND, WORKSPACE, POLICY)
            .map_err(|error| format!("write after ownership loss: {}", error.message))?;
        read_until(&native, SECOND)
            .map_err(|error| format!("read after ownership loss: {error}"))?;
        // Give any background thread time to report the ownership change.
        std::thread::sleep(Duration::from_millis(500));
        Ok(())
    };
    match steps() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("scenario failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn driver() -> ExitCode {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        println!("xp15_clipboard_ownership: not applicable on this platform");
        return ExitCode::SUCCESS;
    }
    let required = std::env::var("ORCEL_REQUIRE_LIVE_CLIPBOARD").as_deref() == Ok("1");
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            eprintln!("xp15_clipboard_ownership: cannot locate the test binary: {error}");
            return ExitCode::FAILURE;
        }
    };
    let output = match Command::new(exe)
        .env(ROLE, "scenario")
        .stdin(Stdio::null())
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            eprintln!("xp15_clipboard_ownership: cannot run the scenario: {error}");
            return ExitCode::FAILURE;
        }
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.code() == Some(i32::from(UNAVAILABLE)) {
        if required {
            eprintln!("xp15_clipboard_ownership: a live clipboard was required: {stderr}");
            return ExitCode::FAILURE;
        }
        println!(
            "xp15_clipboard_ownership: skipped, no clipboard is reachable ({})",
            stderr.trim()
        );
        return ExitCode::SUCCESS;
    }
    if !output.stdout.is_empty() {
        eprintln!(
            "xp15_clipboard_ownership: the clipboard adapter wrote to stdout: {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
        return ExitCode::FAILURE;
    }
    if !output.status.success() {
        eprintln!("xp15_clipboard_ownership: scenario failed: {stderr}");
        return ExitCode::FAILURE;
    }
    println!("xp15_clipboard_ownership: ok; ownership lost and regained, stdout stayed empty");
    ExitCode::SUCCESS
}
