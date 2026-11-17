//! SG-000135 OB-01 end-to-end harness: scripted SOFT consent, TEST BUILDS
//! ONLY (the `browser-full-scripted-consent` feature with both live browser
//! features; `sg000039_main.rs` compiles this module nowhere else).
//!
//! The approval broker stays the real `LocalApprovalBroker` over the real
//! ledger format (nonce, digest, expiry, single use, records); only the SOFT
//! consent a person would give in the system dialog is decided here, through
//! the approval crate's existing test-support soft decider, the same
//! mechanism orceld's native live-browser tests use. STRONG approvals have no
//! presence verifier and fail closed.
//!
//! The decider approves only the mission's four exact action titles (open,
//! fill, select, click) whose whole target is the loopback fixture origin
//! (`https://fixture.test`, optional `:443` and path), and denies every
//! other prompt. Every decision is appended to `ORCEL_E2E_CONSENT_LOG` with the
//! exact dialog text a person would have been shown, so the harness can
//! check what was asked. orceld refuses to start without that log, and a
//! harness that finds no header line in it knows the build it drove was not
//! this one.

use orcel_approval::{
    default_approval_history_path, now_ms, soft_dialog_text, ApprovalDecision, ApprovalPrompt,
    LocalApprovalBroker, NoPresenceVerifier,
};
use serde_json::json;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The environment variable naming the consent log (an absolute path).
pub(crate) const CONSENT_LOG_ENV: &str = "ORCEL_E2E_CONSENT_LOG";

/// The only origin whose browser prompts the scripted consent approves.
const FIXTURE_ORIGIN: &str = "https://fixture.test";

/// The exact action titles of the four approved steps of the mission
/// (`live_browser.rs`): navigate, type a value, choose an option, open a
/// link. No other action, however similar, is approved.
const MISSION_ACTIONS: [&str; 4] = [
    "navigate isolated browser page",
    "type the value on the line after Target into a field of an isolated browser page",
    "choose the option on the line after Target in a list of an isolated browser page",
    "open a link on an isolated browser page",
];

/// Whether the scripted consent approves `prompt`: one of the mission's
/// four actions, whose whole target is on the loopback fixture origin.
/// Nothing else.
pub(crate) fn approves(prompt: &ApprovalPrompt) -> bool {
    MISSION_ACTIONS.contains(&prompt.action.as_str()) && names_fixture(&prompt.target)
}

/// Whether the whole of `target` is the fixture origin: exactly
/// `https://fixture.test`, optionally `:443`, optionally a path starting
/// with `/`, and no whitespace or control character anywhere.
fn names_fixture(target: &str) -> bool {
    if target.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let Some(rest) = target.strip_prefix(FIXTURE_ORIGIN) else {
        return false;
    };
    let rest = rest.strip_prefix(":443").unwrap_or(rest);
    rest.is_empty() || rest.starts_with('/')
}

fn append(log: &Path, line: &serde_json::Value) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)?;
    writeln!(file, "{line}")
}

/// The scripted-consent broker over the default ledger, or why orceld must
/// not start.
pub(crate) fn broker() -> Result<LocalApprovalBroker, String> {
    let log = std::env::var_os(CONSENT_LOG_ENV)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            format!(
                "this is a test-only OB-01 harness build with scripted consent; it refuses to start without an absolute {CONSENT_LOG_ENV}"
            )
        })?;
    let ledger = default_approval_history_path()
        .map_err(|error| format!("initialize approval broker: {error}"))?;
    append(
        &log,
        &json!({
            "event": "scripted_consent_started",
            "at_ms": now_ms(),
            "pid": std::process::id(),
            "rule": "approve only the four mission actions (navigate, type, choose, open a link) whose whole target is https://fixture.test; deny every other prompt",
        }),
    )
    .map_err(|error| format!("write {CONSENT_LOG_ENV}: {error}"))?;
    let decider = move |prompt: &ApprovalPrompt| {
        let approved = approves(prompt);
        let _ = append(
            &log,
            &json!({
                "event": "soft_prompt",
                "at_ms": now_ms(),
                "decision": if approved { "approved" } else { "denied" },
                "action": prompt.action,
                "target": prompt.target,
                "digest": prompt.digest,
                "dialog_text": soft_dialog_text(prompt),
            }),
        );
        if approved {
            ApprovalDecision::Approved
        } else {
            ApprovalDecision::Denied
        }
    };
    Ok(LocalApprovalBroker::with_path_and_soft_decider(
        ledger,
        Arc::new(NoPresenceVerifier),
        Arc::new(decider),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prompt(action: &str, target: &str) -> ApprovalPrompt {
        ApprovalPrompt::new("default", "rev", action, target, "summary", "digest")
    }

    #[test]
    fn only_the_whole_fixture_origin_is_a_fixture_target() {
        for target in [
            "https://fixture.test",
            "https://fixture.test/",
            "https://fixture.test/ob01-form",
            "https://fixture.test:443",
            "https://fixture.test:443/ob01-done",
        ] {
            assert!(names_fixture(target), "{target}");
        }
        for target in [
            "",
            "https://example.com/",
            "https://fixture.test.example.com/",
            "https://fixture.testing/",
            "https://fixture.test:4443/",
            "https://fixture.test:443x",
            "https://fixture.test@evil.example/",
            "https://FIXTURE.test/",
            "http://fixture.test/",
            "see https://fixture.test/",
            "https://evil.example/ https://fixture.test/",
            "https://fixture.test/ extra",
            "https://fixture.test/\tx",
            "https://fixture.test/\nx",
            " https://fixture.test/",
        ] {
            assert!(!names_fixture(target), "{target:?}");
        }
    }

    #[test]
    fn only_the_four_mission_actions_on_the_fixture_are_approved() {
        for action in MISSION_ACTIONS {
            assert!(
                approves(&prompt(action, "https://fixture.test:443")),
                "{action}"
            );
            assert!(
                !approves(&prompt(action, "https://example.com/")),
                "{action}"
            );
        }
        for action in [
            "check a box or option on an isolated browser page",
            "uncheck a box or option on an isolated browser page",
            "press Enter in a field of an isolated browser page",
            "download from isolated browser page",
            "navigate isolated browser page ",
            "Navigate isolated browser page",
            "write a file",
            "emergency revoke",
        ] {
            assert!(
                !approves(&prompt(action, "https://fixture.test/")),
                "{action}"
            );
        }
        // The titles are the live browser's own, word for word.
        let live = include_str!("live_browser.rs");
        for action in MISSION_ACTIONS {
            assert!(live.contains(&format!("\"{action}\"")), "{action}");
        }
    }
}
