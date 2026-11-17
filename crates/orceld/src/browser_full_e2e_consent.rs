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
//! The decider approves only the isolated browser's prompts whose target is
//! the loopback fixture origin (`fixture.test`) and denies every other
//! prompt. Every decision is appended to `ORCEL_E2E_CONSENT_LOG` with the
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
const FIXTURE_HOST: &str = "fixture.test";

/// Whether the scripted consent approves `prompt`: an isolated browser
/// action whose target is on the loopback fixture origin. Nothing else.
pub(crate) fn approves(prompt: &ApprovalPrompt) -> bool {
    prompt.action.contains("isolated browser page") && names_fixture(&prompt.target)
}

/// Whether `target` names the fixture host as a URL host (not merely as text
/// somewhere in it).
fn names_fixture(target: &str) -> bool {
    target.split_whitespace().any(|word| {
        word.strip_prefix("https://")
            .and_then(|rest| rest.split(['/', ':']).next())
            .is_some_and(|host| host.eq_ignore_ascii_case(FIXTURE_HOST))
    })
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
            "rule": "approve only isolated browser prompts targeting https://fixture.test; deny every other prompt",
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
    fn only_isolated_browser_prompts_on_the_fixture_are_approved() {
        assert!(approves(&prompt(
            "navigate isolated browser page",
            "https://fixture.test/ob01-form"
        )));
        assert!(approves(&prompt(
            "open a link on an isolated browser page",
            "https://fixture.test:443/ob01-done"
        )));
        for (action, target) in [
            ("navigate isolated browser page", "https://example.com/"),
            (
                "navigate isolated browser page",
                "https://fixture.test.example.com/",
            ),
            ("navigate isolated browser page", "http://fixture.test/"),
            ("navigate isolated browser page", "see fixture.test"),
            ("write a file", "https://fixture.test/"),
            ("emergency revoke", "https://fixture.test/"),
        ] {
            assert!(!approves(&prompt(action, target)), "{action} {target}");
        }
    }
}
