//! SG-000135 OB-07: the host's side of the read-only challenge detector.
//!
//! The worker classifies the active tab's committed document from the
//! engine's own DOM and layout snapshot (no page script) and answers a
//! closed kind and closed signal names (`apps/orcel-browser-worker/src/
//! challenge.ts`). The host checks that answer against the same closed
//! vocabulary, so nothing but those words crosses to orceld: never page
//! text, a field value, a name or a URL. A reply outside the vocabulary is
//! a protocol violation.
//!
//! The detector only classifies. It never solves, skips, fills, clicks or
//! answers a CAPTCHA, a code, a passkey or a sign-in, and it has no code
//! that could: the person does that in the page.

use crate::error::{HostError, UnavailableReason};

/// The kinds the worker may report.
pub const CHALLENGE_KINDS: [&str; 5] = ["none", "captcha", "mfa", "sign_in", "passkey"];

/// The signals the worker may report, in the worker's vocabulary order.
pub const CHALLENGE_SIGNALS: [&str; 12] = [
    "captcha_frame",
    "captcha_widget",
    "challenge_interstitial",
    "challenge_text",
    "otp_autocomplete",
    "otp_field",
    "otp_split",
    "password_field",
    "http_auth",
    "http_blocked",
    "webauthn_autocomplete",
    "passkey_prompt",
];

/// One checked classification of the active tab's document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeFinding {
    /// One of [`CHALLENGE_KINDS`]; `none` when nothing asks for a person.
    pub kind: String,
    /// Distinct members of [`CHALLENGE_SIGNALS`], in vocabulary order.
    pub signals: Vec<String>,
    /// The worker read a bounded part of a larger snapshot.
    pub truncated: bool,
    /// The tab no longer shows the document the host committed (the page
    /// moved on its own, for example after the person signed in).
    pub moved: bool,
}

impl ChallengeFinding {
    /// Whether the page asks for a person.
    #[must_use]
    pub fn found(&self) -> bool {
        self.kind != "none"
    }
}

/// Check a worker's report against the closed vocabulary: a known kind,
/// known signals each at most once and in vocabulary order, and a kind of
/// `none` exactly when no signal makes one (a blocked status alone makes
/// none).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn check_report(kind: &str, signals: &[String]) -> Result<(), HostError> {
    let violation = || HostError::Unavailable(UnavailableReason::ProtocolViolation);
    if !CHALLENGE_KINDS.contains(&kind) {
        return Err(violation());
    }
    let mut last: Option<usize> = None;
    for signal in signals {
        let at = CHALLENGE_SIGNALS
            .iter()
            .position(|known| known == signal)
            .ok_or_else(violation)?;
        if last.is_some_and(|before| at <= before) {
            return Err(violation());
        }
        last = Some(at);
    }
    let decisive = signals.iter().any(|signal| signal != "http_blocked");
    if decisive == (kind == "none") {
        return Err(violation());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(signals: &[&str]) -> Vec<String> {
        signals.iter().map(|signal| (*signal).to_owned()).collect()
    }

    #[test]
    fn ob07_only_the_closed_vocabulary_crosses() {
        assert!(check_report("captcha", &owned(&["captcha_widget"])).is_ok());
        assert!(check_report("none", &owned(&[])).is_ok());
        assert!(check_report("none", &owned(&["http_blocked"])).is_ok());
        assert!(check_report("sign_in", &owned(&["password_field", "http_auth"])).is_ok());
        for (kind, signals) in [
            ("solved", owned(&["captcha_widget"])),
            ("captcha", owned(&["Password: hunter2"])),
            ("captcha", owned(&["captcha_widget", "captcha_widget"])),
            ("sign_in", owned(&["http_auth", "password_field"])),
            ("none", owned(&["password_field"])),
            ("captcha", owned(&[])),
            ("captcha", owned(&["http_blocked"])),
        ] {
            assert!(
                matches!(
                    check_report(kind, &signals),
                    Err(HostError::Unavailable(UnavailableReason::ProtocolViolation))
                ),
                "{kind} {signals:?}"
            );
        }
    }

    #[test]
    fn ob07_the_vocabulary_matches_the_worker() -> Result<(), String> {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../apps/orcel-browser-worker/src/challenge.ts"
        ))
        .map_err(|error| error.to_string())?;
        let signals = source
            .split("export const CHALLENGE_SIGNALS = [")
            .nth(1)
            .and_then(|rest| rest.split(']').next())
            .ok_or("the worker's signal list is missing")?;
        let worker: Vec<&str> = signals
            .split(',')
            .map(|item| item.trim().trim_matches('"'))
            .filter(|item| !item.is_empty())
            .collect();
        assert_eq!(worker, CHALLENGE_SIGNALS.to_vec());
        let kinds = source
            .split("export type ChallengeKind = ")
            .nth(1)
            .and_then(|rest| rest.split(';').next())
            .ok_or("the worker's kind list is missing")?;
        let worker: Vec<&str> = kinds
            .split('|')
            .map(|item| item.trim().trim_matches('"'))
            .collect();
        assert_eq!(worker, CHALLENGE_KINDS.to_vec());
        Ok(())
    }
}
