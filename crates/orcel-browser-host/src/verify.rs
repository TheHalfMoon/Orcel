//! BR-07: the independent postcondition verifier for browser steps. A
//! caller states what must hold after a step (an element or text visible, a
//! field's value, a checkbox's state, the committed URL, a download's
//! digest); the host checks each one itself, from read-only worker probes
//! or from its own facts, and returns pass or fail with evidence. A model's
//! own summary is never evidence.
//!
//! Adapted from microsoft/playwright at commit
//! 1b025d7e20a026371cd5f98ba0cdce48892737c8,
//! `packages/playwright-core/src/tools/backend/verify.ts` (blob
//! a27eb72ef5ad80ae654c8dac975db1542ee97071), Apache License 2.0, Copyright
//! (c) Microsoft Corporation: the element, text and value checks. Orcel's
//! changes: the worker only observes (visible-match counts, a value, a
//! checked state) and the host decides; an element is named by its node
//! identity from the latest observation and matched by its exact role and
//! raw accessible name, visible only; text is a case-sensitive literal
//! substring, visible only; a value is compared inside the host and never
//! returned, recorded or logged, and secret fields (passwords, one-time
//! codes, payment cards) are never read, so such a check fails; a value or
//! checked state is checked only for a field role in the main frame, and
//! one field can be checked against at most `MAX_VALUE_GUESSES` distinct
//! values per document, so verification is never a way to guess a value
//! the observation hides; URL and download-digest checks use the host's
//! own record (the committed URL, the last committed download) and need no
//! worker; the list check is not ported.
//! Evidence is a fixed vocabulary plus counts, and the report carries a
//! SHA-256 digest of itself that a journey result can reference.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::HostError;

/// Postconditions one verification may check.
pub const MAX_POSTCONDITIONS: usize = 16;
/// Longest text or expected value, in bytes (mirrors the worker).
pub const MAX_VERIFY_TEXT_BYTES: usize = 1024;
/// Visible matches the worker counts at most (mirrors the worker).
pub const MAX_VERIFY_COUNT: u32 = 1000;
/// Longest URL a check may name (the navigation bound).
const MAX_VERIFY_URL_BYTES: usize = 2048;
/// Distinct expected values one field can be checked against per document.
pub const MAX_VALUE_GUESSES: usize = 3;
/// Roles whose value is checked (the worker also requires the element to
/// be an input, textarea or select).
const VALUE_ROLES: [&str; 6] = [
    "textbox",
    "searchbox",
    "combobox",
    "spinbutton",
    "slider",
    "listbox",
];
/// Roles whose checked state is checked.
const CHECKED_ROLES: [&str; 5] = [
    "checkbox",
    "radio",
    "switch",
    "menuitemcheckbox",
    "menuitemradio",
];

/// What must hold after a step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Postcondition {
    /// The element with this node identity (from the latest observation)
    /// is visible: some visible element has its exact role and name.
    ElementVisible { node_id: String },
    /// Visible text contains this text (case-sensitive).
    TextVisible { text: String },
    /// The field with this node identity holds exactly this value.
    ValueEquals { node_id: String, value: String },
    /// The checkbox or radio with this node identity is (not) checked.
    Checked { node_id: String, checked: bool },
    /// The committed document's URL is exactly this one.
    UrlIs { url: String },
    /// The last download's SHA-256 is this one (lower-case hex).
    DownloadSha256 { sha256: String },
}

impl Postcondition {
    fn kind(&self) -> &'static str {
        match self {
            Self::ElementVisible { .. } => "element_visible",
            Self::TextVisible { .. } => "text_visible",
            Self::ValueEquals { .. } => "value_equals",
            Self::Checked { .. } => "checked",
            Self::UrlIs { .. } => "url_is",
            Self::DownloadSha256 { .. } => "download_sha256",
        }
    }
}

/// One checked postcondition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    pub index: usize,
    pub kind: &'static str,
    pub passed: bool,
    /// Fixed vocabulary and counts; never page text, a name or a value.
    pub evidence: String,
}

/// The outcome of one verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verification {
    pub url: String,
    pub document_generation: u64,
    pub results: Vec<CheckResult>,
    /// Every postcondition passed.
    pub verified: bool,
    /// SHA-256 of the report's other fields (JSON), for evidence references.
    pub evidence_sha256: String,
}

/// The host's own facts, used without asking the worker.
#[derive(Debug, Clone, Copy)]
pub struct HostFacts<'a> {
    pub committed_url: &'a str,
    pub download_sha256: Option<&'a str>,
}

/// A read-only probe, as the worker receives it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "probe", rename_all = "snake_case")]
pub(crate) enum Probe {
    VisibleRole {
        role: String,
        name: String,
    },
    VisibleText {
        text: String,
    },
    Value {
        #[serde(rename = "ref")]
        reference: String,
    },
    Checked {
        #[serde(rename = "ref")]
        reference: String,
    },
}

/// A probe's observation, as the worker sends it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ProbeResult {
    Visible { count: u32 },
    Value { value: String },
    Checked { checked: bool },
    Unavailable { reason: String },
}

/// The reasons a probe could not observe, closed.
const UNAVAILABLE: [&str; 4] = ["stale", "secret", "not_a_field", "too_long"];

/// What a check needs before it can be decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Need {
    Probe(Probe),
    /// Decided from the host's facts.
    Host,
    /// The node is not in the latest observation (or cannot be matched).
    Unavailable(&'static str),
}

fn invalid(message: &str) -> HostError {
    HostError::Invalid(message.into())
}

fn bounded_text(text: &str, what: &str) -> Result<(), HostError> {
    if text.is_empty() || text.len() > MAX_VERIFY_TEXT_BYTES || text.chars().any(char::is_control) {
        return Err(invalid(&format!(
            "a {what} must be bounded and without control characters"
        )));
    }
    Ok(())
}

/// Refuses postconditions that cannot be checked as stated.
pub fn check_postconditions(checks: &[Postcondition]) -> Result<(), HostError> {
    if checks.is_empty() || checks.len() > MAX_POSTCONDITIONS {
        return Err(invalid("a verification checks 1 to 16 postconditions"));
    }
    for check in checks {
        match check {
            Postcondition::ElementVisible { node_id } | Postcondition::Checked { node_id, .. } => {
                crate::observation::validate_identity_field(node_id)?
            }
            Postcondition::ValueEquals { node_id, value } => {
                crate::observation::validate_identity_field(node_id)?;
                // An empty expected value is a legitimate postcondition.
                if value.len() > MAX_VERIFY_TEXT_BYTES || value.chars().any(char::is_control) {
                    return Err(invalid(
                        "an expected value must be bounded and without control characters",
                    ));
                }
            }
            Postcondition::TextVisible { text } => bounded_text(text, "verified text")?,
            Postcondition::UrlIs { url } => {
                if url.is_empty()
                    || url.len() > MAX_VERIFY_URL_BYTES
                    || url.chars().any(char::is_control)
                {
                    return Err(invalid("a verified URL must be bounded"));
                }
            }
            Postcondition::DownloadSha256 { sha256 } => {
                if sha256.len() != 64
                    || !sha256
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                {
                    return Err(invalid("a download digest is 64 lower-case hex digits"));
                }
            }
        }
    }
    Ok(())
}

/// What `check` needs; `node` resolves a node identity from the latest
/// observation to its worker ref, role and raw name.
pub(crate) fn need<'a>(
    check: &Postcondition,
    node: impl Fn(&str) -> Option<(&'a str, &'a str, &'a str)>,
) -> Need {
    match check {
        Postcondition::ElementVisible { node_id } => match node(node_id) {
            None => Need::Unavailable("node is not in the latest observation"),
            // Without a name, a role alone does not identify the element.
            Some((_, _, "")) => Need::Unavailable("element has no accessible name to match"),
            // The observation cuts names at the bound: a name at (or near)
            // it may be cut and would never match the real one.
            Some((_, _, name)) if name.len() + 4 > MAX_VERIFY_TEXT_BYTES => {
                Need::Unavailable("element name may be cut and cannot be matched")
            }
            Some((_, _, name)) if name.chars().any(char::is_control) => {
                Need::Unavailable("element name cannot be matched")
            }
            Some((_, role, name)) => Need::Probe(Probe::VisibleRole {
                role: role.to_owned(),
                name: name.to_owned(),
            }),
        },
        Postcondition::TextVisible { text } => {
            Need::Probe(Probe::VisibleText { text: text.clone() })
        }
        Postcondition::ValueEquals { node_id, .. } => match node(node_id) {
            None => Need::Unavailable("node is not in the latest observation"),
            Some((_, role, _)) if !VALUE_ROLES.contains(&role) => {
                Need::Unavailable("node is not a field with a value")
            }
            Some((reference, _, _)) if !main_frame_ref(reference) => {
                Need::Unavailable("fields inside frames are not checked")
            }
            Some((reference, _, _)) => Need::Probe(Probe::Value {
                reference: reference.to_owned(),
            }),
        },
        Postcondition::Checked { node_id, .. } => match node(node_id) {
            None => Need::Unavailable("node is not in the latest observation"),
            Some((_, role, _)) if !CHECKED_ROLES.contains(&role) => {
                Need::Unavailable("node is not a checkbox, radio or switch")
            }
            Some((reference, _, _)) if !main_frame_ref(reference) => {
                Need::Unavailable("fields inside frames are not checked")
            }
            Some((reference, _, _)) => Need::Probe(Probe::Checked {
                reference: reference.to_owned(),
            }),
        },
        Postcondition::UrlIs { .. } | Postcondition::DownloadSha256 { .. } => Need::Host,
    }
}

/// A snapshot ref in the main frame (`e12`, not `f1e12`).
fn main_frame_ref(reference: &str) -> bool {
    reference
        .strip_prefix('e')
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// How many distinct values each field has been checked against in the
/// current document; a new document starts again.
#[derive(Debug, Default)]
pub(crate) struct GuessBudget {
    generation: u64,
    tried: std::collections::HashMap<String, Vec<[u8; 32]>>,
}

impl GuessBudget {
    /// Whether `node_id` may be checked against `value` in `generation`
    /// (a value it was already checked against is always allowed again).
    pub(crate) fn allow(&mut self, generation: u64, node_id: &str, value: &str) -> bool {
        if generation != self.generation {
            self.generation = generation;
            self.tried.clear();
        }
        let digest: [u8; 32] = Sha256::digest(value.as_bytes()).into();
        let tried = self.tried.entry(node_id.to_owned()).or_default();
        if tried.contains(&digest) {
            return true;
        }
        if tried.len() >= MAX_VALUE_GUESSES {
            return false;
        }
        tried.push(digest);
        true
    }
}

/// Spends the value budget: a value check over it is not probed.
pub(crate) fn apply_budget(
    checks: &[Postcondition],
    needs: &mut [Need],
    budget: &mut GuessBudget,
    generation: u64,
) {
    for (check, need) in checks.iter().zip(needs.iter_mut()) {
        if let (Postcondition::ValueEquals { node_id, value }, Need::Probe(_)) = (check, &*need) {
            if !budget.allow(generation, node_id, value) {
                *need = Need::Unavailable("value check limit reached for this field");
            }
        }
    }
}

/// Refuses a worker observation outside the bounds (a worker bug or a
/// compromised worker): the whole verification fails closed.
pub(crate) fn check_probe_result(probe: &Probe, result: &ProbeResult) -> Result<(), HostError> {
    let fits = match (probe, result) {
        (Probe::VisibleRole { .. } | Probe::VisibleText { .. }, ProbeResult::Visible { count }) => {
            *count <= MAX_VERIFY_COUNT
        }
        (Probe::Value { .. }, ProbeResult::Value { value }) => value.len() <= MAX_VERIFY_TEXT_BYTES,
        (Probe::Checked { .. }, ProbeResult::Checked { .. }) => true,
        (Probe::Value { .. } | Probe::Checked { .. }, ProbeResult::Unavailable { reason }) => {
            UNAVAILABLE.contains(&reason.as_str())
        }
        _ => false,
    };
    if fits {
        Ok(())
    } else {
        Err(HostError::Unavailable(
            crate::error::UnavailableReason::ProtocolViolation,
        ))
    }
}

/// Decides one postcondition from what it needed.
pub(crate) fn decide(
    index: usize,
    check: &Postcondition,
    need: &Need,
    observed: Option<&ProbeResult>,
    facts: &HostFacts<'_>,
) -> CheckResult {
    let (passed, evidence) = match (need, check, observed) {
        (Need::Unavailable(why), _, _) => (false, (*why).to_owned()),
        (Need::Host, Postcondition::UrlIs { url }, _) => {
            let same = facts.committed_url == url;
            (
                same,
                if same {
                    "committed URL matches".into()
                } else {
                    "committed URL differs".into()
                },
            )
        }
        (Need::Host, Postcondition::DownloadSha256 { sha256 }, _) => match facts.download_sha256 {
            None => (false, "no download to check".into()),
            Some(actual) if actual.eq_ignore_ascii_case(sha256) => {
                (true, "download digest matches".into())
            }
            Some(_) => (false, "download digest differs".into()),
        },
        (
            Need::Probe(_),
            Postcondition::ElementVisible { .. } | Postcondition::TextVisible { .. },
            Some(ProbeResult::Visible { count }),
        ) => (*count > 0, format!("visible matches: {count}")),
        (
            Need::Probe(_),
            Postcondition::ValueEquals { value, .. },
            Some(ProbeResult::Value { value: actual }),
        ) => {
            let same = actual == value;
            (
                same,
                if same {
                    "value matches".into()
                } else {
                    "value differs".into()
                },
            )
        }
        (
            Need::Probe(_),
            Postcondition::Checked { checked, .. },
            Some(ProbeResult::Checked { checked: actual }),
        ) => (actual == checked, format!("checked: {actual}")),
        (Need::Probe(_), _, Some(ProbeResult::Unavailable { reason })) => {
            (false, format!("unavailable: {reason}"))
        }
        _ => (false, "not observed".into()),
    };
    CheckResult {
        index,
        kind: check.kind(),
        passed,
        evidence,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The report, with its digest; verified only when every check passed.
pub(crate) fn finish(
    url: &str,
    document_generation: u64,
    results: Vec<CheckResult>,
) -> Verification {
    let verified = !results.is_empty() && results.iter().all(|r| r.passed);
    #[derive(Serialize)]
    struct Digested<'a> {
        url: &'a str,
        document_generation: u64,
        results: &'a [CheckResult],
        verified: bool,
    }
    let body = serde_json::to_vec(&Digested {
        url,
        document_generation,
        results: &results,
        verified,
    })
    .unwrap_or_default();
    Verification {
        url: url.to_owned(),
        document_generation,
        evidence_sha256: hex(&Sha256::digest(&body)),
        results,
        verified,
    }
}

/// Decides every postcondition from the needs, the worker's observations
/// (one per probe, in order) and the host's facts.
pub(crate) fn verify_with(
    checks: &[Postcondition],
    needs: &[Need],
    observed: &[ProbeResult],
    facts: &HostFacts<'_>,
    document_generation: u64,
) -> Verification {
    let mut next = observed.iter();
    let results = checks
        .iter()
        .zip(needs)
        .enumerate()
        .map(|(index, (check, need))| {
            let seen = matches!(need, Need::Probe(_))
                .then(|| next.next())
                .flatten();
            decide(index, check, need, seen, facts)
        })
        .collect();
    finish(facts.committed_url, document_generation, results)
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://shop.test/order/42";
    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn facts() -> HostFacts<'static> {
        HostFacts {
            committed_url: URL,
            download_sha256: Some(SHA),
        }
    }

    /// Node identities as the latest observation issued them.
    fn node(id: &str) -> Option<(&'static str, &'static str, &'static str)> {
        match id {
            "n1" => Some(("e1", "heading", "Order confirmed")),
            "n2" => Some(("e2", "textbox", "Email")),
            "n3" => Some(("e3", "checkbox", "Subscribe")),
            "n4" => Some(("e4", "generic", "")),
            "n5" => Some(("e5", "generic", "Pin display")),
            "n6" => Some(("f1e6", "textbox", "Framed")),
            "n7" => Some(("e7", "button", "x\u{7}y")),
            _ => None,
        }
    }

    fn run(checks: &[Postcondition], observed: &[ProbeResult]) -> Verification {
        check_postconditions(checks).unwrap();
        let needs: Vec<Need> = checks.iter().map(|c| need(c, node)).collect();
        verify_with(checks, &needs, observed, &facts(), 7)
    }

    #[test]
    fn br07_every_postcondition_passes_with_evidence() {
        let checks = [
            Postcondition::ElementVisible {
                node_id: "n1".into(),
            },
            Postcondition::TextVisible {
                text: "Thank you".into(),
            },
            Postcondition::ValueEquals {
                node_id: "n2".into(),
                value: "ada@example.test".into(),
            },
            Postcondition::Checked {
                node_id: "n3".into(),
                checked: true,
            },
            Postcondition::UrlIs { url: URL.into() },
            Postcondition::DownloadSha256 { sha256: SHA.into() },
        ];
        let needs: Vec<Need> = checks.iter().map(|c| need(c, node)).collect();
        assert_eq!(
            needs[..4],
            [
                Need::Probe(Probe::VisibleRole {
                    role: "heading".into(),
                    name: "Order confirmed".into()
                }),
                Need::Probe(Probe::VisibleText {
                    text: "Thank you".into()
                }),
                Need::Probe(Probe::Value {
                    reference: "e2".into()
                }),
                Need::Probe(Probe::Checked {
                    reference: "e3".into()
                }),
            ]
        );
        let report = run(
            &checks,
            &[
                ProbeResult::Visible { count: 1 },
                ProbeResult::Visible { count: 2 },
                ProbeResult::Value {
                    value: "ada@example.test".into(),
                },
                ProbeResult::Checked { checked: true },
            ],
        );
        assert!(report.verified, "{report:?}");
        assert_eq!(report.url, URL);
        assert_eq!(report.document_generation, 7);
        let evidence: Vec<&str> = report.results.iter().map(|r| r.evidence.as_str()).collect();
        assert_eq!(
            evidence,
            [
                "visible matches: 1",
                "visible matches: 2",
                "value matches",
                "checked: true",
                "committed URL matches",
                "download digest matches"
            ]
        );
        assert_eq!(report.evidence_sha256.len(), 64);
        // The digest covers the results.
        let other = run(
            &checks,
            &[
                ProbeResult::Visible { count: 1 },
                ProbeResult::Visible { count: 3 },
                ProbeResult::Value {
                    value: "ada@example.test".into(),
                },
                ProbeResult::Checked { checked: true },
            ],
        );
        assert_ne!(report.evidence_sha256, other.evidence_sha256);
    }

    /// Hidden text is counted by the worker as zero visible matches.
    #[test]
    fn br07_text_present_but_hidden_fails() {
        let report = run(
            &[Postcondition::TextVisible {
                text: "Order confirmed".into(),
            }],
            &[ProbeResult::Visible { count: 0 }],
        );
        assert!(!report.verified);
        assert_eq!(report.results[0].evidence, "visible matches: 0");
    }

    #[test]
    fn br07_a_wrong_value_fails_and_is_never_echoed() {
        let report = run(
            &[Postcondition::ValueEquals {
                node_id: "n2".into(),
                value: "expected-secret".into(),
            }],
            &[ProbeResult::Value {
                value: "actual-private-value".into(),
            }],
        );
        assert!(!report.verified);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("expected-secret") && !json.contains("actual-private-value"));
        assert_eq!(report.results[0].evidence, "value differs");
        // A secret field is never read, so the check fails.
        let secret = run(
            &[Postcondition::ValueEquals {
                node_id: "n2".into(),
                value: "x".into(),
            }],
            &[ProbeResult::Unavailable {
                reason: "secret".into(),
            }],
        );
        assert!(!secret.verified);
        assert_eq!(secret.results[0].evidence, "unavailable: secret");
    }

    #[test]
    fn br07_unknown_or_unnamed_nodes_and_host_facts_fail_closed() {
        let report = run(
            &[
                Postcondition::ElementVisible {
                    node_id: "n9".into(),
                },
                Postcondition::ElementVisible {
                    node_id: "n4".into(),
                },
                Postcondition::Checked {
                    node_id: "n3".into(),
                    checked: false,
                },
                Postcondition::UrlIs {
                    url: "https://shop.test/order/43".into(),
                },
            ],
            &[ProbeResult::Checked { checked: true }],
        );
        let outcome: Vec<(bool, &str)> = report
            .results
            .iter()
            .map(|r| (r.passed, r.evidence.as_str()))
            .collect();
        assert_eq!(
            outcome,
            [
                (false, "node is not in the latest observation"),
                (false, "element has no accessible name to match"),
                (false, "checked: true"),
                (false, "committed URL differs"),
            ]
        );
        let no_download = verify_with(
            &[Postcondition::DownloadSha256 { sha256: SHA.into() }],
            &[Need::Host],
            &[],
            &HostFacts {
                committed_url: URL,
                download_sha256: None,
            },
            7,
        );
        assert_eq!(no_download.results[0].evidence, "no download to check");
        assert!(!no_download.verified);
        assert!(
            !finish(URL, 7, Vec::new()).verified,
            "nothing checked is not verified"
        );
    }

    /// Values and checked states only for field roles in the main frame;
    /// names that may be cut or carry control characters never probe.
    #[test]
    fn br07_only_fields_in_the_main_frame_and_matchable_names_are_probed() {
        let unavailable = |check: Postcondition| match need(&check, node) {
            Need::Unavailable(why) => why,
            other => {
                assert!(matches!(other, Need::Unavailable(_)), "{other:?}");
                ""
            }
        };
        assert_eq!(
            unavailable(Postcondition::ValueEquals {
                node_id: "n5".into(),
                value: "1234".into()
            }),
            "node is not a field with a value"
        );
        assert_eq!(
            unavailable(Postcondition::ValueEquals {
                node_id: "n6".into(),
                value: "x".into()
            }),
            "fields inside frames are not checked"
        );
        assert_eq!(
            unavailable(Postcondition::Checked {
                node_id: "n2".into(),
                checked: true
            }),
            "node is not a checkbox, radio or switch"
        );
        assert_eq!(
            unavailable(Postcondition::ElementVisible {
                node_id: "n7".into()
            }),
            "element name cannot be matched"
        );
        let long = "n".repeat(MAX_VERIFY_TEXT_BYTES - 2);
        let cut = need(
            &Postcondition::ElementVisible {
                node_id: "n1".into(),
            },
            |_| Some(("e1", "heading", long.as_str())),
        );
        assert_eq!(
            cut,
            Need::Unavailable("element name may be cut and cannot be matched")
        );
    }

    /// A field can be checked against a few values per document, so the
    /// verifier is not a way to guess a hidden value.
    #[test]
    fn br07_value_checks_are_budgeted_per_field_and_document() {
        let mut budget = GuessBudget::default();
        let guess = |value: &str| Postcondition::ValueEquals {
            node_id: "n2".into(),
            value: value.into(),
        };
        let checks: Vec<Postcondition> = ["1111", "2222", "3333", "1111", "4444"]
            .iter()
            .map(|v| guess(v))
            .collect();
        let mut needs: Vec<Need> = checks.iter().map(|c| need(c, node)).collect();
        apply_budget(&checks, &mut needs, &mut budget, 7);
        let probed: Vec<bool> = needs.iter().map(|n| matches!(n, Need::Probe(_))).collect();
        assert_eq!(
            probed,
            [true, true, true, true, false],
            "a repeated value is free; a fourth is refused"
        );
        // Another call in the same document: still refused.
        let mut again = vec![need(&guess("5555"), node)];
        apply_budget(&[guess("5555")], &mut again, &mut budget, 7);
        assert_eq!(
            again[0],
            Need::Unavailable("value check limit reached for this field")
        );
        // Another field has its own budget; a new document starts again.
        assert!(budget.allow(7, "n9", "x"));
        let mut fresh = vec![need(&guess("5555"), node)];
        apply_budget(&[guess("5555")], &mut fresh, &mut budget, 8);
        assert!(matches!(fresh[0], Need::Probe(_)));
        // The refused check fails with that evidence.
        let report = verify_with(
            &[guess("9999")],
            &[Need::Unavailable(
                "value check limit reached for this field",
            )],
            &[],
            &facts(),
            7,
        );
        assert_eq!(
            report.results[0].evidence,
            "value check limit reached for this field"
        );
    }

    #[test]
    fn br07_postconditions_are_bounded() {
        let ok = Postcondition::TextVisible { text: "x".into() };
        assert!(check_postconditions(&[]).is_err());
        assert!(check_postconditions(&vec![ok.clone(); MAX_POSTCONDITIONS + 1]).is_err());
        for bad in [
            Postcondition::TextVisible {
                text: String::new(),
            },
            Postcondition::TextVisible {
                text: "x".repeat(MAX_VERIFY_TEXT_BYTES + 1),
            },
            Postcondition::TextVisible {
                text: "a\nb".into(),
            },
            Postcondition::ElementVisible {
                node_id: String::new(),
            },
            Postcondition::ElementVisible {
                node_id: "../n1".into(),
            },
            Postcondition::ValueEquals {
                node_id: "n2".into(),
                value: "x".repeat(MAX_VERIFY_TEXT_BYTES + 1),
            },
            Postcondition::UrlIs { url: String::new() },
            Postcondition::DownloadSha256 {
                sha256: SHA.to_uppercase(),
            },
            Postcondition::DownloadSha256 {
                sha256: "abc".into(),
            },
        ] {
            assert!(
                check_postconditions(std::slice::from_ref(&bad)).is_err(),
                "{bad:?}"
            );
        }
        assert!(check_postconditions(&[Postcondition::ValueEquals {
            node_id: "n2".into(),
            value: String::new()
        }])
        .is_ok());
        // The wire form is closed.
        assert!(serde_json::from_str::<Postcondition>(
            r#"{"kind":"text_visible","text":"x","extra":1}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<Postcondition>(r#"{"kind":"evaluate","script":"1"}"#).is_err()
        );
    }

    #[test]
    fn br07_out_of_bounds_worker_observations_fail_closed() {
        let text = Probe::VisibleText { text: "x".into() };
        let value = Probe::Value {
            reference: "e1".into(),
        };
        assert!(check_probe_result(
            &text,
            &ProbeResult::Visible {
                count: MAX_VERIFY_COUNT
            }
        )
        .is_ok());
        assert!(check_probe_result(
            &text,
            &ProbeResult::Visible {
                count: MAX_VERIFY_COUNT + 1
            }
        )
        .is_err());
        assert!(check_probe_result(&text, &ProbeResult::Value { value: "x".into() }).is_err());
        assert!(check_probe_result(
            &text,
            &ProbeResult::Unavailable {
                reason: "stale".into()
            }
        )
        .is_err());
        assert!(check_probe_result(
            &value,
            &ProbeResult::Value {
                value: "x".repeat(MAX_VERIFY_TEXT_BYTES + 1)
            }
        )
        .is_err());
        assert!(check_probe_result(
            &value,
            &ProbeResult::Unavailable {
                reason: "secret".into()
            }
        )
        .is_ok());
        assert!(check_probe_result(
            &value,
            &ProbeResult::Unavailable {
                reason: "made-up".into()
            }
        )
        .is_err());
        // The wire form of probes and results.
        assert_eq!(
            serde_json::to_string(&Probe::Value {
                reference: "f1e2".into()
            })
            .unwrap(),
            r#"{"probe":"value","ref":"f1e2"}"#
        );
        assert!(serde_json::from_str::<ProbeResult>(
            r#"{"result":"visible","count":1,"text":"leak"}"#
        )
        .is_err());
    }
}
