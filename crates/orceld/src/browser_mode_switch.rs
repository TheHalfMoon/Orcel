//! SG-000135 SH-2: moving a `browser_full` task between Shadow and Visible.
//!
//! A session's mode is fixed for its life (OB-04): the engine is launched
//! headless or headed. Switching therefore never changes a running engine.
//! `browser_session_create {continue_from, mode}` opens a new session in the
//! other mode for the same client, on the same profile, and carries the task
//! there:
//!
//! - The checks below run first, and nothing changes when one refuses: the
//!   modes differ; the caller is the one that opened the old session; a
//!   remote caller's session holds no persistent profile; no action of the
//!   old session has an uncertain outcome (an unknown effect, or a receipt
//!   the audit chain refused); no person is using its window; and a move to
//!   Shadow leaves no page that waits for the person.
//! - The old session ends (`mode_switch`) as any session ends: its worker
//!   goes, an ephemeral profile and its evidence files are removed (OB-05),
//!   and its Full Access lease ends with it. A lease names one session id, so
//!   it never covers the new session.
//! - The new session's `session_start` on the audit chain names the old
//!   session, its mode and its last receipt (`continued_from`), and the
//!   verifier checks that link.
//! - What is carried: the profile (a persistent profile keeps its cookies;
//!   an ephemeral profile's cookies end with the old session), the task
//!   label, and the recorded committed URL of each tab, reopened as an
//!   ordinary approved GET navigation in the new session, each with its own
//!   intent and receipt. Nothing else is replayed: no click, fill, select,
//!   submit, Enter or download. A tab's URL is carried exactly only when the
//!   agent could read it in full (nothing redacted, no sign-in seen) and no
//!   query or fragment value looks like a token; otherwise only its scheme, host and path (`agent_url::bare`), so a
//!   query that held what a person typed, or a token, is never sent again.
//!   A tab that is not an https page is not carried.

use crate::browser_broker::SessionMode;
use crate::browser_remote::Caller;
use orcel_contracts::FailureCode;
use orcel_provider_fs::ProviderError;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// One tab of the old session as its worker records it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SwitchTab {
    pub page_id: String,
    /// The tab's committed URL (orceld's record), if it has one.
    pub committed: Option<String>,
    pub active: bool,
}

/// What the old session's worker reports for a switch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SwitchState {
    pub tabs: Vec<SwitchTab>,
    /// A page of the session was detected as a sign-in page (OB-07b).
    pub sign_in_seen: bool,
    /// A person is using the session's window, or stopped less than three
    /// seconds ago (OB-06).
    pub held: bool,
    /// A page waits for the person (OB-07 Needs you).
    pub waiting: bool,
}

/// How much of a tab's committed URL is carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CarryKind {
    /// The committed URL as it is: the agent could read all of it.
    Exact,
    /// Scheme, host and path only: something in it was redacted for the
    /// agent, or the session showed a sign-in page.
    PathOnly,
}

impl CarryKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::PathOnly => "path_only",
        }
    }
}

/// One tab the new session reopens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CarriedTab {
    pub from_page_id: String,
    /// What the new session navigates to (never shown to the agent as is:
    /// replies show it through `agent_url`).
    pub target: String,
    pub kind: CarryKind,
    pub active: bool,
}

/// The old session, as the new one names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SwitchLink {
    pub session_id: String,
    pub mode: SessionMode,
    pub last_receipt_sha256: String,
    /// How many tabs are carried and how many are not.
    pub carried: usize,
    pub dropped: usize,
    pub plan_sha256: String,
}

impl SwitchLink {
    /// What the new session's `session_start` records (no URL).
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "session_id": self.session_id,
            "mode": self.mode.as_str(),
            "last_receipt_sha256": self.last_receipt_sha256,
            "carried": self.carried,
            "dropped": self.dropped,
            "plan_sha256": self.plan_sha256,
        })
    }
}

/// Everything a switch decided before anything changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SwitchPlan {
    pub from: SwitchLink,
    pub target: SessionMode,
    pub caller: Caller,
    /// The persistent profile the new session takes, if the old one held
    /// one.
    pub profile: Option<String>,
    pub task: Option<String>,
    pub tabs: Vec<CarriedTab>,
}

/// The URL a tab carries, and how much of it, or `None` when the tab is not
/// carried (not an https page).
pub(crate) fn carry_url(committed: &str, sign_in_seen: bool) -> Option<(String, CarryKind)> {
    if !committed.starts_with("https://") {
        return None;
    }
    let bare = crate::agent_url::bare(committed);
    if bare.is_empty() {
        return None;
    }
    if !sign_in_seen
        && crate::agent_url::agent_url(committed, false) == committed
        && crate::agent_url::no_token_values(committed)
    {
        Some((committed.to_owned(), CarryKind::Exact))
    } else {
        Some((bare, CarryKind::PathOnly))
    }
}

/// The tabs a switch reopens, background tabs first in the worker's order
/// and the active tab last (so it is active again), and how many are not
/// carried.
pub(crate) fn carried_tabs(state: &SwitchState) -> (Vec<CarriedTab>, usize) {
    let mut carried = Vec::new();
    let mut dropped = 0;
    let (active, background): (Vec<&SwitchTab>, Vec<&SwitchTab>) =
        state.tabs.iter().partition(|tab| tab.active);
    for tab in background.into_iter().chain(active) {
        match tab
            .committed
            .as_deref()
            .and_then(|url| carry_url(url, state.sign_in_seen))
        {
            Some((target, kind)) => carried.push(CarriedTab {
                from_page_id: tab.page_id.clone(),
                target,
                kind,
                active: tab.active,
            }),
            None => dropped += 1,
        }
    }
    (carried, dropped)
}

/// What the old session must satisfy before a switch, checked before any
/// prompt and again right before it ends.
pub(crate) struct SwitchCheck<'a> {
    pub current: SessionMode,
    pub target: SessionMode,
    pub session_caller: &'a Caller,
    pub caller: &'a Caller,
    pub persistent_profile: bool,
    /// Actions with an unknown effect, or whose receipt the chain refused.
    pub unsettled: u64,
    pub state: &'a SwitchState,
}

/// Refuse a switch that may not happen; nothing changes either way.
pub(crate) fn check(check: &SwitchCheck<'_>) -> Result<(), ProviderError> {
    if check.current == check.target {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            format!(
                "the browser session already runs in {} mode; nothing was moved",
                check.target.as_str()
            ),
        ));
    }
    if check.session_caller != check.caller {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "that browser session belongs to another caller; nothing was moved",
        ));
    }
    if check.caller.is_remote() && check.persistent_profile {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "SG-000135 OB-09: persistent Orcel-managed browser profiles are local-only; a remote caller gets an ephemeral session",
        ));
    }
    if check.unsettled > 0 {
        return Err(ProviderError::new(
            FailureCode::OutcomeUnknown,
            format!(
                "{} action(s) of this browser session have an uncertain outcome (see its receipts); a mode switch would lose the guard that keeps an uncertain write from being repeated, so nothing was moved. Reconcile them in this session, or close it",
                check.unsettled
            ),
        ));
    }
    if check.state.held {
        return Err(ProviderError::new(
            FailureCode::HumanTakeover,
            "a person is using this browser session's window, or stopped less than three seconds ago; nothing was moved",
        ));
    }
    if check.state.waiting && check.target == SessionMode::Shadow {
        return Err(ProviderError::new(
            FailureCode::HumanVerificationRequired,
            "a page of this browser session waits for the person; a Shadow session has no window to complete it in, so nothing was moved",
        ));
    }
    Ok(())
}

fn sha256_hex(text: &str) -> String {
    crate::browser_broker::hex(&Sha256::digest(text.as_bytes()))
}

/// The digest of what a switch would do: the old session, its last receipt,
/// the target mode, the profile, the task and each carried tab's URL
/// digest and kind. The approval binds it, and the switch refuses when it
/// changed before the old session ends.
pub(crate) fn plan_digest(
    from_session: &str,
    last_receipt_sha256: &str,
    target: SessionMode,
    profile: Option<&str>,
    task: Option<&str>,
    tabs: &[CarriedTab],
    dropped: usize,
) -> String {
    let tabs: Vec<Value> = tabs
        .iter()
        .map(|tab| {
            json!([
                tab.from_page_id,
                sha256_hex(&tab.target),
                tab.kind.as_str(),
                tab.active
            ])
        })
        .collect();
    let body = json!({
        "from": from_session,
        "last_receipt_sha256": last_receipt_sha256,
        "target": target.as_str(),
        "profile": profile,
        "task_sha256": task.map(sha256_hex),
        "tabs": tabs,
        "dropped": dropped,
    });
    sha256_hex(&format!("orcel-sh2-switch-plan/1\n{body}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tab(page: &str, url: Option<&str>, active: bool) -> SwitchTab {
        SwitchTab {
            page_id: page.to_owned(),
            committed: url.map(str::to_owned),
            active,
        }
    }

    #[test]
    fn sh2_secret_bearing_urls_are_never_carried() {
        // Nothing redacted for the agent: carried exactly.
        assert_eq!(
            carry_url("https://fixture.test/form?step=2#part", false),
            Some((
                "https://fixture.test/form?step=2#part".to_owned(),
                CarryKind::Exact
            ))
        );
        // A secret-looking value, a token, userinfo or a long fragment:
        // path only, never the query.
        for url in [
            "https://fixture.test/cb?code=abc&state=xyz",
            "https://fixture.test/x?q=eyJhbGciOiJIUzI1NiJ9abcdef",
            "https://user:hunter2@fixture.test/p",
            "https://fixture.test/p#access_token=abc",
            "https://fixture.test/login?user=ann&password=hunter2",
        ] {
            let (carried, kind) = carry_url(url, false).expect(url);
            assert_eq!(kind, CarryKind::PathOnly, "{url}");
            assert!(
                !carried.contains('?') && !carried.contains('#'),
                "{carried}"
            );
            for secret in ["abc", "hunter2", "eyJ", "ann", "user:"] {
                assert!(!carried.contains(secret), "{url} carried {carried}");
            }
        }
        // After a sign-in, every URL loses its query and fragment, even one
        // whose values look harmless (a GET sign-in form put what the person
        // typed there).
        assert_eq!(
            carry_url("https://fixture.test/home?lang=en&q=hello#top", true),
            Some(("https://fixture.test/home".to_owned(), CarryKind::PathOnly))
        );
        // Not an https page: not carried.
        for url in [
            "about:blank",
            "http://fixture.test/a",
            "file:///C:/x",
            "data:text/html,x",
            "",
        ] {
            assert_eq!(carry_url(url, false), None, "{url}");
        }
    }

    #[test]
    fn sh2_tabs_are_carried_background_first_and_active_last() {
        let state = SwitchState {
            tabs: vec![
                tab("pg-a", Some("https://fixture.test/a"), false),
                tab("pg-b", Some("https://fixture.test/b?token=t"), true),
                tab("pg-c", None, false),
                tab("pg-d", Some("https://fixture.test/d"), false),
            ],
            ..Default::default()
        };
        let (tabs, dropped) = carried_tabs(&state);
        assert_eq!(dropped, 1);
        let order: Vec<(&str, &str, CarryKind, bool)> = tabs
            .iter()
            .map(|t| (t.from_page_id.as_str(), t.target.as_str(), t.kind, t.active))
            .collect();
        assert_eq!(
            order,
            vec![
                ("pg-a", "https://fixture.test/a", CarryKind::Exact, false),
                ("pg-d", "https://fixture.test/d", CarryKind::Exact, false),
                ("pg-b", "https://fixture.test/b", CarryKind::PathOnly, true),
            ]
        );
    }

    #[test]
    fn sh2_a_switch_is_refused_before_anything_changes() {
        let remote = Caller::Remote(crate::browser_remote::RemoteCaller {
            provider: "openai".into(),
            device: "dev-1".into(),
            connection: "rc-1".into(),
            principal: "p-1".into(),
        });
        let clear = SwitchState::default();
        fn ok<'a>(
            current: SessionMode,
            target: SessionMode,
            state: &'a SwitchState,
        ) -> SwitchCheck<'a> {
            static LOCAL: Caller = Caller::Local;
            SwitchCheck {
                current,
                target,
                session_caller: &LOCAL,
                caller: &LOCAL,
                persistent_profile: false,
                unsettled: 0,
                state,
            }
        }
        let code = |c: SwitchCheck<'_>| check(&c).err().map(|e| e.code);
        assert_eq!(
            code(ok(SessionMode::Shadow, SessionMode::Visible, &clear)),
            None
        );
        assert_eq!(
            code(ok(SessionMode::Visible, SessionMode::Shadow, &clear)),
            None
        );
        assert_eq!(
            code(ok(SessionMode::Shadow, SessionMode::Shadow, &clear)),
            Some(FailureCode::InvalidRequest)
        );
        assert_eq!(
            code(SwitchCheck {
                caller: &remote,
                ..ok(SessionMode::Shadow, SessionMode::Visible, &clear)
            }),
            Some(FailureCode::CapabilityDenied)
        );
        assert_eq!(
            code(SwitchCheck {
                session_caller: &remote,
                caller: &remote,
                persistent_profile: true,
                ..ok(SessionMode::Shadow, SessionMode::Visible, &clear)
            }),
            Some(FailureCode::CapabilityDenied)
        );
        assert_eq!(
            code(SwitchCheck {
                unsettled: 1,
                ..ok(SessionMode::Shadow, SessionMode::Visible, &clear)
            }),
            Some(FailureCode::OutcomeUnknown)
        );
        let held = SwitchState {
            held: true,
            ..Default::default()
        };
        assert_eq!(
            code(ok(SessionMode::Visible, SessionMode::Shadow, &held)),
            Some(FailureCode::HumanTakeover)
        );
        // A page that waits for the person may move to a Visible window
        // (the handoff), never into Shadow.
        let waiting = SwitchState {
            waiting: true,
            ..Default::default()
        };
        assert_eq!(
            code(ok(SessionMode::Shadow, SessionMode::Visible, &waiting)),
            None
        );
        assert_eq!(
            code(ok(SessionMode::Visible, SessionMode::Shadow, &waiting)),
            Some(FailureCode::HumanVerificationRequired)
        );
    }

    #[test]
    fn sh2_the_plan_digest_binds_every_choice() {
        let tabs = vec![CarriedTab {
            from_page_id: "pg-a".into(),
            target: "https://fixture.test/a".into(),
            kind: CarryKind::Exact,
            active: true,
        }];
        let base = plan_digest(
            "bs-1",
            "r1",
            SessionMode::Visible,
            None,
            Some("t"),
            &tabs,
            0,
        );
        let mut other_tab = tabs.clone();
        other_tab[0].target = "https://fixture.test/b".into();
        for changed in [
            plan_digest(
                "bs-2",
                "r1",
                SessionMode::Visible,
                None,
                Some("t"),
                &tabs,
                0,
            ),
            plan_digest(
                "bs-1",
                "r2",
                SessionMode::Visible,
                None,
                Some("t"),
                &tabs,
                0,
            ),
            plan_digest("bs-1", "r1", SessionMode::Shadow, None, Some("t"), &tabs, 0),
            plan_digest(
                "bs-1",
                "r1",
                SessionMode::Visible,
                Some("w"),
                Some("t"),
                &tabs,
                0,
            ),
            plan_digest("bs-1", "r1", SessionMode::Visible, None, None, &tabs, 0),
            plan_digest(
                "bs-1",
                "r1",
                SessionMode::Visible,
                None,
                Some("t"),
                &other_tab,
                0,
            ),
            plan_digest(
                "bs-1",
                "r1",
                SessionMode::Visible,
                None,
                Some("t"),
                &tabs,
                1,
            ),
        ] {
            assert_ne!(base, changed);
        }
        assert_eq!(
            base,
            plan_digest(
                "bs-1",
                "r1",
                SessionMode::Visible,
                None,
                Some("t"),
                &tabs,
                0
            )
        );
    }
}
