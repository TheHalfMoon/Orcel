//! Orcel Browser packet B1: the human-intervention gate on the live
//! browser's agent actions (`orcel-browser-session`).
//!
//! The live browser asks this gate before every agent action on its page:
//! reads (observe, wait, verify, download preview) and writes (navigate,
//! click, form actions, downloads). A write is asked twice: before its
//! approval prompt, and again right before its approval is spent, because a
//! person may take the page over while the prompt is up. While a person
//! holds the page, or the page waits for them (a sign-in, MFA, passkey or
//! CAPTCHA challenge), or the task is paused, the action is refused with
//! `TARGET_STALE` and a message that says the session is paused; after the
//! quiet period the agent must observe the page again before it writes, and
//! a write planned before the person acted is refused as stale. A
//! consequential write (Enter, which may submit; a download) whose outcome
//! is unknown is not admitted again on that page.
//!
//! The gate holds no authority: it can only refuse. It runs before the
//! approval broker, never in its place, and nothing it answers can make an
//! action proceed that the broker or policy would refuse.
//!
//! The switch is off by default (the `browser-takeover-gate` feature, which
//! no build enables) until SG-000135 defines the browser session broker
//! this gate belongs to. Off, every call admits and records nothing.
//! Nothing feeds human input into the gate yet: the engine adapter that
//! reports trusted input events per page (and attaches Orcel's markers to
//! the agent's own) is the next step, through [`TakeoverGate::session_gate`].
//! Its one caller is the live browser, so outside the live builds the module
//! is unused (its declaration allows that).

use orcel_browser_session::{
    ActionClass, ActionKey, Clock, ReadTicket, Refusal, RefusalClass, ResourceId, SessionGate,
    SystemClock, TaskId, WriteOutcome, WriteTicket,
};
use orcel_contracts::FailureCode;
use orcel_provider_fs::ProviderError;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Whether the gate is on in this build. Off until SG-000135 is merged.
pub(crate) const ENABLED: bool = cfg!(feature = "browser-takeover-gate");

/// The one task the live browser runs today (one host, one page).
const LIVE_TASK: &str = "live-browser";

/// Domain separation for action keys.
const ACTION_KEY_DOMAIN: &str = "orcel-b1-action-key/1";

/// The live browser's gate: off, or a session gate over its pages.
pub(crate) struct TakeoverGate<C: Clock = SystemClock> {
    gate: Option<SessionGate<C>>,
    /// The epoch each page's latest observation returned: what the agent's
    /// next write is planned on. orceld cannot see the agent's plan, so the
    /// latest observation stands for it.
    basis: HashMap<String, u64>,
}

impl TakeoverGate<SystemClock> {
    /// The gate as this build's switch sets it.
    pub(crate) fn from_switch() -> Self {
        if ENABLED {
            Self::on(SystemClock::new())
        } else {
            Self::off()
        }
    }
}

impl<C: Clock> TakeoverGate<C> {
    /// A gate that admits everything.
    pub(crate) fn off() -> Self {
        Self {
            gate: None,
            basis: HashMap::new(),
        }
    }

    /// A gate on `clock`.
    pub(crate) fn on(clock: C) -> Self {
        Self {
            gate: Some(SessionGate::new(clock)),
            basis: HashMap::new(),
        }
    }

    /// The session gate, for the engine adapter that reports input events
    /// and challenges, and for the explicit controls (take over, pause,
    /// resume, cancel). `None` while the switch is off. Until that adapter
    /// lands only the tests call it.
    #[allow(dead_code)]
    pub(crate) fn session_gate(&mut self) -> Option<&mut SessionGate<C>> {
        self.gate.as_mut()
    }

    /// The live page opened: the live task owns it.
    pub(crate) fn page_opened(&mut self, page_id: &str) {
        if let Some(gate) = self.gate.as_mut() {
            if gate
                .claim(ResourceId::new(page_id), TaskId::new(LIVE_TASK))
                .is_ok()
            {
                self.basis.insert(page_id.to_owned(), 0);
            }
        }
    }

    /// The live page closed: its session ends with it.
    pub(crate) fn page_closed(&mut self, page_id: &str) {
        if let Some(gate) = self.gate.as_mut() {
            let _ = gate.release(&ResourceId::new(page_id));
        }
        self.basis.remove(page_id);
    }

    /// Before a read of the page.
    pub(crate) fn before_read(
        &mut self,
        page_id: &str,
    ) -> Result<Option<ReadTicket>, ProviderError> {
        match self.gate.as_mut() {
            Some(gate) => gate
                .begin_read(&ResourceId::new(page_id))
                .map_err(|refusal| refused(&refusal)),
            None => Ok(None),
        }
    }

    /// The read under `ticket` was a fresh observation of its page.
    pub(crate) fn observed(&mut self, ticket: Option<ReadTicket>) {
        if let (Some(gate), Some(ticket)) = (self.gate.as_mut(), ticket) {
            if let Some(epoch) = gate.observation_completed(&ticket) {
                self.basis
                    .insert(ticket.resource().as_str().to_owned(), epoch);
            }
        }
    }

    /// Before a write of `kind` on the page; `material` is what makes two
    /// writes the same action (it is hashed here, never kept or logged).
    pub(crate) fn before_write(
        &mut self,
        page_id: &str,
        kind: &str,
        material: &str,
        class: ActionClass,
    ) -> Result<Option<WriteTicket>, ProviderError> {
        let Some(gate) = self.gate.as_mut() else {
            return Ok(None);
        };
        let basis = self.basis.get(page_id).copied().unwrap_or(0);
        gate.begin_write(
            &ResourceId::new(page_id),
            action_key(page_id, kind, material),
            class,
            basis,
        )
        .map_err(|refusal| refused(&refusal))
    }

    /// Right before the write's approval is spent and the frame is sent.
    pub(crate) fn before_dispatch(
        &mut self,
        ticket: Option<&WriteTicket>,
    ) -> Result<(), ProviderError> {
        match (self.gate.as_mut(), ticket) {
            (Some(gate), Some(ticket)) => gate
                .confirm_dispatch(ticket)
                .map_err(|refusal| refused(&refusal)),
            _ => Ok(()),
        }
    }

    /// The write finished: `outcome` is the journal's word for it (`done`,
    /// `failed`, or anything else for unknown).
    pub(crate) fn after_write(&mut self, ticket: Option<WriteTicket>, outcome: &str) {
        if let (Some(gate), Some(ticket)) = (self.gate.as_mut(), ticket) {
            let outcome = match outcome {
                "done" => WriteOutcome::Done,
                "failed" => WriteOutcome::Failed,
                _ => WriteOutcome::Uncertain,
            };
            let _ = gate.finish_write(&ticket, outcome);
        }
    }
}

/// The action key: a digest of the page, the kind and the material.
fn action_key(page_id: &str, kind: &str, material: &str) -> ActionKey {
    let mut hasher = Sha256::new();
    for part in [ACTION_KEY_DOMAIN, page_id, kind, material] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    ActionKey::new(digest)
}

/// A refusal as orceld's closed failure code. The contract has no paused
/// code yet, so every refusal is `TARGET_STALE` (nothing was done; observe
/// again later), and the message says which: paused, stale or ended.
fn refused(refusal: &Refusal) -> ProviderError {
    let class = match refusal.reason.class() {
        RefusalClass::Paused => "browser session paused",
        RefusalClass::Stale => "browser session stale",
        RefusalClass::Ended => "browser session ended",
    };
    ProviderError::new(FailureCode::TargetStale, format!("{class}: {refusal}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_browser_session::{
        ChallengeKind, ChallengeOrigin, InputKind, InputPhase, ManualClock, ObservedInput, QUIET_MS,
    };

    fn human(gate: &mut TakeoverGate<ManualClock>, page: &str) {
        if let Some(gate) = gate.session_gate() {
            let _ = gate.observe_input(&ObservedInput {
                resource: ResourceId::new(page),
                kind: InputKind::Edit,
                phase: InputPhase::Instant,
                marker: None,
            });
        }
    }

    fn on() -> (ManualClock, TakeoverGate<ManualClock>) {
        let clock = ManualClock::at(0);
        let mut gate = TakeoverGate::on(clock.clone());
        gate.page_opened("page-1");
        (clock, gate)
    }

    #[test]
    fn the_switch_is_off_unless_the_feature_is_enabled() {
        assert_eq!(TakeoverGate::from_switch().gate.is_some(), ENABLED);
        #[cfg(not(feature = "browser-takeover-gate"))]
        assert!(!TakeoverGate::from_switch().gate.is_some());
    }

    #[test]
    fn an_off_gate_admits_everything_and_records_nothing() {
        let mut gate: TakeoverGate<ManualClock> = TakeoverGate::off();
        gate.page_opened("page-1");
        human(&mut gate, "page-1");
        assert!(matches!(gate.before_read("page-1"), Ok(None)));
        let ticket = gate.before_write("page-1", "enter", "n1", ActionClass::Consequential);
        assert!(matches!(ticket, Ok(None)));
        assert!(gate.before_dispatch(None).is_ok());
        gate.after_write(None, "unknown");
        assert!(matches!(
            gate.before_write("page-1", "enter", "n1", ActionClass::Consequential),
            Ok(None)
        ));
    }

    #[test]
    fn a_human_on_the_page_refuses_reads_and_writes_as_paused_target_stale() {
        let (_clock, mut gate) = on();
        human(&mut gate, "page-1");
        for refusal in [
            gate.before_read("page-1").err(),
            gate.before_write("page-1", "click", "n1", ActionClass::Repeatable)
                .err(),
        ] {
            assert!(
                matches!(&refusal, Some(error) if error.code == FailureCode::TargetStale
                    && error.message.starts_with("browser session paused: human_override")),
                "{refusal:?}"
            );
        }
    }

    #[test]
    fn after_the_quiet_the_page_must_be_observed_before_a_write() {
        let (clock, mut gate) = on();
        human(&mut gate, "page-1");
        clock.advance(QUIET_MS);
        let stale = gate.before_write("page-1", "click", "n1", ActionClass::Repeatable);
        assert!(
            matches!(&stale, Err(e) if e.message.contains("reobserve_required")),
            "{stale:?}"
        );
        let ticket = gate.before_read("page-1").ok().flatten();
        assert!(ticket.is_some());
        gate.observed(ticket);
        let admitted = gate.before_write("page-1", "click", "n1", ActionClass::Repeatable);
        assert!(matches!(admitted, Ok(Some(_))));
    }

    #[test]
    fn a_person_taking_over_during_the_prompt_stops_the_dispatch() {
        let (_clock, mut gate) = on();
        let ticket = gate
            .before_write("page-1", "fill", "n1 value", ActionClass::Repeatable)
            .ok()
            .flatten();
        assert!(ticket.is_some());
        human(&mut gate, "page-1");
        let refused = gate.before_dispatch(ticket.as_ref());
        assert!(matches!(refused, Err(e) if e.code == FailureCode::TargetStale));
    }

    #[test]
    fn an_enter_with_an_unknown_outcome_is_not_admitted_again() {
        let (_clock, mut gate) = on();
        let ticket = gate
            .before_write("page-1", "enter", "n7", ActionClass::Consequential)
            .ok()
            .flatten();
        assert!(gate.before_dispatch(ticket.as_ref()).is_ok());
        gate.after_write(ticket, "unknown");
        let again = gate.before_write("page-1", "enter", "n7", ActionClass::Consequential);
        assert!(
            matches!(&again, Err(e) if e.message.contains("outcome_uncertain")),
            "{again:?}"
        );
        let other = gate.before_write("page-1", "enter", "n8", ActionClass::Consequential);
        assert!(matches!(other, Ok(Some(_))), "another action goes on");
    }

    #[test]
    fn a_failed_write_releases_its_ticket() {
        let (_clock, mut gate) = on();
        let ticket = gate
            .before_write("page-1", "enter", "n7", ActionClass::Consequential)
            .ok()
            .flatten();
        gate.after_write(ticket, "failed");
        let again = gate.before_write("page-1", "enter", "n7", ActionClass::Consequential);
        assert!(matches!(again, Ok(Some(_))));
    }

    #[test]
    fn a_challenge_refuses_with_needs_you_and_a_closed_page_ends_its_session() {
        let (_clock, mut gate) = on();
        if let Some(session) = gate.session_gate() {
            let _ = session.challenge(
                &ResourceId::new("page-1"),
                ChallengeKind::Captcha,
                ChallengeOrigin::Detected,
            );
        }
        let refused = gate.before_read("page-1");
        assert!(
            matches!(&refused, Err(e) if e.message.contains("await_human_verification")),
            "{refused:?}"
        );
        gate.page_closed("page-1");
        assert!(
            matches!(gate.before_read("page-1"), Ok(None)),
            "an unowned page is not the gate's"
        );
    }

    #[test]
    fn the_refusal_message_never_carries_the_action_material() {
        let (_clock, mut gate) = on();
        human(&mut gate, "page-1");
        let refused =
            gate.before_write("page-1", "fill", "hunter2-secret", ActionClass::Repeatable);
        assert!(
            matches!(&refused, Err(e) if !e.message.contains("hunter2")),
            "{refused:?}"
        );
    }
}
