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
//! is unknown is not admitted again: its key is built from stable action
//! material (origin, URL path, kind, and the target's role, name and ordinal
//! or the link and file name), never a page or node id, and the uncertain
//! actions live in one ledger per orceld process (entries kept per task: the
//! live browser's task, or a broker session's id), so neither a closed page,
//! a renumbered observation nor a host restart forgets them. With the gate
//! on, a page it does not track (one it could not claim) is refused.
//!
//! The gate holds no authority: it can only refuse. It runs before the
//! approval broker, never in its place, and nothing it answers can make an
//! action proceed that the broker or policy would refuse.
//!
//! For `browser_structured` the switch stays off by default (the
//! `browser-takeover-gate` feature, which no build enables): off, every call
//! admits and records nothing. SG-000135 OB-07 turns the gate on for every
//! `browser_full` broker session (`TakeoverGate::enable`), whatever the
//! build's switch, so a challenge page ("Needs you") is refused there.
//!
//! SG-000135 OB-07: the engine's read-only challenge detector reports what
//! it sees on a session's page here. A detected sign-in, one-time code,
//! passkey or CAPTCHA moves the page to `AWAIT_HUMAN_VERIFICATION`
//! ([`TakeoverGate::challenge_detected`]); every agent read and write on it
//! is then refused with `HUMAN_VERIFICATION_REQUIRED`. Only the detector's
//! later report that the challenge is gone
//! ([`TakeoverGate::challenge_gone`]) starts the way back, and only after
//! three quiet seconds does the page move to `REOBSERVE`, where the agent
//! must observe it again before it writes. The agent has no call that can
//! clear a challenge.
//!
//! Nothing feeds human input events into the gate yet: the engine adapter
//! that reports trusted input events per page (and attaches Orcel's markers
//! to the agent's own) is the next step, through
//! [`TakeoverGate::session_gate`]. Its one caller is the live browser, so
//! outside the live builds the module is unused (its declaration allows
//! that).

use orcel_browser_session::{
    ActionClass, ActionKey, ChallengeKind, ChallengeOrigin, Clock, ReadTicket, Reads, Reason,
    Refusal, RefusalClass, ResourceId, SessionGate, SharedLedger, State, SystemClock, TaskId,
    UncertainLedger, WriteOutcome, WriteTicket,
};
use orcel_contracts::FailureCode;
use orcel_provider_fs::ProviderError;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{OnceLock, PoisonError};

/// Whether the gate is on in this build. Off until SG-000135 is merged.
pub(crate) const ENABLED: bool = cfg!(feature = "browser-takeover-gate");

/// The one task the live browser runs today (one host, one page).
const LIVE_TASK: &str = "live-browser";

/// Domain separation for a write's provisional (per-page) key.
const ACTION_KEY_DOMAIN: &str = "orcel-b1-action-key/1";

/// The prefix of a client's ledger task (never a session id or the live
/// task, which carry no such prefix).
const CLIENT_TASK_PREFIX: &str = "client\u{0}";

/// Domain separation for a write's stable key.
const STABLE_KEY_DOMAIN: &str = "orcel-b1-stable-action/1";

/// The process's uncertain-action ledger: every live browser (one per host
/// lifetime) shares it, so a host restart forgets no uncertain action.
fn process_ledger() -> SharedLedger {
    static LEDGER: OnceLock<SharedLedger> = OnceLock::new();
    SharedLedger::clone(LEDGER.get_or_init(UncertainLedger::shared))
}

/// The live browser's gate: off, or a session gate over its pages.
pub(crate) struct TakeoverGate<C: Clock = SystemClock> {
    gate: Option<SessionGate<C>>,
    /// The epoch each page's latest observation returned: what the agent's
    /// next write is planned on. orceld cannot see the agent's plan, so the
    /// latest observation stands for it.
    basis: HashMap<String, u64>,
    /// The task that owns the pages this gate claims: the live browser's
    /// one task, or (SG-000135 OB-01) the broker session's id.
    task: String,
    /// SG-000135 OB-01: the MCP client a broker session belongs to. Its
    /// uncertain consequential actions are also kept under the client in
    /// the shared ledger, so the client cannot repeat one by opening a new
    /// session; unrelated clients stay independent.
    client: Option<String>,
    /// The shared ledger (the session gate's own), for the client entries.
    ledger: Option<SharedLedger>,
    /// The class of the write in progress, from `before_write`.
    pending_class: Option<ActionClass>,
    /// The client-scoped key of the consequential write in progress.
    pending_client_key: Option<ActionKey>,
}

impl TakeoverGate<SystemClock> {
    /// The gate as this build's switch sets it.
    pub(crate) fn from_switch() -> Self {
        if ENABLED {
            Self::on_with_ledger(SystemClock::new(), process_ledger())
        } else {
            Self::off()
        }
    }

    /// SG-000135 OB-07: turn the gate on for a `browser_full` broker
    /// session, whatever the build's switch, on the process's shared
    /// uncertain-action ledger. Called before the session opens any page;
    /// a gate already on is left as it is.
    #[cfg_attr(not(feature = "live-browser-dev"), allow(dead_code))]
    pub(crate) fn enable(&mut self) {
        if self.gate.is_some() {
            return;
        }
        let ledger = process_ledger();
        self.gate = Some(SessionGate::with_ledger(
            SystemClock::new(),
            Reads::Block,
            SharedLedger::clone(&ledger),
        ));
        self.ledger = Some(ledger);
    }
}

impl<C: Clock> TakeoverGate<C> {
    /// A gate that admits everything.
    pub(crate) fn off() -> Self {
        Self {
            gate: None,
            basis: HashMap::new(),
            task: LIVE_TASK.to_owned(),
            client: None,
            ledger: None,
            pending_class: None,
            pending_client_key: None,
        }
    }

    /// A gate on `clock` with a ledger of its own.
    #[cfg(test)]
    pub(crate) fn on(clock: C) -> Self {
        Self::on_with_ledger(clock, UncertainLedger::shared())
    }

    /// A gate on `clock` whose idempotency guard uses `ledger`.
    pub(crate) fn on_with_ledger(clock: C, ledger: SharedLedger) -> Self {
        Self {
            gate: Some(SessionGate::with_ledger(
                clock,
                Reads::Block,
                SharedLedger::clone(&ledger),
            )),
            basis: HashMap::new(),
            task: LIVE_TASK.to_owned(),
            client: None,
            ledger: Some(ledger),
            pending_class: None,
            pending_client_key: None,
        }
    }

    /// SG-000135 OB-01: pages opened from now on belong to `task` (a broker
    /// session's id), so the gate's ownership is per session. A page
    /// already claimed keeps its owner. Every session's gate shares the
    /// process's uncertain-action ledger (`process_ledger`), never one of
    /// its own.
    #[cfg_attr(not(feature = "live-browser-dev"), allow(dead_code))]
    pub(crate) fn set_task(&mut self, task: &str) {
        self.task = task.to_owned();
    }

    /// SG-000135 OB-01: the MCP client (its `client_session_id`) the
    /// session belongs to; its uncertain consequential actions are also
    /// kept per client.
    #[cfg_attr(not(feature = "live-browser-dev"), allow(dead_code))]
    pub(crate) fn set_client(&mut self, client: &str) {
        self.client = Some(client.to_owned());
    }

    /// The ledger task a client's entries are kept under.
    fn client_task(client: &str) -> TaskId {
        TaskId::new(format!("{CLIENT_TASK_PREFIX}{client}"))
    }

    /// With the gate on, a page it does not track is refused (fail closed).
    fn tracked(gate: &SessionGate<C>, page_id: &str) -> Result<(), ProviderError> {
        if gate.owner(&ResourceId::new(page_id)).is_some() {
            Ok(())
        } else {
            Err(ProviderError::new(
                FailureCode::TargetStale,
                "browser session stale: the takeover gate does not track this page; open a page first",
            ))
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

    /// SG-000135 OB-08: the page's intervention epoch (each human
    /// intervention advances it), which a Full Access lease's use is pinned
    /// to; `None` while the switch is off or the page is not tracked.
    pub(crate) fn intervention_epoch(&self, page_id: &str) -> Option<u64> {
        self.gate
            .as_ref()
            .and_then(|gate| gate.epoch(&ResourceId::new(page_id)))
    }

    /// OB-08 review: the intervention epoch of every page the gate tracks,
    /// or `None` while the switch is off (then no person's input can be
    /// seen, and a lease covers nothing).
    pub(crate) fn interventions(&self) -> Option<std::collections::BTreeMap<String, u64>> {
        let gate = self.gate.as_ref()?;
        Some(
            self.basis
                .keys()
                .filter_map(|page| {
                    gate.epoch(&ResourceId::new(page.as_str()))
                        .map(|epoch| (page.clone(), epoch))
                })
                .collect(),
        )
    }

    /// Whether the gate is on.
    pub(crate) fn is_on(&self) -> bool {
        self.gate.is_some()
    }

    /// SG-000135 OB-07: the engine's challenge detector saw `kind` on
    /// `page_id`: the page waits for the person ("Needs you"). Seen again
    /// while it waits, the wait goes on and any report that it was gone is
    /// forgotten. False when the gate is off or does not track the page.
    pub(crate) fn challenge_detected(&mut self, page_id: &str, kind: ChallengeKind) -> bool {
        self.gate.as_mut().is_some_and(|gate| {
            gate.challenge(&ResourceId::new(page_id), kind, ChallengeOrigin::Detected)
                .is_ok()
        })
    }

    /// SG-000135 OB-07: the detector no longer sees `page_id`'s challenge.
    /// The page leaves the wait only after the quiet period, into
    /// `REOBSERVE`. Only the detector calls this: no agent request reaches
    /// it. True when the page was waiting.
    pub(crate) fn challenge_gone(&mut self, page_id: &str) -> bool {
        self.gate.as_mut().is_some_and(|gate| {
            gate.challenge_cleared(&ResourceId::new(page_id))
                .unwrap_or(false)
        })
    }

    /// SG-000135 OB-07: the challenge `page_id` waits on, if it waits.
    pub(crate) fn awaiting(&mut self, page_id: &str) -> Option<ChallengeKind> {
        match self.page_state(page_id) {
            Some(State::AwaitHumanVerification(kind)) => Some(kind),
            _ => None,
        }
    }

    /// `page_id`'s state as of now (None when the gate is off or does not
    /// track it).
    pub(crate) fn page_state(&mut self, page_id: &str) -> Option<State> {
        self.gate
            .as_mut()
            .and_then(|gate| gate.state(&ResourceId::new(page_id)))
    }

    /// The live page opened: the live task owns it.
    pub(crate) fn page_opened(&mut self, page_id: &str) {
        if let Some(gate) = self.gate.as_mut() {
            if gate
                .claim(ResourceId::new(page_id), TaskId::new(self.task.as_str()))
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
            Some(gate) => {
                Self::tracked(gate, page_id)?;
                gate.begin_read(&ResourceId::new(page_id))
                    .map_err(|refusal| refused(&refusal))
            }
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
        Self::tracked(gate, page_id)?;
        self.pending_class = Some(class);
        self.pending_client_key = None;
        let basis = self.basis.get(page_id).copied().unwrap_or(0);
        gate.begin_write(
            &ResourceId::new(page_id),
            action_key(page_id, kind, material),
            class,
            basis,
        )
        .map_err(|refusal| refused(&refusal))
    }

    /// Once the target is bound: key the write by its stable material, the
    /// page's `origin` and the path of its `url`, the action's `kind` and
    /// `material` (a stable target description, never a node id). Refused
    /// if that action's earlier outcome is unknown.
    pub(crate) fn rekey(
        &mut self,
        ticket: Option<&WriteTicket>,
        origin: &str,
        url: Option<&str>,
        kind: &str,
        material: &str,
    ) -> Result<(), ProviderError> {
        let key = stable_key(&self.task, origin, url_path(url), kind, material);
        let (Some(gate), Some(ticket)) = (self.gate.as_mut(), ticket) else {
            return Ok(());
        };
        gate.rekey(ticket, key)
            .map_err(|refusal| refused(&refusal))?;
        // SG-000135 OB-01: the same action's outcome is unknown under this
        // client, from any of its sessions.
        if let (Some(client), Some(ledger)) = (&self.client, &self.ledger) {
            let task = Self::client_task(client);
            let client_key = stable_key(task.as_str(), origin, url_path(url), kind, material);
            let consequential = self.pending_class == Some(ActionClass::Consequential);
            let refuses = ledger
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .refuses(&task, &client_key, consequential);
            if refuses {
                return Err(ProviderError::new(
                    FailureCode::TargetStale,
                    "browser session stale: outcome_uncertain: an earlier session of this client sent this action and its outcome is unknown; check the page and reconcile before repeating it",
                ));
            }
            if consequential {
                self.pending_client_key = Some(client_key);
            }
        }
        Ok(())
    }

    /// SG-000135 OB-01: the outcome of this client's uncertain action
    /// (`origin`, `url`, `kind`, `material`, as `rekey` named it) was
    /// established: the client may send it again. Like the session
    /// reconcile, it is never automatic; until it is called the action
    /// stays refused. False when nothing was recorded.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn reconcile_client(
        &mut self,
        origin: &str,
        url: Option<&str>,
        kind: &str,
        material: &str,
    ) -> bool {
        let (Some(client), Some(ledger)) = (&self.client, &self.ledger) else {
            return false;
        };
        let task = Self::client_task(client);
        let key = stable_key(task.as_str(), origin, url_path(url), kind, material);
        ledger
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reconcile(&task, &key)
    }

    /// SG-000135 OB-01: every uncertain outcome of this client was
    /// established, including any a full ledger could not record.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn reconcile_client_overflow(&mut self) -> bool {
        let (Some(client), Some(ledger)) = (&self.client, &self.ledger) else {
            return false;
        };
        ledger
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reconcile_overflow(&Self::client_task(client))
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
        let client_key = self.pending_client_key.take();
        self.pending_class = None;
        if let (Some(key), Some(client), Some(ledger)) = (client_key, &self.client, &self.ledger) {
            if ticket.is_some() && !matches!(outcome, "done" | "failed") {
                let _ = ledger
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .record(&Self::client_task(client), key);
            }
        }
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

/// A length-prefixed SHA-256 over `parts`, as an action key.
fn digest_key(parts: &[&str]) -> ActionKey {
    let mut hasher = Sha256::new();
    for part in parts {
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

/// A write's provisional key, until its target is bound: the page, the
/// kind and the material.
fn action_key(page_id: &str, kind: &str, material: &str) -> ActionKey {
    digest_key(&[ACTION_KEY_DOMAIN, page_id, kind, material])
}

/// A write's stable key: the owning task (the live browser's one task, or
/// SG-000135 OB-01 a broker session's id), the origin, the URL path, the
/// kind and a stable target description. No page or node id. The ledger
/// keeps its entries per task as well, so one broker session's uncertain
/// action never blocks an unrelated session.
fn stable_key(task: &str, origin: &str, path: &str, kind: &str, material: &str) -> ActionKey {
    digest_key(&[STABLE_KEY_DOMAIN, task, origin, path, kind, material])
}

/// Split `url` at the end of its authority: the authority ends at the
/// first '/', '?' or '#' after the scheme. Returns the part before (scheme
/// and authority) and the path without query or fragment ("/" if none).
fn split_url(url: &str) -> (&str, &str) {
    let start = url.find("://").map_or(0, |at| at + 3);
    let authority_end = url[start..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |at| start + at);
    let rest = &url[authority_end..];
    let path = match rest.find(['?', '#']) {
        Some(0) | None if !rest.starts_with('/') => "/",
        Some(end) => &rest[..end],
        None => rest,
    };
    (&url[..authority_end], path)
}

/// The path of `url` (no query or fragment); empty when unknown.
fn url_path(url: Option<&str>) -> &str {
    url.map_or("", |url| split_url(url).1)
}

/// A link's identity for a download's stable key: its scheme, authority and
/// path, without the query or fragment (a signed URL's changing query must
/// not make the same download look new).
pub(crate) fn link_identity(url: &str) -> String {
    let (origin, path) = split_url(url);
    format!("{origin}{path}")
}

/// A refusal as orceld's closed failure code. A page that waits for a
/// person's verification (SG-000135 OB-07) is `HUMAN_VERIFICATION_REQUIRED`
/// ("Needs you"); the contract has no paused code, so every other refusal
/// is `TARGET_STALE` (nothing was done; observe again later), and the
/// message says which: paused, stale or ended.
fn refused(refusal: &Refusal) -> ProviderError {
    if refusal.reason == Reason::AwaitingHumanVerification {
        return ProviderError::new(
            FailureCode::HumanVerificationRequired,
            format!(
                "needs_you: {refusal}; Orcel never completes or skips it; read browser_task_status until the page no longer needs you, then observe it again"
            ),
        );
    }
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
            matches!(&refused, Err(e) if e.code == FailureCode::HumanVerificationRequired
                && e.message.starts_with("needs_you: await_human_verification")),
            "{refused:?}"
        );
        gate.page_closed("page-1");
        let untracked = gate.before_read("page-1");
        assert!(
            matches!(&untracked, Err(e) if e.code == FailureCode::TargetStale
                && e.message.contains("does not track")),
            "with the gate on, a page it does not track is refused: {untracked:?}"
        );
        assert!(gate
            .before_write("page-1", "click", "n1", ActionClass::Repeatable)
            .is_err());
    }

    /// One Enter on the Search field of https://shop.test/checkout, as the
    /// live browser keys it after the host bound the field.
    fn enter_on(
        gate: &mut TakeoverGate<ManualClock>,
        page: &str,
        node: &str,
    ) -> Result<Option<WriteTicket>, ProviderError> {
        let ticket = gate.before_write(page, "form", node, ActionClass::Consequential)?;
        gate.rekey(
            ticket.as_ref(),
            "https://shop.test",
            Some("https://shop.test/checkout?step=2#pay"),
            "form",
            "enter\u{0}textbox\u{0}Search\u{0}1/1\u{0}",
        )?;
        Ok(ticket)
    }

    #[test]
    fn a_lost_enter_is_refused_after_a_host_restart_and_renumbered_nodes_until_reconciled() {
        let ledger = UncertainLedger::shared();
        let clock = ManualClock::at(0);
        {
            // First host lifetime: the Enter is sent and its reply is lost.
            let mut first = TakeoverGate::on_with_ledger(clock.clone(), ledger.clone());
            first.page_opened("page-1");
            let ticket = enter_on(&mut first, "page-1", "n7").ok().flatten();
            assert!(first.before_dispatch(ticket.as_ref()).is_ok());
            // What the live browser's dispatch does on a lost reply: settle
            // the ticket as unknown, then end the host (closing the page).
            first.after_write(ticket, "unknown");
            first.page_closed("page-1");
        }
        // The host restarts: a new gate on the same process ledger, a new
        // page, and the observation numbers the field differently.
        let mut second = TakeoverGate::on_with_ledger(clock, ledger.clone());
        second.page_opened("page-2");
        let refused = enter_on(&mut second, "page-2", "n42");
        assert!(
            matches!(&refused, Err(e) if e.code == FailureCode::TargetStale
                && e.message.contains("outcome_uncertain")),
            "{refused:?}"
        );
        // Another field is a different action.
        let other = second
            .before_write("page-2", "form", "n43", ActionClass::Consequential)
            .ok()
            .flatten();
        assert!(second
            .rekey(
                other.as_ref(),
                "https://shop.test",
                Some("https://shop.test/checkout"),
                "form",
                "enter\u{0}textbox\u{0}Coupon\u{0}1/1\u{0}",
            )
            .is_ok());
        second.after_write(other, "failed");
        // Reconciled (its outcome established), it may be sent again.
        if let Some(session) = second.session_gate() {
            let key = stable_key(
                LIVE_TASK,
                "https://shop.test",
                "/checkout",
                "form",
                "enter\u{0}textbox\u{0}Search\u{0}1/1\u{0}",
            );
            assert!(session.reconcile_task(&TaskId::new(LIVE_TASK), &key));
        }
        assert!(matches!(
            enter_on(&mut second, "page-2", "n42"),
            Ok(Some(_))
        ));
    }

    #[test]
    fn a_download_link_is_keyed_without_its_query() {
        assert_eq!(
            link_identity("https://files.test/q3.pdf?sig=abc&exp=1"),
            "https://files.test/q3.pdf"
        );
        assert_eq!(
            link_identity("https://files.test/q3.pdf?sig=xyz#page=2"),
            link_identity("https://files.test/q3.pdf")
        );
        assert_eq!(
            link_identity("https://files.test?f=/q3.pdf"),
            "https://files.test/"
        );
        assert_ne!(
            link_identity("https://files.test/q3.pdf"),
            link_identity("https://other.test/q3.pdf")
        );
    }

    #[test]
    fn a_lost_download_with_a_signed_url_is_refused_when_the_signature_changes() {
        let ledger = UncertainLedger::shared();
        let clock = ManualClock::at(0);
        let download = |gate: &mut TakeoverGate<ManualClock>, link: &str| {
            let ticket =
                gate.before_write("page-1", "download", link, ActionClass::Consequential)?;
            gate.rekey(
                ticket.as_ref(),
                "https://files.test",
                Some("https://files.test/reports"),
                "download",
                &format!("{}\u{0}q3.pdf", link_identity(link)),
            )?;
            Ok::<_, ProviderError>(ticket)
        };
        let mut gate = TakeoverGate::on_with_ledger(clock, ledger);
        gate.page_opened("page-1");
        let ticket = download(&mut gate, "https://files.test/q3.pdf?sig=one")
            .ok()
            .flatten();
        assert!(gate.before_dispatch(ticket.as_ref()).is_ok());
        gate.after_write(ticket, "unknown");
        let refused = download(&mut gate, "https://files.test/q3.pdf?sig=two");
        assert!(
            matches!(&refused, Err(e) if e.message.contains("outcome_uncertain")),
            "{refused:?}"
        );
    }

    #[test]
    fn a_lost_download_is_refused_after_a_host_restart() {
        let ledger = UncertainLedger::shared();
        let clock = ManualClock::at(0);
        let download = |gate: &mut TakeoverGate<ManualClock>, page: &str, node: &str| {
            let ticket = gate.before_write(page, "download", node, ActionClass::Consequential)?;
            gate.rekey(
                ticket.as_ref(),
                "https://files.test",
                Some("https://files.test/reports"),
                "download",
                "https://files.test/q3.pdf\u{0}q3.pdf",
            )?;
            Ok::<_, ProviderError>(ticket)
        };
        {
            let mut first = TakeoverGate::on_with_ledger(clock.clone(), ledger.clone());
            first.page_opened("page-1");
            let ticket = download(&mut first, "page-1", "n3").ok().flatten();
            assert!(first.before_dispatch(ticket.as_ref()).is_ok());
            // The page closes before the ticket is settled: the release
            // keeps the sent download as uncertain all the same.
            first.page_closed("page-1");
            first.after_write(ticket, "done");
        }
        let mut second = TakeoverGate::on_with_ledger(clock, ledger);
        second.page_opened("page-2");
        let refused = download(&mut second, "page-2", "n8");
        assert!(
            matches!(&refused, Err(e) if e.message.contains("outcome_uncertain")),
            "{refused:?}"
        );
    }

    #[test]
    fn the_stable_key_ignores_the_query_fragment_and_page() {
        assert_eq!(url_path(Some("https://a.test/x/y?q=1#f")), "/x/y");
        assert_eq!(url_path(Some("https://a.test")), "/");
        assert_eq!(url_path(None), "");
        // The authority ends at '?' or '#', so a slash inside the query or
        // fragment is never taken for the path.
        assert_eq!(url_path(Some("https://a.test?next=/admin")), "/");
        assert_eq!(url_path(Some("https://a.test#/route")), "/");
        assert_eq!(url_path(Some("https://a.test/p?x=/y#/z")), "/p");
        assert_eq!(
            stable_key(LIVE_TASK, "https://a.test", "/x", "form", "m"),
            stable_key(
                LIVE_TASK,
                "https://a.test",
                url_path(Some("https://a.test/x?other")),
                "form",
                "m"
            )
        );
        assert_ne!(
            stable_key(LIVE_TASK, "https://a.test", "/x", "form", "m"),
            stable_key(LIVE_TASK, "https://b.test", "/x", "form", "m")
        );
    }

    /// SG-000135 OB-01: the uncertain-action ledger is shared by every gate
    /// of the process but keyed per task: one broker session's lost Enter
    /// blocks that session (even after its host restarts) and never an
    /// unrelated session doing the same action.
    #[test]
    fn one_sessions_uncertain_action_never_blocks_another_session() {
        let ledger = UncertainLedger::shared();
        let clock = ManualClock::at(0);
        let session = |task: &str, page: &str| {
            let mut gate = TakeoverGate::on_with_ledger(clock.clone(), ledger.clone());
            gate.set_task(task);
            gate.page_opened(page);
            gate
        };
        let (a, b) = (
            "bs-0123456789abcdef-1-0001020304050607",
            "bs-0123456789abcdef-2-0706050403020100",
        );
        let mut first = session(a, "page-a");
        let ticket = enter_on(&mut first, "page-a", "n1").ok().flatten();
        assert!(first.before_dispatch(ticket.as_ref()).is_ok());
        first.after_write(ticket, "unknown");
        assert_ne!(
            stable_key(a, "https://shop.test", "/checkout", "form", "m"),
            stable_key(b, "https://shop.test", "/checkout", "form", "m")
        );
        // The same session, on a new page (a restarted host), is refused...
        let mut again = session(a, "page-a2");
        let refused = enter_on(&mut again, "page-a2", "n9");
        assert!(
            matches!(&refused, Err(e) if e.message.contains("outcome_uncertain")),
            "{refused:?}"
        );
        // ...and an unrelated session doing the same action is not.
        let mut other = session(b, "page-b");
        assert!(matches!(enter_on(&mut other, "page-b", "n1"), Ok(Some(_))));
    }

    /// SG-000135 OB-01: a client's lost consequential action stays
    /// uncertain across that client's sessions; another client is not
    /// blocked by it.
    #[test]
    fn a_client_cannot_repeat_a_lost_action_from_a_new_session() {
        let ledger = UncertainLedger::shared();
        let clock = ManualClock::at(0);
        let session = |client: &str, task: &str, page: &str| {
            let mut gate = TakeoverGate::on_with_ledger(clock.clone(), ledger.clone());
            gate.set_task(task);
            gate.set_client(client);
            gate.page_opened(page);
            gate
        };
        let mut first = session("client-a", "bs-0123456789abcdef-1-0001020304050607", "p1");
        let ticket = enter_on(&mut first, "p1", "n1").ok().flatten();
        assert!(first.before_dispatch(ticket.as_ref()).is_ok());
        first.after_write(ticket, "unknown");
        // The same client, in a fresh session: refused.
        let mut second = session("client-a", "bs-0123456789abcdef-3-0001020304050607", "p2");
        let refused = enter_on(&mut second, "p2", "n5");
        assert!(
            matches!(&refused, Err(e) if e.message.contains("outcome_uncertain")),
            "{refused:?}"
        );
        // Another client doing the same: admitted.
        let mut other = session("client-b", "bs-0123456789abcdef-4-0001020304050607", "p3");
        assert!(matches!(enter_on(&mut other, "p3", "n1"), Ok(Some(_))));
        // Reconciled under the client (never automatically), the client
        // may send it again from a new session.
        assert!(second.reconcile_client(
            "https://shop.test",
            Some("https://shop.test/checkout?step=2#pay"),
            "form",
            "enter\u{0}textbox\u{0}Search\u{0}1/1\u{0}",
        ));
        assert!(!second.reconcile_client_overflow());
        let mut third = session("client-a", "bs-0123456789abcdef-6-0001020304050607", "p5");
        assert!(matches!(enter_on(&mut third, "p5", "n1"), Ok(Some(_))));
        // A poisoned ledger lock still records and refuses (fail closed).
        let poisoned = ledger.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.lock();
            // Unwinds (as a panic would) while the guard is held.
            std::panic::resume_unwind(Box::new("poison the ledger lock"));
        })
        .join();
        assert!(ledger.is_poisoned());
        let mut fourth = session("client-c", "bs-0123456789abcdef-7-0001020304050607", "p6");
        let ticket = enter_on(&mut fourth, "p6", "n1").ok().flatten();
        assert!(fourth.before_dispatch(ticket.as_ref()).is_ok());
        fourth.after_write(ticket, "unknown");
        let mut fifth = session("client-c", "bs-0123456789abcdef-8-0001020304050607", "p7");
        assert!(enter_on(&mut fifth, "p7", "n1").is_err());
        // A done or failed action leaves nothing under the client.
        let ticket = enter_on(&mut other, "p3", "n1").ok().flatten();
        other.after_write(ticket, "failed");
        let mut again = session("client-b", "bs-0123456789abcdef-5-0001020304050607", "p4");
        assert!(matches!(enter_on(&mut again, "p4", "n1"), Ok(Some(_))));
    }

    /// SG-000135 OB-01: a broker session's gate claims its pages for the
    /// session's own task, and still refuses while a person holds the page.
    #[test]
    fn a_session_task_owns_its_pages_and_the_gate_still_refuses() {
        let clock = ManualClock::at(0);
        let mut gate = TakeoverGate::on(clock);
        gate.set_task("bs-0123456789abcdef-1-0001020304050607");
        gate.page_opened("page-s");
        assert!(matches!(gate.before_read("page-s"), Ok(Some(_))));
        human(&mut gate, "page-s");
        assert!(gate.before_read("page-s").is_err());
        assert!(gate
            .before_write("page-s", "click", "n1", ActionClass::Repeatable)
            .is_err());
    }

    /// SG-000135 OB-07: a detected challenge refuses every read and write
    /// with HUMAN_VERIFICATION_REQUIRED; only the detector's report that it
    /// is gone, then three quiet seconds, end the wait, and then the page
    /// must be observed again before a write.
    #[test]
    fn ob07_a_detected_challenge_holds_until_the_detector_clears_it_and_the_quiet_passes() {
        let (clock, mut gate) = on();
        assert!(gate.is_on());
        assert_eq!(gate.awaiting("page-1"), None);
        assert!(gate.challenge_detected("page-1", ChallengeKind::Mfa));
        assert_eq!(gate.awaiting("page-1"), Some(ChallengeKind::Mfa));
        for refused in [
            gate.before_read("page-1").err(),
            gate.before_write("page-1", "click", "n1", ActionClass::Repeatable)
                .err(),
            gate.before_write(
                "page-1",
                "navigate",
                "https://x.test/",
                ActionClass::Repeatable,
            )
            .err(),
        ] {
            assert!(
                matches!(&refused, Some(e) if e.code == FailureCode::HumanVerificationRequired),
                "{refused:?}"
            );
        }
        // Time alone never ends it.
        clock.advance(10 * QUIET_MS);
        assert_eq!(gate.awaiting("page-1"), Some(ChallengeKind::Mfa));
        // The detector reports it gone: still held for the quiet period.
        assert!(gate.challenge_gone("page-1"));
        clock.advance(QUIET_MS - 1);
        assert!(matches!(
            gate.before_read("page-1"),
            Err(e) if e.code == FailureCode::HumanVerificationRequired
        ));
        // A later report that it is gone restarts the quiet from then (the
        // live browser reports it once per disappearance).
        assert!(gate.challenge_gone("page-1"));
        clock.advance(QUIET_MS - 1);
        assert_eq!(gate.awaiting("page-1"), Some(ChallengeKind::Mfa));
        clock.advance(1);
        assert_eq!(gate.awaiting("page-1"), None);
        assert_eq!(gate.page_state("page-1"), Some(State::Reobserve));
        // A write before observing again is stale; after it, admitted.
        let stale = gate.before_write("page-1", "click", "n1", ActionClass::Repeatable);
        assert!(
            matches!(&stale, Err(e) if e.code == FailureCode::TargetStale
                && e.message.contains("reobserve_required")),
            "{stale:?}"
        );
        let read = gate.before_read("page-1").ok().flatten();
        gate.observed(read);
        assert!(matches!(
            gate.before_write("page-1", "click", "n1", ActionClass::Repeatable),
            Ok(Some(_))
        ));
        // Gone with no challenge waiting changes nothing.
        assert!(!gate.challenge_gone("page-1"));
        // Another page of the session is never held by this one's challenge.
        gate.page_opened("page-2");
        assert!(gate.challenge_detected("page-1", ChallengeKind::Captcha));
        assert!(matches!(gate.before_read("page-2"), Ok(Some(_))));
    }

    #[test]
    fn ob07_enable_turns_an_off_gate_on_and_keeps_its_task_and_client() {
        let mut gate = TakeoverGate::from_switch();
        gate.set_task("bs-0123456789abcdef-1-0001020304050607");
        gate.enable();
        assert!(gate.is_on());
        gate.page_opened("page-e");
        assert_eq!(
            gate.gate
                .as_ref()
                .and_then(|inner| inner.owner(&ResourceId::new("page-e")))
                .map(|task| task.as_str().to_owned()),
            Some("bs-0123456789abcdef-1-0001020304050607".to_owned())
        );
        assert!(gate.challenge_detected("page-e", ChallengeKind::SignIn));
        assert!(gate.before_read("page-e").is_err());
        // An off gate reports nothing and refuses nothing.
        let mut off: TakeoverGate<ManualClock> = TakeoverGate::off();
        assert!(!off.challenge_detected("page-e", ChallengeKind::Captcha));
        assert!(!off.challenge_gone("page-e"));
        assert_eq!(off.awaiting("page-e"), None);
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

    /// SG-000135 OB-07 with OB-08: HUMAN_VERIFICATION_REQUIRED stays ahead of
    /// any Full Access lease. The live browser asks the gate (`gate_write`)
    /// before it consults the lease (`authorize`) and again (`gate_confirm`)
    /// before the lease is used (`spend`, the service's Authorize). On a page
    /// awaiting the person, both refuse with HUMAN_VERIFICATION_REQUIRED, and
    /// the lease is never used: the service's Authorize is never asked.
    #[test]
    fn ob07_ob08_a_covered_action_on_a_page_awaiting_verification_is_refused_without_lease_use() {
        use crate::browser_lease::{
            AuthorityView, CoveredAction, FullAccess, LeaseDecision, LeaseMoment, LeaseQuery,
            LeaseSource, SecretMatcher,
        };
        use orcel_contracts::browser_impact::Impact;
        use orcel_policy::browser_lease::{client_ref, BrowserFamily, BrowserLease};
        use orcel_provider_fs::ProviderError;
        use std::cell::{Cell, RefCell};
        use std::rc::Rc;

        const SESSION: &str = "bs-0123456789abcdef-1-0001020304050607";
        const NOW: u64 = 1_800_000_000_000;
        let client = client_ref("mcp-client-a");
        let lease = BrowserLease {
            lease_id: format!("al-{}", "7".repeat(32)),
            client_ref: client.clone(),
            session_id: SESSION.into(),
            windows_user_sid: "S-1-5-21-1-2-3-1001".into(),
            logon_session_id: 42,
            authority_epoch: 5,
            revocations_at_issue: 2,
            origins: vec!["https://fixture.test".into()],
            families: vec![BrowserFamily::Navigate, BrowserFamily::Click],
            issued_at_ms: NOW,
            expires_at_ms: NOW + 60 * 60_000,
            task: None,
            principal_id: client.clone(),
            requester: "pid 7 orcel.exe (via the Orcel authority service)".into(),
        };
        struct Source {
            lease: BrowserLease,
            authorized: Rc<Cell<usize>>,
        }
        impl LeaseSource for Source {
            fn read(&self) -> Result<Option<AuthorityView>, ProviderError> {
                Ok(Some(AuthorityView {
                    epoch: 5,
                    revocations: 2,
                    leases: vec![self.lease.clone()],
                }))
            }
            fn authorize(&self, _action: &CoveredAction) -> Result<(), ProviderError> {
                self.authorized.set(self.authorized.get() + 1);
                Ok(())
            }
            fn end_session(&self, _session_id: &str) {}
        }
        struct NoSecrets;
        impl SecretMatcher for NoSecrets {
            fn matches(&self, _value: &str) -> Result<bool, ()> {
                Ok(false)
            }
        }
        let authorized = Rc::new(Cell::new(0));
        let mut access = FullAccess::new(
            SESSION,
            &client,
            None,
            Box::new(Source {
                lease,
                authorized: Rc::clone(&authorized),
            }),
            Box::new(NoSecrets),
            Some(("S-1-5-21-1-2-3-1001".into(), 42)),
        );
        let decisions = RefCell::new(Vec::new());
        let (_clock, mut gate) = on();
        let moment = |gate: &TakeoverGate<ManualClock>| LeaseMoment {
            approval_epoch: Some(1),
            now_ms: NOW + 1_000,
            interventions: gate.interventions(),
        };
        let query = LeaseQuery {
            family: BrowserFamily::Click,
            also: None,
            effect_origin: "https://fixture.test",
            committed_origin: Some("https://fixture.test"),
            impact: Impact::Routine,
            page_id: "page-1",
        };
        // Before any challenge the lease covers the click (the live order).
        let ticket = gate
            .before_write("page-1", "click", "n1", ActionClass::Repeatable)
            .ok()
            .flatten();
        let used = match access.decide(&query, &moment(&gate)) {
            LeaseDecision::Covered(used) => Some(used),
            other => {
                decisions.borrow_mut().push(format!("{other:?}"));
                None
            }
        };
        assert!(
            used.is_some(),
            "covered before the challenge: {decisions:?}"
        );
        // The detector sees a CAPTCHA while the action is pending: the check
        // right before the lease would be used refuses it.
        if let Some(session) = gate.session_gate() {
            let _ = session.challenge(
                &ResourceId::new("page-1"),
                ChallengeKind::Captcha,
                ChallengeOrigin::Detected,
            );
        }
        let refused = gate.before_dispatch(ticket.as_ref());
        assert!(
            matches!(&refused, Err(e) if e.code == FailureCode::HumanVerificationRequired),
            "{refused:?}"
        );
        // A new covered action on the waiting page is refused before the
        // lease is consulted at all.
        let again = gate.before_write("page-1", "click", "n2", ActionClass::Repeatable);
        assert!(
            matches!(&again, Err(e) if e.code == FailureCode::HumanVerificationRequired),
            "{again:?}"
        );
        assert_eq!(authorized.get(), 0, "the lease was never used");
    }
}
