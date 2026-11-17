//! One resource's human-intervention state machine.
//!
//! ```text
//!   RUNNING ── human input ──▶ HUMAN_OVERRIDE ── input stops ──▶ QUIET
//!      ▲                            ▲    any human input (timer reset) │
//!      │                            └──────────────────────────────────┤
//!      │                                       3000 ms with no input   ▼
//!   REPLAN ◀── fresh observation ── REOBSERVE ◀────────────────────────┘
//!      │ first write planned on that observation
//!      ▼
//!   RUNNING
//!
//!   any live state ── challenge detected or requested ──▶ AWAIT_HUMAN_VERIFICATION
//!      ── the detector reports it cleared, then 3000 ms quiet ──▶ REOBSERVE
//!   any live state ── pause ──▶ PAUSED ── resume ──▶ QUIET / REOBSERVE (or back to AWAIT)
//!   any state ── cancel ──▶ CANCELLED (terminal)
//! ```
//!
//! Every entry into a human-held state from an agent-held one starts a new
//! intervention and bumps the resource's epoch. A write is planned on an
//! epoch (the one its observation returned) and holds a ticket of the epoch
//! it was begun in; any later intervention makes both stale, so pending
//! agent writes and stale targets are invalid from the human's first event
//! on, and stay invalid after the quiet period. The human's edits are
//! authoritative: nothing the agent planned before them is sent.
//!
//! Time comes from the caller as [`Millis`]; nothing here sleeps. The quiet
//! period is measured from the latest human event every time the machine is
//! asked, so every event resets it, and an input still in progress
//! (between `Begin` and `End`) or an explicit takeover keeps it from ever
//! ending: the agent never interrupts ongoing input and never takes a
//! resource back from a human who is still using it.
//!
//! Two rules are ported from BrowserOS (browseros-ai/BrowserOS) at commit
//! bd725831, the neo-takeover lock table
//! `packages/browseros-agent/crates/neo-sdk/neo-takeover/src/locks.rs` (blob
//! b49b759fcc53f44d81ed9e04fadc665fb34a380e): a hold refuses from the moment
//! it is taken, and the dispatcher checks again before each send (here
//! [`ResourceSession::confirm_dispatch`]); instants, not timers, end a hold,
//! so a late tick never extends one. AGPL-3.0-or-later upstream; copied and
//! renamed under the owner-asserted authorization recorded in
//! `docs/orcel/grants/2026-11-17-founder-attestation.md`; notice:
//! `docs/orcel/notices/browseros-AGPL-3.0.txt`. Orcel's changes: the donor's
//! TTL lock taken by a host becomes this state machine driven by human
//! input; there is no async settle loop, trace flush or broadcast, and no
//! TTL cap (a person who keeps a page keeps it).

use crate::lock_decision::refuses;
use crate::{ActionKey, ControlError, InputPhase, Millis, Reason};
use std::collections::{BTreeMap, BTreeSet};

/// How long the human must be idle on a resource before the agent may look
/// at it again.
pub const QUIET_MS: u64 = 3_000;

/// How long a sent write may wait for its outcome, counted from the moment
/// it was confirmed for sending. Past it, a consequential write is treated
/// as uncertain (never admitted again until reconciled).
pub const PENDING_TTL_MS: u64 = 120_000;

/// How long a write may stay pending before it is sent (a person may take
/// a while over its approval prompt). Past it, the unsent ticket is dropped.
pub const UNSENT_TTL_MS: u64 = 30 * 60 * 1_000;

/// The most writes pending on one resource. Past it new writes are
/// refused (fail closed).
pub const MAX_PENDING_WRITES: usize = 64;

/// The most uncertain actions one resource remembers. Once full, every
/// consequential write on it is refused (fail closed).
pub const MAX_UNCERTAIN_ACTIONS: usize = 1_024;

/// Whether an agent operation only reads the resource or may change it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Observation, waiting, verification.
    Read,
    /// Navigation, clicks, form actions, downloads.
    Write,
}

/// Whether a human-held resource also refuses the agent's reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Reads {
    /// Every operation on the resource is refused. The default: a read can
    /// land on the field the human is typing a password into.
    #[default]
    Block,
    /// Only writes are refused.
    Allow,
}

/// What an agent operation targets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// The operation touches no page. Never refused by a hold.
    NoPage,
    /// The operation targets this resource.
    Resource(crate::ResourceId),
    /// The operation has a page the caller could not map to a resource. It
    /// is refused while any hold would refuse it (fail closed).
    UnmappedPage,
}

/// The kind of verification a challenge asks the human for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeKind {
    /// A sign-in form the agent may not complete.
    SignIn,
    /// A one-time code or other second factor.
    Mfa,
    /// A passkey, WebAuthn or OS presence prompt.
    Passkey,
    /// A CAPTCHA. Never solved or bypassed by the agent.
    Captcha,
    /// Anything else only a person can do.
    Other,
}

/// Who raised a challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeOrigin {
    /// The engine's challenge detector saw it on the page.
    Detected,
    /// The agent asked for a person.
    Requested,
}

/// Whether repeating an action could do something twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionClass {
    /// Doing it again is harmless (a fill, a navigation, a link).
    Repeatable,
    /// Doing it again could submit, purchase, publish or send twice.
    Consequential,
}

/// What became of a dispatched write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteOutcome {
    /// It happened.
    Done,
    /// It was refused or failed before it could change anything.
    Failed,
    /// It may or may not have happened.
    Uncertain,
}

/// What the gate made of a finished write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteFate {
    /// Recorded against the current epoch.
    Recorded,
    /// A human intervened while it was in flight: the agent must observe
    /// again before it acts on anything it planned.
    Superseded,
    /// The ticket was not pending (never begun, or already invalidated).
    NotPending,
}

/// A resource's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// The agent may act.
    Running,
    /// A human is using the resource now.
    HumanOverride,
    /// The human stopped; the quiet period is counting.
    Quiet,
    /// The quiet period ended; the agent must observe again.
    Reobserve,
    /// Observed again; the agent's next write must be planned on that
    /// observation.
    Replan,
    /// A challenge waits for the human ("Needs you").
    AwaitHumanVerification(ChallengeKind),
    /// The task is paused.
    Paused,
    /// The task was cancelled. Terminal.
    Cancelled,
}

impl State {
    /// The state's name as the design writes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Running => "RUNNING",
            Self::HumanOverride => "HUMAN_OVERRIDE",
            Self::Quiet => "QUIET",
            Self::Reobserve => "REOBSERVE",
            Self::Replan => "REPLAN",
            Self::AwaitHumanVerification(_) => "AWAIT_HUMAN_VERIFICATION",
            Self::Paused => "PAUSED",
            Self::Cancelled => "CANCELLED",
        }
    }

    /// States in which the agent held the resource: a human event here
    /// starts a new intervention.
    const fn agent_held(self) -> bool {
        matches!(self, Self::Running | Self::Reobserve | Self::Replan)
    }
}

/// A read the agent began on a resource, so its completion can be matched
/// to the epoch it observed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadTicket {
    pub(crate) resource: crate::ResourceId,
    pub(crate) epoch: u64,
}

impl ReadTicket {
    /// The resource it reads.
    #[must_use]
    pub fn resource(&self) -> &crate::ResourceId {
        &self.resource
    }

    /// The epoch it was begun in.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// A write the gate admitted and has not seen finish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteTicket {
    pub(crate) resource: crate::ResourceId,
    pub(crate) id: u64,
    pub(crate) epoch: u64,
}

impl WriteTicket {
    /// The resource it writes.
    #[must_use]
    pub fn resource(&self) -> &crate::ResourceId {
        &self.resource
    }

    /// The epoch it was begun in.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

#[derive(Clone, Debug)]
struct Pending {
    epoch: u64,
    key: ActionKey,
    class: ActionClass,
    begun_at: Millis,
    dispatched: bool,
}

/// One resource's session.
#[derive(Clone, Debug)]
pub struct ResourceSession {
    state: State,
    /// When the current hold began (the instant the state left the agent).
    since: Millis,
    last_human_at: Option<Millis>,
    inputs_in_progress: u32,
    explicit_hold: bool,
    epoch: u64,
    observed_epoch: u64,
    paused_from: Option<State>,
    challenge_origin: Option<ChallengeOrigin>,
    challenge_cleared_at: Option<Millis>,
    next_write: u64,
    pending: BTreeMap<u64, Pending>,
    uncertain: BTreeSet<ActionKey>,
}

impl ResourceSession {
    /// A session that starts `Running` at `now`, epoch 0.
    #[must_use]
    pub fn new(now: Millis) -> Self {
        Self {
            state: State::Running,
            since: now,
            last_human_at: None,
            inputs_in_progress: 0,
            explicit_hold: false,
            epoch: 0,
            observed_epoch: 0,
            paused_from: None,
            challenge_origin: None,
            challenge_cleared_at: None,
            next_write: 1,
            pending: BTreeMap::new(),
            uncertain: BTreeSet::new(),
        }
    }

    /// The state as of the last time the session was advanced.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// The current intervention epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// When the current hold began.
    #[must_use]
    pub fn since(&self) -> Millis {
        self.since
    }

    /// Who raised the challenge the session waits on, if it waits on one.
    #[must_use]
    pub fn challenge_origin(&self) -> Option<ChallengeOrigin> {
        match self.state {
            State::AwaitHumanVerification(_) => self.challenge_origin,
            _ => None,
        }
    }

    /// Whether the session waits for the human ("Needs you").
    #[must_use]
    pub fn needs_you(&self) -> bool {
        matches!(self.state, State::AwaitHumanVerification(_))
            || (self.state == State::Paused
                && matches!(self.paused_from, Some(State::AwaitHumanVerification(_))))
    }

    /// How many writes are pending.
    #[must_use]
    pub fn pending_writes(&self) -> usize {
        self.pending.len()
    }

    /// Whether `key`'s last dispatch has an unknown outcome.
    #[must_use]
    pub fn is_uncertain(&self, key: &ActionKey) -> bool {
        self.uncertain.contains(key)
    }

    fn quiet_elapsed(&self, reference: Option<Millis>, now: Millis) -> bool {
        !self.explicit_hold
            && self.inputs_in_progress == 0
            && reference.is_none_or(|at| now.since(at) >= QUIET_MS)
    }

    fn start_intervention(&mut self, now: Millis) {
        if self.state.agent_held() {
            self.epoch = self.epoch.saturating_add(1);
            self.since = now;
        }
    }

    fn enter_reobserve(&mut self) {
        self.state = State::Reobserve;
        self.challenge_origin = None;
        self.challenge_cleared_at = None;
    }

    fn remember_uncertain(&mut self, key: ActionKey) {
        if self.uncertain.len() < MAX_UNCERTAIN_ACTIONS {
            self.uncertain.insert(key);
        }
    }

    /// Drop expired tickets: an unsent one past [`UNSENT_TTL_MS`] from when
    /// it was begun is gone; a sent one past [`PENDING_TTL_MS`] from when it
    /// was confirmed for sending is dropped, and a consequential one becomes
    /// uncertain.
    fn expire_pending(&mut self, now: Millis) {
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, pending)| {
                let ttl = if pending.dispatched {
                    PENDING_TTL_MS
                } else {
                    UNSENT_TTL_MS
                };
                now.since(pending.begun_at) >= ttl
            })
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            if let Some(pending) = self.pending.remove(&id) {
                if pending.dispatched && pending.class == ActionClass::Consequential {
                    self.remember_uncertain(pending.key);
                }
            }
        }
    }

    /// Bring the session up to `now`: the transitions time alone makes.
    pub fn advance(&mut self, now: Millis) {
        self.expire_pending(now);
        loop {
            match self.state {
                State::HumanOverride
                    if !self.explicit_hold
                        && self.inputs_in_progress == 0
                        && self.last_human_at.is_none_or(|at| now > at) =>
                {
                    self.state = State::Quiet;
                }
                State::Quiet if self.explicit_hold || self.inputs_in_progress > 0 => {
                    self.state = State::HumanOverride;
                    return;
                }
                State::Quiet if self.quiet_elapsed(self.last_human_at, now) => {
                    self.enter_reobserve();
                    return;
                }
                // Only the detector's report that the challenge is gone ends
                // the wait; the human's events only push the resume back.
                State::AwaitHumanVerification(_)
                    if self.challenge_cleared_at.is_some()
                        && self.quiet_elapsed(
                            self.last_human_at.max(self.challenge_cleared_at),
                            now,
                        ) =>
                {
                    self.enter_reobserve();
                    return;
                }
                _ => return,
            }
        }
    }

    /// What the session refuses, as it stands: the reads policy and the
    /// reason, or `None` while the agent may act.
    #[must_use]
    pub fn hold(&self, reads: Reads) -> Option<(Reads, Reason)> {
        match self.state {
            State::Running => None,
            State::HumanOverride => Some((reads, Reason::HumanOverride)),
            State::Quiet => Some((reads, Reason::Quiet)),
            State::Reobserve => Some((Reads::Allow, Reason::ReobserveRequired)),
            State::Replan => Some((Reads::Allow, Reason::ReplanRequired)),
            State::AwaitHumanVerification(_) => {
                Some((Reads::Block, Reason::AwaitingHumanVerification))
            }
            State::Paused => Some((Reads::Block, Reason::Paused)),
            State::Cancelled => Some((Reads::Block, Reason::Cancelled)),
        }
    }

    /// One human input event on the resource, at `now`.
    pub fn human_input(&mut self, phase: InputPhase, now: Millis) {
        if self.state == State::Cancelled {
            return;
        }
        self.last_human_at = Some(self.last_human_at.map_or(now, |at| at.max(now)));
        match phase {
            InputPhase::Instant => {}
            InputPhase::Begin => {
                self.inputs_in_progress = self.inputs_in_progress.saturating_add(1);
            }
            InputPhase::End => {
                self.inputs_in_progress = self.inputs_in_progress.saturating_sub(1);
            }
        }
        match self.state {
            State::Running | State::Reobserve | State::Replan => {
                self.start_intervention(now);
                self.state = State::HumanOverride;
            }
            State::Quiet => self.state = State::HumanOverride,
            State::AwaitHumanVerification(_)
            | State::HumanOverride
            | State::Paused
            | State::Cancelled => {}
        }
    }

    /// Whether an operation with `effect` may proceed now.
    ///
    /// # Errors
    /// The reason the session refuses it.
    pub fn check(&mut self, effect: Effect, reads: Reads, now: Millis) -> Result<(), Reason> {
        self.advance(now);
        match self.hold(reads) {
            Some((reads, reason)) if refuses(reads, effect) => Err(reason),
            _ => Ok(()),
        }
    }

    /// Begin a read; its ticket matches the completion to this epoch.
    ///
    /// # Errors
    /// The reason the session refuses a read.
    pub fn begin_read(
        &mut self,
        resource: &crate::ResourceId,
        reads: Reads,
        now: Millis,
    ) -> Result<ReadTicket, Reason> {
        self.check(Effect::Read, reads, now)?;
        Ok(ReadTicket {
            resource: resource.clone(),
            epoch: self.epoch,
        })
    }

    /// A read begun under `ticket` completed with a fresh observation.
    /// Returns the epoch a write may be planned on, or `None` when a human
    /// intervened since the read began (its observation is already stale).
    pub fn observation_completed(&mut self, ticket: &ReadTicket, now: Millis) -> Option<u64> {
        self.advance(now);
        if ticket.epoch != self.epoch {
            return None;
        }
        match self.state {
            State::Reobserve => {
                self.observed_epoch = self.epoch;
                self.state = State::Replan;
                Some(self.epoch)
            }
            State::Running | State::Replan => {
                self.observed_epoch = self.epoch;
                Some(self.epoch)
            }
            _ => None,
        }
    }

    /// Begin a write planned on `basis` (the epoch its observation
    /// returned).
    ///
    /// # Errors
    /// The state's reason; `TargetStale` for a basis older (or newer) than
    /// the current epoch; `OutcomeUncertain` for an action whose earlier
    /// dispatch has an unknown outcome, or a consequential action already in
    /// flight.
    pub fn begin_write(
        &mut self,
        resource: &crate::ResourceId,
        key: ActionKey,
        class: ActionClass,
        basis: u64,
        now: Millis,
    ) -> Result<WriteTicket, Reason> {
        self.advance(now);
        match self.state {
            State::Running => {}
            State::Replan if basis == self.epoch && self.observed_epoch == self.epoch => {}
            State::Replan => return Err(Reason::TargetStale),
            _ => {
                return Err(self
                    .hold(Reads::Block)
                    .map_or(Reason::TargetStale, |(_, reason)| reason))
            }
        }
        if basis != self.epoch {
            return Err(Reason::TargetStale);
        }
        if self.uncertain.contains(&key) {
            return Err(Reason::OutcomeUncertain);
        }
        if class == ActionClass::Consequential
            && (self.uncertain.len() >= MAX_UNCERTAIN_ACTIONS
                || self.pending.values().any(|pending| pending.key == key))
        {
            return Err(Reason::OutcomeUncertain);
        }
        if self.pending.len() >= MAX_PENDING_WRITES {
            return Err(Reason::TargetStale);
        }
        // The first write planned on the fresh observation ends the replan.
        self.state = State::Running;
        let id = self.next_write;
        self.next_write = self.next_write.saturating_add(1);
        self.pending.insert(
            id,
            Pending {
                epoch: self.epoch,
                key,
                class,
                begun_at: now,
                dispatched: false,
            },
        );
        Ok(WriteTicket {
            resource: resource.clone(),
            id,
            epoch: self.epoch,
        })
    }

    /// Give a pending ticket the key of its stable action material, once
    /// the caller knows it (after the target was bound). The idempotency
    /// guard then applies to that key. A refused ticket is invalidated.
    ///
    /// # Errors
    /// `TargetStale` for a ticket that is no longer pending or current;
    /// `OutcomeUncertain` for a key whose earlier dispatch is uncertain, or
    /// a consequential action with that key already pending.
    pub fn rekey(
        &mut self,
        ticket: &WriteTicket,
        key: ActionKey,
        now: Millis,
    ) -> Result<(), Reason> {
        self.advance(now);
        let Some(pending) = self.pending.get(&ticket.id) else {
            return Err(Reason::TargetStale);
        };
        let class = pending.class;
        let refusal = if pending.epoch != self.epoch || pending.dispatched {
            Some(Reason::TargetStale)
        } else if self.uncertain.contains(&key)
            || (class == ActionClass::Consequential
                && self
                    .pending
                    .iter()
                    .any(|(id, other)| *id != ticket.id && other.key == key))
        {
            Some(Reason::OutcomeUncertain)
        } else {
            None
        };
        if let Some(reason) = refusal {
            self.pending.remove(&ticket.id);
            return Err(reason);
        }
        if let Some(pending) = self.pending.get_mut(&ticket.id) {
            pending.key = key;
        }
        Ok(())
    }

    /// Drop a pending ticket the caller will not send.
    pub fn invalidate(&mut self, ticket: &WriteTicket) -> bool {
        self.pending.remove(&ticket.id).is_some()
    }

    /// Check again, right before sending, that the write may still go: the
    /// human may have taken over while the agent waited (an approval
    /// prompt, a slow plan). A refused ticket is invalidated.
    ///
    /// # Errors
    /// The state's reason, or `TargetStale` for an invalidated ticket.
    pub fn confirm_dispatch(&mut self, ticket: &WriteTicket, now: Millis) -> Result<(), Reason> {
        self.advance(now);
        let Some(pending) = self.pending.get(&ticket.id) else {
            return Err(Reason::TargetStale);
        };
        let refusal = if self.state != State::Running {
            Some(
                self.hold(Reads::Block)
                    .map_or(Reason::TargetStale, |(_, reason)| reason),
            )
        } else if pending.epoch != self.epoch {
            Some(Reason::TargetStale)
        } else {
            None
        };
        match refusal {
            Some(reason) => {
                self.pending.remove(&ticket.id);
                Err(reason)
            }
            None => {
                if let Some(pending) = self.pending.get_mut(&ticket.id) {
                    // The outcome timer starts now, not when the write was
                    // begun: a slow approval does not make it stale.
                    pending.dispatched = true;
                    pending.begun_at = now;
                }
                Ok(())
            }
        }
    }

    /// A write finished with `outcome`. A consequential write with an
    /// uncertain outcome is never admitted again until reconciled.
    pub fn finish_write(&mut self, ticket: &WriteTicket, outcome: WriteOutcome) -> WriteFate {
        self.finish_write_keyed(ticket, outcome).0
    }

    /// As [`Self::finish_write`], also returning the key it recorded as
    /// uncertain, if it recorded one.
    pub fn finish_write_keyed(
        &mut self,
        ticket: &WriteTicket,
        outcome: WriteOutcome,
    ) -> (WriteFate, Option<ActionKey>) {
        let Some(pending) = self.pending.remove(&ticket.id) else {
            return (WriteFate::NotPending, None);
        };
        let fate = if pending.epoch == self.epoch {
            WriteFate::Recorded
        } else {
            WriteFate::Superseded
        };
        if outcome == WriteOutcome::Uncertain && pending.class == ActionClass::Consequential {
            self.remember_uncertain(pending.key.clone());
            return (fate, Some(pending.key));
        }
        (fate, None)
    }

    /// What the session knows to be uncertain when it ends: the keys it
    /// recorded, and every consequential write sent whose outcome never
    /// came back. A caller that outlives the session keeps them.
    #[must_use]
    pub fn into_uncertain(self) -> Vec<ActionKey> {
        let mut keys: Vec<ActionKey> = self.uncertain.into_iter().collect();
        keys.extend(
            self.pending
                .into_values()
                .filter(|pending| pending.dispatched && pending.class == ActionClass::Consequential)
                .map(|pending| pending.key),
        );
        keys
    }

    /// The outcome of `key`'s uncertain dispatch was established (by a
    /// verifier read or by the human). Only then may it be sent again.
    pub fn reconcile(&mut self, key: &ActionKey) -> bool {
        self.uncertain.remove(key)
    }

    /// The human took the resource explicitly ("Take Over"). The agent
    /// stays off it until the human gives it back.
    ///
    /// # Errors
    /// `Cancelled` once the task was cancelled.
    pub fn take_over(&mut self, now: Millis) -> Result<(), ControlError> {
        if self.state == State::Cancelled {
            return Err(ControlError::Cancelled);
        }
        self.explicit_hold = true;
        self.last_human_at = Some(self.last_human_at.map_or(now, |at| at.max(now)));
        match self.state {
            State::Running | State::Reobserve | State::Replan => {
                self.start_intervention(now);
                self.state = State::HumanOverride;
            }
            // A paused challenge stays a challenge: the person holds the
            // page, and only the detector's report ends the wait.
            State::Paused => {
                self.state = match self.paused_from.take() {
                    Some(State::AwaitHumanVerification(kind)) => {
                        State::AwaitHumanVerification(kind)
                    }
                    _ => State::HumanOverride,
                };
            }
            State::Quiet => self.state = State::HumanOverride,
            State::AwaitHumanVerification(_) | State::HumanOverride | State::Cancelled => {}
        }
        Ok(())
    }

    /// The human gave the resource back ("Return to Shadow"). The quiet
    /// period starts now; input still in progress keeps it from ending.
    ///
    /// # Errors
    /// `Cancelled` once the task was cancelled.
    pub fn return_control(&mut self, now: Millis) -> Result<(), ControlError> {
        if self.state == State::Cancelled {
            return Err(ControlError::Cancelled);
        }
        self.explicit_hold = false;
        self.last_human_at = Some(self.last_human_at.map_or(now, |at| at.max(now)));
        Ok(())
    }

    /// Pause the task on this resource. Idempotent.
    ///
    /// # Errors
    /// `Cancelled` once the task was cancelled.
    pub fn pause(&mut self, now: Millis) -> Result<(), ControlError> {
        match self.state {
            State::Cancelled => Err(ControlError::Cancelled),
            State::Paused => Ok(()),
            state => {
                self.start_intervention(now);
                self.paused_from = Some(state);
                self.state = State::Paused;
                Ok(())
            }
        }
    }

    /// Resume a paused task. A pending challenge is waited on again;
    /// otherwise the agent observes again once the human has been quiet.
    ///
    /// # Errors
    /// `Cancelled` once the task was cancelled; `NotPaused` otherwise.
    pub fn resume(&mut self, now: Millis) -> Result<(), ControlError> {
        match self.state {
            State::Cancelled => return Err(ControlError::Cancelled),
            State::Paused => {}
            _ => return Err(ControlError::NotPaused),
        }
        self.state = match self.paused_from.take() {
            Some(State::AwaitHumanVerification(kind)) => State::AwaitHumanVerification(kind),
            _ if self.explicit_hold || self.inputs_in_progress > 0 => State::HumanOverride,
            _ => State::Quiet,
        };
        self.advance(now);
        Ok(())
    }

    /// Cancel the task. Terminal: every pending write is dropped and every
    /// later operation refused.
    pub fn cancel(&mut self) {
        self.state = State::Cancelled;
        self.paused_from = None;
        self.explicit_hold = false;
        self.pending.clear();
    }

    /// A challenge needs the human. Raising it again while it waits keeps
    /// the request as it is (it does not restart the wait).
    ///
    /// # Errors
    /// `Cancelled` once the task was cancelled.
    pub fn challenge(
        &mut self,
        kind: ChallengeKind,
        origin: ChallengeOrigin,
        now: Millis,
    ) -> Result<(), ControlError> {
        match self.state {
            State::Cancelled => Err(ControlError::Cancelled),
            State::AwaitHumanVerification(_) => Ok(()),
            State::Paused => {
                if !matches!(self.paused_from, Some(State::AwaitHumanVerification(_))) {
                    self.paused_from = Some(State::AwaitHumanVerification(kind));
                    self.challenge_origin = Some(origin);
                    self.challenge_cleared_at = None;
                }
                Ok(())
            }
            _ => {
                self.start_intervention(now);
                self.state = State::AwaitHumanVerification(kind);
                self.challenge_origin = Some(origin);
                self.challenge_cleared_at = None;
                Ok(())
            }
        }
    }

    /// The engine's challenge detector no longer sees the challenge. The
    /// session resumes once the human has been quiet for the quiet period.
    /// Only the detector calls this; the agent cannot clear a challenge,
    /// and the human's own activity never does either.
    pub fn challenge_cleared(&mut self, now: Millis) -> bool {
        if matches!(self.state, State::AwaitHumanVerification(_))
            || (self.state == State::Paused
                && matches!(self.paused_from, Some(State::AwaitHumanVerification(_))))
        {
            self.challenge_cleared_at = Some(now);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResourceId;

    #[test]
    fn an_observation_while_running_refreshes_the_basis_without_changing_state() {
        let resource = ResourceId::new("p");
        let mut session = ResourceSession::new(Millis(0));
        let ticket = session.begin_read(&resource, Reads::Block, Millis(1));
        let basis = ticket
            .ok()
            .and_then(|t| session.observation_completed(&t, Millis(2)));
        assert_eq!(basis, Some(0));
        assert_eq!(session.state(), State::Running);
    }

    #[test]
    fn the_challenge_origin_is_reported_only_while_waiting() {
        let mut session = ResourceSession::new(Millis(0));
        assert_eq!(session.challenge_origin(), None);
        let _ = session.challenge(
            ChallengeKind::Captcha,
            ChallengeOrigin::Requested,
            Millis(0),
        );
        assert_eq!(session.challenge_origin(), Some(ChallengeOrigin::Requested));
        assert!(session.challenge_cleared(Millis(10)));
        session.advance(Millis(10 + QUIET_MS));
        assert_eq!(session.state(), State::Reobserve);
        assert_eq!(session.challenge_origin(), None);
        assert!(!session.challenge_cleared(Millis(20 + QUIET_MS)));
    }

    #[test]
    fn a_write_planned_on_a_future_epoch_is_refused() {
        let resource = ResourceId::new("p");
        let mut session = ResourceSession::new(Millis(0));
        let refused = session.begin_write(
            &resource,
            ActionKey::new("k"),
            ActionClass::Repeatable,
            7,
            Millis(0),
        );
        assert_eq!(refused.err(), Some(Reason::TargetStale));
        assert_eq!(session.pending_writes(), 0);
    }

    #[test]
    fn state_names_follow_the_design() {
        assert_eq!(State::Quiet.name(), "QUIET");
        assert_eq!(
            State::AwaitHumanVerification(ChallengeKind::Mfa).name(),
            "AWAIT_HUMAN_VERIFICATION"
        );
    }
}
