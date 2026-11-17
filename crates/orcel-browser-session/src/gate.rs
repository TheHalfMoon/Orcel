//! The gate over every resource an agent task owns.
//!
//! Ownership is per resource (a page or a tab): a task claims the pages it
//! opens and releases them when they close, so a reused tab number never
//! inherits an old session. Human input on an agent-owned resource holds
//! the agent off that resource only; every other resource, and every other
//! task, goes on. Input on a resource no task owns concerns no task and is
//! ignored.
//!
//! The ownership rule (claim on open, release on close) follows BrowserOS's
//! claw-server page-ownership effect, `apps/claw-server/src/api/mcp/effects/ownership_claims.rs`
//! (blob 52903f76b17a3bcbbfb4c7e296ad0aeb953d3c46). The challenge handoff
//! keeps the lifecycle of its human-help registry, `apps/claw-server/src/services/help.rs`
//! (blob e7f9b5c6d22ad423dff78158c07fb15d337d770f): one open request per
//! resource, a repeated request reattaches without restarting the wait,
//! only the human's side resolves it, and a hard cancel discards it. Both at
//! BrowserOS commit bd725831 under `packages/browseros-agent/`,
//! AGPL-3.0-or-later upstream, under the owner-asserted authorization in
//! `docs/orcel/grants/2026-11-17-founder-attestation.md`; notice:
//! `docs/orcel/notices/browseros-AGPL-3.0.txt`. Orcel's changes: no async
//! registry, cockpit or wait loop (the gate is synchronous and pure), the
//! request lives in the resource's state machine rather than in a per-session
//! map, and resolution is the human's activity followed by the quiet period
//! or the engine detector clearing the challenge, never the agent.
//!
//! The gate can only refuse. It has no operation that grants, widens or
//! approves anything: the authority to act stays with the caller's own
//! policy and approval path, which runs only after the gate let an
//! operation through.

use crate::lock_decision::{self, Hold};
use crate::machine::ResourceSession;
use crate::{uncertain, Reason, SharedLedger, UncertainLedger};
use crate::{
    ActionClass, ActionKey, AgentMarker, ChallengeKind, ChallengeOrigin, Clock, ControlError,
    Effect, InjectionLedger, InputSource, ObservedInput, ReadTicket, Reads, Refusal, ResourceId,
    State, Target, TaskId, WriteFate, WriteOutcome, WriteTicket,
};
use std::collections::BTreeMap;

/// The most resources one gate tracks. Past it a claim is refused, and a
/// caller that cannot claim a page must refuse to act on it (fail closed).
pub const MAX_RESOURCES: usize = 256;

/// What the gate made of one input event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputVerdict {
    /// The agent's own input (an open marker); no state changes.
    Agent,
    /// A human's input on an agent-owned resource; the agent is held off.
    Human,
    /// Input on a resource no task owns; ignored.
    Unowned,
}

#[derive(Debug)]
struct Owned {
    task: TaskId,
    session: ResourceSession,
}

/// The human-intervention gate.
#[derive(Debug)]
pub struct SessionGate<C: Clock> {
    clock: C,
    reads: Reads,
    ledger: InjectionLedger,
    uncertain: SharedLedger,
    owned: BTreeMap<ResourceId, Owned>,
}

impl<C: Clock> SessionGate<C> {
    /// A gate with no owned resources whose holds also block reads.
    #[must_use]
    pub fn new(clock: C) -> Self {
        Self::with_reads(clock, Reads::Block)
    }

    /// A gate with no owned resources and the given reads policy for human
    /// holds. (Verification, pause and cancel always block reads.)
    #[must_use]
    pub fn with_reads(clock: C, reads: Reads) -> Self {
        Self::with_ledger(clock, reads, UncertainLedger::shared())
    }

    /// A gate whose idempotency guard uses `uncertain`, which may be
    /// shared with other gates (one per host lifetime, say), so an
    /// uncertain action stays refused after its page or host is gone.
    #[must_use]
    pub fn with_ledger(clock: C, reads: Reads, uncertain: SharedLedger) -> Self {
        Self {
            clock,
            reads,
            ledger: InjectionLedger::new(),
            uncertain,
            owned: BTreeMap::new(),
        }
    }

    /// The gate's clock.
    pub fn clock(&self) -> &C {
        &self.clock
    }

    /// `task` owns `resource` from now on. Claiming a resource the task
    /// already owns changes nothing.
    ///
    /// # Errors
    /// `OwnedByAnotherTask` if another task owns it; `Full` once the gate
    /// tracks [`MAX_RESOURCES`].
    pub fn claim(&mut self, resource: ResourceId, task: TaskId) -> Result<(), ControlError> {
        if let Some(owned) = self.owned.get(&resource) {
            return if owned.task == task {
                Ok(())
            } else {
                Err(ControlError::OwnedByAnotherTask)
            };
        }
        if self.owned.len() >= MAX_RESOURCES {
            return Err(ControlError::Full);
        }
        let session = ResourceSession::new(self.clock.now());
        self.owned.insert(resource, Owned { task, session });
        Ok(())
    }

    /// The resource closed or its task let it go: its session ends with it.
    /// What it knew to be uncertain (including consequential writes sent
    /// whose outcome never came back) stays in the task's ledger.
    pub fn release(&mut self, resource: &ResourceId) -> Option<TaskId> {
        let owned = self.owned.remove(resource)?;
        let task = owned.task;
        let mut ledger = uncertain::lock(&self.uncertain);
        for key in owned.session.into_uncertain() {
            let _ = ledger.record(&task, key);
        }
        Some(task)
    }

    /// The shared ledger this gate's idempotency guard uses.
    #[must_use]
    pub fn uncertain_ledger(&self) -> SharedLedger {
        SharedLedger::clone(&self.uncertain)
    }

    /// The task that owns `resource`.
    #[must_use]
    pub fn owner(&self, resource: &ResourceId) -> Option<&TaskId> {
        self.owned.get(resource).map(|owned| &owned.task)
    }

    /// `resource`'s state as of now.
    pub fn state(&mut self, resource: &ResourceId) -> Option<State> {
        let now = self.clock.now();
        self.owned.get_mut(resource).map(|owned| {
            owned.session.advance(now);
            owned.session.state()
        })
    }

    /// `resource`'s current intervention epoch.
    #[must_use]
    pub fn epoch(&self, resource: &ResourceId) -> Option<u64> {
        self.owned.get(resource).map(|owned| owned.session.epoch())
    }

    /// The resources whose sessions wait for the human ("Needs you").
    pub fn needs_you(&mut self) -> Vec<ResourceId> {
        self.tick();
        self.owned
            .iter()
            .filter(|(_, owned)| owned.session.needs_you())
            .map(|(resource, _)| resource.clone())
            .collect()
    }

    /// Bring every session up to now.
    pub fn tick(&mut self) {
        let now = self.clock.now();
        for owned in self.owned.values_mut() {
            owned.session.advance(now);
        }
    }

    /// Issue a marker for one agent action on `resource`; the engine adapter
    /// attaches it to the input that action dispatches.
    pub fn issue_marker(&mut self, resource: &ResourceId) -> AgentMarker {
        let now = self.clock.now();
        self.ledger.issue(resource, now)
    }

    /// The action finished: its marker no longer vouches for input.
    pub fn retire_marker(&mut self, marker: &AgentMarker) {
        self.ledger.retire(marker);
    }

    /// One input event the engine adapter saw.
    pub fn observe_input(&mut self, event: &ObservedInput) -> InputVerdict {
        let now = self.clock.now();
        if self.ledger.classify(event, now) == InputSource::Agent {
            return InputVerdict::Agent;
        }
        match self.owned.get_mut(&event.resource) {
            Some(owned) => {
                owned.session.human_input(event.phase, now);
                InputVerdict::Human
            }
            None => InputVerdict::Unowned,
        }
    }

    /// Whether an agent operation on `target` with `effect` may proceed.
    ///
    /// # Errors
    /// The refusal of the hold that covers it (the first, if several do).
    pub fn check(&mut self, target: &Target, effect: Effect) -> Result<(), Refusal> {
        self.tick();
        let reads = self.reads;
        let holds = self.owned.iter().filter_map(|(resource, owned)| {
            owned.session.hold(reads).map(|(reads, reason)| Hold {
                resource,
                reads,
                since: owned.session.since(),
                reason,
            })
        });
        lock_decision::decide(holds, target, effect)
    }

    fn refusal(resource: &ResourceId, reason: crate::Reason) -> Refusal {
        Refusal {
            resource: resource.clone(),
            reason,
        }
    }

    /// Begin a read of `resource`. `None` for a resource no task owns (the
    /// gate has nothing to say about it).
    ///
    /// # Errors
    /// The resource's refusal of a read.
    pub fn begin_read(&mut self, resource: &ResourceId) -> Result<Option<ReadTicket>, Refusal> {
        let now = self.clock.now();
        let reads = self.reads;
        match self.owned.get_mut(resource) {
            Some(owned) => owned
                .session
                .begin_read(resource, reads, now)
                .map(Some)
                .map_err(|reason| Self::refusal(resource, reason)),
            None => Ok(None),
        }
    }

    /// The read under `ticket` produced a fresh observation. Returns the
    /// epoch writes may be planned on, or `None` if it is already stale.
    pub fn observation_completed(&mut self, ticket: &ReadTicket) -> Option<u64> {
        let now = self.clock.now();
        self.owned
            .get_mut(&ticket.resource)
            .and_then(|owned| owned.session.observation_completed(ticket, now))
    }

    /// Begin a write on `resource` planned on `basis`. `None` for a resource
    /// no task owns.
    ///
    /// # Errors
    /// The resource's refusal of the write.
    pub fn begin_write(
        &mut self,
        resource: &ResourceId,
        key: ActionKey,
        class: ActionClass,
        basis: u64,
    ) -> Result<Option<WriteTicket>, Refusal> {
        let now = self.clock.now();
        let Some(owned) = self.owned.get_mut(resource) else {
            return Ok(None);
        };
        {
            let ledger = uncertain::lock(&self.uncertain);
            if ledger.refuses(&owned.task, &key, class == ActionClass::Consequential) {
                return Err(Self::refusal(resource, Reason::OutcomeUncertain));
            }
        }
        owned
            .session
            .begin_write(resource, key, class, basis, now)
            .map(Some)
            .map_err(|reason| Self::refusal(resource, reason))
    }

    /// Give a pending write the key of its stable action material, once
    /// the caller knows it (after binding the target, before sending). The
    /// idempotency guard applies to that key from then on.
    ///
    /// # Errors
    /// `OutcomeUncertain` for a key whose earlier dispatch is uncertain (in
    /// the task's ledger or the session), or a consequential action with it
    /// already pending; `TargetStale` for a ticket no longer pending. A
    /// refused ticket is invalidated.
    pub fn rekey(&mut self, ticket: &WriteTicket, key: ActionKey) -> Result<(), Refusal> {
        let now = self.clock.now();
        let Some(owned) = self.owned.get_mut(&ticket.resource) else {
            return Err(Self::refusal(&ticket.resource, Reason::TargetStale));
        };
        if uncertain::lock(&self.uncertain).contains(&owned.task, &key) {
            let _ = owned.session.invalidate(ticket);
            return Err(Self::refusal(&ticket.resource, Reason::OutcomeUncertain));
        }
        owned
            .session
            .rekey(ticket, key, now)
            .map_err(|reason| Self::refusal(&ticket.resource, reason))
    }

    /// Check `ticket` again right before it is sent.
    ///
    /// # Errors
    /// The resource's refusal, or `TargetStale` once the ticket is invalid
    /// (its resource released included).
    pub fn confirm_dispatch(&mut self, ticket: &WriteTicket) -> Result<(), Refusal> {
        let now = self.clock.now();
        match self.owned.get_mut(&ticket.resource) {
            Some(owned) => owned
                .session
                .confirm_dispatch(ticket, now)
                .map_err(|reason| Self::refusal(&ticket.resource, reason)),
            None => Err(Self::refusal(&ticket.resource, crate::Reason::TargetStale)),
        }
    }

    /// The write under `ticket` finished with `outcome`.
    pub fn finish_write(&mut self, ticket: &WriteTicket, outcome: WriteOutcome) -> WriteFate {
        let now = self.clock.now();
        match self.owned.get_mut(&ticket.resource) {
            Some(owned) => {
                owned.session.advance(now);
                let (fate, recorded) = owned.session.finish_write_keyed(ticket, outcome);
                if let Some(key) = recorded {
                    let _ = uncertain::lock(&self.uncertain).record(&owned.task, key);
                }
                fate
            }
            None => WriteFate::NotPending,
        }
    }

    /// The outcome of `key`'s uncertain dispatch on `resource` was
    /// established; it may be sent again.
    pub fn reconcile(&mut self, resource: &ResourceId, key: &ActionKey) -> bool {
        let Some(owned) = self.owned.get_mut(resource) else {
            return false;
        };
        let in_session = owned.session.reconcile(key);
        let in_ledger = uncertain::lock(&self.uncertain).reconcile(&owned.task, key);
        in_session || in_ledger
    }

    /// The outcome of `key`'s uncertain dispatch for `task` was
    /// established, whether or not the task still owns a resource.
    pub fn reconcile_task(&mut self, task: &TaskId, key: &ActionKey) -> bool {
        let mut any = false;
        for owned in self.owned.values_mut().filter(|owned| owned.task == *task) {
            any |= owned.session.reconcile(key);
        }
        uncertain::lock(&self.uncertain).reconcile(task, key) || any
    }

    /// Every uncertain outcome of `task` was established, including any the
    /// full ledger could not record: its consequential writes may go again.
    pub fn reconcile_overflow(&mut self, task: &TaskId) -> bool {
        uncertain::lock(&self.uncertain).reconcile_overflow(task)
    }

    fn control(
        &mut self,
        resource: &ResourceId,
        apply: impl FnOnce(&mut ResourceSession, crate::Millis) -> Result<(), ControlError>,
    ) -> Result<(), ControlError> {
        let now = self.clock.now();
        let owned = self
            .owned
            .get_mut(resource)
            .ok_or(ControlError::UnknownResource)?;
        owned.session.advance(now);
        apply(&mut owned.session, now)
    }

    /// The human took `resource` explicitly ("Take Over").
    ///
    /// # Errors
    /// `UnknownResource` or `Cancelled`.
    pub fn take_over(&mut self, resource: &ResourceId) -> Result<(), ControlError> {
        self.control(resource, ResourceSession::take_over)
    }

    /// The human gave `resource` back ("Return to Shadow").
    ///
    /// # Errors
    /// `UnknownResource` or `Cancelled`.
    pub fn return_control(&mut self, resource: &ResourceId) -> Result<(), ControlError> {
        self.control(resource, ResourceSession::return_control)
    }

    /// Pause the task on `resource`.
    ///
    /// # Errors
    /// `UnknownResource` or `Cancelled`.
    pub fn pause(&mut self, resource: &ResourceId) -> Result<(), ControlError> {
        self.control(resource, ResourceSession::pause)
    }

    /// Resume the task on `resource`.
    ///
    /// # Errors
    /// `UnknownResource`, `Cancelled` or `NotPaused`.
    pub fn resume(&mut self, resource: &ResourceId) -> Result<(), ControlError> {
        self.control(resource, ResourceSession::resume)
    }

    /// Cancel the task on `resource`.
    ///
    /// # Errors
    /// `UnknownResource`.
    pub fn cancel(&mut self, resource: &ResourceId) -> Result<(), ControlError> {
        self.control(resource, |session, _| {
            session.cancel();
            Ok(())
        })
    }

    /// A challenge on `resource` needs the human.
    ///
    /// # Errors
    /// `UnknownResource` or `Cancelled`.
    pub fn challenge(
        &mut self,
        resource: &ResourceId,
        kind: ChallengeKind,
        origin: ChallengeOrigin,
    ) -> Result<(), ControlError> {
        self.control(resource, |session, now| {
            session.challenge(kind, origin, now)
        })
    }

    /// The engine's detector no longer sees `resource`'s challenge.
    ///
    /// # Errors
    /// `UnknownResource`.
    pub fn challenge_cleared(&mut self, resource: &ResourceId) -> Result<bool, ControlError> {
        let now = self.clock.now();
        let owned = self
            .owned
            .get_mut(resource)
            .ok_or(ControlError::UnknownResource)?;
        owned.session.advance(now);
        Ok(owned.session.challenge_cleared(now))
    }
}
