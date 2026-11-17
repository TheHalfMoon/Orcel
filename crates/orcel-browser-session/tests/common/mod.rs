//! Shared test scene: a gate on a manual clock with one task owning pages.
#![allow(dead_code)]

use orcel_browser_session::{
    ActionClass, ActionKey, InputKind, InputPhase, InputVerdict, ManualClock, ObservedInput,
    Reason, ResourceId, SessionGate, State, TaskId, WriteTicket,
};

pub struct Scene {
    pub clock: ManualClock,
    pub gate: SessionGate<ManualClock>,
}

pub fn page(id: &str) -> ResourceId {
    ResourceId::new(id)
}

pub fn key(id: &str) -> ActionKey {
    ActionKey::new(id)
}

impl Scene {
    /// A gate at t = 0 whose task "task" owns each of `pages`.
    pub fn new(pages: &[&str]) -> Self {
        let clock = ManualClock::at(0);
        let mut gate = SessionGate::new(clock.clone());
        for id in pages {
            assert_eq!(gate.claim(page(id), TaskId::new("task")), Ok(()));
        }
        Self { clock, gate }
    }

    pub fn at(&self, ms: u64) {
        self.clock.set(ms);
    }

    pub fn advance(&self, ms: u64) {
        self.clock.advance(ms);
    }

    pub fn human(&mut self, id: &str, kind: InputKind, phase: InputPhase) -> InputVerdict {
        self.gate.observe_input(&ObservedInput {
            resource: page(id),
            kind,
            phase,
            marker: None,
        })
    }

    pub fn click(&mut self, id: &str) -> InputVerdict {
        self.human(id, InputKind::Pointer, InputPhase::Instant)
    }

    pub fn state(&mut self, id: &str) -> State {
        self.gate.state(&page(id)).unwrap_or(State::Cancelled)
    }

    pub fn epoch(&self, id: &str) -> u64 {
        self.gate.epoch(&page(id)).unwrap_or(u64::MAX)
    }

    /// Begin a repeatable write planned on `basis`; the refusal's reason on
    /// failure.
    pub fn write(&mut self, id: &str, action: &str, basis: u64) -> Result<WriteTicket, Reason> {
        self.write_as(id, action, ActionClass::Repeatable, basis)
    }

    pub fn write_as(
        &mut self,
        id: &str,
        action: &str,
        class: ActionClass,
        basis: u64,
    ) -> Result<WriteTicket, Reason> {
        match self.gate.begin_write(&page(id), key(action), class, basis) {
            Ok(Some(ticket)) => Ok(ticket),
            Ok(None) => panic!("{id} is not owned"),
            Err(refusal) => Err(refusal.reason),
        }
    }

    /// Observe `id` (begin and complete a read); the epoch to plan on.
    pub fn observe(&mut self, id: &str) -> Result<u64, Reason> {
        let ticket = match self.gate.begin_read(&page(id)) {
            Ok(Some(ticket)) => ticket,
            Ok(None) => panic!("{id} is not owned"),
            Err(refusal) => return Err(refusal.reason),
        };
        self.gate
            .observation_completed(&ticket)
            .ok_or(Reason::TargetStale)
    }

    /// Drive `id` from a human event at the current instant through quiet,
    /// reobserve and replan; returns the new basis.
    pub fn settle_and_reobserve(&mut self, id: &str) -> u64 {
        self.advance(orcel_browser_session::QUIET_MS);
        assert_eq!(self.state(id), State::Reobserve);
        let basis = self.observe(id).unwrap_or(u64::MAX);
        assert_eq!(self.state(id), State::Replan);
        basis
    }
}
