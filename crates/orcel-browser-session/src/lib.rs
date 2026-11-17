//! Orcel Browser packet B1: the human-intervention state machine for agent
//! browser sessions, as a pure library.
//!
//! When a person uses a page an agent task owns, the agent stops acting on
//! that page at the first human event, waits until the person has been idle
//! for three seconds (every human event restarts the count, and input still
//! in progress or an explicit takeover keeps it from ever ending), observes
//! the page again, treats what the person did as authoritative, and only
//! then plans and acts again. Other pages and other tasks never stop. A
//! sign-in, MFA, passkey or CAPTCHA challenge hands the page to the person
//! ("Needs you") and resumes after they finish; nothing here can solve,
//! skip or pretend to complete one.
//!
//! - [`SessionGate`]: the gate over every owned resource. A caller asks it
//!   before every agent operation ([`SessionGate::check`],
//!   [`SessionGate::begin_read`], [`SessionGate::begin_write`]), again right
//!   before sending a write ([`SessionGate::confirm_dispatch`]), and tells
//!   it what became of the write ([`SessionGate::finish_write`]).
//! - [`ResourceSession`]: one resource's state machine
//!   (`RUNNING → HUMAN_OVERRIDE → QUIET → REOBSERVE → REPLAN → RUNNING`,
//!   plus `AWAIT_HUMAN_VERIFICATION`, `PAUSED` and `CANCELLED`).
//! - [`InjectionLedger`]: tells the agent's own dispatched input (it carries
//!   an Orcel-issued [`AgentMarker`]) from the human's (everything else).
//!   Input events carry their kind only, never their contents.
//! - The idempotency guard: a consequential write (submit, purchase,
//!   publish) whose outcome is uncertain is never admitted again until its
//!   outcome is reconciled. [`UncertainLedger`] keeps those actions per
//!   task, past the page's session and, shared, past a host restart.
//! - [`Clock`]: injectable time ([`SystemClock`], [`ManualClock`]).
//!
//! The gate holds no authority. It can refuse or pause an operation; it
//! cannot approve, grant or widen one. A caller runs its own policy and
//! approval path after the gate let an operation through, never instead.
//!
//! Provenance: the hold rule in `lock_decision` is adapted from BrowserOS's
//! `neo-takeover` crate, and the ownership and challenge-handoff lifecycle
//! follow BrowserOS's claw-server (see each module's header and
//! `docs/orcel/browseros_provenance.json`).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod clock;
mod gate;
mod ids;
mod input;
mod lock_decision;
mod machine;
mod refusal;
mod uncertain;

pub use clock::{Clock, ManualClock, Millis, SystemClock};
pub use gate::{InputVerdict, SessionGate, MAX_RESOURCES};
pub use ids::{ActionKey, ResourceId, TaskId};
pub use input::{
    AgentMarker, InjectionLedger, InputKind, InputPhase, InputSource, ObservedInput,
    MARKER_TAG_BYTES, MARKER_TTL_MS, MAX_OPEN_MARKERS,
};
pub use machine::{
    ActionClass, ChallengeKind, ChallengeOrigin, Effect, ReadTicket, Reads, ResourceSession, State,
    Target, WriteFate, WriteOutcome, WriteTicket, MAX_PENDING_WRITES, MAX_UNCERTAIN_ACTIONS,
    PENDING_TTL_MS, QUIET_MS, UNSENT_TTL_MS,
};
pub use refusal::{ControlError, Reason, Refusal, RefusalClass};
pub use uncertain::{SharedLedger, UncertainLedger, MAX_LEDGER_ACTIONS};
