//! Job contract and state machine (spec section 4.7).
//!
//! Jobs reuse the frozen SG-000093 `ExecutionState` vocabulary; no state is
//! added. The transition table here is data: `orcel-jobs` and `orceld`
//! enforce it.

use serde::{Deserialize, Serialize};

use crate::lease::DispatchAuthority;
use crate::{Contract, FailureCode};

/// SG-000093 execution state. Moved from `orcel-policy` with identical serde
/// spellings; `orcel-policy` re-exports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    NotStarted,
    Dispatched,
    Completed,
    Cancelled,
    OutcomeUnknown,
}

impl ExecutionState {
    pub const ALL: [Self; 5] = [
        Self::NotStarted,
        Self::Dispatched,
        Self::Completed,
        Self::Cancelled,
        Self::OutcomeUnknown,
    ];

    /// `completed`, `cancelled` and `outcome_unknown` are terminal.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Cancelled | Self::OutcomeUnknown
        )
    }

    /// The state a job admitted by policy starts in.
    pub const INITIAL: Self = Self::NotStarted;

    /// Whether the job state machine allows `self -> to` (section 4.7).
    /// Staying in the same state is not a transition. `outcome_unknown` is
    /// never retried (C-08): nothing leaves a terminal state.
    pub const fn job_may_transition_to(self, to: Self) -> bool {
        matches!(
            (self, to),
            (Self::NotStarted, Self::Cancelled)
                | (Self::NotStarted, Self::Dispatched)
                | (Self::Dispatched, Self::Completed)
                | (Self::Dispatched, Self::Cancelled)
                | (Self::Dispatched, Self::OutcomeUnknown)
        )
    }

    /// Where an `orceld` restart moves a job in this state: approvals were
    /// bound to the old `orcel_session_id`, so nothing resumes.
    pub const fn after_restart(self) -> Self {
        match self {
            Self::NotStarted => Self::Cancelled,
            Self::Dispatched => Self::OutcomeUnknown,
            terminal => terminal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    WebCrawl,
    /// A map run is one crawl-shaped unit in map mode (section 5.2 row 2).
    WebMap,
    WebBatchScrape,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum JobOutcome {
    Succeeded,
    /// Some units failed.
    Partial,
    Failed {
        code: FailureCode,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct JobProgress {
    pub total: u64,
    pub completed: u64,
    pub failed: u64,
    pub skipped: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    /// `"orcel.job/1"`.
    pub contract: String,
    /// 128-bit random, base32.
    pub job_id: String,
    pub kind: JobKind,
    /// `Principal.principal_id`; only the owner may read or cancel (S7).
    pub owner: String,
    pub orcel_session_id: String,
    /// SHA-256 of `canonical_json(spec)`; the approval binds it.
    pub spec_digest: String,
    pub state: ExecutionState,
    /// Only when `state` is `completed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<JobOutcome>,
    pub authority: DispatchAuthority,
    pub progress: JobProgress,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub expires_at_ms: u64,
}

impl Contract for Job {
    const CONTRACT: &'static str = "orcel.job/1";
}

impl Job {
    /// Whether `outcome` is consistent with `state`: present exactly when
    /// the job is `completed`.
    pub fn outcome_matches_state(&self) -> bool {
        (self.state == ExecutionState::Completed) == self.outcome.is_some()
    }
}
