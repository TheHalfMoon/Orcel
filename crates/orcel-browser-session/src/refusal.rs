//! Why the gate refused an agent operation. A refusal is the gate's only
//! output besides "go on": it never grants anything, and nothing was sent
//! when it refuses.

use crate::ResourceId;
use std::fmt;

/// The reason an agent operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// A human is using the resource now.
    HumanOverride,
    /// The human stopped, and the three quiet seconds have not passed.
    Quiet,
    /// The quiet period ended; the agent must observe the resource again
    /// before it writes.
    ReobserveRequired,
    /// The resource was observed again; a write must be planned on that
    /// observation.
    ReplanRequired,
    /// The write was planned on an observation older than the latest human
    /// intervention, or its pending ticket was invalidated by one.
    TargetStale,
    /// A sign-in, MFA, passkey or CAPTCHA challenge waits for the human.
    AwaitingHumanVerification,
    /// The task was paused.
    Paused,
    /// The task was cancelled.
    Cancelled,
    /// The same action was sent before and its outcome is unknown. It is
    /// never repeated automatically.
    OutcomeUncertain,
}

/// How a caller with a closed code set should report a refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalClass {
    /// The agent's view of the resource is out of date: observe again.
    Stale,
    /// The agent must wait: a human holds the resource, or the task is
    /// paused or waiting for verification.
    Paused,
    /// The task ended.
    Ended,
}

impl Reason {
    /// A stable code for logs and wire replies.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::HumanOverride => "human_override",
            Self::Quiet => "human_quiet",
            Self::ReobserveRequired => "reobserve_required",
            Self::ReplanRequired => "replan_required",
            Self::TargetStale => "target_stale",
            Self::AwaitingHumanVerification => "await_human_verification",
            Self::Paused => "paused",
            Self::Cancelled => "cancelled",
            Self::OutcomeUncertain => "outcome_uncertain",
        }
    }

    /// The class a closed-code caller maps this reason to.
    #[must_use]
    pub const fn class(self) -> RefusalClass {
        match self {
            Self::HumanOverride | Self::Quiet | Self::AwaitingHumanVerification | Self::Paused => {
                RefusalClass::Paused
            }
            Self::ReobserveRequired
            | Self::ReplanRequired
            | Self::TargetStale
            | Self::OutcomeUncertain => RefusalClass::Stale,
            Self::Cancelled => RefusalClass::Ended,
        }
    }
}

/// An agent operation the gate refused, and on which resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The resource whose state refused it. For an operation whose page the
    /// caller could not map, the resource that would have refused it.
    pub resource: ResourceId,
    /// Why.
    pub reason: Reason,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let advice = match self.reason {
            Reason::HumanOverride | Reason::Quiet => {
                "a person is using this page; nothing was done; wait for them to finish"
            }
            Reason::ReobserveRequired | Reason::ReplanRequired | Reason::TargetStale => {
                "the page changed since the agent last looked; nothing was done; observe it again"
            }
            Reason::AwaitingHumanVerification => {
                "the page needs a person to complete a verification; nothing was done"
            }
            Reason::Paused => "the task is paused; nothing was done",
            Reason::Cancelled => "the task was cancelled; nothing was done",
            Reason::OutcomeUncertain => {
                "the same action was sent before and its outcome is unknown; it is not repeated"
            }
        };
        write!(f, "{} ({}): {advice}", self.reason.code(), self.resource)
    }
}

impl std::error::Error for Refusal {}

/// Why an explicit control (pause, resume, take over) did not apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlError {
    /// No task owns that resource.
    UnknownResource,
    /// The task was cancelled; nothing applies any more.
    Cancelled,
    /// Resume was asked of a resource that is not paused.
    NotPaused,
    /// Another task already owns the resource.
    OwnedByAnotherTask,
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownResource => "no task owns that resource",
            Self::Cancelled => "the task was cancelled",
            Self::NotPaused => "the resource is not paused",
            Self::OwnedByAnotherTask => "another task owns that resource",
        })
    }
}

impl std::error::Error for ControlError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reason_has_a_distinct_code_and_a_class() {
        let all = [
            Reason::HumanOverride,
            Reason::Quiet,
            Reason::ReobserveRequired,
            Reason::ReplanRequired,
            Reason::TargetStale,
            Reason::AwaitingHumanVerification,
            Reason::Paused,
            Reason::Cancelled,
            Reason::OutcomeUncertain,
        ];
        let mut codes: Vec<&str> = all.iter().map(|reason| reason.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
        assert_eq!(Reason::HumanOverride.class(), RefusalClass::Paused);
        assert_eq!(Reason::TargetStale.class(), RefusalClass::Stale);
        assert_eq!(Reason::Cancelled.class(), RefusalClass::Ended);
    }

    #[test]
    fn the_message_names_the_code_and_says_nothing_was_done() {
        let refusal = Refusal {
            resource: ResourceId::new("page-1"),
            reason: Reason::HumanOverride,
        };
        let text = refusal.to_string();
        assert!(text.starts_with("human_override (page-1)"), "{text}");
        assert!(text.contains("nothing was done"), "{text}");
    }
}
