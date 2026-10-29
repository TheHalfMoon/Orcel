//! SG-000115 A2: **inert/test-only** bounded descendant-accounting model.
//!
//! The actual Unix process-group, Linux pidfd/subreaper, and macOS kqueue
//! implementation is NOT present here. This is a small deterministic
//! fail-closed accounting primitive for fixture identities and teardown
//! reasoning. It never spawns, signals, waits for, or attaches to a process.
//! The only module declaration is #[cfg(test)] in lib.rs; no browser launch,
//! runtime dispatch, MCP, or release packaging can reach this code.
//!
//! An OS-specific verifier must establish a trustworthy immutable process
//! identity and *complete* descendant observation before this model could
//! support a real shutdown claim. In particular, the macOS process-group
//! escape problem remains OPEN and is not resolved by these tests.

use std::collections::BTreeMap;

use crate::supervise::JOB_ACTIVE_PROCESS_LIMIT;

/// A PID alone is insufficient: it may be reused after a child exits.
/// The start token represents an independently verified kernel birth identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessIdentity {
    pid: u32,
    birth_token: u64,
}

impl ProcessIdentity {
    fn fixture(pid: u32, birth_token: u64) -> Result<Self, &'static str> {
        if pid == 0 || birth_token == 0 {
            return Err("missing process identity");
        }
        Ok(Self { pid, birth_token })
    }
}

#[derive(Debug, Clone, Copy)]
struct Node {
    identity: ProcessIdentity,
    parent: Option<ProcessIdentity>,
    exited: bool,
}

/// An external OS verifier would have to prove this independently.
/// The model cannot turn Incomplete into Complete by observing just a leader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SweepCoverage {
    Incomplete,
    IndependentlyVerifiedComplete,
}

/// A bounded fixture graph, never a process-launch or signalling interface.
struct DescendantTracker {
    members: BTreeMap<u32, Node>,
}

impl DescendantTracker {
    fn new(root: ProcessIdentity) -> Self {
        let members = BTreeMap::from([(
            root.pid,
            Node {
                identity: root,
                parent: None,
                exited: false,
            },
        )]);
        Self { members }
    }

    fn observe_child(
        &mut self,
        parent: ProcessIdentity,
        child: ProcessIdentity,
    ) -> Result<(), &'static str> {
        // The root may have exited before the supervisor discovers an adopted
        // child. Parent identity must match, but liveness is not required.
        let Some(known_parent) = self.members.get(&parent.pid) else {
            return Err("unverified parent");
        };
        if known_parent.identity != parent {
            return Err("parent PID reuse or identity mismatch");
        }
        if self.members.contains_key(&child.pid) {
            // Duplicate observations and reused PIDs are not silently merged.
            return Err("duplicate or reused PID");
        }
        if self.members.len() >= JOB_ACTIVE_PROCESS_LIMIT as usize {
            return Err("descendant limit exceeded");
        }
        self.members.insert(
            child.pid,
            Node {
                identity: child,
                parent: Some(parent),
                exited: false,
            },
        );
        Ok(())
    }

    fn confirm_exit(&mut self, identity: ProcessIdentity) -> Result<(), &'static str> {
        let Some(node) = self.members.get_mut(&identity.pid) else {
            return Err("exit for unobserved process");
        };
        if node.identity != identity {
            return Err("exit identity mismatch or PID reuse");
        }
        node.exited = true;
        Ok(())
    }

    /// Only a *separate* OS-level proof of complete descendant coverage,
    /// plus exit confirmation of every observed member, could make this
    /// true. The macOS escape case cannot be assumed complete.
    fn all_exited_with_coverage(&self, coverage: SweepCoverage) -> bool {
        coverage == SweepCoverage::IndependentlyVerifiedComplete
            && self.members.values().all(|member| member.exited)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn id(pid: u32) -> ProcessIdentity {
        ProcessIdentity::fixture(pid, u64::from(pid) + 1000).unwrap()
    }

    #[test]
    fn root_exit_never_proves_descendant_exit() {
        let mut tracker = DescendantTracker::new(id(10));
        tracker.observe_child(id(10), id(11)).unwrap();
        tracker.confirm_exit(id(10)).unwrap();
        assert!(!tracker.all_exited_with_coverage(SweepCoverage::IndependentlyVerifiedComplete));
        tracker.confirm_exit(id(11)).unwrap();
        assert!(tracker.all_exited_with_coverage(SweepCoverage::IndependentlyVerifiedComplete));
    }

    #[test]
    fn a_fixture_descendant_that_escapes_the_process_group_still_blocks() {
        // This models a child that called setsid(); it is NOT an OS-level
        // demonstration that macOS can discover such a child.
        let mut tracker = DescendantTracker::new(id(20));
        tracker.observe_child(id(20), id(21)).unwrap();
        tracker.observe_child(id(21), id(22)).unwrap();
        tracker.confirm_exit(id(20)).unwrap();
        tracker.confirm_exit(id(21)).unwrap();
        assert!(!tracker.all_exited_with_coverage(SweepCoverage::IndependentlyVerifiedComplete));
        tracker.confirm_exit(id(22)).unwrap();
        assert!(tracker.all_exited_with_coverage(SweepCoverage::IndependentlyVerifiedComplete));
    }

    #[test]
    fn no_coverage_proof_means_no_success_even_if_every_observed_pid_exited() {
        let mut tracker = DescendantTracker::new(id(30));
        tracker.confirm_exit(id(30)).unwrap();
        assert!(!tracker.all_exited_with_coverage(SweepCoverage::Incomplete));
    }

    #[test]
    fn missing_and_zero_identities_are_rejected() {
        assert!(ProcessIdentity::fixture(0, 55).is_err());
        assert!(ProcessIdentity::fixture(1, 0).is_err());
        let mut tracker = DescendantTracker::new(id(40));
        assert!(tracker.observe_child(id(99), id(41)).is_err());
        assert!(tracker.confirm_exit(id(98)).is_err());
    }

    #[test]
    fn a_reused_pid_cannot_be_inferred_from_old_child_identity() {
        let mut tracker = DescendantTracker::new(id(50));
        tracker.observe_child(id(50), id(51)).unwrap();
        let reused = ProcessIdentity::fixture(51, 88_888).unwrap();
        assert!(tracker.observe_child(id(50), reused).is_err());
        assert!(tracker.confirm_exit(reused).is_err());
        assert!(!tracker.all_exited_with_coverage(SweepCoverage::IndependentlyVerifiedComplete));
    }

    #[test]
    fn cannot_attach_to_a_reused_parent_pid() {
        let mut tracker = DescendantTracker::new(id(60));
        let stale = ProcessIdentity::fixture(60, 42).unwrap();
        assert!(tracker.observe_child(stale, id(61)).is_err());
        assert_eq!(tracker.members.len(), 1);
    }

    #[test]
    fn identity_bound_adoption_is_recorded_even_after_parent_exit() {
        let mut tracker = DescendantTracker::new(id(70));
        tracker.confirm_exit(id(70)).unwrap();
        tracker.observe_child(id(70), id(71)).unwrap();
        assert_eq!(tracker.members.get(&71).unwrap().parent, Some(id(70)));
        assert!(!tracker.all_exited_with_coverage(SweepCoverage::IndependentlyVerifiedComplete));
    }

    #[test]
    fn bounded_process_count_rejects_one_more_without_mutation() {
        let mut tracker = DescendantTracker::new(id(100));
        for pid in 101..(100 + JOB_ACTIVE_PROCESS_LIMIT) {
            tracker.observe_child(id(100), id(pid)).unwrap();
        }
        assert_eq!(tracker.members.len(), JOB_ACTIVE_PROCESS_LIMIT as usize);
        assert!(tracker
            .observe_child(id(100), id(100 + JOB_ACTIVE_PROCESS_LIMIT))
            .is_err());
        assert_eq!(tracker.members.len(), JOB_ACTIVE_PROCESS_LIMIT as usize);
    }

    #[test]
    fn duplicate_child_observation_is_not_silently_accepted() {
        let mut tracker = DescendantTracker::new(id(200));
        tracker.observe_child(id(200), id(201)).unwrap();
        assert!(tracker.observe_child(id(200), id(201)).is_err());
    }

    #[test]
    fn test_only_module_has_no_production_callers() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let lib = std::fs::read_to_string(dir.join("lib.rs")).unwrap();
        assert!(lib.contains("#[cfg(test)]\nmod unix_descendants;"));
        assert!(!lib.contains("pub mod unix_descendants"));
        for entry in std::fs::read_dir(&dir).unwrap() {
            let file = entry.unwrap().path();
            if !file.is_file() || file.file_name().is_some_and(|n| n == "unix_descendants.rs") {
                continue;
            }
            let text = std::fs::read_to_string(file).unwrap();
            assert!(
                !text.contains("DescendantTracker")
                    && !text.contains("unix_descendants::")
                    && !text.contains("SweepCoverage"),
                "unexpected production reference"
            );
        }
    }
}
