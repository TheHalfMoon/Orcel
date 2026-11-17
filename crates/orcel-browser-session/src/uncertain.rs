//! The idempotency guard's memory: per task, the actions whose dispatch
//! has an unknown outcome. It outlives a page's session (a page that closes
//! after a lost reply takes nothing with it) and can be shared by every
//! gate a process makes, so a host restart forgets nothing either.
//!
//! Keys should be built from stable action material (the origin, the URL
//! path, the action's kind and a stable description of its target such as
//! its role and name), never from page or node ids, so a new page or a
//! renumbered observation still finds the same action.

use crate::{ActionKey, TaskId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

/// The most uncertain actions a ledger holds over all tasks. Once full, the
/// gate refuses every consequential write (fail closed).
pub const MAX_LEDGER_ACTIONS: usize = 4_096;

/// A ledger several gates can share.
pub type SharedLedger = Arc<Mutex<UncertainLedger>>;

/// Uncertain actions by task.
#[derive(Debug, Default)]
pub struct UncertainLedger {
    by_task: BTreeMap<TaskId, BTreeSet<ActionKey>>,
    len: usize,
}

impl UncertainLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty ledger, ready to share.
    #[must_use]
    pub fn shared() -> SharedLedger {
        Arc::new(Mutex::new(Self::new()))
    }

    /// Remember `key` as uncertain for `task`. False if the ledger is full
    /// (it then refuses every consequential write anyway).
    pub fn record(&mut self, task: &TaskId, key: ActionKey) -> bool {
        if self.contains(task, &key) {
            return true;
        }
        if self.is_full() {
            return false;
        }
        self.by_task.entry(task.clone()).or_default().insert(key);
        self.len += 1;
        true
    }

    /// Whether `key` is uncertain for `task`.
    #[must_use]
    pub fn contains(&self, task: &TaskId, key: &ActionKey) -> bool {
        self.by_task
            .get(task)
            .is_some_and(|keys| keys.contains(key))
    }

    /// The outcome of `key` was established: forget it.
    pub fn reconcile(&mut self, task: &TaskId, key: &ActionKey) -> bool {
        let Some(keys) = self.by_task.get_mut(task) else {
            return false;
        };
        let removed = keys.remove(key);
        if keys.is_empty() {
            self.by_task.remove(task);
        }
        if removed {
            self.len -= 1;
        }
        removed
    }

    /// Whether the ledger is full.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.len >= MAX_LEDGER_ACTIONS
    }

    /// How many actions it holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether it holds none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Lock a shared ledger. A panic elsewhere while holding it leaves its data
/// consistent (every change is one insert or remove), so a poisoned lock is
/// still read.
pub(crate) fn lock(ledger: &SharedLedger) -> std::sync::MutexGuard<'_, UncertainLedger> {
    ledger.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_per_task_and_reconcile_forgets_them() {
        let mut ledger = UncertainLedger::new();
        let (one, two) = (TaskId::new("one"), TaskId::new("two"));
        assert!(ledger.record(&one, ActionKey::new("k")));
        assert!(ledger.contains(&one, &ActionKey::new("k")));
        assert!(!ledger.contains(&two, &ActionKey::new("k")));
        assert!(ledger.record(&one, ActionKey::new("k")), "idempotent");
        assert_eq!(ledger.len(), 1);
        assert!(ledger.reconcile(&one, &ActionKey::new("k")));
        assert!(ledger.is_empty());
    }

    #[test]
    fn a_full_ledger_records_nothing_more() {
        let mut ledger = UncertainLedger::new();
        let task = TaskId::new("t");
        for index in 0..MAX_LEDGER_ACTIONS {
            assert!(ledger.record(&task, ActionKey::new(index.to_string())));
        }
        assert!(ledger.is_full());
        assert!(!ledger.record(&task, ActionKey::new("one more")));
    }
}
