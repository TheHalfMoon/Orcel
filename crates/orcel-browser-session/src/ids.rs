//! Names the gate keys its state by. They are opaque to the gate: the
//! caller chooses them (a page id, a tab id, a task id, a digest of an
//! action) and never puts page text, field values or keystrokes in them.

use std::fmt;

/// One page or tab an agent task can own.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceId(String);

impl ResourceId {
    /// A resource named `id`.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The agent task that owns a resource.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(String);

impl TaskId {
    /// A task named `id`.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What makes two agent writes "the same action" for the idempotency
/// guard: the caller's digest of the action's kind, target and value. It
/// must be a digest, never the value itself.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionKey(String);

impl ActionKey {
    /// A key from the caller's digest.
    #[must_use]
    pub fn new(digest: impl Into<String>) -> Self {
        Self(digest.into())
    }

    /// The digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
