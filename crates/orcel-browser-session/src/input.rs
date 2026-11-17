//! Telling the human's input from the agent's own.
//!
//! Every input the agent dispatches into a page carries an [`AgentMarker`]
//! that Orcel issued for that one action: a sequence number, the resource
//! it was issued for, and a tag only this process can compute. The engine
//! adapter attaches the marker to the input events that action produced.
//! Anything that arrives without a marker Orcel still holds open (no
//! marker, a forged or retired one, or one issued for another resource) is
//! the human's. Misjudging the human as the agent would let the agent act
//! under the human's hand; misjudging the agent as the human only pauses
//! it, so every doubt resolves to "human".
//!
//! An input event records what kind of input it was and nothing else:
//! there is no field for a key, a character or a value, so keystroke
//! contents cannot reach the gate or its logs.

use crate::ResourceId;
use std::collections::hash_map::RandomState;
use std::collections::BTreeMap;
use std::hash::BuildHasher;

/// The most agent actions whose markers are open at once. Past it the
/// oldest is retired; its late events then count as human (a pause, never
/// an action under the human's hand).
pub const MAX_OPEN_MARKERS: usize = 1024;

/// What kind of input an event was. No contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputKind {
    /// A pointer press, release, move or click.
    Pointer,
    /// A key press or release.
    Key,
    /// Text entry, including IME composition.
    Text,
    /// A wheel or touch scroll.
    Scroll,
    /// A navigation the person started (address bar, back, forward,
    /// reload).
    Navigation,
    /// A change to a field's value or the page's content.
    Edit,
    /// A focus change inside the page.
    Focus,
}

/// Where an event sits in an input that spans time.
///
/// `Begin` and `End` bracket an input in progress (a key held down, a
/// drag, an IME composition): the quiet period never ends between them, so
/// the agent never interrupts ongoing input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputPhase {
    /// A complete event (a click, a key stroke, a scroll step).
    Instant,
    /// An input started and is still going on.
    Begin,
    /// An input that started ended.
    End,
}

/// Orcel's mark on one agent-dispatched action. Issued by
/// [`InjectionLedger::issue`]; valid until retired.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentMarker {
    /// The resource it was issued for.
    pub resource: ResourceId,
    /// Its sequence number.
    pub sequence: u64,
    /// A tag only the issuing ledger can compute for this sequence and
    /// resource.
    pub tag: u64,
}

/// One input event, as the engine adapter saw it on a resource. The gate
/// stamps it with its own clock when it arrives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedInput {
    /// The page or tab it happened on.
    pub resource: ResourceId,
    /// What kind of input it was.
    pub kind: InputKind,
    /// Whether it was a whole event or bracketed an ongoing input.
    pub phase: InputPhase,
    /// The marker the adapter found on it, if any.
    pub marker: Option<AgentMarker>,
}

/// Who an input came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputSource {
    /// The agent's own dispatched input, with an open marker Orcel issued.
    Agent,
    /// Everything else.
    Human,
}

/// The markers Orcel issued and has not retired.
#[derive(Debug)]
pub struct InjectionLedger {
    keys: RandomState,
    next: u64,
    open: BTreeMap<u64, ResourceId>,
}

impl Default for InjectionLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl InjectionLedger {
    /// An empty ledger with fresh per-process tag keys.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: RandomState::new(),
            next: 1,
            open: BTreeMap::new(),
        }
    }

    fn tag_for(&self, sequence: u64, resource: &ResourceId) -> u64 {
        self.keys.hash_one((sequence, resource.as_str()))
    }

    /// Issue a marker for one agent action on `resource`.
    pub fn issue(&mut self, resource: &ResourceId) -> AgentMarker {
        let sequence = self.next;
        self.next = self.next.saturating_add(1);
        self.open.insert(sequence, resource.clone());
        while self.open.len() > MAX_OPEN_MARKERS {
            if self.open.pop_first().is_none() {
                break;
            }
        }
        AgentMarker {
            resource: resource.clone(),
            sequence,
            tag: self.tag_for(sequence, resource),
        }
    }

    /// Retire a marker once its action finished: its events after this
    /// count as human.
    pub fn retire(&mut self, marker: &AgentMarker) {
        if self.verify(marker, &marker.resource) {
            self.open.remove(&marker.sequence);
        }
    }

    /// Whether `marker` is open, was issued for `resource`, and carries the
    /// tag this ledger computes for it.
    #[must_use]
    pub fn verify(&self, marker: &AgentMarker, resource: &ResourceId) -> bool {
        marker.resource == *resource
            && self.open.get(&marker.sequence) == Some(resource)
            && marker.tag == self.tag_for(marker.sequence, resource)
    }

    /// Who `event` came from.
    #[must_use]
    pub fn classify(&self, event: &ObservedInput) -> InputSource {
        match &event.marker {
            Some(marker) if self.verify(marker, &event.resource) => InputSource::Agent,
            _ => InputSource::Human,
        }
    }

    /// How many markers are open.
    #[must_use]
    pub fn open_markers(&self) -> usize {
        self.open.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(resource: &str, marker: Option<AgentMarker>) -> ObservedInput {
        ObservedInput {
            resource: ResourceId::new(resource),
            kind: InputKind::Pointer,
            phase: InputPhase::Instant,
            marker,
        }
    }

    #[test]
    fn an_event_without_a_marker_is_human() {
        let ledger = InjectionLedger::new();
        assert_eq!(ledger.classify(&event("p", None)), InputSource::Human);
    }

    #[test]
    fn an_open_marker_on_its_own_resource_is_the_agent_for_every_event_of_its_action() {
        let mut ledger = InjectionLedger::new();
        let marker = ledger.issue(&ResourceId::new("p"));
        for _ in 0..3 {
            assert_eq!(
                ledger.classify(&event("p", Some(marker.clone()))),
                InputSource::Agent
            );
        }
    }

    #[test]
    fn a_retired_marker_replayed_is_human() {
        let mut ledger = InjectionLedger::new();
        let marker = ledger.issue(&ResourceId::new("p"));
        ledger.retire(&marker);
        assert_eq!(
            ledger.classify(&event("p", Some(marker))),
            InputSource::Human
        );
    }

    #[test]
    fn a_forged_tag_or_sequence_is_human() {
        let mut ledger = InjectionLedger::new();
        let marker = ledger.issue(&ResourceId::new("p"));
        let forged_tag = AgentMarker {
            tag: marker.tag ^ 1,
            ..marker.clone()
        };
        assert_eq!(
            ledger.classify(&event("p", Some(forged_tag))),
            InputSource::Human
        );
        let forged_sequence = AgentMarker {
            sequence: marker.sequence + 1,
            ..marker
        };
        assert_eq!(
            ledger.classify(&event("p", Some(forged_sequence))),
            InputSource::Human
        );
    }

    #[test]
    fn a_marker_issued_for_another_resource_is_human_here() {
        let mut ledger = InjectionLedger::new();
        let marker = ledger.issue(&ResourceId::new("a"));
        assert_eq!(
            ledger.classify(&event("b", Some(marker.clone()))),
            InputSource::Human
        );
        let relabelled = AgentMarker {
            resource: ResourceId::new("b"),
            ..marker
        };
        assert_eq!(
            ledger.classify(&event("b", Some(relabelled))),
            InputSource::Human,
            "the tag binds the resource"
        );
    }

    #[test]
    fn another_ledgers_marker_is_human() {
        let mut ours = InjectionLedger::new();
        let mut theirs = InjectionLedger::new();
        let _ = ours.issue(&ResourceId::new("p"));
        let foreign = theirs.issue(&ResourceId::new("p"));
        assert_eq!(
            ours.classify(&event("p", Some(foreign))),
            InputSource::Human
        );
    }

    #[test]
    fn the_open_set_is_bounded_and_drops_the_oldest() {
        let mut ledger = InjectionLedger::new();
        let first = ledger.issue(&ResourceId::new("p"));
        for _ in 0..MAX_OPEN_MARKERS {
            let _ = ledger.issue(&ResourceId::new("p"));
        }
        assert_eq!(ledger.open_markers(), MAX_OPEN_MARKERS);
        assert_eq!(
            ledger.classify(&event("p", Some(first))),
            InputSource::Human
        );
    }
}
