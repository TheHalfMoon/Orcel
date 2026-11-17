//! Telling the human's input from the agent's own.
//!
//! Every input the agent dispatches into a page carries an [`AgentMarker`]
//! that Orcel issued for that one action: a sequence number, the resource
//! it was issued for, and an HMAC-SHA256 tag over both under a key drawn
//! from the operating system's random source when the ledger was made,
//! which never leaves the process. The engine adapter attaches the marker
//! to the input events that action produced. Anything that arrives without
//! a marker Orcel still holds open (no marker, a forged, retired or expired
//! one, or one issued for another resource) is the human's. Misjudging the
//! human as the agent would let the agent act under the human's hand;
//! misjudging the agent as the human only pauses it, so every doubt
//! resolves to "human", and a ledger that could not get a random key vouches
//! for nothing.
//!
//! An input event records what kind of input it was and nothing else:
//! there is no field for a key, a character or a value, so keystroke
//! contents cannot reach the gate or its logs. A marker's tag is never
//! printed (its `Debug` redacts it).

use crate::{Millis, ResourceId};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

/// The most agent actions whose markers are open at once. Past it the
/// oldest is retired; its late events then count as human (a pause, never
/// an action under the human's hand).
pub const MAX_OPEN_MARKERS: usize = 1024;

/// How long a marker vouches for input after it was issued. An action's
/// input arrives well within it; a marker presented later counts as human.
pub const MARKER_TTL_MS: u64 = 30_000;

/// The length of a marker's tag (an HMAC-SHA256 output).
pub const MARKER_TAG_BYTES: usize = 32;

const TAG_DOMAIN: &[u8] = b"orcel-agent-marker/1";
const BLOCK: usize = 64;

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
/// [`InjectionLedger::issue`]; valid until retired or expired.
#[derive(Clone, PartialEq, Eq)]
pub struct AgentMarker {
    /// The resource it was issued for.
    pub resource: ResourceId,
    /// Its sequence number.
    pub sequence: u64,
    /// HMAC-SHA256 over the sequence and the resource under the issuing
    /// ledger's key.
    pub tag: [u8; MARKER_TAG_BYTES],
}

impl fmt::Debug for AgentMarker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentMarker")
            .field("resource", &self.resource)
            .field("sequence", &self.sequence)
            .field("tag", &"<redacted>")
            .finish()
    }
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

#[derive(Debug)]
struct Open {
    resource: ResourceId,
    issued_at: Millis,
}

/// The markers Orcel issued and has not retired.
pub struct InjectionLedger {
    key: Option<[u8; BLOCK]>,
    next: u64,
    open: BTreeMap<u64, Open>,
}

impl fmt::Debug for InjectionLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InjectionLedger")
            .field("keyed", &self.key.is_some())
            .field("next", &self.next)
            .field("open", &self.open.len())
            .finish()
    }
}

impl Drop for InjectionLedger {
    /// Zero the HMAC key. Best effort without unsafe code: `black_box`
    /// keeps the compiler from dropping the writes as dead stores.
    fn drop(&mut self) {
        if let Some(key) = self.key.as_mut() {
            key.fill(0);
            std::hint::black_box(&*key);
        }
        self.key = None;
    }
}

impl Default for InjectionLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// A 256-bit key from the operating system's random source, or `None`.
fn random_key() -> Option<[u8; BLOCK]> {
    let mut key = [0u8; BLOCK];
    let (secret, _) = key.split_at_mut(32);
    getrandom::fill(secret).ok()?;
    Some(key)
}

/// HMAC-SHA256 (RFC 2104) of `parts` under `key` (zero-padded to a block).
fn hmac_sha256(key: &[u8; BLOCK], parts: &[&[u8]]) -> [u8; MARKER_TAG_BYTES] {
    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    for part in parts {
        inner.update(part);
    }
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// Equality that takes the same time wherever the inputs differ.
fn constant_time_eq(left: &[u8; MARKER_TAG_BYTES], right: &[u8; MARKER_TAG_BYTES]) -> bool {
    left.iter()
        .zip(right.iter())
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

impl InjectionLedger {
    /// An empty ledger with a fresh per-process key from the operating
    /// system. If no random key could be had, the ledger vouches for no
    /// input at all (everything counts as human).
    #[must_use]
    pub fn new() -> Self {
        Self {
            key: random_key(),
            next: 1,
            open: BTreeMap::new(),
        }
    }

    /// Whether the ledger has a key (and so can vouch for anything).
    #[must_use]
    pub fn is_keyed(&self) -> bool {
        self.key.is_some()
    }

    fn tag_for(&self, sequence: u64, resource: &ResourceId) -> Option<[u8; MARKER_TAG_BYTES]> {
        let key = self.key.as_ref()?;
        let name = resource.as_str().as_bytes();
        Some(hmac_sha256(
            key,
            &[
                TAG_DOMAIN,
                &sequence.to_be_bytes(),
                &(name.len() as u64).to_be_bytes(),
                name,
            ],
        ))
    }

    /// Issue a marker for one agent action on `resource` at `now`.
    pub fn issue(&mut self, resource: &ResourceId, now: Millis) -> AgentMarker {
        self.open
            .retain(|_, open| now.since(open.issued_at) < MARKER_TTL_MS);
        let sequence = self.next;
        self.next = self.next.saturating_add(1);
        self.open.insert(
            sequence,
            Open {
                resource: resource.clone(),
                issued_at: now,
            },
        );
        while self.open.len() > MAX_OPEN_MARKERS {
            if self.open.pop_first().is_none() {
                break;
            }
        }
        AgentMarker {
            resource: resource.clone(),
            sequence,
            tag: self
                .tag_for(sequence, resource)
                .unwrap_or([0u8; MARKER_TAG_BYTES]),
        }
    }

    /// Retire a marker once its action finished: its events after this
    /// count as human.
    pub fn retire(&mut self, marker: &AgentMarker) {
        let matches = self.open.get(&marker.sequence).is_some_and(|open| {
            open.resource == marker.resource
                && self
                    .tag_for(marker.sequence, &marker.resource)
                    .is_some_and(|tag| constant_time_eq(&tag, &marker.tag))
        });
        if matches {
            self.open.remove(&marker.sequence);
        }
    }

    /// Whether `marker` is open and unexpired at `now`, was issued for
    /// `resource`, and carries the tag this ledger computes for it.
    #[must_use]
    pub fn verify(&self, marker: &AgentMarker, resource: &ResourceId, now: Millis) -> bool {
        let Some(open) = self.open.get(&marker.sequence) else {
            return false;
        };
        let Some(expected) = self.tag_for(marker.sequence, resource) else {
            return false;
        };
        let tag_ok = constant_time_eq(&expected, &marker.tag);
        tag_ok
            && marker.resource == *resource
            && open.resource == *resource
            && now.since(open.issued_at) < MARKER_TTL_MS
    }

    /// Who `event` came from, judged at `now`.
    #[must_use]
    pub fn classify(&self, event: &ObservedInput, now: Millis) -> InputSource {
        match &event.marker {
            Some(marker) if self.verify(marker, &event.resource, now) => InputSource::Agent,
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

    const T0: Millis = Millis(1_000);

    fn event(resource: &str, marker: Option<AgentMarker>) -> ObservedInput {
        ObservedInput {
            resource: ResourceId::new(resource),
            kind: InputKind::Pointer,
            phase: InputPhase::Instant,
            marker,
        }
    }

    #[test]
    fn the_ledger_has_an_os_random_key() {
        assert!(InjectionLedger::new().is_keyed());
    }

    #[test]
    fn hmac_matches_the_rfc_4231_test_case_2() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
        let mut key = [0u8; BLOCK];
        key[..4].copy_from_slice(b"Jefe");
        let tag = hmac_sha256(&key, &[b"what do ya want ", b"for nothing?"]);
        let hex: String = tag.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn an_event_without_a_marker_is_human() {
        let ledger = InjectionLedger::new();
        assert_eq!(ledger.classify(&event("p", None), T0), InputSource::Human);
    }

    #[test]
    fn an_open_marker_on_its_own_resource_is_the_agent_for_every_event_of_its_action() {
        let mut ledger = InjectionLedger::new();
        let marker = ledger.issue(&ResourceId::new("p"), T0);
        for _ in 0..3 {
            assert_eq!(
                ledger.classify(&event("p", Some(marker.clone())), T0),
                InputSource::Agent
            );
        }
    }

    #[test]
    fn a_marker_expires() {
        let mut ledger = InjectionLedger::new();
        let marker = ledger.issue(&ResourceId::new("p"), T0);
        let late = T0.plus(MARKER_TTL_MS);
        assert_eq!(
            ledger.classify(
                &event("p", Some(marker.clone())),
                T0.plus(MARKER_TTL_MS - 1)
            ),
            InputSource::Agent
        );
        assert_eq!(
            ledger.classify(&event("p", Some(marker)), late),
            InputSource::Human
        );
    }

    #[test]
    fn a_retired_marker_replayed_is_human() {
        let mut ledger = InjectionLedger::new();
        let marker = ledger.issue(&ResourceId::new("p"), T0);
        ledger.retire(&marker);
        assert_eq!(
            ledger.classify(&event("p", Some(marker)), T0),
            InputSource::Human
        );
    }

    #[test]
    fn a_forged_tag_or_sequence_is_human() {
        let mut ledger = InjectionLedger::new();
        let marker = ledger.issue(&ResourceId::new("p"), T0);
        let mut tag = marker.tag;
        tag[0] ^= 1;
        let forged_tag = AgentMarker {
            tag,
            ..marker.clone()
        };
        assert_eq!(
            ledger.classify(&event("p", Some(forged_tag)), T0),
            InputSource::Human
        );
        let forged_sequence = AgentMarker {
            sequence: marker.sequence + 1,
            ..marker
        };
        assert_eq!(
            ledger.classify(&event("p", Some(forged_sequence)), T0),
            InputSource::Human
        );
    }

    #[test]
    fn a_marker_issued_for_another_resource_is_human_here() {
        let mut ledger = InjectionLedger::new();
        let marker = ledger.issue(&ResourceId::new("a"), T0);
        assert_eq!(
            ledger.classify(&event("b", Some(marker.clone())), T0),
            InputSource::Human
        );
        let relabelled = AgentMarker {
            resource: ResourceId::new("b"),
            ..marker
        };
        assert_eq!(
            ledger.classify(&event("b", Some(relabelled)), T0),
            InputSource::Human,
            "the tag binds the resource"
        );
    }

    #[test]
    fn another_ledgers_marker_is_human() {
        let mut ours = InjectionLedger::new();
        let mut theirs = InjectionLedger::new();
        let _ = ours.issue(&ResourceId::new("p"), T0);
        let foreign = theirs.issue(&ResourceId::new("p"), T0);
        assert_eq!(
            ours.classify(&event("p", Some(foreign)), T0),
            InputSource::Human
        );
    }

    #[test]
    fn a_ledger_without_a_key_vouches_for_nothing() {
        let mut ledger = InjectionLedger {
            key: None,
            next: 1,
            open: BTreeMap::new(),
        };
        let marker = ledger.issue(&ResourceId::new("p"), T0);
        assert_eq!(
            ledger.classify(&event("p", Some(marker)), T0),
            InputSource::Human
        );
    }

    #[test]
    fn the_open_set_is_bounded_and_drops_the_oldest() {
        let mut ledger = InjectionLedger::new();
        let first = ledger.issue(&ResourceId::new("p"), T0);
        for _ in 0..MAX_OPEN_MARKERS {
            let _ = ledger.issue(&ResourceId::new("p"), T0);
        }
        assert_eq!(ledger.open_markers(), MAX_OPEN_MARKERS);
        assert_eq!(
            ledger.classify(&event("p", Some(first)), T0),
            InputSource::Human
        );
    }

    #[test]
    fn debug_never_prints_the_tag() {
        let mut ledger = InjectionLedger::new();
        let marker = ledger.issue(&ResourceId::new("p"), T0);
        let printed = format!("{marker:?} {ledger:?}");
        assert!(printed.contains("<redacted>"), "{printed}");
        let hex: String = marker
            .tag
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert!(!printed.contains(&hex));
        assert!(!printed.contains(&format!("{:?}", marker.tag)));
    }
}
