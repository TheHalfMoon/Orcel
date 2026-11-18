//! Anchors (spec 4.8, WP1-03): every [`ANCHOR_INTERVAL_EVENTS`] events the
//! writer hands `(log, file id, seq, digest)` to an [`Anchorer`] and records
//! what it answered as an `anchor` event in the chain itself.
//!
//! An anchor only means something when it is held outside the user session.
//! The authority service (SG-000132) is that place: orceld supplies an
//! [`Anchorer`] that asks it, and the service records the anchor in its own
//! chain and writes Event Log event 4100 under the source it registered.
//! Without the service the writer records a local marker that says
//! `unanchored`: the chain is then tamper-evident against edits, deletions
//! and reorders, but a rewrite of the whole file, or a cut of whole records
//! at its end, cannot be told from the file alone. Nothing here claims more
//! than that.
//!
//! [`ANCHOR_INTERVAL_EVENTS`]: orcel_contracts::event::ANCHOR_INTERVAL_EVENTS

use orcel_contracts::event::AnchorRef;
use serde_json::{json, Value};

/// What an [`Anchorer`] answered for one anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorOutcome {
    /// Held outside the session. `by` names the holder; `receipt` is what it
    /// returned (for the authority service: its own audit seq and the Event
    /// Log event id).
    Anchored { by: String, receipt: Value },
    /// Not held anywhere outside this file.
    Unanchored { reason: String },
}

impl AnchorOutcome {
    /// The `detail` of the chain's `anchor` event for `anchor`.
    pub(crate) fn detail(&self, anchor: &AnchorRef) -> Value {
        let anchor = json!({
            "log": anchor.log,
            "file_id": anchor.file_id,
            "seq": anchor.seq,
            "digest": anchor.digest,
        });
        match self {
            Self::Anchored { by, receipt } => json!({
                "anchor": anchor,
                "status": "anchored",
                "by": crate::redact::bounded(by, crate::MAX_FIELD_CHARS),
                "receipt": receipt,
            }),
            Self::Unanchored { reason } => json!({
                "anchor": anchor,
                "status": "unanchored",
                "reason": crate::redact::bounded(reason, crate::MAX_FIELD_CHARS),
                "note": UNANCHORED_NOTE,
            }),
        }
    }
}

/// What every local marker says, so no reader takes it for more.
pub const UNANCHORED_NOTE: &str = "local marker only: no anchor outside the user session; \
     edits, deletions and reorders are evident, a rewrite of the whole file or a cut at its end is not";

/// Holds anchors outside the user session.
pub trait Anchorer: Send + Sync {
    fn anchor(&self, anchor: &AnchorRef) -> AnchorOutcome;
}

/// No external holder: every anchor is a local, unanchored marker.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalMarker;

impl Anchorer for LocalMarker {
    fn anchor(&self, _anchor: &AnchorRef) -> AnchorOutcome {
        AnchorOutcome::Unanchored {
            reason: "no authority service anchors this chain".to_owned(),
        }
    }
}
