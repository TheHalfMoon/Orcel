//! Audit event chain shapes (spec section 4.8).
//!
//! Shapes only. Hashing, appending, anchoring and verification are
//! `orcel-audit`'s (WP1-03). Lease lifecycle keeps `orcel-policy`'s
//! `AuthorityAuditEvent` unchanged: a `lease` event carries it verbatim in
//! `detail`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::{canonical_json_value, CanonicalJsonError};
use crate::job::ExecutionState;
use crate::lease::DispatchAuthority;
use crate::Contract;

/// `prev_digest` of the first event of the first log file.
pub const GENESIS_PREV_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// An anchor is written at least every this many events.
pub const ANCHOR_INTERVAL_EVENTS: u64 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    Request,
    Decision,
    Approval,
    Dispatch,
    State,
    Lease,
    Standing,
    EmergencyStop,
    Sidecar,
    Rotation,
    Anchor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    /// `"orcel.audit-event/1"`.
    pub contract: String,
    /// 0-based, gapless per log file.
    pub seq: u64,
    /// Digest of `seq - 1`; for `seq` 0 the last digest of the previous
    /// file, or `GENESIS_PREV_DIGEST`.
    pub prev_digest: String,
    pub at_ms: u64,
    pub kind: AuditEventKind,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub job_id: Option<String>,
    #[serde(default)]
    pub principal_id: Option<String>,
    #[serde(default)]
    pub capability: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    /// Lease id, binding digest and epoch for every Full Control dispatch
    /// (C-05).
    #[serde(default)]
    pub authority: Option<DispatchAuthority>,
    #[serde(default)]
    pub state: Option<ExecutionState>,
    /// True when the request fields (action, capability, operation,
    /// principal, task) are claims made by the user session rather than
    /// facts the writer observed itself (C-27 e).
    pub asserted_by_session: bool,
    /// Caller process id the authority service observed on its pipe.
    #[serde(default)]
    pub caller_pid: Option<u32>,
    /// Caller image path the authority service observed on its pipe.
    #[serde(default)]
    pub caller_image: Option<String>,
    /// Bounded and redacted; argv, URLs and query strings appear only as
    /// SHA-256 digests.
    pub detail: Value,
    /// SHA-256 of `digest_input()`.
    pub digest: String,
}

impl Contract for AuditEvent {
    const CONTRACT: &'static str = "orcel.audit-event/1";
}

impl AuditEvent {
    /// The canonical JSON text the event's `digest` covers: the event
    /// without its `digest` field. The caller hashes it with SHA-256.
    pub fn digest_input(&self) -> Result<String, CanonicalJsonError> {
        let mut value = serde_json::to_value(self)
            .map_err(|error| CanonicalJsonError::Unserializable(error.to_string()))?;
        if let Value::Object(map) = &mut value {
            map.remove("digest");
        }
        canonical_json_value(&value)
    }
}

/// Where an anchor points in the chain: `(log, file id, seq, digest)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AnchorRef {
    /// Which chain: for example `"orceld"` or `"authority"`.
    pub log: String,
    pub file_id: String,
    pub seq: u64,
    pub digest: String,
}

/// Prefix of the anchor insertion string written to the Windows Event Log.
pub const EVENT_LOG_ANCHOR_PREFIX: &str = "orcel-anchor/1";

/// Windows Event Log event id of an anchor record.
pub const EVENT_LOG_ANCHOR_EVENT_ID: u32 = 4100;
/// Event id of a granted Full Control scope record.
pub const EVENT_LOG_GRANT_EVENT_ID: u32 = 4101;
/// Event id of a grant intent and its confirmation answer.
pub const EVENT_LOG_GRANT_INTENT_EVENT_ID: u32 = 4102;

impl AnchorRef {
    /// The Event Log insertion string
    /// `orcel-anchor/1|<log>|<file id>|<seq>|<digest>` (section 4.8), or
    /// `None` when a part is empty or contains the `|` separator or a
    /// control character, which would make the record ambiguous.
    pub fn event_log_insertion(&self) -> Option<String> {
        let clean =
            |part: &str| !part.is_empty() && !part.chars().any(|c| c == '|' || c.is_control());
        if !(clean(&self.log) && clean(&self.file_id) && clean(&self.digest)) {
            return None;
        }
        Some(format!(
            "{EVENT_LOG_ANCHOR_PREFIX}|{}|{}|{}|{}",
            self.log, self.file_id, self.seq, self.digest
        ))
    }
}
