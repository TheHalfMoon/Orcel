//! The authority pipe protocol: one little-endian `u32` length, then that
//! many bytes of JSON, in each direction. A request is a [`Request`]; the
//! answer is a [`Response`]. Frames above [`MAX_FRAME_BYTES`] are refused.
//!
//! Spec 4.13 names `GrantBegin`, `GrantComplete`, `StandingBegin`,
//! `StandingComplete`, `Authorize`, `Stop`, `Status` and `Heartbeat`. Slices 1
//! and 2 implement `GrantBegin` (as [`Request::GrantBegin`]), the grant's
//! completion (as [`Request::PresenceComplete`], shared with enrollment),
//! `Authorize`, `Stop` and `Status`, plus lease `Verify`, `List` and
//! `Revoke`, and the attested enrollment and reset of a Windows Hello key.
//! Standing approvals and the indicator heartbeat are later slices; their
//! requests are not accepted yet.

use crate::error::AuthorityError;
use crate::lease::LeaseScope;
use orcel_contracts::{ExecutorClass, FailureCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{Read, Write};

/// The protocol name returned by `Status`.
pub const PROTOCOL: &str = "orcel.authority-pipe/1";

/// The largest frame either side accepts.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Where a caller says a grant request came from. This is an UNVERIFIED
/// claim: any process can send any value. The service refuses every value
/// but [`ClaimedOrigin::OwnerCli`], which only stops callers honest enough
/// to say what they are. What carries weight is observed (orceld's image,
/// an interactive logon in the active console session), the one-time code
/// only the requesting process receives, the service-rendered confirmation
/// that shows that code and that process, and Windows Hello.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimedOrigin {
    OwnerCli,
    Mcp,
    Agent,
    Remote,
    Orceld,
}

/// What the caller claims an `Authorize` is for (all session-asserted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeClaims {
    pub request_id: String,
    pub capability: String,
    pub operation: String,
    pub principal_id: String,
    pub task: String,
    /// SHA-256 of the action's arguments, never the arguments themselves.
    pub action_digest: String,
    /// Review F4: for a browser lease, the page's committed origin the
    /// action lands on; the service checks it against the lease's origins
    /// (and `operation` against its families). Absent for desktop actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// The service's mode, epoch, revocation counter, public key and what
    /// this slice defers.
    Status,
    /// Spec 4.13 step 1: record a grant intent. `scope` absent means the
    /// narrow default; `minutes` absent means 30.
    GrantBegin {
        origin: ClaimedOrigin,
        scope: Option<LeaseScope>,
        minutes: Option<u64>,
        principal_id: String,
        task: String,
    },
    /// Slice 2: enroll a Windows Hello key credential. The caller's token
    /// must be elevated; the key's TPM attestation
    /// (`KeyCredential.GetAttestationAsync`) must verify to a pinned root.
    /// The service then renders a confirmation showing the key fingerprint;
    /// on Yes the new key signs the challenge (`IntentStatus`,
    /// `PresenceComplete`). `replace` replaces an enrolled key.
    EnrollBegin {
        origin: ClaimedOrigin,
        public_key_spki_hex: String,
        attestation_hex: String,
        certificate_chain_hex: String,
        replace: bool,
    },
    /// Slice 2: remove the caller's enrolled key (elevated, confirmed).
    ResetEnrollment { origin: ClaimedOrigin },
    /// Where the caller's pending intent stands; carries the challenge once
    /// the confirmation was answered Yes.
    IntentStatus { intent_id: String },
    /// Spec 4.13 step 5: the one-time code `GrantBegin` returned and the
    /// Windows Hello signature over the challenge.
    PresenceComplete {
        intent_id: String,
        code: String,
        signature_hex: String,
    },
    /// Drop the caller's pending intent.
    CancelIntent { intent_id: String },
    /// The caller's leases (bound to its SID and logon session).
    List,
    /// The signed lease and its state now.
    Verify { lease_id: String },
    /// Spec 4.13 Authorize (slice 1: lease, epoch, binding, executor and
    /// the audit record written first; no Job Object, standing approval or
    /// heartbeat yet).
    Authorize {
        lease_id: String,
        executor: ExecutorClass,
        claims: AuthorizeClaims,
    },
    /// End one of the caller's leases.
    Revoke { lease_id: String },
    /// Spec C-28: end every lease of the caller's logon session, advance
    /// the epoch.
    Stop,
}

impl Request {
    /// The operation name, for the audit record.
    pub fn op(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::GrantBegin { .. } => "grant_begin",
            Self::EnrollBegin { .. } => "enroll_begin",
            Self::ResetEnrollment { .. } => "reset_enrollment",
            Self::IntentStatus { .. } => "intent_status",
            Self::PresenceComplete { .. } => "presence_complete",
            Self::CancelIntent { .. } => "cancel_intent",
            Self::List => "list",
            Self::Verify { .. } => "verify",
            Self::Authorize { .. } => "authorize",
            Self::Revoke { .. } => "revoke",
            Self::Stop => "stop",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub result: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<FailureCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Response {
    pub fn success(result: Value) -> Self {
        Self {
            ok: true,
            result,
            code: None,
            message: None,
        }
    }

    pub fn failure(error: &AuthorityError) -> Self {
        Self {
            ok: false,
            result: Value::Null,
            code: Some(error.code.clone()),
            message: Some(error.message.clone()),
        }
    }

    /// The result, or the error the service answered.
    pub fn into_result(self) -> Result<Value, AuthorityError> {
        if self.ok {
            Ok(self.result)
        } else {
            Err(AuthorityError::new(
                self.code.unwrap_or(FailureCode::InternalError),
                self.message.unwrap_or_default(),
            ))
        }
    }
}

/// Reads one frame. `Ok(None)` at a clean end of stream.
pub fn read_frame(source: &mut impl Read) -> Result<Option<Vec<u8>>, AuthorityError> {
    let mut length = [0u8; 4];
    let mut filled = 0;
    while filled < 4 {
        let read = source
            .read(&mut length[filled..])
            .map_err(|error| AuthorityError::unavailable(format!("read a frame: {error}")))?;
        if read == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err(AuthorityError::invalid("a frame ended inside its length"));
        }
        filled += read;
    }
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(AuthorityError::invalid("a frame length is out of bounds"));
    }
    let mut body = vec![0u8; length];
    source
        .read_exact(&mut body)
        .map_err(|error| AuthorityError::invalid(format!("a frame ended early: {error}")))?;
    Ok(Some(body))
}

/// Writes one frame.
pub fn write_frame(sink: &mut impl Write, body: &[u8]) -> Result<(), AuthorityError> {
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(AuthorityError::invalid("a frame length is out of bounds"));
    }
    let length = u32::try_from(body.len())
        .map_err(|_| AuthorityError::invalid("a frame length is out of bounds"))?;
    sink.write_all(&length.to_le_bytes())
        .and_then(|()| sink.write_all(body))
        .and_then(|()| sink.flush())
        .map_err(|error| AuthorityError::unavailable(format!("write a frame: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_bounds_hold() -> Result<(), String> {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, b"{\"op\":\"status\"}").map_err(|e| e.to_string())?;
        let mut cursor = std::io::Cursor::new(buffer);
        let frame = read_frame(&mut cursor).map_err(|e| e.to_string())?;
        assert_eq!(frame.as_deref(), Some(&b"{\"op\":\"status\"}"[..]));
        assert_eq!(read_frame(&mut cursor).map_err(|e| e.to_string())?, None);
        let oversized = ((MAX_FRAME_BYTES + 1) as u32).to_le_bytes();
        assert!(read_frame(&mut std::io::Cursor::new(oversized.to_vec())).is_err());
        assert!(write_frame(&mut Vec::new(), &[]).is_err());
        Ok(())
    }

    #[test]
    fn requests_are_strict() {
        let ok: Result<Request, _> = serde_json::from_str(r#"{"op":"status"}"#);
        assert_eq!(ok.ok(), Some(Request::Status));
        let unknown: Result<Request, _> = serde_json::from_str(r#"{"op":"heartbeat"}"#);
        assert!(unknown.is_err());
        let extra: Result<Request, _> =
            serde_json::from_str(r#"{"op":"revoke","lease_id":"al-1","force":true}"#);
        assert!(extra.is_err());
    }
}
