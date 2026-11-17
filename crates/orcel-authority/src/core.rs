//! The authority state machine (spec 4.13, C-27 to C-30).
//!
//! [`AuthorityCore`] holds the epoch, the monotonic revocation counter, the
//! lease records, the enrolled Windows Hello public keys, the pending
//! intents and the audit chain. Every request runs under one lock held by
//! the caller (the pipe server keeps the core in a `Mutex`), so Authorize,
//! issuance and Stop are atomic with respect to each other (C-30).
//!
//! Grant (and enrollment) flow, spec 4.13 steps 1 to 6:
//!
//! 1. `GrantBegin` from an interactive console-session caller claiming the
//!    owner CLI origin records the session's single pending intent (audit +
//!    Event Log 4102). It expires after 5 minutes. orceld, MCP, agent and
//!    remote origins and non-interactive callers are refused.
//! 2. Only the first service-observed `WTS_SESSION_UNLOCK` of that session
//!    after the intent, with no lease active there, opens a 120 s window
//!    ([`AuthorityCore::observe_unlock`]). A routine unlock without an
//!    intent opens nothing. Console mode never observes session changes, so
//!    it can never issue.
//! 3. The scope defaults to the narrow form; widening is explicit.
//! 4. The service renders the confirmation itself (`WTSSendMessageW`, see
//!    `win::confirm`) outside the core lock and reports the answer
//!    ([`AuthorityCore::confirmation_answer`]). Only Yes continues.
//! 5. The service issues a 32-byte challenge bound to the intent digest;
//!    the user session signs it with the enrolled Windows Hello key
//!    credential; the service verifies the signature.
//! 6. The lease is signed, stored, audited, and its granted scope written to
//!    the Event Log (4101).
//!
//! Grants are refused while any lease is active in the session. Stop (from
//! any process of the logon session, from session lock, sign-out and
//! disconnect, and on expiry) ends the leases, advances the epoch and the
//! revocation counter, and writes `emergency_stop`.

use crate::audit::{AuditChain, AuditRecord, Observed};
use crate::caller::{CallerFacts, CallerRole, ClientPolicy};
use crate::error::AuthorityError;
use crate::lease::{
    key_id_of, signing_input, GrantEvidence, LeaseBody, LeaseContext, LeaseScope,
    ObservedRequester, SignedLease, DEFAULT_LEASE_MINUTES, LEASE_CONTRACT, LEASE_ID_PREFIX,
    MAX_FIELD_BYTES, MAX_LEASE_MINUTES, MIN_LEASE_MINUTES,
};
use crate::protocol::{AuthorizeClaims, ClaimedOrigin, Request, PROTOCOL};
use crate::{hex, sha256_hex, unhex, RunMode};
use orcel_contracts::ExecutorClass;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const STATE_CONTRACT: &str = "orcel.authority-state/1";
pub const STATE_FILE: &str = "state.json";
pub const AUDIT_FILE: &str = "audit.jsonl";

/// Spec 4.13: an intent expires after 5 minutes.
pub const INTENT_TTL_MS: u64 = 5 * 60 * 1_000;
/// Spec 4.13: the grant window lasts 120 s from the observed unlock.
pub const GRANT_WINDOW_MS: u64 = 120 * 1_000;
/// Spec 4.13: the confirmation times out after 60 s.
pub const CONFIRMATION_TIMEOUT_SECS: u32 = 60;
/// Ended lease records kept for `List`.
pub const MAX_LEASE_RECORDS: usize = 64;
/// The confirmation's title (spec 4.13 step 4).
pub const CONFIRMATION_TITLE: &str = "Orcel Authority";

const PRESENCE_DOMAIN: &[u8] = b"orcel-authority-presence-challenge/1\n";

/// What this slice does not do yet; returned by `Status` and `Authorize`.
pub const DEFERRED: [&str; 6] = [
    "service-owned Job Objects (Authorize returns job_name null)",
    "standing approvals (spec 4.15)",
    "indicator heartbeat",
    "TPM-backed signing key (the key is a CNG software key wrapped by DPAPI)",
    "Authenticode signature requirement on the orceld image",
    "WP1-10 proof that injected input cannot answer the confirmation",
];

/// Signs lease bodies; holds the only copy of the private key.
pub trait LeaseSigner: Send {
    /// The public key blob verifiers use (CNG `BCRYPT_ECCPUBLIC_BLOB`).
    fn public_key(&self) -> Vec<u8>;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AuthorityError>;
}

/// Checks Windows Hello key-credential signatures.
pub trait PresenceVerifier: Send {
    /// Refuse a public key the verifier cannot use.
    fn check_public_key(&self, spki_der: &[u8]) -> Result<(), AuthorityError>;
    fn verify(
        &self,
        spki_der: &[u8],
        challenge: &[u8],
        signature: &[u8],
    ) -> Result<(), AuthorityError>;
}

/// Writes Event Log entries (4100, 4101, 4102).
pub trait EventSink: Send {
    fn record(&self, event_id: u32, error: bool, text: &str) -> Result<(), AuthorityError>;
}

/// Cryptographic randomness.
pub trait Entropy: Send {
    fn fill(&self, out: &mut [u8]) -> Result<(), AuthorityError>;
}

/// The platform pieces the core runs on.
pub struct Services {
    pub signer: Box<dyn LeaseSigner>,
    pub presence: Box<dyn PresenceVerifier>,
    pub events: Box<dyn EventSink>,
    pub entropy: Box<dyn Entropy>,
    pub clock: fn() -> u64,
}

/// A confirmation's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmAnswer {
    Yes,
    No,
    Timeout,
    Failed(String),
}

impl ConfirmAnswer {
    fn as_str(&self) -> &str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Timeout => "timeout",
            Self::Failed(_) => "failed",
        }
    }
}

/// A confirmation the service must render now (outside the core lock).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmationTask {
    pub intent_id: String,
    pub ts_session_id: u32,
    pub title: String,
    pub text: String,
    pub timeout_secs: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Active,
    Revoked,
    Expired,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRecord {
    pub lease: SignedLease,
    pub state: LeaseState,
    pub ended_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolledKey {
    pub windows_user_sid: String,
    pub spki_hex: String,
    pub key_digest: String,
    pub enrolled_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedState {
    pub contract: String,
    /// Only grows.
    pub epoch: u64,
    /// Only grows: every revoke, stop and session end adds one.
    pub revocations: u64,
    pub leases: Vec<LeaseRecord>,
    pub enrolled: Vec<EnrolledKey>,
}

impl PersistedState {
    fn fresh() -> Self {
        Self {
            contract: STATE_CONTRACT.to_owned(),
            epoch: 1,
            revocations: 0,
            leases: Vec::new(),
            enrolled: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Purpose {
    Grant {
        scope: LeaseScope,
        minutes: u64,
        principal_id: String,
        task: String,
    },
    Enroll {
        spki: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Awaiting {
    Unlock,
    Confirmation,
    Presence { challenge: Vec<u8> },
}

impl Awaiting {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Unlock => "awaiting_unlock",
            Self::Confirmation => "awaiting_confirmation",
            Self::Presence { .. } => "awaiting_presence",
        }
    }
}

#[derive(Debug, Clone)]
struct Intent {
    id: String,
    digest: String,
    ts_session_id: u32,
    sid: String,
    logon_session_id: u64,
    requester: ObservedRequester,
    purpose: Purpose,
    expires_at_ms: u64,
    window_ends_ms: Option<u64>,
    state: Awaiting,
}

pub struct AuthorityCore {
    mode: RunMode,
    state_dir: PathBuf,
    policy: ClientPolicy,
    services: Services,
    state: PersistedState,
    intents: Vec<Intent>,
    audit: AuditChain,
}

fn observed(caller: &CallerFacts, role: CallerRole) -> Observed {
    Observed {
        caller_sid: caller.user_sid.clone(),
        logon_session_id: caller.logon_session_id,
        ts_session_id: caller.ts_session_id,
        caller_pid: caller.pid,
        caller_image: caller.image.clone(),
        role: role.as_str().to_owned(),
    }
}

fn check_field(name: &str, value: &str) -> Result<(), AuthorityError> {
    if value.is_empty() || value.len() > MAX_FIELD_BYTES || value.chars().any(char::is_control) {
        return Err(AuthorityError::invalid(format!(
            "{name} is 1 to 256 bytes without control characters"
        )));
    }
    Ok(())
}

fn is_lower_hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Writes `bytes` to `path` through a temporary file and a rename.
pub fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), AuthorityError> {
    use std::io::Write;
    let temp = path.with_extension("tmp");
    let result = std::fs::File::create(&temp)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&temp, path));
    result.map_err(|error| AuthorityError::internal(format!("write {}: {error}", path.display())))
}

impl AuthorityCore {
    /// Opens the authority's state in `state_dir`: verifies the audit
    /// chain, loads the state (refusing a missing state file while audit
    /// records exist), and records the start.
    pub fn open(
        mode: RunMode,
        state_dir: &Path,
        policy: ClientPolicy,
        services: Services,
    ) -> Result<Self, AuthorityError> {
        let audit = AuditChain::open(&state_dir.join(AUDIT_FILE))?;
        let state_path = state_dir.join(STATE_FILE);
        let state = if state_path.exists() {
            let text = std::fs::read_to_string(&state_path)
                .map_err(|error| AuthorityError::internal(format!("read the state: {error}")))?;
            let state: PersistedState = serde_json::from_str(&text)
                .map_err(|error| AuthorityError::internal(format!("parse the state: {error}")))?;
            if state.contract != STATE_CONTRACT || state.epoch == 0 {
                return Err(AuthorityError::internal(
                    "the state file is not an authority state",
                ));
            }
            state
        } else if audit.last_seq() > 0 {
            return Err(AuthorityError::internal(
                "the state file is missing while the audit chain has records; refusing to start with a reset epoch",
            ));
        } else {
            PersistedState::fresh()
        };
        let mut core = Self {
            mode,
            state_dir: state_dir.to_path_buf(),
            policy,
            services,
            state,
            intents: Vec::new(),
            audit,
        };
        core.persist()?;
        let detail = json!({
            "mode": mode.as_str(),
            "epoch": core.state.epoch,
            "revocations": core.state.revocations,
            "key_id": core.key_id(),
            "version": env!("CARGO_PKG_VERSION"),
        });
        core.audit_service("start", detail)?;
        Ok(core)
    }

    pub fn mode(&self) -> RunMode {
        self.mode
    }

    pub fn epoch(&self) -> u64 {
        self.state.epoch
    }

    pub fn revocations(&self) -> u64 {
        self.state.revocations
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.services.signer.public_key()
    }

    pub fn key_id(&self) -> String {
        key_id_of(&self.services.signer.public_key())
    }

    fn now(&self) -> u64 {
        (self.services.clock)()
    }

    fn persist(&self) -> Result<(), AuthorityError> {
        let text = serde_json::to_vec_pretty(&self.state)
            .map_err(|error| AuthorityError::internal(format!("encode the state: {error}")))?;
        write_atomically(&self.state_dir.join(STATE_FILE), &text)
    }

    fn random(&self, length: usize) -> Result<Vec<u8>, AuthorityError> {
        let mut out = vec![0u8; length];
        self.services.entropy.fill(&mut out)?;
        if out.iter().all(|b| *b == 0) {
            return Err(AuthorityError::internal("the random source returned zeros"));
        }
        Ok(out)
    }

    fn event(&self, event_id: u32, error: bool, text: &str) -> Result<(), AuthorityError> {
        self.services.events.record(event_id, error, text)
    }

    fn after_append(&self, record: &AuditRecord) -> Result<(), AuthorityError> {
        if AuditChain::anchor_due(record) {
            self.event(
                crate::EVENT_ANCHOR,
                false,
                &format!(
                    "orcel-anchor/1|authority|{}|{}|{}",
                    AUDIT_FILE, record.seq, record.digest
                ),
            )?;
        }
        Ok(())
    }

    fn audit(
        &mut self,
        kind: &str,
        asserted: Value,
        observed: Observed,
        detail: Value,
    ) -> Result<AuditRecord, AuthorityError> {
        let now = self.now();
        let record = self.audit.append(now, kind, asserted, observed, detail)?;
        self.after_append(&record)?;
        Ok(record)
    }

    fn audit_service(&mut self, kind: &str, detail: Value) -> Result<AuditRecord, AuthorityError> {
        self.audit(kind, Value::Null, Observed::service(), detail)
    }

    fn active_lease_in_session(&self, ts_session_id: u32, now: u64) -> bool {
        self.state.leases.iter().any(|record| {
            record.state == LeaseState::Active
                && record.lease.body.ts_session_id == ts_session_id
                && now < record.lease.body.expires_at_ms
                && record.lease.body.authority_epoch == self.state.epoch
        })
    }

    fn bound_to(caller: &CallerFacts, body: &LeaseBody) -> bool {
        body.windows_user_sid == caller.user_sid && body.logon_session_id == caller.logon_session_id
    }

    /// Handles one request from `caller`. Refusals of state-changing
    /// requests are audited too.
    pub fn handle(
        &mut self,
        caller: &CallerFacts,
        request: Request,
    ) -> Result<Value, AuthorityError> {
        let role = self.policy.classify(caller);
        let op = request.op();
        let result = self.dispatch(caller, role, request);
        if let Err(error) = &result {
            if !matches!(op, "status" | "intent_status") {
                let detail = json!({
                    "op": op,
                    "decision": "refused",
                    "code": error.code,
                    "message": error.message,
                });
                // A refusal is already the answer; a failed audit of it
                // cannot make it less refused.
                let _ = self.audit("decision", Value::Null, observed(caller, role), detail);
            }
        }
        result
    }

    fn dispatch(
        &mut self,
        caller: &CallerFacts,
        role: CallerRole,
        request: Request,
    ) -> Result<Value, AuthorityError> {
        match request {
            Request::Status => Ok(self.status(caller, role)),
            Request::GrantBegin {
                origin,
                scope,
                minutes,
                principal_id,
                task,
            } => self.grant_begin(caller, role, origin, scope, minutes, principal_id, task),
            Request::EnrollBegin {
                origin,
                public_key_spki_hex,
            } => self.enroll_begin(caller, role, origin, &public_key_spki_hex),
            Request::IntentStatus { intent_id } => self.intent_status(caller, &intent_id),
            Request::PresenceComplete {
                intent_id,
                signature_hex,
            } => self.presence_complete(caller, role, &intent_id, &signature_hex),
            Request::CancelIntent { intent_id } => self.cancel_intent(caller, role, &intent_id),
            Request::List => self.list(caller, role),
            Request::Verify { lease_id } => self.verify(caller, role, &lease_id),
            Request::Authorize {
                lease_id,
                executor,
                claims,
            } => self.authorize(caller, role, &lease_id, executor, claims),
            Request::Revoke { lease_id } => self.revoke(caller, role, &lease_id),
            Request::Stop => self.stop(caller, role),
        }
    }

    fn status(&self, caller: &CallerFacts, role: CallerRole) -> Value {
        json!({
            "protocol": PROTOCOL,
            "service": crate::SERVICE_NAME,
            "mode": self.mode.as_str(),
            "version": env!("CARGO_PKG_VERSION"),
            "epoch": self.state.epoch,
            "revocations": self.state.revocations,
            "key_id": self.key_id(),
            "public_key_hex": hex(&self.public_key()),
            "signature_algorithm": "ECDSA_P256_SHA256",
            "audit_seq": self.audit.last_seq(),
            "audit_head": self.audit.head(),
            "caller_role": role.as_str(),
            "caller_enrolled": self.state.enrolled.iter().any(|key| key.windows_user_sid == caller.user_sid),
            "can_issue": self.mode == RunMode::Service,
            "deferred": DEFERRED,
        })
    }

    fn require_owner_path(
        &self,
        role: CallerRole,
        origin: ClaimedOrigin,
    ) -> Result<(), AuthorityError> {
        match role {
            CallerRole::Interactive => {}
            CallerRole::Orceld => {
                return Err(AuthorityError::denied(
                    "orceld cannot ask for a grant: leases are issued only on the owner's path (agents, MCP and remote callers can never issue)",
                ))
            }
            CallerRole::Other => {
                return Err(AuthorityError::denied(
                    "grants are asked for only from an interactive logon in the active console session",
                ))
            }
        }
        if origin != ClaimedOrigin::OwnerCli {
            return Err(AuthorityError::denied(
                "agent, MCP, orceld and remote self-grant is denied; only the owner's CLI may record a grant intent",
            ));
        }
        Ok(())
    }

    fn drop_expired_intents(&mut self, now: u64) {
        let mut ended = Vec::new();
        self.intents.retain(|intent| {
            let window_over = intent.window_ends_ms.is_some_and(|end| now >= end);
            let unlock_over = intent.state == Awaiting::Unlock && now >= intent.expires_at_ms;
            if window_over || unlock_over {
                ended.push(intent.id.clone());
                false
            } else {
                true
            }
        });
        for id in ended {
            let _ = self.event(
                crate::EVENT_INTENT,
                false,
                &format!("orcel-intent/1|expired|{id}"),
            );
        }
    }

    fn pending_in_session(&self, ts_session_id: u32) -> bool {
        self.intents
            .iter()
            .any(|intent| intent.ts_session_id == ts_session_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn grant_begin(
        &mut self,
        caller: &CallerFacts,
        role: CallerRole,
        origin: ClaimedOrigin,
        scope: Option<LeaseScope>,
        minutes: Option<u64>,
        principal_id: String,
        task: String,
    ) -> Result<Value, AuthorityError> {
        self.require_owner_path(role, origin)?;
        let scope = scope.unwrap_or_else(LeaseScope::narrow_default);
        scope.validate()?;
        let minutes = minutes.unwrap_or(DEFAULT_LEASE_MINUTES);
        if !(MIN_LEASE_MINUTES..=MAX_LEASE_MINUTES).contains(&minutes) {
            return Err(AuthorityError::invalid("a lease lasts 1 to 720 minutes"));
        }
        check_field("principal_id", &principal_id)?;
        check_field("task", &task)?;
        if !self
            .state
            .enrolled
            .iter()
            .any(|key| key.windows_user_sid == caller.user_sid)
        {
            return Err(AuthorityError::denied(
                "no Windows Hello key credential is enrolled for this user; run the enrollment first",
            ));
        }
        let purpose = Purpose::Grant {
            scope,
            minutes,
            principal_id,
            task,
        };
        self.record_intent(caller, role, origin, purpose)
    }

    fn enroll_begin(
        &mut self,
        caller: &CallerFacts,
        role: CallerRole,
        origin: ClaimedOrigin,
        spki_hex: &str,
    ) -> Result<Value, AuthorityError> {
        self.require_owner_path(role, origin)?;
        if spki_hex.len() > 8192 {
            return Err(AuthorityError::invalid("the public key is too long"));
        }
        let spki =
            unhex(spki_hex).ok_or_else(|| AuthorityError::invalid("the public key is not hex"))?;
        self.services.presence.check_public_key(&spki)?;
        if self
            .state
            .enrolled
            .iter()
            .any(|key| key.windows_user_sid == caller.user_sid)
        {
            return Err(AuthorityError::denied(
                "a Windows Hello key credential is already enrolled for this user; replacing it needs an administrator reset (slice 1)",
            ));
        }
        self.record_intent(caller, role, origin, Purpose::Enroll { spki })
    }

    fn record_intent(
        &mut self,
        caller: &CallerFacts,
        role: CallerRole,
        origin: ClaimedOrigin,
        purpose: Purpose,
    ) -> Result<Value, AuthorityError> {
        let now = self.now();
        self.drop_expired_intents(now);
        if self.active_lease_in_session(caller.ts_session_id, now) {
            return Err(AuthorityError::denied(
                "a Full Control lease is active in this session; grants and renewals are refused until it ends",
            ));
        }
        if self.pending_in_session(caller.ts_session_id) {
            return Err(AuthorityError::denied(
                "an intent is already pending in this session; cancel it or wait until it expires",
            ));
        }
        let id = format!("in-{}", hex(&self.random(16)?));
        let (asserted, describe) = match &purpose {
            Purpose::Grant {
                scope,
                minutes,
                principal_id,
                task,
            } => (
                json!({
                    "origin": origin,
                    "scope": scope,
                    "minutes": minutes,
                    "principal_id": principal_id,
                    "task": task,
                }),
                format!(
                    "grant|{}|client {principal_id}|task {task}|{minutes} min",
                    scope.describe()
                ),
            ),
            Purpose::Enroll { spki } => (
                json!({ "origin": origin, "public_key_digest": sha256_hex(spki) }),
                format!("enroll|key {}", sha256_hex(spki)),
            ),
        };
        let digest = sha256_hex(
            format!(
                "{id}|{}|{}|{}|{}",
                caller.user_sid,
                caller.logon_session_id,
                caller.ts_session_id,
                serde_json::to_string(&asserted).unwrap_or_default()
            )
            .as_bytes(),
        );
        let expires_at_ms = now.saturating_add(INTENT_TTL_MS);
        self.audit(
            "intent",
            asserted,
            observed(caller, role),
            json!({ "intent_id": id, "intent_digest": digest, "expires_at_ms": expires_at_ms }),
        )?;
        self.event(
            crate::EVENT_INTENT,
            false,
            &format!(
                "orcel-intent/1|recorded|{id}|session {}|{describe}|expires {expires_at_ms}",
                caller.ts_session_id
            ),
        )?;
        self.intents.push(Intent {
            id: id.clone(),
            digest,
            ts_session_id: caller.ts_session_id,
            sid: caller.user_sid.clone(),
            logon_session_id: caller.logon_session_id,
            requester: ObservedRequester {
                pid: caller.pid,
                image: caller.image.clone(),
            },
            purpose,
            expires_at_ms,
            window_ends_ms: None,
            state: Awaiting::Unlock,
        });
        Ok(json!({
            "intent_id": id,
            "state": "awaiting_unlock",
            "expires_at_ms": expires_at_ms,
            "next": "Lock your PC (Win+L) and unlock it within 5 minutes; then read the Orcel Authority confirmation and approve only the scope you asked for.",
        }))
    }

    fn find_intent(&self, caller: &CallerFacts, intent_id: &str) -> Result<usize, AuthorityError> {
        self.intents
            .iter()
            .position(|intent| {
                intent.id == intent_id
                    && intent.sid == caller.user_sid
                    && intent.logon_session_id == caller.logon_session_id
            })
            .ok_or_else(|| AuthorityError::invalid("no such pending intent for this logon session"))
    }

    fn intent_status(
        &mut self,
        caller: &CallerFacts,
        intent_id: &str,
    ) -> Result<Value, AuthorityError> {
        let now = self.now();
        self.drop_expired_intents(now);
        let index = self.find_intent(caller, intent_id)?;
        let intent = &self.intents[index];
        let mut value = json!({
            "intent_id": intent.id,
            "state": intent.state.as_str(),
            "expires_at_ms": intent.expires_at_ms,
            "window_ends_ms": intent.window_ends_ms,
        });
        if let Awaiting::Presence { challenge } = &intent.state {
            value["challenge_hex"] = Value::String(hex(challenge));
        }
        Ok(value)
    }

    fn cancel_intent(
        &mut self,
        caller: &CallerFacts,
        role: CallerRole,
        intent_id: &str,
    ) -> Result<Value, AuthorityError> {
        let index = self.find_intent(caller, intent_id)?;
        let intent = self.intents.remove(index);
        self.audit(
            "intent",
            Value::Null,
            observed(caller, role),
            json!({ "intent_id": intent.id, "decision": "cancelled" }),
        )?;
        self.event(
            crate::EVENT_INTENT,
            false,
            &format!("orcel-intent/1|cancelled|{}", intent.id),
        )?;
        Ok(json!({ "intent_id": intent.id, "state": "cancelled" }))
    }

    /// Spec 4.13 step 2: a service-observed unlock of `ts_session_id`.
    /// Opens the window for that session's pending intent, if any, and
    /// returns the confirmation to render. Nothing opens without an intent.
    pub fn observe_unlock(&mut self, ts_session_id: u32) -> Option<ConfirmationTask> {
        let now = self.now();
        self.drop_expired_intents(now);
        let lease_active = self.active_lease_in_session(ts_session_id, now);
        let index = self.intents.iter().position(|intent| {
            intent.ts_session_id == ts_session_id && intent.state == Awaiting::Unlock
        })?;
        if lease_active {
            let intent = self.intents.remove(index);
            let _ = self.event(
                crate::EVENT_INTENT,
                false,
                &format!("orcel-intent/1|refused-lease-active|{}", intent.id),
            );
            return None;
        }
        let intent = &mut self.intents[index];
        intent.state = Awaiting::Confirmation;
        intent.window_ends_ms = Some(now.saturating_add(GRANT_WINDOW_MS));
        let text = confirmation_text(intent);
        let task = ConfirmationTask {
            intent_id: intent.id.clone(),
            ts_session_id,
            title: CONFIRMATION_TITLE.to_owned(),
            text,
            timeout_secs: CONFIRMATION_TIMEOUT_SECS,
        };
        let id = task.intent_id.clone();
        let _ = self.event(
            crate::EVENT_INTENT,
            false,
            &format!("orcel-intent/1|window-opened|{id}|session {ts_session_id}"),
        );
        Some(task)
    }

    /// Spec 4.13 step 4: the answer to a rendered confirmation.
    pub fn confirmation_answer(
        &mut self,
        intent_id: &str,
        answer: ConfirmAnswer,
    ) -> Result<(), AuthorityError> {
        let now = self.now();
        let Some(index) = self
            .intents
            .iter()
            .position(|intent| intent.id == intent_id && intent.state == Awaiting::Confirmation)
        else {
            return Err(AuthorityError::invalid(
                "no intent awaits this confirmation",
            ));
        };
        let in_window = self.intents[index]
            .window_ends_ms
            .is_some_and(|end| now < end);
        let detail = match &answer {
            ConfirmAnswer::Failed(reason) => format!("failed: {reason}"),
            other => other.as_str().to_owned(),
        };
        if answer == ConfirmAnswer::Yes && in_window {
            let nonce = self.random(32)?;
            let intent = &mut self.intents[index];
            let mut input = Vec::with_capacity(PRESENCE_DOMAIN.len() + 96);
            input.extend_from_slice(PRESENCE_DOMAIN);
            input.extend_from_slice(intent.digest.as_bytes());
            input.extend_from_slice(&nonce);
            let challenge = crate::unhex(&sha256_hex(&input)).unwrap_or_default();
            intent.state = Awaiting::Presence { challenge };
            self.audit_service(
                "intent",
                json!({ "intent_id": intent_id, "confirmation": "yes", "input_protected": false }),
            )?;
            self.event(
                crate::EVENT_INTENT,
                false,
                &format!("orcel-intent/1|confirmed-yes|{intent_id}|input-protected false"),
            )?;
            return Ok(());
        }
        let intent = self.intents.remove(index);
        let result = if in_window {
            detail
        } else {
            "window closed".to_owned()
        };
        self.audit_service(
            "intent",
            json!({ "intent_id": intent.id, "confirmation": result }),
        )?;
        self.event(
            crate::EVENT_INTENT,
            false,
            &format!(
                "orcel-intent/1|confirmation-{}|{}",
                answer.as_str(),
                intent.id
            ),
        )?;
        Ok(())
    }

    fn presence_complete(
        &mut self,
        caller: &CallerFacts,
        role: CallerRole,
        intent_id: &str,
        signature_hex: &str,
    ) -> Result<Value, AuthorityError> {
        if role == CallerRole::Orceld || role == CallerRole::Other {
            return Err(AuthorityError::denied(
                "presence is completed only on the owner's interactive path",
            ));
        }
        let now = self.now();
        self.drop_expired_intents(now);
        let index = self.find_intent(caller, intent_id)?;
        let Awaiting::Presence { challenge } = self.intents[index].state.clone() else {
            return Err(AuthorityError::denied(
                "this intent has no open grant window with a confirmed Yes; a grant needs a recorded intent, a service-observed unlock and the confirmation first",
            ));
        };
        // One attempt: the intent is consumed whatever the outcome.
        let intent = self.intents.remove(index);
        let signature = unhex(signature_hex)
            .filter(|bytes| !bytes.is_empty() && bytes.len() <= 1024)
            .ok_or_else(|| AuthorityError::invalid("the signature is not bounded hex"))?;
        match intent.purpose.clone() {
            Purpose::Enroll { spki } => {
                self.services
                    .presence
                    .verify(&spki, &challenge, &signature)?;
                let key = EnrolledKey {
                    windows_user_sid: intent.sid.clone(),
                    spki_hex: hex(&spki),
                    key_digest: sha256_hex(&spki),
                    enrolled_at_ms: now,
                };
                self.state
                    .enrolled
                    .retain(|k| k.windows_user_sid != intent.sid);
                self.state.enrolled.push(key.clone());
                self.persist()?;
                self.audit(
                    "enroll",
                    Value::Null,
                    observed(caller, role),
                    json!({ "intent_id": intent.id, "key_digest": key.key_digest }),
                )?;
                self.event(
                    crate::EVENT_INTENT,
                    false,
                    &format!(
                        "orcel-enroll/1|enrolled|{}|key {}",
                        intent.sid, key.key_digest
                    ),
                )?;
                Ok(json!({ "enrolled": true, "key_digest": key.key_digest }))
            }
            Purpose::Grant {
                scope,
                minutes,
                principal_id,
                task,
            } => {
                let key = self
                    .state
                    .enrolled
                    .iter()
                    .find(|key| key.windows_user_sid == intent.sid)
                    .cloned()
                    .ok_or_else(|| AuthorityError::denied("no enrolled presence key"))?;
                let spki = unhex(&key.spki_hex)
                    .ok_or_else(|| AuthorityError::internal("an enrolled key is not hex"))?;
                self.services
                    .presence
                    .verify(&spki, &challenge, &signature)?;
                if self.active_lease_in_session(intent.ts_session_id, now) {
                    return Err(AuthorityError::denied(
                        "a Full Control lease became active in this session; the grant is refused",
                    ));
                }
                let lease = self.issue(&intent, scope, minutes, principal_id, task, &key, now)?;
                Ok(json!({ "lease": lease }))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn issue(
        &mut self,
        intent: &Intent,
        scope: LeaseScope,
        minutes: u64,
        principal_id: String,
        task: String,
        key: &EnrolledKey,
        now: u64,
    ) -> Result<SignedLease, AuthorityError> {
        let lease_id = format!("{LEASE_ID_PREFIX}{}", hex(&self.random(16)?));
        let expires_at_ms = now
            .checked_add(minutes.saturating_mul(60_000))
            .ok_or_else(|| AuthorityError::invalid("lease expiry overflow"))?;
        let body = LeaseBody {
            contract: LEASE_CONTRACT.to_owned(),
            lease_id: lease_id.clone(),
            scope,
            windows_user_sid: intent.sid.clone(),
            logon_session_id: intent.logon_session_id,
            ts_session_id: intent.ts_session_id,
            principal_id,
            task,
            requester: intent.requester.clone(),
            authority_epoch: self.state.epoch,
            revocations_at_issue: self.state.revocations,
            issued_at_ms: now,
            expires_at_ms,
            key_id: self.key_id(),
            grant: GrantEvidence {
                intent_digest: intent.digest.clone(),
                confirmation: "service_rendered".to_owned(),
                confirmation_input_protected: false,
                presence: "windows_hello_key_credential".to_owned(),
                presence_key_digest: key.key_digest.clone(),
            },
        };
        let signature = self.services.signer.sign(&signing_input(&body)?)?;
        let lease = SignedLease {
            body,
            signature: hex(&signature),
        };
        self.state.leases.push(LeaseRecord {
            lease: lease.clone(),
            state: LeaseState::Active,
            ended_at_ms: None,
        });
        self.prune();
        self.persist()?;
        let caller_like = Observed {
            caller_sid: intent.sid.clone(),
            logon_session_id: intent.logon_session_id,
            ts_session_id: intent.ts_session_id,
            caller_pid: intent.requester.pid,
            caller_image: intent.requester.image.clone(),
            role: CallerRole::Interactive.as_str().to_owned(),
        };
        self.audit(
            "lease",
            json!({
                "principal_id": lease.body.principal_id,
                "task": lease.body.task,
                "scope": lease.body.scope,
            }),
            caller_like,
            json!({
                "decision": "issued",
                "lease_id": lease_id,
                "epoch": lease.body.authority_epoch,
                "expires_at_ms": expires_at_ms,
                "intent_id": intent.id,
            }),
        )?;
        self.event(
            crate::EVENT_GRANTED_SCOPE,
            false,
            &format!(
                "orcel-grant/1|{lease_id}|{}|client {}|task {}|user {} logon {} session {}|expires {expires_at_ms}|epoch {}",
                lease.body.scope.describe(),
                lease.body.principal_id,
                lease.body.task,
                lease.body.windows_user_sid,
                lease.body.logon_session_id,
                lease.body.ts_session_id,
                lease.body.authority_epoch
            ),
        )?;
        Ok(lease)
    }

    fn prune(&mut self) {
        while self.state.leases.len() > MAX_LEASE_RECORDS {
            match self
                .state
                .leases
                .iter()
                .position(|record| record.state != LeaseState::Active)
            {
                Some(index) => {
                    self.state.leases.remove(index);
                }
                None => break,
            }
        }
    }

    fn effective_state(&self, record: &LeaseRecord, now: u64) -> &'static str {
        match record.state {
            LeaseState::Revoked => "revoked",
            LeaseState::Stopped => "stopped",
            LeaseState::Expired => "expired",
            LeaseState::Active if now >= record.lease.body.expires_at_ms => "expired",
            LeaseState::Active if record.lease.body.authority_epoch != self.state.epoch => {
                "epoch_moved"
            }
            LeaseState::Active => "active",
        }
    }

    fn require_known(role: CallerRole, caller: &CallerFacts) -> Result<(), AuthorityError> {
        if caller.user_sid.is_empty() || caller.logon_session_id == 0 {
            return Err(AuthorityError::denied(
                "the caller's identity could not be read",
            ));
        }
        let _ = role;
        Ok(())
    }

    fn list(&mut self, caller: &CallerFacts, role: CallerRole) -> Result<Value, AuthorityError> {
        if role == CallerRole::Other {
            return Err(AuthorityError::denied(
                "listing leases needs an interactive caller or orceld",
            ));
        }
        let now = self.now();
        let leases: Vec<Value> = self
            .state
            .leases
            .iter()
            .filter(|record| Self::bound_to(caller, &record.lease.body))
            .map(|record| {
                json!({
                    "lease": record.lease,
                    "state": self.effective_state(record, now),
                    "ended_at_ms": record.ended_at_ms,
                })
            })
            .collect();
        Ok(json!({
            "epoch": self.state.epoch,
            "revocations": self.state.revocations,
            "leases": leases,
        }))
    }

    fn find_lease(&self, caller: &CallerFacts, lease_id: &str) -> Result<usize, AuthorityError> {
        self.state
            .leases
            .iter()
            .position(|record| {
                record.lease.body.lease_id == lease_id && Self::bound_to(caller, &record.lease.body)
            })
            .ok_or_else(|| {
                AuthorityError::lease_invalid(
                    "no such lease bound to this Windows user and logon session",
                )
            })
    }

    fn active_lease(
        &self,
        caller: &CallerFacts,
        lease_id: &str,
        now: u64,
    ) -> Result<usize, AuthorityError> {
        let index = self.find_lease(caller, lease_id)?;
        let record = &self.state.leases[index];
        let state = self.effective_state(record, now);
        if state != "active" {
            return Err(AuthorityError::lease_invalid(format!(
                "the lease is {state}"
            )));
        }
        record.lease.body.check(&LeaseContext {
            windows_user_sid: &caller.user_sid,
            logon_session_id: caller.logon_session_id,
            authority_epoch: self.state.epoch,
            now_ms: now,
        })?;
        Ok(index)
    }

    fn verify(
        &mut self,
        caller: &CallerFacts,
        role: CallerRole,
        lease_id: &str,
    ) -> Result<Value, AuthorityError> {
        Self::require_known(role, caller)?;
        if role == CallerRole::Other {
            return Err(AuthorityError::denied(
                "verifying a lease needs an interactive caller or orceld",
            ));
        }
        let now = self.now();
        let index = self.active_lease(caller, lease_id, now)?;
        let lease = self.state.leases[index].lease.clone();
        self.audit(
            "verify",
            Value::Null,
            observed(caller, role),
            json!({ "lease_id": lease_id, "decision": "active", "epoch": self.state.epoch }),
        )?;
        Ok(json!({
            "lease": lease,
            "state": "active",
            "epoch": self.state.epoch,
            "revocations": self.state.revocations,
            "checked_at_ms": now,
        }))
    }

    fn authorize(
        &mut self,
        caller: &CallerFacts,
        role: CallerRole,
        lease_id: &str,
        executor: ExecutorClass,
        claims: AuthorizeClaims,
    ) -> Result<Value, AuthorityError> {
        if role != CallerRole::Orceld {
            return Err(AuthorityError::denied(
                "only orceld (a configured trusted image) may ask for Authorize",
            ));
        }
        if executor == ExecutorClass::Admin {
            return Err(AuthorityError::denied(
                "the Admin executor is refused: the authority service never elevates (SG-000098)",
            ));
        }
        for (name, value) in [
            ("request_id", &claims.request_id),
            ("capability", &claims.capability),
            ("operation", &claims.operation),
            ("principal_id", &claims.principal_id),
            ("task", &claims.task),
        ] {
            check_field(name, value)?;
        }
        if !is_lower_hex(&claims.action_digest, 64) {
            return Err(AuthorityError::invalid(
                "action_digest is a SHA-256 in lowercase hex",
            ));
        }
        let now = self.now();
        let index = self.active_lease(caller, lease_id, now)?;
        let body = self.state.leases[index].lease.body.clone();
        if !body.scope.admits(executor) {
            return Err(AuthorityError::denied(format!(
                "the lease does not cover the {} executor",
                crate::lease::executor_name(executor)
            )));
        }
        if claims.principal_id != body.principal_id {
            return Err(AuthorityError::denied(
                "the lease was granted to another client principal",
            ));
        }
        let authorization_id = format!("az-{}", hex(&self.random(16)?));
        // Write before dispatch: the record is on disk before the answer.
        self.audit(
            "authorize",
            json!({
                "request_id": claims.request_id,
                "capability": claims.capability,
                "operation": claims.operation,
                "principal_id": claims.principal_id,
                "task": claims.task,
                "action_digest": claims.action_digest,
                "executor": executor,
            }),
            observed(caller, role),
            json!({
                "decision": "allow",
                "authorization_id": authorization_id,
                "lease_id": lease_id,
                "epoch": self.state.epoch,
                "job_name": Value::Null,
            }),
        )?;
        Ok(json!({
            "authorization_id": authorization_id,
            "lease_id": lease_id,
            "epoch": self.state.epoch,
            "revocations": self.state.revocations,
            "job_name": Value::Null,
            "deferred": DEFERRED,
        }))
    }

    fn end_lease(&mut self, index: usize, state: LeaseState, now: u64) {
        let record = &mut self.state.leases[index];
        record.state = state;
        record.ended_at_ms = Some(now);
    }

    fn revoke(
        &mut self,
        caller: &CallerFacts,
        role: CallerRole,
        lease_id: &str,
    ) -> Result<Value, AuthorityError> {
        Self::require_known(role, caller)?;
        let now = self.now();
        let index = self.find_lease(caller, lease_id)?;
        if self.state.leases[index].state != LeaseState::Active {
            return Err(AuthorityError::lease_invalid("the lease has already ended"));
        }
        self.end_lease(index, LeaseState::Revoked, now);
        self.state.revocations = self.state.revocations.saturating_add(1);
        self.persist()?;
        self.audit(
            "lease",
            Value::Null,
            observed(caller, role),
            json!({ "decision": "revoked", "lease_id": lease_id, "revocations": self.state.revocations }),
        )?;
        Ok(
            json!({ "lease_id": lease_id, "state": "revoked", "revocations": self.state.revocations }),
        )
    }

    fn advance_epoch(&mut self) -> Result<(), AuthorityError> {
        self.state.epoch = self
            .state
            .epoch
            .checked_add(1)
            .ok_or_else(|| AuthorityError::internal("the authority epoch is exhausted"))?;
        self.state.revocations = self.state.revocations.saturating_add(1);
        Ok(())
    }

    fn stop(&mut self, caller: &CallerFacts, role: CallerRole) -> Result<Value, AuthorityError> {
        Self::require_known(role, caller)?;
        let now = self.now();
        let mut ended = Vec::new();
        for index in 0..self.state.leases.len() {
            if self.state.leases[index].state == LeaseState::Active
                && Self::bound_to(caller, &self.state.leases[index].lease.body)
            {
                ended.push(self.state.leases[index].lease.body.lease_id.clone());
                self.end_lease(index, LeaseState::Stopped, now);
            }
        }
        self.intents.retain(|intent| {
            !(intent.sid == caller.user_sid && intent.logon_session_id == caller.logon_session_id)
        });
        self.advance_epoch()?;
        self.persist()?;
        self.audit(
            "emergency_stop",
            Value::Null,
            observed(caller, role),
            json!({
                "trigger": "stop_request",
                "ended": ended,
                "epoch": self.state.epoch,
                "revocations": self.state.revocations,
            }),
        )?;
        Ok(json!({
            "stopped": true,
            "ended": ended,
            "epoch": self.state.epoch,
            "revocations": self.state.revocations,
        }))
    }

    /// Spec C-28: session lock, sign-out or disconnect of `ts_session_id`
    /// (`reason` names which). A lock keeps an intent that still awaits
    /// its unlock (the grant flow itself locks the session) and ends
    /// everything else of that session.
    pub fn session_ended(
        &mut self,
        ts_session_id: u32,
        reason: &str,
        lock: bool,
    ) -> Result<(), AuthorityError> {
        let now = self.now();
        let mut ended = Vec::new();
        for index in 0..self.state.leases.len() {
            if self.state.leases[index].state == LeaseState::Active
                && self.state.leases[index].lease.body.ts_session_id == ts_session_id
            {
                ended.push(self.state.leases[index].lease.body.lease_id.clone());
                self.end_lease(index, LeaseState::Stopped, now);
            }
        }
        self.intents.retain(|intent| {
            intent.ts_session_id != ts_session_id || (lock && intent.state == Awaiting::Unlock)
        });
        if ended.is_empty() {
            return Ok(());
        }
        self.advance_epoch()?;
        self.persist()?;
        self.audit_service(
            "emergency_stop",
            json!({
                "trigger": reason,
                "ts_session_id": ts_session_id,
                "ended": ended,
                "epoch": self.state.epoch,
                "revocations": self.state.revocations,
            }),
        )?;
        Ok(())
    }

    /// Expiry: ends expired leases (advancing the epoch, C-28) and drops
    /// expired intents. The service calls it every second.
    pub fn tick(&mut self) -> Result<(), AuthorityError> {
        let now = self.now();
        self.drop_expired_intents(now);
        let mut ended = Vec::new();
        for index in 0..self.state.leases.len() {
            if self.state.leases[index].state == LeaseState::Active
                && now >= self.state.leases[index].lease.body.expires_at_ms
            {
                ended.push(self.state.leases[index].lease.body.lease_id.clone());
                self.end_lease(index, LeaseState::Expired, now);
            }
        }
        if ended.is_empty() {
            return Ok(());
        }
        self.advance_epoch()?;
        self.persist()?;
        self.audit_service(
            "emergency_stop",
            json!({
                "trigger": "expiry",
                "ended": ended,
                "epoch": self.state.epoch,
                "revocations": self.state.revocations,
            }),
        )?;
        Ok(())
    }

    /// Records the service's shutdown in the chain (and anchors it).
    pub fn shutdown(&mut self) -> Result<(), AuthorityError> {
        self.audit_service(
            "start",
            json!({ "event": "shutdown", "epoch": self.state.epoch }),
        )
        .map(|_| ())
    }
}

fn confirmation_text(intent: &Intent) -> String {
    let warning = "Full Control acts with your Windows rights. Effects made through Windows outside Orcel's process trees (scheduled tasks, other programs) can persist after Stop, and Orcel cannot undo them. A program running as you can record a request like this and lock your PC, and can draw windows that imitate this one: if you did not just ask for exactly this, choose No. Biometric Windows Hello is recommended; a PIN can be observed by programs running as you.";
    match &intent.purpose {
        Purpose::Grant {
            scope,
            minutes,
            principal_id,
            task,
        } => format!(
            "A program asked for Orcel Full Control. Approve only if you asked for exactly this:\n\nScope: {}\nClient: {principal_id}\nTask: {task}\nExpires: {minutes} minutes after approval\nRequested by: process {} {}\n\n{warning}\n\nApprove this grant?",
            scope.describe(),
            intent.requester.pid,
            intent.requester.image
        ),
        Purpose::Enroll { spki } => format!(
            "A program asked to enroll a Windows Hello key for Orcel Authority. After this, grants of Orcel Full Control for your account are confirmed with that key.\n\nKey fingerprint: {}\nRequested by: process {} {}\n\n{warning}\n\nEnroll this key?",
            &sha256_hex(spki)[..32],
            intent.requester.pid,
            intent.requester.image
        ),
    }
}
