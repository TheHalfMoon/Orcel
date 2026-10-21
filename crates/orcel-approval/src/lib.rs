pub use orcel_contracts::FailureCode;
pub use orcel_platform::PlatformError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// XP-09: the macOS SOFT dialog and STRONG presence; XP-10: Linux. Each OS's
// presenter and verifier lives in its own module and is selected below by
// cfg, without touching the Windows path. Linux shares the session states
// and the escaper of the macOS modules. Other OSes compile these modules
// only into tests, which run their pure rules (session classification,
// escaping, helper protocol, outcome mapping) everywhere.
#[cfg(any(target_os = "linux", test))]
mod linux;
#[cfg(any(target_os = "macos", target_os = "linux", test))]
mod presence_unix;
#[cfg(any(target_os = "macos", target_os = "linux", test))]
mod soft_macos;

/// The Linux helper's own protocol module, so tests on every OS check that
/// orceld and the helper agree.
#[cfg(test)]
#[path = "../../../apps/orcel-approval-helper-linux/src/protocol.rs"]
mod linux_helper_protocol;

#[cfg(target_os = "linux")]
pub use linux::{PolkitPresenceVerifier, POLKIT_ACTION_ID, POLKIT_PRESENCE_METHOD};
#[cfg(target_os = "macos")]
pub use presence_unix::{MacLocalAuthPresenceVerifier, MAC_LOCAL_AUTH_METHOD};

pub const APPROVAL_TTL_MS: u64 = 5 * 60 * 1_000;
pub const SINGLE_OPERATION_SCOPE: &str = "single-operation";
pub const STRONG_VERIFY_TIMEOUT_MS: u64 = 120_000;
const LEDGER_SCHEMA: &str = "orcel-approval-ledger-v3";

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalClass {
    #[serde(rename = "SOFT")]
    Soft,
    #[serde(rename = "STRONG")]
    Strong,
}

impl ApprovalClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalClass::Soft => "SOFT",
            ApprovalClass::Strong => "STRONG",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresenceOutcome {
    #[serde(rename = "soft-approved")]
    SoftApproved,
    #[serde(rename = "verified-strong")]
    VerifiedStrong,
    #[serde(rename = "denied")]
    Denied,
    #[serde(rename = "unavailable")]
    Unavailable,
}

impl PresenceOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            PresenceOutcome::SoftApproved => "soft-approved",
            PresenceOutcome::VerifiedStrong => "verified-strong",
            PresenceOutcome::Denied => "denied",
            PresenceOutcome::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceContext {
    pub nonce: String,
    pub digest: String,
    pub workspace_id: String,
    pub action: String,
    /// The request's target and summary, for verifiers that show the whole
    /// request before asking for presence (Linux, XP-10). Empty unless set
    /// with [`PresenceContext::with_details`].
    pub target: String,
    pub summary: String,
}

impl PresenceContext {
    pub fn new(
        nonce: impl Into<String>,
        digest: impl Into<String>,
        workspace_id: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self {
            nonce: nonce.into(),
            digest: digest.into(),
            workspace_id: workspace_id.into(),
            action: action.into(),
            target: String::new(),
            summary: String::new(),
        }
    }

    pub fn with_details(mut self, target: impl Into<String>, summary: impl Into<String>) -> Self {
        self.target = target.into();
        self.summary = summary.into();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceAttestation {
    pub method: String,
    pub verified_at_ms: u64,
    pub nonce: String,
    pub digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceFailureReason {
    Denied,
    Cancelled,
    Timeout,
    Unavailable,
    Failed,
    InvalidResponse,
}

#[derive(Debug, Clone)]
pub struct PresenceError {
    pub code: FailureCode,
    pub message: String,
    pub reason: PresenceFailureReason,
}

impl PresenceError {
    pub fn denied(message: impl Into<String>) -> Self {
        Self {
            code: FailureCode::ApprovalDenied,
            message: message.into(),
            reason: PresenceFailureReason::Denied,
        }
    }

    pub fn cancelled(message: impl Into<String>) -> Self {
        Self {
            code: FailureCode::ApprovalDenied,
            message: message.into(),
            reason: PresenceFailureReason::Cancelled,
        }
    }

    pub fn timeout(message: impl Into<String>) -> Self {
        Self {
            code: FailureCode::ApprovalUnavailable,
            message: message.into(),
            reason: PresenceFailureReason::Timeout,
        }
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            code: FailureCode::ApprovalUnavailable,
            message: message.into(),
            reason: PresenceFailureReason::Unavailable,
        }
    }

    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            code: FailureCode::ApprovalUnavailable,
            message: message.into(),
            reason: PresenceFailureReason::Failed,
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: FailureCode::ApprovalUnavailable,
            message: message.into(),
            reason: PresenceFailureReason::InvalidResponse,
        }
    }
}

#[derive(Debug)]
pub struct InputLeaseGuard {
    suspended: bool,
}

impl InputLeaseGuard {
    pub(crate) fn suspend_for_presence() -> Self {
        Self { suspended: true }
    }

    pub fn is_suspended(&self) -> bool {
        self.suspended
    }
}

impl Drop for InputLeaseGuard {
    fn drop(&mut self) {
        self.suspended = false;
    }
}

pub trait PresenceVerifier: Send + Sync + std::fmt::Debug {
    fn method(&self) -> &'static str;
    fn is_available(&self) -> bool;
    fn verify(
        &self,
        ctx: &PresenceContext,
        lease: &InputLeaseGuard,
    ) -> Result<PresenceAttestation, PresenceError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoPresenceVerifier;

impl PresenceVerifier for NoPresenceVerifier {
    fn method(&self) -> &'static str {
        "none"
    }

    fn is_available(&self) -> bool {
        false
    }

    fn verify(
        &self,
        _ctx: &PresenceContext,
        _lease: &InputLeaseGuard,
    ) -> Result<PresenceAttestation, PresenceError> {
        Err(PresenceError::unavailable(
            "strong user-presence verification is unavailable on this platform; STRONG approval fails closed without SOFT downgrade",
        ))
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsHelloPresenceVerifier;

#[cfg(windows)]
impl WindowsHelloPresenceVerifier {
    pub fn new() -> Self {
        Self
    }

    fn hello_availability(&self) -> bool {
        if std::env::var("CI").is_ok() || std::env::var("GITHUB_ACTIONS").is_ok() {
            return false;
        }
        check_hello_availability()
    }
}

#[cfg(windows)]
impl PresenceVerifier for WindowsHelloPresenceVerifier {
    fn method(&self) -> &'static str {
        "windows-hello"
    }

    fn is_available(&self) -> bool {
        self.hello_availability()
    }

    fn verify(
        &self,
        ctx: &PresenceContext,
        lease: &InputLeaseGuard,
    ) -> Result<PresenceAttestation, PresenceError> {
        if !lease.is_suspended() {
            return Err(PresenceError::invalid(
                "strong verification requires a suspended input lease",
            ));
        }
        if ctx.nonce.trim().is_empty() || ctx.digest.trim().is_empty() {
            return Err(PresenceError::invalid(
                "strong verification context is malformed",
            ));
        }
        if !self.hello_availability() {
            return Err(PresenceError::unavailable(
                "Windows Hello verification is unavailable; STRONG approval fails closed",
            ));
        }
        verify_with_hello(ctx, self.method())
    }
}

#[cfg(windows)]
fn check_hello_availability() -> bool {
    use windows::Security::Credentials::UI::UserConsentVerifier;
    let result = (|| -> windows::core::Result<bool> {
        let operation = UserConsentVerifier::CheckAvailabilityAsync()?;
        let availability = operation.get()?;
        Ok(availability
            == windows::Security::Credentials::UI::UserConsentVerifierAvailability::Available)
    })();
    result.unwrap_or(false)
}

#[cfg(windows)]
fn verify_with_hello(
    ctx: &PresenceContext,
    method: &'static str,
) -> Result<PresenceAttestation, PresenceError> {
    use std::sync::mpsc::channel;
    use std::time::Duration;
    use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};

    let nonce_prefix: String = ctx.nonce.chars().take(8).collect();
    let digest_prefix: String = ctx.digest.chars().take(12).collect();
    let message = format!(
        "Orcel STRONG approval {nonce_prefix} {digest_prefix} for {} in workspace {}",
        ctx.action, ctx.workspace_id
    );
    let nonce = ctx.nonce.clone();
    let digest = ctx.digest.clone();
    let (sender, receiver) = channel();
    std::thread::spawn(move || {
        let outcome = (|| -> windows::core::Result<UserConsentVerificationResult> {
            let operation = UserConsentVerifier::RequestVerificationAsync(&message.clone().into())?;
            operation.get()
        })();
        let _ = sender.send(outcome);
    });
    let outcome = receiver
        .recv_timeout(Duration::from_millis(STRONG_VERIFY_TIMEOUT_MS))
        .map_err(|_| {
            PresenceError::timeout(
                "strong user-presence verification timed out; STRONG approval fails closed",
            )
        })?;
    let result = outcome.map_err(|_| {
        PresenceError::failed("Windows Hello verification failed; STRONG approval fails closed")
    })?;
    match result {
        UserConsentVerificationResult::Verified => Ok(PresenceAttestation {
            method: method.to_owned(),
            verified_at_ms: now_ms(),
            nonce,
            digest,
        }),
        UserConsentVerificationResult::DeviceNotPresent
        | UserConsentVerificationResult::NotConfiguredForUser
        | UserConsentVerificationResult::DisabledByPolicy
        | UserConsentVerificationResult::DeviceBusy => Err(PresenceError::unavailable(
            "Windows Hello is not configured for this device; STRONG approval fails closed",
        )),
        UserConsentVerificationResult::Canceled => Err(PresenceError::cancelled(
            "strong user-presence verification was cancelled; STRONG approval fails closed",
        )),
        UserConsentVerificationResult::RetriesExhausted => Err(PresenceError::denied(
            "strong user-presence verification retries exhausted; STRONG approval fails closed",
        )),
        _ => Err(PresenceError::invalid(
            "Windows Hello returned an unexpected result; STRONG approval fails closed",
        )),
    }
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub type DefaultPresenceVerifier = NoPresenceVerifier;

#[cfg(target_os = "linux")]
pub type DefaultPresenceVerifier = PolkitPresenceVerifier;

#[cfg(target_os = "macos")]
pub type DefaultPresenceVerifier = MacLocalAuthPresenceVerifier;

#[cfg(windows)]
pub type DefaultPresenceVerifier = WindowsHelloPresenceVerifier;

fn default_presence_verifier() -> Arc<dyn PresenceVerifier> {
    Arc::new(DefaultPresenceVerifier::default())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPrompt {
    pub workspace_id: String,
    pub policy_revision: String,
    pub action: String,
    pub target: String,
    pub summary: String,
    pub digest: String,
    pub nonce: String,
    pub requested_at_ms: u64,
    pub expires_at_ms: u64,
    pub reuse_scope: String,
    pub approval_class: ApprovalClass,
}

impl ApprovalPrompt {
    pub fn new(
        workspace_id: impl Into<String>,
        policy_revision: impl Into<String>,
        action: impl Into<String>,
        target: impl Into<String>,
        summary: impl Into<String>,
        digest: impl Into<String>,
    ) -> Self {
        Self::new_with_clock(
            workspace_id,
            policy_revision,
            action,
            target,
            summary,
            digest,
            now_ms(),
        )
    }

    pub fn new_with_clock(
        workspace_id: impl Into<String>,
        policy_revision: impl Into<String>,
        action: impl Into<String>,
        target: impl Into<String>,
        summary: impl Into<String>,
        digest: impl Into<String>,
        now_ms: u64,
    ) -> Self {
        Self::new_with_class_and_clock(
            workspace_id,
            policy_revision,
            action,
            target,
            summary,
            digest,
            ApprovalClass::Soft,
            now_ms,
        )
    }

    pub fn new_strong(
        workspace_id: impl Into<String>,
        policy_revision: impl Into<String>,
        action: impl Into<String>,
        target: impl Into<String>,
        summary: impl Into<String>,
        digest: impl Into<String>,
    ) -> Self {
        Self::new_strong_with_clock(
            workspace_id,
            policy_revision,
            action,
            target,
            summary,
            digest,
            now_ms(),
        )
    }

    pub fn new_strong_with_clock(
        workspace_id: impl Into<String>,
        policy_revision: impl Into<String>,
        action: impl Into<String>,
        target: impl Into<String>,
        summary: impl Into<String>,
        digest: impl Into<String>,
        now_ms: u64,
    ) -> Self {
        Self::new_with_class_and_clock(
            workspace_id,
            policy_revision,
            action,
            target,
            summary,
            digest,
            ApprovalClass::Strong,
            now_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_class_and_clock(
        workspace_id: impl Into<String>,
        policy_revision: impl Into<String>,
        action: impl Into<String>,
        target: impl Into<String>,
        summary: impl Into<String>,
        digest: impl Into<String>,
        approval_class: ApprovalClass,
        now_ms: u64,
    ) -> Self {
        let digest = digest.into();
        Self {
            workspace_id: workspace_id.into(),
            policy_revision: policy_revision.into(),
            action: action.into(),
            target: target.into(),
            summary: summary.into(),
            nonce: fresh_nonce(&digest, now_ms),
            requested_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(APPROVAL_TTL_MS),
            reuse_scope: SINGLE_OPERATION_SCOPE.to_owned(),
            digest,
            approval_class,
        }
    }

    pub fn with_class(mut self, approval_class: ApprovalClass) -> Self {
        let now = self.requested_at_ms;
        self.nonce = fresh_nonce(&self.digest, now);
        self.approval_class = approval_class;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approved,
    Denied,
}

#[derive(Debug, Clone)]
pub struct ApprovalError {
    pub code: FailureCode,
    pub message: String,
}

impl ApprovalError {
    fn denied(message: impl Into<String>) -> Self {
        Self {
            code: FailureCode::ApprovalDenied,
            message: message.into(),
        }
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            code: FailureCode::ApprovalUnavailable,
            message: message.into(),
        }
    }

    fn stale(message: impl Into<String>) -> Self {
        Self {
            code: FailureCode::TargetStale,
            message: message.into(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: FailureCode::InvalidRequest,
            message: message.into(),
        }
    }
}

impl From<PresenceError> for ApprovalError {
    fn from(error: PresenceError) -> Self {
        Self {
            code: error.code,
            message: error.message,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedToken {
    pub record_id: String,
    pub nonce: String,
    pub digest: String,
    pub workspace_id: String,
    pub policy_revision: String,
    pub expires_at_ms: u64,
    pub approval_class: ApprovalClass,
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumeExpectation {
    pub digest: String,
    pub workspace_id: String,
    pub policy_revision: String,
    pub approval_class: ApprovalClass,
}

impl ConsumeExpectation {
    pub fn new(
        digest: impl Into<String>,
        workspace_id: impl Into<String>,
        policy_revision: impl Into<String>,
    ) -> Self {
        Self {
            digest: digest.into(),
            workspace_id: workspace_id.into(),
            policy_revision: policy_revision.into(),
            approval_class: ApprovalClass::Soft,
        }
    }

    pub fn new_with_class(
        digest: impl Into<String>,
        workspace_id: impl Into<String>,
        policy_revision: impl Into<String>,
        approval_class: ApprovalClass,
    ) -> Self {
        Self {
            digest: digest.into(),
            workspace_id: workspace_id.into(),
            policy_revision: policy_revision.into(),
            approval_class,
        }
    }

    pub fn strong(
        digest: impl Into<String>,
        workspace_id: impl Into<String>,
        policy_revision: impl Into<String>,
    ) -> Self {
        Self::new_with_class(digest, workspace_id, policy_revision, ApprovalClass::Strong)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordedDecision {
    Approved,
    Denied,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRecord {
    schema: String,
    id: String,
    nonce: String,
    digest: String,
    workspace_id: String,
    policy_revision: String,
    decision: RecordedDecision,
    approval_class: ApprovalClass,
    presence_outcome: PresenceOutcome,
    presence_method: String,
    epoch: u64,
    is_revoke: bool,
    requested_at_ms: u64,
    decided_at_ms: u64,
    expires_at_ms: u64,
    reuse_scope: String,
    consumed: bool,
    prev_checksum: String,
    checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRecordSummary {
    pub id: String,
    pub digest: String,
    pub workspace_id: String,
    pub policy_revision: String,
    pub decision: RecordedDecision,
    pub approval_class: ApprovalClass,
    pub presence_outcome: PresenceOutcome,
    pub presence_method: String,
    pub epoch: u64,
    pub is_revoke: bool,
    pub requested_at_ms: u64,
    pub decided_at_ms: u64,
    pub expires_at_ms: u64,
    pub reuse_scope: String,
    pub consumed: bool,
}

pub trait ApprovalBroker {
    fn request_token(&self, prompt: &ApprovalPrompt) -> Result<ApprovedToken, ApprovalError>;

    fn consume(
        &self,
        token: &ApprovedToken,
        expected: &ConsumeExpectation,
        now_ms: u64,
    ) -> Result<(), ApprovalError>;

    fn emergency_revoke(&self, _prompt: &ApprovalPrompt) -> Result<u64, ApprovalError> {
        Err(ApprovalError::unavailable(
            "emergency revoke is unavailable through this broker",
        ))
    }

    fn request(&self, prompt: &ApprovalPrompt) -> Result<ApprovalDecision, ApprovalError> {
        let token = self.request_token(prompt)?;
        let expected = ConsumeExpectation::new_with_class(
            prompt.digest.clone(),
            prompt.workspace_id.clone(),
            prompt.policy_revision.clone(),
            prompt.approval_class,
        );
        self.consume(&token, &expected, now_ms())?;
        Ok(ApprovalDecision::Approved)
    }

    fn history(&self, _limit: usize) -> Vec<ApprovalRecordSummary> {
        Vec::new()
    }
}

#[derive(Debug)]
pub struct LocalApprovalBroker {
    ledger: Mutex<ApprovalLedger>,
    presence: Arc<dyn PresenceVerifier>,
    /// Test builds only: decides the SOFT consent instead of the system
    /// dialog. Everything else (ledger, nonce, expiry, single use, records)
    /// is the real broker.
    #[cfg(any(test, feature = "test-support"))]
    soft_decider: Option<SoftDeciderHandle>,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone)]
struct SoftDeciderHandle(Arc<SoftDecider>);

#[cfg(any(test, feature = "test-support"))]
impl std::fmt::Debug for SoftDeciderHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SoftDecider(test)")
    }
}

/// Test builds only: the SOFT consent a scripted test gives.
#[cfg(any(test, feature = "test-support"))]
pub type SoftDecider = dyn Fn(&ApprovalPrompt) -> ApprovalDecision + Send + Sync;

impl LocalApprovalBroker {
    /// The broker over the default ledger. Fails with `ApprovalUnavailable`
    /// when the default location cannot be resolved, rather than recording
    /// approvals anywhere else.
    pub fn new() -> Result<Self, ApprovalError> {
        let path = default_approval_history_path().map_err(history_path_unavailable)?;
        Ok(Self::with_path(path))
    }

    pub fn with_path(path: impl Into<std::path::PathBuf>) -> Self {
        Self::with_path_and_verifier(path, default_presence_verifier())
    }

    pub fn with_presence_verifier(
        presence: Arc<dyn PresenceVerifier>,
    ) -> Result<Self, ApprovalError> {
        let path = default_approval_history_path().map_err(history_path_unavailable)?;
        Ok(Self::with_path_and_verifier(path, presence))
    }

    pub fn with_path_and_verifier(
        path: impl Into<std::path::PathBuf>,
        presence: Arc<dyn PresenceVerifier>,
    ) -> Self {
        let ledger = ApprovalLedger::load_or_create(path.into());
        Self {
            ledger: Mutex::new(ledger),
            presence,
            #[cfg(any(test, feature = "test-support"))]
            soft_decider: None,
        }
    }

    /// Test builds only: the real broker over the ledger at `path`, with
    /// the SOFT consent decided by `decider` instead of the system dialog.
    /// STRONG approvals still require the presence verifier.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_path_and_soft_decider(
        path: impl Into<std::path::PathBuf>,
        presence: Arc<dyn PresenceVerifier>,
        decider: Arc<SoftDecider>,
    ) -> Self {
        let mut broker = Self::with_path_and_verifier(path, presence);
        broker.soft_decider = Some(SoftDeciderHandle(decider));
        broker
    }

    pub fn presence_method(&self) -> &'static str {
        self.presence.method()
    }

    pub fn presence_available(&self) -> bool {
        self.presence.is_available()
    }

    pub fn history(&self, limit: usize) -> Vec<ApprovalRecordSummary> {
        self.ledger
            .lock()
            .map(|mut ledger| ledger.history(limit))
            .unwrap_or_default()
    }
}

impl ApprovalBroker for LocalApprovalBroker {
    fn request_token(&self, prompt: &ApprovalPrompt) -> Result<ApprovedToken, ApprovalError> {
        validate_prompt(prompt)?;
        match prompt.approval_class {
            ApprovalClass::Soft => self.request_soft_token(prompt),
            ApprovalClass::Strong => self.request_strong_token(prompt),
        }
    }

    fn consume(
        &self,
        token: &ApprovedToken,
        expected: &ConsumeExpectation,
        now_ms: u64,
    ) -> Result<(), ApprovalError> {
        self.ledger
            .lock()
            .map_err(|_| ApprovalError::unavailable("approval ledger is unavailable"))?
            .consume(token, expected, now_ms)
    }

    fn history(&self, limit: usize) -> Vec<ApprovalRecordSummary> {
        Self::history(self, limit)
    }

    fn emergency_revoke(&self, prompt: &ApprovalPrompt) -> Result<u64, ApprovalError> {
        validate_prompt(prompt)?;
        if prompt.approval_class != ApprovalClass::Strong {
            return Err(ApprovalError::invalid(
                "emergency revoke requires the STRONG class",
            ));
        }
        self.preflight()?;
        let lease = InputLeaseGuard::suspend_for_presence();
        if !lease.is_suspended() {
            return Err(ApprovalError::unavailable(
                "emergency revoke requires a suspended input lease",
            ));
        }
        let ctx = PresenceContext::new(
            prompt.nonce.clone(),
            prompt.digest.clone(),
            prompt.workspace_id.clone(),
            prompt.action.clone(),
        )
        .with_details(prompt.target.clone(), prompt.summary.clone());
        let method = self.presence.method();
        let attestation = self.presence.verify(&ctx, &lease);
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| ApprovalError::unavailable("approval ledger is unavailable"))?;
        match attestation {
            Ok(attestation) => {
                if attestation.nonce != prompt.nonce || attestation.digest != prompt.digest {
                    let recorded = ledger.record_decision(
                        prompt,
                        RecordedDecision::Unavailable,
                        PresenceOutcome::Unavailable,
                        method,
                    );
                    return Err(with_recording(
                        ApprovalError::unavailable(
                            "revoke presence result does not match the request; revoke fails closed",
                        ),
                        recorded,
                    ));
                }
                if attestation.method != method {
                    let recorded = ledger.record_decision(
                        prompt,
                        RecordedDecision::Unavailable,
                        PresenceOutcome::Unavailable,
                        method,
                    );
                    return Err(with_recording(
                        ApprovalError::unavailable(
                            "revoke presence method mismatch; revoke fails closed",
                        ),
                        recorded,
                    ));
                }
                let record = ledger.record_revoke(prompt, &attestation.method)?;
                Ok(record.epoch)
            }
            Err(error) => {
                let outcome = match error.reason {
                    PresenceFailureReason::Denied | PresenceFailureReason::Cancelled => {
                        PresenceOutcome::Denied
                    }
                    _ => PresenceOutcome::Unavailable,
                };
                let decision = match outcome {
                    PresenceOutcome::Denied => RecordedDecision::Denied,
                    _ => RecordedDecision::Unavailable,
                };
                let recorded = ledger.record_decision(prompt, decision, outcome, method);
                Err(with_recording(error.into(), recorded))
            }
        }
    }
}

impl LocalApprovalBroker {
    /// Verifies the ledger before any person is prompted. The ledger mutex
    /// and the cross-process lock are released while the person decides.
    fn preflight(&self) -> Result<PromptView, ApprovalError> {
        self.ledger
            .lock()
            .map_err(|_| ApprovalError::unavailable("approval ledger is unavailable"))?
            .preflight()
    }

    fn request_soft_token(&self, prompt: &ApprovalPrompt) -> Result<ApprovedToken, ApprovalError> {
        let prompt_view = self.preflight()?;
        #[cfg(any(test, feature = "test-support"))]
        let decision = match &self.soft_decider {
            Some(decider) => Ok((decider.0)(prompt)),
            None => platform_prompt(prompt),
        };
        #[cfg(not(any(test, feature = "test-support")))]
        let decision = platform_prompt(prompt);
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| ApprovalError::unavailable("approval ledger is unavailable"))?;
        match decision {
            Ok(ApprovalDecision::Approved) => {
                let record = ledger.record_prompted_decision(
                    prompt,
                    RecordedDecision::Approved,
                    PresenceOutcome::SoftApproved,
                    "soft-button",
                    Some(&prompt_view),
                )?;
                Ok(ApprovedToken {
                    record_id: record.id.clone(),
                    nonce: record.nonce.clone(),
                    digest: record.digest.clone(),
                    workspace_id: record.workspace_id.clone(),
                    policy_revision: record.policy_revision.clone(),
                    expires_at_ms: record.expires_at_ms,
                    approval_class: ApprovalClass::Soft,
                    epoch: record.epoch,
                })
            }
            Ok(ApprovalDecision::Denied) => {
                let recorded = ledger.record_decision(
                    prompt,
                    RecordedDecision::Denied,
                    PresenceOutcome::Denied,
                    "soft-button",
                );
                Err(with_recording(
                    ApprovalError::denied("local user denied the operation"),
                    recorded,
                ))
            }
            Err(error) => {
                let recorded = ledger.record_decision(
                    prompt,
                    RecordedDecision::Unavailable,
                    PresenceOutcome::Unavailable,
                    "soft-button",
                );
                Err(with_recording(error, recorded))
            }
        }
    }

    fn request_strong_token(
        &self,
        prompt: &ApprovalPrompt,
    ) -> Result<ApprovedToken, ApprovalError> {
        let prompt_view = self.preflight()?;
        let lease = InputLeaseGuard::suspend_for_presence();
        if !lease.is_suspended() {
            return Err(ApprovalError::unavailable(
                "strong approval requires a suspended input lease",
            ));
        }
        let ctx = PresenceContext::new(
            prompt.nonce.clone(),
            prompt.digest.clone(),
            prompt.workspace_id.clone(),
            prompt.action.clone(),
        )
        .with_details(prompt.target.clone(), prompt.summary.clone());
        let method = self.presence.method();
        let attestation = self.presence.verify(&ctx, &lease);
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| ApprovalError::unavailable("approval ledger is unavailable"))?;
        match attestation {
            Ok(attestation) => {
                if attestation.nonce != prompt.nonce || attestation.digest != prompt.digest {
                    let recorded = ledger.record_decision(
                        prompt,
                        RecordedDecision::Unavailable,
                        PresenceOutcome::Unavailable,
                        method,
                    );
                    return Err(with_recording(
                        ApprovalError::unavailable(
                            "strong presence result does not match the approved request; STRONG approval fails closed",
                        ),
                        recorded,
                    ));
                }
                if attestation.method != method {
                    let recorded = ledger.record_decision(
                        prompt,
                        RecordedDecision::Unavailable,
                        PresenceOutcome::Unavailable,
                        method,
                    );
                    return Err(with_recording(
                        ApprovalError::unavailable(
                            "strong presence method mismatch; STRONG approval fails closed",
                        ),
                        recorded,
                    ));
                }
                let record = ledger.record_prompted_decision(
                    prompt,
                    RecordedDecision::Approved,
                    PresenceOutcome::VerifiedStrong,
                    &attestation.method,
                    Some(&prompt_view),
                )?;
                Ok(ApprovedToken {
                    record_id: record.id.clone(),
                    nonce: record.nonce.clone(),
                    digest: record.digest.clone(),
                    workspace_id: record.workspace_id.clone(),
                    policy_revision: record.policy_revision.clone(),
                    expires_at_ms: record.expires_at_ms,
                    approval_class: ApprovalClass::Strong,
                    epoch: record.epoch,
                })
            }
            Err(error) => {
                let outcome = match error.reason {
                    PresenceFailureReason::Denied | PresenceFailureReason::Cancelled => {
                        PresenceOutcome::Denied
                    }
                    _ => PresenceOutcome::Unavailable,
                };
                let decision = match outcome {
                    PresenceOutcome::Denied => RecordedDecision::Denied,
                    _ => RecordedDecision::Unavailable,
                };
                let recorded = ledger.record_decision(prompt, decision, outcome, method);
                Err(with_recording(error.into(), recorded))
            }
        }
    }
}

/// Keeps the decision's own error and notes when the decision itself could
/// not be recorded, so the audit gap is visible to the caller.
fn with_recording(
    error: ApprovalError,
    recorded: Result<StoredRecord, ApprovalError>,
) -> ApprovalError {
    match recorded {
        Ok(_) => error,
        Err(failure) => ApprovalError {
            code: error.code,
            message: format!(
                "{}; the decision was not recorded: {}",
                error.message, failure.message
            ),
        },
    }
}

fn validate_prompt(prompt: &ApprovalPrompt) -> Result<(), ApprovalError> {
    if prompt.workspace_id.trim().is_empty() {
        return Err(ApprovalError::invalid("approval prompt workspace is empty"));
    }
    if prompt.policy_revision.trim().is_empty() {
        return Err(ApprovalError::invalid(
            "approval prompt policy revision is empty",
        ));
    }
    if prompt.digest.trim().is_empty() {
        return Err(ApprovalError::invalid("approval prompt digest is empty"));
    }
    if prompt.nonce.trim().is_empty() {
        return Err(ApprovalError::invalid("approval prompt nonce is empty"));
    }
    if prompt.reuse_scope != SINGLE_OPERATION_SCOPE {
        return Err(ApprovalError::invalid(
            "approval prompt reuse scope must be single-operation",
        ));
    }
    if prompt.expires_at_ms <= prompt.requested_at_ms {
        return Err(ApprovalError::invalid("approval prompt expiry is invalid"));
    }
    Ok(())
}

/// How long one ledger transaction waits for another Orcel process to finish
/// its own transaction before the ledger is reported busy (never corrupt).
const LEDGER_LOCK_WAIT: Duration = Duration::from_secs(5);
const HISTORY_LOCK_WAIT: Duration = Duration::from_millis(100);
const LEDGER_RECOVERY_HINT: &str =
    "run `orcel approvals recover` to quarantine it (the evidence is preserved) and start a new approval ledger";
const LEDGER_REPLACED_HINT: &str =
    "restart the Orcel processes so they load the ledger now on disk; if `orcel doctor` then reports that it fails verification, run `orcel approvals recover`";
const LEDGER_DURABILITY_HINT: &str =
    "retry; the broker resumes once the ledger verifies again, otherwise check disk space and permissions and run `orcel doctor`";
const RECOVERY_WORKSPACE: &str = "orcel-ledger-recovery";
const RECOVERY_METHOD: &str = "ledger-recovery";

/// Sidecar file whose OS lock serializes ledger transactions across
/// processes. The ledger file itself is never locked.
pub fn approval_ledger_lock_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    path.with_file_name(name)
}

fn acquire_ledger_lock(path: &Path, wait: Duration) -> Result<std::fs::File, ApprovalError> {
    try_ledger_lock(path, wait).map_err(LockFailure::into_error)
}

/// Why the writer lock was not obtained.
#[derive(Debug)]
enum LockFailure {
    /// Another broker held it for the whole wait.
    Busy(ApprovalError),
    /// The lock file could not be opened or locked.
    Io(ApprovalError),
}

impl LockFailure {
    fn into_error(self) -> ApprovalError {
        match self {
            Self::Busy(error) | Self::Io(error) => error,
        }
    }
}

fn try_ledger_lock(path: &Path, wait: Duration) -> Result<std::fs::File, LockFailure> {
    let lock_path = approval_ledger_lock_path(path);
    let opened = (|| -> std::io::Result<std::fs::File> {
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        // Without FILE_SHARE_DELETE the lock file cannot be deleted (and a
        // second, unrelated lock file created) while any broker holds it.
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            const FILE_SHARE_READ: u32 = 0x1;
            const FILE_SHARE_WRITE: u32 = 0x2;
            options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        }
        options.open(&lock_path)
    })();
    let lock = opened.map_err(|error| {
        LockFailure::Io(ApprovalError::unavailable(format!(
            "approval ledger lock is unavailable: {error}"
        )))
    })?;
    let deadline = Instant::now() + wait;
    loop {
        match fs4::FileExt::try_lock(&lock) {
            // Released when the handle closes, including on process death.
            Ok(()) => return Ok(lock),
            Err(fs4::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(fs4::TryLockError::WouldBlock) => {
                return Err(LockFailure::Busy(ApprovalError::unavailable(
                    "approval ledger is busy in another Orcel process; retry shortly",
                )))
            }
            Err(fs4::TryLockError::Error(error)) => {
                return Err(LockFailure::Io(ApprovalError::unavailable(format!(
                    "approval ledger lock failed: {error}"
                ))))
            }
        }
    }
}

/// Why a ledger refuses every approval until it is recovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LedgerFault {
    /// An event does not verify against the chain. Every v0.1.0 history that
    /// consumed an approval is affected by #278 and lands here once.
    Unverifiable,
    /// The last record is incomplete, as after a crash during a write.
    TornTail,
    /// The file shrank, vanished or was replaced while this broker ran.
    Replaced,
    /// An append failed, so whether it became durable is unknown.
    Durability,
}

impl LedgerFault {
    fn describe(self) -> &'static str {
        match self {
            Self::Unverifiable => "the approval ledger does not verify (expected once after upgrading from v0.1.0, see #278; otherwise it indicates damage or tampering)",
            Self::TornTail => "the approval ledger's last record is incomplete, as after a crash during a write",
            Self::Replaced => "the approval ledger was truncated, deleted or replaced while Orcel was running",
            Self::Durability => "an approval ledger write failed, so its durability is unknown",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Self::Durability => LEDGER_DURABILITY_HINT,
            Self::Replaced => LEDGER_REPLACED_HINT,
            Self::Unverifiable | Self::TornTail => LEDGER_RECOVERY_HINT,
        }
    }
}

/// The chain and revoke epoch a person's prompt was shown under.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PromptView {
    genesis: Option<String>,
    epoch: u64,
}

#[derive(Debug)]
struct ApprovalLedger {
    path: PathBuf,
    records: BTreeMap<String, StoredRecord>,
    nonces: HashSet<String>,
    consumed: HashSet<String>,
    tip: String,
    revoke_epoch: u64,
    /// Checksum of the chain's first record, identifying this chain.
    genesis: Option<String>,
    /// Bytes of the ledger file already verified and applied in memory.
    verified_len: u64,
    /// The last verified line (with its newline), re-read before trusting
    /// the file again so a same-length replacement cannot go unnoticed.
    last_line: Vec<u8>,
    lock_wait: Duration,
    fault: Option<LedgerFault>,
}

impl ApprovalLedger {
    fn empty(path: PathBuf) -> Self {
        Self {
            path,
            records: BTreeMap::new(),
            nonces: HashSet::new(),
            consumed: HashSet::new(),
            tip: String::from("GENESIS"),
            revoke_epoch: 0,
            genesis: None,
            verified_len: 0,
            last_line: Vec::new(),
            lock_wait: LEDGER_LOCK_WAIT,
            fault: None,
        }
    }

    fn load_or_create(path: PathBuf) -> Self {
        let mut ledger = Self::empty(path);
        if !ledger.path.exists() {
            return ledger;
        }
        // A busy ledger is not an integrity failure: every later transaction
        // verifies the file again under the lock before it acts.
        if let Ok(_lock) = acquire_ledger_lock(&ledger.path, ledger.lock_wait) {
            let _ = ledger.refresh();
        }
        ledger
    }

    fn poisoned(&self) -> bool {
        self.fault.is_some()
    }

    /// Runs one transaction under the cross-process writer lock, after
    /// applying every record other processes appended since the last view.
    fn transact<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, ApprovalError>,
    ) -> Result<T, ApprovalError> {
        self.transact_waiting(self.lock_wait, operation)
    }

    fn transact_waiting<T>(
        &mut self,
        wait: Duration,
        operation: impl FnOnce(&mut Self) -> Result<T, ApprovalError>,
    ) -> Result<T, ApprovalError> {
        let _lock = acquire_ledger_lock(&self.path, wait)?;
        if self.poisoned() && !self.resume() {
            self.ensure_ready()?;
        }
        if let Err(error) = self.refresh() {
            // A ledger replaced by recovery is adopted within this transaction.
            if !(self.poisoned() && self.adopt_recovered()) {
                return Err(error);
            }
        }
        operation(self)
    }

    /// Checks the ledger before a person is asked to decide, so nobody is
    /// prompted for an approval the broker could not record. Returns the
    /// chain and revoke epoch the prompt is shown under.
    fn preflight(&mut self) -> Result<PromptView, ApprovalError> {
        self.transact(|ledger| {
            Ok(PromptView {
                genesis: ledger.genesis.clone(),
                epoch: ledger.revoke_epoch,
            })
        })
    }

    /// Clears a poisoned state when that is provably safe (the caller holds
    /// the lock). After an uncertain write, the unknown record either landed
    /// whole and verifies (it is applied like any other) or never landed (it
    /// was never acknowledged), so the broker continues once the file still
    /// extends its last verified line and verifies. Otherwise only a chain
    /// started by `orcel approvals recover` can be adopted.
    fn resume(&mut self) -> bool {
        if self.fault == Some(LedgerFault::Durability) {
            self.fault = None;
            match self.refresh() {
                Ok(()) => return true,
                // Transient: still uncertain, keep the accurate guidance.
                Err(_) if self.fault.is_none() => {
                    self.fault = Some(LedgerFault::Durability);
                    return false;
                }
                Err(_) => {}
            }
        }
        self.adopt_recovered()
    }

    /// Lets a poisoned broker continue after `orcel approvals recover`
    /// replaced the ledger: the new chain must differ from the one this
    /// broker knew, start with the recovery record, and verify completely.
    /// Nothing from the old view carries over. The caller holds the lock.
    fn adopt_recovered(&mut self) -> bool {
        let mut fresh = Self::empty(self.path.clone());
        fresh.lock_wait = self.lock_wait;
        if fresh.refresh().is_err() || fresh.genesis == self.genesis {
            return false;
        }
        let starts_with_recovery = fresh.starts_with_recovery();
        if starts_with_recovery {
            *self = fresh;
        }
        starts_with_recovery
    }

    /// Whether this chain was started by `orcel approvals recover`.
    fn starts_with_recovery(&self) -> bool {
        self.records
            .values()
            .find(|record| record.prev_checksum == "GENESIS")
            .is_some_and(|record| {
                record.workspace_id == RECOVERY_WORKSPACE
                    && record.presence_method == RECOVERY_METHOD
                    && record.decision == RecordedDecision::Unavailable
            })
    }

    fn ensure_ready(&self) -> Result<(), ApprovalError> {
        match self.fault {
            Some(fault) => Err(ApprovalError::unavailable(format!(
                "{}; no approval can be granted; {}",
                fault.describe(),
                fault.hint()
            ))),
            None => Ok(()),
        }
    }

    fn poison(&mut self, fault: LedgerFault) -> ApprovalError {
        self.fault.get_or_insert(fault);
        self.ensure_ready().unwrap_err()
    }

    /// Verifies and applies the bytes appended since `verified_len`, after
    /// confirming the last verified line is still in place. A missing,
    /// shrunken, replaced, torn or unverifiable file poisons the ledger; an
    /// invalid suffix never yields a usable valid-prefix history. Transient
    /// I/O errors fail the transaction without poisoning.
    fn refresh(&mut self) -> Result<(), ApprovalError> {
        use std::io::{Read as _, Seek as _, SeekFrom};
        self.ensure_ready()?;
        let unreadable = |error: std::io::Error| {
            ApprovalError::unavailable(format!(
                "approval ledger is temporarily unreadable; retry shortly: {error}"
            ))
        };
        let len = match std::fs::metadata(&self.path) {
            Ok(metadata) if metadata.is_file() => metadata.len(),
            Ok(_) => return Err(self.poison(LedgerFault::Replaced)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return if self.verified_len == 0 {
                    Ok(())
                } else {
                    Err(self.poison(LedgerFault::Replaced))
                };
            }
            Err(error) => return Err(unreadable(error)),
        };
        if len < self.verified_len {
            return Err(self.poison(LedgerFault::Replaced));
        }
        let start = self.verified_len - self.last_line.len() as u64;
        let mut bytes = Vec::new();
        std::fs::File::open(&self.path)
            .and_then(|mut file| {
                file.seek(SeekFrom::Start(start))?;
                file.read_to_end(&mut bytes)
            })
            .map_err(unreadable)?;
        let Some(appended) = bytes.strip_prefix(self.last_line.as_slice()) else {
            return Err(self.poison(LedgerFault::Replaced));
        };
        if appended.is_empty() {
            return Ok(());
        }
        if appended.last() != Some(&b'\n') {
            return Err(self.poison(LedgerFault::TornTail));
        }
        let Ok(text) = std::str::from_utf8(appended) else {
            return Err(self.poison(LedgerFault::Unverifiable));
        };
        let mut last_line = self.last_line.clone();
        for line in text.split_terminator('\n') {
            let applied = serde_json::from_str::<StoredRecord>(line)
                .ok()
                .is_some_and(|record| self.apply(record));
            if !applied {
                return Err(self.poison(LedgerFault::Unverifiable));
            }
            last_line = format!("{line}\n").into_bytes();
        }
        self.verified_len += appended.len() as u64;
        self.last_line = last_line;
        Ok(())
    }

    /// Applies one persisted event, returning false when it does not verify.
    fn apply(&mut self, record: StoredRecord) -> bool {
        if record.schema != LEDGER_SCHEMA || !verify_record_checksum(&record, &self.tip) {
            return false;
        }
        if record.is_revoke && !record.consumed {
            return false;
        }
        if record.consumed && !record.is_revoke {
            // Consumption is a separate append-only transition, never a
            // rewrite of the original issuance entry.
            let Some(previous) = self.records.get(&record.id) else {
                return false;
            };
            let mut expected = previous.clone();
            expected.consumed = true;
            expected.prev_checksum = record.prev_checksum.clone();
            expected.checksum = record.checksum.clone();
            if previous.consumed
                || serde_json::to_value(&expected).ok() != serde_json::to_value(&record).ok()
            {
                return false;
            }
            self.consumed.insert(record.nonce.clone());
        } else {
            if self.records.contains_key(&record.id)
                || !self.nonces.insert(record.nonce.clone())
                || (record.is_revoke && record.epoch != self.revoke_epoch.saturating_add(1))
                || (!record.is_revoke && record.epoch != self.revoke_epoch)
            {
                return false;
            }
            if record.is_revoke {
                self.revoke_epoch = record.epoch;
                self.consumed.insert(record.nonce.clone());
            }
        }
        self.tip = record.checksum.clone();
        self.genesis.get_or_insert_with(|| record.checksum.clone());
        self.records.insert(record.id.clone(), record);
        true
    }

    /// Record ids embed the wall clock and a per-process counter, which can
    /// repeat after a restart or a clock step backwards.
    fn unique_record_id(&self, prefix: &str) -> (String, u64) {
        loop {
            let decided_at = now_ms();
            let id = format!(
                "{prefix}-{decided_at}-{}",
                NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            if !self.records.contains_key(&id) {
                return (id, decided_at);
            }
        }
    }

    fn record_decision(
        &mut self,
        prompt: &ApprovalPrompt,
        decision: RecordedDecision,
        presence_outcome: PresenceOutcome,
        presence_method: &str,
    ) -> Result<StoredRecord, ApprovalError> {
        self.record_prompted_decision(prompt, decision, presence_outcome, presence_method, None)
    }

    /// Records a person's decision. When `prompt_view` is the chain and
    /// revoke epoch the prompt was shown under and an emergency revoke or a
    /// recovery happened while the person decided, an approval is recorded as
    /// unavailable and refused.
    fn record_prompted_decision(
        &mut self,
        prompt: &ApprovalPrompt,
        decision: RecordedDecision,
        presence_outcome: PresenceOutcome,
        presence_method: &str,
        prompt_view: Option<&PromptView>,
    ) -> Result<StoredRecord, ApprovalError> {
        if prompt.approval_class == ApprovalClass::Strong
            && presence_outcome == PresenceOutcome::SoftApproved
        {
            return Err(ApprovalError::invalid(
                "a soft button alone never satisfies the STRONG class",
            ));
        }
        self.transact(|ledger| {
            if ledger.nonces.contains(&prompt.nonce) {
                return Err(ApprovalError::invalid(
                    "approval nonce was already issued; retry with a fresh prompt",
                ));
            }
            let revoked_meanwhile = decision == RecordedDecision::Approved
                && prompt_view.is_some_and(|view| {
                    // A chain that appeared on an empty ledger is a change only
                    // when recovery started it.
                    let chain_changed = view.genesis != ledger.genesis
                        && (view.genesis.is_some() || ledger.starts_with_recovery());
                    view.epoch != ledger.revoke_epoch || chain_changed
                });
            let (decision, presence_outcome) = if revoked_meanwhile {
                (RecordedDecision::Unavailable, PresenceOutcome::Unavailable)
            } else {
                (decision, presence_outcome)
            };
            let (id, decided_at) = ledger.unique_record_id("apr");
            let mut record = StoredRecord {
                schema: LEDGER_SCHEMA.to_owned(),
                id,
                nonce: prompt.nonce.clone(),
                digest: prompt.digest.clone(),
                workspace_id: prompt.workspace_id.clone(),
                policy_revision: prompt.policy_revision.clone(),
                decision,
                approval_class: prompt.approval_class,
                presence_outcome,
                presence_method: presence_method.to_owned(),
                epoch: ledger.revoke_epoch,
                is_revoke: false,
                requested_at_ms: prompt.requested_at_ms,
                decided_at_ms: decided_at,
                expires_at_ms: prompt.expires_at_ms,
                reuse_scope: prompt.reuse_scope.clone(),
                consumed: false,
                prev_checksum: ledger.tip.clone(),
                checksum: String::new(),
            };
            record.checksum = record_checksum(&record);
            let record = ledger.append(record)?;
            if revoked_meanwhile {
                return Err(ApprovalError::denied(
                    "an emergency revoke or ledger recovery happened while this approval was pending; request a fresh approval",
                ));
            }
            Ok(record)
        })
    }

    fn record_revoke(
        &mut self,
        prompt: &ApprovalPrompt,
        presence_method: &str,
    ) -> Result<StoredRecord, ApprovalError> {
        if prompt.approval_class != ApprovalClass::Strong {
            return Err(ApprovalError::invalid(
                "emergency revoke requires the STRONG class",
            ));
        }
        self.transact(|ledger| {
            if ledger.nonces.contains(&prompt.nonce) {
                return Err(ApprovalError::invalid(
                    "approval nonce was already issued; retry with a fresh prompt",
                ));
            }
            let (id, decided_at) = ledger.unique_record_id("rev");
            let mut record = StoredRecord {
                schema: LEDGER_SCHEMA.to_owned(),
                id,
                nonce: prompt.nonce.clone(),
                digest: prompt.digest.clone(),
                workspace_id: prompt.workspace_id.clone(),
                policy_revision: prompt.policy_revision.clone(),
                decision: RecordedDecision::Approved,
                approval_class: ApprovalClass::Strong,
                presence_outcome: PresenceOutcome::VerifiedStrong,
                presence_method: presence_method.to_owned(),
                epoch: ledger.revoke_epoch.saturating_add(1),
                is_revoke: true,
                requested_at_ms: prompt.requested_at_ms,
                decided_at_ms: decided_at,
                expires_at_ms: prompt.expires_at_ms,
                reuse_scope: prompt.reuse_scope.clone(),
                consumed: true,
                prev_checksum: ledger.tip.clone(),
                checksum: String::new(),
            };
            record.checksum = record_checksum(&record);
            ledger.append(record)
        })
    }

    #[cfg(test)]
    fn current_epoch(&self) -> u64 {
        self.revoke_epoch
    }

    fn consume(
        &mut self,
        token: &ApprovedToken,
        expected: &ConsumeExpectation,
        now_ms: u64,
    ) -> Result<(), ApprovalError> {
        self.transact(|ledger| {
            let marker = ledger.check_consumable(token, expected, now_ms)?;
            // No authorization is released until this transition is durable.
            // Any ambiguous append poisons the broker, without retrying.
            ledger.append(marker).map(|_| ())
        })
    }

    fn check_consumable(
        &self,
        token: &ApprovedToken,
        expected: &ConsumeExpectation,
        now_ms: u64,
    ) -> Result<StoredRecord, ApprovalError> {
        let record = self.records.get(&token.record_id).ok_or_else(|| {
            ApprovalError::invalid("approval token references an unknown approval record")
        })?;
        if record.decision != RecordedDecision::Approved {
            return Err(ApprovalError::denied(
                "approval token was not approved and cannot authorize execution",
            ));
        }
        if record.is_revoke {
            return Err(ApprovalError::denied(
                "revoke records never authorize execution",
            ));
        }
        if record.epoch != self.revoke_epoch || token.epoch != self.revoke_epoch {
            return Err(ApprovalError::denied(
                "approval was revoked by emergency revoke and cannot authorize execution",
            ));
        }
        if record.epoch != token.epoch {
            return Err(ApprovalError::stale(
                "approval epoch changed after approval; approval cannot be reused",
            ));
        }
        if record.nonce != token.nonce {
            return Err(ApprovalError::stale(
                "approval token nonce does not match the recorded approval",
            ));
        }
        if record.approval_class != token.approval_class {
            return Err(ApprovalError::stale(
                "approval class changed after approval; approval cannot be reused",
            ));
        }
        if record.approval_class != expected.approval_class
            || token.approval_class != expected.approval_class
        {
            return Err(ApprovalError::stale(
                "approval class does not match the expected class; STRONG never downgrades to SOFT",
            ));
        }
        if now_ms > record.expires_at_ms || now_ms > token.expires_at_ms {
            return Err(ApprovalError::denied(
                "local approval expired before execution",
            ));
        }
        if record.digest != expected.digest || token.digest != expected.digest {
            return Err(ApprovalError::stale(
                "operation digest changed after approval; approval cannot be reused",
            ));
        }
        if record.workspace_id != expected.workspace_id
            || token.workspace_id != expected.workspace_id
        {
            return Err(ApprovalError::stale(
                "workspace changed after approval; approval cannot be reused",
            ));
        }
        if record.policy_revision != expected.policy_revision
            || token.policy_revision != expected.policy_revision
        {
            return Err(ApprovalError::stale(
                "policy revision changed after approval; approval cannot be reused",
            ));
        }
        if record.consumed || self.consumed.contains(&record.nonce) {
            return Err(ApprovalError::denied(
                "approval was already consumed and cannot authorize another operation",
            ));
        }
        let mut marker = record.clone();
        marker.consumed = true;
        marker.prev_checksum = self.tip.clone();
        marker.checksum = record_checksum(&marker);
        Ok(marker)
    }

    /// Durably appends one event (the caller holds the writer lock), then
    /// applies it in memory through the same verifier used on load.
    fn append(&mut self, record: StoredRecord) -> Result<StoredRecord, ApprovalError> {
        use std::io::Write as _;
        self.ensure_ready()?;
        let mut serialized = serde_json::to_vec(&record)
            .map_err(|error| ApprovalError::unavailable(format!("serialize approval: {error}")))?;
        serialized.push(b'\n');
        let created = self.verified_len == 0;
        // Nothing was written if the file cannot be opened: transient.
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| {
                ApprovalError::unavailable(format!(
                    "approval ledger is temporarily unwritable; retry shortly: {error}"
                ))
            })?;
        let persist = (|| -> std::io::Result<u64> {
            file.write_all(&serialized)?;
            file.sync_all()?;
            if created {
                sync_parent_dir(&self.path)?;
            }
            Ok(file.metadata()?.len())
        })();
        match persist {
            Err(error) => {
                let refused = self.poison(LedgerFault::Durability);
                return Err(ApprovalError::unavailable(format!(
                    "{}: {error}",
                    refused.message
                )));
            }
            // A concurrent append by a writer that bypassed or replaced the
            // lock shows up as extra bytes; such an append is not acknowledged.
            Ok(len) if len != self.verified_len + serialized.len() as u64 => {
                return Err(self.poison(LedgerFault::Replaced));
            }
            Ok(_) => {}
        }
        if !self.apply(record.clone()) {
            return Err(self.poison(LedgerFault::Unverifiable));
        }
        self.verified_len += serialized.len() as u64;
        self.last_line = serialized;
        Ok(record)
    }

    fn history(&mut self, limit: usize) -> Vec<ApprovalRecordSummary> {
        // History is best effort: it waits briefly for the writer lock and a
        // busy or failed refresh still reports the last verified view.
        let _ = self.transact_waiting(HISTORY_LOCK_WAIT, |_| Ok(()));
        let bound = limit.clamp(1, 200);
        self.records
            .values()
            .rev()
            .take(bound)
            .map(|record| ApprovalRecordSummary {
                id: record.id.clone(),
                digest: record.digest.clone(),
                workspace_id: record.workspace_id.clone(),
                policy_revision: record.policy_revision.clone(),
                decision: record.decision,
                approval_class: record.approval_class,
                presence_outcome: record.presence_outcome,
                presence_method: record.presence_method.clone(),
                epoch: record.epoch,
                is_revoke: record.is_revoke,
                requested_at_ms: record.requested_at_ms,
                decided_at_ms: record.decided_at_ms,
                expires_at_ms: record.expires_at_ms,
                reuse_scope: record.reuse_scope.clone(),
                consumed: self.consumed.contains(&record.nonce),
            })
            .collect()
    }
}

/// Makes a newly created ledger's directory entry durable. NTFS journals
/// metadata and Windows offers no portable directory flush, so this is a
/// no-op there.
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalLedgerStatus {
    /// No ledger has been written yet.
    Missing,
    /// Every persisted event verifies.
    Verified,
    /// The ledger fails verification; approvals stay blocked until recovery.
    Corrupt,
    /// Another Orcel process held the writer lock for the whole wait; retry.
    Busy,
    /// The ledger or its lock could not be read; `detail` says why.
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalLedgerInspection {
    pub status: ApprovalLedgerStatus,
    pub verified_records: usize,
    /// The underlying error for `Corrupt`, `Busy` and `Unreadable`.
    pub detail: String,
}

/// Verifies the ledger without changing it (only the sidecar lock may be
/// created).
pub fn inspect_approval_ledger(path: &Path) -> ApprovalLedgerInspection {
    let mut ledger = ApprovalLedger::empty(path.to_path_buf());
    let inspection = |status, verified_records, detail: String| ApprovalLedgerInspection {
        status,
        verified_records,
        detail,
    };
    match path.try_exists() {
        Ok(false) => return inspection(ApprovalLedgerStatus::Missing, 0, String::new()),
        Ok(true) => {}
        Err(error) => {
            return inspection(ApprovalLedgerStatus::Unreadable, 0, error.to_string());
        }
    }
    let (status, detail) = match try_ledger_lock(path, ledger.lock_wait) {
        Err(LockFailure::Busy(error)) => (ApprovalLedgerStatus::Busy, error.message),
        Err(LockFailure::Io(error)) => (ApprovalLedgerStatus::Unreadable, error.message),
        Ok(_lock) => match ledger.refresh() {
            Ok(()) => (ApprovalLedgerStatus::Verified, String::new()),
            Err(error) if ledger.poisoned() => (ApprovalLedgerStatus::Corrupt, error.message),
            Err(error) => (ApprovalLedgerStatus::Unreadable, error.message),
        },
    };
    inspection(status, ledger.records.len(), detail)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalLedgerRecovery {
    pub quarantined_to: PathBuf,
    pub quarantined_sha256: String,
    pub quarantined_bytes: u64,
}

/// Recovers a ledger that fails verification. The original bytes are kept
/// at a quarantine path for forensics (never deleted or rewritten), and a new
/// chain starts with a non-authorizing record that names the quarantine file
/// and its SHA-256. No earlier approval is carried over, so every operation
/// needs a fresh approval afterwards. A verified, missing, busy or merely
/// unreadable ledger is refused.
///
/// The ledger path is never absent: the new chain is written and synced to a
/// staged file, the quarantine is a hard link to (or a verified copy of) the
/// original, and the staged chain then replaces the ledger in one rename. A
/// failure at any step leaves the original ledger in place.
pub fn recover_approval_ledger(path: &Path) -> Result<ApprovalLedgerRecovery, ApprovalError> {
    recover_approval_ledger_with_wait(path, LEDGER_LOCK_WAIT)
}

fn recover_approval_ledger_with_wait(
    path: &Path,
    wait: Duration,
) -> Result<ApprovalLedgerRecovery, ApprovalError> {
    let missing = || ApprovalError::invalid("there is no approval ledger to recover");
    let exists = |path: &Path| {
        path.try_exists().map_err(|error| {
            ApprovalError::unavailable(format!("approval ledger is unreadable: {error}"))
        })
    };
    // Checked before taking the lock so nothing is created when there is
    // nothing to recover, and again under the lock.
    if !exists(path)? {
        return Err(missing());
    }
    let _lock = acquire_ledger_lock(path, wait)?;
    if !exists(path)? {
        return Err(missing());
    }
    let mut current = ApprovalLedger::empty(path.to_path_buf());
    match current.refresh() {
        Ok(()) => return Err(ApprovalError::invalid(
            "the approval ledger verifies; recovery is only for a ledger that fails verification",
        )),
        // Unreadable is not corrupt: never quarantine a ledger that may verify.
        Err(error) if !current.poisoned() => return Err(error),
        Err(_) => {}
    }
    // Windows cannot replace (or flush) a read-only file; refuse before any
    // file is created so the operator can clear the attribute and retry.
    #[cfg(windows)]
    {
        let read_only = std::fs::metadata(path)
            .map(|metadata| metadata.permissions().readonly())
            .map_err(|error| {
                ApprovalError::unavailable(format!("approval ledger is unreadable: {error}"))
            })?;
        if read_only {
            return Err(ApprovalError::unavailable(
                "the approval ledger file is read-only; clear its read-only attribute and run recovery again",
            ));
        }
    }
    let bytes = std::fs::read(path).map_err(|error| {
        ApprovalError::unavailable(format!("read approval ledger for quarantine: {error}"))
    })?;
    let sha256 = hex_lower(&Sha256::digest(&bytes));
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".quarantine-{}-{}", now_ms(), &sha256[..12]));
    let quarantined_to = path.with_file_name(name);
    if quarantined_to.exists() {
        return Err(ApprovalError::unavailable(
            "approval ledger quarantine path already exists; retry",
        ));
    }
    let mut staged_name = path.file_name().unwrap_or_default().to_os_string();
    staged_name.push(format!(".recovering-{}", now_ms()));
    let staged = path.with_file_name(staged_name);
    let mut fresh = ApprovalLedger::empty(staged.clone());
    let (id, decided_at) = fresh.unique_record_id("rcv");
    let mut record = StoredRecord {
        schema: LEDGER_SCHEMA.to_owned(),
        id,
        nonce: fresh_nonce(&sha256, decided_at),
        digest: format!("sha256:{sha256}"),
        workspace_id: RECOVERY_WORKSPACE.to_owned(),
        policy_revision: quarantined_to
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        // Unavailable records can never authorize execution.
        decision: RecordedDecision::Unavailable,
        approval_class: ApprovalClass::Soft,
        presence_outcome: PresenceOutcome::Unavailable,
        presence_method: RECOVERY_METHOD.to_owned(),
        epoch: 0,
        is_revoke: false,
        requested_at_ms: decided_at,
        decided_at_ms: decided_at,
        expires_at_ms: decided_at,
        reuse_scope: SINGLE_OPERATION_SCOPE.to_owned(),
        consumed: false,
        prev_checksum: fresh.tip.clone(),
        checksum: String::new(),
    };
    record.checksum = record_checksum(&record);
    let swapped = fresh
        .append(record)
        .and_then(|_| preserve_quarantine(path, &quarantined_to, &sha256))
        .and_then(|()| {
            // Replaces the ledger in one step (MoveFileEx with replace on
            // Windows, rename(2) elsewhere); the quarantine keeps the bytes.
            std::fs::rename(&staged, path)
                .and_then(|()| sync_parent_dir(path))
                .map_err(|error| {
                    ApprovalError::unavailable(format!(
                        "install the recovered approval ledger (the original is unchanged; its quarantine copy {} is kept): {error}",
                        quarantined_to.display()
                    ))
                })
        });
    if let Err(error) = swapped {
        let _ = std::fs::remove_file(&staged);
        return Err(error);
    }
    Ok(ApprovalLedgerRecovery {
        quarantined_to,
        quarantined_sha256: sha256,
        quarantined_bytes: bytes.len() as u64,
    })
}

/// Keeps the ledger's current bytes at `quarantined_to` without moving the
/// ledger: a hard link, or a copy where links are unsupported. Either way the
/// quarantine must hash to `sha256` before the ledger is replaced.
fn preserve_quarantine(
    path: &Path,
    quarantined_to: &Path,
    sha256: &str,
) -> Result<(), ApprovalError> {
    let failed = |error: std::io::Error| {
        ApprovalError::unavailable(format!(
            "preserve the approval ledger for quarantine (the original is unchanged): {error}"
        ))
    };
    match std::fs::hard_link(path, quarantined_to) {
        // The link shares the original's data, which may not be on disk yet
        // (for example after an edit outside the broker): flush it.
        Ok(()) => {
            if let Err(error) = flush_existing_file(quarantined_to) {
                let note = remove_own_file(quarantined_to);
                return Err(ApprovalError::unavailable(format!(
                    "flush the approval ledger quarantine (the original is unchanged{note}): {error}"
                )));
            }
        }
        // Never replace whatever already exists at the quarantine name.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(failed(error));
        }
        // Links unsupported here (for example FAT or some network shares).
        Err(_) => copy_into_new_file(path, quarantined_to).map_err(failed)?,
    }
    sync_parent_dir(quarantined_to).map_err(failed)?;
    let kept = std::fs::read(quarantined_to).map_err(failed)?;
    if hex_lower(&Sha256::digest(&kept)) != sha256 {
        // Only this attempt's own link or copy is removed, never the original.
        let note = remove_own_file(quarantined_to);
        return Err(ApprovalError::unavailable(format!(
            "the quarantined approval ledger does not match the original; the original is unchanged{note}"
        )));
    }
    Ok(())
}

/// Removes a link or copy this recovery attempt created, describing any file
/// that had to be left behind.
fn remove_own_file(path: &Path) -> String {
    match std::fs::remove_file(path) {
        Ok(()) => String::new(),
        Err(error) => format!("; {} could not be removed: {error}", path.display()),
    }
}

/// Flushes an existing file's data to disk without writing to it.
fn flush_existing_file(path: &Path) -> std::io::Result<()> {
    // FlushFileBuffers needs a write handle on Windows (read-only ledgers are
    // refused before recovery starts); fsync works on a read-only descriptor.
    #[cfg(windows)]
    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    #[cfg(not(windows))]
    let file = std::fs::File::open(path)?;
    file.sync_all()
}

/// Copies `from` into `to`, which must not exist yet, and flushes the copy.
/// On Unix the copy is created owner-only, never more readable than needed.
/// A partial copy is removed, and the error names it if that fails.
fn copy_into_new_file(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut source = std::fs::File::open(from)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut target = options.open(to)?;
    let copied = std::io::copy(&mut source, &mut target).and_then(|_| target.sync_all());
    if let Err(error) = copied {
        drop(target);
        let note = remove_own_file(to);
        return Err(std::io::Error::new(error.kind(), format!("{error}{note}")));
    }
    Ok(())
}

fn record_checksum(record: &StoredRecord) -> String {
    let mut hasher = Sha256::new();
    checksum_field(&mut hasher, LEDGER_SCHEMA.as_bytes());
    checksum_field(&mut hasher, record.id.as_bytes());
    checksum_field(&mut hasher, record.nonce.as_bytes());
    checksum_field(&mut hasher, record.digest.as_bytes());
    checksum_field(&mut hasher, record.workspace_id.as_bytes());
    checksum_field(&mut hasher, record.policy_revision.as_bytes());
    checksum_field(&mut hasher, format!("{:?}", record.decision).as_bytes());
    checksum_field(&mut hasher, record.approval_class.as_str().as_bytes());
    checksum_field(&mut hasher, record.presence_outcome.as_str().as_bytes());
    checksum_field(&mut hasher, record.presence_method.as_bytes());
    checksum_field(&mut hasher, record.epoch.to_string().as_bytes());
    checksum_field(
        &mut hasher,
        (if record.is_revoke { "1" } else { "0" }).as_bytes(),
    );
    checksum_field(&mut hasher, record.requested_at_ms.to_string().as_bytes());
    checksum_field(&mut hasher, record.decided_at_ms.to_string().as_bytes());
    checksum_field(&mut hasher, record.expires_at_ms.to_string().as_bytes());
    checksum_field(&mut hasher, record.reuse_scope.as_bytes());
    checksum_field(
        &mut hasher,
        (if record.consumed { "1" } else { "0" }).as_bytes(),
    );
    checksum_field(&mut hasher, record.prev_checksum.as_bytes());
    hex_lower(&hasher.finalize())
}

fn verify_record_checksum(record: &StoredRecord, tip: &str) -> bool {
    if record.prev_checksum != tip {
        return false;
    }
    record.checksum == record_checksum(record)
}

fn checksum_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn fresh_nonce(digest: &str, now_ms: u64) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher as _};
    let count = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = DefaultHasher::new();
    std::process::id().hash(&mut hasher);
    now_ms.hash(&mut hasher);
    count.hash(&mut hasher);
    digest.hash(&mut hasher);
    format!("{:016x}{:016x}", hasher.finish(), count ^ now_ms)
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// `ORCEL_APPROVAL_HISTORY_PATH`, else `approval-history.jsonl` in the
/// private per-user Orcel state root. Fails closed when the override is
/// empty, relative or not in a private directory, or when the root cannot
/// be resolved or is not private; it never falls back to the shared temp
/// directory.
pub fn default_approval_history_path() -> Result<std::path::PathBuf, PlatformError> {
    default_approval_history_path_from(&|name| std::env::var_os(name))
}

/// [`default_approval_history_path`] with the environment read through
/// `lookup`.
pub fn default_approval_history_path_from(
    lookup: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<std::path::PathBuf, PlatformError> {
    if let Some(path) = lookup("ORCEL_APPROVAL_HISTORY_PATH") {
        return orcel_platform::paths::private_file_override(path);
    }
    let root = orcel_platform::paths::state_root_from(lookup)?;
    orcel_platform::paths::ensure_private_dir(&root)?;
    Ok(root.join("approval-history.jsonl"))
}

fn history_path_unavailable(error: PlatformError) -> ApprovalError {
    ApprovalError::unavailable(format!("approval history is unavailable: {error}"))
}

#[cfg(windows)]
fn platform_prompt(prompt: &ApprovalPrompt) -> Result<ApprovalDecision, ApprovalError> {
    use std::ffi::c_void;
    use std::ptr;

    type Hwnd = *mut c_void;
    const MB_YESNO: u32 = 0x0000_0004;
    const MB_ICONWARNING: u32 = 0x0000_0030;
    const MB_DEFBUTTON2: u32 = 0x0000_0100;
    const MB_SYSTEMMODAL: u32 = 0x0000_1000;
    const IDYES: i32 = 6;
    const IDNO: i32 = 7;

    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(hwnd: Hwnd, text: *const u16, caption: *const u16, kind: u32) -> i32;
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    debug_assert_eq!(prompt.approval_class, ApprovalClass::Soft);
    let body = format!(
        "Orcel requests a local action.\n\nWorkspace: {}\nAction: {}\nTarget: {}\n{}\nDigest: {}\nApproval: SOFT {} (single use, expires in 5 minutes)\n\nApprove this exact operation?",
        prompt.workspace_id,
        prompt.action,
        prompt.target,
        prompt.summary,
        prompt.digest,
        &prompt.nonce[..prompt.nonce.len().min(8)],
    );
    let body = wide(&body);
    let caption = wide("Orcel approval SOFT");
    let result = unsafe {
        MessageBoxW(
            ptr::null_mut(),
            body.as_ptr(),
            caption.as_ptr(),
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SYSTEMMODAL,
        )
    };

    match result {
        IDYES => Ok(ApprovalDecision::Approved),
        IDNO => Ok(ApprovalDecision::Denied),
        _ => Err(ApprovalError::unavailable(format!(
            "Windows approval prompt returned unexpected result {result}"
        ))),
    }
}

#[cfg(target_os = "macos")]
fn platform_prompt(prompt: &ApprovalPrompt) -> Result<ApprovalDecision, ApprovalError> {
    soft_macos::platform_prompt(prompt)
}

#[cfg(target_os = "linux")]
fn platform_prompt(prompt: &ApprovalPrompt) -> Result<ApprovalDecision, ApprovalError> {
    linux::platform_prompt(prompt)
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn platform_prompt(prompt: &ApprovalPrompt) -> Result<ApprovalDecision, ApprovalError> {
    debug_assert_eq!(prompt.approval_class, ApprovalClass::Soft);
    let _ = prompt;
    Err(ApprovalError::unavailable(
        "local approval UI is not available on this platform in the current Orcel runtime",
    ))
}

#[cfg(test)]
mod state_root_tests {
    use super::*;
    use std::ffi::OsString;

    fn lookup(vars: Vec<(&'static str, OsString)>) -> impl Fn(&str) -> Option<OsString> {
        move |name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        }
    }

    fn sandbox(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "orcel-approval-root-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("sandbox");
        // Independent of the umask, so the ancestor checks see a private base.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("chmod sandbox");
        }
        dir
    }

    /// The per-user variable the running OS's layout reads, pointed at `base`.
    fn user_root_env(base: &Path) -> Vec<(&'static str, OsString)> {
        #[cfg(windows)]
        let name = "LOCALAPPDATA";
        #[cfg(not(windows))]
        let name = "HOME";
        vec![(name, base.as_os_str().to_owned())]
    }

    fn approve_once(broker: &LocalApprovalBroker, digest: &str) -> ApprovedToken {
        let prompt = ApprovalPrompt::new("ws", "rev-1", "act", "target", "summary", digest);
        broker.request_token(&prompt).expect("approved")
    }

    fn scripted_broker(path: &Path) -> LocalApprovalBroker {
        LocalApprovalBroker::with_path_and_soft_decider(
            path,
            Arc::new(NoPresenceVerifier),
            Arc::new(|_| ApprovalDecision::Approved),
        )
    }

    #[test]
    fn history_path_override_is_kept() {
        let base = sandbox("override");
        let custom = base.join("custom-history.jsonl");
        let path = default_approval_history_path_from(&lookup(vec![(
            "ORCEL_APPROVAL_HISTORY_PATH",
            custom.clone().into_os_string(),
        )]));
        assert_eq!(path, Ok(custom));
        let _ = std::fs::remove_dir_all(base);
    }

    /// XP-01B: an override gets the default location's guarantees, so a
    /// parent directory other users can reach is refused.
    #[cfg(unix)]
    #[test]
    fn override_in_a_shared_directory_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let base = sandbox("shared-override");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755))
            .expect("chmod shared");
        let error = default_approval_history_path_from(&lookup(vec![(
            "ORCEL_APPROVAL_HISTORY_PATH",
            base.join("approval-history.jsonl").into_os_string(),
        )]))
        .expect_err("shared parent");
        assert!(
            matches!(error, PlatformError::InsecureMode { .. }),
            "{error:?}"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn empty_or_relative_history_override_is_refused() {
        for value in ["", "custom-history.jsonl", "state/history.jsonl"] {
            let error = default_approval_history_path_from(&lookup(vec![(
                "ORCEL_APPROVAL_HISTORY_PATH",
                OsString::from(value),
            )]))
            .expect_err("relative override");
            assert_eq!(
                error,
                PlatformError::NotAbsolute(PathBuf::from(value)),
                "{value:?}"
            );
            assert_eq!(
                history_path_unavailable(error).code,
                FailureCode::ApprovalUnavailable
            );
        }
    }

    #[test]
    fn missing_state_root_is_an_error_never_temp() {
        let error = default_approval_history_path_from(&lookup(Vec::new())).expect_err("no root");
        assert!(matches!(error, PlatformError::StateRootUnavailable(_)));
        let error = history_path_unavailable(error);
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);
    }

    #[test]
    fn broker_writes_history_under_the_private_root() {
        let base = sandbox("write");
        let lookup = lookup(user_root_env(&base));
        let root = orcel_platform::paths::state_root_from(&lookup).expect("root");
        let path = default_approval_history_path_from(&lookup).expect("history path");
        assert_eq!(path, root.join("approval-history.jsonl"));
        assert!(path.starts_with(&base));
        assert!(!path.starts_with(std::env::temp_dir().join("orcel")));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&root).expect("root").permissions().mode();
            assert_eq!(mode & 0o077, 0);
        }
        let broker = scripted_broker(&path);
        let token = approve_once(&broker, &"a".repeat(64));
        assert!(path.is_file());
        assert!(broker
            .history(10)
            .iter()
            .any(|record| record.id == token.record_id));
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_state_root_fails_closed() {
        let base = sandbox("symlink");
        let lookup = lookup(user_root_env(&base));
        let root = orcel_platform::paths::state_root_from(&lookup).expect("root");
        std::fs::create_dir_all(root.parent().expect("parent")).expect("parent");
        let elsewhere = base.join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("elsewhere");
        std::os::unix::fs::symlink(&elsewhere, &root).expect("symlink");
        let error = default_approval_history_path_from(&lookup).expect_err("symlink");
        assert_eq!(error, PlatformError::Symlink(root));
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn existing_ledger_is_read_in_place_without_migration() {
        let base = sandbox("existing");
        let lookup = lookup(user_root_env(&base));
        let path = default_approval_history_path_from(&lookup).expect("history path");
        let token = approve_once(&scripted_broker(&path), &"b".repeat(64));
        let before = std::fs::read(&path).expect("ledger");
        // A later process resolves the same file and reads it unchanged.
        let again = default_approval_history_path_from(&lookup).expect("history path");
        assert_eq!(again, path);
        let broker = scripted_broker(&again);
        assert!(broker
            .history(10)
            .iter()
            .any(|record| record.id == token.record_id));
        assert_eq!(std::fs::read(&path).expect("ledger"), before);
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(windows)]
    #[test]
    fn windows_ledger_path_is_byte_identical_to_the_previous_default() {
        let local_app_data = sandbox("windows");
        let lookup = lookup(vec![(
            "LOCALAPPDATA",
            local_app_data.clone().into_os_string(),
        )]);
        let path = default_approval_history_path_from(&lookup).expect("history path");
        // The expression the previous default used.
        let previous = PathBuf::from(local_app_data.clone().into_os_string())
            .join("Orcel")
            .join("approval-history.jsonl");
        assert_eq!(
            path.as_os_str().as_encoded_bytes(),
            previous.as_os_str().as_encoded_bytes()
        );
        // Resolution creates the directory private, as on Unix (#358 item
        // 2), so it passes the private-directory check again.
        let orcel = local_app_data.join("Orcel");
        assert!(orcel.is_dir());
        assert_eq!(orcel_platform::paths::ensure_private_dir(&orcel), Ok(()));
        let _ = std::fs::remove_dir_all(local_app_data);
    }
}

#[cfg(test)]
mod soft_decider_tests {
    use super::*;

    fn temp_ledger(label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "orcel-soft-decider-{label}-{}-{nanos}.json",
            std::process::id()
        ))
    }

    fn prompt(digest: &str) -> ApprovalPrompt {
        ApprovalPrompt::new("ws", "rev-1", "act", "target", "summary", digest)
    }

    #[test]
    fn a_scripted_consent_still_runs_the_real_ledger() {
        let path = temp_ledger("approve");
        let broker = LocalApprovalBroker::with_path_and_soft_decider(
            &path,
            Arc::new(NoPresenceVerifier),
            Arc::new(|_| ApprovalDecision::Approved),
        );
        let digest = "a".repeat(64);
        let token = broker.request_token(&prompt(&digest)).expect("approved");
        let expected = ConsumeExpectation::new(digest.clone(), "ws", "rev-1");
        broker
            .consume(&token, &expected, now_ms())
            .expect("first consume");
        // Single use, and the digest must match: the ledger's own rules.
        assert!(broker.consume(&token, &expected, now_ms()).is_err());
        let other = broker.request_token(&prompt(&digest)).expect("approved");
        let wrong = ConsumeExpectation::new("b".repeat(64), "ws", "rev-1");
        assert!(broker.consume(&other, &wrong, now_ms()).is_err());
        let history = broker.history(10);
        assert!(history
            .iter()
            .any(|record| record.id == token.record_id && record.consumed));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_scripted_denial_is_recorded_and_issues_nothing() {
        let path = temp_ledger("deny");
        let broker = LocalApprovalBroker::with_path_and_soft_decider(
            &path,
            Arc::new(NoPresenceVerifier),
            Arc::new(|_| ApprovalDecision::Denied),
        );
        let error = broker
            .request_token(&prompt(&"c".repeat(64)))
            .expect_err("denied");
        assert_eq!(error.code, FailureCode::ApprovalDenied);
        assert!(broker
            .history(10)
            .iter()
            .all(|record| record.decision != RecordedDecision::Approved));
        let _ = std::fs::remove_file(&path);
    }
}

/// XP-09 contract: what any OS's SOFT presenter and STRONG verifier may
/// and may not do to the broker. These run on every OS; the macOS-only
/// tests at the end exercise the real presenter and verifier.
#[cfg(test)]
mod xp09_contract_tests {
    use super::*;

    fn temp_ledger(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "orcel-xp09-{label}-{}-{nanos}.jsonl",
            std::process::id()
        ))
    }

    fn strong(digest: &str) -> ApprovalPrompt {
        ApprovalPrompt::new_strong(
            "default",
            "rev-1",
            "delete file",
            "target",
            "summary",
            digest,
        )
    }

    /// Answers the first request honestly and then replays that answer,
    /// or forges the nonce of every answer.
    #[derive(Debug)]
    struct ScriptedVerifier {
        forge_nonce: bool,
        first: Mutex<Option<PresenceAttestation>>,
    }

    impl ScriptedVerifier {
        fn replaying() -> Self {
            Self {
                forge_nonce: false,
                first: Mutex::new(None),
            }
        }

        fn forging() -> Self {
            Self {
                forge_nonce: true,
                first: Mutex::new(None),
            }
        }
    }

    impl PresenceVerifier for ScriptedVerifier {
        fn method(&self) -> &'static str {
            "test-xp09"
        }

        fn is_available(&self) -> bool {
            true
        }

        fn verify(
            &self,
            ctx: &PresenceContext,
            _lease: &InputLeaseGuard,
        ) -> Result<PresenceAttestation, PresenceError> {
            let honest = PresenceAttestation {
                method: self.method().to_owned(),
                verified_at_ms: now_ms(),
                nonce: ctx.nonce.clone(),
                digest: ctx.digest.clone(),
            };
            if self.forge_nonce {
                return Ok(PresenceAttestation {
                    nonce: format!("{}-other", ctx.nonce),
                    ..honest
                });
            }
            let mut first = self.first.lock().expect("script");
            Ok(first.get_or_insert(honest).clone())
        }
    }

    fn assert_refused_and_recorded(broker: &LocalApprovalBroker, prompt: &ApprovalPrompt) {
        let error = broker.request_token(prompt).expect_err("refused");
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);
        let latest = broker.history(1);
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].digest, prompt.digest);
        assert_eq!(latest[0].decision, RecordedDecision::Unavailable);
    }

    #[test]
    fn xp09_mismatched_presence_nonce_is_rejected() {
        let path = temp_ledger("forged");
        let broker = LocalApprovalBroker::with_path_and_verifier(
            &path,
            Arc::new(ScriptedVerifier::forging()),
        );
        assert_refused_and_recorded(&broker, &strong(&"a".repeat(64)));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn xp09_replayed_presence_answer_is_rejected() {
        let path = temp_ledger("replay");
        let broker = LocalApprovalBroker::with_path_and_verifier(
            &path,
            Arc::new(ScriptedVerifier::replaying()),
        );
        let digest = "b".repeat(64);
        let first = strong(&digest);
        let token = broker
            .request_token(&first)
            .expect("first answer is honest");
        // The same operation asked again: the earlier answer is replayed.
        let second = strong(&digest);
        assert_refused_and_recorded(&broker, &second);
        // And the token from the honest answer is single use.
        let expected = ConsumeExpectation::strong(digest.clone(), "default", "rev-1");
        broker
            .consume(&token, &expected, now_ms())
            .expect("first use");
        assert_eq!(
            broker
                .consume(&token, &expected, now_ms())
                .expect_err("replayed token")
                .code,
            FailureCode::ApprovalDenied
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn xp09_soft_consent_never_answers_strong() {
        let path = temp_ledger("soft-strong");
        let broker = LocalApprovalBroker::with_path_and_soft_decider(
            &path,
            Arc::new(NoPresenceVerifier),
            Arc::new(|_| ApprovalDecision::Approved),
        );
        let error = broker
            .request_token(&strong(&"c".repeat(64)))
            .expect_err("no SOFT downgrade");
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);
        assert!(broker
            .history(10)
            .iter()
            .all(|record| record.decision != RecordedDecision::Approved));
        let _ = std::fs::remove_file(path);
    }

    /// Each OS selects its own verifier; Windows keeps Windows Hello.
    #[test]
    fn xp09_default_verifier_is_selected_per_os() {
        let method = DefaultPresenceVerifier::default().method();
        #[cfg(windows)]
        assert_eq!(method, "windows-hello");
        #[cfg(target_os = "macos")]
        assert_eq!(method, MAC_LOCAL_AUTH_METHOD);
        #[cfg(target_os = "macos")]
        assert_eq!(method, "macos-local-authentication");
        #[cfg(target_os = "linux")]
        assert_eq!(method, POLKIT_PRESENCE_METHOD);
        #[cfg(target_os = "linux")]
        assert_eq!(method, "linux-polkit-auth-self");
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        assert_eq!(method, "none");
    }

    /// CI on macos-latest: the real dialog and the real LocalAuthentication
    /// verifier, through the real broker, fail closed without showing
    /// anything. `ORCEL_REQUIRE_XP09_HEADLESS=1` (set by CI) makes an
    /// interactive session a failure instead of a skip, so the check can
    /// never pass by not running.
    #[cfg(target_os = "macos")]
    #[test]
    fn xp09_macos_headless_paths_fail_closed() {
        let required = std::env::var_os("ORCEL_REQUIRE_XP09_HEADLESS").is_some();
        let session = presence_unix::session_state();
        eprintln!(
            "xp09 session probe: state {session:?}, SessionGetInfo {:x?}",
            presence_unix::session_info()
        );
        if session == presence_unix::SessionState::Interactive {
            assert!(
                !required,
                "ORCEL_REQUIRE_XP09_HEADLESS is set but this session can show prompts"
            );
            return;
        }
        if std::env::var_os("ORCEL_REQUIRE_XP09_BYPASS_ENV").is_some() {
            // S-24: the donor's bypass variables are set for this run.
            for name in [
                ["CUA_ENV", "_SKIP_SENSITIVE_AUTH"].concat(),
                ["CUA_ENV", "_ALLOW_UNVERIFIED_SENSITIVE_EXPORT"].concat(),
            ] {
                assert_eq!(std::env::var(&name).as_deref(), Ok("1"), "{name}");
            }
        }

        let soft = ApprovalPrompt::new(
            "default",
            "rev-1",
            "act",
            "target",
            "summary",
            "d".repeat(64),
        );
        let error = platform_prompt(&soft).expect_err("SOFT fails closed");
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);

        let verifier = MacLocalAuthPresenceVerifier::new();
        assert!(!verifier.is_available());
        let ctx = PresenceContext::new("nonce-probe", "digest-probe", "default", "probe");
        let lease = InputLeaseGuard::suspend_for_presence();
        let error = verifier
            .verify(&ctx, &lease)
            .expect_err("STRONG fails closed");
        assert_eq!(error.reason, PresenceFailureReason::Unavailable);

        let path = temp_ledger("macos-headless");
        let broker = LocalApprovalBroker::with_path(&path);
        assert_eq!(broker.presence_method(), MAC_LOCAL_AUTH_METHOD);
        for prompt in [soft.clone(), strong(&"e".repeat(64))] {
            let error = broker.request_token(&prompt).expect_err("fails closed");
            assert_eq!(error.code, FailureCode::ApprovalUnavailable);
        }
        let history = broker.history(10);
        assert_eq!(history.len(), 2);
        assert!(history
            .iter()
            .all(|record| record.decision == RecordedDecision::Unavailable));
        let _ = std::fs::remove_file(path);
    }

    /// Manual live check on a Mac at the keyboard (never in CI):
    /// `ORCEL_LIVE_APPROVAL_DIALOG=1 ORCEL_LIVE_APPROVAL_EXPECT=approve
    /// cargo test -p orcel-approval xp09_live -- --nocapture` (then again
    /// with `deny`). The SOFT dialog and then the STRONG prompt appear;
    /// answer both as the variable says.
    #[cfg(target_os = "macos")]
    #[test]
    fn xp09_live_macos_dialog_and_presence() {
        if std::env::var_os("ORCEL_LIVE_APPROVAL_DIALOG").is_none() {
            return;
        }
        let expect = std::env::var("ORCEL_LIVE_APPROVAL_EXPECT").unwrap_or_default();
        assert!(
            expect == "approve" || expect == "deny",
            "set ORCEL_LIVE_APPROVAL_EXPECT to approve or deny, got {expect:?}"
        );
        assert_eq!(
            presence_unix::session_state(),
            presence_unix::SessionState::Interactive,
            "the live check needs a GUI login session outside CI"
        );
        let path = temp_ledger("macos-live");
        let broker = LocalApprovalBroker::with_path(&path);
        let soft = ApprovalPrompt::new(
            "default",
            "rev-1",
            "XP-09 live check (SOFT)",
            "nothing is changed",
            "Answer as ORCEL_LIVE_APPROVAL_EXPECT says.",
            "f".repeat(64),
        );
        let strong_prompt = ApprovalPrompt::new_strong(
            "default",
            "rev-1",
            "XP-09 live check (STRONG)",
            "nothing is changed",
            "Answer as ORCEL_LIVE_APPROVAL_EXPECT says.",
            "0".repeat(64),
        );
        for prompt in [soft, strong_prompt] {
            let outcome = broker.request_token(&prompt);
            eprintln!("xp09 live {}: {outcome:?}", prompt.approval_class.as_str());
            assert_eq!(outcome.is_ok(), expect == "approve");
        }
        let _ = std::fs::remove_file(path);
    }
}

/// XP-10: the real Linux paths. On a runner nobody can answer, so the SOFT
/// dialog and polkit presence, through the real broker, must fail closed;
/// the GTK helper itself runs under Xvfb when CI provides it.
#[cfg(all(test, target_os = "linux"))]
mod xp10_linux_tests {
    use super::*;

    fn temp_ledger(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "orcel-xp10-{label}-{}-{nanos}.jsonl",
            std::process::id()
        ))
    }

    /// `ORCEL_REQUIRE_XP10_HEADLESS=1` (set by CI) makes an interactive
    /// session a failure instead of a skip, so the check can never pass by
    /// not running. With `ORCEL_REQUIRE_XP10_BYPASS_ENV` the donor's two
    /// bypass variables must be set and change nothing (S-24).
    #[test]
    fn xp10_linux_headless_paths_fail_closed() {
        let required = std::env::var_os("ORCEL_REQUIRE_XP10_HEADLESS").is_some();
        let session = linux::session_state();
        // The probe of the runner itself, without the CI guard, must also
        // refuse: no logind graphical session is active and local here.
        let facts = linux::sys::session_facts_ignoring_automation();
        eprintln!("xp10 session probe: state {session:?}, facts {facts:?}");
        if session == presence_unix::SessionState::Interactive {
            assert!(
                !required,
                "ORCEL_REQUIRE_XP10_HEADLESS is set but this session can show prompts"
            );
            return;
        }
        if required {
            assert_eq!(
                linux::classify_session(&facts),
                presence_unix::SessionState::NoGraphicSession,
                "{facts:?}"
            );
        }
        if std::env::var_os("ORCEL_REQUIRE_XP10_BYPASS_ENV").is_some() {
            for name in [
                ["CUA_ENV", "_SKIP_SENSITIVE_AUTH"].concat(),
                ["CUA_ENV", "_ALLOW_UNVERIFIED_SENSITIVE_EXPORT"].concat(),
            ] {
                assert_eq!(std::env::var(&name).as_deref(), Ok("1"), "{name}");
            }
        }

        let soft = ApprovalPrompt::new(
            "default",
            "rev-1",
            "act",
            "target",
            "summary",
            "d".repeat(64),
        );
        let error = platform_prompt(&soft).expect_err("SOFT fails closed");
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);

        let verifier = PolkitPresenceVerifier::new();
        assert!(!verifier.is_available());
        let ctx = PresenceContext::new("nonce-probe", "digest-probe", "default", "probe");
        let lease = InputLeaseGuard::suspend_for_presence();
        let error = verifier
            .verify(&ctx, &lease)
            .expect_err("STRONG fails closed");
        assert_eq!(error.reason, PresenceFailureReason::Unavailable);

        let path = temp_ledger("linux-headless");
        let broker = LocalApprovalBroker::with_path(&path);
        assert_eq!(broker.presence_method(), POLKIT_PRESENCE_METHOD);
        let strong = ApprovalPrompt::new_strong(
            "default",
            "rev-1",
            "delete file",
            "target",
            "summary",
            "e".repeat(64),
        );
        for prompt in [soft.clone(), strong] {
            let error = broker.request_token(&prompt).expect_err("fails closed");
            assert_eq!(error.code, FailureCode::ApprovalUnavailable);
        }
        let history = broker.history(10);
        assert_eq!(history.len(), 2);
        assert!(history
            .iter()
            .all(|record| record.decision == RecordedDecision::Unavailable));
        let _ = std::fs::remove_file(path);
    }

    /// CI under Xvfb: the real GTK4 helper shows the dialog, nobody answers,
    /// and its own timeout answers deny with this request's nonce. The
    /// binary comes from `ORCEL_XP10_HELPER_BINARY` in this test only; the
    /// shipped code never reads a helper location from the environment.
    /// `ORCEL_REQUIRE_XP10_HELPER=1` makes a missing binary or display a
    /// failure instead of a skip.
    #[test]
    fn xp10_real_helper_times_out_to_deny_under_xvfb() {
        let required = std::env::var_os("ORCEL_REQUIRE_XP10_HELPER").is_some();
        let binary = std::env::var_os("ORCEL_XP10_HELPER_BINARY").map(PathBuf::from);
        let display = std::env::var_os("DISPLAY").is_some();
        let Some(binary) = binary.filter(|_| display) else {
            assert!(
                !required,
                "ORCEL_REQUIRE_XP10_HELPER is set without ORCEL_XP10_HELPER_BINARY and DISPLAY"
            );
            return;
        };
        let env: Vec<(std::ffi::OsString, std::ffi::OsString)> = linux::HELPER_ENV_ALLOWLIST
            .iter()
            .filter_map(|name| std::env::var_os(name).map(|value| ((*name).into(), value)))
            .collect();
        let started = Instant::now();
        let outcome = linux::sys::run_helper(
            &binary,
            ApprovalClass::Soft,
            soft_macos::DIALOG_HEADER,
            "Orcel requests a local action.\n\nAction: XP-10 CI check\n\nNobody answers; the dialog times out.",
            2,
            Duration::from_secs(60),
            env.clone(),
        );
        eprintln!(
            "xp10 helper under Xvfb: {outcome:?} in {:?}",
            started.elapsed()
        );
        assert_eq!(outcome, linux::HelperOutcome::Answered(false));
        assert!(started.elapsed() >= Duration::from_secs(2));

        // No display: GTK cannot start, and the helper exits without an
        // answer.
        let no_display: Vec<_> = env
            .into_iter()
            .filter(|(name, _)| name != "DISPLAY" && name != "WAYLAND_DISPLAY")
            .collect();
        let outcome = linux::sys::run_helper(
            &binary,
            ApprovalClass::Soft,
            "t",
            "b",
            2,
            Duration::from_secs(60),
            no_display,
        );
        eprintln!("xp10 helper without a display: {outcome:?}");
        assert!(
            matches!(outcome, linux::HelperOutcome::Crashed(_)),
            "{outcome:?}"
        );
    }

    /// #373 item 3, CI under Xvfb: a same-user process that substitutes the
    /// request between orceld and the real GTK4 helper (here a wrapper that
    /// rewrites the action text, keeping the nonce, before the real helper
    /// reads it) gets an answer orceld refuses, because the helper answers
    /// with the SHA-256 of the bytes it read. The unmodified pipe through the
    /// same wrapper is the control: its timeout answers deny normally.
    #[test]
    fn xp10_real_helper_refuses_a_substituted_request_under_xvfb() {
        use std::os::unix::fs::PermissionsExt;
        let required = std::env::var_os("ORCEL_REQUIRE_XP10_HELPER").is_some();
        let binary = std::env::var_os("ORCEL_XP10_HELPER_BINARY").map(PathBuf::from);
        let display = std::env::var_os("DISPLAY").is_some();
        let Some(binary) = binary.filter(|_| display) else {
            assert!(
                !required,
                "ORCEL_REQUIRE_XP10_HELPER is set without ORCEL_XP10_HELPER_BINARY and DISPLAY"
            );
            return;
        };
        let dir = std::env::temp_dir().join(format!(
            "orcel-xp10-substitute-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir(&dir).expect("dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let wrapper = |name: &str, filter: &str| {
            let path = dir.join(name);
            std::fs::write(
                &path,
                format!(
                    "#!/bin/sh\n{filter} | '{}'\n",
                    binary.display().to_string().replace('\'', r"'\''")
                ),
            )
            .expect("wrapper");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
            path
        };
        let control = wrapper("control", "/bin/cat");
        let substitute = wrapper(
            "substitute",
            "/usr/bin/sed 's/Action: delete the draft/Action: delete everything/'",
        );
        let env: Vec<(std::ffi::OsString, std::ffi::OsString)> = linux::HELPER_ENV_ALLOWLIST
            .iter()
            .filter_map(|name| std::env::var_os(name).map(|value| ((*name).into(), value)))
            .collect();
        let body = "Orcel requests a local action.\n\nAction: delete the draft\n\nNobody answers; the dialog times out.";
        let run = |path: &std::path::Path| {
            linux::sys::run_helper(
                path,
                ApprovalClass::Soft,
                soft_macos::DIALOG_HEADER,
                body,
                2,
                Duration::from_secs(60),
                env.clone(),
            )
        };
        let outcome = run(&control);
        eprintln!("xp10 helper behind an unmodified pipe: {outcome:?}");
        assert_eq!(outcome, linux::HelperOutcome::Answered(false));
        let outcome = run(&substitute);
        eprintln!("xp10 helper behind a substituting pipe: {outcome:?}");
        assert!(
            matches!(outcome, linux::HelperOutcome::Malformed(_)),
            "{outcome:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Manual live check on a Linux desktop at the keyboard (never in CI).
    /// See SECURITY_INTEGRATION.md, "XP-10 manual live check (Linux)".
    #[test]
    fn xp10_live_linux_dialog_and_presence() {
        if std::env::var_os("ORCEL_LIVE_APPROVAL_DIALOG").is_none() {
            return;
        }
        let expect = std::env::var("ORCEL_LIVE_APPROVAL_EXPECT").unwrap_or_default();
        assert!(
            expect == "approve" || expect == "deny",
            "set ORCEL_LIVE_APPROVAL_EXPECT to approve or deny, got {expect:?}"
        );
        assert_eq!(
            linux::session_state(),
            presence_unix::SessionState::Interactive,
            "the live check needs an active local X11 or Wayland session outside CI and SSH"
        );
        let path = temp_ledger("linux-live");
        let broker = LocalApprovalBroker::with_path(&path);
        let soft = ApprovalPrompt::new(
            "default",
            "rev-1",
            "XP-10 live check (SOFT)",
            "nothing is changed",
            "Answer as ORCEL_LIVE_APPROVAL_EXPECT says.",
            "f".repeat(64),
        );
        let strong_prompt = ApprovalPrompt::new_strong(
            "default",
            "rev-1",
            "XP-10 live check (STRONG)",
            "nothing is changed",
            "Answer as ORCEL_LIVE_APPROVAL_EXPECT says.",
            "0".repeat(64),
        );
        for prompt in [soft, strong_prompt] {
            let outcome = broker.request_token(&prompt);
            eprintln!("xp10 live {}: {outcome:?}", prompt.approval_class.as_str());
            assert_eq!(outcome.is_ok(), expect == "approve");
        }
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::{Mutex, OnceLock};

    fn issued() -> &'static Mutex<BTreeMap<String, StoredRecord>> {
        static ISSUED: OnceLock<Mutex<BTreeMap<String, StoredRecord>>> = OnceLock::new();
        ISSUED.get_or_init(|| Mutex::new(BTreeMap::new()))
    }

    fn consumed_set() -> &'static Mutex<BTreeSet<String>> {
        static CONSUMED: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
        CONSUMED.get_or_init(|| Mutex::new(BTreeSet::new()))
    }

    #[derive(Debug, Clone, Copy)]
    pub struct FixedApprovalBroker(pub ApprovalDecision);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TestPresenceResult {
        Verified,
        Denied,
        Cancelled,
        Timeout,
        Unavailable,
        Failed,
        Invalid,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct TestPresenceVerifier {
        pub available: bool,
        pub result: TestPresenceResult,
        pub method: &'static str,
    }

    impl TestPresenceVerifier {
        pub fn verified() -> Self {
            Self {
                available: true,
                result: TestPresenceResult::Verified,
                method: "test-hello",
            }
        }

        pub fn unavailable() -> Self {
            Self {
                available: false,
                result: TestPresenceResult::Unavailable,
                method: "test-hello",
            }
        }

        pub fn denied() -> Self {
            Self {
                available: true,
                result: TestPresenceResult::Denied,
                method: "test-hello",
            }
        }
    }

    impl PresenceVerifier for TestPresenceVerifier {
        fn method(&self) -> &'static str {
            self.method
        }

        fn is_available(&self) -> bool {
            self.available
        }

        fn verify(
            &self,
            ctx: &PresenceContext,
            lease: &InputLeaseGuard,
        ) -> Result<PresenceAttestation, PresenceError> {
            if !lease.is_suspended() {
                return Err(PresenceError::invalid(
                    "test presence requires a suspended input lease",
                ));
            }
            if ctx.nonce.trim().is_empty() || ctx.digest.trim().is_empty() {
                return Err(PresenceError::invalid("test presence context is malformed"));
            }
            if !self.available {
                return Err(PresenceError::unavailable(
                    "test presence provider is unavailable",
                ));
            }
            match self.result {
                TestPresenceResult::Verified => Ok(PresenceAttestation {
                    method: self.method.to_owned(),
                    verified_at_ms: ctx.nonce.len() as u64,
                    nonce: ctx.nonce.clone(),
                    digest: ctx.digest.clone(),
                }),
                TestPresenceResult::Denied => {
                    Err(PresenceError::denied("test presence denied the operation"))
                }
                TestPresenceResult::Cancelled => Err(PresenceError::cancelled(
                    "test presence cancelled the operation",
                )),
                TestPresenceResult::Timeout => {
                    Err(PresenceError::timeout("test presence timed out"))
                }
                TestPresenceResult::Unavailable => {
                    Err(PresenceError::unavailable("test presence is unavailable"))
                }
                TestPresenceResult::Failed => Err(PresenceError::failed("test presence failed")),
                TestPresenceResult::Invalid => Err(PresenceError::invalid(
                    "test presence returned invalid data",
                )),
            }
        }
    }

    pub fn broker_with_presence(
        path: std::path::PathBuf,
        verifier: TestPresenceVerifier,
    ) -> LocalApprovalBroker {
        LocalApprovalBroker::with_path_and_verifier(path, Arc::new(verifier))
    }

    fn test_record(prompt: &ApprovalPrompt) -> StoredRecord {
        StoredRecord {
            schema: LEDGER_SCHEMA.to_owned(),
            id: format!("test-{}", prompt.nonce),
            nonce: prompt.nonce.clone(),
            digest: prompt.digest.clone(),
            workspace_id: prompt.workspace_id.clone(),
            policy_revision: prompt.policy_revision.clone(),
            decision: RecordedDecision::Approved,
            approval_class: prompt.approval_class,
            presence_outcome: match prompt.approval_class {
                ApprovalClass::Soft => PresenceOutcome::SoftApproved,
                ApprovalClass::Strong => PresenceOutcome::VerifiedStrong,
            },
            presence_method: String::from("test"),
            epoch: 0,
            is_revoke: false,
            requested_at_ms: prompt.requested_at_ms,
            decided_at_ms: prompt.requested_at_ms,
            expires_at_ms: prompt.expires_at_ms,
            reuse_scope: prompt.reuse_scope.clone(),
            consumed: false,
            prev_checksum: String::from("TEST"),
            checksum: String::from("TEST"),
        }
    }

    impl ApprovalBroker for FixedApprovalBroker {
        fn request_token(&self, prompt: &ApprovalPrompt) -> Result<ApprovedToken, ApprovalError> {
            validate_prompt(prompt)?;
            if prompt.approval_class == ApprovalClass::Strong {
                return Err(ApprovalError::unavailable(
                    "STRONG approval requires platform-mediated presence; a soft test button never satisfies STRONG",
                ));
            }
            match self.0 {
                ApprovalDecision::Approved => {
                    let mut issued = issued().lock().expect("test ledger");
                    if issued.contains_key(&prompt.nonce) {
                        return Err(ApprovalError::invalid(
                            "test approval nonce was already issued",
                        ));
                    }
                    issued.insert(prompt.nonce.clone(), test_record(prompt));
                    Ok(ApprovedToken {
                        record_id: format!("test-{}", prompt.nonce),
                        nonce: prompt.nonce.clone(),
                        digest: prompt.digest.clone(),
                        workspace_id: prompt.workspace_id.clone(),
                        policy_revision: prompt.policy_revision.clone(),
                        expires_at_ms: prompt.expires_at_ms,
                        approval_class: ApprovalClass::Soft,
                        epoch: 0,
                    })
                }
                ApprovalDecision::Denied => Err(ApprovalError::denied(
                    "local user denied the operation in test",
                )),
            }
        }

        fn consume(
            &self,
            token: &ApprovedToken,
            expected: &ConsumeExpectation,
            now_ms: u64,
        ) -> Result<(), ApprovalError> {
            if token.approval_class != expected.approval_class {
                return Err(ApprovalError::stale(
                    "test approval class does not match; STRONG never downgrades to SOFT",
                ));
            }
            let issued = issued().lock().expect("test ledger");
            let record = issued
                .get(&token.nonce)
                .ok_or_else(|| ApprovalError::invalid("test approval token is unknown"))?;
            if record.digest != expected.digest || token.digest != expected.digest {
                return Err(ApprovalError::stale(
                    "test operation digest changed after approval",
                ));
            }
            if record.workspace_id != expected.workspace_id
                || record.policy_revision != expected.policy_revision
            {
                return Err(ApprovalError::stale("test approval scope changed"));
            }
            if now_ms > record.expires_at_ms {
                return Err(ApprovalError::denied("test approval expired"));
            }
            drop(issued);
            let mut consumed = consumed_set().lock().expect("test ledger");
            if !consumed.insert(token.nonce.clone()) {
                return Err(ApprovalError::denied("test approval was already consumed"));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{
        broker_with_presence, FixedApprovalBroker, TestPresenceResult, TestPresenceVerifier,
    };
    use super::*;

    fn prompt_with(digest: &str, now: u64) -> ApprovalPrompt {
        ApprovalPrompt::new_with_clock(
            "default",
            "sg-000019-v1",
            "test action",
            "target",
            "summary",
            digest,
            now,
        )
    }

    fn strong_prompt_with(digest: &str, now: u64) -> ApprovalPrompt {
        ApprovalPrompt::new_strong_with_clock(
            "default",
            "sg-000019-v1",
            "privileged test action",
            "target",
            "summary",
            digest,
            now,
        )
    }

    fn ledger_in(path: &std::path::Path) -> ApprovalLedger {
        ApprovalLedger::load_or_create(path.to_path_buf())
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("orcel-approval-{name}-{suffix}.jsonl"))
    }

    fn token_from(record: &StoredRecord) -> ApprovedToken {
        ApprovedToken {
            record_id: record.id.clone(),
            nonce: record.nonce.clone(),
            digest: record.digest.clone(),
            workspace_id: record.workspace_id.clone(),
            policy_revision: record.policy_revision.clone(),
            expires_at_ms: record.expires_at_ms,
            approval_class: record.approval_class,
            epoch: record.epoch,
        }
    }

    #[test]
    fn issue_a_and_b_consume_a_then_restart_replay_denied() {
        let path = temp_path("reg278-replay");
        let mut ledger = ledger_in(&path);
        let a = strong_prompt_with("reg278-a", 5_000);
        let b = strong_prompt_with("reg278-b", 5_000);
        let ra = ledger
            .record_decision(
                &a,
                RecordedDecision::Approved,
                PresenceOutcome::VerifiedStrong,
                "test",
            )
            .expect("issue A");
        ledger
            .record_decision(
                &b,
                RecordedDecision::Approved,
                PresenceOutcome::VerifiedStrong,
                "test",
            )
            .expect("issue B");
        let token = token_from(&ra);
        let expected = ConsumeExpectation::strong(a.digest.clone(), "default", "sg-000019-v1");
        ledger.consume(&token, &expected, 5_100).expect("consume A");
        drop(ledger);
        let mut resumed = ledger_in(&path);
        assert!(!resumed.poisoned(), "history must load completely");
        assert!(resumed.consumed.contains(&token.nonce));
        assert_eq!(
            resumed.consume(&token, &expected, 5_200).unwrap_err().code,
            FailureCode::ApprovalDenied
        );
        drop(resumed);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn issue_c_after_consumption_survives_restart() {
        let path = temp_path("reg278-successor");
        let mut ledger = ledger_in(&path);
        let a = strong_prompt_with("reg278-before", 5_000);
        let ra = ledger
            .record_decision(
                &a,
                RecordedDecision::Approved,
                PresenceOutcome::VerifiedStrong,
                "test",
            )
            .expect("issue A");
        ledger
            .consume(
                &token_from(&ra),
                &ConsumeExpectation::strong(a.digest.clone(), "default", "sg-000019-v1"),
                5_100,
            )
            .expect("consume A");
        let c = strong_prompt_with("reg278-after", 5_300);
        let rc = ledger
            .record_decision(
                &c,
                RecordedDecision::Approved,
                PresenceOutcome::VerifiedStrong,
                "test",
            )
            .expect("issue C");
        drop(ledger);
        let mut resumed = ledger_in(&path);
        assert!(!resumed.poisoned());
        assert!(
            resumed.records.contains_key(&rc.id),
            "C must survive restart"
        );
        resumed
            .consume(
                &token_from(&rc),
                &ConsumeExpectation::strong(c.digest.clone(), "default", "sg-000019-v1"),
                5_400,
            )
            .expect("consume C after restart");
        drop(resumed);
        let _ = std::fs::remove_file(path);
    }

    fn strong_expectation(record: &StoredRecord) -> ConsumeExpectation {
        ConsumeExpectation::strong(record.digest.clone(), "default", "sg-000019-v1")
    }

    fn issue_strong(ledger: &mut ApprovalLedger, digest: &str, now: u64) -> StoredRecord {
        ledger
            .record_decision(
                &strong_prompt_with(digest, now),
                RecordedDecision::Approved,
                PresenceOutcome::VerifiedStrong,
                "test",
            )
            .expect("issue")
    }

    fn remove_ledger(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(approval_ledger_lock_path(path));
    }

    #[test]
    fn two_brokers_on_one_ledger_see_each_others_transitions() {
        let path = temp_path("reg278-writers");
        let mut first = ledger_in(&path);
        let mut second = ledger_in(&path);
        assert!(
            !first.poisoned() && !second.poisoned(),
            "a second broker is not an integrity failure"
        );
        let a = issue_strong(&mut first, "reg278-concurrent-a", 5_000);
        second
            .consume(&token_from(&a), &strong_expectation(&a), 5_100)
            .expect("second broker sees and consumes A");
        assert_eq!(
            first
                .consume(&token_from(&a), &strong_expectation(&a), 5_100)
                .unwrap_err()
                .code,
            FailureCode::ApprovalDenied,
            "first broker must observe the other broker's consumption"
        );
        let b = issue_strong(&mut second, "reg278-concurrent-b", 5_200);
        first
            .consume(&token_from(&b), &strong_expectation(&b), 5_300)
            .expect("first broker sees and consumes B");
        assert!(!first.poisoned() && !second.poisoned());
        drop(first);
        drop(second);
        let mut resumed = ledger_in(&path);
        assert!(!resumed.poisoned());
        for record in [&a, &b] {
            assert_eq!(
                resumed
                    .consume(&token_from(record), &strong_expectation(record), 5_400)
                    .unwrap_err()
                    .code,
                FailureCode::ApprovalDenied
            );
        }
        drop(resumed);
        remove_ledger(&path);
    }

    #[test]
    fn writer_lock_contention_is_transient_and_never_corruption() {
        let path = temp_path("reg278-busy");
        let mut ledger = ledger_in(&path);
        ledger.lock_wait = Duration::from_millis(50);
        let a = issue_strong(&mut ledger, "reg278-busy", 5_000);
        let holder = acquire_ledger_lock(&path, Duration::ZERO).expect("hold the writer lock");
        let error = ledger
            .consume(&token_from(&a), &strong_expectation(&a), 5_100)
            .unwrap_err();
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);
        assert!(error.message.contains("busy"), "{}", error.message);
        assert!(!ledger.poisoned(), "contention must not poison the broker");
        drop(holder);
        ledger
            .consume(&token_from(&a), &strong_expectation(&a), 5_100)
            .expect("consumption succeeds once the other transaction ends");
        drop(ledger);
        remove_ledger(&path);
    }

    #[test]
    fn truncated_or_deleted_ledger_under_a_live_broker_fails_closed() {
        for delete in [false, true] {
            let path = temp_path("reg278-rollback");
            let mut ledger = ledger_in(&path);
            let a = issue_strong(&mut ledger, "reg278-rollback-a", 5_000);
            ledger
                .consume(&token_from(&a), &strong_expectation(&a), 5_100)
                .expect("consume A");
            let source = std::fs::read_to_string(&path).expect("read");
            if delete {
                std::fs::remove_file(&path).expect("delete ledger");
            } else {
                // Roll back to the issuance, dropping A's consumption marker.
                let first_line = source.find('\n').expect("one line") + 1;
                std::fs::write(&path, &source[..first_line]).expect("truncate");
            }
            assert_eq!(
                ledger
                    .consume(&token_from(&a), &strong_expectation(&a), 5_200)
                    .unwrap_err()
                    .code,
                FailureCode::ApprovalUnavailable
            );
            assert!(ledger.poisoned(), "delete={delete}");
            drop(ledger);
            remove_ledger(&path);
        }
    }

    #[test]
    fn torn_or_modified_chain_never_authorizes_a_token() {
        let path = temp_path("reg278-torn");
        let mut ledger = ledger_in(&path);
        let a = strong_prompt_with("reg278-torn", 5_000);
        let ra = ledger
            .record_decision(
                &a,
                RecordedDecision::Approved,
                PresenceOutcome::VerifiedStrong,
                "test",
            )
            .expect("issue A");
        let token = token_from(&ra);
        let expected = ConsumeExpectation::strong(a.digest.clone(), "default", "sg-000019-v1");
        ledger.consume(&token, &expected, 5_100).expect("consume A");
        drop(ledger);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open");
        use std::io::Write as _;
        file.write_all(b"{\\\"truncated\\\":")
            .expect("partial write");
        drop(file);
        let mut reloaded = ledger_in(&path);
        assert!(
            reloaded.poisoned(),
            "invalid tail must poison instead of trusting prefix"
        );
        assert_eq!(
            reloaded.consume(&token, &expected, 5_200).unwrap_err().code,
            FailureCode::ApprovalUnavailable
        );
        assert!(reloaded
            .record_decision(
                &a,
                RecordedDecision::Approved,
                PresenceOutcome::VerifiedStrong,
                "test"
            )
            .is_err());
        drop(reloaded);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn out_of_order_consumptions_remain_one_shot_across_two_restarts() {
        let path = temp_path("reg278-out-of-order");
        let mut ledger = ledger_in(&path);
        let a = strong_prompt_with("reg278-out-a", 5_000);
        let b = strong_prompt_with("reg278-out-b", 5_100);
        let ra = ledger
            .record_decision(
                &a,
                RecordedDecision::Approved,
                PresenceOutcome::VerifiedStrong,
                "test",
            )
            .expect("issue A");
        let rb = ledger
            .record_decision(
                &b,
                RecordedDecision::Approved,
                PresenceOutcome::VerifiedStrong,
                "test",
            )
            .expect("issue B");
        let ea = ConsumeExpectation::strong(a.digest.clone(), "default", "sg-000019-v1");
        let eb = ConsumeExpectation::strong(b.digest.clone(), "default", "sg-000019-v1");
        ledger
            .consume(&token_from(&rb), &eb, 5_200)
            .expect("consume B first");
        ledger
            .consume(&token_from(&ra), &ea, 5_200)
            .expect("consume A second");
        drop(ledger);
        for _ in 0..2 {
            let mut ledger = ledger_in(&path);
            assert!(!ledger.poisoned());
            assert_eq!(
                ledger
                    .consume(&token_from(&ra), &ea, 5_300)
                    .unwrap_err()
                    .code,
                FailureCode::ApprovalDenied
            );
            assert_eq!(
                ledger
                    .consume(&token_from(&rb), &eb, 5_300)
                    .unwrap_err()
                    .code,
                FailureCode::ApprovalDenied
            );
            drop(ledger);
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn modified_consumption_marker_poison_blocks_further_approvals() {
        let path = temp_path("reg278-marker-tamper");
        let mut ledger = ledger_in(&path);
        let prompt = strong_prompt_with("reg278-tamper", 5_000);
        let record = ledger
            .record_decision(
                &prompt,
                RecordedDecision::Approved,
                PresenceOutcome::VerifiedStrong,
                "test",
            )
            .expect("issue");
        let expected = ConsumeExpectation::strong(prompt.digest.clone(), "default", "sg-000019-v1");
        ledger
            .consume(&token_from(&record), &expected, 5_100)
            .expect("consume");
        drop(ledger);
        let source = std::fs::read_to_string(&path).expect("read");
        assert!(source.contains("\"consumed\":true"));
        let modified = source.replace("\"consumed\":true", "\"consumed\":false");
        std::fs::write(&path, modified).expect("tamper");
        let mut restarted = ledger_in(&path);
        assert!(restarted.poisoned());
        assert_eq!(
            restarted
                .consume(&token_from(&record), &expected, 5_200)
                .unwrap_err()
                .code,
            FailureCode::ApprovalUnavailable
        );
        drop(restarted);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn unsuccessful_append_poison_blocks_all_later_grants() {
        let path = temp_path("reg278-write-failure");
        let mut ledger = ledger_in(&path);
        assert!(!ledger.poisoned());
        // Deliberately make the ledger path a directory so the append fails.
        std::fs::create_dir(&path).expect("simulate storage failure");
        let prompt = strong_prompt_with("reg278-io-failure", 5_000);
        let err = ledger
            .record_decision(
                &prompt,
                RecordedDecision::Approved,
                PresenceOutcome::VerifiedStrong,
                "test",
            )
            .expect_err("persist must fail");
        assert_eq!(err.code, FailureCode::ApprovalUnavailable);
        assert!(ledger.poisoned());
        std::fs::remove_dir(&path).expect("remove blocker");
        let fresh = strong_prompt_with("reg278-next-grant", 5_200);
        assert_eq!(
            ledger
                .record_decision(
                    &fresh,
                    RecordedDecision::Approved,
                    PresenceOutcome::VerifiedStrong,
                    "test"
                )
                .unwrap_err()
                .code,
            FailureCode::ApprovalUnavailable
        );
        drop(ledger);
    }

    /// Writes a history exactly as the v0.1.0 broker did: after consuming A
    /// it reset the tip to A's issuance checksum, so the next record (B)
    /// chains to the issuance instead of to A's consumption marker.
    fn write_legacy_v010_ledger(
        path: &std::path::Path,
        with_successor: bool,
    ) -> (StoredRecord, Vec<u8>) {
        let issuance = |prompt: &ApprovalPrompt, id: &str, prev: &str| {
            let mut record = StoredRecord {
                schema: LEDGER_SCHEMA.to_owned(),
                id: id.to_owned(),
                nonce: prompt.nonce.clone(),
                digest: prompt.digest.clone(),
                workspace_id: prompt.workspace_id.clone(),
                policy_revision: prompt.policy_revision.clone(),
                decision: RecordedDecision::Approved,
                approval_class: ApprovalClass::Strong,
                presence_outcome: PresenceOutcome::VerifiedStrong,
                presence_method: String::from("test-hello"),
                epoch: 0,
                is_revoke: false,
                requested_at_ms: prompt.requested_at_ms,
                decided_at_ms: prompt.requested_at_ms,
                expires_at_ms: prompt.expires_at_ms,
                reuse_scope: prompt.reuse_scope.clone(),
                consumed: false,
                prev_checksum: prev.to_owned(),
                checksum: String::new(),
            };
            record.checksum = record_checksum(&record);
            record
        };
        let a = issuance(
            &strong_prompt_with("legacy-a", 5_000),
            "apr-5000-0",
            "GENESIS",
        );
        let mut marker = a.clone();
        marker.consumed = true;
        marker.prev_checksum = a.checksum.clone();
        marker.checksum = record_checksum(&marker);
        let mut lines = vec![a.clone(), marker];
        if with_successor {
            lines.push(issuance(
                &strong_prompt_with("legacy-b", 5_100),
                "apr-5100-1",
                &a.checksum,
            ));
        }
        let mut bytes = Vec::new();
        for line in &lines {
            bytes.extend(serde_json::to_vec(line).expect("serialize"));
            bytes.push(b'\n');
        }
        std::fs::write(path, &bytes).expect("write legacy ledger");
        (a, bytes)
    }

    #[test]
    fn legacy_v010_history_without_a_successor_still_verifies() {
        let path = temp_path("reg278-legacy-ok");
        let (a, _) = write_legacy_v010_ledger(&path, false);
        let mut ledger = ledger_in(&path);
        assert!(!ledger.poisoned(), "a valid v0.1.0 chain must keep loading");
        assert_eq!(
            ledger
                .consume(&token_from(&a), &strong_expectation(&a), 5_100)
                .unwrap_err()
                .code,
            FailureCode::ApprovalDenied
        );
        drop(ledger);
        remove_ledger(&path);
    }

    #[test]
    fn legacy_v010_broken_chain_fails_closed_until_recovered_with_preserved_evidence() {
        let path = temp_path("reg278-legacy");
        let (a, original) = write_legacy_v010_ledger(&path, true);
        let mut ledger = ledger_in(&path);
        assert!(
            ledger.poisoned(),
            "a broken chain is never trusted as a prefix"
        );
        let error = ledger
            .consume(&token_from(&a), &strong_expectation(&a), 5_100)
            .unwrap_err();
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);
        assert!(
            error.message.contains("orcel approvals recover"),
            "{}",
            error.message
        );
        drop(ledger);
        assert_eq!(
            inspect_approval_ledger(&path).status,
            ApprovalLedgerStatus::Corrupt
        );

        let recovery = recover_approval_ledger(&path).expect("recover");
        assert_eq!(
            std::fs::read(&recovery.quarantined_to).expect("quarantine"),
            original,
            "quarantined evidence is preserved byte for byte"
        );
        assert_eq!(
            recovery.quarantined_sha256,
            hex_lower(&Sha256::digest(&original))
        );
        assert_eq!(recovery.quarantined_bytes, original.len() as u64);
        assert_eq!(
            inspect_approval_ledger(&path),
            ApprovalLedgerInspection {
                status: ApprovalLedgerStatus::Verified,
                verified_records: 1,
                detail: String::new(),
            }
        );

        let mut fresh = ledger_in(&path);
        assert!(!fresh.poisoned());
        assert!(
            fresh
                .consume(&token_from(&a), &strong_expectation(&a), 5_100)
                .is_err(),
            "nothing from the quarantined history authorizes"
        );
        let marker = fresh
            .records
            .values()
            .next()
            .cloned()
            .expect("recovery record");
        assert_eq!(marker.workspace_id, RECOVERY_WORKSPACE);
        assert!(marker.digest.ends_with(&recovery.quarantined_sha256));
        assert!(
            fresh
                .consume(
                    &token_from(&marker),
                    &ConsumeExpectation::new_with_class(
                        marker.digest.clone(),
                        RECOVERY_WORKSPACE,
                        marker.policy_revision.clone(),
                        ApprovalClass::Soft,
                    ),
                    marker.expires_at_ms,
                )
                .is_err(),
            "the recovery record never authorizes"
        );
        let c = issue_strong(&mut fresh, "reg278-after-recovery", 6_000);
        fresh
            .consume(&token_from(&c), &strong_expectation(&c), 6_100)
            .expect("fresh approvals work after recovery");
        drop(fresh);
        let _ = std::fs::remove_file(&recovery.quarantined_to);
        remove_ledger(&path);
    }

    #[test]
    fn recovery_refuses_missing_verified_or_busy_ledgers() {
        let path = temp_path("reg278-recover-refuse");
        let mut ledger = ledger_in(&path);
        let a = issue_strong(&mut ledger, "reg278-recover-refuse", 5_000);
        assert_eq!(
            recover_approval_ledger(&path).unwrap_err().code,
            FailureCode::InvalidRequest,
            "a verified ledger is never quarantined"
        );
        let holder = acquire_ledger_lock(&path, Duration::ZERO).expect("hold the writer lock");
        let busy = recover_approval_ledger_with_wait(&path, Duration::from_millis(50)).unwrap_err();
        assert!(busy.message.contains("busy"), "{}", busy.message);
        drop(holder);
        ledger
            .consume(&token_from(&a), &strong_expectation(&a), 5_100)
            .expect("the refused recovery left the ledger untouched");
        drop(ledger);
        remove_ledger(&path);
    }

    #[test]
    fn same_length_replacement_under_a_live_broker_fails_closed() {
        let path = temp_path("reg278-replaced");
        let mut ledger = ledger_in(&path);
        let a = issue_strong(&mut ledger, "reg278-replaced", 5_000);
        let source = std::fs::read_to_string(&path).expect("read");
        // Same length, different content: flip one checksum hex digit.
        let at = source.find("\"checksum\":\"").expect("checksum") + 12;
        let flipped = if &source[at..at + 1] == "0" { "1" } else { "0" };
        let replaced = format!("{}{}{}", &source[..at], flipped, &source[at + 1..]);
        assert_eq!(replaced.len(), source.len());
        std::fs::write(&path, replaced).expect("replace");
        let error = ledger
            .consume(&token_from(&a), &strong_expectation(&a), 5_100)
            .unwrap_err();
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);
        assert!(error.message.contains("replaced"), "{}", error.message);
        assert!(ledger.poisoned());
        drop(ledger);
        remove_ledger(&path);
    }

    #[test]
    fn emergency_revoke_during_an_open_prompt_refuses_the_approval() {
        let path = temp_path("reg278-revoke-race");
        let mut ledger = ledger_in(&path);
        let prompt = strong_prompt_with("reg278-pending", 5_000);
        let prompt_view = ledger.preflight().expect("preflight");
        // Another process revokes while the person is still deciding.
        let mut other = ledger_in(&path);
        other
            .record_revoke(&strong_prompt_with("reg278-revoke", 5_010), "test")
            .expect("revoke");
        let error = ledger
            .record_prompted_decision(
                &prompt,
                RecordedDecision::Approved,
                PresenceOutcome::VerifiedStrong,
                "test",
                Some(&prompt_view),
            )
            .unwrap_err();
        assert_eq!(error.code, FailureCode::ApprovalDenied);
        let recorded = ledger
            .records
            .values()
            .find(|record| record.nonce == prompt.nonce)
            .expect("the refused decision is still recorded");
        assert_eq!(recorded.decision, RecordedDecision::Unavailable);
        drop(other);
        drop(ledger);
        remove_ledger(&path);
    }

    #[test]
    fn live_broker_adopts_a_recovered_ledger_without_restart() {
        let path = temp_path("reg278-adopt");
        let mut live = ledger_in(&path);
        let a = issue_strong(&mut live, "reg278-adopt-a", 5_000);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open");
        use std::io::Write as _;
        file.write_all(b"{\"torn\":").expect("torn tail");
        drop(file);
        let torn = live
            .consume(&token_from(&a), &strong_expectation(&a), 5_100)
            .unwrap_err();
        assert!(torn.message.contains("incomplete"), "{}", torn.message);
        let recovery = recover_approval_ledger(&path).expect("recover");
        let b = issue_strong(&mut live, "reg278-adopt-b", 6_000);
        assert!(!live.poisoned(), "the live broker adopted the new ledger");
        assert!(
            live.consume(&token_from(&a), &strong_expectation(&a), 6_050)
                .is_err(),
            "nothing from the old view survives adoption"
        );
        live.consume(&token_from(&b), &strong_expectation(&b), 6_100)
            .expect("fresh approval after adoption");
        drop(live);
        let _ = std::fs::remove_file(&recovery.quarantined_to);
        remove_ledger(&path);
    }

    #[test]
    fn poisoned_broker_never_adopts_its_own_unchanged_chain() {
        // The broker already knows this recovery chain; a poisoned view of it
        // must not be cleared by "adopting" the same chain again.
        let path = temp_path("reg278-no-self-adopt");
        write_legacy_v010_ledger(&path, true);
        let recovery = recover_approval_ledger(&path).expect("recover");
        let mut ledger = ledger_in(&path);
        assert!(ledger.starts_with_recovery());
        issue_strong(&mut ledger, "reg278-no-self-adopt", 5_000);
        ledger.fault = Some(LedgerFault::Unverifiable);
        let error = ledger.preflight().unwrap_err();
        assert!(
            error.message.contains("does not verify"),
            "{}",
            error.message
        );
        assert!(ledger.poisoned());
        drop(ledger);
        let _ = std::fs::remove_file(&recovery.quarantined_to);
        remove_ledger(&path);
    }

    #[test]
    fn legacy_v010_interleaved_consumption_fails_closed_with_upgrade_guidance() {
        let path = temp_path("reg278-legacy-interleaved");
        let (a, _) = write_legacy_v010_ledger(&path, false);
        // v0.1.0 chained a marker to its own issuance, so "issue A, issue B,
        // consume A" breaks the chain even with no record after the marker.
        let text = std::fs::read_to_string(&path).expect("read");
        let mut lines: Vec<StoredRecord> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("record"))
            .collect();
        let mut b = a.clone();
        b.id = String::from("apr-5050-9");
        b.nonce = String::from("legacy-b-nonce");
        b.prev_checksum = a.checksum.clone();
        b.checksum = record_checksum(&b);
        lines.insert(1, b);
        let rebuilt: String = lines
            .iter()
            .map(|record| serde_json::to_string(record).expect("serialize") + "\n")
            .collect();
        std::fs::write(&path, rebuilt).expect("write");
        let mut ledger = ledger_in(&path);
        assert!(ledger.poisoned());
        let error = ledger.preflight().unwrap_err();
        assert!(error.message.contains("v0.1.0"), "{}", error.message);
        assert!(error.message.contains("orcel approvals recover"));
        drop(ledger);
        remove_ledger(&path);
    }

    #[cfg(windows)]
    #[test]
    fn sharing_violation_is_transient_and_never_corruption() {
        use std::os::windows::fs::OpenOptionsExt as _;
        let path = temp_path("reg278-sharing");
        let mut ledger = ledger_in(&path);
        let a = issue_strong(&mut ledger, "reg278-sharing", 5_000);
        // Like antivirus or backup software holding the file exclusively.
        let exclusive = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .expect("exclusive open");
        let error = ledger
            .consume(&token_from(&a), &strong_expectation(&a), 5_100)
            .unwrap_err();
        assert!(
            error.message.contains("temporarily unreadable"),
            "{}",
            error.message
        );
        assert!(!ledger.poisoned());
        drop(exclusive);
        ledger
            .consume(&token_from(&a), &strong_expectation(&a), 5_100)
            .expect("consumption succeeds once the file is readable");
        drop(ledger);
        remove_ledger(&path);
    }

    #[test]
    fn open_failure_before_writing_is_transient_not_poison() {
        let path = temp_path("ocr-open-failure");
        let mut ledger = ledger_in(&path);
        let a = issue_strong(&mut ledger, "ocr-open-failure-a", 5_000);
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions.clone()).expect("read-only");
        let error = ledger
            .consume(&token_from(&a), &strong_expectation(&a), 5_100)
            .unwrap_err();
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);
        assert!(
            error.message.contains("temporarily unwritable"),
            "{}",
            error.message
        );
        assert!(
            !ledger.poisoned(),
            "nothing was written, so nothing is uncertain"
        );
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        std::fs::set_permissions(&path, permissions).expect("writable");
        ledger
            .consume(&token_from(&a), &strong_expectation(&a), 5_100)
            .expect("consumption succeeds once the file is writable");
        drop(ledger);
        remove_ledger(&path);
    }

    #[test]
    fn uncertain_write_resumes_only_while_the_chain_still_verifies() {
        let path = temp_path("ocr-uncertain");
        let mut ledger = ledger_in(&path);
        issue_strong(&mut ledger, "ocr-uncertain-a", 5_000);
        ledger.fault = Some(LedgerFault::Durability);
        let error = ledger.ensure_ready().unwrap_err();
        assert!(
            !error.message.contains("approvals recover"),
            "{}",
            error.message
        );
        let b = issue_strong(&mut ledger, "ocr-uncertain-b", 5_100);
        assert!(!ledger.poisoned(), "an intact chain lets the broker resume");
        ledger
            .consume(&token_from(&b), &strong_expectation(&b), 5_200)
            .expect("consume after resuming");

        // The uncertain write landed torn: the broker stays fail-closed.
        ledger.fault = Some(LedgerFault::Durability);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open");
        use std::io::Write as _;
        file.write_all(b"{\"torn\":").expect("torn tail");
        drop(file);
        let torn = ledger.preflight().unwrap_err();
        assert!(torn.message.contains("incomplete"), "{}", torn.message);
        assert!(ledger.poisoned());
        drop(ledger);
        remove_ledger(&path);
    }

    #[test]
    fn recovery_during_an_open_prompt_refuses_the_approval() {
        let path = temp_path("ocr-recovery-race");
        let mut ledger = ledger_in(&path);
        let prompt = strong_prompt_with("ocr-pending", 5_000);
        let prompt_view = ledger.preflight().expect("preflight");
        // Meanwhile another process revokes, the ledger tears and is recovered.
        let mut other = ledger_in(&path);
        other
            .record_revoke(&strong_prompt_with("ocr-revoke", 5_010), "test")
            .expect("revoke");
        drop(other);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open");
        use std::io::Write as _;
        file.write_all(b"{\"torn\":").expect("torn tail");
        drop(file);
        let recovery = recover_approval_ledger(&path).expect("recover");
        let error = ledger
            .record_prompted_decision(
                &prompt,
                RecordedDecision::Approved,
                PresenceOutcome::VerifiedStrong,
                "test",
                Some(&prompt_view),
            )
            .unwrap_err();
        assert_eq!(error.code, FailureCode::ApprovalDenied);
        assert_eq!(
            ledger.revoke_epoch, 0,
            "the recovered chain restarts at epoch 0"
        );
        drop(ledger);
        let _ = std::fs::remove_file(&recovery.quarantined_to);
        remove_ledger(&path);
    }

    #[test]
    fn healthy_broker_adopts_a_recovered_ledger_in_one_transaction() {
        let path = temp_path("ocr-adopt-once");
        let mut live = ledger_in(&path);
        issue_strong(&mut live, "ocr-adopt-once-a", 5_000);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open");
        use std::io::Write as _;
        file.write_all(b"{\"torn\":").expect("torn tail");
        drop(file);
        let recovery = recover_approval_ledger(&path).expect("recover");
        assert!(!live.poisoned(), "this broker never saw the torn tail");
        let b = issue_strong(&mut live, "ocr-adopt-once-b", 6_000);
        live.consume(&token_from(&b), &strong_expectation(&b), 6_100)
            .expect("the first transaction after recovery already succeeds");
        drop(live);
        let _ = std::fs::remove_file(&recovery.quarantined_to);
        remove_ledger(&path);
    }

    #[test]
    fn append_is_never_acknowledged_when_another_writer_appended() {
        let path = temp_path("ocr-second-writer");
        let mut ledger = ledger_in(&path);
        let a = issue_strong(&mut ledger, "ocr-second-writer-a", 5_000);
        let marker = ledger
            .check_consumable(&token_from(&a), &strong_expectation(&a), 5_100)
            .expect("consumable");
        // A writer that bypassed the lock appends the same transition first.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open");
        use std::io::Write as _;
        let mut line = serde_json::to_vec(&marker).expect("serialize");
        line.push(b'\n');
        file.write_all(&line).expect("rival append");
        drop(file);
        let error = ledger.append(marker).unwrap_err();
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);
        assert!(
            ledger.poisoned(),
            "an append that was not alone is never acknowledged"
        );
        assert!(!ledger.consumed.contains(&a.nonce));
        drop(ledger);
        remove_ledger(&path);
    }

    #[test]
    fn recover_with_nothing_to_recover_creates_nothing() {
        let dir = temp_path("ocr-nothing").with_extension("");
        let path = dir.join("approval-history.jsonl");
        assert_eq!(
            recover_approval_ledger(&path).unwrap_err().code,
            FailureCode::InvalidRequest
        );
        assert!(!dir.exists(), "no directory or lock file is created");
        assert_eq!(
            inspect_approval_ledger(&path).status,
            ApprovalLedgerStatus::Missing
        );
        assert!(!dir.exists());
    }

    #[cfg(windows)]
    #[test]
    fn held_lock_file_cannot_be_deleted_and_unreadable_ledger_is_not_quarantined() {
        use std::os::windows::fs::OpenOptionsExt as _;
        let path = temp_path("ocr-windows-lock");
        let mut ledger = ledger_in(&path);
        issue_strong(&mut ledger, "ocr-windows-lock", 5_000);
        let holder = acquire_ledger_lock(&path, Duration::ZERO).expect("hold the writer lock");
        assert!(
            std::fs::remove_file(approval_ledger_lock_path(&path)).is_err(),
            "a held lock file cannot be deleted and replaced"
        );
        drop(holder);

        let exclusive = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .expect("exclusive open");
        let inspection = inspect_approval_ledger(&path);
        assert_eq!(inspection.status, ApprovalLedgerStatus::Unreadable);
        assert!(!inspection.detail.is_empty());
        assert!(recover_approval_ledger(&path).is_err());
        drop(exclusive);
        assert!(path.exists(), "an unreadable ledger is never quarantined");
        assert_eq!(
            inspect_approval_ledger(&path).status,
            ApprovalLedgerStatus::Verified
        );
        drop(ledger);
        remove_ledger(&path);
    }

    #[test]
    fn first_record_during_a_prompt_on_an_empty_ledger_is_not_a_chain_change() {
        let path = temp_path("ocr-first-record");
        let mut ledger = ledger_in(&path);
        let prompt = strong_prompt_with("ocr-first-pending", 5_000);
        let prompt_view = ledger.preflight().expect("preflight");
        assert_eq!(prompt_view.genesis, None);
        let mut other = ledger_in(&path);
        issue_strong(&mut other, "ocr-first-other", 5_010);
        drop(other);
        let record = ledger
            .record_prompted_decision(
                &prompt,
                RecordedDecision::Approved,
                PresenceOutcome::VerifiedStrong,
                "test",
                Some(&prompt_view),
            )
            .expect("an ordinary first record is not a revoke or recovery");
        assert_eq!(record.decision, RecordedDecision::Approved);
        drop(ledger);
        remove_ledger(&path);
    }

    #[test]
    fn recovery_keeps_the_ledger_path_present_and_leaves_no_staged_file() {
        let path = temp_path("ocr-recovery-swap");
        let (_, original) = write_legacy_v010_ledger(&path, true);
        let recovery = recover_approval_ledger(&path).expect("recover");
        assert!(path.exists());
        assert_eq!(std::fs::read(&recovery.quarantined_to).unwrap(), original);
        let dir = path.parent().unwrap();
        let stem = path.file_name().unwrap().to_string_lossy().into_owned();
        let staged: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{stem}.recovering-"))
            })
            .collect();
        assert!(staged.is_empty(), "the staged chain was renamed into place");
        assert_eq!(
            inspect_approval_ledger(&path).status,
            ApprovalLedgerStatus::Verified
        );
        let _ = std::fs::remove_file(&recovery.quarantined_to);
        remove_ledger(&path);
    }

    #[test]
    fn quarantine_preservation_refuses_a_mismatched_copy_and_keeps_the_original() {
        let path = temp_path("ocr-preserve");
        std::fs::write(&path, b"original\n").unwrap();
        let quarantine = path.with_extension("quarantine-test");
        let error = preserve_quarantine(&path, &quarantine, "0000").unwrap_err();
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);
        assert_eq!(std::fs::read(&path).unwrap(), b"original\n");
        assert!(!quarantine.exists(), "a mismatched quarantine is removed");
        std::fs::write(&quarantine, b"older evidence\n").unwrap();
        assert!(
            preserve_quarantine(&path, &quarantine, "0000").is_err(),
            "an existing file at the quarantine name is never replaced"
        );
        assert_eq!(std::fs::read(&quarantine).unwrap(), b"older evidence\n");
        std::fs::remove_file(&quarantine).unwrap();
        let copy = path.with_extension("copy-test");
        copy_into_new_file(&path, &copy).expect("copy into a new file");
        assert_eq!(std::fs::read(&copy).unwrap(), b"original\n");
        assert!(
            copy_into_new_file(&path, &copy).is_err(),
            "never overwrites"
        );
        assert_eq!(std::fs::read(&copy).unwrap(), b"original\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&copy).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "the copy is owner-only: {mode:o}");
        }
        let _ = std::fs::remove_file(&copy);
        flush_existing_file(&path).expect("flush an existing file");
        let digest = hex_lower(&Sha256::digest(b"original\n"));
        preserve_quarantine(&path, &quarantine, &digest).expect("matching quarantine");
        assert_eq!(std::fs::read(&quarantine).unwrap(), b"original\n");
        assert_eq!(std::fs::read(&path).unwrap(), b"original\n");
        let _ = std::fs::remove_file(&quarantine);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn inspection_reports_lock_contention_as_busy() {
        let path = temp_path("ocr-inspect-busy");
        let mut ledger = ledger_in(&path);
        issue_strong(&mut ledger, "ocr-inspect-busy", 5_000);
        let holder = acquire_ledger_lock(&path, Duration::ZERO).expect("hold the writer lock");
        let inspection = inspect_approval_ledger(&path);
        assert_eq!(inspection.status, ApprovalLedgerStatus::Busy);
        assert!(inspection.detail.contains("busy"), "{}", inspection.detail);
        drop(holder);
        drop(ledger);
        remove_ledger(&path);
    }

    #[test]
    fn unopenable_lock_is_reported_unreadable_not_busy() {
        let path = temp_path("ocr-lock-io");
        let mut ledger = ledger_in(&path);
        issue_strong(&mut ledger, "ocr-lock-io", 5_000);
        drop(ledger);
        let lock = approval_ledger_lock_path(&path);
        std::fs::remove_file(&lock).unwrap();
        std::fs::create_dir(&lock).unwrap();
        let inspection = inspect_approval_ledger(&path);
        assert_eq!(inspection.status, ApprovalLedgerStatus::Unreadable);
        assert!(inspection.detail.contains("lock"), "{}", inspection.detail);
        std::fs::remove_dir(&lock).unwrap();
        remove_ledger(&path);
    }

    #[cfg(windows)]
    #[test]
    fn read_only_ledger_is_refused_before_any_recovery_file_is_created() {
        let path = temp_path("ocr-read-only");
        let (_, original) = write_legacy_v010_ledger(&path, true);
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions.clone()).unwrap();
        let error = recover_approval_ledger(&path).unwrap_err();
        assert!(error.message.contains("read-only"), "{}", error.message);
        let dir = path.parent().unwrap();
        let stem = path.file_name().unwrap().to_string_lossy().into_owned();
        let leftovers: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| {
                name.starts_with(&format!("{stem}.quarantine-"))
                    || name.starts_with(&format!("{stem}.recovering-"))
            })
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        assert_eq!(std::fs::read(&path).unwrap(), original);
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        std::fs::set_permissions(&path, permissions).unwrap();
        let recovery = recover_approval_ledger(&path).expect("recovers once writable");
        let _ = std::fs::remove_file(&recovery.quarantined_to);
        remove_ledger(&path);
    }

    #[cfg(windows)]
    #[test]
    fn transient_error_while_resuming_keeps_the_durability_fault() {
        use std::os::windows::fs::OpenOptionsExt as _;
        let path = temp_path("ocr-resume-transient");
        let mut ledger = ledger_in(&path);
        issue_strong(&mut ledger, "ocr-resume-transient", 5_000);
        ledger.fault = Some(LedgerFault::Durability);
        let exclusive = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .expect("exclusive open");
        assert!(ledger.preflight().is_err());
        assert_eq!(ledger.fault, Some(LedgerFault::Durability));
        drop(exclusive);
        ledger
            .preflight()
            .expect("resumes once the ledger is readable");
        assert!(!ledger.poisoned());
        drop(ledger);
        remove_ledger(&path);
    }

    #[cfg(windows)]
    #[test]
    fn failed_final_rename_keeps_the_original_and_removes_the_staged_chain() {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_SHARE_READ: u32 = 0x1;
        const FILE_SHARE_WRITE: u32 = 0x2;
        let path = temp_path("ocr-rename-fails");
        let (_, original) = write_legacy_v010_ledger(&path, true);
        // A process holding the ledger without delete sharing blocks the
        // replacing rename but not reading or linking it.
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&path)
            .expect("hold the ledger");
        let error = recover_approval_ledger(&path).unwrap_err();
        drop(holder);
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);
        assert!(
            error.message.contains("original is unchanged"),
            "{}",
            error.message
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let dir = path.parent().unwrap();
        let stem = path.file_name().unwrap().to_string_lossy().into_owned();
        let leftovers: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(&format!("{stem}.")))
            .collect();
        assert!(
            !leftovers.iter().any(|name| name.contains(".recovering-")),
            "{leftovers:?}"
        );
        for name in leftovers
            .iter()
            .filter(|name| name.contains(".quarantine-"))
        {
            assert_eq!(std::fs::read(dir.join(name)).unwrap(), original);
            std::fs::remove_file(dir.join(name)).unwrap();
        }
        let recovery = recover_approval_ledger(&path).expect("recovery succeeds once released");
        assert_eq!(std::fs::read(&recovery.quarantined_to).unwrap(), original);
        let _ = std::fs::remove_file(&recovery.quarantined_to);
        remove_ledger(&path);
    }

    const CHILD_MODE: &str = "ORCEL_APPROVAL_TEST_CHILD";
    const CHILD_PATH: &str = "ORCEL_APPROVAL_TEST_PATH";
    const CHILD_RECORD: &str = "ORCEL_APPROVAL_TEST_RECORD";
    const CHILD_GO: &str = "ORCEL_APPROVAL_TEST_GO";

    fn spawn_child(
        mode: &str,
        path: &std::path::Path,
        extra: &[(&str, &str)],
    ) -> std::process::Child {
        let mut command = std::process::Command::new(std::env::current_exe().expect("test exe"));
        command
            .args(["--exact", "tests::cross_process_child", "--nocapture"])
            .env(CHILD_MODE, mode)
            .env(CHILD_PATH, path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        for (key, value) in extra {
            command.env(key, value);
        }
        command.spawn().expect("spawn child broker")
    }

    /// Child-process body for the cross-process tests; returns immediately
    /// unless one of them spawned this process.
    #[test]
    fn cross_process_child() {
        use std::io::Write as _;
        let Ok(mode) = std::env::var(CHILD_MODE) else {
            return;
        };
        let path = std::path::PathBuf::from(std::env::var_os(CHILD_PATH).expect("path"));
        match mode.as_str() {
            "consume" => {
                let mut ledger = ledger_in(&path);
                let id = std::env::var(CHILD_RECORD).expect("record id");
                let record = ledger.records.get(&id).cloned().expect("child sees record");
                let go = std::path::PathBuf::from(std::env::var_os(CHILD_GO).expect("go"));
                let deadline = Instant::now() + Duration::from_secs(20);
                while !go.exists() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(1));
                }
                let now = record.requested_at_ms + 1;
                let code =
                    match ledger.consume(&token_from(&record), &strong_expectation(&record), now) {
                        Ok(()) => 0,
                        Err(error) if error.code == FailureCode::ApprovalDenied => 3,
                        Err(_) => 4,
                    };
                std::process::exit(code);
            }
            "crash-mid-append" => {
                let _lock = acquire_ledger_lock(&path, Duration::from_secs(5)).expect("lock");
                let mut file = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .expect("open");
                file.write_all(b"{\"schema\":\"orcel-approval-ledger-v3\",\"id\":")
                    .expect("partial append");
                file.sync_all().expect("sync");
                // Die holding the lock, mid-record, without unwinding.
                std::process::abort();
            }
            _ => std::process::exit(5),
        }
    }

    #[test]
    fn concurrent_processes_consume_one_token_exactly_once() {
        let path = temp_path("reg278-processes");
        let mut ledger = ledger_in(&path);
        let a = issue_strong(&mut ledger, "reg278-processes", 5_000);
        let go = path.with_extension("go");
        let go_value = go.to_string_lossy().into_owned();
        let children: Vec<_> = (0..4)
            .map(|_| {
                spawn_child(
                    "consume",
                    &path,
                    &[(CHILD_RECORD, &a.id), (CHILD_GO, &go_value)],
                )
            })
            .collect();
        std::fs::write(&go, b"").expect("release the children together");
        let codes: Vec<i32> = children
            .into_iter()
            .map(|mut child| child.wait().expect("wait").code().unwrap_or(-1))
            .collect();
        assert_eq!(
            codes.iter().filter(|code| **code == 0).count(),
            1,
            "{codes:?}"
        );
        assert_eq!(
            codes.iter().filter(|code| **code == 3).count(),
            3,
            "{codes:?}"
        );
        assert_eq!(
            ledger
                .consume(
                    &token_from(&a),
                    &strong_expectation(&a),
                    a.requested_at_ms + 1
                )
                .unwrap_err()
                .code,
            FailureCode::ApprovalDenied,
            "this process observes the child's durable consumption"
        );
        assert!(!ledger.poisoned());
        drop(ledger);
        let _ = std::fs::remove_file(go);
        remove_ledger(&path);
    }

    #[test]
    fn crash_mid_append_releases_the_lock_and_fails_closed_until_recovery() {
        let path = temp_path("reg278-crash");
        let mut ledger = ledger_in(&path);
        let a = issue_strong(&mut ledger, "reg278-crash", 5_000);
        let status = spawn_child("crash-mid-append", &path, &[])
            .wait()
            .expect("wait");
        assert!(!status.success(), "the child must die mid-append");
        assert_eq!(
            inspect_approval_ledger(&path).status,
            ApprovalLedgerStatus::Corrupt,
            "the OS released the dead writer's lock and the torn tail is detected"
        );
        assert_eq!(
            ledger
                .consume(&token_from(&a), &strong_expectation(&a), 5_100)
                .unwrap_err()
                .code,
            FailureCode::ApprovalUnavailable
        );
        assert!(ledger.poisoned());
        drop(ledger);
        let recovery = recover_approval_ledger(&path).expect("recover after crash");
        let mut fresh = ledger_in(&path);
        let b = issue_strong(&mut fresh, "reg278-after-crash", 6_000);
        fresh
            .consume(&token_from(&b), &strong_expectation(&b), 6_100)
            .expect("fresh approval after recovery");
        drop(fresh);
        let _ = std::fs::remove_file(&recovery.quarantined_to);
        remove_ledger(&path);
    }

    #[test]
    fn nonces_are_fresh_unique_and_bound_to_digest() {
        let first = prompt_with("digest-a", 1_000);
        let second = prompt_with("digest-a", 1_000);
        assert_ne!(first.nonce, second.nonce);
        assert_eq!(first.expires_at_ms, 1_000 + APPROVAL_TTL_MS);
        assert_eq!(first.reuse_scope, SINGLE_OPERATION_SCOPE);
        assert_eq!(first.approval_class, ApprovalClass::Soft);
        let other = prompt_with("digest-b", 1_000);
        assert_ne!(first.nonce, other.nonce);
    }

    #[test]
    fn broker_contract_distinguishes_soft_and_strong_classes() {
        let soft = prompt_with("digest-soft", 1_000);
        let strong = strong_prompt_with("digest-strong", 1_000);
        assert_eq!(soft.approval_class, ApprovalClass::Soft);
        assert_eq!(strong.approval_class, ApprovalClass::Strong);
        assert_ne!(soft.nonce, strong.nonce);
    }

    #[test]
    fn ledger_consumes_once_then_rejects_replay() {
        let path = temp_path("replay");
        let mut ledger = ledger_in(&path);
        let prompt = prompt_with("digest-replay", 5_000);
        let record = ledger
            .record_decision(
                &prompt,
                RecordedDecision::Approved,
                PresenceOutcome::SoftApproved,
                "soft-button",
            )
            .expect("record");
        let token = token_from(&record);
        let expected = ConsumeExpectation::new(record.digest.clone(), "default", "sg-000019-v1");
        ledger.consume(&token, &expected, 6_000).expect("first use");
        let replay = ledger
            .consume(&token, &expected, 6_000)
            .expect_err("replay");
        assert_eq!(replay.code, FailureCode::ApprovalDenied);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn strong_consumes_once_then_rejects_replay() {
        let path = temp_path("strong-replay");
        let mut ledger = ledger_in(&path);
        let prompt = strong_prompt_with("digest-strong-replay", 5_000);
        let record = ledger
            .record_decision(
                &prompt,
                RecordedDecision::Approved,
                PresenceOutcome::VerifiedStrong,
                "test-hello",
            )
            .expect("record");
        assert_eq!(record.approval_class, ApprovalClass::Strong);
        let token = token_from(&record);
        let expected = ConsumeExpectation::strong(record.digest.clone(), "default", "sg-000019-v1");
        ledger.consume(&token, &expected, 6_000).expect("first use");
        let replay = ledger
            .consume(&token, &expected, 6_000)
            .expect_err("replay");
        assert_eq!(replay.code, FailureCode::ApprovalDenied);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn soft_button_never_satisfies_strong_class() {
        let broker = FixedApprovalBroker(ApprovalDecision::Approved);
        let strong = strong_prompt_with("digest-strong-soft", 9_000);
        let error = broker.request_token(&strong).expect_err("STRONG via soft");
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);
    }

    #[test]
    fn strong_requires_platform_presence_and_fails_closed_when_unavailable() {
        let path = temp_path("strong-unavailable");
        let broker = broker_with_presence(path.clone(), TestPresenceVerifier::unavailable());
        let prompt = strong_prompt_with("digest-unavailable", 5_000);
        let error = broker.request_token(&prompt).expect_err("unavailable");
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);
        let history = broker.history(10);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].approval_class, ApprovalClass::Strong);
        assert_eq!(history[0].presence_outcome, PresenceOutcome::Unavailable);
        assert_eq!(history[0].decision, RecordedDecision::Unavailable);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn strong_succeeds_only_with_verified_presence() {
        let path = temp_path("strong-verified");
        let broker = broker_with_presence(path.clone(), TestPresenceVerifier::verified());
        let prompt = strong_prompt_with("digest-verified", 5_000);
        let token = broker.request_token(&prompt).expect("verified");
        assert_eq!(token.approval_class, ApprovalClass::Strong);
        let expected = ConsumeExpectation::strong(prompt.digest.clone(), "default", "sg-000019-v1");
        broker.consume(&token, &expected, 6_000).expect("consume");
        let history = broker.history(10);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].presence_outcome, PresenceOutcome::VerifiedStrong);
        assert_eq!(history[0].presence_method, "test-hello");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn strong_denial_cancellation_timeout_and_failure_fail_closed() {
        for result in [
            TestPresenceResult::Denied,
            TestPresenceResult::Cancelled,
            TestPresenceResult::Timeout,
            TestPresenceResult::Failed,
            TestPresenceResult::Invalid,
        ] {
            let path = temp_path("strong-negative");
            let broker = broker_with_presence(
                path.clone(),
                TestPresenceVerifier {
                    available: true,
                    result,
                    method: "test-hello",
                },
            );
            let prompt = strong_prompt_with("digest-negative", 5_000);
            let error = broker.request_token(&prompt).expect_err("must fail closed");
            assert!(
                matches!(
                    error.code,
                    FailureCode::ApprovalDenied | FailureCode::ApprovalUnavailable
                ),
                "unexpected code for {result:?}"
            );
            let history = broker.history(10);
            assert_eq!(history.len(), 1);
            assert_ne!(history[0].decision, RecordedDecision::Approved);
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn strong_never_downgrades_to_soft() {
        let path = temp_path("strong-no-downgrade");
        let broker = broker_with_presence(path.clone(), TestPresenceVerifier::verified());
        let prompt = strong_prompt_with("digest-no-downgrade", 5_000);
        let token = broker.request_token(&prompt).expect("verified");
        let soft_expected =
            ConsumeExpectation::new(prompt.digest.clone(), "default", "sg-000019-v1");
        let error = broker
            .consume(&token, &soft_expected, 6_000)
            .expect_err("downgrade");
        assert_eq!(error.code, FailureCode::TargetStale);
        let strong_expected =
            ConsumeExpectation::strong(prompt.digest.clone(), "default", "sg-000019-v1");
        broker
            .consume(&token, &strong_expected, 6_000)
            .expect("strong consume");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn weak_approval_cannot_satisfy_strong_expectation() {
        let path = temp_path("weak-for-strong");
        let mut ledger = ledger_in(&path);
        let soft_prompt = prompt_with("digest-weak", 5_000);
        let record = ledger
            .record_decision(
                &soft_prompt,
                RecordedDecision::Approved,
                PresenceOutcome::SoftApproved,
                "soft-button",
            )
            .expect("record");
        let token = token_from(&record);
        let strong_expected =
            ConsumeExpectation::strong(record.digest.clone(), "default", "sg-000019-v1");
        let error = ledger
            .consume(&token, &strong_expected, 6_000)
            .expect_err("weak for strong");
        assert_eq!(error.code, FailureCode::TargetStale);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn forged_attestation_without_broker_token_cannot_authorize() {
        let path = temp_path("forged");
        let mut ledger = ledger_in(&path);
        let prompt = strong_prompt_with("digest-forged", 5_000);
        let forged = ApprovedToken {
            record_id: "apr-forged".to_owned(),
            nonce: prompt.nonce.clone(),
            digest: prompt.digest.clone(),
            workspace_id: prompt.workspace_id.clone(),
            policy_revision: prompt.policy_revision.clone(),
            expires_at_ms: prompt.expires_at_ms,
            approval_class: ApprovalClass::Strong,
            epoch: 0,
        };
        let expected = ConsumeExpectation::strong(prompt.digest.clone(), "default", "sg-000019-v1");
        let error = ledger
            .consume(&forged, &expected, 6_000)
            .expect_err("forged");
        assert_eq!(error.code, FailureCode::InvalidRequest);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ledger_rejects_expiry_mismatch_and_drift() {
        let path = temp_path("drift");
        let mut ledger = ledger_in(&path);
        let prompt = prompt_with("digest-drift", 5_000);
        let record = ledger
            .record_decision(
                &prompt,
                RecordedDecision::Approved,
                PresenceOutcome::SoftApproved,
                "soft-button",
            )
            .expect("record");
        let token = token_from(&record);
        let expected = ConsumeExpectation::new(record.digest.clone(), "default", "sg-000019-v1");
        let expired = ledger
            .consume(&token, &expected, record.expires_at_ms + 1)
            .expect_err("expired");
        assert_eq!(expired.code, FailureCode::ApprovalDenied);
        let changed = ConsumeExpectation::new("other-digest", "default", "sg-000019-v1");
        let mismatch = ledger
            .consume(&token, &changed, 6_000)
            .expect_err("mismatch");
        assert_eq!(mismatch.code, FailureCode::TargetStale);
        let moved =
            ConsumeExpectation::new(record.digest.clone(), "other-workspace", "sg-000019-v1");
        let drift = ledger.consume(&token, &moved, 6_000).expect_err("drift");
        assert_eq!(drift.code, FailureCode::TargetStale);
        let stale_policy =
            ConsumeExpectation::new(record.digest.clone(), "default", "sg-000018-v1");
        let revision = ledger
            .consume(&token, &stale_policy, 6_000)
            .expect_err("revision drift");
        assert_eq!(revision.code, FailureCode::TargetStale);
        let class_drift =
            ConsumeExpectation::strong(record.digest.clone(), "default", "sg-000019-v1");
        let class_error = ledger
            .consume(&token, &class_drift, 6_000)
            .expect_err("class drift");
        assert_eq!(class_error.code, FailureCode::TargetStale);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn denied_and_unavailable_records_never_authorize() {
        let path = temp_path("denied");
        let mut ledger = ledger_in(&path);
        let prompt = prompt_with("digest-denied", 5_000);
        let record = ledger
            .record_decision(
                &prompt,
                RecordedDecision::Denied,
                PresenceOutcome::Denied,
                "soft-button",
            )
            .expect("record");
        let token = token_from(&record);
        let expected = ConsumeExpectation::new(record.digest.clone(), "default", "sg-000019-v1");
        let error = ledger
            .consume(&token, &expected, 6_000)
            .expect_err("denied");
        assert_eq!(error.code, FailureCode::ApprovalDenied);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn strong_denied_records_never_authorize() {
        let path = temp_path("strong-denied");
        let broker = broker_with_presence(path.clone(), TestPresenceVerifier::denied());
        let prompt = strong_prompt_with("digest-strong-denied", 5_000);
        let error = broker.request_token(&prompt).expect_err("denied");
        assert_eq!(error.code, FailureCode::ApprovalDenied);
        let history = broker.history(10);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].presence_outcome, PresenceOutcome::Denied);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn history_records_class_and_presence_without_secrets() {
        let path = temp_path("history-class");
        let soft_broker = broker_with_presence(path.clone(), TestPresenceVerifier::unavailable());
        let soft_prompt = prompt_with("digest-soft-history", 5_000);
        let _ = soft_broker.ledger.lock().map(|mut ledger| {
            ledger
                .record_decision(
                    &soft_prompt,
                    RecordedDecision::Approved,
                    PresenceOutcome::SoftApproved,
                    "soft-button",
                )
                .expect("soft record")
        });
        drop(soft_broker);
        let strong_broker = broker_with_presence(path.clone(), TestPresenceVerifier::verified());
        drop(strong_broker);
        let mut ledger = ledger_in(&path);
        let strong_prompt = strong_prompt_with("digest-strong-history", 5_000);
        ledger
            .record_decision(
                &strong_prompt,
                RecordedDecision::Approved,
                PresenceOutcome::VerifiedStrong,
                "test-hello",
            )
            .expect("strong record");
        let full = ledger.history(200);
        assert!(full.len() >= 2);
        let rendered = format!("{full:?}");
        assert!(!rendered.contains("summary"));
        assert!(!rendered.contains("target"));
        assert!(!rendered.contains("biometric"));
        assert!(!rendered.contains("secret"));
        assert!(rendered.contains("Soft") || rendered.contains("Strong"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn history_is_redacted_bounded_and_tamper_evident() {
        let path = temp_path("history");
        let mut ledger = ledger_in(&path);
        for digest in ["digest-one", "digest-two", "digest-three"] {
            let prompt = prompt_with(digest, 5_000);
            ledger
                .record_decision(
                    &prompt,
                    RecordedDecision::Approved,
                    PresenceOutcome::SoftApproved,
                    "soft-button",
                )
                .expect("record");
        }
        let full = ledger.history(200);
        assert_eq!(full.len(), 3);
        let rendered = format!("{full:?}");
        assert!(!rendered.contains("summary"));
        assert!(!rendered.contains("target"));
        let bounded = ledger.history(2);
        assert_eq!(bounded.len(), 2);
        drop(ledger);
        let mut text = std::fs::read_to_string(&path).expect("read ledger");
        text = text.replace("digest-two", "digest-tampered");
        std::fs::write(&path, text).expect("tamper ledger");
        let reloaded = ledger_in(&path);
        assert!(reloaded.records.len() < 3);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn forged_history_is_rejected() {
        let path = temp_path("history-forge");
        let mut ledger = ledger_in(&path);
        let prompt = strong_prompt_with("digest-forge", 5_000);
        ledger
            .record_decision(
                &prompt,
                RecordedDecision::Approved,
                PresenceOutcome::VerifiedStrong,
                "test-hello",
            )
            .expect("record");
        drop(ledger);
        let mut text = std::fs::read_to_string(&path).expect("read");
        text = text.replace("verified-strong", "soft-approved");
        std::fs::write(&path, text).expect("tamper");
        let reloaded = ledger_in(&path);
        assert!(reloaded.records.is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn fixed_broker_enforces_one_shot_without_real_ui() {
        let broker = FixedApprovalBroker(ApprovalDecision::Approved);
        let prompt = prompt_with("digest-fixed", 9_000);
        let token = broker.request_token(&prompt).expect("token");
        let expected = ConsumeExpectation::new("digest-fixed", "default", "sg-000019-v1");
        broker.consume(&token, &expected, 9_500).expect("first use");
        let replay = broker
            .consume(&token, &expected, 9_500)
            .expect_err("replay");
        assert_eq!(replay.code, FailureCode::ApprovalDenied);
        let denied = FixedApprovalBroker(ApprovalDecision::Denied);
        let error = denied.request_token(&prompt).expect_err("denied");
        assert_eq!(error.code, FailureCode::ApprovalDenied);
    }

    #[test]
    fn duplicate_consumption_is_replay_for_strong() {
        let path = temp_path("strong-double");
        let broker = broker_with_presence(path.clone(), TestPresenceVerifier::verified());
        let prompt = strong_prompt_with("digest-double", 5_000);
        let token = broker.request_token(&prompt).expect("token");
        let expected = ConsumeExpectation::strong(prompt.digest.clone(), "default", "sg-000019-v1");
        broker.consume(&token, &expected, 6_000).expect("first");
        let replay = broker
            .consume(&token, &expected, 6_000)
            .expect_err("replay");
        assert_eq!(replay.code, FailureCode::ApprovalDenied);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn expired_strong_approval_fails_closed() {
        let path = temp_path("strong-expired");
        let broker = broker_with_presence(path.clone(), TestPresenceVerifier::verified());
        let prompt = strong_prompt_with("digest-expired", 5_000);
        let token = broker.request_token(&prompt).expect("token");
        let expected = ConsumeExpectation::strong(prompt.digest.clone(), "default", "sg-000019-v1");
        let error = broker
            .consume(&token, &expected, prompt.expires_at_ms + 1)
            .expect_err("expired");
        assert_eq!(error.code, FailureCode::ApprovalDenied);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn wrong_nonce_workspace_and_revision_fail_closed_for_strong() {
        let path = temp_path("strong-drift");
        let broker = broker_with_presence(path.clone(), TestPresenceVerifier::verified());
        let prompt = strong_prompt_with("digest-drift", 5_000);
        let token = broker.request_token(&prompt).expect("token");
        let wrong_digest = ConsumeExpectation::strong("other-digest", "default", "sg-000019-v1");
        assert_eq!(
            broker
                .consume(&token, &wrong_digest, 6_000)
                .expect_err("digest")
                .code,
            FailureCode::TargetStale
        );
        let wrong_workspace =
            ConsumeExpectation::strong(prompt.digest.clone(), "other", "sg-000019-v1");
        let path2 = temp_path("strong-drift-2");
        let broker2 = broker_with_presence(path2.clone(), TestPresenceVerifier::verified());
        let prompt2 = strong_prompt_with("digest-drift", 5_000);
        let token2 = broker2.request_token(&prompt2).expect("token");
        assert_eq!(
            broker2
                .consume(&token2, &wrong_workspace, 6_000)
                .expect_err("workspace")
                .code,
            FailureCode::TargetStale
        );
        let wrong_revision =
            ConsumeExpectation::strong(prompt2.digest.clone(), "default", "sg-000018-v1");
        let path3 = temp_path("strong-drift-3");
        let broker3 = broker_with_presence(path3.clone(), TestPresenceVerifier::verified());
        let prompt3 = strong_prompt_with("digest-drift", 5_000);
        let token3 = broker3.request_token(&prompt3).expect("token");
        assert_eq!(
            broker3
                .consume(&token3, &wrong_revision, 6_000)
                .expect_err("revision")
                .code,
            FailureCode::TargetStale
        );
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path2);
        let _ = std::fs::remove_file(path3);
    }

    #[cfg(windows)]
    #[test]
    fn windows_real_presence_path_reports_availability_explicitly() {
        let verifier = WindowsHelloPresenceVerifier::new();
        let available = verifier.is_available();
        let method = verifier.method();
        assert_eq!(method, "windows-hello");
        if available {
            assert!(available);
        } else {
            let ctx = PresenceContext::new("nonce-probe", "digest-probe", "default", "probe");
            let lease = InputLeaseGuard::suspend_for_presence();
            let error = verifier
                .verify(&ctx, &lease)
                .expect_err("unavailable fails closed");
            assert_eq!(error.code, FailureCode::ApprovalUnavailable);
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_default_presence_is_unavailable_fail_closed() {
        let verifier = NoPresenceVerifier;
        assert!(!verifier.is_available());
        let ctx = PresenceContext::new("nonce-probe", "digest-probe", "default", "probe");
        let lease = InputLeaseGuard::suspend_for_presence();
        let error = verifier.verify(&ctx, &lease).expect_err("unavailable");
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);
    }

    #[test]
    fn emergency_revoke_requires_strong_and_invalidates_prior_tokens() {
        let path = temp_path("revoke");
        let broker = broker_with_presence(path.clone(), TestPresenceVerifier::verified());
        let prompt = strong_prompt_with("digest-before-revoke", 5_000);
        let token = broker.request_token(&prompt).expect("token");
        assert_eq!(token.epoch, 0);
        let revoke_prompt = ApprovalPrompt::new_strong_with_clock(
            "default",
            "sg-000019-v1",
            "emergency revoke",
            "revoke",
            "revoke all pending approvals",
            "digest-revoke",
            5_500,
        );
        let epoch = broker.emergency_revoke(&revoke_prompt).expect("revoke");
        assert_eq!(epoch, 1);
        let expected = ConsumeExpectation::strong(prompt.digest.clone(), "default", "sg-000019-v1");
        let error = broker
            .consume(&token, &expected, 6_000)
            .expect_err("revoked");
        assert_eq!(error.code, FailureCode::ApprovalDenied);
        let history = broker.history(10);
        assert!(history.iter().any(|record| record.is_revoke));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn emergency_revoke_with_soft_class_fails_closed() {
        let path = temp_path("revoke-soft");
        let broker = broker_with_presence(path.clone(), TestPresenceVerifier::verified());
        let soft = prompt_with("digest-soft-revoke", 5_000);
        let error = broker.emergency_revoke(&soft).expect_err("soft revoke");
        assert_eq!(error.code, FailureCode::InvalidRequest);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn emergency_revoke_without_presence_fails_closed() {
        let path = temp_path("revoke-unavailable");
        let broker = broker_with_presence(path.clone(), TestPresenceVerifier::unavailable());
        let revoke_prompt = ApprovalPrompt::new_strong_with_clock(
            "default",
            "sg-000019-v1",
            "emergency revoke",
            "revoke",
            "revoke all pending approvals",
            "digest-revoke",
            5_500,
        );
        let error = broker
            .emergency_revoke(&revoke_prompt)
            .expect_err("unavailable");
        assert_eq!(error.code, FailureCode::ApprovalUnavailable);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn revoked_tokens_fail_closed_after_reload() {
        let path = temp_path("revoke-reload");
        let broker = broker_with_presence(path.clone(), TestPresenceVerifier::verified());
        let prompt = strong_prompt_with("digest-reload", 5_000);
        let token = broker.request_token(&prompt).expect("token");
        let revoke_prompt = ApprovalPrompt::new_strong_with_clock(
            "default",
            "sg-000019-v1",
            "emergency revoke",
            "revoke",
            "revoke all pending approvals",
            "digest-revoke",
            5_500,
        );
        broker.emergency_revoke(&revoke_prompt).expect("revoke");
        drop(broker);
        let reloaded = ApprovalLedger::load_or_create(path.clone());
        assert_eq!(reloaded.current_epoch(), 1);
        let expected = ConsumeExpectation::strong(prompt.digest.clone(), "default", "sg-000019-v1");
        let mut reloaded = reloaded;
        let error = reloaded
            .consume(&token, &expected, 6_000)
            .expect_err("revoked after reload");
        assert_eq!(error.code, FailureCode::ApprovalDenied);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn approvals_after_revoke_use_new_epoch() {
        let path = temp_path("revoke-new-epoch");
        let broker = broker_with_presence(path.clone(), TestPresenceVerifier::verified());
        let revoke_prompt = ApprovalPrompt::new_strong_with_clock(
            "default",
            "sg-000019-v1",
            "emergency revoke",
            "revoke",
            "revoke all pending approvals",
            "digest-revoke",
            5_000,
        );
        let epoch = broker.emergency_revoke(&revoke_prompt).expect("revoke");
        assert_eq!(epoch, 1);
        let prompt = strong_prompt_with("digest-after", 6_000);
        let token = broker.request_token(&prompt).expect("token");
        assert_eq!(token.epoch, 1);
        let expected = ConsumeExpectation::strong(prompt.digest.clone(), "default", "sg-000019-v1");
        broker.consume(&token, &expected, 6_500).expect("consume");
        let _ = std::fs::remove_file(path);
    }
}
