//! Authority vocabulary, lease views, grants and standing approvals (spec
//! section 4.3; founder decision FD-UP-10 for standing approvals).
//!
//! Wire types only: no issuance, no checking and no secret material.
//! Issuance and checking stay in `orcel-policy` and `orcel-approval`. A
//! `LeaseView` is a projection and is never accepted as proof of authority.

use serde::{Deserialize, Serialize};

use crate::Contract;

/// SG-000093 authority mode. Moved from `orcel-policy` with identical serde
/// spellings; `orcel-policy` re-exports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityMode {
    Safe,
    FullUser,
    FullAdmin,
    PersistentAdmin,
    RemoteFullControl,
}

impl AuthorityMode {
    pub const ALL: [Self; 5] = [
        Self::Safe,
        Self::FullUser,
        Self::FullAdmin,
        Self::PersistentAdmin,
        Self::RemoteFullControl,
    ];

    pub fn is_default(self) -> bool {
        self == Self::Safe
    }
}

/// SG-000093 executor class. Moved from `orcel-policy` with identical serde
/// spellings; `orcel-policy` re-exports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorClass {
    DesktopObservation,
    DesktopInput,
    ShellProcess,
    Filesystem,
    Browser,
    Web,
    VisualAgent,
    Admin,
    Remote,
}

impl ExecutorClass {
    pub const ALL: [Self; 9] = [
        Self::DesktopObservation,
        Self::DesktopInput,
        Self::ShellProcess,
        Self::Filesystem,
        Self::Browser,
        Self::Web,
        Self::VisualAgent,
        Self::Admin,
        Self::Remote,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Active,
    Expired,
    Revoked,
    Invalidated,
}

/// Approval class. The wire spellings are the existing ones of the MCP tool
/// catalog (`"none"`, `"SOFT"`, `"STRONG"`) and of `orcel-approval`, so the
/// Rust tool mirror and the TypeScript catalog compare equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalClass {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "SOFT")]
    Soft,
    #[serde(rename = "STRONG")]
    Strong,
}

/// Wire projection of an SG-000093 lease. It carries no secret and is never
/// accepted as proof of authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseView {
    /// `"orcel.lease-view/1"`.
    pub contract: String,
    /// Domain-separated SHA-256 (SG-000093, unchanged encoding).
    pub lease_id: String,
    pub mode: AuthorityMode,
    /// SG-000093 binding digest (unchanged encoding).
    pub binding_digest: String,
    pub authority_epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    /// Executor classes enabled now, not the profile ceiling.
    pub executors: Vec<ExecutorClass>,
    pub state: LeaseState,
}

impl Contract for LeaseView {
    const CONTRACT: &'static str = "orcel.lease-view/1";
}

/// A per-action approval: an existing `orcel-approval` one-shot nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRef {
    /// `"orcel.grant-ref/1"`.
    pub contract: String,
    pub approval_class: ApprovalClass,
    /// What was approved, exactly (canonical JSON SHA-256 for new shapes).
    pub action_digest: String,
    /// One-shot, short expiry (SG-000018).
    pub nonce_id: String,
    /// Bound: a restart invalidates every outstanding grant (S10).
    pub orcel_session_id: String,
}

impl Contract for GrantRef {
    const CONTRACT: &'static str = "orcel.grant-ref/1";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRef {
    pub lease_id: String,
    pub binding_digest: String,
    pub authority_epoch: u64,
}

/// The scope a standing approval covers (FD-UP-10). Every list narrows: an
/// empty list covers nothing of that dimension, never everything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingApprovalScope {
    /// `capability/operation` pairs, for example `"web/scrape"`.
    pub operations: Vec<String>,
    /// Executor classes the approval may be used with under a lease. It
    /// never covers `admin` or `remote` (policy refuses such a grant).
    #[serde(default)]
    pub executors: Vec<ExecutorClass>,
    /// Exact origins (`https://host:port`) for web operations.
    #[serde(default)]
    pub origins: Vec<String>,
    /// Workspace roots, as workspace ids, for filesystem operations.
    #[serde(default)]
    pub roots: Vec<String>,
}

/// A standing approval granted once for a declared task scope, per client,
/// with an expiry (founder decision FD-UP-10, recommended safe form).
///
/// It is bound to the requesting principal and client profile (another MCP
/// or REST client cannot use it), to `orcel_session_id` (a restart ends
/// it), and, when granted under Full Control, to the lease (Stop, expiry or
/// an epoch advance ends it). Every dispatch it covers is still audited
/// individually. It never covers remote callers or out-of-scope targets.
/// This is the wire shape only; whether and how it is honoured is decided
/// by `orcel-policy` once FD-UP-10 is decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingApproval {
    /// `"orcel.standing-approval/1"`.
    pub contract: String,
    pub standing_approval_id: String,
    /// `Principal.principal_id` of the client the approval is for.
    pub principal_id: String,
    /// The client profile the approval is for, when the client has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_profile_id: Option<String>,
    /// Caller-supplied task label, shown in the prompt and on the indicator
    /// (bounded, escaped by `prompt_display`). Informational only.
    pub task: String,
    pub scope: StandingApprovalScope,
    /// SHA-256 of `canonical_json(scope)`; dispatches cite it.
    pub scope_digest: String,
    /// The class of the prompt that granted it (STRONG for Full Control).
    pub granted_with: ApprovalClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<LeaseRef>,
    pub orcel_session_id: String,
    pub issued_at_ms: u64,
    /// No later than the lease's expiry when a lease is bound.
    pub expires_at_ms: u64,
}

impl Contract for StandingApproval {
    const CONTRACT: &'static str = "orcel.standing-approval/1";
}

/// Reference to the standing approval a dispatch relied on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingApprovalRef {
    pub standing_approval_id: String,
    pub scope_digest: String,
}

/// Attached by `orceld` to every dispatch and audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchAuthority {
    pub mode: AuthorityMode,
    /// `Some` for every Full Control dispatch (C-05).
    #[serde(default)]
    pub lease: Option<LeaseRef>,
    /// `Some` for every per-action approved dispatch, with or without a
    /// lease (C-04).
    #[serde(default)]
    pub grant: Option<GrantRef>,
    /// `Some` when a standing approval (FD-UP-10) covered the dispatch
    /// instead of a per-action grant. Omitted when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standing_approval: Option<StandingApprovalRef>,
}
