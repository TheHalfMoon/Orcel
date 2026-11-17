//! Authority vocabulary, lease views, grants and standing approvals (spec
//! sections 4.1 to 4.4 and 4.15; FD-UP-10 decided).
//!
//! Wire types only: no issuance, no checking and no secret material.
//! Issuance and checking stay in `orcel-policy` and `orcel-approval`. A
//! `LeaseView` is a projection and is never accepted as proof of authority.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::Contract;

/// SG-000093 authority mode. Moved from `orcel-policy` with identical serde
/// spellings; `orcel-policy` re-exports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
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
#[cfg_attr(test, derive(schemars::JsonSchema))]
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
#[cfg_attr(test, derive(schemars::JsonSchema))]
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
#[cfg_attr(test, derive(schemars::JsonSchema))]
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
#[cfg_attr(test, derive(schemars::JsonSchema))]
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

/// A per-action approval: an existing `orcel-approval` one-shot nonce,
/// bound to the client principal and the Orcel session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
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
    /// The client principal the approval was given to; another client
    /// cannot use it.
    pub principal_id: String,
}

impl Contract for GrantRef {
    const CONTRACT: &'static str = "orcel.grant-ref/1";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct LeaseRef {
    pub lease_id: String,
    pub binding_digest: String,
    pub authority_epoch: u64,
}

/// Why an authority shape is inconsistent. Names the rule, never a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityShapeError {
    /// A non-Safe mode without a lease reference (C-05).
    LeaseMissing,
    /// A non-Safe mode without the authority service's authorization id
    /// (C-05: no authorization record means no dispatch).
    AuthorizationMissing,
    /// Safe mode carrying a lease, a standing approval or an
    /// authorization id, which exist only under Full Control.
    FullControlFieldInSafeMode,
    /// A standing approval not granted with STRONG presence.
    StandingNotStrong,
    /// A standing approval naming an executor it may never cover.
    StandingExecutorRefused,
    /// A standing approval that is empty, unbounded or outlives its lease.
    StandingScopeInvalid,
}

impl fmt::Display for AuthorityShapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::LeaseMissing => "a Full Control mode requires a lease reference",
            Self::AuthorizationMissing => "a Full Control mode requires an authorization id",
            Self::FullControlFieldInSafeMode => "Safe mode carries no lease or standing approval",
            Self::StandingNotStrong => "a standing approval requires STRONG presence",
            Self::StandingExecutorRefused => "a standing approval never covers admin or remote",
            Self::StandingScopeInvalid => "a standing approval scope is empty or unbounded",
        };
        f.write_str(text)
    }
}

impl std::error::Error for AuthorityShapeError {}

/// Attached by `orceld` to every dispatch and audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
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
    /// The standing approval id (section 4.15) that covered the dispatch
    /// instead of a per-action grant.
    #[serde(default)]
    pub standing: Option<String>,
    /// The authority service's `Authorize` decision id (section 4.13);
    /// `Some` for every Full Control dispatch.
    #[serde(default)]
    pub authorization_id: Option<String>,
}

impl DispatchAuthority {
    /// Shape check only: a non-Safe mode needs a lease and an
    /// authorization id; Safe mode carries neither, nor a standing
    /// approval (standing approvals are lease-bound). It decides nothing
    /// about validity: the authority service checks the lease itself.
    pub fn check(&self) -> Result<(), AuthorityShapeError> {
        if self.mode == AuthorityMode::Safe {
            if self.lease.is_some() || self.standing.is_some() || self.authorization_id.is_some() {
                return Err(AuthorityShapeError::FullControlFieldInSafeMode);
            }
            return Ok(());
        }
        if self.lease.is_none() {
            return Err(AuthorityShapeError::LeaseMissing);
        }
        if self.authorization_id.is_none() {
            return Err(AuthorityShapeError::AuthorizationMissing);
        }
        Ok(())
    }
}

/// Upper bound of a declared task text, in bytes.
pub const MAX_TASK_BYTES: usize = 512;
/// Upper bound of each declared scope list.
pub const MAX_STANDING_SCOPE_ITEMS: usize = 64;

/// A standing approval (section 4.15, FD-UP-10 decided): granted once with
/// STRONG presence by the authority service for one identified client and
/// one declared task, bound to a lease, with a declared scope and an expiry
/// no later than the lease's. Every dispatch it covers is still authorized
/// and audited individually with its id. It never covers `admin`, remote
/// callers, out-of-scope targets or another client. Issued only by the
/// service; this is the wire shape.
///
/// Every scope list narrows and nothing is implied: an empty `roots`,
/// `origins` or `commands` list, and `commands: None`, cover nothing of
/// that dimension, never "anything". The `covers_*` methods state this in
/// code, and `check` refuses a `filesystem` executor without roots, since
/// such an approval could cover no filesystem operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct StandingApproval {
    /// `"orcel.standing-approval/1"`.
    pub contract: String,
    pub id: String,
    pub lease_id: String,
    /// The one client the approval is for.
    pub principal_id: String,
    /// Declared task, at most `MAX_TASK_BYTES`, escaped for prompts.
    pub task: String,
    /// Never `admin` or `remote`.
    pub executors: Vec<ExecutorClass>,
    /// Authorized roots (drives or folders); empty covers no path.
    #[serde(default)]
    pub roots: Vec<String>,
    /// Exact canonical origins (`https://host[:port]`) for web operations;
    /// empty covers no origin.
    #[serde(default)]
    pub origins: Vec<String>,
    /// Command names a shell executor may run; `None` or empty covers no
    /// command.
    #[serde(default)]
    pub commands: Option<Vec<String>>,
    /// The presence class of the grant; only `STRONG` is valid.
    pub granted_with: ApprovalClass,
    pub issued_at_ms: u64,
    /// At most the lease's expiry.
    pub expires_at_ms: u64,
}

impl Contract for StandingApproval {
    const CONTRACT: &'static str = "orcel.standing-approval/1";
}

fn bounded_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= crate::MAX_ID_BYTES
}

fn bounded_item(value: &str) -> bool {
    bounded_id(value) && !value.chars().any(char::is_control)
}

impl StandingApproval {
    /// Shape check: STRONG only, no `admin` or `remote` executor, roots for
    /// a `filesystem` executor, canonical origins, a valid declared task,
    /// non-empty bounded fields and a positive time box.
    pub fn check(&self) -> Result<(), AuthorityShapeError> {
        if self.granted_with != ApprovalClass::Strong {
            return Err(AuthorityShapeError::StandingNotStrong);
        }
        if self
            .executors
            .iter()
            .any(|e| matches!(e, ExecutorClass::Admin | ExecutorClass::Remote))
        {
            return Err(AuthorityShapeError::StandingExecutorRefused);
        }
        let commands = self.commands.as_deref().unwrap_or(&[]);
        let lists_ok = !self.executors.is_empty()
            && self.executors.len() <= MAX_STANDING_SCOPE_ITEMS
            && self.roots.len() <= MAX_STANDING_SCOPE_ITEMS
            && self.origins.len() <= MAX_STANDING_SCOPE_ITEMS
            && commands.len() <= MAX_STANDING_SCOPE_ITEMS
            && self
                .roots
                .iter()
                .chain(commands.iter())
                .all(|item| bounded_item(item))
            && self
                .origins
                .iter()
                .all(|origin| crate::web::is_origin(origin));
        let filesystem_without_roots =
            self.executors.contains(&ExecutorClass::Filesystem) && self.roots.is_empty();
        if !lists_ok
            || filesystem_without_roots
            || !bounded_id(&self.id)
            || !bounded_id(&self.lease_id)
            || !bounded_id(&self.principal_id)
            || !crate::web::is_valid_task(&self.task)
            || self.expires_at_ms <= self.issued_at_ms
        {
            return Err(AuthorityShapeError::StandingScopeInvalid);
        }
        Ok(())
    }

    /// Whether `root` is one of the declared roots, exactly. An empty list
    /// covers nothing. Path normalization and containment are the
    /// filesystem provider's.
    pub fn covers_root(&self, root: &str) -> bool {
        self.roots.iter().any(|declared| declared == root)
    }

    /// Whether `origin` is one of the declared origins, exactly. An empty
    /// list covers nothing.
    pub fn covers_origin(&self, origin: &str) -> bool {
        self.origins.iter().any(|declared| declared == origin)
    }

    /// Whether `command` is one of the declared commands, exactly. `None`
    /// and an empty list cover nothing.
    pub fn covers_command(&self, command: &str) -> bool {
        self.commands
            .as_deref()
            .is_some_and(|commands| commands.iter().any(|declared| declared == command))
    }

    /// `check`, plus binding to the given lease: same lease id and an
    /// expiry no later than the lease's.
    pub fn check_against_lease(&self, lease: &LeaseView) -> Result<(), AuthorityShapeError> {
        self.check()?;
        if self.lease_id != lease.lease_id || self.expires_at_ms > lease.expires_at_ms {
            return Err(AuthorityShapeError::StandingScopeInvalid);
        }
        Ok(())
    }
}
