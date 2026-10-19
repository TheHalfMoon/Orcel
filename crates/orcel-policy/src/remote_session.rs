//! SG-000055 local remote-session lease.
//!
//! A remote-session lease is a local `orceld` authorization object created
//! only through a STRONG-gated local command. Every remote-context request is
//! checked against the lease store immediately before dispatch. A request
//! without an exact active lease fails with `REMOTE_SESSION_INACTIVE`; the
//! relay and the provider can never create, widen, renew, or extend a lease.
//!
//! This module is pure policy plus an atomic, checksummed JSON store. It
//! performs no network I/O and holds no provider token, relay secret, or
//! device private key.

use orcel_contracts::{FailureCode, RemoteContext, RequestEnvelope};
use orcel_platform::{paths, PlatformError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::PolicyError;

pub const LEASE_STORE_SCHEMA: &str = "orcel-remote-lease-store/1";
/// Hard maximum lease duration (REMOTE_SESSION_AUTHORIZATION.md section 5).
pub const LEASE_MAX_DURATION_MS: u64 = 15 * 60 * 1000;
/// Minimum lease duration so a lease is never created already expired.
pub const LEASE_MIN_DURATION_MS: u64 = 60 * 1000;
/// Bounded number of stored leases.
pub const MAX_LEASES: usize = 8;
/// The only tool-surface profile mapped for remote use.
pub const REMOTE_PROFILE_CORE: &str = "core";
/// Remote OAuth scope vocabulary (SG-000054).
pub const REMOTE_SCOPES: [&str; 3] = ["orcel.read", "orcel.write", "orcel.execute"];

/// Capability prefixes that manage local authority and are never reachable
/// from a remote-context request, whatever lease exists.
const LOCAL_ONLY_PREFIXES: [&str; 6] = [
    "remote.",
    "workspace.trust.",
    "trust.",
    "approval.",
    "lifecycle.",
    "executable.",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadMode {
    /// Read tools without their own approval class run during the lease.
    Session,
    /// Every remote read additionally requires a fresh local SOFT approval.
    PerRequest,
    /// Remote reads are denied.
    Disabled,
}

impl ReadMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "session" => Some(Self::Session),
            "per_request" => Some(Self::PerRequest),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

/// Interactive workstation binding: the Windows session and its logon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkstationBinding {
    pub session_id: u32,
    pub logon_id: i64,
}

/// Observed workstation state at the moment of dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkstationState {
    Unlocked(WorkstationBinding),
    Locked,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeaseWorkspace {
    pub workspace_id: String,
    /// Workspace trust revision observed when the lease was created.
    pub trust_revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteSessionLease {
    pub lease_id: String,
    pub principal: String,
    pub remote_connection_id: String,
    /// Short-lived connection pinned on first remote use; a different
    /// connection afterwards (for example after reconnect) is inactive.
    pub connection_id: Option<String>,
    pub device_id: String,
    pub device_epoch: u64,
    pub provider_kind: String,
    pub client_profile_id: String,
    pub client_profile_revision: u64,
    pub tool_surface_profile: String,
    pub scope_ceiling: Vec<String>,
    pub workspaces: Vec<LeaseWorkspace>,
    pub read_mode: ReadMode,
    pub policy_revision: String,
    pub workspace_set_digest: String,
    pub workstation: WorkstationBinding,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub revoked: bool,
}

/// Parameters for a new lease, taken from the local STRONG-gated command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRequest {
    pub principal: String,
    pub remote_connection_id: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub provider_kind: String,
    pub client_profile_id: String,
    pub client_profile_revision: u64,
    pub tool_surface_profile: String,
    pub scope_ceiling: Vec<String>,
    pub workspace_ids: Vec<String>,
    pub read_mode: ReadMode,
    pub duration_ms: u64,
}

/// Environment observed by `orceld` immediately before a decision.
pub struct GateEnvironment<'a> {
    pub now_ms: u64,
    pub policy_revision: &'a str,
    pub workspace_set_digest: &'a str,
    pub workstation: WorkstationState,
    /// Current trust revision for a workspace, `None` when untrusted.
    pub trust_revision: &'a dyn Fn(&str) -> Option<u64>,
}

/// A permitted remote dispatch. It is never an action approval: the
/// capability's own SOFT or STRONG approval still applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseGrant {
    pub lease_id: String,
    /// `per_request` read mode: a fresh local SOFT approval is required.
    pub read_requires_approval: bool,
    /// Connection to pin on the lease when this is its first remote use.
    pub pin_connection: Option<String>,
}

fn inactive(message: impl Into<String>) -> PolicyError {
    PolicyError {
        code: FailureCode::RemoteSessionInactive,
        message: message.into(),
    }
}

fn invalid(message: impl Into<String>) -> PolicyError {
    PolicyError {
        code: FailureCode::InvalidRequest,
        message: message.into(),
    }
}

fn is_hex_id(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 32
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_opaque_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

fn is_known_scope(scope: &str) -> bool {
    REMOTE_SCOPES.contains(&scope)
}

/// Required remote scopes for each remotely reachable core capability.
/// Unmapped capability shapes are not covered by any lease.
pub fn required_scopes(capability: &str, operation: &str) -> Option<&'static [&'static str]> {
    const READ: &[&str] = &["orcel.read"];
    const WRITE: &[&str] = &["orcel.write"];
    const EXECUTE: &[&str] = &["orcel.execute"];
    Some(match (capability, operation) {
        ("system.status", "get")
        | ("workspace.get", "get")
        | ("fs.stat", "stat")
        | ("fs.list", "list")
        | ("fs.read", "read")
        | ("fs.search", "search")
        | ("git.status", "status")
        | ("git.diff", "diff")
        | ("git.log", "log")
        | ("fs.read_range", "read")
        | ("fs.find", "find") => READ,
        ("fs.write", "preview")
        | ("fs.write", "write")
        | ("git.branch.create", "create")
        | ("git.stage", "stage")
        | ("git.unstage", "unstage")
        | ("git.commit", "commit")
        | ("git.fetch.preview", "preview")
        | ("git.fetch", "fetch")
        | ("git.push.preview", "preview")
        | ("git.push", "push")
        | ("fs.mkdir", "mkdir")
        | ("fs.move", "move")
        | ("fs.remove", "remove")
        | ("fs.edit", "edit") => WRITE,
        ("process.spawn", "spawn") => EXECUTE,
        _ => return None,
    })
}

/// Whether a capability is a read for read-mode purposes.
pub fn is_read_capability(capability: &str, operation: &str) -> bool {
    required_scopes(capability, operation) == Some(&["orcel.read"][..])
}

/// Whether a capability manages local authority and is local-only.
pub fn is_local_only_capability(capability: &str) -> bool {
    LOCAL_ONLY_PREFIXES
        .iter()
        .any(|prefix| capability.starts_with(prefix))
}

/// Validate the shape of a remote context supplied by the device uplink.
pub fn validate_remote_context(remote: &RemoteContext) -> Result<(), PolicyError> {
    if !is_hex_id(&remote.principal, "rp-")
        || !is_hex_id(&remote.remote_connection_id, "rc-")
        || !is_hex_id(&remote.device_id, "dev-")
        || !is_opaque_token(&remote.connection_id, 128)
        || !is_opaque_token(&remote.provider_kind, 32)
        || !is_opaque_token(&remote.client_profile_id, 64)
        || remote.device_epoch == 0
    {
        return Err(inactive("remote context is malformed"));
    }
    if remote.tool_surface_profile != REMOTE_PROFILE_CORE {
        return Err(inactive("remote tool-surface profile is not mapped"));
    }
    if remote.scopes.is_empty() || !remote.scopes.iter().all(|s| is_known_scope(s)) {
        return Err(inactive("remote scopes are missing or unknown"));
    }
    Ok(())
}

/// Digest of the configured workspace set; any change invalidates leases.
pub fn workspace_set_digest(workspaces: &[(String, PathBuf)]) -> String {
    let mut sorted: Vec<(String, String)> = workspaces
        .iter()
        .map(|(id, root)| (id.clone(), root.to_string_lossy().into_owned()))
        .collect();
    sorted.sort();
    let mut hasher = Sha256::new();
    hasher.update(b"ORCEL_WORKSPACE_SET_V1");
    for (id, root) in sorted {
        hasher.update((id.len() as u64).to_be_bytes());
        hasher.update(id.as_bytes());
        hasher.update((root.len() as u64).to_be_bytes());
        hasher.update(root.as_bytes());
    }
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decide a remote-context request against the stored leases. Any mismatch
/// fails closed with `REMOTE_SESSION_INACTIVE`; local-only capabilities fail
/// with `CAPABILITY_DENIED`. A grant is never an action approval.
pub fn check_remote_dispatch(
    leases: &[RemoteSessionLease],
    request: &RequestEnvelope,
    remote: &RemoteContext,
    env: &GateEnvironment<'_>,
) -> Result<LeaseGrant, PolicyError> {
    if is_local_only_capability(&request.capability) {
        return Err(PolicyError {
            code: FailureCode::CapabilityDenied,
            message: "local authority management is never reachable remotely".into(),
        });
    }
    validate_remote_context(remote)?;
    let lease = leases
        .iter()
        .find(|lease| lease.remote_connection_id == remote.remote_connection_id)
        .ok_or_else(|| inactive("no remote-session lease exists for this connection"))?;
    if lease.revoked {
        return Err(inactive("the remote-session lease was revoked"));
    }
    if lease.expires_at_ms <= lease.created_at_ms
        || lease.expires_at_ms - lease.created_at_ms > LEASE_MAX_DURATION_MS
        || env.now_ms >= lease.expires_at_ms
        || env.now_ms < lease.created_at_ms
    {
        return Err(inactive("the remote-session lease is expired"));
    }
    if lease.principal != remote.principal
        || lease.device_id != remote.device_id
        || lease.device_epoch != remote.device_epoch
        || lease.provider_kind != remote.provider_kind
    {
        return Err(inactive(
            "the remote route does not match the remote-session lease",
        ));
    }
    if lease.client_profile_id != remote.client_profile_id
        || lease.client_profile_revision != remote.client_profile_revision
        || lease.tool_surface_profile != remote.tool_surface_profile
    {
        return Err(inactive(
            "the client profile changed since the remote-session lease was created",
        ));
    }
    let pin_connection = match &lease.connection_id {
        Some(pinned) if pinned == &remote.connection_id => None,
        Some(_) => {
            return Err(inactive(
                "the remote connection changed; reconnect does not extend the lease",
            ))
        }
        None => Some(remote.connection_id.clone()),
    };
    if lease.policy_revision != env.policy_revision
        || lease.workspace_set_digest != env.workspace_set_digest
    {
        return Err(inactive(
            "the local policy changed since the remote-session lease was created",
        ));
    }
    match &env.workstation {
        WorkstationState::Unlocked(binding) if binding == &lease.workstation => {}
        WorkstationState::Unlocked(_) => {
            return Err(inactive(
                "the interactive logon changed since the remote-session lease was created",
            ))
        }
        WorkstationState::Locked => return Err(inactive("the workstation is locked")),
        WorkstationState::Unknown => {
            return Err(inactive(
                "the workstation state is unavailable; remote dispatch fails closed",
            ))
        }
    }
    let leased = lease
        .workspaces
        .iter()
        .find(|entry| entry.workspace_id == request.workspace_id)
        .ok_or_else(|| inactive("the workspace is not included in the remote-session lease"))?;
    if (env.trust_revision)(&leased.workspace_id) != Some(leased.trust_revision) {
        return Err(inactive(
            "the workspace trust changed since the remote-session lease was created",
        ));
    }
    let required = required_scopes(&request.capability, &request.operation)
        .ok_or_else(|| inactive("the capability is not covered by the remote-session lease"))?;
    for scope in required {
        if !remote.scopes.iter().any(|s| s == scope)
            || !lease.scope_ceiling.iter().any(|s| s == scope)
        {
            return Err(inactive(
                "the required remote scope is outside the token or the leased ceiling",
            ));
        }
    }
    let read = is_read_capability(&request.capability, &request.operation);
    if read && lease.read_mode == ReadMode::Disabled {
        return Err(inactive(
            "remote reads are disabled for this remote-session lease",
        ));
    }
    Ok(LeaseGrant {
        lease_id: lease.lease_id.clone(),
        read_requires_approval: read && lease.read_mode == ReadMode::PerRequest,
        pin_connection,
    })
}

/// Validate a lease request and build the lease. Callers must obtain STRONG
/// local presence bound to `lease_request_digest` before storing it.
pub fn build_lease(
    request: &LeaseRequest,
    lease_id: String,
    env: &GateEnvironment<'_>,
    configured_workspaces: &[String],
) -> Result<RemoteSessionLease, PolicyError> {
    if !is_hex_id(&request.principal, "rp-")
        || !is_hex_id(&request.remote_connection_id, "rc-")
        || !is_hex_id(&request.device_id, "dev-")
        || request.device_epoch == 0
        || !is_opaque_token(&request.provider_kind, 32)
        || !is_opaque_token(&request.client_profile_id, 64)
    {
        return Err(invalid("lease route identifiers are malformed"));
    }
    if request.tool_surface_profile != REMOTE_PROFILE_CORE {
        return Err(invalid(
            "only the core tool-surface profile is mapped for remote use",
        ));
    }
    if request.scope_ceiling.is_empty() || !request.scope_ceiling.iter().all(|s| is_known_scope(s))
    {
        return Err(invalid("the lease scope ceiling is missing or unknown"));
    }
    if request.duration_ms < LEASE_MIN_DURATION_MS || request.duration_ms > LEASE_MAX_DURATION_MS {
        return Err(invalid(
            "lease duration must be between 1 and 15 minutes; no remote API can request longer",
        ));
    }
    if request.workspace_ids.is_empty() || request.workspace_ids.len() > 16 {
        return Err(invalid("a lease names between 1 and 16 workspaces"));
    }
    let WorkstationState::Unlocked(workstation) = env.workstation.clone() else {
        return Err(inactive(
            "a lease can only be created on an unlocked interactive workstation",
        ));
    };
    let mut workspaces = Vec::new();
    for id in &request.workspace_ids {
        if !configured_workspaces
            .iter()
            .any(|configured| configured == id)
        {
            return Err(PolicyError {
                code: FailureCode::WorkspaceDenied,
                message: "a leased workspace is not configured".into(),
            });
        }
        if workspaces
            .iter()
            .any(|entry: &LeaseWorkspace| &entry.workspace_id == id)
        {
            return Err(invalid("a leased workspace is listed twice"));
        }
        let trust_revision = (env.trust_revision)(id).ok_or_else(|| PolicyError {
            code: FailureCode::WorkspaceDenied,
            message: "a leased workspace is not trusted".into(),
        })?;
        workspaces.push(LeaseWorkspace {
            workspace_id: id.clone(),
            trust_revision,
        });
    }
    Ok(RemoteSessionLease {
        lease_id,
        principal: request.principal.clone(),
        remote_connection_id: request.remote_connection_id.clone(),
        connection_id: None,
        device_id: request.device_id.clone(),
        device_epoch: request.device_epoch,
        provider_kind: request.provider_kind.clone(),
        client_profile_id: request.client_profile_id.clone(),
        client_profile_revision: request.client_profile_revision,
        tool_surface_profile: request.tool_surface_profile.clone(),
        scope_ceiling: request.scope_ceiling.clone(),
        workspaces,
        read_mode: request.read_mode,
        policy_revision: env.policy_revision.to_owned(),
        workspace_set_digest: env.workspace_set_digest.to_owned(),
        workstation,
        created_at_ms: env.now_ms,
        expires_at_ms: env.now_ms + request.duration_ms,
        revoked: false,
    })
}

/// Digest bound into the STRONG approval for a lease creation.
pub fn lease_request_digest(request: &LeaseRequest, policy_revision: &str) -> String {
    let mut hasher = Sha256::new();
    let mut field = |value: &[u8]| {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    };
    field(b"ORCEL_REMOTE_LEASE_APPROVAL_V1");
    field(policy_revision.as_bytes());
    field(request.principal.as_bytes());
    field(request.remote_connection_id.as_bytes());
    field(request.device_id.as_bytes());
    field(request.device_epoch.to_string().as_bytes());
    field(request.provider_kind.as_bytes());
    field(request.client_profile_id.as_bytes());
    field(request.client_profile_revision.to_string().as_bytes());
    field(request.tool_surface_profile.as_bytes());
    field(request.scope_ceiling.join(" ").as_bytes());
    field(request.workspace_ids.join("\n").as_bytes());
    field(format!("{:?}", request.read_mode).as_bytes());
    field(request.duration_ms.to_string().as_bytes());
    hex_lower(&hasher.finalize())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StoredLeases {
    schema: String,
    leases: Vec<RemoteSessionLease>,
    checksum: String,
}

fn leases_checksum(leases: &[RemoteSessionLease]) -> String {
    let body = serde_json::to_vec(leases).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(LEASE_STORE_SCHEMA.as_bytes());
    hasher.update(&body);
    hex_lower(&hasher.finalize())
}

/// Protected lease store location: `ORCEL_REMOTE_LEASE_PATH`, else
/// `remote_leases.json` in the private per-user Orcel state root (XP-01B).
/// Fails closed when the override is empty or relative, or when the root
/// cannot be resolved or is not private; it never falls back to the shared
/// temp directory. The override must stay listed in
/// `protected_state::PROTECTED_STATE_OVERRIDES`.
pub fn default_lease_store_path() -> Result<PathBuf, PlatformError> {
    default_lease_store_path_from(&|name| std::env::var_os(name))
}

/// [`default_lease_store_path`] with the environment read through `lookup`.
pub fn default_lease_store_path_from(
    lookup: &dyn Fn(&str) -> Option<OsString>,
) -> Result<PathBuf, PlatformError> {
    if let Some(path) = lookup("ORCEL_REMOTE_LEASE_PATH") {
        return paths::absolute_override(path);
    }
    let root = paths::state_root_from(lookup)?;
    paths::ensure_private_dir(&root)?;
    Ok(root.join("remote_leases.json"))
}

/// Load the lease store. A missing, unreadable, corrupt, or tampered store
/// yields no leases, so every remote request fails closed.
pub fn load_leases(path: &Path) -> Vec<RemoteSessionLease> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    let Ok(stored) = serde_json::from_slice::<StoredLeases>(&bytes) else {
        return Vec::new();
    };
    if stored.schema != LEASE_STORE_SCHEMA
        || stored.checksum != leases_checksum(&stored.leases)
        || stored.leases.len() > MAX_LEASES
    {
        return Vec::new();
    }
    stored.leases
}

/// Atomically replace the lease store.
pub fn save_leases(path: &Path, leases: &[RemoteSessionLease]) -> Result<(), PolicyError> {
    if leases.len() > MAX_LEASES {
        return Err(invalid("too many remote-session leases"));
    }
    let stored = StoredLeases {
        schema: LEASE_STORE_SCHEMA.into(),
        leases: leases.to_vec(),
        checksum: leases_checksum(leases),
    };
    let bytes = serde_json::to_vec_pretty(&stored)
        .map_err(|error| invalid(format!("serialize lease store: {error}")))?;
    let internal = |message: String| PolicyError {
        code: FailureCode::InternalError,
        message,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| internal(format!("create lease store directory: {error}")))?;
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| internal("lease store path has no file name".into()))?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let temp = path.with_file_name(format!(
        ".{}.tmp-{}-{nanos}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let result = std::fs::write(&temp, &bytes)
        .and_then(|()| std::fs::rename(&temp, path))
        .map_err(|error| internal(format!("write lease store: {error}")));
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// Insert or replace the lease for one remote connection, pruning expired
/// and revoked leases. Replacing is the only widening path and requires the
/// same STRONG approval as creation.
pub fn upsert_lease(
    leases: &[RemoteSessionLease],
    lease: RemoteSessionLease,
    now_ms: u64,
) -> Result<Vec<RemoteSessionLease>, PolicyError> {
    let mut next: Vec<RemoteSessionLease> = leases
        .iter()
        .filter(|existing| {
            existing.remote_connection_id != lease.remote_connection_id
                && !existing.revoked
                && existing.expires_at_ms > now_ms
        })
        .cloned()
        .collect();
    if next.len() >= MAX_LEASES {
        return Err(invalid("too many active remote-session leases"));
    }
    next.push(lease);
    Ok(next)
}

/// Revoke the lease for one remote connection, or every lease when `None`.
/// Revocation is authority-reducing and needs no approval.
pub fn revoke_leases(
    leases: &[RemoteSessionLease],
    remote_connection_id: Option<&str>,
) -> (Vec<RemoteSessionLease>, usize) {
    let mut count = 0;
    let next = leases
        .iter()
        .map(|lease| {
            let mut lease = lease.clone();
            if !lease.revoked
                && remote_connection_id.is_none_or(|id| id == lease.remote_connection_id)
            {
                lease.revoked = true;
                count += 1;
            }
            lease
        })
        .collect();
    (next, count)
}

/// Pin the short-lived connection on first remote use.
pub fn pin_connection(
    leases: &[RemoteSessionLease],
    remote_connection_id: &str,
    connection_id: &str,
) -> Vec<RemoteSessionLease> {
    leases
        .iter()
        .map(|lease| {
            let mut lease = lease.clone();
            if lease.remote_connection_id == remote_connection_id && lease.connection_id.is_none() {
                lease.connection_id = Some(connection_id.to_owned());
            }
            lease
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: u64 = 1_800_000_000_000;

    fn binding() -> WorkstationBinding {
        WorkstationBinding {
            session_id: 2,
            logon_id: 133_000_000_000_000_000,
        }
    }

    fn trusted(id: &str) -> Option<u64> {
        if id == "default" || id == "other" {
            Some(3)
        } else {
            None
        }
    }

    fn env(now_ms: u64) -> GateEnvironment<'static> {
        GateEnvironment {
            now_ms,
            policy_revision: "sg-000040-v1",
            workspace_set_digest: "d1",
            workstation: WorkstationState::Unlocked(binding()),
            trust_revision: &trusted,
        }
    }

    fn lease_request() -> LeaseRequest {
        LeaseRequest {
            principal: format!("rp-{}", "a".repeat(32)),
            remote_connection_id: format!("rc-{}", "b".repeat(32)),
            device_id: format!("dev-{}", "c".repeat(32)),
            device_epoch: 1,
            provider_kind: "generic".into(),
            client_profile_id: "profile-1".into(),
            client_profile_revision: 1,
            tool_surface_profile: "core".into(),
            scope_ceiling: vec!["orcel.read".into(), "orcel.write".into()],
            workspace_ids: vec!["default".into()],
            read_mode: ReadMode::Session,
            duration_ms: 10 * 60 * 1000,
        }
    }

    fn lease() -> RemoteSessionLease {
        build_lease(
            &lease_request(),
            "lease-1".into(),
            &env(NOW),
            &["default".into(), "other".into()],
        )
        .unwrap()
    }

    fn remote() -> RemoteContext {
        RemoteContext {
            principal: format!("rp-{}", "a".repeat(32)),
            remote_connection_id: format!("rc-{}", "b".repeat(32)),
            connection_id: "cn-1".into(),
            device_id: format!("dev-{}", "c".repeat(32)),
            device_epoch: 1,
            provider_kind: "generic".into(),
            client_profile_id: "profile-1".into(),
            client_profile_revision: 1,
            tool_surface_profile: "core".into(),
            scopes: vec!["orcel.read".into(), "orcel.write".into()],
        }
    }

    fn request(capability: &str, operation: &str, workspace: &str) -> RequestEnvelope {
        RequestEnvelope {
            version: 1,
            request_id: "r1".into(),
            client_session_id: "s1".into(),
            workspace_id: workspace.into(),
            capability: capability.into(),
            operation: operation.into(),
            target: Some(".".into()),
            arguments: json!({}),
        }
    }

    fn inactive_code(result: Result<LeaseGrant, PolicyError>) -> String {
        let error = result.expect_err("must deny");
        assert_eq!(
            error.code,
            FailureCode::RemoteSessionInactive,
            "{}",
            error.message
        );
        error.message
    }

    #[test]
    fn active_exact_lease_permits_and_pins_connection() {
        let leases = vec![lease()];
        let grant = check_remote_dispatch(
            &leases,
            &request("fs.read", "read", "default"),
            &remote(),
            &env(NOW + 1000),
        )
        .unwrap();
        assert_eq!(grant.pin_connection.as_deref(), Some("cn-1"));
        assert!(!grant.read_requires_approval);
        let pinned = pin_connection(&leases, &remote().remote_connection_id, "cn-1");
        let again = check_remote_dispatch(
            &pinned,
            &request("fs.read", "read", "default"),
            &remote(),
            &env(NOW + 2000),
        )
        .unwrap();
        assert_eq!(again.pin_connection, None);
    }

    /// SG-000071: two providers paired to the same device each hold their
    /// own lease. A context from one provider can never use the other's
    /// lease, whatever single identity field it shares or changes.
    #[test]
    fn cross_provider_contexts_never_share_a_lease() {
        let openai = lease();
        let mut claude_request = lease_request();
        claude_request.remote_connection_id = format!("rc-{}", "d".repeat(32));
        claude_request.provider_kind = "anthropic".into();
        claude_request.client_profile_id = "profile-2".into();
        let claude = build_lease(
            &claude_request,
            "lease-2".into(),
            &env(NOW),
            &["default".into(), "other".into()],
        )
        .unwrap();
        let leases = vec![openai.clone(), claude.clone()];
        let read = request("fs.read", "read", "default");

        // Each provider's own context is admitted by its own lease only.
        let mut claude_remote = remote();
        claude_remote.remote_connection_id = claude.remote_connection_id.clone();
        claude_remote.provider_kind = "anthropic".into();
        claude_remote.client_profile_id = "profile-2".into();
        claude_remote.connection_id = "cn-2".into();
        assert!(check_remote_dispatch(&leases, &read, &remote(), &env(NOW + 1)).is_ok());
        assert!(check_remote_dispatch(&leases, &read, &claude_remote, &env(NOW + 1)).is_ok());

        // Provider B presenting provider A's connection with any of its own
        // identity fields is inactive.
        type Mutation = Box<dyn Fn(&mut RemoteContext)>;
        let mutations: Vec<(&str, Mutation)> = vec![
            (
                "provider kind",
                Box::new(|r| r.provider_kind = "anthropic".into()),
            ),
            (
                "client profile",
                Box::new(|r| r.client_profile_id = "profile-2".into()),
            ),
            (
                "client profile revision",
                Box::new(|r| r.client_profile_revision = 2),
            ),
            (
                "principal",
                Box::new(|r| r.principal = format!("rp-{}", "e".repeat(32))),
            ),
            (
                "device",
                Box::new(|r| r.device_id = format!("dev-{}", "f".repeat(32))),
            ),
            ("device epoch", Box::new(|r| r.device_epoch = 2)),
            (
                "tool surface",
                Box::new(|r| r.tool_surface_profile = "desktop_structured".into()),
            ),
        ];
        for (label, mutate) in &mutations {
            let mut forged = remote();
            mutate(&mut forged);
            let message = inactive_code(check_remote_dispatch(
                std::slice::from_ref(&openai),
                &read,
                &forged,
                &env(NOW + 1),
            ));
            assert!(!message.is_empty(), "{label}");
        }
        // Provider A's identity fields on provider B's connection are inactive.
        let mut borrowed = remote();
        borrowed.remote_connection_id = claude.remote_connection_id.clone();
        inactive_code(check_remote_dispatch(
            &leases,
            &read,
            &borrowed,
            &env(NOW + 1),
        ));

        // A connection pinned by provider A cannot be used by provider B's
        // transport connection.
        let pinned = pin_connection(&leases, &remote().remote_connection_id, "cn-1");
        let mut other_transport = remote();
        other_transport.connection_id = "cn-2".into();
        inactive_code(check_remote_dispatch(
            &pinned,
            &read,
            &other_transport,
            &env(NOW + 2),
        ));

        // Scope ceilings are per lease: provider A's write ceiling never lends
        // provider B a scope its own lease lacks.
        let mut narrow_request = claude_request.clone();
        narrow_request.scope_ceiling = vec!["orcel.read".into()];
        let narrow = build_lease(
            &narrow_request,
            "lease-3".into(),
            &env(NOW),
            &["default".into(), "other".into()],
        )
        .unwrap();
        let write = request("fs.write", "write", "default");
        inactive_code(check_remote_dispatch(
            &[openai.clone(), narrow],
            &write,
            &claude_remote,
            &env(NOW + 3),
        ));

        // Revoking provider A's lease leaves provider B active.
        let mut revoked_a = openai.clone();
        revoked_a.revoked = true;
        let after = vec![revoked_a, claude.clone()];
        inactive_code(check_remote_dispatch(
            &after,
            &read,
            &remote(),
            &env(NOW + 4),
        ));
        assert!(check_remote_dispatch(&after, &read, &claude_remote, &env(NOW + 4)).is_ok());
    }

    #[test]
    fn no_lease_expired_lease_and_revoked_lease_are_inactive() {
        let req = request("fs.read", "read", "default");
        inactive_code(check_remote_dispatch(&[], &req, &remote(), &env(NOW)));
        let leases = vec![lease()];
        inactive_code(check_remote_dispatch(
            &leases,
            &req,
            &remote(),
            &env(NOW + 10 * 60 * 1000),
        ));
        inactive_code(check_remote_dispatch(
            &leases,
            &req,
            &remote(),
            &env(NOW - 1),
        ));
        let (revoked, count) = revoke_leases(&leases, None);
        assert_eq!(count, 1);
        inactive_code(check_remote_dispatch(
            &revoked,
            &req,
            &remote(),
            &env(NOW + 1),
        ));
    }

    #[test]
    fn reconnect_does_not_extend_or_rebind_the_lease() {
        let leases = pin_connection(&[lease()], &remote().remote_connection_id, "cn-1");
        let mut reconnected = remote();
        reconnected.connection_id = "cn-2".into();
        let message = inactive_code(check_remote_dispatch(
            &leases,
            &request("fs.read", "read", "default"),
            &reconnected,
            &env(NOW + 1000),
        ));
        assert!(message.contains("reconnect"));
    }

    #[test]
    fn route_profile_policy_and_trust_drift_are_inactive() {
        let leases = vec![lease()];
        let req = request("fs.read", "read", "default");
        let cases: [fn(&mut RemoteContext); 7] = [
            |r| r.principal = format!("rp-{}", "f".repeat(32)),
            |r| r.device_id = format!("dev-{}", "f".repeat(32)),
            |r| r.device_epoch = 2,
            |r| r.provider_kind = "other".into(),
            |r| r.client_profile_id = "profile-2".into(),
            |r| r.client_profile_revision = 2,
            |r| r.remote_connection_id = format!("rc-{}", "f".repeat(32)),
        ];
        for mutate in cases {
            let mut r = remote();
            mutate(&mut r);
            inactive_code(check_remote_dispatch(&leases, &req, &r, &env(NOW + 1)));
        }
        let mut drift = env(NOW + 1);
        drift.policy_revision = "sg-000099-v1";
        inactive_code(check_remote_dispatch(&leases, &req, &remote(), &drift));
        let mut drift = env(NOW + 1);
        drift.workspace_set_digest = "d2";
        inactive_code(check_remote_dispatch(&leases, &req, &remote(), &drift));
        let revoked_trust = |_: &str| None;
        let mut drift = env(NOW + 1);
        drift.trust_revision = &revoked_trust;
        inactive_code(check_remote_dispatch(&leases, &req, &remote(), &drift));
        let changed_trust = |_: &str| Some(4);
        let mut drift = env(NOW + 1);
        drift.trust_revision = &changed_trust;
        inactive_code(check_remote_dispatch(&leases, &req, &remote(), &drift));
    }

    #[test]
    fn lock_logoff_and_unknown_workstation_state_are_inactive() {
        let leases = vec![lease()];
        let req = request("fs.read", "read", "default");
        for state in [
            WorkstationState::Locked,
            WorkstationState::Unknown,
            WorkstationState::Unlocked(WorkstationBinding {
                session_id: 2,
                logon_id: 1,
            }),
            WorkstationState::Unlocked(WorkstationBinding {
                session_id: 3,
                logon_id: binding().logon_id,
            }),
        ] {
            let mut e = env(NOW + 1);
            e.workstation = state;
            inactive_code(check_remote_dispatch(&leases, &req, &remote(), &e));
        }
    }

    #[test]
    fn workspace_scope_and_profile_ceilings_fail_closed() {
        let leases = vec![lease()];
        inactive_code(check_remote_dispatch(
            &leases,
            &request("fs.read", "read", "other"),
            &remote(),
            &env(NOW + 1),
        ));
        inactive_code(check_remote_dispatch(
            &leases,
            &request("process.spawn", "spawn", "default"),
            &RemoteContext {
                scopes: vec!["orcel.read".into(), "orcel.execute".into()],
                ..remote()
            },
            &env(NOW + 1),
        ));
        inactive_code(check_remote_dispatch(
            &leases,
            &request("fs.write", "write", "default"),
            &RemoteContext {
                scopes: vec!["orcel.read".into()],
                ..remote()
            },
            &env(NOW + 1),
        ));
        inactive_code(check_remote_dispatch(
            &leases,
            &request("browser.navigate", "navigate", "default"),
            &remote(),
            &env(NOW + 1),
        ));
        inactive_code(check_remote_dispatch(
            &leases,
            &request("fs.read", "read", "default"),
            &RemoteContext {
                tool_surface_profile: "developer".into(),
                ..remote()
            },
            &env(NOW + 1),
        ));
        inactive_code(check_remote_dispatch(
            &leases,
            &request("fs.read", "read", "default"),
            &RemoteContext {
                scopes: vec!["orcel.admin".into()],
                ..remote()
            },
            &env(NOW + 1),
        ));
    }

    #[test]
    fn local_authority_management_is_never_remote() {
        let leases = vec![lease()];
        for capability in [
            "remote.lease.create",
            "remote.lease.revoke",
            "workspace.trust.grant",
            "trust.revoke_emergency",
            "approval.history.query",
            "lifecycle.update",
        ] {
            let error = check_remote_dispatch(
                &leases,
                &request(capability, "create", "default"),
                &remote(),
                &env(NOW + 1),
            )
            .unwrap_err();
            assert_eq!(error.code, FailureCode::CapabilityDenied);
        }
    }

    #[test]
    fn read_modes_apply_only_to_reads() {
        let mut per_request = lease();
        per_request.read_mode = ReadMode::PerRequest;
        let grant = check_remote_dispatch(
            &[per_request.clone()],
            &request("fs.read", "read", "default"),
            &remote(),
            &env(NOW + 1),
        )
        .unwrap();
        assert!(grant.read_requires_approval);
        let write = check_remote_dispatch(
            &[per_request],
            &request("fs.write", "write", "default"),
            &remote(),
            &env(NOW + 1),
        )
        .unwrap();
        assert!(!write.read_requires_approval);
        let mut disabled = lease();
        disabled.read_mode = ReadMode::Disabled;
        inactive_code(check_remote_dispatch(
            &[disabled.clone()],
            &request("git.log", "log", "default"),
            &remote(),
            &env(NOW + 1),
        ));
        assert!(check_remote_dispatch(
            &[disabled],
            &request("git.stage", "stage", "default"),
            &remote(),
            &env(NOW + 1),
        )
        .is_ok());
    }

    #[test]
    fn lease_creation_is_bounded_and_requires_trusted_configured_workspaces() {
        let configured = vec!["default".to_string(), "other".to_string()];
        let mut req = lease_request();
        req.duration_ms = LEASE_MAX_DURATION_MS + 1;
        assert!(build_lease(&req, "l".into(), &env(NOW), &configured).is_err());
        req.duration_ms = LEASE_MIN_DURATION_MS - 1;
        assert!(build_lease(&req, "l".into(), &env(NOW), &configured).is_err());
        let mut req = lease_request();
        req.workspace_ids = vec!["missing".into()];
        assert_eq!(
            build_lease(&req, "l".into(), &env(NOW), &configured)
                .unwrap_err()
                .code,
            FailureCode::WorkspaceDenied
        );
        let mut req = lease_request();
        req.workspace_ids = vec!["default".into(), "default".into()];
        assert!(build_lease(&req, "l".into(), &env(NOW), &configured).is_err());
        let mut req = lease_request();
        req.tool_surface_profile = "developer".into();
        assert!(build_lease(&req, "l".into(), &env(NOW), &configured).is_err());
        let mut req = lease_request();
        req.scope_ceiling = vec!["orcel.root".into()];
        assert!(build_lease(&req, "l".into(), &env(NOW), &configured).is_err());
        let mut locked = env(NOW);
        locked.workstation = WorkstationState::Locked;
        assert!(build_lease(&lease_request(), "l".into(), &locked, &configured).is_err());
        let built = build_lease(&lease_request(), "l".into(), &env(NOW), &configured).unwrap();
        assert_eq!(built.expires_at_ms - built.created_at_ms, 10 * 60 * 1000);
        assert!(built.connection_id.is_none());
    }

    #[test]
    fn approval_digest_binds_every_lease_field() {
        let base = lease_request_digest(&lease_request(), "p");
        let mut changed = lease_request();
        changed.duration_ms += 1;
        assert_ne!(base, lease_request_digest(&changed, "p"));
        let mut changed = lease_request();
        changed.workspace_ids.push("other".into());
        assert_ne!(base, lease_request_digest(&changed, "p"));
        let mut changed = lease_request();
        changed.read_mode = ReadMode::PerRequest;
        assert_ne!(base, lease_request_digest(&changed, "p"));
        assert_ne!(base, lease_request_digest(&lease_request(), "q"));
    }

    #[test]
    fn store_is_atomic_checksummed_and_fails_closed_when_tampered() {
        let dir =
            std::env::temp_dir().join(format!("orcel-lease-store-{}-{}", std::process::id(), NOW));
        let path = dir.join("remote_leases.json");
        assert!(load_leases(&path).is_empty());
        save_leases(&path, &[lease()]).unwrap();
        assert_eq!(load_leases(&path), vec![lease()]);
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("\"orcel.write\"", "\"orcel.execute\"")).unwrap();
        assert!(
            load_leases(&path).is_empty(),
            "tampered store must yield no lease"
        );
        std::fs::write(&path, b"{not json").unwrap();
        assert!(load_leases(&path).is_empty());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn upsert_replaces_and_prunes_and_is_bounded() {
        let first = lease();
        let leases = upsert_lease(&[], first.clone(), NOW).unwrap();
        let mut replacement = first.clone();
        replacement.lease_id = "lease-2".into();
        let leases = upsert_lease(&leases, replacement, NOW).unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].lease_id, "lease-2");
        let mut many = Vec::new();
        for i in 0..MAX_LEASES {
            let mut l = first.clone();
            l.remote_connection_id = format!("rc-{:032x}", i);
            many.push(l);
        }
        let mut extra = first.clone();
        extra.remote_connection_id = format!("rc-{}", "e".repeat(32));
        assert!(upsert_lease(&many, extra.clone(), NOW).is_err());
        assert!(upsert_lease(&many, extra, NOW + 11 * 60 * 1000).is_ok());
    }
}
