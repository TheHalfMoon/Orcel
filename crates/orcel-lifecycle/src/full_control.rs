//! SG-000095 local Full User authority control and runtime-session binding.
//!
//! This module is reachable only from the human-invoked orcel lifecycle CLI.
//! It never exposes a grant operation through MCP. Full User grant requires a
//! STRONG platform-presence approval and binds the lease to one live orcel
//! owner process, Windows user/logon session, local device key, policy
//! revision, authority epoch, and finite expiry.

#[cfg(windows)]
use crate::layout::write_json_atomic;
use crate::layout::{read_json, Layout};
use crate::LifecycleError;
#[cfg(windows)]
use orcel_approval::{ApprovalBroker, ApprovalPrompt, LocalApprovalBroker};
#[cfg(windows)]
use orcel_policy::full_control::AuthorityMode;
use orcel_policy::full_control::FullControlLease;
use orcel_policy::full_control_store;
#[cfg(any(windows, test))]
use orcel_policy::POLICY_REVISION;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[cfg(any(windows, test))]
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;

pub const RUNTIME_SESSION_SCHEMA: &str = "orcel-runtime-session/1";
pub const RUNTIME_SESSION_ENV: &str = "ORCEL_ORCEL_SESSION_ID";
pub const MAX_FULL_USER_MINUTES: u64 = 12 * 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSessionRecord {
    pub schema: String,
    pub session_id: String,
    pub owner_pid: u32,
    pub owner_creation_time: u64,
    pub owner_image: String,
    pub started_at_ms: u64,
}

pub fn session_record_path(layout: &Layout) -> PathBuf {
    layout.run_dir().join("full-control-session.json")
}

fn policy_error(error: orcel_policy::PolicyError) -> LifecycleError {
    LifecycleError::state(format!(
        "full-control policy denied the request: {}",
        error.message
    ))
}

#[cfg(windows)]
fn approval_error(error: orcel_approval::ApprovalError) -> LifecycleError {
    LifecycleError::state(format!(
        "full-control presence approval failed: {}",
        error.message
    ))
}

#[cfg(any(windows, test))]
fn lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(any(windows, test))]
fn session_id(pid: u32, creation_time: u64, image: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"orcel/sg000095/runtime-session/v1");
    hasher.update(pid.to_le_bytes());
    hasher.update(creation_time.to_le_bytes());
    hasher.update(image.as_bytes());
    hasher.update(crate::nonce().as_bytes());
    let digest = lower_hex(&hasher.finalize());
    format!("orcel-session-{pid}-{creation_time:016x}-{}", &digest[..32])
}

#[cfg(any(windows, test))]
fn record_shape_valid(record: &RuntimeSessionRecord) -> bool {
    if record.schema != RUNTIME_SESSION_SCHEMA
        || record.owner_pid == 0
        || record.owner_creation_time == 0
    {
        return false;
    }
    let expected_prefix = format!(
        "orcel-session-{}-{:016x}-",
        record.owner_pid, record.owner_creation_time
    );
    let Some(nonce) = record.session_id.strip_prefix(&expected_prefix) else {
        return false;
    };
    nonce.len() == 32
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(windows)]
fn invalidate_existing_authority(layout: &Layout) -> Result<Option<u64>, LifecycleError> {
    let key_path = full_control_store::authority_key_path(&layout.root);
    if !key_path.exists() {
        return Ok(None);
    }
    let key = full_control_store::read_key(&key_path).map_err(policy_error)?;
    let epoch = full_control_store::invalidate(
        &full_control_store::authority_store_path(&layout.root),
        &key,
    )
    .map_err(policy_error)?;
    Ok(Some(epoch))
}

#[cfg(windows)]
pub fn begin_runtime_session(layout: &Layout) -> Result<RuntimeSessionRecord, LifecycleError> {
    use crate::runtime;
    let identity = runtime::identify(std::process::id())
        .ok_or_else(|| LifecycleError::state("the orcel runtime owner identity is unavailable"))?;
    if !crate::lifecycle::is_installed_cli(layout, Path::new(&identity.image)) {
        return Err(LifecycleError::state(
            "full-control runtime sessions require the active installed orcel executable",
        ));
    }
    let _ = invalidate_existing_authority(layout)?;
    std::fs::create_dir_all(layout.run_dir())
        .map_err(|error| LifecycleError::io("create orcel runtime directory", error))?;
    let record = RuntimeSessionRecord {
        schema: RUNTIME_SESSION_SCHEMA.into(),
        session_id: session_id(identity.pid, identity.creation_time, &identity.image),
        owner_pid: identity.pid,
        owner_creation_time: identity.creation_time,
        owner_image: identity.image,
        started_at_ms: crate::lifecycle::now_ms(),
    };
    write_json_atomic(&session_record_path(layout), &record)?;
    Ok(record)
}

#[cfg(not(windows))]
pub fn begin_runtime_session(_layout: &Layout) -> Result<RuntimeSessionRecord, LifecycleError> {
    Err(LifecycleError::prerequisite(
        "Full User runtime sessions are available only on Windows",
    ))
}

#[cfg(windows)]
pub fn active_runtime_session(layout: &Layout) -> Result<RuntimeSessionRecord, LifecycleError> {
    use crate::runtime::{self, ProcessIdentity};
    let record: RuntimeSessionRecord = read_json(&session_record_path(layout))?
        .ok_or_else(|| LifecycleError::state("no active Orcel runtime session is recorded"))?;
    if !record_shape_valid(&record) {
        return Err(LifecycleError::state(
            "the Orcel runtime session record is malformed",
        ));
    }
    if !crate::lifecycle::is_installed_cli(layout, Path::new(&record.owner_image)) {
        return Err(LifecycleError::state(
            "the Orcel runtime session owner is outside the active install",
        ));
    }
    let identity = ProcessIdentity {
        pid: record.owner_pid,
        creation_time: record.owner_creation_time,
        image: record.owner_image.clone(),
    };
    if runtime::open_verified(&identity).is_none() {
        return Err(LifecycleError::state(
            "the recorded Orcel runtime session owner is no longer live",
        ));
    }
    orcel_policy::full_control_store::validate_runtime_session(&record.session_id)
        .map_err(policy_error)?;
    Ok(record)
}

#[cfg(not(windows))]
pub fn active_runtime_session(_layout: &Layout) -> Result<RuntimeSessionRecord, LifecycleError> {
    Err(LifecycleError::prerequisite(
        "Full User runtime sessions are available only on Windows",
    ))
}

pub fn end_runtime_session(layout: &Layout, session_id: &str) {
    let path = session_record_path(layout);
    let current: Option<RuntimeSessionRecord> = read_json(&path).ok().flatten();
    if current.as_ref().map(|record| record.session_id.as_str()) == Some(session_id) {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(any(windows, test))]
fn grant_digest(
    workspace_id: &str,
    session: &RuntimeSessionRecord,
    windows_sid: &str,
    logon_session_id: u64,
    device_id: &str,
    duration_ms: u64,
) -> String {
    let mut hasher = Sha256::new();
    for value in [
        "orcel/sg000095/full-user-grant/v1".to_owned(),
        workspace_id.to_owned(),
        POLICY_REVISION.to_owned(),
        session.session_id.clone(),
        windows_sid.to_owned(),
        logon_session_id.to_string(),
        device_id.to_owned(),
        duration_ms.to_string(),
    ] {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    lower_hex(&hasher.finalize())
}

#[cfg(windows)]
pub fn grant_full_user(
    layout: &Layout,
    workspace_id: &str,
    minutes: u64,
) -> Result<FullControlLease, LifecycleError> {
    if minutes == 0 || minutes > MAX_FULL_USER_MINUTES {
        return Err(LifecycleError::usage(format!(
            "--minutes must be from 1 to {MAX_FULL_USER_MINUTES}"
        )));
    }
    let session = active_runtime_session(layout)?;
    let identity = orcel_policy::full_control::current_windows_identity().map_err(policy_error)?;
    let authority_dir = full_control_store::authority_dir(&layout.root);
    std::fs::create_dir_all(&authority_dir)
        .map_err(|error| LifecycleError::io("create full-control authority directory", error))?;
    // Protect the parent before key creation so authority.key and its
    // temporary install file inherit the owner-only ACL from birth.
    crate::host_platform().protect_tree(&authority_dir)?;
    let key_path = full_control_store::authority_key_path(&layout.root);
    let key = full_control_store::ensure_key(&key_path).map_err(policy_error)?;
    let device_id = full_control_store::derive_device_id(&key);
    let duration_ms = minutes
        .checked_mul(60_000)
        .ok_or_else(|| LifecycleError::usage("--minutes overflow"))?;
    let digest = grant_digest(
        workspace_id,
        &session,
        &identity.windows_user_sid,
        identity.logon_session_id,
        &device_id,
        duration_ms,
    );
    let prompt = ApprovalPrompt::new_strong(
        workspace_id.to_owned(),
        POLICY_REVISION,
        "grant Full User desktop control",
        session.session_id.clone(),
        format!(
            "mode=full_user session={} device={} duration_minutes={minutes}",
            session.session_id, device_id
        ),
        digest,
    );
    LocalApprovalBroker::new()
        .map_err(approval_error)?
        .request(&prompt)
        .map_err(approval_error)?;
    full_control_store::grant_local(
        &full_control_store::authority_store_path(&layout.root),
        &key,
        AuthorityMode::FullUser,
        duration_ms,
        identity.windows_user_sid,
        identity.logon_session_id,
        session.session_id,
        orcel_approval::now_ms(),
    )
    .map_err(policy_error)
}

#[cfg(not(windows))]
pub fn grant_full_user(
    _layout: &Layout,
    _workspace_id: &str,
    _minutes: u64,
) -> Result<FullControlLease, LifecycleError> {
    Err(LifecycleError::prerequisite(
        "Full User desktop control is available only on Windows",
    ))
}

pub fn revoke_full_user(layout: &Layout) -> Result<Option<u64>, LifecycleError> {
    let key_path = full_control_store::authority_key_path(&layout.root);
    if !key_path.exists() {
        return Ok(None);
    }
    let key = full_control_store::read_key(&key_path).map_err(policy_error)?;
    full_control_store::revoke(
        &full_control_store::authority_store_path(&layout.root),
        &key,
    )
    .map(Some)
    .map_err(policy_error)
}

pub fn status(layout: &Layout) -> Result<Value, LifecycleError> {
    let key_path = full_control_store::authority_key_path(&layout.root);
    if !key_path.exists() {
        return Ok(json!({
            "mode": "safe",
            "active": false,
            "authority_epoch": full_control_store::INITIAL_AUTHORITY_EPOCH,
            "reason": "no local Full User grant exists"
        }));
    }
    let key = full_control_store::read_key(&key_path).map_err(policy_error)?;
    let stored = full_control_store::load_store(
        &full_control_store::authority_store_path(&layout.root),
        &key,
    )
    .map_err(policy_error)?;
    let Some(lease) = stored.lease else {
        return Ok(json!({
            "mode": "safe",
            "active": false,
            "authority_epoch": stored.authority_epoch,
            "reason": "Full User is revoked or has not been granted"
        }));
    };

    let active = match active_runtime_session(layout) {
        Ok(session) => match orcel_policy::full_control::current_windows_identity() {
            Ok(identity) => full_control_store::check_desktop_input(
                &full_control_store::authority_store_path(&layout.root),
                &key,
                &identity.windows_user_sid,
                identity.logon_session_id,
                &session.session_id,
                orcel_approval::now_ms(),
            )
            .is_ok(),
            Err(_) => false,
        },
        Err(_) => false,
    };
    Ok(json!({
        "mode": "full_user",
        "active": active,
        "lease_id": lease.lease_id,
        "authority_epoch": stored.authority_epoch,
        "issued_at_ms": lease.issued_at_ms,
        "expires_at_ms": lease.expires_at_ms,
        "session_id": lease.orcel_session_id,
        "policy_revision": lease.policy_revision
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_session_shape_binds_pid_and_creation_time() {
        let id = session_id(42, 0x1234, "C:/Orcel/orcel.exe");
        let record = RuntimeSessionRecord {
            schema: RUNTIME_SESSION_SCHEMA.into(),
            session_id: id,
            owner_pid: 42,
            owner_creation_time: 0x1234,
            owner_image: "C:/Orcel/orcel.exe".into(),
            started_at_ms: 1,
        };
        assert!(record_shape_valid(&record));
        let mut drifted = record.clone();
        drifted.owner_creation_time += 1;
        assert!(!record_shape_valid(&drifted));
    }

    #[test]
    fn grant_digest_changes_on_every_security_binding() {
        let session = RuntimeSessionRecord {
            schema: RUNTIME_SESSION_SCHEMA.into(),
            session_id: "orcel-session-42-0000000000001234-0123456789abcdef0123456789abcdef".into(),
            owner_pid: 42,
            owner_creation_time: 0x1234,
            owner_image: "C:/Orcel/orcel.exe".into(),
            started_at_ms: 1,
        };
        let base = grant_digest("default", &session, "S-1-5-21-1", 9, "device-a", 60_000);
        assert_ne!(
            base,
            grant_digest("other", &session, "S-1-5-21-1", 9, "device-a", 60_000)
        );
        assert_ne!(
            base,
            grant_digest("default", &session, "S-1-5-21-2", 9, "device-a", 60_000)
        );
        assert_ne!(
            base,
            grant_digest("default", &session, "S-1-5-21-1", 10, "device-a", 60_000)
        );
        assert_ne!(
            base,
            grant_digest("default", &session, "S-1-5-21-1", 9, "device-b", 60_000)
        );
        assert_ne!(
            base,
            grant_digest("default", &session, "S-1-5-21-1", 9, "device-a", 120_000)
        );
    }
}
