//! SG-000095 protected Full User authority store.
//!
//! The store is local-only policy state. It never exposes grant material to
//! MCP, donor, relay, browser, or remote callers. The persisted lease is
//! authenticated with a per-install 256-bit key kept under Orcel protected
//! state. Missing, corrupt, or mismatched state fails closed.

use crate::full_control::{
    check_full_control, issue_full_control, AuthorityContext, AuthorityMode, ElevationState,
    ExecutorClass, FullControlLease, FullControlLeaseRequest, LocalGrantProof,
};
use crate::{PolicyError, POLICY_REVISION};
use orcel_contracts::FailureCode;
use orcel_platform::{paths, PlatformError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub const AUTHORITY_STORE_SCHEMA: &str = "orcel-full-control-store/1";
pub const AUTHORITY_KEY_BYTES: usize = 32;
pub const INITIAL_AUTHORITY_EPOCH: u64 = 1;
const KEY_FILE_NAME: &str = "authority.key";
const STORE_FILE_NAME: &str = "full_control.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredBody {
    schema: String,
    authority_epoch: u64,
    lease: Option<FullControlLease>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEnvelope {
    body: StoredBody,
    mac: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityStatus {
    pub authority_epoch: u64,
    pub lease: Option<FullControlLease>,
}

fn invalid(message: impl Into<String>) -> PolicyError {
    PolicyError {
        code: FailureCode::InvalidRequest,
        message: message.into(),
    }
}

fn denied(message: impl Into<String>) -> PolicyError {
    PolicyError {
        code: FailureCode::CapabilityDenied,
        message: message.into(),
    }
}

fn unavailable(message: impl Into<String>) -> PolicyError {
    PolicyError {
        code: FailureCode::ProviderUnavailable,
        message: message.into(),
    }
}

pub fn authority_dir(root: &Path) -> PathBuf {
    root.join("state").join("authority")
}

pub fn authority_key_path(root: &Path) -> PathBuf {
    authority_dir(root).join(KEY_FILE_NAME)
}

pub fn authority_store_path(root: &Path) -> PathBuf {
    authority_dir(root).join(STORE_FILE_NAME)
}

/// The authority directory under the private per-user Orcel state root
/// (XP-01B). Fails closed when the root cannot be resolved or is not
/// private; it never falls back to the shared temp directory.
pub fn default_authority_dir() -> Result<PathBuf, PolicyError> {
    default_authority_dir_from(&|name| std::env::var_os(name))
}

/// [`default_authority_dir`] with the environment read through `lookup`.
pub fn default_authority_dir_from(
    lookup: &dyn Fn(&str) -> Option<OsString>,
) -> Result<PathBuf, PolicyError> {
    let root = paths::state_root_from(lookup).map_err(state_unavailable)?;
    paths::ensure_private_dir(&root).map_err(state_unavailable)?;
    Ok(authority_dir(&root))
}

pub fn default_key_path() -> Result<PathBuf, PolicyError> {
    Ok(default_authority_dir()?.join(KEY_FILE_NAME))
}

pub fn default_store_path() -> Result<PathBuf, PolicyError> {
    Ok(default_authority_dir()?.join(STORE_FILE_NAME))
}

fn state_unavailable(error: PlatformError) -> PolicyError {
    unavailable(format!("Full User authority state is unavailable: {error}"))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&a, &b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

fn hmac_sha256(key: &[u8; AUTHORITY_KEY_BYTES], body: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for (index, byte) in key.iter().enumerate() {
        ipad[index] ^= *byte;
        opad[index] ^= *byte;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(body);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

fn body_mac(key: &[u8; AUTHORITY_KEY_BYTES], body: &StoredBody) -> Result<String, PolicyError> {
    let bytes = serde_json::to_vec(body)
        .map_err(|error| invalid(format!("serialize full-control state: {error}")))?;
    Ok(hex_lower(&hmac_sha256(key, &bytes)))
}

pub fn derive_device_id(key: &[u8; AUTHORITY_KEY_BYTES]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"orcel/sg000095/local-device/v1");
    hasher.update(key);
    let digest = hex_lower(&hasher.finalize());
    format!("device-local-{}", &digest[..32])
}

fn validate_key(key: &[u8; AUTHORITY_KEY_BYTES]) -> Result<(), PolicyError> {
    if key.iter().all(|byte| *byte == 0) {
        return Err(denied("full-control authority key is invalid"));
    }
    Ok(())
}

pub fn read_key(path: &Path) -> Result<[u8; AUTHORITY_KEY_BYTES], PolicyError> {
    let bytes = std::fs::read(path)
        .map_err(|error| unavailable(format!("read full-control authority key: {error}")))?;
    if bytes.len() != AUTHORITY_KEY_BYTES {
        return Err(denied("full-control authority key has an invalid length"));
    }
    let mut key = [0u8; AUTHORITY_KEY_BYTES];
    key.copy_from_slice(&bytes);
    validate_key(&key)?;
    Ok(key)
}

#[cfg(windows)]
fn random_key() -> Result<[u8; AUTHORITY_KEY_BYTES], PolicyError> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let mut key = [0u8; AUTHORITY_KEY_BYTES];
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            key.as_mut_ptr(),
            key.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(unavailable(
            "Windows CSPRNG could not create the full-control authority key",
        ));
    }
    validate_key(&key)?;
    Ok(key)
}

#[cfg(not(windows))]
fn random_key() -> Result<[u8; AUTHORITY_KEY_BYTES], PolicyError> {
    Err(unavailable(
        "full-control authority key creation is available only on Windows",
    ))
}

pub fn ensure_key(path: &Path) -> Result<[u8; AUTHORITY_KEY_BYTES], PolicyError> {
    if path.exists() {
        return read_key(path);
    }
    let key = random_key()?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("full-control authority key path has no parent"))?;
    std::fs::create_dir_all(parent).map_err(|error| {
        unavailable(format!("create full-control authority directory: {error}"))
    })?;
    let temp = path.with_file_name(format!(".{KEY_FILE_NAME}.tmp-{}", std::process::id()));
    std::fs::write(&temp, key)
        .map_err(|error| unavailable(format!("write full-control authority key: {error}")))?;
    match std::fs::rename(&temp, path) {
        Ok(()) => Ok(key),
        Err(_error) if path.exists() => {
            let _ = std::fs::remove_file(&temp);
            read_key(path)
        }
        Err(error) => {
            let _ = std::fs::remove_file(&temp);
            Err(unavailable(format!(
                "install full-control authority key: {error}"
            )))
        }
    }
}

fn initial_status() -> AuthorityStatus {
    AuthorityStatus {
        authority_epoch: INITIAL_AUTHORITY_EPOCH,
        lease: None,
    }
}

pub fn load_store(
    path: &Path,
    key: &[u8; AUTHORITY_KEY_BYTES],
) -> Result<AuthorityStatus, PolicyError> {
    validate_key(key)?;
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(initial_status()),
        Err(error) => {
            return Err(unavailable(format!(
                "read full-control authority state: {error}"
            )))
        }
    };
    let stored: StoredEnvelope = serde_json::from_slice(&bytes)
        .map_err(|_| denied("full-control authority state is corrupt"))?;
    if stored.body.schema != AUTHORITY_STORE_SCHEMA || stored.body.authority_epoch == 0 {
        return Err(denied(
            "full-control authority state schema or epoch is invalid",
        ));
    }
    let expected = body_mac(key, &stored.body)?;
    if !constant_time_eq(expected.as_bytes(), stored.mac.as_bytes()) {
        return Err(denied("full-control authority state authentication failed"));
    }
    if let Some(lease) = &stored.body.lease {
        if lease.authority_epoch != stored.body.authority_epoch {
            return Err(denied(
                "full-control lease epoch does not match the authority store",
            ));
        }
    }
    Ok(AuthorityStatus {
        authority_epoch: stored.body.authority_epoch,
        lease: stored.body.lease,
    })
}

pub fn save_store(
    path: &Path,
    key: &[u8; AUTHORITY_KEY_BYTES],
    status: &AuthorityStatus,
) -> Result<(), PolicyError> {
    validate_key(key)?;
    if status.authority_epoch == 0 {
        return Err(invalid("authority epoch must be non-zero"));
    }
    if let Some(lease) = &status.lease {
        if lease.authority_epoch != status.authority_epoch {
            return Err(invalid(
                "full-control lease epoch does not match authority state",
            ));
        }
    }
    let body = StoredBody {
        schema: AUTHORITY_STORE_SCHEMA.into(),
        authority_epoch: status.authority_epoch,
        lease: status.lease.clone(),
    };
    let envelope = StoredEnvelope {
        mac: body_mac(key, &body)?,
        body,
    };
    let bytes = serde_json::to_vec_pretty(&envelope)
        .map_err(|error| invalid(format!("serialize full-control authority state: {error}")))?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("full-control authority state path has no parent"))?;
    std::fs::create_dir_all(parent).map_err(|error| {
        unavailable(format!("create full-control authority directory: {error}"))
    })?;
    let temp = path.with_file_name(format!(".{STORE_FILE_NAME}.tmp-{}", std::process::id()));
    let result = std::fs::write(&temp, bytes)
        .and_then(|()| std::fs::rename(&temp, path))
        .map_err(|error| unavailable(format!("write full-control authority state: {error}")));
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn advance_epoch(value: u64) -> Result<u64, PolicyError> {
    value
        .checked_add(1)
        .ok_or_else(|| invalid("full-control authority epoch overflow"))
}

/// Authority-reducing invalidation used on runtime restart and emergency stop.
pub fn invalidate(path: &Path, key: &[u8; AUTHORITY_KEY_BYTES]) -> Result<u64, PolicyError> {
    let current = load_store(path, key)?;
    let epoch = advance_epoch(current.authority_epoch)?;
    save_store(
        path,
        key,
        &AuthorityStatus {
            authority_epoch: epoch,
            lease: None,
        },
    )?;
    Ok(epoch)
}

#[allow(clippy::too_many_arguments)]
pub fn grant_local(
    path: &Path,
    key: &[u8; AUTHORITY_KEY_BYTES],
    mode: AuthorityMode,
    duration_ms: u64,
    windows_user_sid: String,
    logon_session_id: u64,
    orcel_session_id: String,
    now_ms: u64,
) -> Result<FullControlLease, PolicyError> {
    if mode != AuthorityMode::FullUser {
        return Err(denied(
            "SG-000095 grants DesktopInput only under Full User; Full Admin remains successor-only",
        ));
    }
    let current = load_store(path, key)?;
    let authority_epoch = advance_epoch(current.authority_epoch)?;
    let proof = LocalGrantProof::from_secret(*key)?;
    let request = FullControlLeaseRequest {
        mode,
        windows_user_sid,
        logon_session_id,
        device_id: derive_device_id(key),
        orcel_session_id,
        policy_revision: POLICY_REVISION.into(),
        authority_epoch,
        issued_at_ms: now_ms,
        duration_ms,
    };
    let lease = issue_full_control(&proof, request)?;
    save_store(
        path,
        key,
        &AuthorityStatus {
            authority_epoch,
            lease: Some(lease.clone()),
        },
    )?;
    Ok(lease)
}

pub fn revoke(path: &Path, key: &[u8; AUTHORITY_KEY_BYTES]) -> Result<u64, PolicyError> {
    invalidate(path, key)
}

pub fn revoke_default_if_present() -> Result<Option<u64>, PolicyError> {
    let dir = default_authority_dir()?;
    let key_path = dir.join(KEY_FILE_NAME);
    if !key_path.exists() {
        return Ok(None);
    }
    let key = read_key(&key_path)?;
    revoke(&dir.join(STORE_FILE_NAME), &key).map(Some)
}

pub fn check_desktop_input(
    path: &Path,
    key: &[u8; AUTHORITY_KEY_BYTES],
    windows_user_sid: &str,
    logon_session_id: u64,
    orcel_session_id: &str,
    now_ms: u64,
) -> Result<FullControlLease, PolicyError> {
    let status = load_store(path, key)?;
    let lease = status.lease.ok_or_else(|| {
        denied("Safe mode has no DesktopInput authority; grant Full User locally")
    })?;
    if !crate::full_control::executor_enabled_now(lease.mode, ExecutorClass::DesktopInput) {
        return Err(denied(
            "the active authority mode does not permit DesktopInput",
        ));
    }
    let device_id = derive_device_id(key);
    let context = AuthorityContext {
        windows_user_sid,
        logon_session_id,
        device_id: &device_id,
        orcel_session_id,
        policy_revision: POLICY_REVISION,
        authority_epoch: status.authority_epoch,
        now_ms,
        elevation_state: ElevationState::Standard,
        elevation_proof_id: None,
    };
    check_full_control(&lease, &context)?;
    Ok(lease)
}

#[cfg(windows)]
pub fn validate_runtime_session(session_id: &str) -> Result<(), PolicyError> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE,
    };

    let rest = session_id
        .strip_prefix("orcel-session-")
        .ok_or_else(|| denied("Orcel runtime session binding is malformed"))?;
    let mut parts = rest.splitn(3, '-');
    let pid = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| denied("Orcel runtime session owner PID is malformed"))?;
    let creation = parts
        .next()
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| denied("Orcel runtime session creation time is malformed"))?;
    let nonce = parts
        .next()
        .filter(|value| {
            value.len() == 32
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| denied("Orcel runtime session nonce is malformed"))?;

    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if handle == 0 {
        return Err(denied("Orcel runtime session owner is no longer running"));
    }
    struct Handle(isize);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    let handle = Handle(handle);
    if unsafe { WaitForSingleObject(handle.0, 0) } != WAIT_TIMEOUT {
        return Err(denied("Orcel runtime session owner already exited"));
    }
    let mut created = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = created;
    let mut kernel = created;
    let mut user = created;
    if unsafe { GetProcessTimes(handle.0, &mut created, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(unavailable(
            "Orcel runtime session owner identity could not be verified",
        ));
    }
    let observed = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    if observed != creation {
        return Err(denied(
            "Orcel runtime session owner PID was reused; the lease is stale",
        ));
    }
    let _ = nonce;
    Ok(())
}

#[cfg(not(windows))]
pub fn validate_runtime_session(_session_id: &str) -> Result<(), PolicyError> {
    Err(unavailable(
        "Orcel runtime session validation is available only on Windows",
    ))
}

pub fn check_current_desktop_input() -> Result<FullControlLease, PolicyError> {
    let identity = crate::full_control::current_windows_identity()?;
    let session_id = std::env::var("ORCEL_ORCEL_SESSION_ID")
        .map_err(|_| denied("DesktopInput requires an active Orcel runtime session binding"))?;
    validate_runtime_session(&session_id)?;
    let dir = default_authority_dir()?;
    let key = read_key(&dir.join(KEY_FILE_NAME))?;
    check_desktop_input(
        &dir.join(STORE_FILE_NAME),
        &key,
        &identity.windows_user_sid,
        identity.logon_session_id,
        &session_id,
        orcel_approval::now_ms(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("orcel-full-control-{label}-{}", std::process::id()))
    }

    fn key() -> [u8; 32] {
        [0xA5; 32]
    }

    #[test]
    fn missing_state_is_safe_and_grant_is_exactly_bound() {
        let dir = temp("grant");
        let path = dir.join("state.json");
        let key = key();
        let initial = load_store(&path, &key).unwrap();
        assert_eq!(initial.authority_epoch, 1);
        assert!(initial.lease.is_none());
        assert!(check_desktop_input(&path, &key, "S-1-5-21-1", 42, "session-a", 10).is_err());
        let lease = grant_local(
            &path,
            &key,
            AuthorityMode::FullUser,
            60_000,
            "S-1-5-21-1".into(),
            42,
            "session-a".into(),
            1_000,
        )
        .unwrap();
        assert_eq!(lease.authority_epoch, 2);
        assert!(check_desktop_input(&path, &key, "S-1-5-21-1", 42, "session-a", 2_000).is_ok());
        assert!(check_desktop_input(&path, &key, "S-1-5-21-2", 42, "session-a", 2_000).is_err());
        assert!(check_desktop_input(&path, &key, "S-1-5-21-1", 43, "session-a", 2_000).is_err());
        assert!(check_desktop_input(&path, &key, "S-1-5-21-1", 42, "session-b", 2_000).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn revoke_expiry_and_new_epoch_fail_closed() {
        let dir = temp("revoke");
        let path = dir.join("state.json");
        let key = key();
        grant_local(
            &path,
            &key,
            AuthorityMode::FullUser,
            60_000,
            "S-1-5-21-1".into(),
            42,
            "session-a".into(),
            1_000,
        )
        .unwrap();
        assert!(check_desktop_input(&path, &key, "S-1-5-21-1", 42, "session-a", 61_000).is_err());
        let epoch = revoke(&path, &key).unwrap();
        assert_eq!(epoch, 3);
        assert!(check_desktop_input(&path, &key, "S-1-5-21-1", 42, "session-a", 2_000).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tamper_and_wrong_key_are_denied() {
        let dir = temp("tamper");
        let path = dir.join("state.json");
        let key = key();
        grant_local(
            &path,
            &key,
            AuthorityMode::FullUser,
            60_000,
            "S-1-5-21-1".into(),
            42,
            "session-a".into(),
            1_000,
        )
        .unwrap();
        assert!(load_store(&path, &[0x5A; 32]).is_err());
        let mut bytes = std::fs::read(&path).unwrap();
        let index = bytes.iter().position(|byte| *byte == b'2').unwrap_or(0);
        bytes[index] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(load_store(&path, &key).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn only_desktop_input_is_enabled_by_sg95() {
        assert!(crate::full_control::executor_enabled_now(
            AuthorityMode::FullUser,
            ExecutorClass::DesktopInput
        ));
        assert!(!crate::full_control::executor_enabled_now(
            AuthorityMode::Safe,
            ExecutorClass::DesktopInput
        ));
        assert!(!crate::full_control::executor_enabled_now(
            AuthorityMode::FullUser,
            ExecutorClass::ShellProcess
        ));
    }
}
