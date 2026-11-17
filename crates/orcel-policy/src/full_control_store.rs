//! SG-000095 protected Full User authority store.
//!
//! The store is local-only policy state. It never exposes grant material to
//! MCP, donor, relay, browser, or remote callers. The persisted lease is
//! authenticated with a per-install 256-bit key kept under Orcel protected
//! state. Missing, corrupt, or mismatched state fails closed.

use crate::browser_lease::{
    issue_browser_lease, BrowserFamily, BrowserLease, BrowserLeaseRequest, MAX_BROWSER_LEASES,
};
use crate::full_control::{
    check_full_control, issue_full_control, AuthorityContext, AuthorityMode, ElevationState,
    ExecutorClass, FullControlLease, FullControlLeaseRequest, LocalGrantProof,
};
use crate::{PolicyError, POLICY_REVISION};
use orcel_contracts::FailureCode;
use orcel_platform::{files, paths, PlatformError};
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
    /// SG-000135 OB-08: Full Access browser leases. Absent when empty, so a
    /// store without one serializes (and authenticates) exactly as before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    browser_leases: Vec<BrowserLease>,
    /// OB-08 review: advanced by every browser lease revoke, replacement
    /// and invalidation, never lowered. Absent while zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    browser_revocations: u64,
    /// OB-08 review: the latest time a browser lease change was written; a
    /// clock behind it went backwards. Absent while zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    browser_clock_ms: u64,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
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
    /// SG-000135 OB-08: the browser leases, each issued at this epoch.
    pub browser_leases: Vec<BrowserLease>,
    /// OB-08 review: the browser revocation counter (only grows).
    pub browser_revocations: u64,
    /// OB-08 review: the store's last-seen time for browser leases.
    pub browser_clock_ms: u64,
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
    orcel_platform::stores::AUTHORITY.path(root)
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
    // #358 item 4: never replace a key another process created meanwhile;
    // whoever loses the race adopts the winner's key.
    match files::write_private_new(path, &key) {
        Ok(()) => Ok(key),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read_key(path),
        Err(error) => Err(unavailable(format!(
            "install full-control authority key: {error}"
        ))),
    }
}

fn initial_status() -> AuthorityStatus {
    AuthorityStatus {
        authority_epoch: INITIAL_AUTHORITY_EPOCH,
        lease: None,
        browser_leases: Vec::new(),
        browser_revocations: 0,
        browser_clock_ms: 0,
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
    check_browser_leases(
        &stored.body.browser_leases,
        stored.body.authority_epoch,
        stored.body.browser_revocations,
    )
    .map_err(|_| denied("browser lease state does not match the authority store"))?;
    // OB-08 review: a store whose revocation counter is behind the
    // high-water mark written beside it was restored from an older copy.
    if stored.body.browser_revocations < read_revocation_mark(path, key)? {
        return Err(denied(
            "the authority store is older than its revocation mark (restored from a copy); it is refused",
        ));
    }
    Ok(AuthorityStatus {
        authority_epoch: stored.body.authority_epoch,
        lease: stored.body.lease,
        browser_leases: stored.body.browser_leases,
        browser_revocations: stored.body.browser_revocations,
        browser_clock_ms: stored.body.browser_clock_ms,
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
    check_browser_leases(
        &status.browser_leases,
        status.authority_epoch,
        status.browser_revocations,
    )?;
    let body = StoredBody {
        schema: AUTHORITY_STORE_SCHEMA.into(),
        authority_epoch: status.authority_epoch,
        lease: status.lease.clone(),
        browser_leases: status.browser_leases.clone(),
        browser_revocations: status.browser_revocations,
        browser_clock_ms: status.browser_clock_ms,
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
    files::write_private_atomic(path, &bytes)
        .map_err(|error| unavailable(format!("write full-control authority state: {error}")))?;
    // OB-08 review: the mark follows the store (never ahead of it), so a
    // crash between the two writes leaves a store at or past its mark.
    if status.browser_revocations > read_revocation_mark(path, key)? {
        write_revocation_mark(path, key, status.browser_revocations)?;
    }
    Ok(())
}

/// OB-08 review: where the revocation high-water mark lives, beside the
/// store and outside its body.
fn revocation_mark_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".revocations");
    path.with_file_name(name)
}

fn revocation_mark_mac(key: &[u8; AUTHORITY_KEY_BYTES], counter: u64) -> String {
    let mut message = b"orcel/sg000135/browser-revocation-mark/v1\n".to_vec();
    message.extend_from_slice(counter.to_string().as_bytes());
    hex_lower(&hmac_sha256(key, &message))
}

/// The authenticated revocation high-water mark (0 when none was ever
/// written). A mark that does not authenticate fails closed.
fn read_revocation_mark(path: &Path, key: &[u8; AUTHORITY_KEY_BYTES]) -> Result<u64, PolicyError> {
    let text = match std::fs::read_to_string(revocation_mark_path(path)) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(unavailable(format!(
                "read the browser revocation mark: {error}"
            )))
        }
    };
    let (counter, mac) = text
        .trim()
        .split_once(' ')
        .ok_or_else(|| denied("the browser revocation mark is corrupt"))?;
    let counter: u64 = counter
        .parse()
        .map_err(|_| denied("the browser revocation mark is corrupt"))?;
    if !constant_time_eq(revocation_mark_mac(key, counter).as_bytes(), mac.as_bytes()) {
        return Err(denied("the browser revocation mark failed authentication"));
    }
    Ok(counter)
}

fn write_revocation_mark(
    path: &Path,
    key: &[u8; AUTHORITY_KEY_BYTES],
    counter: u64,
) -> Result<(), PolicyError> {
    let text = format!("{counter} {}\n", revocation_mark_mac(key, counter));
    files::write_private_atomic(&revocation_mark_path(path), text.as_bytes())
        .map_err(|error| unavailable(format!("write the browser revocation mark: {error}")))
}

fn advance_epoch(value: u64) -> Result<u64, PolicyError> {
    value
        .checked_add(1)
        .ok_or_else(|| invalid("full-control authority epoch overflow"))
}

/// The store's own lock, held for one read-modify-write and released when dropped,
/// including when the process dies. Every change to the store takes it, so a revoke and a
/// grant can't interleave and lose one of the two. It is held for microseconds, never across
/// a person's approval, so a revoke never waits behind a Windows Hello prompt.
struct StoreLock {
    _file: std::fs::File,
}

/// How long a change waits for another change to the store to finish.
const STORE_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

fn lock_store(path: &Path) -> Result<StoreLock, PolicyError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| invalid("full-control authority state path has no file name"))?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lock");
    let lock_path = path.with_file_name(lock_name);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            unavailable(format!("create full-control authority directory: {error}"))
        })?;
    }
    let deadline = std::time::Instant::now() + STORE_LOCK_WAIT;
    loop {
        if let Some(file) = try_lock_file(&lock_path)? {
            return Ok(StoreLock { _file: file });
        }
        if std::time::Instant::now() >= deadline {
            return Err(unavailable(
                "full-control authority state is busy with another change; try again",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Windows: an open that shares nothing, so a second open fails with a sharing violation
/// until this handle closes.
#[cfg(windows)]
fn try_lock_file(path: &Path) -> Result<Option<std::fs::File>, PolicyError> {
    use std::os::windows::fs::OpenOptionsExt;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Ok(None),
        Err(error) => Err(unavailable(format!(
            "lock full-control authority state: {error}"
        ))),
    }
}

/// Unix: an exclusive advisory `flock` on an owner-only lock file.
#[cfg(unix)]
fn try_lock_file(path: &Path) -> Result<Option<std::fs::File>, PolicyError> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|error| unavailable(format!("lock full-control authority state: {error}")))?;
    match paths::try_lock_exclusive(&file) {
        Ok(true) => Ok(Some(file)),
        Ok(false) => Ok(None),
        Err(error) => Err(unavailable(format!(
            "lock full-control authority state: {error}"
        ))),
    }
}

/// Authority-reducing invalidation used on runtime restart and emergency stop.
pub fn invalidate(path: &Path, key: &[u8; AUTHORITY_KEY_BYTES]) -> Result<u64, PolicyError> {
    let _lock = lock_store(path)?;
    let current = load_store(path, key)?;
    let epoch = advance_epoch(current.authority_epoch)?;
    save_store(
        path,
        key,
        &AuthorityStatus {
            authority_epoch: epoch,
            lease: None,
            // Every browser lease ends with the epoch it was issued at, and
            // the revocation counter moves past them.
            browser_leases: Vec::new(),
            browser_revocations: advance_epoch(current.browser_revocations)?,
            browser_clock_ms: current.browser_clock_ms,
        },
    )?;
    Ok(epoch)
}

/// Grants without checking the epoch a person approved at. Production grants use
/// [`grant_local_at_epoch`], so a revoke made while the approval prompt was open isn't
/// overwritten; this form is for tests and for callers that hold no approval prompt open.
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
    grant(
        path,
        key,
        None,
        mode,
        duration_ms,
        windows_user_sid,
        logon_session_id,
        orcel_session_id,
        now_ms,
    )
}

/// [`grant_local`] for a grant a person approved after reading the store at
/// `approved_at_epoch`: it is refused if anything changed the epoch since, such as a revoke,
/// an emergency stop or a runtime restart while the approval prompt was open. Without this,
/// a grant approved slowly would overwrite a revoke made in the meantime.
#[allow(clippy::too_many_arguments)]
pub fn grant_local_at_epoch(
    path: &Path,
    key: &[u8; AUTHORITY_KEY_BYTES],
    approved_at_epoch: u64,
    mode: AuthorityMode,
    duration_ms: u64,
    windows_user_sid: String,
    logon_session_id: u64,
    orcel_session_id: String,
    now_ms: u64,
) -> Result<FullControlLease, PolicyError> {
    grant(
        path,
        key,
        Some(approved_at_epoch),
        mode,
        duration_ms,
        windows_user_sid,
        logon_session_id,
        orcel_session_id,
        now_ms,
    )
}

#[allow(clippy::too_many_arguments)]
fn grant(
    path: &Path,
    key: &[u8; AUTHORITY_KEY_BYTES],
    approved_at_epoch: Option<u64>,
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
    let _lock = lock_store(path)?;
    let current = load_store(path, key)?;
    if let Some(approved) = approved_at_epoch {
        if current.authority_epoch != approved {
            return Err(denied(
                "desktop control was revoked or reset while this grant was being approved; nothing was granted, request it again",
            ));
        }
    }
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
            // A desktop grant advances the epoch, which ends every browser
            // lease issued at the old one (fail closed, never carried over).
            browser_leases: Vec::new(),
            browser_revocations: if current.browser_leases.is_empty() {
                current.browser_revocations
            } else {
                advance_epoch(current.browser_revocations)?
            },
            browser_clock_ms: current.browser_clock_ms,
        },
    )?;
    Ok(lease)
}

/// SG-000135 OB-08: a store's browser leases are each well formed, issued at
/// the store's `epoch`, one per broker session, and at most
/// `MAX_BROWSER_LEASES`. Anything else is refused (fail closed).
fn check_browser_leases(
    leases: &[BrowserLease],
    epoch: u64,
    revocations: u64,
) -> Result<(), PolicyError> {
    if leases.len() > MAX_BROWSER_LEASES {
        return Err(invalid("the authority store holds too many browser leases"));
    }
    let mut sessions = std::collections::BTreeSet::new();
    for lease in leases {
        lease.check_shape()?;
        if lease.authority_epoch != epoch {
            return Err(invalid(
                "browser lease epoch does not match the authority store",
            ));
        }
        if lease.revocations > revocations {
            return Err(invalid(
                "browser lease names a revocation counter the store has not reached",
            ));
        }
        if !sessions.insert(lease.session_id.as_str()) {
            return Err(invalid("two browser leases name one browser session"));
        }
    }
    Ok(())
}

/// SG-000135 OB-08: what the owner approved for one browser lease. The
/// store adds the device, the policy revision and its authority epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserLeaseGrant {
    pub client_ref: String,
    pub session_id: String,
    pub windows_user_sid: String,
    pub logon_session_id: u64,
    /// The approval ledger's verified revoke epoch the owner approved at.
    pub approval_epoch: u64,
    pub origins: Vec<String>,
    pub families: Vec<BrowserFamily>,
    pub duration_ms: u64,
    /// The session's task label the owner saw.
    pub task: Option<String>,
    /// Who asked, as the owner channel identified it.
    pub requester: String,
}

/// SG-000135 OB-08: issue a browser lease the owner approved with STRONG
/// presence after reading the store at `approved_at_epoch`. Refused when the
/// epoch moved meanwhile (a revoke, emergency stop or desktop grant while
/// the prompt was open), so a slow approval never overwrites a revoke. The
/// lease is issued at the current epoch, which it does not advance (the
/// desktop lease is untouched); an earlier lease of the same session is
/// replaced, expired leases are dropped, and at most `MAX_BROWSER_LEASES`
/// are kept.
pub fn grant_browser_lease_at_epoch(
    path: &Path,
    key: &[u8; AUTHORITY_KEY_BYTES],
    approved_at_epoch: u64,
    grant: BrowserLeaseGrant,
    now_ms: u64,
) -> Result<BrowserLease, PolicyError> {
    let _lock = lock_store(path)?;
    let current = load_store(path, key)?;
    if current.authority_epoch != approved_at_epoch {
        return Err(denied(
            "authority was revoked or reset while this browser lease was being approved; nothing was granted, request it again",
        ));
    }
    if now_ms < current.browser_clock_ms {
        return Err(denied(
            "the clock went backwards behind the authority store; nothing was granted",
        ));
    }
    // Replacing a live lease of the same session revokes it: the counter
    // moves first, and the new lease is issued at the new counter.
    let replaces = current
        .browser_leases
        .iter()
        .any(|kept| kept.expires_at_ms > now_ms && kept.session_id == grant.session_id);
    let revocations = if replaces {
        advance_epoch(current.browser_revocations)?
    } else {
        current.browser_revocations
    };
    let proof = LocalGrantProof::from_secret(*key)?;
    let lease = issue_browser_lease(
        &proof,
        BrowserLeaseRequest {
            client_ref: grant.client_ref,
            session_id: grant.session_id,
            windows_user_sid: grant.windows_user_sid,
            logon_session_id: grant.logon_session_id,
            device_id: derive_device_id(key),
            policy_revision: POLICY_REVISION.into(),
            authority_epoch: current.authority_epoch,
            approval_epoch: grant.approval_epoch,
            origins: grant.origins,
            families: grant.families,
            issued_at_ms: now_ms,
            duration_ms: grant.duration_ms,
            task: grant.task,
            requester: grant.requester,
            revocations,
        },
    )?;
    let mut leases: Vec<BrowserLease> = current
        .browser_leases
        .into_iter()
        .filter(|kept| kept.expires_at_ms > now_ms && kept.session_id != lease.session_id)
        .collect();
    if leases.len() >= MAX_BROWSER_LEASES {
        return Err(denied(format!(
            "the authority store already holds {MAX_BROWSER_LEASES} browser leases; revoke one first"
        )));
    }
    leases.push(lease.clone());
    save_store(
        path,
        key,
        &AuthorityStatus {
            authority_epoch: current.authority_epoch,
            lease: current.lease,
            browser_leases: leases,
            browser_revocations: revocations,
            browser_clock_ms: current.browser_clock_ms.max(now_ms),
        },
    )?;
    Ok(lease)
}

/// SG-000135 OB-08: remove the browser leases `matches` selects. Authority
/// reducing: no presence, the epoch and the desktop lease unchanged; a
/// store with nothing to remove is not rewritten. Returns how many went.
fn remove_browser_leases(
    path: &Path,
    key: &[u8; AUTHORITY_KEY_BYTES],
    matches: &dyn Fn(&BrowserLease) -> bool,
) -> Result<usize, PolicyError> {
    let _lock = lock_store(path)?;
    let current = load_store(path, key)?;
    let before = current.browser_leases.len();
    let kept: Vec<BrowserLease> = current
        .browser_leases
        .into_iter()
        .filter(|lease| !matches(lease))
        .collect();
    let removed = before - kept.len();
    if removed > 0 {
        save_store(
            path,
            key,
            &AuthorityStatus {
                authority_epoch: current.authority_epoch,
                lease: current.lease,
                browser_leases: kept,
                // Every revoke moves the counter: a copy of the store from
                // before it is refused, so the lease cannot come back.
                browser_revocations: advance_epoch(current.browser_revocations)?,
                browser_clock_ms: current.browser_clock_ms,
            },
        )?;
    }
    Ok(removed)
}

/// SG-000135 OB-08: revoke the browser lease `lease_id`, or every browser
/// lease (`None`). Returns how many were revoked.
pub fn revoke_browser_leases(
    path: &Path,
    key: &[u8; AUTHORITY_KEY_BYTES],
    lease_id: Option<&str>,
) -> Result<usize, PolicyError> {
    remove_browser_leases(path, key, &|lease| {
        lease_id.is_none_or(|id| lease.lease_id == id)
    })
}

/// SG-000135 OB-08: a broker session ended; its lease (if any) goes too.
pub fn revoke_session_browser_leases(
    path: &Path,
    key: &[u8; AUTHORITY_KEY_BYTES],
    session_id: &str,
) -> Result<usize, PolicyError> {
    remove_browser_leases(path, key, &|lease| lease.session_id == session_id)
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

    /// #358 item 4: processes racing to create the authority key all end up
    /// with the one key on disk; none overwrites another's.
    #[cfg(windows)]
    #[test]
    fn concurrent_key_creation_yields_one_key() {
        let dir = temp("key-race");
        std::fs::create_dir_all(&dir).unwrap();
        for round in 0..10 {
            let path = dir.join(format!("authority-{round}.key"));
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
            let keys: Vec<_> = (0..8)
                .map(|_| {
                    let path = path.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        ensure_key(&path).unwrap()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .collect();
            let on_disk = read_key(&path).unwrap();
            assert!(keys.iter().all(|key| *key == on_disk), "round {round}");
        }
        let _ = std::fs::remove_dir_all(dir);
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

    /// A grant approved after a revoke must not undo it: the grant read the store before
    /// its approval prompt, a revoke advanced the epoch meanwhile, so the grant is refused
    /// and the store keeps the revoke.
    #[test]
    fn a_grant_approved_after_a_revoke_is_refused() {
        let dir = temp("revoke-race");
        let path = dir.join("state.json");
        let key = key();
        let approved_at = load_store(&path, &key).unwrap().authority_epoch;
        let revoked = revoke(&path, &key).unwrap();
        let refused = grant_local_at_epoch(
            &path,
            &key,
            approved_at,
            AuthorityMode::FullUser,
            60_000,
            "S-1-5-21-1".into(),
            42,
            "session-a".into(),
            1_000,
        );
        assert_eq!(
            refused.map(|_| ()).map_err(|error| error.code),
            Err(FailureCode::CapabilityDenied)
        );
        let status = load_store(&path, &key).unwrap();
        assert_eq!(status.authority_epoch, revoked);
        assert!(status.lease.is_none());
        // Approved at the current epoch, the same grant goes through.
        let lease = grant_local_at_epoch(
            &path,
            &key,
            revoked,
            AuthorityMode::FullUser,
            60_000,
            "S-1-5-21-1".into(),
            42,
            "session-a".into(),
            1_000,
        )
        .unwrap();
        assert_eq!(lease.authority_epoch, revoked + 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Changes to the store hold its lock, so concurrent revokes lose no update: each one
    /// advances the epoch.
    #[test]
    fn concurrent_revokes_each_advance_the_epoch() {
        let dir = temp("revoke-concurrent");
        let path = dir.join("state.json");
        let key = key();
        let start = load_store(&path, &key).unwrap().authority_epoch;
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || revoke(&path, &key).unwrap())
            })
            .collect();
        let mut epochs: Vec<u64> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        epochs.sort_unstable();
        assert_eq!(epochs, (start + 1..=start + 8).collect::<Vec<_>>());
        assert_eq!(load_store(&path, &key).unwrap().authority_epoch, start + 8);
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

    fn browser_grant(session: &str) -> BrowserLeaseGrant {
        BrowserLeaseGrant {
            client_ref: crate::browser_lease::client_ref("client-a"),
            session_id: session.into(),
            windows_user_sid: "S-1-5-21-1".into(),
            logon_session_id: 42,
            approval_epoch: 0,
            origins: vec!["https://fixture.test".into()],
            families: vec![BrowserFamily::Navigate, BrowserFamily::Type],
            duration_ms: 60_000,
            task: Some("task".into()),
            requester: "pid 7 test.exe (test channel)".into(),
        }
    }

    const BROWSER_SESSION: &str = "bs-0123456789abcdef-1-0001020304050607";

    /// SG-000135 OB-08: a browser lease is issued at the store's epoch
    /// without advancing it, beside the desktop lease, and authenticated
    /// with the rest of the store.
    #[test]
    fn ob08_a_browser_lease_is_issued_at_the_epoch_beside_the_desktop_lease() {
        let dir = temp("ob08-grant");
        let path = dir.join("state.json");
        let key = key();
        let desktop = grant_local(
            &path,
            &key,
            AuthorityMode::FullUser,
            60_000,
            "S-1-5-21-1".into(),
            42,
            "session-a".into(),
            1_000,
        )
        .expect("desktop");
        // Without a browser lease the store is written exactly as before.
        let text = std::fs::read_to_string(&path).expect("store");
        assert!(!text.contains("browser_leases"));
        let epoch = load_store(&path, &key).expect("load").authority_epoch;
        let lease =
            grant_browser_lease_at_epoch(&path, &key, epoch, browser_grant(BROWSER_SESSION), 2_000)
                .expect("browser lease");
        assert_eq!(lease.authority_epoch, epoch);
        assert_eq!(lease.device_id, derive_device_id(&key));
        assert_eq!(lease.policy_revision, POLICY_REVISION);
        let status = load_store(&path, &key).expect("load");
        assert_eq!(status.authority_epoch, epoch);
        assert_eq!(status.lease.as_ref(), Some(&desktop));
        assert_eq!(status.browser_leases, vec![lease.clone()]);
        assert!(check_desktop_input(&path, &key, "S-1-5-21-1", 42, "session-a", 3_000).is_ok());
        // A tampered browser lease fails the whole store closed.
        let tampered = std::fs::read_to_string(&path)
            .expect("store")
            .replace("https://fixture.test", "https://fixture.tesu");
        std::fs::write(&path, tampered).expect("write");
        assert!(load_store(&path, &key).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// SG-000135 OB-08: an approval that read an older epoch is refused, a
    /// revoke removes the lease without touching the epoch, and an
    /// emergency invalidate or a desktop grant ends every browser lease.
    #[test]
    fn ob08_revoke_invalidate_and_a_stale_approval_end_browser_leases() {
        let dir = temp("ob08-revoke");
        let path = dir.join("state.json");
        let key = key();
        let approved_at = load_store(&path, &key).expect("load").authority_epoch;
        let moved = invalidate(&path, &key).expect("invalidate");
        assert!(grant_browser_lease_at_epoch(
            &path,
            &key,
            approved_at,
            browser_grant(BROWSER_SESSION),
            2_000
        )
        .is_err());
        assert!(load_store(&path, &key)
            .expect("load")
            .browser_leases
            .is_empty());
        let lease =
            grant_browser_lease_at_epoch(&path, &key, moved, browser_grant(BROWSER_SESSION), 2_000)
                .expect("lease");
        assert_eq!(
            revoke_browser_leases(&path, &key, Some("bl-other")).expect("revoke"),
            0
        );
        assert_eq!(
            revoke_browser_leases(&path, &key, Some(&lease.lease_id)).expect("revoke"),
            1
        );
        let status = load_store(&path, &key).expect("load");
        assert!(status.browser_leases.is_empty());
        assert_eq!(status.authority_epoch, moved);

        grant_browser_lease_at_epoch(&path, &key, moved, browser_grant(BROWSER_SESSION), 2_000)
            .expect("again");
        assert_eq!(
            revoke_session_browser_leases(&path, &key, BROWSER_SESSION).expect("session end"),
            1
        );
        grant_browser_lease_at_epoch(&path, &key, moved, browser_grant(BROWSER_SESSION), 2_000)
            .expect("again");
        let advanced = invalidate(&path, &key).expect("emergency");
        let status = load_store(&path, &key).expect("load");
        assert_eq!(status.authority_epoch, advanced);
        assert!(status.browser_leases.is_empty());

        grant_browser_lease_at_epoch(&path, &key, advanced, browser_grant(BROWSER_SESSION), 2_000)
            .expect("again");
        grant_local(
            &path,
            &key,
            AuthorityMode::FullUser,
            60_000,
            "S-1-5-21-1".into(),
            42,
            "session-a".into(),
            3_000,
        )
        .expect("desktop grant");
        assert!(load_store(&path, &key)
            .expect("load")
            .browser_leases
            .is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// OB-08 review: every revoke advances the counter and its mark, so a
    /// copy of the store from before the revoke is refused (the revoked
    /// lease cannot come back); a clock behind the store refuses a grant.
    #[test]
    fn ob08_a_restored_store_cannot_resurrect_a_revoked_lease() {
        let dir = temp("ob08-rollback");
        let path = dir.join("state.json");
        let key = key();
        let epoch = load_store(&path, &key).expect("load").authority_epoch;
        let lease =
            grant_browser_lease_at_epoch(&path, &key, epoch, browser_grant(BROWSER_SESSION), 2_000)
                .expect("lease");
        assert_eq!(lease.revocations, 0);
        let before_revoke = std::fs::read(&path).expect("copy");
        revoke_browser_leases(&path, &key, Some(&lease.lease_id)).expect("revoke");
        let status = load_store(&path, &key).expect("load");
        assert_eq!(status.browser_revocations, 1);
        std::fs::write(&path, &before_revoke).expect("restore the old copy");
        let refused = load_store(&path, &key).expect_err("rolled back");
        assert!(
            refused.message.contains("revocation mark"),
            "{}",
            refused.message
        );
        // A forged mark does not authenticate.
        std::fs::write(revocation_mark_path(&path), "0 00").expect("forge");
        assert!(load_store(&path, &key).is_err());
        let _ = std::fs::remove_dir_all(&dir);

        let dir = temp("ob08-clock");
        let path = dir.join("state.json");
        grant_browser_lease_at_epoch(&path, &key, epoch, browser_grant(BROWSER_SESSION), 5_000)
            .expect("lease");
        assert_eq!(
            load_store(&path, &key).expect("load").browser_clock_ms,
            5_000
        );
        let other = "bs-0123456789abcdef-2-0001020304050607";
        let refused = grant_browser_lease_at_epoch(&path, &key, epoch, browser_grant(other), 4_000)
            .expect_err("clock went back");
        assert!(refused.message.contains("clock"), "{}", refused.message);
        // Replacing a session's live lease revokes it: the counter moves
        // and the new lease names the new counter.
        let again =
            grant_browser_lease_at_epoch(&path, &key, epoch, browser_grant(BROWSER_SESSION), 6_000)
                .expect("re-issue");
        assert_eq!(again.revocations, 1);
        assert_eq!(
            load_store(&path, &key).expect("load").browser_revocations,
            1
        );
        // An emergency invalidate moves it again and keeps it.
        invalidate(&path, &key).expect("invalidate");
        assert_eq!(
            load_store(&path, &key).expect("load").browser_revocations,
            2
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// SG-000135 OB-08: one lease per session (a re-issue replaces it),
    /// expired leases dropped, and a bounded number kept.
    #[test]
    fn ob08_one_lease_per_session_and_a_bounded_store() {
        let dir = temp("ob08-bounds");
        let path = dir.join("state.json");
        let key = key();
        let epoch = load_store(&path, &key).expect("load").authority_epoch;
        let first =
            grant_browser_lease_at_epoch(&path, &key, epoch, browser_grant(BROWSER_SESSION), 2_000)
                .expect("first");
        let second =
            grant_browser_lease_at_epoch(&path, &key, epoch, browser_grant(BROWSER_SESSION), 3_000)
                .expect("second");
        assert_ne!(first.lease_id, second.lease_id);
        assert_eq!(
            load_store(&path, &key).expect("load").browser_leases,
            vec![second]
        );
        for n in 2..=MAX_BROWSER_LEASES {
            let session = format!("bs-0123456789abcdef-{n}-0001020304050607");
            grant_browser_lease_at_epoch(&path, &key, epoch, browser_grant(&session), 3_000)
                .expect("within the bound");
        }
        let over = format!(
            "bs-0123456789abcdef-{}-0001020304050607",
            MAX_BROWSER_LEASES + 1
        );
        assert!(
            grant_browser_lease_at_epoch(&path, &key, epoch, browser_grant(&over), 3_000).is_err()
        );
        // Once they expired, there is room again.
        grant_browser_lease_at_epoch(&path, &key, epoch, browser_grant(&over), 70_000)
            .expect("expired leases dropped");
        assert_eq!(
            load_store(&path, &key).expect("load").browser_leases.len(),
            1
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
