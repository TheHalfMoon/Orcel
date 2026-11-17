//! SG-000093 full-control authority and profile model.
//!
//! This module defines Orcel-owned authority leases only. It does not expose
//! desktop input, shell/process widening, expanded filesystem access, browser
//! or web executors, an elevation broker, persistent-admin service, or remote
//! full-control execution. Donor runtimes remain absent from this grain.

use orcel_contracts::FailureCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

use crate::PolicyError;

pub const FULL_CONTROL_LEASE_SCHEMA: &str = "orcel-full-control-lease/1";
pub const ADMIN_LEASE_SCHEMA: &str = "orcel-admin-lease/1";
pub const MIN_FULL_CONTROL_LEASE_MS: u64 = 60_000;
pub const MAX_FULL_CONTROL_LEASE_MS: u64 = 12 * 60 * 60 * 1_000;
pub const MAX_AUTHORITY_FIELD_BYTES: usize = 256;

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

/// Opaque proof that authority issuance came from Orcel's authenticated
/// local-user control path. The private 256-bit secret is also the keying
/// material for domain-separated lease identifiers. External callers cannot
/// construct or inspect this proof.
pub struct LocalGrantProof {
    secret: [u8; 32],
}

impl LocalGrantProof {
    pub(crate) fn from_secret(secret: [u8; 32]) -> Result<Self, PolicyError> {
        let proof = Self { secret };
        validate_local_grant_proof(&proof)?;
        Ok(proof)
    }

    /// SG-000135 OB-08: the keying material for another lease kind's
    /// domain-separated identifier (`browser_lease`). Crate-private, like
    /// the proof itself.
    pub(crate) fn id_key(&self) -> &[u8; 32] {
        &self.secret
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UntrustedGrantOrigin {
    McpCaller,
    Agent,
    Donor,
    Relay,
    RemotePrincipal,
}

pub fn reject_untrusted_grant(_origin: UntrustedGrantOrigin) -> Result<(), PolicyError> {
    Err(denied(
        "agent, MCP, donor, relay, and remote authority self-grant is denied",
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElevationState {
    Standard,
    ElevatedAdministrator,
    System,
    TrustedInstaller,
}

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

const FULL_USER_CEILING: &[ExecutorClass] = &[
    ExecutorClass::DesktopObservation,
    ExecutorClass::DesktopInput,
    ExecutorClass::ShellProcess,
    ExecutorClass::Filesystem,
    ExecutorClass::Browser,
    ExecutorClass::Web,
    ExecutorClass::VisualAgent,
];

const FULL_ADMIN_CEILING: &[ExecutorClass] = &[
    ExecutorClass::DesktopObservation,
    ExecutorClass::DesktopInput,
    ExecutorClass::ShellProcess,
    ExecutorClass::Filesystem,
    ExecutorClass::Browser,
    ExecutorClass::Web,
    ExecutorClass::VisualAgent,
    ExecutorClass::Admin,
];

pub fn future_profile_ceiling(mode: AuthorityMode) -> &'static [ExecutorClass] {
    match mode {
        AuthorityMode::FullUser => FULL_USER_CEILING,
        AuthorityMode::FullAdmin => FULL_ADMIN_CEILING,
        AuthorityMode::Safe | AuthorityMode::PersistentAdmin | AuthorityMode::RemoteFullControl => {
            &[]
        }
    }
}

pub fn mode_selectable(proof: &LocalGrantProof, mode: AuthorityMode) -> Result<(), PolicyError> {
    validate_local_grant_proof(proof)?;
    match mode {
        AuthorityMode::Safe | AuthorityMode::FullUser | AuthorityMode::FullAdmin => Ok(()),
        AuthorityMode::PersistentAdmin => Err(denied(
            "persistent admin is unavailable until its dedicated P20 successor closes canonically",
        )),
        AuthorityMode::RemoteFullControl => Err(denied(
            "remote full control is unavailable until its dedicated P20 successor closes canonically",
        )),
    }
}

pub fn executor_enabled_now(mode: AuthorityMode, executor: ExecutorClass) -> bool {
    matches!(executor, ExecutorClass::DesktopInput) && mode == AuthorityMode::FullUser
}

pub fn broader_fallback_allowed() -> bool {
    false
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullControlLease {
    pub schema: String,
    pub lease_id: String,
    pub mode: AuthorityMode,
    pub windows_user_sid: String,
    pub logon_session_id: u64,
    pub device_id: String,
    pub orcel_session_id: String,
    pub policy_revision: String,
    pub authority_epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullControlLeaseRequest {
    pub mode: AuthorityMode,
    pub windows_user_sid: String,
    pub logon_session_id: u64,
    pub device_id: String,
    pub orcel_session_id: String,
    pub policy_revision: String,
    pub authority_epoch: u64,
    pub issued_at_ms: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct AuthorityContext<'a> {
    pub windows_user_sid: &'a str,
    pub logon_session_id: u64,
    pub device_id: &'a str,
    pub orcel_session_id: &'a str,
    pub policy_revision: &'a str,
    pub authority_epoch: u64,
    pub now_ms: u64,
    pub elevation_state: ElevationState,
    pub elevation_proof_id: Option<&'a str>,
}

pub fn issue_full_control(
    proof: &LocalGrantProof,
    request: FullControlLeaseRequest,
) -> Result<FullControlLease, PolicyError> {
    mode_selectable(proof, request.mode)?;
    if !matches!(
        request.mode,
        AuthorityMode::FullUser | AuthorityMode::FullAdmin
    ) {
        return Err(invalid(
            "safe mode does not require a lease and successor-only modes cannot be issued here",
        ));
    }
    validate_sid(&request.windows_user_sid)?;
    validate_field("device id", &request.device_id)?;
    validate_field("Orcel session id", &request.orcel_session_id)?;
    validate_field("policy revision", &request.policy_revision)?;
    if request.logon_session_id == 0 {
        return Err(invalid("logon session id must be non-zero"));
    }
    if request.authority_epoch == 0 {
        return Err(invalid("authority epoch must be non-zero"));
    }
    if !(MIN_FULL_CONTROL_LEASE_MS..=MAX_FULL_CONTROL_LEASE_MS).contains(&request.duration_ms) {
        return Err(invalid("full-control lease duration is out of bounds"));
    }
    let expires_at_ms = request
        .issued_at_ms
        .checked_add(request.duration_ms)
        .ok_or_else(|| invalid("full-control lease expiry overflow"))?;
    let lease_id = derive_full_control_lease_id(proof, &request, expires_at_ms);
    Ok(FullControlLease {
        schema: FULL_CONTROL_LEASE_SCHEMA.to_owned(),
        lease_id,
        mode: request.mode,
        windows_user_sid: request.windows_user_sid,
        logon_session_id: request.logon_session_id,
        device_id: request.device_id,
        orcel_session_id: request.orcel_session_id,
        policy_revision: request.policy_revision,
        authority_epoch: request.authority_epoch,
        issued_at_ms: request.issued_at_ms,
        expires_at_ms,
        revoked: false,
    })
}

pub fn check_full_control(
    lease: &FullControlLease,
    context: &AuthorityContext<'_>,
) -> Result<(), PolicyError> {
    if lease.schema != FULL_CONTROL_LEASE_SCHEMA {
        return Err(denied("unknown full-control lease schema"));
    }
    if lease.revoked {
        return Err(denied("full-control lease revoked"));
    }
    if context.now_ms < lease.issued_at_ms || context.now_ms >= lease.expires_at_ms {
        return Err(denied("full-control lease inactive at the current time"));
    }
    if lease.windows_user_sid != context.windows_user_sid {
        return Err(denied("full-control lease Windows user binding mismatch"));
    }
    if lease.logon_session_id != context.logon_session_id {
        return Err(denied("full-control lease logon-session binding mismatch"));
    }
    if lease.device_id != context.device_id {
        return Err(denied("full-control lease device binding mismatch"));
    }
    if lease.orcel_session_id != context.orcel_session_id {
        return Err(denied("full-control lease Orcel-session binding mismatch"));
    }
    if lease.policy_revision != context.policy_revision {
        return Err(denied("full-control lease policy revision mismatch"));
    }
    if lease.authority_epoch != context.authority_epoch {
        return Err(denied("full-control lease authority epoch mismatch"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminLease {
    pub schema: String,
    pub lease_id: String,
    pub full_control_lease_id: String,
    pub windows_user_sid: String,
    pub logon_session_id: u64,
    pub device_id: String,
    pub orcel_session_id: String,
    pub policy_revision: String,
    pub authority_epoch: u64,
    pub elevation_proof_digest: String,
    pub elevation_state: ElevationState,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminLeaseRequest {
    pub elevation_proof_id: String,
    pub elevation_state: ElevationState,
    pub issued_at_ms: u64,
    pub duration_ms: u64,
}

pub fn issue_admin_lease(
    proof: &LocalGrantProof,
    request: AdminLeaseRequest,
    full_control: &FullControlLease,
    context: &AuthorityContext<'_>,
) -> Result<AdminLease, PolicyError> {
    mode_selectable(proof, AuthorityMode::FullAdmin)?;
    check_full_control(full_control, context)?;
    if full_control.mode != AuthorityMode::FullAdmin {
        return Err(denied("admin lease requires Full Admin intent"));
    }
    validate_id(
        &request.elevation_proof_id,
        "win-elev-",
        64,
        "Windows elevation proof id",
    )?;
    if request.elevation_state != ElevationState::ElevatedAdministrator
        || context.elevation_state != ElevationState::ElevatedAdministrator
    {
        return Err(denied(
            "admin lease requires a legitimate elevated administrator Windows authority binding",
        ));
    }
    if context.elevation_proof_id != Some(request.elevation_proof_id.as_str()) {
        return Err(denied("Windows elevation proof binding mismatch"));
    }
    if request.issued_at_ms < full_control.issued_at_ms
        || request.issued_at_ms >= full_control.expires_at_ms
    {
        return Err(invalid(
            "admin lease issue time is outside the full-control lease",
        ));
    }
    if !(MIN_FULL_CONTROL_LEASE_MS..=MAX_FULL_CONTROL_LEASE_MS).contains(&request.duration_ms) {
        return Err(invalid("admin lease duration is out of bounds"));
    }
    let expires_at_ms = request
        .issued_at_ms
        .checked_add(request.duration_ms)
        .ok_or_else(|| invalid("admin lease expiry overflow"))?;
    if expires_at_ms > full_control.expires_at_ms {
        return Err(denied(
            "admin lease cannot outlive the Full Admin full-control lease",
        ));
    }
    let elevation_proof_digest = proof_digest(&request.elevation_proof_id);
    let lease_id = derive_admin_lease_id(
        proof,
        full_control,
        &elevation_proof_digest,
        request.issued_at_ms,
        expires_at_ms,
    );
    Ok(AdminLease {
        schema: ADMIN_LEASE_SCHEMA.to_owned(),
        lease_id,
        full_control_lease_id: full_control.lease_id.clone(),
        windows_user_sid: full_control.windows_user_sid.clone(),
        logon_session_id: full_control.logon_session_id,
        device_id: full_control.device_id.clone(),
        orcel_session_id: full_control.orcel_session_id.clone(),
        policy_revision: full_control.policy_revision.clone(),
        authority_epoch: full_control.authority_epoch,
        elevation_proof_digest,
        elevation_state: request.elevation_state,
        issued_at_ms: request.issued_at_ms,
        expires_at_ms,
        revoked: false,
    })
}

pub fn check_admin_lease(
    admin: &AdminLease,
    full_control: &FullControlLease,
    context: &AuthorityContext<'_>,
) -> Result<(), PolicyError> {
    check_full_control(full_control, context)?;
    if full_control.mode != AuthorityMode::FullAdmin {
        return Err(denied(
            "admin authority requires an active Full Admin lease",
        ));
    }
    if admin.schema != ADMIN_LEASE_SCHEMA || admin.revoked {
        return Err(denied("admin lease inactive"));
    }
    if admin.full_control_lease_id != full_control.lease_id {
        return Err(denied(
            "admin lease is bound to a different full-control lease",
        ));
    }
    if context.now_ms < admin.issued_at_ms || context.now_ms >= admin.expires_at_ms {
        return Err(denied("admin lease inactive at the current time"));
    }
    if admin.windows_user_sid != context.windows_user_sid
        || admin.logon_session_id != context.logon_session_id
        || admin.device_id != context.device_id
        || admin.orcel_session_id != context.orcel_session_id
        || admin.policy_revision != context.policy_revision
        || admin.authority_epoch != context.authority_epoch
    {
        return Err(denied("admin lease authority binding mismatch"));
    }
    if admin.elevation_state != ElevationState::ElevatedAdministrator
        || context.elevation_state != ElevationState::ElevatedAdministrator
    {
        return Err(denied("admin lease Windows elevation binding mismatch"));
    }
    let Some(presented_proof) = context.elevation_proof_id else {
        return Err(denied("admin lease Windows elevation proof is unavailable"));
    };
    if proof_digest(presented_proof) != admin.elevation_proof_digest {
        return Err(denied("admin lease Windows elevation binding mismatch"));
    }
    Ok(())
}

pub fn revoke_full_control(lease: &mut FullControlLease) {
    lease.revoked = true;
}

pub fn revoke_admin(lease: &mut AdminLease) {
    lease.revoked = true;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityEpoch {
    value: u64,
}

impl AuthorityEpoch {
    pub fn new(value: u64) -> Result<Self, PolicyError> {
        if value == 0 {
            return Err(invalid("authority epoch must be non-zero"));
        }
        Ok(Self { value })
    }

    pub fn value(self) -> u64 {
        self.value
    }

    /// Emergency revoke is authority-reducing: advancing the epoch invalidates
    /// every lease issued under the previous value before new dispatch.
    pub fn emergency_revoke(&mut self) -> Result<u64, PolicyError> {
        self.value = self
            .value
            .checked_add(1)
            .ok_or_else(|| invalid("authority epoch overflow"))?;
        Ok(self.value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    NotStarted,
    Dispatched,
    Completed,
    Cancelled,
    OutcomeUnknown,
}

impl ExecutionState {
    pub const ALL: [Self; 5] = [
        Self::NotStarted,
        Self::Dispatched,
        Self::Completed,
        Self::Cancelled,
        Self::OutcomeUnknown,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    Granted,
    Revoked,
    Expired,
    Invalidated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityAuditEvent {
    pub kind: AuditKind,
    pub lease_id: String,
    pub mode: AuthorityMode,
    pub binding_digest: String,
    pub authority_epoch: u64,
    pub at_ms: u64,
}

pub fn full_control_audit_event(
    kind: AuditKind,
    lease: &FullControlLease,
    at_ms: u64,
) -> AuthorityAuditEvent {
    AuthorityAuditEvent {
        kind,
        lease_id: lease.lease_id.clone(),
        mode: lease.mode,
        binding_digest: binding_digest(
            &lease.windows_user_sid,
            lease.logon_session_id,
            &lease.device_id,
            &lease.orcel_session_id,
            &lease.policy_revision,
            lease.authority_epoch,
            None,
        ),
        authority_epoch: lease.authority_epoch,
        at_ms,
    }
}

pub fn admin_audit_event(kind: AuditKind, lease: &AdminLease, at_ms: u64) -> AuthorityAuditEvent {
    AuthorityAuditEvent {
        kind,
        lease_id: lease.lease_id.clone(),
        mode: AuthorityMode::FullAdmin,
        binding_digest: binding_digest(
            &lease.windows_user_sid,
            lease.logon_session_id,
            &lease.device_id,
            &lease.orcel_session_id,
            &lease.policy_revision,
            lease.authority_epoch,
            Some(&lease.elevation_proof_digest),
        ),
        authority_epoch: lease.authority_epoch,
        at_ms,
    }
}

fn proof_digest(proof: &str) -> String {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, proof.as_bytes());
    hex_digest(hasher.finalize().as_slice())
}

fn validate_local_grant_proof(proof: &LocalGrantProof) -> Result<(), PolicyError> {
    if proof.secret.iter().all(|byte| *byte == 0) {
        return Err(invalid("local grant proof secret is invalid"));
    }
    Ok(())
}

fn authority_mode_tag(mode: AuthorityMode) -> &'static str {
    match mode {
        AuthorityMode::Safe => "safe",
        AuthorityMode::FullUser => "full_user",
        AuthorityMode::FullAdmin => "full_admin",
        AuthorityMode::PersistentAdmin => "persistent_admin",
        AuthorityMode::RemoteFullControl => "remote_full_control",
    }
}

fn hash_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn derive_full_control_lease_id(
    proof: &LocalGrantProof,
    request: &FullControlLeaseRequest,
    expires_at_ms: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"orcel/sg000093/full-control-lease/v1");
    hasher.update(proof.secret);
    hash_part(&mut hasher, authority_mode_tag(request.mode).as_bytes());
    hash_part(&mut hasher, request.windows_user_sid.as_bytes());
    hasher.update(request.logon_session_id.to_le_bytes());
    hash_part(&mut hasher, request.device_id.as_bytes());
    hash_part(&mut hasher, request.orcel_session_id.as_bytes());
    hash_part(&mut hasher, request.policy_revision.as_bytes());
    hasher.update(request.authority_epoch.to_le_bytes());
    hasher.update(request.issued_at_ms.to_le_bytes());
    hasher.update(expires_at_ms.to_le_bytes());
    format!("fc-{}", hex_digest(hasher.finalize().as_slice()))
}

fn derive_admin_lease_id(
    proof: &LocalGrantProof,
    full_control: &FullControlLease,
    elevation_proof_digest: &str,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"orcel/sg000093/admin-lease/v1");
    hasher.update(proof.secret);
    hash_part(&mut hasher, full_control.lease_id.as_bytes());
    hash_part(&mut hasher, elevation_proof_digest.as_bytes());
    hasher.update(full_control.authority_epoch.to_le_bytes());
    hasher.update(issued_at_ms.to_le_bytes());
    hasher.update(expires_at_ms.to_le_bytes());
    format!("admin-{}", hex_digest(hasher.finalize().as_slice()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeWindowsIdentity {
    pub windows_user_sid: String,
    pub logon_session_id: u64,
}

#[cfg(windows)]
pub fn current_windows_identity() -> Result<NativeWindowsIdentity, PolicyError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenStatistics, TokenUser, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct Token(HANDLE);

    impl Drop for Token {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    fn last_error(context: &str) -> PolicyError {
        unavailable(format!("{context}: {}", std::io::Error::last_os_error()))
    }

    fn token_info(token: &Token, class: i32) -> Result<Vec<usize>, PolicyError> {
        let mut needed = 0u32;
        unsafe { GetTokenInformation(token.0, class, ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            return Err(last_error("GetTokenInformation size"));
        }
        let word = std::mem::size_of::<usize>();
        let words = (needed as usize).div_ceil(word);
        let mut buffer = vec![0usize; words];
        if unsafe {
            GetTokenInformation(
                token.0,
                class,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(last_error("GetTokenInformation"));
        }
        Ok(buffer)
    }

    fn from_wide_ptr(ptr: *const u16) -> String {
        let mut len = 0usize;
        unsafe {
            while *ptr.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
        }
    }

    let mut token_handle: HANDLE = 0;
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) } == 0 {
        return Err(last_error("OpenProcessToken"));
    }
    let token = Token(token_handle);

    let user_buffer = token_info(&token, TokenUser)?;
    let user = unsafe { &*(user_buffer.as_ptr() as *const TOKEN_USER) };
    let mut sid_text: *mut u16 = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_text) } == 0 {
        return Err(last_error("ConvertSidToStringSidW"));
    }
    let windows_user_sid = from_wide_ptr(sid_text);
    unsafe { LocalFree(sid_text as _) };
    validate_sid(&windows_user_sid)?;

    let statistics_buffer = token_info(&token, TokenStatistics)?;
    let statistics = unsafe { &*(statistics_buffer.as_ptr() as *const TOKEN_STATISTICS) };
    let authentication_id = statistics.AuthenticationId;
    let logon_session_id =
        ((authentication_id.HighPart as u32 as u64) << 32) | authentication_id.LowPart as u64;
    if logon_session_id == 0 {
        return Err(unavailable(
            "Windows token authentication LUID is unavailable",
        ));
    }

    Ok(NativeWindowsIdentity {
        windows_user_sid,
        logon_session_id,
    })
}

#[cfg(not(windows))]
pub fn current_windows_identity() -> Result<NativeWindowsIdentity, PolicyError> {
    Err(unavailable(
        "native Windows identity binding is unavailable on this platform",
    ))
}

fn binding_digest(
    windows_user_sid: &str,
    logon_session_id: u64,
    device_id: &str,
    orcel_session_id: &str,
    policy_revision: &str,
    authority_epoch: u64,
    elevation_proof_id: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    let logon_session_id = logon_session_id.to_string();
    let authority_epoch = authority_epoch.to_string();
    for part in [
        windows_user_sid,
        logon_session_id.as_str(),
        device_id,
        orcel_session_id,
        policy_revision,
        authority_epoch.as_str(),
        elevation_proof_id.unwrap_or(""),
    ] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn validate_sid(value: &str) -> Result<(), PolicyError> {
    validate_field("Windows user SID", value)?;
    if !value.starts_with("S-1-") {
        return Err(invalid("Windows user SID has an invalid shape"));
    }
    Ok(())
}

fn validate_field(name: &str, value: &str) -> Result<(), PolicyError> {
    if value.is_empty() || value.len() > MAX_AUTHORITY_FIELD_BYTES {
        return Err(invalid(format!("{name} malformed")));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(format!("{name} contains a control character")));
    }
    Ok(())
}

fn validate_id(value: &str, prefix: &str, hex_chars: usize, name: &str) -> Result<(), PolicyError> {
    if value.len() != prefix.len() + hex_chars || !value.starts_with(prefix) {
        return Err(invalid(format!("{name} malformed")));
    }
    if !value[prefix.len()..]
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(format!("{name} malformed")));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000;
    const SID: &str = "S-1-5-21-1000-2000-3000-1001";
    const DEVICE: &str = "device-local-1";
    const ORCEL_SESSION: &str = "orcel-session-1";
    const POLICY: &str = "sg-000093-v1";

    fn local_proof() -> LocalGrantProof {
        LocalGrantProof { secret: [0xA5; 32] }
    }

    fn other_local_proof() -> LocalGrantProof {
        LocalGrantProof { secret: [0x5A; 32] }
    }

    fn lease_id(prefix: &str, ch: char) -> String {
        format!("{prefix}{}", ch.to_string().repeat(64))
    }

    fn request(mode: AuthorityMode) -> FullControlLeaseRequest {
        FullControlLeaseRequest {
            mode,
            windows_user_sid: SID.into(),
            logon_session_id: 42,
            device_id: DEVICE.into(),
            orcel_session_id: ORCEL_SESSION.into(),
            policy_revision: POLICY.into(),
            authority_epoch: 7,
            issued_at_ms: NOW,
            duration_ms: 60 * 60 * 1_000,
        }
    }

    fn context<'a>(
        sid: &'a str,
        device: &'a str,
        session: &'a str,
        policy: &'a str,
    ) -> AuthorityContext<'a> {
        AuthorityContext {
            windows_user_sid: sid,
            logon_session_id: 42,
            device_id: device,
            orcel_session_id: session,
            policy_revision: policy,
            authority_epoch: 7,
            now_ms: NOW + 1_000,
            elevation_state: ElevationState::Standard,
            elevation_proof_id: None,
        }
    }

    #[test]
    fn authority_modes_and_profile_ceilings_are_exact() {
        assert_eq!(AuthorityMode::ALL.len(), 5);
        assert_eq!(
            AuthorityMode::ALL
                .iter()
                .filter(|mode| mode.is_default())
                .count(),
            1
        );
        assert!(AuthorityMode::Safe.is_default());
        assert!(mode_selectable(&local_proof(), AuthorityMode::FullUser).is_ok());
        assert!(mode_selectable(&local_proof(), AuthorityMode::FullAdmin).is_ok());
        assert!(mode_selectable(&local_proof(), AuthorityMode::PersistentAdmin).is_err());
        assert!(mode_selectable(&local_proof(), AuthorityMode::RemoteFullControl).is_err());
        assert!(
            future_profile_ceiling(AuthorityMode::FullUser).contains(&ExecutorClass::DesktopInput)
        );
        assert!(!future_profile_ceiling(AuthorityMode::FullUser).contains(&ExecutorClass::Admin));
        assert!(future_profile_ceiling(AuthorityMode::FullAdmin).contains(&ExecutorClass::Admin));
        assert!(future_profile_ceiling(AuthorityMode::PersistentAdmin).is_empty());
        assert!(future_profile_ceiling(AuthorityMode::RemoteFullControl).is_empty());
        for mode in AuthorityMode::ALL {
            for executor in [
                ExecutorClass::DesktopObservation,
                ExecutorClass::DesktopInput,
                ExecutorClass::ShellProcess,
                ExecutorClass::Filesystem,
                ExecutorClass::Browser,
                ExecutorClass::Web,
                ExecutorClass::VisualAgent,
                ExecutorClass::Admin,
                ExecutorClass::Remote,
            ] {
                let enabled =
                    mode == AuthorityMode::FullUser && executor == ExecutorClass::DesktopInput;
                assert_eq!(executor_enabled_now(mode, executor), enabled);
            }
        }
        assert!(!broader_fallback_allowed());
    }

    #[test]
    fn exact_local_full_control_lease_checks_and_drift_fails_closed() {
        let lease = issue_full_control(&local_proof(), request(AuthorityMode::FullUser)).unwrap();
        let base = context(SID, DEVICE, ORCEL_SESSION, POLICY);
        assert!(check_full_control(&lease, &base).is_ok());

        let other_sid = "S-1-5-21-1000-2000-3000-1002";
        let mut cases = vec![
            context(other_sid, DEVICE, ORCEL_SESSION, POLICY),
            context(SID, "device-local-2", ORCEL_SESSION, POLICY),
            context(SID, DEVICE, "orcel-session-2", POLICY),
            context(SID, DEVICE, ORCEL_SESSION, "sg-000093-v2"),
        ];
        cases[0].logon_session_id = 43;
        for case in cases {
            assert!(check_full_control(&lease, &case).is_err());
        }
        let mut epoch = base;
        epoch.authority_epoch = 8;
        assert!(check_full_control(&lease, &epoch).is_err());
        let mut expired = base;
        expired.now_ms = lease.expires_at_ms;
        assert!(check_full_control(&lease, &expired).is_err());
        let mut revoked = lease.clone();
        revoke_full_control(&mut revoked);
        assert!(check_full_control(&revoked, &base).is_err());
    }

    #[test]
    fn agent_donor_relay_mcp_and_remote_origins_cannot_mint_authority() {
        for origin in [
            UntrustedGrantOrigin::McpCaller,
            UntrustedGrantOrigin::Agent,
            UntrustedGrantOrigin::Donor,
            UntrustedGrantOrigin::Relay,
            UntrustedGrantOrigin::RemotePrincipal,
        ] {
            assert!(reject_untrusted_grant(origin).is_err());
        }

        // Successful issuance requires LocalGrantProof. Its only field is
        // private to this module, so an external caller cannot construct it.
        let lease = issue_full_control(&local_proof(), request(AuthorityMode::FullUser)).unwrap();
        assert_eq!(lease.mode, AuthorityMode::FullUser);
    }

    #[test]
    fn admin_lease_requires_exact_legitimate_windows_elevation_binding() {
        let full = issue_full_control(&local_proof(), request(AuthorityMode::FullAdmin)).unwrap();
        let proof = lease_id("win-elev-", 'b');
        let mut elevated = context(SID, DEVICE, ORCEL_SESSION, POLICY);
        elevated.elevation_state = ElevationState::ElevatedAdministrator;
        elevated.elevation_proof_id = Some(&proof);
        let admin = issue_admin_lease(
            &local_proof(),
            AdminLeaseRequest {
                elevation_proof_id: proof.clone(),
                elevation_state: ElevationState::ElevatedAdministrator,
                issued_at_ms: NOW + 1_000,
                duration_ms: 30 * 60 * 1_000,
            },
            &full,
            &elevated,
        )
        .unwrap();
        assert!(check_admin_lease(&admin, &full, &elevated).is_ok());

        for state in [
            ElevationState::Standard,
            ElevationState::System,
            ElevationState::TrustedInstaller,
        ] {
            let mut ctx = elevated;
            ctx.elevation_state = state;
            assert!(check_admin_lease(&admin, &full, &ctx).is_err());
        }

        let mut wrong_proof = elevated;
        wrong_proof.elevation_proof_id =
            Some("win-elev-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
        assert!(check_admin_lease(&admin, &full, &wrong_proof).is_err());

        let full_user =
            issue_full_control(&local_proof(), request(AuthorityMode::FullUser)).unwrap();
        assert!(issue_admin_lease(
            &local_proof(),
            AdminLeaseRequest {
                elevation_proof_id: proof.clone(),
                elevation_state: ElevationState::ElevatedAdministrator,
                issued_at_ms: NOW + 1_000,
                duration_ms: 30 * 60 * 1_000,
            },
            &full_user,
            &elevated,
        )
        .is_err());
    }

    #[test]
    fn revoke_and_epoch_change_invalidate_before_new_dispatch() {
        let mut lease =
            issue_full_control(&local_proof(), request(AuthorityMode::FullUser)).unwrap();
        let mut epoch = AuthorityEpoch::new(lease.authority_epoch).unwrap();
        let mut ctx = context(SID, DEVICE, ORCEL_SESSION, POLICY);
        assert!(check_full_control(&lease, &ctx).is_ok());

        ctx.authority_epoch = epoch.emergency_revoke().unwrap();
        assert!(check_full_control(&lease, &ctx).is_err());

        revoke_full_control(&mut lease);
        assert!(check_full_control(&lease, &ctx).is_err());
    }

    #[test]
    fn audit_projection_hashes_identity_and_elevation_binding_material() {
        let full = issue_full_control(&local_proof(), request(AuthorityMode::FullAdmin)).unwrap();
        let event = full_control_audit_event(AuditKind::Granted, &full, NOW + 1);
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains(SID));
        assert!(!json.contains(DEVICE));
        assert!(!json.contains(ORCEL_SESSION));
        assert_eq!(event.binding_digest.len(), 64);

        let proof = lease_id("win-elev-", 'f');
        let mut elevated = context(SID, DEVICE, ORCEL_SESSION, POLICY);
        elevated.elevation_state = ElevationState::ElevatedAdministrator;
        elevated.elevation_proof_id = Some(&proof);
        let admin = issue_admin_lease(
            &local_proof(),
            AdminLeaseRequest {
                elevation_proof_id: proof.clone(),
                elevation_state: ElevationState::ElevatedAdministrator,
                issued_at_ms: NOW + 1,
                duration_ms: 60_000,
            },
            &full,
            &elevated,
        )
        .unwrap();
        let serialized_lease = serde_json::to_string(&admin).unwrap();
        assert!(!serialized_lease.contains(&proof));
        assert_eq!(admin.elevation_proof_digest.len(), 64);

        let admin_event = admin_audit_event(AuditKind::Granted, &admin, NOW + 2);
        let json = serde_json::to_string(&admin_event).unwrap();
        assert!(!json.contains(&proof));
        assert!(!json.contains(SID));
        assert_eq!(admin_event.binding_digest.len(), 64);
    }

    #[test]
    fn lease_ids_are_secret_and_binding_derived_not_caller_supplied() {
        let base_request = request(AuthorityMode::FullUser);
        let first = issue_full_control(&local_proof(), base_request.clone()).unwrap();
        let second = issue_full_control(&other_local_proof(), base_request.clone()).unwrap();
        assert!(first.lease_id.starts_with("fc-"));
        assert_eq!(first.lease_id.len(), 67);
        assert_ne!(first.lease_id, second.lease_id);

        let mut changed = base_request;
        changed.device_id = "device-local-2".into();
        let changed = issue_full_control(&local_proof(), changed).unwrap();
        assert_ne!(first.lease_id, changed.lease_id);

        let mut zero = LocalGrantProof { secret: [0; 32] };
        assert!(issue_full_control(&zero, request(AuthorityMode::FullUser)).is_err());
        zero.secret[0] = 1;
        assert!(issue_full_control(&zero, request(AuthorityMode::FullUser)).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_sid_and_logon_luid_bind_full_control() {
        let native = current_windows_identity().expect("native Windows identity");
        assert!(native.windows_user_sid.starts_with("S-1-"));
        assert_ne!(native.logon_session_id, 0);

        let lease = issue_full_control(
            &local_proof(),
            FullControlLeaseRequest {
                mode: AuthorityMode::FullUser,
                windows_user_sid: native.windows_user_sid.clone(),
                logon_session_id: native.logon_session_id,
                device_id: DEVICE.into(),
                orcel_session_id: ORCEL_SESSION.into(),
                policy_revision: POLICY.into(),
                authority_epoch: 11,
                issued_at_ms: NOW,
                duration_ms: 60_000,
            },
        )
        .unwrap();

        let exact = AuthorityContext {
            windows_user_sid: &native.windows_user_sid,
            logon_session_id: native.logon_session_id,
            device_id: DEVICE,
            orcel_session_id: ORCEL_SESSION,
            policy_revision: POLICY,
            authority_epoch: 11,
            now_ms: NOW + 1,
            elevation_state: ElevationState::Standard,
            elevation_proof_id: None,
        };
        assert!(check_full_control(&lease, &exact).is_ok());

        let mut wrong_logon = exact;
        wrong_logon.logon_session_id = native.logon_session_id.wrapping_add(1);
        assert!(check_full_control(&lease, &wrong_logon).is_err());

        let mut wrong_sid = exact;
        wrong_sid.windows_user_sid = "S-1-0-0";
        assert!(check_full_control(&lease, &wrong_sid).is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn native_windows_identity_fails_closed_off_windows() {
        let error = current_windows_identity().unwrap_err();
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
    }

    #[test]
    fn execution_state_vocabulary_stays_exact_and_no_retry_semantics_are_added() {
        assert_eq!(
            ExecutionState::ALL,
            [
                ExecutionState::NotStarted,
                ExecutionState::Dispatched,
                ExecutionState::Completed,
                ExecutionState::Cancelled,
                ExecutionState::OutcomeUnknown,
            ]
        );
        assert!(!broader_fallback_allowed());
    }
}
