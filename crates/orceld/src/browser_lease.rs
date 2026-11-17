//! SG-000135 OB-08: Full Access browser leases in orceld.
//!
//! Two halves:
//!
//! - The owner's local management path (`browser.lease.issue`, `.list`,
//!   `.revoke`): local only, never under a tool surface profile, never for
//!   a remote caller (`full_control::reject_untrusted_grant`). Issuance
//!   needs a STRONG (Windows Hello) approval of the exact scope and writes
//!   the lease to the protected full-control store (interim, SG-000135
//!   decision 8). There is no MCP tool for any of them; agents read their
//!   session's lease status through `browser_task_status` only.
//! - [`FullAccess`]: the per-session lease cache the live browser consults
//!   before it would prompt. A valid cached lease covering the session, the
//!   committed origin and the action's family, for an action positively
//!   classified routine, dispatches without the SOFT prompt; anything else
//!   asks as before. Right before dispatch the lease is checked once more
//!   against one fresh read of the store, the verified approval epoch, the
//!   clock and the takeover gate. A revoke, an epoch move (authority or
//!   approval), a policy revision change, expiry, a session end or a human
//!   interruption ends the lease's use at once: that action is refused
//!   `lease_invalid` with nothing sent, and later actions ask as before.
//!
//! The lease grants nothing the action would not get with a SOFT approval:
//! policy, the profile gate, the takeover gate, the secret-field refusal
//! and the host's binding all still apply, and the receipt names the lease.
//!
//! OB-08 review (findings 1 and 2 stay open until the SG-000132 authority
//! service): issuance needs an [`OwnerChannel`] that identifies who asked.
//! No build has a real one yet (the Control Room pipe or the authority
//! service plugs in here), so issuance is OFF in default, development and
//! release builds; only the test-and-development
//! `browser-lease-dev-issuance` feature names orceld's parent process as
//! the requester. The requester, the client reference and the session's
//! task label are shown on the STRONG prompt and bound into its digest and
//! the lease. Every revoke advances a revocation counter that the lease and
//! a mark beside the store bind, the store keeps a last-seen time (a clock
//! behind it refuses), only implemented families can be leased, nothing is
//! covered without the takeover gate, and a value that looks secret or
//! holds a stored secret is never typed under a lease.

use orcel_approval::{ApprovalBroker, ApprovalPrompt, ConsumeExpectation};
use orcel_contracts::browser_impact::Impact;
use orcel_contracts::{FailureCode, RequestEnvelope};
use orcel_policy::browser_lease::{
    canonical_origin, check_browser_lease, check_scope, is_client_ref, is_session_id,
    BrowserFamily, BrowserLease, BrowserLeaseContext, MAX_BROWSER_LEASE_ORIGINS,
};
use orcel_policy::full_control::{reject_untrusted_grant, UntrustedGrantOrigin};
use orcel_policy::full_control_store::{self, BrowserLeaseGrant, AUTHORITY_KEY_BYTES};
use orcel_policy::{PolicyError, POLICY_REVISION};
use orcel_provider_fs::ProviderError;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// The capability prefix of the owner's lease management shapes.
pub(crate) const MANAGEMENT_PREFIX: &str = "browser.lease.";

/// The STRONG prompt's action title for an issuance.
pub(crate) const LEASE_ISSUE_ACTION: &str = "grant Full Access to an Orcel browser session";

/// The longest lease an owner may issue, in minutes (12 hours).
pub(crate) const MAX_LEASE_MINUTES: u64 = 12 * 60;

/// The message prefix of every lease invalidation refusal.
pub(crate) const LEASE_INVALID: &str = "lease_invalid";

/// Whether `capability` is one of the owner's browser lease management
/// shapes.
pub(crate) fn is_management(capability: &str) -> bool {
    capability.starts_with(MANAGEMENT_PREFIX)
}

fn provider(error: PolicyError) -> ProviderError {
    ProviderError::new(error.code, error.message)
}

fn invalid(message: impl Into<String>) -> ProviderError {
    ProviderError::new(FailureCode::InvalidRequest, message)
}

/// Refuse a management request from anything but the owner's local path:
/// a remote caller, or a request that names a tool surface profile (an MCP
/// edge always does). Reuses the authority self-grant refusal.
pub(crate) fn refuse_untrusted(remote: bool, profile: Option<&str>) -> Result<(), ProviderError> {
    let origin = if remote {
        Some(UntrustedGrantOrigin::RemotePrincipal)
    } else if profile.is_some() {
        Some(UntrustedGrantOrigin::McpCaller)
    } else {
        None
    };
    match origin {
        Some(origin) => reject_untrusted_grant(origin).map_err(|error| {
            ProviderError::new(
                error.code,
                format!(
                    "{}; Full Access browser leases are managed only by the owner, locally",
                    error.message
                ),
            )
        }),
        None => Ok(()),
    }
}

/// OB-08 review: who asked for an issuance, as the owner channel saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Requester {
    pub pid: u32,
    /// The requester's executable image, bounded for the prompt.
    pub image: String,
    /// Which owner channel identified it.
    pub channel: &'static str,
}

/// The longest requester image the prompt shows.
const MAX_REQUESTER_IMAGE_CHARS: usize = 160;

impl Requester {
    /// One line for the prompt, the digest and the lease.
    pub(crate) fn describe(&self) -> String {
        let image: String = self
            .image
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_REQUESTER_IMAGE_CHARS)
            .collect();
        format!("pid {} {} (via {})", self.pid, image, self.channel)
    }
}

/// OB-08 review: the seam through which an issuance request reaches orceld
/// from the owner, and which says who sent it. The Control Room pipe or
/// the SG-000132 authority service (a separate principal) implements it;
/// until one exists no build issues a lease outside tests and the
/// development-only feature.
pub(crate) trait OwnerChannel {
    /// The requester of the issuance in progress, or why this channel
    /// cannot vouch for one (issuance is then refused before any prompt).
    fn requester(&self) -> Result<Requester, ProviderError>;
}

/// The default: no owner channel, no issuance.
#[cfg_attr(feature = "browser-lease-dev-issuance", allow(dead_code))]
pub(crate) struct NoOwnerChannel;

impl OwnerChannel for NoOwnerChannel {
    fn requester(&self) -> Result<Requester, ProviderError> {
        Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "issuing a Full Access browser lease needs the owner channel (the Control Room pipe or the SG-000132 authority service), which this build does not have; no lease was issued",
        ))
    }
}

/// TEST AND DEVELOPMENT ONLY (`browser-lease-dev-issuance`): the process
/// that started this orceld is the requester. It identifies the requester
/// for the prompt; it does not authenticate the owner (finding 1 stays
/// open until a real owner channel exists).
#[cfg(all(windows, feature = "browser-lease-dev-issuance"))]
pub(crate) struct DevParentChannel;

#[cfg(all(windows, feature = "browser-lease-dev-issuance"))]
impl OwnerChannel for DevParentChannel {
    fn requester(&self) -> Result<Requester, ProviderError> {
        let unknown = || {
            ProviderError::new(
                FailureCode::ProviderUnavailable,
                "the process that asked for the lease could not be identified; no lease was issued",
            )
        };
        let pid = parent_pid().ok_or_else(unknown)?;
        let (image, _) =
            orcel_platform::process::image_path_and_generation(pid).map_err(|_| unknown())?;
        Ok(Requester {
            pid,
            image,
            channel: "development parent-process channel",
        })
    }
}

/// The parent process id of this orceld (Windows tool help snapshot).
#[cfg(all(windows, feature = "browser-lease-dev-issuance"))]
fn parent_pid() -> Option<u32> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let me = std::process::id();
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return None;
    }
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut found = None;
    if unsafe { Process32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            if entry.th32ProcessID == me {
                found = Some(entry.th32ParentProcessID).filter(|pid| *pid != 0);
                break;
            }
            if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }
    unsafe { CloseHandle(snapshot) };
    found
}

/// This build's owner channel: none, except in the development-only
/// feature build.
pub(crate) fn owner_channel() -> Box<dyn OwnerChannel> {
    #[cfg(all(windows, feature = "browser-lease-dev-issuance"))]
    {
        Box::new(DevParentChannel)
    }
    #[cfg(not(all(windows, feature = "browser-lease-dev-issuance")))]
    {
        Box::new(NoOwnerChannel)
    }
}

/// Where the protected store is and what this process is: injectable so
/// the management path is tested without the user's real state.
pub(crate) struct ManagementEnv {
    pub store_path: PathBuf,
    /// The store key, or why it is unavailable.
    pub key: Result<[u8; AUTHORITY_KEY_BYTES], ProviderError>,
    /// The Windows user SID and logon session of this process.
    pub identity: Result<(String, u64), ProviderError>,
    pub now_ms: fn() -> u64,
    /// OB-08 review: how an issuance reached orceld from the owner.
    pub owner: Box<dyn OwnerChannel>,
}

impl ManagementEnv {
    /// The default protected store. `create_key` makes the store key if it
    /// is missing (issuance only; reads and revokes never create it).
    pub(crate) fn default(create_key: bool) -> Result<Self, ProviderError> {
        let dir = full_control_store::default_authority_dir().map_err(provider)?;
        let key_path = dir.join("authority.key");
        let key = if create_key {
            full_control_store::ensure_key(&key_path).map_err(provider)
        } else {
            full_control_store::read_key(&key_path).map_err(provider)
        };
        Ok(Self {
            store_path: dir.join("full_control.json"),
            key,
            identity: orcel_policy::full_control::current_windows_identity()
                .map(|identity| (identity.windows_user_sid, identity.logon_session_id))
                .map_err(provider),
            now_ms: orcel_approval::now_ms,
            owner: owner_channel(),
        })
    }
}

fn string_field(arguments: &Map<String, Value>, name: &str) -> Result<String, ProviderError> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| invalid(format!("browser lease argument {name} must be a string")))
}

fn string_list(arguments: &Map<String, Value>, name: &str) -> Result<Vec<String>, ProviderError> {
    let items = arguments
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("browser lease argument {name} must be a list")))?;
    if items.len() > MAX_BROWSER_LEASE_ORIGINS {
        return Err(invalid(format!(
            "browser lease argument {name} is too long"
        )));
    }
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid(format!("browser lease argument {name} holds strings")))
        })
        .collect()
}

fn exact_fields(
    request: &RequestEnvelope,
    fields: &[&str],
) -> Result<Map<String, Value>, ProviderError> {
    if request.target.is_some() {
        return Err(invalid("browser lease management takes no target"));
    }
    let empty = Map::new();
    let arguments = match &request.arguments {
        Value::Object(map) => map,
        Value::Null => &empty,
        _ => return Err(invalid("browser lease arguments must be an object")),
    };
    if arguments.len() != fields.len() || !fields.iter().all(|field| arguments.contains_key(*field))
    {
        return Err(invalid(format!(
            "{} accepts exactly these argument fields: {}",
            request.capability,
            fields.join(", ")
        )));
    }
    Ok(arguments.clone())
}

/// What an issuance names, checked.
struct IssueRequest {
    session_id: String,
    client_ref: String,
    origins: Vec<String>,
    families: Vec<BrowserFamily>,
    minutes: u64,
    /// The session's task label, as the owner names it (it must match the
    /// session's own for the lease to cover anything).
    task: Option<String>,
}

fn parse_issue(request: &RequestEnvelope) -> Result<IssueRequest, ProviderError> {
    let arguments = exact_fields(
        request,
        &[
            "session_id",
            "client_ref",
            "origins",
            "families",
            "minutes",
            "task",
        ],
    )?;
    let task = match arguments.get("task") {
        Some(Value::Null) => None,
        Some(Value::String(task)) => Some(task.clone()),
        _ => return Err(invalid("task must be the session's task label or null")),
    };
    orcel_policy::browser_lease::check_task(task.as_deref()).map_err(provider)?;
    let session_id = string_field(&arguments, "session_id")?;
    if !is_session_id(&session_id) {
        return Err(invalid("session_id is not an Orcel browser session id"));
    }
    let client_ref = string_field(&arguments, "client_ref")?;
    if !is_client_ref(&client_ref) {
        return Err(invalid("client_ref is not a client reference (cl-...)"));
    }
    let families = string_list(&arguments, "families")?
        .iter()
        .map(|name| {
            BrowserFamily::parse(name)
                .ok_or_else(|| invalid("families are navigate, click, type, select or tabs"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (origins, families) =
        check_scope(&string_list(&arguments, "origins")?, &families).map_err(provider)?;
    let minutes = arguments
        .get("minutes")
        .and_then(Value::as_u64)
        .filter(|minutes| (1..=MAX_LEASE_MINUTES).contains(minutes))
        .ok_or_else(|| invalid(format!("minutes must be 1 to {MAX_LEASE_MINUTES}")))?;
    Ok(IssueRequest {
        session_id,
        client_ref,
        origins,
        families,
        minutes,
        task,
    })
}

/// The digest the STRONG approval binds: every part of the scope and every
/// binding the lease will carry.
#[allow(clippy::too_many_arguments)]
fn issue_digest(
    workspace_id: &str,
    issue: &IssueRequest,
    sid: &str,
    logon: u64,
    device_id: &str,
    authority_epoch: u64,
    approval_epoch: u64,
    requester: &str,
) -> String {
    let mut hasher = Sha256::new();
    let mut part = |bytes: &[u8]| {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    };
    part(b"orcel/sg000135/browser-lease-issue/v2");
    part(workspace_id.as_bytes());
    part(POLICY_REVISION.as_bytes());
    part(issue.session_id.as_bytes());
    part(issue.client_ref.as_bytes());
    part(issue.origins.join("\n").as_bytes());
    let families: Vec<&str> = issue.families.iter().map(|f| f.as_str()).collect();
    part(families.join("\n").as_bytes());
    part(issue.minutes.to_string().as_bytes());
    part(sid.as_bytes());
    part(logon.to_string().as_bytes());
    part(device_id.as_bytes());
    part(authority_epoch.to_string().as_bytes());
    part(approval_epoch.to_string().as_bytes());
    part(requester.as_bytes());
    match &issue.task {
        Some(task) => part(format!("task:{task}").as_bytes()),
        None => part(b"no task"),
    }
    crate::browser_broker::hex(&hasher.finalize())
}

/// The STRONG prompt's summary: everything the digest binds that a person
/// can judge (the duration, the families, every origin, what still asks,
/// the client, who asked, the bindings, and the session's task label, last
/// and marked as agent-supplied so it cannot pose as the scope).
fn issue_summary(issue: &IssueRequest, requester: &str) -> String {
    format!(
        "Full Access for {} minutes, routine actions only ({}) on {}; submit, send, buy, publish, delete, uploads, secrets and other sites still ask. Client {}. Asked by {}. Bound to this Windows session, this device and the current authority and approval epochs. Session task label (agent-supplied): {}",
        issue.minutes,
        family_names(&issue.families).join(", "),
        issue.origins.join(" "),
        issue.client_ref,
        requester,
        issue.task.as_deref().unwrap_or("none"),
    )
}

fn family_names(families: &[BrowserFamily]) -> Vec<&'static str> {
    families.iter().map(|family| family.as_str()).collect()
}

/// A lease as the owner's list and an agent's status show it: no Windows
/// user, logon session or device.
pub(crate) fn lease_summary(lease: &BrowserLease, now_ms: u64) -> Value {
    json!({
        "lease_id": lease.lease_id,
        "session_id": lease.session_id,
        "client_ref": lease.client_ref,
        "origins": lease.origins,
        "families": family_names(&lease.families),
        "issued_at_ms": lease.issued_at_ms,
        "expires_at_ms": lease.expires_at_ms,
        "active": now_ms >= lease.issued_at_ms && now_ms < lease.expires_at_ms,
        "routine_only": true,
        "task": lease.task,
    })
}

/// The owner's local lease management. The caller has already refused
/// remote and profiled requests (`refuse_untrusted`) and checked the
/// workspace.
pub(crate) fn dispatch_management(
    env: &ManagementEnv,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    match (request.capability.as_str(), request.operation.as_str()) {
        ("browser.lease.issue", "issue") => issue(env, approval, request),
        ("browser.lease.list", "list") => {
            exact_fields(request, &[])?;
            let leases = match &env.key {
                Ok(key) => {
                    full_control_store::load_store(&env.store_path, key)
                        .map_err(provider)?
                        .browser_leases
                }
                // No key: nothing was ever issued.
                Err(_) => Vec::new(),
            };
            let now = (env.now_ms)();
            Ok(json!({
                "leases": leases.iter().map(|lease| lease_summary(lease, now)).collect::<Vec<_>>(),
            }))
        }
        ("browser.lease.revoke", "revoke") => {
            let arguments = exact_fields(request, &["lease_id"])?;
            let lease_id = match arguments.get("lease_id") {
                Some(Value::Null) => None,
                Some(Value::String(id)) => Some(id.clone()),
                _ => return Err(invalid("lease_id must be a string or null")),
            };
            let revoked = match &env.key {
                Ok(key) => full_control_store::revoke_browser_leases(
                    &env.store_path,
                    key,
                    lease_id.as_deref(),
                )
                .map_err(provider)?,
                Err(_) => 0,
            };
            Ok(json!({ "revoked": revoked }))
        }
        _ => Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "unknown browser lease operation",
        )),
    }
}

fn issue(
    env: &ManagementEnv,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    let issue = parse_issue(request)?;
    // Who asked, from the owner channel; without one, nothing is asked.
    let requester = env.owner.requester()?.describe();
    let key = env
        .key
        .as_ref()
        .map_err(|error| ProviderError::new(error.code.clone(), error.message.clone()))?;
    let (sid, logon) = env
        .identity
        .as_ref()
        .map_err(|error| ProviderError::new(error.code.clone(), error.message.clone()))?;
    let device_id = full_control_store::derive_device_id(key);
    // The epochs this grant is approved at: a revoke, emergency stop or
    // desktop grant while the prompt is open refuses it afterwards.
    let authority_epoch = full_control_store::load_store(&env.store_path, key)
        .map_err(provider)?
        .authority_epoch;
    let approval_epoch = approval.verified_revoke_epoch().ok_or_else(|| {
        ProviderError::new(
            FailureCode::ApprovalUnavailable,
            "the approval ledger could not be verified just now; no browser lease was issued",
        )
    })?;
    let digest = issue_digest(
        &request.workspace_id,
        &issue,
        sid,
        *logon,
        &device_id,
        authority_epoch,
        approval_epoch,
        &requester,
    );
    let summary = issue_summary(&issue, &requester);
    // The owner sees the whole scope, or no prompt at all: a summary the
    // prompt would cut is refused (issue fewer origins per lease).
    if orcel_contracts::prompt_display::shown_exactly(
        &summary,
        orcel_contracts::prompt_display::MAX_SUMMARY_CHARS,
    )
    .is_err()
    {
        return Err(invalid(
            "the lease scope is too long for its prompt to show in full; issue fewer origins",
        ));
    }
    let prompt = ApprovalPrompt::new_strong(
        request.workspace_id.clone(),
        POLICY_REVISION,
        LEASE_ISSUE_ACTION,
        issue.session_id.clone(),
        summary,
        digest.clone(),
    );
    let token = approval
        .request_token(&prompt)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    approval
        .consume(
            &token,
            &ConsumeExpectation::strong(digest, request.workspace_id.clone(), POLICY_REVISION),
            (env.now_ms)(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    if approval.verified_revoke_epoch() != Some(approval_epoch) {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "an emergency revoke happened while the browser lease was being approved; nothing was granted",
        ));
    }
    let duration_ms = issue.minutes.saturating_mul(60_000);
    let lease = full_control_store::grant_browser_lease_at_epoch(
        &env.store_path,
        key,
        authority_epoch,
        BrowserLeaseGrant {
            client_ref: issue.client_ref,
            session_id: issue.session_id,
            windows_user_sid: sid.clone(),
            logon_session_id: *logon,
            approval_epoch,
            origins: issue.origins,
            families: issue.families,
            duration_ms,
            task: issue.task,
            requester,
        },
        // The lease starts when presence is confirmed: the wait never
        // shortens or extends the approved duration.
        (env.now_ms)(),
    )
    .map_err(provider)?;
    Ok(lease_summary(&lease, (env.now_ms)()))
}

// ---------------------------------------------------------------------
// The per-session lease cache.
// ---------------------------------------------------------------------

/// What the store says now, for one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreView {
    pub authority_epoch: u64,
    pub device_id: String,
    pub leases: Vec<BrowserLease>,
    /// The store's browser revocation counter (only grows).
    pub revocations: u64,
    /// The store's last-seen time for browser leases.
    pub clock_ms: u64,
}

/// Where a session's lease is read from (the protected store in orceld;
/// a scripted one in tests).
pub(crate) trait LeaseSource {
    /// One read of the store: `None` when it holds no key (nothing was
    /// ever issued). An error fails closed.
    fn read(&self) -> Result<Option<StoreView>, ProviderError>;
    /// The session ended: remove its lease (authority reducing, best
    /// effort).
    fn end_session(&self, session_id: &str);
}

/// The default protected store (its revocation mark is checked by
/// `load_store`: a store restored from an older copy is refused).
pub(crate) struct ProtectedStore;

impl LeaseSource for ProtectedStore {
    fn read(&self) -> Result<Option<StoreView>, ProviderError> {
        let dir = full_control_store::default_authority_dir().map_err(provider)?;
        let key_path = dir.join("authority.key");
        if !key_path.exists() {
            return Ok(None);
        }
        let key = full_control_store::read_key(&key_path).map_err(provider)?;
        let status = full_control_store::load_store(&dir.join("full_control.json"), &key)
            .map_err(provider)?;
        Ok(Some(StoreView {
            authority_epoch: status.authority_epoch,
            device_id: full_control_store::derive_device_id(&key),
            leases: status.browser_leases,
            revocations: status.browser_revocations,
            clock_ms: status.browser_clock_ms,
        }))
    }

    fn end_session(&self, session_id: &str) {
        let Ok(dir) = full_control_store::default_authority_dir() else {
            return;
        };
        let Ok(key) = full_control_store::read_key(&dir.join("authority.key")) else {
            return;
        };
        let _ = full_control_store::revoke_session_browser_leases(
            &dir.join("full_control.json"),
            &key,
            session_id,
        );
    }
}

/// OB-08 review: whether a value matches a secret the secret store holds.
pub(crate) trait SecretMatcher {
    /// `Ok(true)` when `value` holds a stored secret; `Err` when the store
    /// could not be checked (the fill then asks: the person sees it).
    fn matches(&self, value: &str) -> Result<bool, ()>;
}

/// The XP-19 secret store of this account: every fixed secret name, read
/// inside orceld only for this comparison and wiped after it.
pub(crate) struct StoredSecrets;

impl SecretMatcher for StoredSecrets {
    fn matches(&self, value: &str) -> Result<bool, ()> {
        let store = crate::secret_store::SecretStore::open_default().map_err(|_| ())?;
        let value = value.trim().as_bytes();
        for name in crate::secret_store::SecretName::ALL {
            match store.get(name) {
                Ok(secret) => {
                    let secret = secret.as_slice();
                    let contained = secret.len() >= 8
                        && value.windows(secret.len()).any(|window| window == secret);
                    if value == secret || contained {
                        return Ok(true);
                    }
                }
                Err(crate::secret_store::SecretError::NotFound) => {}
                Err(_) => return Err(()),
            }
        }
        Ok(false)
    }
}

/// OB-08 review: what a value an agent would type under a lease is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FillValue {
    /// Neither secret-looking nor a stored secret.
    Ordinary,
    /// Looks secret or is a stored secret: never typed under a lease.
    Secret,
    /// The secret store could not be checked: not covered, so it asks.
    Unverified,
}

/// What the live browser knows about one action at the point it would
/// prompt for it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LeaseQuery<'a> {
    /// The action's family, and a second one it also needs (a new tab to a
    /// URL needs `tabs` and `navigate`).
    pub family: BrowserFamily,
    pub also: Option<BrowserFamily>,
    /// The origin the action's effect lands on.
    pub effect_origin: &'a str,
    /// The page's committed origin now, if it has a document. An effect on
    /// any other origin is cross-origin and never routine.
    pub committed_origin: Option<&'a str>,
    /// The target's routine classification.
    pub impact: Impact,
    /// The page the action is on (its takeover-gate intervention epoch).
    pub page_id: &'a str,
}

/// What is true right now, read by the live browser for one decision.
#[derive(Debug, Clone)]
pub(crate) struct LeaseMoment {
    /// The approval ledger's revoke epoch, verified now (`None`: not
    /// verifiable, which fails closed).
    pub approval_epoch: Option<u64>,
    pub now_ms: u64,
    /// The takeover gate's intervention epoch of every page it tracks;
    /// `None` when the gate is off. Without a gate no person's input can be
    /// seen, so nothing is covered.
    pub interventions: Option<BTreeMap<String, u64>>,
}

/// A lease covering one action: what is checked again right before it is
/// dispatched, and what its receipt names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LeaseUse {
    pub lease_id: String,
    /// The one-shot record id the host frame carries (unique per session).
    pub record_id: String,
    page_id: String,
}

impl LeaseUse {
    /// The page the covered action is on.
    pub(crate) fn page_id(&self) -> &str {
        &self.page_id
    }
}

#[cfg(test)]
impl LeaseUse {
    /// Tests only: a use that names no lease, standing in for an expected
    /// covered decision that did not come (it then fails every check).
    pub(crate) fn missing(decision: &str) -> Self {
        Self {
            lease_id: format!("missing: {decision}"),
            record_id: String::new(),
            page_id: String::new(),
        }
    }
}

/// The decision for one action.
#[derive(Debug)]
pub(crate) enum LeaseDecision {
    /// A valid lease covers it: dispatch without the SOFT prompt, after
    /// [`FullAccess::confirm`].
    Covered(LeaseUse),
    /// No lease covers it: ask as before.
    Ask,
    /// The session's lease just became invalid: refuse, nothing sent.
    Refuse(ProviderError),
}

#[cfg(test)]
impl LeaseDecision {
    /// Tests only: the covered use, if the decision is one.
    pub(crate) fn covered(self) -> Option<LeaseUse> {
        match self {
            Self::Covered(used) => Some(used),
            _ => None,
        }
    }
}

/// The cached lease of one session, as last validated.
struct Cached {
    lease: BrowserLease,
    authority_epoch: u64,
    device_id: String,
    /// The takeover gate's intervention epoch of every page, taken when the
    /// lease was cached and when a page opens afterwards: any move since is
    /// a person's input, and ends the lease's use.
    baseline: BTreeMap<String, u64>,
}

/// SG-000135 OB-08: one broker session's Full Access lease cache.
pub(crate) struct FullAccess {
    session_id: String,
    client_ref: String,
    /// The session's own task label (the lease must name the same).
    task: Option<String>,
    source: Box<dyn LeaseSource>,
    secrets: Box<dyn SecretMatcher>,
    /// This process's Windows user and logon session; `None` (no native
    /// identity) never covers anything.
    identity: Option<(String, u64)>,
    cached: Option<Cached>,
    /// Leases that became invalid for this session: never used again, so
    /// later actions ask.
    dead: BTreeSet<String>,
    /// An invalidation that happened between actions (`invalidate`), for
    /// the next action to report.
    pending: Option<String>,
    uses: u64,
    /// The highest store revocation counter seen: a store behind it was
    /// restored from an older copy.
    revocation_floor: u64,
    /// The latest time seen: a clock behind it went backwards.
    clock_floor: u64,
}

fn lease_invalid(reason: &str) -> ProviderError {
    ProviderError::new(
        FailureCode::CapabilityDenied,
        format!(
            "{LEASE_INVALID}: {reason}; Full Access stopped for this browser session and nothing was sent; later actions ask for approval"
        ),
    )
}

impl FullAccess {
    pub(crate) fn new(
        session_id: &str,
        client_ref: &str,
        task: Option<&str>,
        source: Box<dyn LeaseSource>,
        secrets: Box<dyn SecretMatcher>,
        identity: Option<(String, u64)>,
    ) -> Self {
        Self {
            session_id: session_id.to_owned(),
            client_ref: client_ref.to_owned(),
            task: task.map(str::to_owned),
            source,
            secrets,
            identity,
            cached: None,
            dead: BTreeSet::new(),
            pending: None,
            uses: 0,
            revocation_floor: 0,
            clock_floor: 0,
        }
    }

    /// The protected store and the secret store, with this process's
    /// native identity.
    pub(crate) fn protected(session_id: &str, client_session_id: &str, task: Option<&str>) -> Self {
        let identity = orcel_policy::full_control::current_windows_identity()
            .ok()
            .map(|identity| (identity.windows_user_sid, identity.logon_session_id));
        Self::new(
            session_id,
            &orcel_policy::browser_lease::client_ref(client_session_id),
            task,
            Box::new(ProtectedStore),
            Box::new(StoredSecrets),
            identity,
        )
    }

    fn kill(&mut self, lease_id: &str) {
        self.dead.insert(lease_id.to_owned());
        self.cached = None;
    }

    /// End the cached lease's use from outside an action (a human took
    /// over the page, the session is ending). The next action reports it.
    pub(crate) fn invalidate(&mut self, reason: &str) {
        if let Some(cached) = self.cached.take() {
            self.dead.insert(cached.lease.lease_id);
            self.pending = Some(reason.to_owned());
        }
    }

    /// A page opened (a tab, a popup the session adopted): its intervention
    /// epoch joins the cached lease's baseline now, not at its first use.
    pub(crate) fn page_opened(&mut self, page_id: &str, epoch: Option<u64>) {
        if let (Some(cached), Some(epoch)) = (self.cached.as_mut(), epoch) {
            cached.baseline.entry(page_id.to_owned()).or_insert(epoch);
        }
    }

    /// Check `lease` against the store facts and the moment, and move the
    /// clock and revocation floors.
    fn check(
        &mut self,
        lease: &BrowserLease,
        view: (u64, &str, u64, u64),
        moment: &LeaseMoment,
    ) -> Result<(), String> {
        let (authority_epoch, device_id, revocations, store_clock) = view;
        if moment.now_ms < self.clock_floor {
            return Err("the clock went backwards".into());
        }
        if revocations < self.revocation_floor {
            return Err("the authority store went back behind a revoke it had shown".into());
        }
        let Some((sid, logon)) = &self.identity else {
            return Err("this process's Windows session could not be read".into());
        };
        check_browser_lease(
            lease,
            &BrowserLeaseContext {
                windows_user_sid: sid,
                logon_session_id: *logon,
                device_id,
                policy_revision: POLICY_REVISION,
                authority_epoch,
                approval_epoch: moment.approval_epoch,
                session_id: &self.session_id,
                client_ref: &self.client_ref,
                task: self.task.as_deref(),
                now_ms: moment.now_ms,
                store_revocations: revocations,
                store_clock_ms: store_clock,
            },
        )
        .map_err(|error| error.message)?;
        self.clock_floor = self.clock_floor.max(moment.now_ms);
        self.revocation_floor = self.revocation_floor.max(revocations);
        Ok(())
    }

    /// Whether the takeover gate saw a person on any page since the lease
    /// was cached (or the page opened). Pages opened since join the
    /// baseline here at the latest.
    fn interrupted(cached: &mut Cached, interventions: &BTreeMap<String, u64>) -> bool {
        let mut moved = false;
        for (page, epoch) in interventions {
            match cached.baseline.get(page) {
                Some(mark) if mark != epoch => moved = true,
                Some(_) => {}
                None => {
                    cached.baseline.insert(page.clone(), *epoch);
                }
            }
        }
        moved
    }

    /// Before the prompt: whether this session's lease covers `query` now.
    /// Uses the cached lease when there is one (the store is read again in
    /// [`Self::confirm`]); otherwise reads the store once.
    pub(crate) fn decide(&mut self, query: &LeaseQuery<'_>, moment: &LeaseMoment) -> LeaseDecision {
        if let Some(reason) = self.pending.take() {
            return LeaseDecision::Refuse(lease_invalid(&reason));
        }
        // Without the takeover gate no person's input can be seen: nothing
        // is covered, and a page the gate does not track asks too.
        let Some(interventions) = moment.interventions.as_ref() else {
            return LeaseDecision::Ask;
        };
        if !interventions.contains_key(query.page_id) {
            return LeaseDecision::Ask;
        }
        if self.cached.is_none() {
            let view = match self.source.read() {
                Ok(Some(view)) => view,
                // No store, or an unreadable one: no lease is in force, so
                // the action asks (nothing was cached, nothing is lost).
                Ok(None) | Err(_) => return LeaseDecision::Ask,
            };
            let Some(lease) = view
                .leases
                .iter()
                .find(|lease| {
                    lease.session_id == self.session_id && !self.dead.contains(&lease.lease_id)
                })
                .cloned()
            else {
                return LeaseDecision::Ask;
            };
            let facts = (
                view.authority_epoch,
                view.device_id.as_str(),
                view.revocations,
                view.clock_ms,
            );
            if let Err(reason) = self.check(&lease, facts, moment) {
                // A lease for this session that does not hold now is never
                // used; it is reported once.
                self.kill(&lease.lease_id);
                return LeaseDecision::Refuse(lease_invalid(&reason));
            }
            self.cached = Some(Cached {
                lease,
                authority_epoch: view.authority_epoch,
                device_id: view.device_id,
                // Every tracked page's epoch, now: the lease is cached.
                baseline: interventions.clone(),
            });
        }
        let Some(cached) = self.cached.as_ref() else {
            return LeaseDecision::Ask;
        };
        let lease = cached.lease.clone();
        let facts = (
            cached.authority_epoch,
            cached.device_id.clone(),
            self.revocation_floor,
            0,
        );
        if let Err(reason) = self.check(&lease, (facts.0, &facts.1, facts.2, facts.3), moment) {
            self.kill(&lease.lease_id);
            return LeaseDecision::Refuse(lease_invalid(&reason));
        }
        let interrupted = match self.cached.as_mut() {
            Some(cached) => Self::interrupted(cached, interventions),
            None => true,
        };
        if interrupted {
            self.kill(&lease.lease_id);
            return LeaseDecision::Refuse(lease_invalid(
                "a person interrupted this browser session",
            ));
        }
        if !covers(&lease, query) {
            return LeaseDecision::Ask;
        }
        self.uses += 1;
        LeaseDecision::Covered(LeaseUse {
            record_id: format!(
                "lease-{}-{}",
                self.uses,
                lease.lease_id.get(3..19).unwrap_or("")
            ),
            lease_id: lease.lease_id,
            page_id: query.page_id.to_owned(),
        })
    }

    /// Right before dispatch: one fresh read of the store, the verified
    /// approval epoch, the clock and the takeover gate. The lease must be
    /// the cached one, unchanged and still valid. Anything else ends it and
    /// refuses the action (nothing sent).
    pub(crate) fn confirm(
        &mut self,
        used: &LeaseUse,
        moment: &LeaseMoment,
    ) -> Result<(), ProviderError> {
        let read = self.source.read();
        let refuse = |this: &mut Self, reason: &str| {
            this.kill(&used.lease_id);
            Err(lease_invalid(reason))
        };
        let Some(interventions) = moment.interventions.as_ref() else {
            return refuse(self, "the takeover gate is not available");
        };
        let Some(cached) = self.cached.as_ref() else {
            return refuse(self, "the browser lease is no longer cached");
        };
        if cached.lease.lease_id != used.lease_id {
            return refuse(self, "the browser lease changed");
        }
        let view = match read {
            Ok(Some(view)) => view,
            Ok(None) => return refuse(self, "the authority store holds no key any more"),
            Err(_) => return refuse(self, "the authority store could not be read"),
        };
        let Some(current) = view
            .leases
            .iter()
            .find(|lease| lease.lease_id == used.lease_id)
            .cloned()
        else {
            return refuse(self, "the browser lease was revoked");
        };
        if current != cached.lease
            || view.authority_epoch != cached.authority_epoch
            || view.device_id != cached.device_id
        {
            return refuse(self, "the browser lease or the authority epoch changed");
        }
        let facts = (
            view.authority_epoch,
            view.device_id.as_str(),
            view.revocations,
            view.clock_ms,
        );
        if let Err(reason) = self.check(&current, facts, moment) {
            return refuse(self, &reason);
        }
        let interrupted = match self.cached.as_mut() {
            Some(cached) => Self::interrupted(cached, interventions),
            None => true,
        };
        if interrupted {
            return refuse(self, "a person interrupted this browser session");
        }
        Ok(())
    }

    /// OB-08 review: whether `value` may be typed under the lease: never a
    /// value that looks secret or holds a stored secret; a secret store
    /// that cannot be checked leaves it to the person (it asks).
    pub(crate) fn fill_value(&self, value: &str) -> FillValue {
        if orcel_contracts::browser_impact::value_looks_secret(value) {
            return FillValue::Secret;
        }
        match self.secrets.matches(value) {
            Ok(true) => FillValue::Secret,
            Ok(false) => FillValue::Ordinary,
            Err(()) => FillValue::Unverified,
        }
    }

    /// `browser_task_status`'s read-only view of this session's lease: its
    /// scope and expiry, never anything an agent could use to issue or
    /// widen one.
    pub(crate) fn status(&self, now_ms: u64) -> Value {
        let view = match self.source.read() {
            Ok(Some(view)) => view,
            _ => return json!({ "active": false, "client_ref": self.client_ref }),
        };
        match view.leases.iter().find(|lease| {
            lease.session_id == self.session_id && lease.client_ref == self.client_ref
        }) {
            Some(lease) => {
                let mut summary = lease_summary(lease, now_ms);
                if let Value::Object(map) = &mut summary {
                    let usable = !self.dead.contains(&lease.lease_id)
                        && map.get("active") == Some(&Value::Bool(true));
                    map.insert("active".into(), Value::Bool(usable));
                }
                summary
            }
            None => json!({ "active": false, "client_ref": self.client_ref }),
        }
    }

    /// The session ended: the cache goes, and the store forgets its lease.
    pub(crate) fn session_ended(&mut self) {
        self.cached = None;
        self.source.end_session(&self.session_id);
    }
}

/// Whether `lease` covers `query`: the action's family (and the second one
/// it needs), its effect's origin, no cross-origin effect, and a target
/// positively classified routine.
fn covers(lease: &BrowserLease, query: &LeaseQuery<'_>) -> bool {
    if query.impact != Impact::Routine {
        return false;
    }
    let Some(effect) = canonical_origin(query.effect_origin) else {
        return false;
    };
    if let Some(committed) = query.committed_origin {
        if canonical_origin(committed).as_deref() != Some(effect.as_str()) {
            return false;
        }
    }
    lease.covers(&effect, query.family) && query.also.is_none_or(|also| lease.covers(&effect, also))
}
