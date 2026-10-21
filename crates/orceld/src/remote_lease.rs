//! SG-000055 remote-session lease enforcement inside `orceld`.
//!
//! Lease management (`remote.lease.create`, `remote.lease.revoke`,
//! `remote.lease.status`) is local-only. Creation and widening require STRONG
//! platform-mediated presence. Every remote-context request is checked
//! against the lease store immediately before dispatch.

use orcel_approval::{ApprovalBroker, ApprovalPrompt, ConsumeExpectation};
use orcel_contracts::{FailureCode, RemoteContext, RequestEnvelope};
use orcel_policy::remote_session::{
    self, build_lease, check_remote_dispatch, lease_request_digest, load_leases, pin_connection,
    revoke_leases, save_leases, upsert_lease, GateEnvironment, LeaseRequest, ReadMode,
    WorkstationState,
};
use orcel_policy::{PolicyError, POLICY_REVISION};
use orcel_provider_fs::ProviderError;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::trust;

/// Configured workspace identities and their digest, read from the same
/// environment that configured the policy engine.
#[derive(Debug, Clone)]
pub struct WorkspaceSet {
    pub ids: Vec<String>,
    pub roots: Vec<PathBuf>,
    pub digest: String,
}

#[derive(Debug, Deserialize)]
struct WorkspaceConfig {
    id: String,
    root: PathBuf,
}

impl WorkspaceSet {
    pub fn from_environment() -> Self {
        let pairs: Vec<(String, PathBuf)> = if let Ok(raw) = std::env::var("ORCEL_WORKSPACES_JSON")
        {
            serde_json::from_str::<Vec<WorkspaceConfig>>(&raw)
                .map(|configs| configs.into_iter().map(|c| (c.id, c.root)).collect())
                .unwrap_or_default()
        } else if let Some(root) = std::env::var_os("ORCEL_WORKSPACE_ROOT") {
            vec![(
                std::env::var("ORCEL_WORKSPACE_ID").unwrap_or_else(|_| "default".into()),
                PathBuf::from(root),
            )]
        } else {
            Vec::new()
        };
        Self::from_pairs(&pairs)
    }

    pub fn from_pairs(pairs: &[(String, PathBuf)]) -> Self {
        Self {
            ids: pairs.iter().map(|(id, _)| id.clone()).collect(),
            roots: pairs.iter().map(|(_, root)| root.clone()).collect(),
            digest: remote_session::workspace_set_digest(pairs),
        }
    }
}

/// Inputs observed for one decision; injectable for tests.
pub struct LeaseContext<'a> {
    pub lease_path: &'a Path,
    pub workspaces: &'a WorkspaceSet,
    pub workstation: &'a dyn Fn() -> WorkstationState,
    pub now_ms: &'a dyn Fn() -> u64,
}

fn provider_error(error: PolicyError) -> ProviderError {
    ProviderError::new(error.code, error.message)
}

fn trust_revision_fn(trust_store: &trust::TrustStore) -> impl Fn(&str) -> Option<u64> + '_ {
    move |workspace_id: &str| {
        let status = trust_store.get(workspace_id);
        status.trusted.then_some(status.revision)
    }
}

pub fn is_lease_management(capability: &str) -> bool {
    capability.starts_with("remote.lease.")
}

fn string_arg(arguments: &Value, name: &str) -> Result<String, ProviderError> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("remote lease argument {name} must be a string"),
            )
        })
}

fn u64_arg(arguments: &Value, name: &str) -> Result<u64, ProviderError> {
    arguments.get(name).and_then(Value::as_u64).ok_or_else(|| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            format!("remote lease argument {name} must be a non-negative integer"),
        )
    })
}

fn string_list_arg(arguments: &Value, name: &str) -> Result<Vec<String>, ProviderError> {
    let items = arguments
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("remote lease argument {name} must be a list of strings"),
            )
        })?;
    items
        .iter()
        .map(|item| {
            item.as_str().map(str::to_owned).ok_or_else(|| {
                ProviderError::new(
                    FailureCode::InvalidRequest,
                    format!("remote lease argument {name} must be a list of strings"),
                )
            })
        })
        .collect()
}

const LEASE_CREATE_FIELDS: [&str; 12] = [
    "principal",
    "remote_connection_id",
    "device_id",
    "device_epoch",
    "provider_kind",
    "client_profile_id",
    "client_profile_revision",
    "tool_surface_profile",
    "scope_ceiling",
    "workspaces",
    "read_mode",
    "duration_seconds",
];

fn parse_lease_request(arguments: &Value) -> Result<LeaseRequest, ProviderError> {
    let object = arguments.as_object().ok_or_else(|| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "remote lease arguments must be an object",
        )
    })?;
    if object.len() != LEASE_CREATE_FIELDS.len()
        || !LEASE_CREATE_FIELDS
            .iter()
            .all(|field| object.contains_key(*field))
    {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "remote lease creation accepts exactly the documented fields",
        ));
    }
    let read_mode = ReadMode::parse(&string_arg(arguments, "read_mode")?).ok_or_else(|| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "read_mode must be session, per_request, or disabled",
        )
    })?;
    let duration_seconds = u64_arg(arguments, "duration_seconds")?;
    Ok(LeaseRequest {
        principal: string_arg(arguments, "principal")?,
        remote_connection_id: string_arg(arguments, "remote_connection_id")?,
        device_id: string_arg(arguments, "device_id")?,
        device_epoch: u64_arg(arguments, "device_epoch")?,
        provider_kind: string_arg(arguments, "provider_kind")?,
        client_profile_id: string_arg(arguments, "client_profile_id")?,
        client_profile_revision: u64_arg(arguments, "client_profile_revision")?,
        tool_surface_profile: string_arg(arguments, "tool_surface_profile")?,
        scope_ceiling: string_list_arg(arguments, "scope_ceiling")?,
        workspace_ids: string_list_arg(arguments, "workspaces")?,
        read_mode,
        duration_ms: duration_seconds.saturating_mul(1000),
    })
}

fn lease_summary(lease: &remote_session::RemoteSessionLease, now_ms: u64) -> Value {
    json!({
        "lease_id": lease.lease_id,
        "remote_connection_id": lease.remote_connection_id,
        "device_id": lease.device_id,
        "device_epoch": lease.device_epoch,
        "provider_kind": lease.provider_kind,
        "client_profile_id": lease.client_profile_id,
        "tool_surface_profile": lease.tool_surface_profile,
        "scope_ceiling": lease.scope_ceiling,
        "workspaces": lease.workspaces.iter().map(|w| w.workspace_id.clone()).collect::<Vec<_>>(),
        "read_mode": lease.read_mode,
        "connection_pinned": lease.connection_id.is_some(),
        "created_at_ms": lease.created_at_ms,
        "expires_at_ms": lease.expires_at_ms,
        "revoked": lease.revoked,
        "active": !lease.revoked && now_ms < lease.expires_at_ms,
    })
}

/// Local-only lease management. A remote context never reaches this path.
pub fn dispatch_lease_management(
    ctx: &LeaseContext<'_>,
    approval: &impl ApprovalBroker,
    trust_store: &trust::TrustStore,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    match (request.capability.as_str(), request.operation.as_str()) {
        ("remote.lease.create", "create") => create_lease(ctx, approval, trust_store, request),
        ("remote.lease.revoke", "revoke") => {
            let target = match request.arguments.get("remote_connection_id") {
                None | Some(Value::Null) => None,
                Some(Value::String(id)) => Some(id.clone()),
                Some(_) => {
                    return Err(ProviderError::new(
                        FailureCode::InvalidRequest,
                        "remote_connection_id must be a string or null",
                    ))
                }
            };
            let leases = load_leases(ctx.lease_path);
            let (next, revoked) = revoke_leases(&leases, target.as_deref());
            save_leases(ctx.lease_path, &next).map_err(provider_error)?;
            Ok(json!({ "revoked": revoked }))
        }
        ("remote.lease.status", "get") => {
            let leases = load_leases(ctx.lease_path);
            let now_ms = (ctx.now_ms)();
            Ok(json!({
                "leases": leases.iter().map(|l| lease_summary(l, now_ms)).collect::<Vec<_>>(),
            }))
        }
        _ => Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "unknown remote lease operation",
        )),
    }
}

fn create_lease(
    ctx: &LeaseContext<'_>,
    approval: &impl ApprovalBroker,
    trust_store: &trust::TrustStore,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    let lease_request = parse_lease_request(&request.arguments)?;
    if !lease_request
        .workspace_ids
        .iter()
        .any(|id| id == &request.workspace_id)
    {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "the request workspace must be one of the leased workspaces",
        ));
    }
    let trust_revision = trust_revision_fn(trust_store);
    let requested_at_ms = (ctx.now_ms)();
    let env = GateEnvironment {
        now_ms: requested_at_ms,
        policy_revision: POLICY_REVISION,
        workspace_set_digest: &ctx.workspaces.digest,
        workstation: (ctx.workstation)(),
        trust_revision: &trust_revision,
    };
    let lease_id = format!(
        "lease-{}",
        &lease_request_digest(&lease_request, "id")[..32]
    );
    let candidate =
        build_lease(&lease_request, lease_id, &env, &ctx.workspaces.ids).map_err(provider_error)?;
    let digest = lease_request_digest(&lease_request, POLICY_REVISION);
    let prompt = ApprovalPrompt::new_strong(
        request.workspace_id.clone(),
        POLICY_REVISION,
        "allow a remote session",
        lease_request.remote_connection_id.clone(),
        format!(
            "remote_connection={} device={} provider={} profile={} scopes={} workspaces={} read_mode={:?} minutes={}",
            lease_request.remote_connection_id,
            lease_request.device_id,
            lease_request.provider_kind,
            lease_request.tool_surface_profile,
            lease_request.scope_ceiling.join(" "),
            lease_request.workspace_ids.join(","),
            lease_request.read_mode,
            lease_request.duration_ms / 60_000
        ),
        digest.clone(),
    );
    let token = approval
        .request_token(&prompt)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    approval
        .consume(
            &token,
            &ConsumeExpectation::strong(digest, request.workspace_id.clone(), POLICY_REVISION),
            orcel_approval::now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    // The lease starts when presence is confirmed so the approval wait never
    // shortens or extends the approved duration.
    let env = GateEnvironment {
        now_ms: (ctx.now_ms)().max(requested_at_ms),
        policy_revision: POLICY_REVISION,
        workspace_set_digest: &ctx.workspaces.digest,
        workstation: (ctx.workstation)(),
        trust_revision: &trust_revision,
    };
    let lease = build_lease(
        &lease_request,
        candidate.lease_id.clone(),
        &env,
        &ctx.workspaces.ids,
    )
    .map_err(provider_error)?;
    if lease.workspaces != candidate.workspaces || lease.workstation != candidate.workstation {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "workspace trust or workstation state changed during approval; lease creation fails closed",
        ));
    }
    let leases = load_leases(ctx.lease_path);
    let next = upsert_lease(&leases, lease.clone(), env.now_ms).map_err(provider_error)?;
    save_leases(ctx.lease_path, &next).map_err(provider_error)?;
    Ok(lease_summary(&lease, env.now_ms))
}

fn per_request_digest(lease_id: &str, request: &RequestEnvelope) -> String {
    let mut hasher = Sha256::new();
    for field in [
        "ORCEL_REMOTE_READ_APPROVAL_V1",
        lease_id,
        &request.request_id,
        &request.workspace_id,
        &request.capability,
        &request.operation,
        request.target.as_deref().unwrap_or(""),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Check a remote-context request against the lease store immediately before
/// dispatch. Denials are `REMOTE_SESSION_INACTIVE` (or `CAPABILITY_DENIED`
/// for local-only capabilities). A grant is never an action approval.
pub fn gate_remote(
    ctx: &LeaseContext<'_>,
    approval: &impl ApprovalBroker,
    trust_store: &trust::TrustStore,
    request: &RequestEnvelope,
    remote: &RemoteContext,
) -> Result<(), ProviderError> {
    let leases = load_leases(ctx.lease_path);
    let trust_revision = trust_revision_fn(trust_store);
    let env = GateEnvironment {
        now_ms: (ctx.now_ms)(),
        policy_revision: POLICY_REVISION,
        workspace_set_digest: &ctx.workspaces.digest,
        workstation: (ctx.workstation)(),
        trust_revision: &trust_revision,
    };
    let grant = check_remote_dispatch(&leases, request, remote, &env).map_err(provider_error)?;
    if let Some(connection) = &grant.pin_connection {
        let pinned = pin_connection(&leases, &remote.remote_connection_id, connection);
        save_leases(ctx.lease_path, &pinned).map_err(|_| {
            ProviderError::new(
                FailureCode::RemoteSessionInactive,
                "the remote-session lease could not record its connection; failing closed",
            )
        })?;
    }
    if grant.read_requires_approval {
        let prompt = ApprovalPrompt::new(
            request.workspace_id.clone(),
            POLICY_REVISION,
            "allow one remote read",
            request.target.clone().unwrap_or_default(),
            format!(
                "remote read {}/{} under lease {}",
                request.capability, request.operation, grant.lease_id
            ),
            per_request_digest(&grant.lease_id, request),
        );
        approval
            .request(&prompt)
            .map_err(|error| ProviderError::new(error.code, error.message))?;
    }
    Ok(())
}

/// SG-000057: STRONG local presence before `orcel remote enable` or
/// `orcel remote pair` runs. Only the local lifecycle CLI calls this; remote
/// contexts never reach it.
pub fn authorize_enrollment(
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    let object = request.arguments.as_object().ok_or_else(|| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "enrollment arguments must be an object",
        )
    })?;
    if object.len() != 2 {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "enrollment accepts exactly action and relay_origin",
        ));
    }
    let action = string_arg(&request.arguments, "action")?;
    if action != "enable" && action != "pair" {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "enrollment action must be enable or pair",
        ));
    }
    let relay_origin = string_arg(&request.arguments, "relay_origin")?;
    if relay_origin.is_empty()
        || relay_origin.len() > 256
        || relay_origin.contains(char::is_whitespace)
    {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "relay_origin is malformed",
        ));
    }
    let mut hasher = Sha256::new();
    for field in [
        "ORCEL_REMOTE_ENROLLMENT_V1",
        POLICY_REVISION,
        &request.workspace_id,
        &action,
        &relay_origin,
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let prompt = ApprovalPrompt::new_strong(
        request.workspace_id.clone(),
        POLICY_REVISION,
        if action == "enable" {
            "enable remote access for this device"
        } else {
            "pair a remote AI client with this device"
        },
        relay_origin.clone(),
        format!("action={action} relay={relay_origin}"),
        digest.clone(),
    );
    let token = approval
        .request_token(&prompt)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    approval
        .consume(
            &token,
            &ConsumeExpectation::strong(digest, request.workspace_id.clone(), POLICY_REVISION),
            orcel_approval::now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    Ok(json!({ "authorized": true, "action": action }))
}

/// Emergency revoke invalidates every remote-session lease immediately.
pub fn revoke_all(lease_path: &Path) -> Result<usize, ProviderError> {
    let leases = load_leases(lease_path);
    let (next, revoked) = revoke_leases(&leases, None);
    save_leases(lease_path, &next).map_err(provider_error)?;
    Ok(revoked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_approval::test_support::{
        broker_with_presence, FixedApprovalBroker, TestPresenceVerifier,
    };
    use orcel_approval::ApprovalDecision;
    use orcel_policy::remote_session::WorkstationBinding;
    use std::cell::{Cell, RefCell};

    const T0: u64 = 1_800_000_000_000;

    fn next_temp_sequence() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        // macOS clocks tick in microseconds, so a timestamp alone can repeat
        // across parallel tests in one process.
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    }

    fn temp(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let nanos = format!("{nanos}-{}", next_temp_sequence());
        let dir = std::env::temp_dir().join(format!(
            "orceld-lease-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn unlocked() -> WorkstationState {
        WorkstationState::Unlocked(WorkstationBinding {
            session_id: 1,
            logon_id: 42,
        })
    }

    fn trusted_store(dir: &Path) -> trust::TrustStore {
        let mut store = trust::TrustStore::load_or_create(dir.join("trust.jsonl"));
        store
            .grant("default", POLICY_REVISION, "test", T0 - 10)
            .expect("grant trust");
        store
    }

    fn workspaces() -> WorkspaceSet {
        WorkspaceSet::from_pairs(&[
            ("default".into(), PathBuf::from("C:/w/default")),
            ("other".into(), PathBuf::from("C:/w/other")),
        ])
    }

    fn create_request() -> RequestEnvelope {
        RequestEnvelope {
            version: 1,
            request_id: "create-1".into(),
            client_session_id: "local".into(),
            workspace_id: "default".into(),
            capability: "remote.lease.create".into(),
            operation: "create".into(),
            target: None,
            arguments: json!({
                "principal": format!("rp-{}", "a".repeat(32)),
                "remote_connection_id": format!("rc-{}", "b".repeat(32)),
                "device_id": format!("dev-{}", "c".repeat(32)),
                "device_epoch": 1,
                "provider_kind": "generic",
                "client_profile_id": "profile-1",
                "client_profile_revision": 1,
                "tool_surface_profile": "core",
                "scope_ceiling": ["orcel.read", "orcel.write"],
                "workspaces": ["default"],
                "read_mode": "session",
                "duration_seconds": 600,
            }),
        }
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
            scopes: vec!["orcel.read".into()],
        }
    }

    fn read_request() -> RequestEnvelope {
        RequestEnvelope {
            version: 1,
            request_id: "read-1".into(),
            client_session_id: "remote".into(),
            workspace_id: "default".into(),
            capability: "fs.read".into(),
            operation: "read".into(),
            target: Some("README.md".into()),
            arguments: json!({}),
        }
    }

    struct Fixture {
        dir: PathBuf,
        lease_path: PathBuf,
        workspaces: WorkspaceSet,
        now: Cell<u64>,
        state: RefCell<WorkstationState>,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let dir = temp(label);
            Self {
                lease_path: dir.join("remote_leases.json"),
                dir,
                workspaces: workspaces(),
                now: Cell::new(T0),
                state: RefCell::new(unlocked()),
            }
        }
    }

    fn with_ctx<R>(fixture: &Fixture, f: impl FnOnce(&LeaseContext<'_>) -> R) -> R {
        let probe = || fixture.state.borrow().clone();
        let clock = || fixture.now.get();
        let ctx = LeaseContext {
            lease_path: &fixture.lease_path,
            workspaces: &fixture.workspaces,
            workstation: &probe,
            now_ms: &clock,
        };
        f(&ctx)
    }

    fn strong_broker(fixture: &Fixture, verifier: TestPresenceVerifier) -> impl ApprovalBroker {
        broker_with_presence(fixture.dir.join("approval.jsonl"), verifier)
    }

    fn assert_inactive(result: Result<(), ProviderError>) {
        let error = result.expect_err("remote dispatch must fail closed");
        assert_eq!(
            error.code,
            FailureCode::RemoteSessionInactive,
            "{}",
            error.message
        );
    }

    fn created_fixture(label: &str) -> (Fixture, trust::TrustStore) {
        let fixture = Fixture::new(label);
        let trust = trusted_store(&fixture.dir);
        let broker = strong_broker(&fixture, TestPresenceVerifier::verified());
        with_ctx(&fixture, |ctx| {
            dispatch_lease_management(ctx, &broker, &trust, &create_request())
        })
        .expect("lease created");
        (fixture, trust)
    }

    #[test]
    fn strong_presence_creates_a_bounded_lease_that_permits_exact_remote_dispatch() {
        let (fixture, trust) = created_fixture("create");
        let leases = load_leases(&fixture.lease_path);
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].expires_at_ms - leases[0].created_at_ms, 600_000);
        assert!(leases[0].connection_id.is_none());
        let soft = FixedApprovalBroker(ApprovalDecision::Denied);
        with_ctx(&fixture, |ctx| {
            gate_remote(ctx, &soft, &trust, &read_request(), &remote())
        })
        .expect("exact active lease permits a session-mode read without a prompt");
        let status = with_ctx(&fixture, |ctx| {
            dispatch_lease_management(
                ctx,
                &soft,
                &trust,
                &RequestEnvelope {
                    capability: "remote.lease.status".into(),
                    operation: "get".into(),
                    arguments: json!({}),
                    ..create_request()
                },
            )
        })
        .unwrap();
        assert_eq!(status["leases"][0]["connection_pinned"], true);
        assert_eq!(status["leases"][0]["active"], true);
        let text = status.to_string();
        assert!(
            !text.contains(&format!("rp-{}", "a".repeat(32))),
            "status omits the principal"
        );
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn lease_creation_fails_closed_without_strong_presence() {
        for verifier in [
            TestPresenceVerifier::denied(),
            TestPresenceVerifier::unavailable(),
        ] {
            let fixture = Fixture::new("denied");
            let trust = trusted_store(&fixture.dir);
            let broker = strong_broker(&fixture, verifier);
            let error = with_ctx(&fixture, |ctx| {
                dispatch_lease_management(ctx, &broker, &trust, &create_request())
            })
            .expect_err("no lease without STRONG presence");
            assert_ne!(error.code, FailureCode::RemoteSessionInactive);
            assert!(load_leases(&fixture.lease_path).is_empty());
            let _ = std::fs::remove_dir_all(&fixture.dir);
        }
        let fixture = Fixture::new("fixed-denied");
        let trust = trusted_store(&fixture.dir);
        assert!(with_ctx(&fixture, |ctx| {
            dispatch_lease_management(
                ctx,
                &FixedApprovalBroker(ApprovalDecision::Denied),
                &trust,
                &create_request(),
            )
        })
        .is_err());
        assert!(load_leases(&fixture.lease_path).is_empty());
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn lease_creation_requires_unlocked_workstation_and_trusted_configured_workspaces() {
        let fixture = Fixture::new("locked");
        let trust = trusted_store(&fixture.dir);
        let broker = strong_broker(&fixture, TestPresenceVerifier::verified());
        *fixture.state.borrow_mut() = WorkstationState::Locked;
        assert!(with_ctx(&fixture, |ctx| {
            dispatch_lease_management(ctx, &broker, &trust, &create_request())
        })
        .is_err());
        *fixture.state.borrow_mut() = unlocked();
        let mut untrusted = create_request();
        untrusted.workspace_id = "other".into();
        untrusted.arguments["workspaces"] = json!(["other"]);
        let error = with_ctx(&fixture, |ctx| {
            dispatch_lease_management(ctx, &broker, &trust, &untrusted)
        })
        .unwrap_err();
        assert_eq!(error.code, FailureCode::WorkspaceDenied);
        let mut extra = create_request();
        extra.arguments["forever"] = json!(true);
        assert_eq!(
            with_ctx(&fixture, |ctx| {
                dispatch_lease_management(ctx, &broker, &trust, &extra)
            })
            .unwrap_err()
            .code,
            FailureCode::InvalidRequest
        );
        let mut long = create_request();
        long.arguments["duration_seconds"] = json!(901);
        assert!(with_ctx(&fixture, |ctx| {
            dispatch_lease_management(ctx, &broker, &trust, &long)
        })
        .is_err());
        let mut outside = create_request();
        outside.workspace_id = "other".into();
        assert_eq!(
            with_ctx(&fixture, |ctx| {
                dispatch_lease_management(ctx, &broker, &trust, &outside)
            })
            .unwrap_err()
            .code,
            FailureCode::InvalidRequest
        );
        assert!(load_leases(&fixture.lease_path).is_empty());
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn no_lease_expiry_revoke_and_emergency_revoke_deny_remote_reads() {
        let soft = FixedApprovalBroker(ApprovalDecision::Approved);
        let fixture = Fixture::new("none");
        let trust = trusted_store(&fixture.dir);
        assert_inactive(with_ctx(&fixture, |ctx| {
            gate_remote(ctx, &soft, &trust, &read_request(), &remote())
        }));
        let _ = std::fs::remove_dir_all(&fixture.dir);

        let (fixture, trust) = created_fixture("expiry");
        fixture.now.set(T0 + 600_001);
        assert_inactive(with_ctx(&fixture, |ctx| {
            gate_remote(ctx, &soft, &trust, &read_request(), &remote())
        }));
        let _ = std::fs::remove_dir_all(&fixture.dir);

        let (fixture, trust) = created_fixture("revoke");
        let revoked = with_ctx(&fixture, |ctx| {
            dispatch_lease_management(
                ctx,
                &soft,
                &trust,
                &RequestEnvelope {
                    capability: "remote.lease.revoke".into(),
                    operation: "revoke".into(),
                    arguments: json!({ "remote_connection_id": format!("rc-{}", "b".repeat(32)) }),
                    ..create_request()
                },
            )
        })
        .unwrap();
        assert_eq!(revoked["revoked"], 1);
        assert_inactive(with_ctx(&fixture, |ctx| {
            gate_remote(ctx, &soft, &trust, &read_request(), &remote())
        }));
        let _ = std::fs::remove_dir_all(&fixture.dir);

        let (fixture, trust) = created_fixture("emergency");
        assert_eq!(revoke_all(&fixture.lease_path).unwrap(), 1);
        assert_inactive(with_ctx(&fixture, |ctx| {
            gate_remote(ctx, &soft, &trust, &read_request(), &remote())
        }));
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn reconnect_lock_logoff_and_workspace_revoke_deny_remote_reads() {
        let soft = FixedApprovalBroker(ApprovalDecision::Approved);
        let (fixture, mut trust) = created_fixture("drift");
        with_ctx(&fixture, |ctx| {
            gate_remote(ctx, &soft, &trust, &read_request(), &remote())
        })
        .expect("first use pins the connection");
        let mut reconnected = remote();
        reconnected.connection_id = "cn-2".into();
        assert_inactive(with_ctx(&fixture, |ctx| {
            gate_remote(ctx, &soft, &trust, &read_request(), &reconnected)
        }));
        *fixture.state.borrow_mut() = WorkstationState::Locked;
        assert_inactive(with_ctx(&fixture, |ctx| {
            gate_remote(ctx, &soft, &trust, &read_request(), &remote())
        }));
        *fixture.state.borrow_mut() = WorkstationState::Unlocked(WorkstationBinding {
            session_id: 1,
            logon_id: 43,
        });
        assert_inactive(with_ctx(&fixture, |ctx| {
            gate_remote(ctx, &soft, &trust, &read_request(), &remote())
        }));
        *fixture.state.borrow_mut() = unlocked();
        with_ctx(&fixture, |ctx| {
            gate_remote(ctx, &soft, &trust, &read_request(), &remote())
        })
        .expect("unlock alone restores only an unexpired, unchanged lease");
        trust
            .revoke_workspace("default", POLICY_REVISION, "test", T0 + 5)
            .unwrap();
        assert_inactive(with_ctx(&fixture, |ctx| {
            gate_remote(ctx, &soft, &trust, &read_request(), &remote())
        }));
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn per_request_mode_requires_a_local_soft_approval_for_each_remote_read() {
        let fixture = Fixture::new("per-request");
        let trust = trusted_store(&fixture.dir);
        let broker = strong_broker(&fixture, TestPresenceVerifier::verified());
        let mut request = create_request();
        request.arguments["read_mode"] = json!("per_request");
        with_ctx(&fixture, |ctx| {
            dispatch_lease_management(ctx, &broker, &trust, &request)
        })
        .unwrap();
        let denied = FixedApprovalBroker(ApprovalDecision::Denied);
        let error = with_ctx(&fixture, |ctx| {
            gate_remote(ctx, &denied, &trust, &read_request(), &remote())
        })
        .unwrap_err();
        assert_ne!(error.code, FailureCode::RemoteSessionInactive);
        let approved = FixedApprovalBroker(ApprovalDecision::Approved);
        with_ctx(&fixture, |ctx| {
            gate_remote(ctx, &approved, &trust, &read_request(), &remote())
        })
        .expect("approved per-request read");
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn remote_context_can_never_manage_leases_or_trust() {
        let (fixture, trust) = created_fixture("local-only");
        let soft = FixedApprovalBroker(ApprovalDecision::Approved);
        for capability in [
            "remote.lease.create",
            "remote.lease.revoke",
            "workspace.trust.grant",
        ] {
            let error = with_ctx(&fixture, |ctx| {
                gate_remote(
                    ctx,
                    &soft,
                    &trust,
                    &RequestEnvelope {
                        capability: capability.into(),
                        ..read_request()
                    },
                    &remote(),
                )
            })
            .unwrap_err();
            assert_eq!(error.code, FailureCode::CapabilityDenied);
        }
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[test]
    fn enrollment_requires_strong_presence_and_exact_arguments() {
        let fixture = Fixture::new("enroll");
        let request = RequestEnvelope {
            capability: "remote.enrollment.authorize".into(),
            operation: "authorize".into(),
            arguments: json!({ "action": "pair", "relay_origin": "https://relay.example" }),
            ..create_request()
        };
        let verified = strong_broker(&fixture, TestPresenceVerifier::verified());
        assert_eq!(
            authorize_enrollment(&verified, &request).unwrap()["authorized"],
            true
        );
        for verifier in [
            TestPresenceVerifier::denied(),
            TestPresenceVerifier::unavailable(),
        ] {
            let broker = strong_broker(&fixture, verifier);
            assert!(authorize_enrollment(&broker, &request).is_err());
        }
        let mut wrong = request.clone();
        wrong.arguments =
            json!({ "action": "grant_everything", "relay_origin": "https://relay.example" });
        assert!(authorize_enrollment(&verified, &wrong).is_err());
        wrong.arguments =
            json!({ "action": "pair", "relay_origin": "https://relay.example", "extra": 1 });
        assert!(authorize_enrollment(&verified, &wrong).is_err());
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }
}
