use orcel_approval::{ApprovalBroker, ApprovalClass, LocalApprovalBroker};
use orcel_audit::{default_audit_path, AuditLogger};
use orcel_contracts::{
    FailureCode, RemoteRequestEnvelope, RequestEnvelope, ResponseEnvelope,
    INTERNAL_PROTOCOL_VERSION,
};
use orcel_policy::{PolicyEngine, Workspace, POLICY_REVISION};
use orcel_provider_fs::ProviderError;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, Write};
use std::path::Path;

mod browser;
mod clipboard;
mod executable_admin;
mod fs_mutation;
mod git_fetch;
mod git_mutation;
mod git_push;
#[cfg(all(windows, feature = "live-browser-test"))]
mod live_browser;
mod profile_gate;
mod remote_lease;
mod trust;
mod uia;
mod workstation;

#[allow(dead_code)]
mod legacy {
    pub(super) fn load_policy_bridge() -> Result<orcel_policy::PolicyEngine, String> {
        load_policy()
    }

    pub(super) fn dispatch_bridge(
        policy: &orcel_policy::PolicyEngine,
        workspace: &orcel_policy::Workspace,
        approval: &impl orcel_approval::ApprovalBroker,
        request: &orcel_contracts::RequestEnvelope,
    ) -> Result<serde_json::Value, orcel_provider_fs::ProviderError> {
        dispatch(policy, workspace, approval, request)
    }

    include!("main.rs");
}

fn main() {
    if let Err(error) = run() {
        eprintln!("orceld fatal: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let policy = legacy::load_policy_bridge()?;
    let audit_path = default_audit_path().map_err(|error| format!("resolve audit log: {error}"))?;
    let audit =
        AuditLogger::new(audit_path).map_err(|error| format!("initialize audit log: {error}"))?;
    let approval = LocalApprovalBroker::new()
        .map_err(|error| format!("initialize approval broker: {}", error.message))?;
    let workspace_set = remote_lease::WorkspaceSet::from_environment();

    eprintln!(
        "orceld ready: protocol={} audit={} mode=SG-000039_CLIPBOARD_WRITE",
        INTERNAL_PROTOCOL_VERSION,
        audit.path().display()
    );

    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                eprintln!("orceld stdin error: {error}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<RemoteRequestEnvelope>(&line) {
            Ok(envelope) => handle_envelope(&policy, &audit, &approval, &workspace_set, envelope),
            Err(error) => ResponseEnvelope::failure(
                "unknown",
                FailureCode::InvalidRequest,
                format!("invalid request JSON: {error}"),
            ),
        };

        serde_json::to_writer(&mut stdout, &response)
            .map_err(|error| format!("serialize response: {error}"))?;
        stdout
            .write_all(b"\n")
            .map_err(|error| format!("write response: {error}"))?;
        stdout
            .flush()
            .map_err(|error| format!("flush response: {error}"))?;
    }

    Ok(())
}

/// SG-000055 entry: remote-context requests must pass the local
/// remote-session lease gate before any policy or dispatch step, and local
/// remote-lease management never reaches workspace dispatch.
fn handle_envelope(
    policy: &PolicyEngine,
    audit: &AuditLogger,
    approval: &impl ApprovalBroker,
    workspace_set: &remote_lease::WorkspaceSet,
    envelope: RemoteRequestEnvelope,
) -> ResponseEnvelope {
    let RemoteRequestEnvelope {
        request,
        remote,
        profile,
    } = envelope;
    // SG-000108 decision 6: before any lease, policy or dispatch step.
    if let Err((code, message)) = profile_gate::gate(&request, profile.as_deref(), remote.as_ref())
    {
        let _ = audit.record(&request, POLICY_REVISION, "PROFILE_DENIED");
        return ResponseEnvelope::failure(request.request_id, code, message);
    }
    let lease_path = orcel_policy::remote_session::default_lease_store_path();
    let probe = workstation::current;
    let clock = orcel_approval::now_ms;
    let ctx = remote_lease::LeaseContext {
        lease_path: &lease_path,
        workspaces: workspace_set,
        workstation: &probe,
        now_ms: &clock,
    };
    if let Some(remote) = &remote {
        if uia::is_full_user_desktop_shape(&request.capability, &request.operation) {
            let _ = audit.record(&request, POLICY_REVISION, "REMOTE_DENIED");
            return ResponseEnvelope::failure(
                request.request_id,
                FailureCode::CapabilityDenied,
                "SG-000095 Full User desktop authority is local-only; Remote Full Control remains unavailable",
            );
        }
        let trust_store = trust::TrustStore::load_or_create(trust::default_trust_path());
        if let Err(error) =
            remote_lease::gate_remote(&ctx, approval, &trust_store, &request, remote)
        {
            let _ = audit.record(&request, POLICY_REVISION, "REMOTE_DENIED");
            return ResponseEnvelope::failure(request.request_id, error.code, error.message);
        }
        return handle_request(policy, audit, approval, request);
    }
    if request.capability == "remote.enrollment.authorize" && request.operation == "authorize" {
        if policy.workspace(&request.workspace_id).is_none() {
            let _ = audit.record(&request, POLICY_REVISION, "DENIED");
            return ResponseEnvelope::failure(
                request.request_id,
                FailureCode::WorkspaceDenied,
                "requested workspace is not configured",
            );
        }
        return match remote_lease::authorize_enrollment(approval, &request) {
            Ok(value) => {
                let _ = audit.record(&request, POLICY_REVISION, "SUCCESS");
                ResponseEnvelope::success(&request, value, POLICY_REVISION)
            }
            Err(error) => {
                let _ = audit.record(&request, POLICY_REVISION, "FAILED");
                ResponseEnvelope::failure(request.request_id, error.code, error.message)
            }
        };
    }
    if executable_admin::is_registry_management(&request.capability) {
        if policy.workspace(&request.workspace_id).is_none() {
            let _ = audit.record(&request, POLICY_REVISION, "DENIED");
            return ResponseEnvelope::failure(
                request.request_id,
                FailureCode::WorkspaceDenied,
                "requested workspace is not configured",
            );
        }
        return match executable_admin::dispatch_registry(
            &orcel_policy::executable_registry::default_registry_path(),
            &workspace_set.roots,
            approval,
            &request,
            orcel_approval::now_ms(),
        ) {
            Ok(value) => {
                let _ = audit.record(&request, POLICY_REVISION, "SUCCESS");
                ResponseEnvelope::success(&request, value, POLICY_REVISION)
            }
            Err(error) => {
                let _ = audit.record(&request, POLICY_REVISION, "FAILED");
                ResponseEnvelope::failure(request.request_id, error.code, error.message)
            }
        };
    }
    if remote_lease::is_lease_management(&request.capability) {
        if policy.workspace(&request.workspace_id).is_none() {
            let _ = audit.record(&request, POLICY_REVISION, "DENIED");
            return ResponseEnvelope::failure(
                request.request_id,
                FailureCode::WorkspaceDenied,
                "requested workspace is not configured",
            );
        }
        let trust_store = trust::TrustStore::load_or_create(trust::default_trust_path());
        return match remote_lease::dispatch_lease_management(&ctx, approval, &trust_store, &request)
        {
            Ok(value) => {
                if let Err(error) = audit.record(&request, POLICY_REVISION, "SUCCESS") {
                    return ResponseEnvelope::failure(
                        request.request_id,
                        FailureCode::InternalError,
                        format!("audit write failed: {error}"),
                    );
                }
                ResponseEnvelope::success(&request, value, POLICY_REVISION)
            }
            Err(error) => {
                let _ = audit.record(&request, POLICY_REVISION, "FAILED");
                ResponseEnvelope::failure(request.request_id, error.code, error.message)
            }
        };
    }
    handle_request(policy, audit, approval, request)
}

fn handle_request(
    policy: &PolicyEngine,
    audit: &AuditLogger,
    approval: &impl ApprovalBroker,
    request: RequestEnvelope,
) -> ResponseEnvelope {
    let decision = match policy.authorize(&request) {
        Ok(decision) => decision,
        Err(error) => {
            let _ = audit.record(&request, POLICY_REVISION, "DENIED");
            return ResponseEnvelope::failure(request.request_id, error.code, error.message);
        }
    };

    let mut trust_store = trust::TrustStore::load_or_create(trust::default_trust_path());
    let browser_resolver = browser::system_resolver();
    let browser_root = orcel_provider_browser::default_profile_root();
    match dispatch(
        policy,
        &decision.workspace,
        approval,
        &mut trust_store,
        &request,
        &browser_resolver,
        &browser_root,
    ) {
        Ok(value) => {
            if let Err(error) = audit.record(&request, decision.policy_revision, "SUCCESS") {
                return ResponseEnvelope::failure(
                    request.request_id,
                    FailureCode::InternalError,
                    format!("audit write failed: {error}"),
                );
            }
            ResponseEnvelope::success(&request, value, decision.policy_revision)
        }
        Err(error) => {
            let state = match error.code {
                FailureCode::ApprovalDenied => "APPROVAL_DENIED",
                FailureCode::ApprovalUnavailable => "APPROVAL_UNAVAILABLE",
                FailureCode::TargetStale => "TARGET_STALE",
                FailureCode::ProcessTimeout => "PROCESS_TIMEOUT",
                FailureCode::ProcessTerminationUnverified => "PROCESS_TERMINATION_UNVERIFIED",
                FailureCode::OutputLimit => "OUTPUT_LIMIT",
                _ => "FAILED",
            };
            let _ = audit.record(&request, decision.policy_revision, state);
            ResponseEnvelope::failure(request.request_id, error.code, error.message)
        }
    }
}

fn dispatch(
    policy: &PolicyEngine,
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    trust_store: &mut trust::TrustStore,
    request: &RequestEnvelope,
    browser_resolver: &impl orcel_provider_browser::DnsResolver,
    browser_root: &Path,
) -> Result<Value, ProviderError> {
    if let Some(result) = fs_mutation::dispatch_fs_mutation(workspace, approval, request)? {
        return Ok(result);
    }
    if let Some(result) = dispatch_trust(workspace, approval, trust_store, request)? {
        return Ok(result);
    }
    if let Some(result) = uia::dispatch_uia(workspace, approval, request)? {
        return Ok(result);
    }
    if let Some(result) = clipboard::dispatch_clipboard(workspace, approval, request)? {
        return Ok(result);
    }
    if let Some(result) =
        browser::dispatch_navigation(workspace, approval, request, browser_resolver, browser_root)?
    {
        return Ok(result);
    }
    if let Some(result) = browser::dispatch_observation(workspace, request, browser_root)? {
        return Ok(result);
    }
    if let Some(result) = browser::dispatch_actuation(workspace, approval, request, browser_root)? {
        return Ok(result);
    }
    if let Some(result) =
        browser::dispatch_download(workspace, approval, request, browser_resolver, browser_root)?
    {
        return Ok(result);
    }
    let trust = trust_store.get(&workspace.id);
    if let Some(result) = browser::dispatch_upload(
        workspace,
        approval,
        request,
        trust.trusted,
        trust.revision,
        browser_root,
    )? {
        return Ok(result);
    }
    if let Some(result) = browser::dispatch(workspace, request, browser_resolver, browser_root)? {
        return Ok(result);
    }
    if orcel_policy::approval_class_for(&request.capability, &request.operation)
        == ApprovalClass::Strong
    {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "STRONG-class operations require platform-mediated presence and no STRONG execution authority is authorized for this shape; failing closed without SOFT downgrade",
        ));
    }
    let push_lookup = git_push::PolicyPushLookup { policy };
    let push_resolver = git_push::system_resolver();
    if let Some(result) =
        git_push::dispatch(workspace, approval, request, &push_lookup, &push_resolver)?
    {
        return Ok(result);
    }
    let fetch_lookup = git_fetch::PolicyFetchLookup { policy };
    let fetch_resolver = git_fetch::system_resolver();
    if let Some(result) =
        git_fetch::dispatch(workspace, approval, request, &fetch_lookup, &fetch_resolver)?
    {
        return Ok(result);
    }
    if let Some(result) = git_mutation::dispatch(workspace, approval, request)? {
        return Ok(result);
    }
    legacy::dispatch_bridge(policy, workspace, approval, request)
}

fn dispatch_trust(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    trust_store: &mut trust::TrustStore,
    request: &RequestEnvelope,
) -> Result<Option<Value>, ProviderError> {
    match (request.capability.as_str(), request.operation.as_str()) {
        ("workspace.trust.get", "get") => {
            let status = trust_store.get(&request.workspace_id);
            Ok(Some(json!({
                "workspace_id": status.workspace_id,
                "trusted": status.trusted,
                "revision": status.revision,
                "provenance_method": status.provenance_method,
                "updated_at_ms": status.updated_at_ms,
                "policy_revision": status.policy_revision,
            })))
        }
        ("workspace.trust.grant", "grant") => {
            change_trust(workspace, approval, trust_store, request, true).map(Some)
        }
        ("workspace.trust.revoke", "revoke") => {
            change_trust(workspace, approval, trust_store, request, false).map(Some)
        }
        ("trust.revoke_emergency", "revoke") => {
            let digest = revoke_digest(workspace, request);
            let prompt = orcel_approval::ApprovalPrompt::new_strong(
                workspace.id.clone(),
                POLICY_REVISION,
                "emergency revoke all pending approvals",
                request.workspace_id.clone(),
                format!("workspace={} policy={POLICY_REVISION}", workspace.id),
                digest.clone(),
            );
            let epoch = approval
                .emergency_revoke(&prompt)
                .map_err(|error| ProviderError::new(error.code, error.message))?;
            let full_control_epoch =
                orcel_policy::full_control_store::revoke_default_if_present().map_err(|error| {
                    ProviderError::new(
                        FailureCode::InternalError,
                        format!(
                            "emergency revoke advanced the approval epoch but Full User desktop authority could not be revoked: {}",
                            error.message
                        ),
                    )
                })?;
            let leases_revoked = remote_lease::revoke_all(
                &orcel_policy::remote_session::default_lease_store_path(),
            )
            .map_err(|error| {
                ProviderError::new(
                    FailureCode::InternalError,
                    format!(
                        "emergency revoke advanced the approval epoch but remote-session leases could not be revoked: {}",
                        error.message
                    ),
                )
            })?;
            Ok(Some(json!({
                "workspace_id": request.workspace_id,
                "revoke_epoch": epoch,
                "full_control_authority_epoch": full_control_epoch,
                "remote_leases_revoked": leases_revoked,
                "policy_revision": POLICY_REVISION,
            })))
        }
        ("approval.history.query", "query") => {
            let limit = history_limit(request)?;
            let entries = approval.history(limit);
            let items: Vec<Value> = entries
                .iter()
                .map(|entry| {
                    json!({
                        "id": entry.id,
                        "digest": entry.digest,
                        "workspace_id": entry.workspace_id,
                        "policy_revision": entry.policy_revision,
                        "decision": format!("{:?}", entry.decision),
                        "approval_class": entry.approval_class.as_str(),
                        "presence_outcome": entry.presence_outcome.as_str(),
                        "presence_method": entry.presence_method,
                        "epoch": entry.epoch,
                        "is_revoke": entry.is_revoke,
                        "requested_at_ms": entry.requested_at_ms,
                        "decided_at_ms": entry.decided_at_ms,
                        "expires_at_ms": entry.expires_at_ms,
                        "reuse_scope": entry.reuse_scope,
                        "consumed": entry.consumed,
                    })
                })
                .collect();
            Ok(Some(json!({"entries": items})))
        }
        ("trust.history.query", "query") => {
            let limit = history_limit(request)?;
            let entries = trust_store.history(limit);
            let items: Vec<Value> = entries
                .iter()
                .map(|entry| {
                    json!({
                        "workspace_id": entry.workspace_id,
                        "trusted": entry.trusted,
                        "revision": entry.revision,
                        "provenance_method": entry.provenance_method,
                        "updated_at_ms": entry.updated_at_ms,
                        "policy_revision": entry.policy_revision,
                    })
                })
                .collect();
            Ok(Some(json!({"entries": items})))
        }
        _ => Ok(None),
    }
}

fn change_trust(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    trust_store: &mut trust::TrustStore,
    request: &RequestEnvelope,
    requested_trusted: bool,
) -> Result<Value, ProviderError> {
    let before = trust_store.get(&request.workspace_id);
    let digest = trust_digest(workspace, request, &before, requested_trusted);
    let action = if requested_trusted {
        "grant workspace trust"
    } else {
        "revoke workspace trust"
    };
    let prompt = orcel_approval::ApprovalPrompt::new_strong(
        workspace.id.clone(),
        POLICY_REVISION,
        action,
        request.workspace_id.clone(),
        format!(
            "workspace={} requested_trusted={requested_trusted} current_trusted={} current_revision={} policy={POLICY_REVISION}",
            request.workspace_id, before.trusted, before.revision
        ),
        digest.clone(),
    );
    let token = approval
        .request_token(&prompt)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    approval
        .consume(
            &token,
            &orcel_approval::ConsumeExpectation::strong(
                digest,
                workspace.id.clone(),
                POLICY_REVISION,
            ),
            orcel_approval::now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let after = trust_store.get(&request.workspace_id);
    if after.trusted != before.trusted || after.revision != before.revision {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "workspace trust state changed after approval; trust change fails closed",
        ));
    }
    let method = approval
        .history(1)
        .first()
        .map(|entry| entry.presence_method.clone())
        .unwrap_or_else(|| "unknown".to_owned());
    let status = if requested_trusted {
        trust_store.grant(
            &request.workspace_id,
            POLICY_REVISION,
            &method,
            orcel_approval::now_ms(),
        )?
    } else {
        trust_store.revoke_workspace(
            &request.workspace_id,
            POLICY_REVISION,
            &method,
            orcel_approval::now_ms(),
        )?
    };
    Ok(json!({
        "workspace_id": status.workspace_id,
        "trusted": status.trusted,
        "revision": status.revision,
        "provenance_method": status.provenance_method,
        "updated_at_ms": status.updated_at_ms,
        "policy_revision": status.policy_revision,
    }))
}

fn trust_digest(
    workspace: &Workspace,
    request: &RequestEnvelope,
    before: &trust::TrustStatus,
    requested_trusted: bool,
) -> String {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, b"ORCEL_TRUST_APPROVAL_V1");
    digest_field(&mut hasher, workspace.id.as_bytes());
    digest_field(&mut hasher, POLICY_REVISION.as_bytes());
    digest_field(&mut hasher, request.capability.as_bytes());
    digest_field(&mut hasher, request.operation.as_bytes());
    digest_field(&mut hasher, request.workspace_id.as_bytes());
    digest_field(
        &mut hasher,
        (if requested_trusted { "grant" } else { "revoke" }).as_bytes(),
    );
    digest_field(
        &mut hasher,
        (if before.trusted { "1" } else { "0" }).as_bytes(),
    );
    digest_field(&mut hasher, before.revision.to_string().as_bytes());
    hex_lower(&hasher.finalize())
}

fn revoke_digest(workspace: &Workspace, request: &RequestEnvelope) -> String {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, b"ORCEL_REVOKE_APPROVAL_V1");
    digest_field(&mut hasher, workspace.id.as_bytes());
    digest_field(&mut hasher, request.capability.as_bytes());
    digest_field(&mut hasher, request.operation.as_bytes());
    digest_field(&mut hasher, request.workspace_id.as_bytes());
    hex_lower(&hasher.finalize())
}

fn history_limit(request: &RequestEnvelope) -> Result<usize, ProviderError> {
    match request.arguments.get("limit") {
        None => Ok(50),
        Some(value) => {
            let limit = value.as_u64().ok_or_else(|| {
                ProviderError::new(
                    FailureCode::InvalidRequest,
                    "history query limit must be an unsigned integer",
                )
            })? as usize;
            if !(1..=200).contains(&limit) {
                return Err(ProviderError::new(
                    FailureCode::InvalidRequest,
                    "history query limit must be between 1 and 200",
                ));
            }
            Ok(limit)
        }
    }
}

fn digest_field(hasher: &mut Sha256, value: &[u8]) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_approval::test_support::FixedApprovalBroker;
    use orcel_approval::ApprovalDecision;
    use orcel_provider_browser::ProviderError as BrowserError;
    use serde_json::json;
    use std::fs;
    use std::net::IpAddr;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct StaticBrowserResolver {
        addresses: Vec<IpAddr>,
    }

    impl orcel_provider_browser::DnsResolver for StaticBrowserResolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, BrowserError> {
            Ok(self.addresses.clone())
        }
    }

    fn public_browser_resolver() -> StaticBrowserResolver {
        StaticBrowserResolver {
            addresses: vec!["93.184.216.34".parse().unwrap()],
        }
    }

    fn temp_root() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("orcel-sg21-main-{suffix}"));
        fs::create_dir_all(&root).expect("root");
        root
    }

    fn temp_trust_path() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "orcel-sg21-trust-{}-{suffix}.jsonl",
            std::process::id()
        ))
    }

    fn temp_browser_root(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "orcel-sg21-browser-{label}-{}-{suffix}",
            std::process::id()
        ))
    }

    fn trust_store_at(path: &Path) -> trust::TrustStore {
        trust::TrustStore::load_or_create(path.to_path_buf())
    }

    fn git(cwd: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", null_device())
            .output()
            .expect("git");
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn policy_for(workspace: &Workspace) -> PolicyEngine {
        PolicyEngine::with_destinations(
            vec![workspace.clone()],
            Vec::new(),
            vec![orcel_policy::PushDestination {
                workspace_id: "default".into(),
                id: "test-origin".into(),
                canonical_url: "https://example.com/repo.git".into(),
                hostname: "example.com".into(),
                port: 443,
                credential_reference: "anonymous".into(),
            }],
        )
        .expect("policy")
    }

    fn browser_request(capability: &str, operation: &str, arguments: Value) -> RequestEnvelope {
        RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "sg21-browser".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: None,
            arguments,
        }
    }

    #[test]
    fn sg000021_profile_status_dispatches_isolated_identity() {
        let root = temp_root();
        git(&root, &["init", "-b", "main"]);
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical"),
        };
        let policy = policy_for(&workspace);
        let request = browser_request("browser.profile", "status", json!({}));
        policy.authorize(&request).expect("policy");
        let trust_path = temp_trust_path();
        let mut trust_store = trust_store_at(&trust_path);
        let browser_root = temp_browser_root("status");
        let result = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &mut trust_store,
            &request,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect("dispatch");
        assert_eq!(result["isolated"], true);
        assert_eq!(result["personal_data"], false);
        assert_eq!(result["workspace_id"], "default");
        assert_eq!(result["policy_revision"], POLICY_REVISION);
        let marker = browser_root.join("ORCEL_AUTOMATION_PROFILE");
        assert!(marker.is_file(), "profile marker must exist");
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_file(trust_path);
        let _ = fs::remove_dir_all(browser_root);
    }

    #[test]
    fn sg000021_destination_validate_accepts_public_and_denies_ssrf_and_widening() {
        let root = temp_root();
        git(&root, &["init", "-b", "main"]);
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical"),
        };
        let policy = policy_for(&workspace);
        let trust_path = temp_trust_path();
        let mut trust_store = trust_store_at(&trust_path);
        let browser_root = temp_browser_root("validate");

        let accepted = browser_request(
            "browser.destination",
            "validate",
            json!({"url": "https://example.com/docs"}),
        );
        policy.authorize(&accepted).expect("policy");
        let result = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &mut trust_store,
            &accepted,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect("dispatch");
        assert_eq!(result["origin"], "https://example.com:443");

        let loopback = StaticBrowserResolver {
            addresses: vec!["127.0.0.1".parse().unwrap()],
        };
        let error = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &mut trust_store,
            &accepted,
            &loopback,
            &browser_root,
        )
        .expect_err("loopback must fail closed");
        assert_eq!(error.code, FailureCode::CapabilityDenied);

        let widened = browser_request(
            "browser.destination",
            "validate",
            json!({"url": "https://evil.example.com/", "expected_origin": "https://example.com/"}),
        );
        policy.authorize(&widened).expect("shape authorized");
        let error = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &mut trust_store,
            &widened,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect_err("redirect widening must fail closed");
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_file(trust_path);
        let _ = fs::remove_dir_all(browser_root);
    }

    #[test]
    fn sg000021_actuation_dispatch_fails_closed_without_soft_downgrade() {
        let root = temp_root();
        git(&root, &["init", "-b", "main"]);
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical"),
        };
        let policy = policy_for(&workspace);
        let trust_path = temp_trust_path();
        let mut trust_store = trust_store_at(&trust_path);
        let browser_root = temp_browser_root("actuation");
        for (capability, operation) in [
            ("browser.navigate", "navigate"),
            // NOTE (SG-000024 successor): structured browser.dom/click and
            // browser.dom/fill are authorized successor shapes covered by
            // the SG-000024 actuation tests; they no longer fail closed here.
            // NOTE (SG-000025 successor): scoped browser.download/preview and
            // browser.download/download are authorized successor shapes
            // covered by the SG-000025 download tests; they no longer fail
            // closed here. Downloaded-file execution, opening, extraction,
            // and upload remain denied in every successor grain.
            ("browser.download", "execute"),
            ("browser.download", "open"),
            ("browser.download", "extract"),
            ("browser.file", "execute"),
            ("browser.archive", "extract"),
            ("browser.upload", "upload"),
            ("browser.profile", "use_personal"),
            ("browser.script", "evaluate"),
            ("policy.change", "change"),
            ("fs.delete", "delete"),
        ] {
            assert_eq!(
                orcel_policy::approval_class_for(capability, operation),
                orcel_approval::ApprovalClass::Strong
            );
            let request = browser_request(capability, operation, json!({}));
            let error = dispatch(
                &policy,
                &workspace,
                &FixedApprovalBroker(ApprovalDecision::Approved),
                &mut trust_store,
                &request,
                &public_browser_resolver(),
                &browser_root,
            )
            .expect_err("actuation dispatch must fail closed");
            assert_eq!(
                error.code,
                FailureCode::CapabilityDenied,
                "{capability}/{operation}"
            );
        }
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_file(trust_path);
        let _ = fs::remove_dir_all(browser_root);
    }

    #[test]
    fn sg000021_personal_profile_root_never_reaches_disk() {
        let root = temp_root();
        git(&root, &["init", "-b", "main"]);
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical"),
        };
        let policy = policy_for(&workspace);
        let request = browser_request(
            "browser.profile",
            "status",
            json!({"profile_root": "C:\\Users\\Owner\\AppData\\Local\\Google\\Chrome\\User Data"}),
        );
        let error = policy
            .authorize(&request)
            .expect_err("personal profile root must be rejected");
        assert_eq!(error.code, FailureCode::InvalidRequest);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sg000021_trust_grant_still_requires_strong_presence() {
        use orcel_approval::test_support::{broker_with_presence, TestPresenceVerifier};
        let root = temp_root();
        git(&root, &["init", "-b", "main"]);
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical"),
        };
        let policy = policy_for(&workspace);
        let trust_path = temp_trust_path();
        let mut trust_store = trust_store_at(&trust_path);
        let grant = RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "sg21-grant".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: "workspace.trust.grant".into(),
            operation: "grant".into(),
            target: Some(".".into()),
            arguments: json!({}),
        };
        policy.authorize(&grant).expect("grant authorized");
        let approval_path = temp_trust_path();
        let broker = broker_with_presence(approval_path.clone(), TestPresenceVerifier::verified());
        let browser_root = temp_browser_root("trust");
        let result = dispatch(
            &policy,
            &workspace,
            &broker,
            &mut trust_store,
            &grant,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect("dispatch");
        assert_eq!(result["trusted"], true);
        assert_eq!(result["revision"], 1);
        let weak = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &mut trust_store,
            &grant,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect_err("weak grant must fail");
        assert!(matches!(
            weak.code,
            FailureCode::ApprovalDenied | FailureCode::ApprovalUnavailable
        ));
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_file(trust_path);
        let _ = fs::remove_file(approval_path);
        let _ = fs::remove_dir_all(browser_root);
    }

    #[test]
    fn sg000021_soft_push_preview_retained() {
        let root = temp_root();
        git(&root, &["init", "-b", "main"]);
        git(&root, &["config", "user.name", "Orcel Test"]);
        git(&root, &["config", "user.email", "orcel@example.invalid"]);
        fs::write(root.join("a.txt"), "one\n").expect("write");
        git(&root, &["add", "a.txt"]);
        git(&root, &["commit", "-m", "initial"]);
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical"),
        };
        let policy = policy_for(&workspace);
        assert_eq!(
            orcel_policy::approval_class_for("git.push.preview", "preview"),
            orcel_approval::ApprovalClass::Soft
        );
        let preview_request = RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "sg21-soft".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: "git.push.preview".into(),
            operation: "preview".into(),
            target: Some(".".into()),
            arguments: json!({"policy_id": "test-origin", "source_branch": "main", "dest_branch": "main", "credential_reference": "anonymous"}),
        };
        policy.authorize(&preview_request).expect("SOFT retained");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sg000022_page_open_preview_navigate_round_trip_with_soft_approval() {
        let root = temp_root();
        git(&root, &["init", "-b", "main"]);
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical"),
        };
        let policy = policy_for(&workspace);
        let trust_path = temp_trust_path();
        let mut trust_store = trust_store_at(&trust_path);
        let browser_root = temp_browser_root("sg22-roundtrip");
        let open_request = browser_request("browser.page", "open", json!({}));
        policy
            .authorize(&open_request)
            .expect("page open authorized");
        let opened = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &mut trust_store,
            &open_request,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect("open dispatches");
        let page_id = opened["page_id"].as_str().expect("page id").to_owned();
        assert!(page_id.starts_with("pg-"));

        let preview_request = browser_request(
            "browser.navigation",
            "preview",
            json!({"page_id": page_id, "url": "https://example.com/docs"}),
        );
        policy
            .authorize(&preview_request)
            .expect("preview authorized");
        let preview = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &mut trust_store,
            &preview_request,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect("preview dispatches");
        assert_eq!(preview["target_origin"], "https://example.com:443");

        let navigate_request = browser_request(
            "browser.navigation",
            "navigate",
            json!({
                "page_id": page_id,
                "url": "https://example.com/docs",
                "expected_origin": "",
                "expected_generation": 0,
                "expected_pinned_address": "93.184.216.34",
            }),
        );
        policy
            .authorize(&navigate_request)
            .expect("navigate shape authorized");
        let evidence = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &mut trust_store,
            &navigate_request,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect("navigate dispatches");
        assert_eq!(evidence["final_origin"], "https://example.com:443");
        assert_eq!(evidence["new_generation"], 1);
        assert_eq!(evidence["cookies"], false);
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_file(trust_path);
        let _ = fs::remove_dir_all(browser_root);
    }

    #[test]
    fn sg000022_navigation_denies_widening_ssrf_download_and_stale_handles() {
        let root = temp_root();
        git(&root, &["init", "-b", "main"]);
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical"),
        };
        let policy = policy_for(&workspace);
        let trust_path = temp_trust_path();
        let mut trust_store = trust_store_at(&trust_path);
        let browser_root = temp_browser_root("sg22-denies");
        let opened = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &mut trust_store,
            &browser_request("browser.page", "open", json!({})),
            &public_browser_resolver(),
            &browser_root,
        )
        .expect("open")
        .clone();
        let page_id = opened["page_id"].as_str().expect("page id").to_owned();
        let navigate = |url: &str,
                        expected_origin: &str,
                        expected_generation: u64,
                        expected_pin: &str|
         -> RequestEnvelope {
            browser_request(
                "browser.navigation",
                "navigate",
                json!({
                    "page_id": page_id,
                    "url": url,
                    "expected_origin": expected_origin,
                    "expected_generation": expected_generation,
                    "expected_pinned_address": expected_pin,
                }),
            )
        };
        for (url, code) in [
            (
                "https://example.com/tool.exe",
                FailureCode::CapabilityDenied,
            ),
            ("https://example.com/", FailureCode::TargetStale),
        ] {
            let (origin, generation, pin) = if url == "https://example.com/" {
                ("https://wrong.example:443", 0, "93.184.216.34")
            } else {
                ("", 0, "93.184.216.34")
            };
            let error = dispatch(
                &policy,
                &workspace,
                &FixedApprovalBroker(ApprovalDecision::Approved),
                &mut trust_store,
                &navigate(url, origin, generation, pin),
                &public_browser_resolver(),
                &browser_root,
            )
            .expect_err("navigation must fail closed");
            assert_eq!(error.code, code, "{url}");
        }
        let widened = browser_request(
            "browser.navigation",
            "navigate",
            json!({
                "page_id": page_id,
                "url": "https://example.com/",
                "expected_origin": "",
                "expected_generation": 0,
                "expected_pinned_address": "93.184.216.34",
                "redirect_chain": ["https://evil.example.com/"],
            }),
        );
        let error = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &mut trust_store,
            &widened,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect_err("redirect widening must fail closed");
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        let loopback = StaticBrowserResolver {
            addresses: vec!["127.0.0.1".parse().unwrap()],
        };
        let error = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &mut trust_store,
            &navigate("https://example.com/", "", 0, "93.184.216.34"),
            &loopback,
            &browser_root,
        )
        .expect_err("loopback must fail closed");
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        let forged = browser_request(
            "browser.navigation",
            "navigate",
            json!({
                "page_id": "pg-forged-handle",
                "url": "https://example.com/",
                "expected_origin": "",
                "expected_generation": 0,
                "expected_pinned_address": "93.184.216.34",
            }),
        );
        let error = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &mut trust_store,
            &forged,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect_err("forged handle must fail");
        assert_eq!(error.code, FailureCode::TargetStale);
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_file(trust_path);
        let _ = fs::remove_dir_all(browser_root);
    }

    #[test]
    fn sg000022_dom_download_upload_scripting_debug_and_personal_remain_denied() {
        let root = temp_root();
        git(&root, &["init", "-b", "main"]);
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical"),
        };
        let policy = policy_for(&workspace);
        let trust_path = temp_trust_path();
        let mut trust_store = trust_store_at(&trust_path);
        let browser_root = temp_browser_root("sg22-denied");
        for (capability, operation) in [
            // NOTE (SG-000024 successor): structured browser.dom/click and
            // browser.dom/fill are lawfully authorized by the SG-000024
            // successor grain and are therefore no longer in this denied
            // set; they are covered by the SG-000024 actuation tests below.
            ("browser.dom", "snapshot"),
            ("browser.snapshot", "capture"),
            // NOTE (SG-000025 successor): scoped browser.download/preview and
            // browser.download/download are authorized successor shapes
            // covered by the SG-000025 download tests; they no longer fail
            // closed here. Downloaded-file execution, opening, extraction,
            // and upload remain denied in every successor grain.
            ("browser.download", "execute"),
            ("browser.download", "open"),
            ("browser.download", "extract"),
            ("browser.file", "execute"),
            ("browser.archive", "extract"),
            ("browser.upload", "upload"),
            ("browser.script", "evaluate"),
            ("browser.cdp", "command"),
            ("browser.profile", "use_personal"),
            ("browser.page", "close"),
            ("browser.navigation", "back"),
        ] {
            assert_eq!(
                orcel_policy::approval_class_for(capability, operation),
                orcel_approval::ApprovalClass::Strong
            );
            let request = browser_request(capability, operation, json!({}));
            let error = dispatch(
                &policy,
                &workspace,
                &FixedApprovalBroker(ApprovalDecision::Approved),
                &mut trust_store,
                &request,
                &public_browser_resolver(),
                &browser_root,
            )
            .expect_err("denied shape must fail closed");
            assert_eq!(
                error.code,
                FailureCode::CapabilityDenied,
                "{capability}/{operation}"
            );
        }
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_file(trust_path);
        let _ = fs::remove_dir_all(browser_root);
    }

    #[test]
    fn sg000023_snapshot_observe_round_trip_with_typed_node_identity() {
        let root = temp_root();
        git(&root, &["init", "-b", "main"]);
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical"),
        };
        let policy = policy_for(&workspace);
        let trust_path = temp_trust_path();
        let mut trust_store = trust_store_at(&trust_path);
        let browser_root = temp_browser_root("sg23-roundtrip");
        let opened = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &mut trust_store,
            &browser_request("browser.page", "open", json!({})),
            &public_browser_resolver(),
            &browser_root,
        )
        .expect("open")
        .clone();
        let page_id = opened["page_id"].as_str().expect("page id").to_owned();

        let denied_before_navigate = browser_request(
            "browser.snapshot",
            "observe",
            json!({
                "page_id": page_id,
                "expected_origin": "",
                "expected_generation": 0,
            }),
        );
        policy
            .authorize(&denied_before_navigate)
            .expect("snapshot shape authorized");
        let error = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &mut trust_store,
            &denied_before_navigate,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect_err("open pages have no document and must fail closed");
        assert_eq!(error.code, FailureCode::TargetStale);

        let navigate_request = browser_request(
            "browser.navigation",
            "navigate",
            json!({
                "page_id": page_id,
                "url": "https://example.com/docs",
                "expected_origin": "",
                "expected_generation": 0,
                "expected_pinned_address": "93.184.216.34",
            }),
        );
        policy
            .authorize(&navigate_request)
            .expect("navigate authorized");
        let evidence = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &mut trust_store,
            &navigate_request,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect("navigate dispatches");
        assert_eq!(evidence["final_origin"], "https://example.com:443");

        let snapshot_request = browser_request(
            "browser.snapshot",
            "observe",
            json!({
                "page_id": page_id,
                "expected_origin": "https://example.com:443",
                "expected_generation": 1,
            }),
        );
        policy
            .authorize(&snapshot_request)
            .expect("snapshot authorized");
        let snapshot = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &mut trust_store,
            &snapshot_request,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect("snapshot dispatches");
        assert_eq!(snapshot["page_id"], page_id.as_str());
        assert_eq!(snapshot["origin"], "https://example.com:443");
        assert_eq!(snapshot["page_generation"], 1);
        assert_eq!(snapshot["cookies"], false);
        assert_eq!(snapshot["credentials"], false);
        let nodes = snapshot["nodes"].as_array().expect("nodes");
        assert!(!nodes.is_empty());
        for node in nodes {
            assert!(node["node_id"]
                .as_str()
                .is_some_and(|value| value.starts_with("nd-")));
            assert_eq!(node["page_id"], page_id.as_str());
            assert_eq!(node["page_generation"], 1);
            assert_eq!(node["origin"], "https://example.com:443");
        }
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_file(trust_path);
        let _ = fs::remove_dir_all(browser_root);
    }

    #[test]
    fn sg000023_snapshot_denies_stale_foreign_oversized_and_actuation() {
        let root = temp_root();
        git(&root, &["init", "-b", "main"]);
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical"),
        };
        let policy = policy_for(&workspace);
        let trust_path = temp_trust_path();
        let mut trust_store = trust_store_at(&trust_path);
        let browser_root = temp_browser_root("sg23-denies");
        let opened = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &mut trust_store,
            &browser_request("browser.page", "open", json!({})),
            &public_browser_resolver(),
            &browser_root,
        )
        .expect("open")
        .clone();
        let page_id = opened["page_id"].as_str().expect("page id").to_owned();
        let navigate_request = browser_request(
            "browser.navigation",
            "navigate",
            json!({
                "page_id": page_id,
                "url": "https://example.com/docs",
                "expected_origin": "",
                "expected_generation": 0,
                "expected_pinned_address": "93.184.216.34",
            }),
        );
        dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &mut trust_store,
            &navigate_request,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect("navigate");

        let observe = |arguments: Value| -> RequestEnvelope {
            browser_request("browser.snapshot", "observe", arguments)
        };
        for (arguments, code) in [
            (
                json!({
                    "page_id": page_id,
                    "expected_origin": "https://wrong.example:443",
                    "expected_generation": 1,
                }),
                FailureCode::TargetStale,
            ),
            (
                json!({
                    "page_id": page_id,
                    "expected_origin": "https://example.com:443",
                    "expected_generation": 9,
                }),
                FailureCode::TargetStale,
            ),
            (
                json!({
                    "page_id": "pg-forged-handle",
                    "expected_origin": "https://example.com:443",
                    "expected_generation": 1,
                }),
                FailureCode::TargetStale,
            ),
        ] {
            let error = dispatch(
                &policy,
                &workspace,
                &FixedApprovalBroker(ApprovalDecision::Denied),
                &mut trust_store,
                &observe(arguments),
                &public_browser_resolver(),
                &browser_root,
            )
            .expect_err("stale snapshot must fail closed");
            assert_eq!(error.code, code);
        }

        let oversized = observe(json!({
            "page_id": page_id,
            "expected_origin": "https://example.com:443",
            "expected_generation": 1,
            "max_nodes": 201,
        }));
        let error = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &mut trust_store,
            &oversized,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect_err("oversized snapshot must fail closed");
        assert!(matches!(
            error.code,
            FailureCode::InvalidRequest | FailureCode::OutputLimit
        ));

        for (capability, operation) in [
            // NOTE (SG-000024 successor): browser.dom/click and
            // browser.dom/fill are authorized successor shapes covered by
            // the SG-000024 actuation tests below.
            ("browser.snapshot", "capture"),
            ("browser.script", "evaluate"),
            ("browser.cdp", "command"),
        ] {
            let error = dispatch(
                &policy,
                &workspace,
                &FixedApprovalBroker(ApprovalDecision::Approved),
                &mut trust_store,
                &browser_request(capability, operation, json!({})),
                &public_browser_resolver(),
                &browser_root,
            )
            .expect_err("actuation must fail closed");
            assert_eq!(
                error.code,
                FailureCode::CapabilityDenied,
                "{capability}/{operation}"
            );
        }
        let widened = observe(json!({
            "page_id": page_id,
            "expected_origin": "https://example.com:443",
            "expected_generation": 1,
            "script": "alert(1)",
        }));
        let error = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &mut trust_store,
            &widened,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect_err("script widening must fail closed");
        assert!(matches!(
            error.code,
            FailureCode::InvalidRequest | FailureCode::CapabilityDenied
        ));
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_file(trust_path);
        let _ = fs::remove_dir_all(browser_root);
    }

    fn open_navigate_snapshot_for_actuation(
        policy: &PolicyEngine,
        workspace: &Workspace,
        trust_store: &mut trust::TrustStore,
        browser_root: &Path,
    ) -> (String, Value) {
        let opened = dispatch(
            policy,
            workspace,
            &FixedApprovalBroker(ApprovalDecision::Denied),
            trust_store,
            &browser_request("browser.page", "open", json!({})),
            &public_browser_resolver(),
            browser_root,
        )
        .expect("open")
        .clone();
        let page_id = opened["page_id"].as_str().expect("page id").to_owned();
        let navigate_request = browser_request(
            "browser.navigation",
            "navigate",
            json!({
                "page_id": page_id,
                "url": "https://example.com/docs",
                "expected_origin": "",
                "expected_generation": 0,
                "expected_pinned_address": "93.184.216.34",
            }),
        );
        policy
            .authorize(&navigate_request)
            .expect("navigate authorized");
        dispatch(
            policy,
            workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            trust_store,
            &navigate_request,
            &public_browser_resolver(),
            browser_root,
        )
        .expect("navigate");
        let snapshot_request = browser_request(
            "browser.snapshot",
            "observe",
            json!({
                "page_id": page_id,
                "expected_origin": "https://example.com:443",
                "expected_generation": 1,
            }),
        );
        policy
            .authorize(&snapshot_request)
            .expect("snapshot authorized");
        let snapshot = dispatch(
            policy,
            workspace,
            &FixedApprovalBroker(ApprovalDecision::Denied),
            trust_store,
            &snapshot_request,
            &public_browser_resolver(),
            browser_root,
        )
        .expect("snapshot");
        (page_id, snapshot)
    }

    #[test]
    fn sg000024_click_round_trip_with_soft_approval_and_generation_bump() {
        let root = temp_root();
        git(&root, &["init", "-b", "main"]);
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical"),
        };
        let policy = policy_for(&workspace);
        let trust_path = temp_trust_path();
        let mut trust_store = trust_store_at(&trust_path);
        let browser_root = temp_browser_root("sg24-click");
        let (page_id, snapshot) = open_navigate_snapshot_for_actuation(
            &policy,
            &workspace,
            &mut trust_store,
            &browser_root,
        );
        let link = snapshot["nodes"]
            .as_array()
            .expect("nodes")
            .iter()
            .find(|node| node["role"] == "link")
            .expect("link node")
            .clone();
        let node_id = link["node_id"].as_str().expect("node id").to_owned();
        let click_request = browser_request(
            "browser.dom",
            "click",
            json!({
                "page_id": page_id,
                "expected_origin": "https://example.com:443",
                "expected_generation": 1,
                "expected_document_generation": 1,
                "node_id": node_id,
                "expected_role": "link",
                "expected_state": "enabled",
            }),
        );
        policy.authorize(&click_request).expect("click authorized");
        let evidence = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &mut trust_store,
            &click_request,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect("click dispatches");
        assert!(evidence["actuation_id"]
            .as_str()
            .is_some_and(|value| value.starts_with("ac-")));
        assert_eq!(evidence["node_id"], node_id.as_str());
        assert_eq!(evidence["action"], "click");
        assert_eq!(evidence["prior_generation"], 1);
        assert_eq!(evidence["new_generation"], 2);
        assert_eq!(evidence["cookies"], false);
        assert!(evidence.get("value").is_none());
        let replay = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &mut trust_store,
            &click_request,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect_err("replayed generation must fail");
        assert_eq!(replay.code, FailureCode::TargetStale);
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_file(trust_path);
        let _ = fs::remove_dir_all(browser_root);
    }

    #[test]
    fn sg000024_fill_round_trip_binds_value_digest_without_value_leakage() {
        let root = temp_root();
        git(&root, &["init", "-b", "main"]);
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical"),
        };
        let policy = policy_for(&workspace);
        let trust_path = temp_trust_path();
        let mut trust_store = trust_store_at(&trust_path);
        let browser_root = temp_browser_root("sg24-fill");
        let (page_id, snapshot) = open_navigate_snapshot_for_actuation(
            &policy,
            &workspace,
            &mut trust_store,
            &browser_root,
        );
        let textbox = snapshot["nodes"]
            .as_array()
            .expect("nodes")
            .iter()
            .find(|node| node["role"] == "textbox")
            .expect("textbox node")
            .clone();
        let node_id = textbox["node_id"].as_str().expect("node id").to_owned();
        let fill_request = browser_request(
            "browser.dom",
            "fill",
            json!({
                "page_id": page_id,
                "expected_origin": "https://example.com:443",
                "expected_generation": 1,
                "expected_document_generation": 1,
                "node_id": node_id,
                "expected_role": "textbox",
                "expected_state": "enabled",
                "value": "hello orcel",
            }),
        );
        policy.authorize(&fill_request).expect("fill authorized");
        let evidence = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &mut trust_store,
            &fill_request,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect("fill dispatches");
        assert_eq!(evidence["action"], "fill");
        assert_eq!(evidence["new_generation"], 2);
        assert!(!evidence["value_digest"].as_str().unwrap_or("").is_empty());
        assert!(evidence.get("value").is_none());
        assert!(evidence.get("password").is_none());
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_file(trust_path);
        let _ = fs::remove_dir_all(browser_root);
    }

    #[test]
    fn sg000024_actuation_denies_stale_mismatch_oversized_and_extended_verbs() {
        let root = temp_root();
        git(&root, &["init", "-b", "main"]);
        let workspace = Workspace {
            id: "default".into(),
            root: fs::canonicalize(&root).expect("canonical"),
        };
        let policy = policy_for(&workspace);
        let trust_path = temp_trust_path();
        let mut trust_store = trust_store_at(&trust_path);
        let browser_root = temp_browser_root("sg24-denies");
        let (page_id, snapshot) = open_navigate_snapshot_for_actuation(
            &policy,
            &workspace,
            &mut trust_store,
            &browser_root,
        );
        let link = snapshot["nodes"]
            .as_array()
            .expect("nodes")
            .iter()
            .find(|node| node["role"] == "link")
            .expect("link node")
            .clone();
        let node_id = link["node_id"].as_str().expect("node id").to_owned();
        let click = |arguments: Value| -> RequestEnvelope {
            browser_request("browser.dom", "click", arguments)
        };
        let base = || {
            json!({
                "page_id": page_id,
                "expected_origin": "https://example.com:443",
                "expected_generation": 1,
                "expected_document_generation": 1,
                "node_id": node_id,
                "expected_role": "link",
                "expected_state": "enabled",
            })
        };
        let mut stale_generation = base();
        stale_generation["expected_generation"] = json!(9);
        let error = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &mut trust_store,
            &click(stale_generation),
            &public_browser_resolver(),
            &browser_root,
        )
        .expect_err("stale generation must fail");
        assert_eq!(error.code, FailureCode::TargetStale);

        let mut wrong_role = base();
        wrong_role["expected_role"] = json!("button");
        let error = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &mut trust_store,
            &click(wrong_role),
            &public_browser_resolver(),
            &browser_root,
        )
        .expect_err("role mismatch must fail");
        assert_eq!(error.code, FailureCode::TargetStale);

        let fill_request = browser_request(
            "browser.dom",
            "fill",
            json!({
                "page_id": page_id,
                "expected_origin": "https://example.com:443",
                "expected_generation": 1,
                "expected_document_generation": 1,
                "node_id": node_id,
                "expected_role": "link",
                "expected_state": "enabled",
                "value": "x",
            }),
        );
        let error = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &mut trust_store,
            &fill_request,
            &public_browser_resolver(),
            &browser_root,
        )
        .expect_err("fill on link must fail");
        assert_eq!(error.code, FailureCode::CapabilityDenied);

        let denied_approval = dispatch(
            &policy,
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &mut trust_store,
            &click(base()),
            &public_browser_resolver(),
            &browser_root,
        )
        .expect_err("denied approval must fail");
        assert_eq!(denied_approval.code, FailureCode::ApprovalDenied);

        for (capability, operation) in [
            ("browser.dom", "select"),
            ("browser.dom", "type"),
            ("browser.snapshot", "capture"),
            ("browser.script", "evaluate"),
            ("browser.cdp", "command"),
            // NOTE (SG-000025 successor): scoped browser.download/preview and
            // browser.download/download are authorized successor shapes
            // covered by the SG-000025 download tests; they no longer fail
            // closed here. Downloaded-file execution, opening, extraction,
            // and upload remain denied in every successor grain.
            ("browser.download", "execute"),
            ("browser.download", "open"),
            ("browser.download", "extract"),
            ("browser.file", "execute"),
            ("browser.archive", "extract"),
            ("browser.shell", "run"),
            ("browser.upload", "upload"),
        ] {
            let error = dispatch(
                &policy,
                &workspace,
                &FixedApprovalBroker(ApprovalDecision::Approved),
                &mut trust_store,
                &browser_request(capability, operation, json!({})),
                &public_browser_resolver(),
                &browser_root,
            )
            .expect_err("extended verb must fail closed");
            assert_eq!(
                error.code,
                FailureCode::CapabilityDenied,
                "{capability}/{operation}"
            );
        }
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_file(trust_path);
        let _ = fs::remove_dir_all(browser_root);
    }

    // Git for Windows maps `/dev/null` to the null device; Git 2.56 rejects `NUL`.
    fn null_device() -> &'static str {
        "/dev/null"
    }
}

#[cfg(test)]
mod sg000055_envelope_tests {
    use super::*;
    use orcel_approval::test_support::FixedApprovalBroker;
    use orcel_approval::ApprovalDecision;
    use orcel_contracts::RemoteContext;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture() -> (PolicyEngine, AuditLogger, std::path::PathBuf) {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "orcel-sg55-envelope-{}-{suffix}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("workspace")).expect("workspace");
        let workspace = Workspace {
            id: "default".into(),
            root: std::fs::canonicalize(root.join("workspace")).expect("canonical"),
        };
        let policy = PolicyEngine::new(vec![workspace]).expect("policy");
        let audit = AuditLogger::new(root.join("audit.jsonl")).expect("audit");
        (policy, audit, root)
    }

    fn request(capability: &str, operation: &str, workspace: &str) -> RequestEnvelope {
        RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "sg55".into(),
            client_session_id: "remote".into(),
            workspace_id: workspace.into(),
            capability: capability.into(),
            operation: operation.into(),
            target: Some("README.md".into()),
            arguments: json!({}),
        }
    }

    fn remote() -> RemoteContext {
        RemoteContext {
            principal: format!("rp-{}", "1".repeat(32)),
            remote_connection_id: format!("rc-{}", "2".repeat(32)),
            connection_id: "conn-sg55-test".into(),
            device_id: format!("dev-{}", "3".repeat(32)),
            device_epoch: 1,
            provider_kind: "generic".into(),
            client_profile_id: "profile-test".into(),
            client_profile_revision: 1,
            tool_surface_profile: "core".into(),
            scopes: vec!["orcel.read".into()],
        }
    }

    fn code(response: &ResponseEnvelope) -> FailureCode {
        response.error.as_ref().expect("failure").code.clone()
    }

    #[test]
    fn remote_requests_without_an_exact_active_lease_never_reach_dispatch() {
        let (policy, audit, root) = fixture();
        let workspaces =
            remote_lease::WorkspaceSet::from_pairs(&[("default".into(), root.join("workspace"))]);
        let approval = FixedApprovalBroker(ApprovalDecision::Approved);
        for (capability, operation) in [
            ("fs.read", "read"),
            ("system.status", "get"),
            ("fs.write", "write"),
            ("process.spawn", "spawn"),
        ] {
            let response = handle_envelope(
                &policy,
                &audit,
                &approval,
                &workspaces,
                RemoteRequestEnvelope {
                    request: request(capability, operation, "default"),
                    remote: Some(remote()),
                    profile: None,
                },
            );
            assert!(!response.ok);
            assert_eq!(code(&response), FailureCode::RemoteSessionInactive);
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn remote_requests_can_never_manage_leases_trust_or_approvals() {
        let (policy, audit, root) = fixture();
        let workspaces =
            remote_lease::WorkspaceSet::from_pairs(&[("default".into(), root.join("workspace"))]);
        let approval = FixedApprovalBroker(ApprovalDecision::Approved);
        for (capability, operation) in [
            ("remote.lease.create", "create"),
            ("remote.lease.revoke", "revoke"),
            ("workspace.trust.grant", "grant"),
            ("trust.revoke_emergency", "revoke"),
            ("approval.history.query", "query"),
        ] {
            let response = handle_envelope(
                &policy,
                &audit,
                &approval,
                &workspaces,
                RemoteRequestEnvelope {
                    request: request(capability, operation, "default"),
                    remote: Some(remote()),
                    profile: None,
                },
            );
            assert_eq!(code(&response), FailureCode::CapabilityDenied);
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn local_lease_management_requires_a_configured_workspace() {
        let (policy, audit, root) = fixture();
        let workspaces =
            remote_lease::WorkspaceSet::from_pairs(&[("default".into(), root.join("workspace"))]);
        let approval = FixedApprovalBroker(ApprovalDecision::Approved);
        let response = handle_envelope(
            &policy,
            &audit,
            &approval,
            &workspaces,
            RemoteRequestEnvelope {
                request: request("remote.lease.status", "get", "missing"),
                remote: None,
                profile: None,
            },
        );
        assert_eq!(code(&response), FailureCode::WorkspaceDenied);
        let unknown = handle_envelope(
            &policy,
            &audit,
            &approval,
            &workspaces,
            RemoteRequestEnvelope {
                request: request("remote.lease.extend", "extend", "default"),
                remote: None,
                profile: None,
            },
        );
        assert_eq!(code(&unknown), FailureCode::CapabilityDenied);
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod sg000058_lease_boundary_tests {
    use super::*;
    use orcel_approval::test_support::FixedApprovalBroker;
    use orcel_approval::ApprovalDecision;
    use orcel_contracts::RemoteContext;
    use orcel_policy::remote_session::{
        build_lease, revoke_leases, save_leases, GateEnvironment, LeaseRequest, ReadMode,
        WorkstationState,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn remote(connection: &str) -> RemoteContext {
        RemoteContext {
            principal: format!("rp-{}", "5".repeat(32)),
            remote_connection_id: format!("rc-{}", "6".repeat(32)),
            connection_id: connection.into(),
            device_id: format!("dev-{}", "7".repeat(32)),
            device_epoch: 1,
            provider_kind: "generic".into(),
            client_profile_id: "remote-default".into(),
            client_profile_revision: 1,
            tool_surface_profile: "core".into(),
            scopes: vec!["orcel.read".into()],
        }
    }

    fn read(workspace: &str) -> RemoteRequestEnvelope {
        RemoteRequestEnvelope {
            request: RequestEnvelope {
                version: INTERNAL_PROTOCOL_VERSION,
                request_id: "sg58".into(),
                client_session_id: "remote".into(),
                workspace_id: workspace.into(),
                capability: "fs.read".into(),
                operation: "read".into(),
                target: Some("README.md".into()),
                arguments: json!({}),
            },
            remote: Some(remote("conn-sg58-a")),
            profile: None,
        }
    }

    fn code(response: &ResponseEnvelope) -> Option<FailureCode> {
        response.error.as_ref().map(|error| error.code.clone())
    }

    /// Real orceld lease boundary on this host: the real workstation probe,
    /// the real lease store, trust store, policy, and dispatch.
    #[test]
    fn sg000058_real_lease_boundary_on_this_workstation() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("orcel-sg58-{}-{suffix}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).expect("workspace");
        std::fs::write(
            root.join("workspace").join("README.md"),
            b"sg58 lease boundary",
        )
        .expect("file");
        let workspace_root = std::fs::canonicalize(root.join("workspace")).expect("canonical");
        let trust_path = root.join("trust.jsonl");
        let lease_path = root.join("remote_leases.json");
        std::env::set_var("ORCEL_TRUST_PATH", &trust_path);
        std::env::set_var("ORCEL_REMOTE_LEASE_PATH", &lease_path);
        let mut trust_store = trust::TrustStore::load_or_create(trust_path.clone());
        trust_store
            .grant("default", POLICY_REVISION, "test", orcel_approval::now_ms())
            .expect("grant");
        let policy = PolicyEngine::new(vec![Workspace {
            id: "default".into(),
            root: workspace_root.clone(),
        }])
        .expect("policy");
        let audit = AuditLogger::new(root.join("audit.jsonl")).expect("audit");
        let workspaces =
            remote_lease::WorkspaceSet::from_pairs(&[("default".into(), workspace_root.clone())]);
        let approval = FixedApprovalBroker(ApprovalDecision::Approved);

        // No lease: denied before policy and dispatch.
        let denied = handle_envelope(&policy, &audit, &approval, &workspaces, read("default"));
        assert_eq!(code(&denied), Some(FailureCode::RemoteSessionInactive));

        let state = workstation::current();
        let trust_revision = |id: &str| {
            let status = trust::TrustStore::load_or_create(trust_path.clone()).get(id);
            status.trusted.then_some(status.revision)
        };
        let env = GateEnvironment {
            now_ms: orcel_approval::now_ms(),
            policy_revision: POLICY_REVISION,
            workspace_set_digest: &workspaces.digest,
            workstation: state.clone(),
            trust_revision: &trust_revision,
        };
        let request = LeaseRequest {
            principal: remote("x").principal,
            remote_connection_id: remote("x").remote_connection_id,
            device_id: remote("x").device_id,
            device_epoch: 1,
            provider_kind: "generic".into(),
            client_profile_id: "remote-default".into(),
            client_profile_revision: 1,
            tool_surface_profile: "core".into(),
            scope_ceiling: vec!["orcel.read".into()],
            workspace_ids: vec!["default".into()],
            read_mode: ReadMode::Session,
            duration_ms: 5 * 60 * 1000,
        };
        let WorkstationState::Unlocked(_) = state else {
            assert!(build_lease(&request, "lease-sg58".into(), &env, &workspaces.ids).is_err());
            eprintln!("SG-000058 lease boundary: workstation is not an unlocked interactive session on this host ({state:?}); lease creation and every remote dispatch fail closed; allowed path UNVERIFIED here");
            let _ = std::fs::remove_dir_all(&root);
            return;
        };
        let lease =
            build_lease(&request, "lease-sg58".into(), &env, &workspaces.ids).expect("lease");
        save_leases(&lease_path, std::slice::from_ref(&lease)).expect("save");

        // Exact active lease on this real unlocked session: dispatch runs.
        let allowed = handle_envelope(&policy, &audit, &approval, &workspaces, read("default"));
        assert!(allowed.ok, "{:?}", allowed.error);
        assert!(allowed
            .result
            .as_ref()
            .expect("result")
            .to_string()
            .contains("sg58 lease boundary"));

        // Reconnect (different short-lived connection) never extends the lease.
        let mut reconnect = read("default");
        if let Some(remote) = reconnect.remote.as_mut() {
            remote.connection_id = "conn-sg58-b".into();
        }
        let reconnected = handle_envelope(&policy, &audit, &approval, &workspaces, reconnect);
        assert_eq!(code(&reconnected), Some(FailureCode::RemoteSessionInactive));

        // A workspace outside the lease is never reachable.
        let outside = handle_envelope(&policy, &audit, &approval, &workspaces, read("other"));
        assert!(!outside.ok);

        // Expired lease (queue-after-lease-expiry): denied.
        let mut expired = lease.clone();
        expired.created_at_ms -= 10 * 60 * 1000;
        expired.expires_at_ms = orcel_approval::now_ms() - 1;
        save_leases(&lease_path, &[expired]).expect("save");
        let late = handle_envelope(&policy, &audit, &approval, &workspaces, read("default"));
        assert_eq!(code(&late), Some(FailureCode::RemoteSessionInactive));

        // Revoked lease (queue-after-revoke): denied.
        let (revoked, _) = revoke_leases(std::slice::from_ref(&lease), None);
        save_leases(&lease_path, &revoked).expect("save");
        let after_revoke =
            handle_envelope(&policy, &audit, &approval, &workspaces, read("default"));
        assert_eq!(
            code(&after_revoke),
            Some(FailureCode::RemoteSessionInactive)
        );

        // Workspace trust revoke invalidates an otherwise active lease.
        save_leases(&lease_path, std::slice::from_ref(&lease)).expect("save");
        assert!(handle_envelope(&policy, &audit, &approval, &workspaces, read("default")).ok);
        trust::TrustStore::load_or_create(trust_path.clone())
            .revoke_workspace("default", POLICY_REVISION, "test", orcel_approval::now_ms())
            .expect("revoke trust");
        let untrusted = handle_envelope(&policy, &audit, &approval, &workspaces, read("default"));
        assert_eq!(code(&untrusted), Some(FailureCode::RemoteSessionInactive));

        // Policy drift (a different workspace set) invalidates the lease.
        let drifted = remote_lease::WorkspaceSet::from_pairs(&[
            ("default".into(), workspace_root.clone()),
            ("added".into(), root.clone()),
        ]);
        let policy_change = handle_envelope(&policy, &audit, &approval, &drifted, read("default"));
        assert_eq!(
            code(&policy_change),
            Some(FailureCode::RemoteSessionInactive)
        );
        eprintln!("SG-000058 lease boundary: allowed, reconnect, outside-workspace, expiry, revoke, trust-revoke, and policy-drift paths exercised on a real unlocked interactive Windows session");
        let _ = std::fs::remove_dir_all(&root);
    }
}
