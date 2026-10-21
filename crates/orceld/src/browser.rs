use orcel_approval::{now_ms, ApprovalBroker, ApprovalPrompt, ConsumeExpectation};
use orcel_contracts::{FailureCode, RequestEnvelope};
use orcel_policy::{Workspace, POLICY_REVISION};
use orcel_provider_browser::DnsResolver;
use orcel_provider_fs::ProviderError;
use serde_json::Value;
use std::path::Path;

/// Dispatch the SG-000021 browser shapes, the SG-000022 page lifecycle and
/// origin-bound navigation, and the SG-000023 read-only snapshot
/// observation. Profile status and destination validation remain strictly
/// local. Page open allocates server-side identity with no network activity.
/// Preview validates with re-resolution but mutates nothing. Navigate
/// requires fresh SOFT approval with digest binding and hop-by-hop redirect
/// validation. Snapshot observe performs a bounded read-only observation of
/// one known active page with no approval and no network activity. Every
/// other browser shape returns `Ok(None)` so the caller fails closed through
/// the STRONG gate or the legacy denial.
pub fn dispatch(
    workspace: &Workspace,
    request: &RequestEnvelope,
    resolver: &impl DnsResolver,
    profile_root: &Path,
) -> Result<Option<Value>, ProviderError> {
    match (request.capability.as_str(), request.operation.as_str()) {
        ("browser.profile", "status") => {
            if request.target.is_some() {
                return Err(ProviderError::new(
                    FailureCode::InvalidRequest,
                    "browser.profile/status does not accept a target field",
                ));
            }
            reject_browser_arguments(request, &[])?;
            let profile = orcel_provider_browser::ensure_isolated_profile(profile_root)
                .map_err(|error| ProviderError::new(error.code, error.message))?;
            Ok(Some(profile.status_json(&workspace.id, POLICY_REVISION)))
        }
        ("browser.destination", "validate") => {
            if request.target.is_some() {
                return Err(ProviderError::new(
                    FailureCode::InvalidRequest,
                    "browser.destination/validate does not accept a target field",
                ));
            }
            reject_browser_arguments(request, &["url", "expected_origin"])?;
            let url = required_string(request, "url")?;
            let validated = match request.arguments.get("expected_origin") {
                None => orcel_provider_browser::validate_destination(url, resolver),
                Some(value) => {
                    let expected = value.as_str().ok_or_else(|| {
                        ProviderError::new(
                            FailureCode::InvalidRequest,
                            "browser.destination/validate expected_origin must be a string",
                        )
                    })?;
                    orcel_provider_browser::validate_redirect(expected, url, resolver)
                }
            }
            .map_err(|error| ProviderError::new(error.code, error.message))?;
            Ok(Some(validated.to_json()))
        }
        _ => Ok(None),
    }
}

/// Dispatch SG-000022 page lifecycle and navigation shapes. Returns
/// `Ok(None)` for non-navigation shapes so the caller falls through to the
/// SG-000021 dispatch above. Page open and preview require no approval;
/// navigate requires a fresh SOFT approval with one-shot consumption.
pub fn dispatch_navigation(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
    resolver: &impl DnsResolver,
    profile_root: &Path,
) -> Result<Option<Value>, ProviderError> {
    match (request.capability.as_str(), request.operation.as_str()) {
        ("browser.page", "open") => {
            if request.target.is_some() {
                return Err(ProviderError::new(
                    FailureCode::InvalidRequest,
                    "browser.page/open does not accept a target field",
                ));
            }
            reject_navigation_arguments(request, &[])?;
            let profile = orcel_provider_browser::ensure_isolated_profile(profile_root)
                .map_err(|error| ProviderError::new(error.code, error.message))?;
            let registry_path = orcel_provider_browser::default_page_registry_path(&profile.root);
            let mut store = orcel_provider_browser::PageStore::load_or_create(registry_path);
            let page = store
                .open_page(&workspace.id, &profile.identity, POLICY_REVISION)
                .map_err(|error| ProviderError::new(error.code, error.message))?;
            Ok(Some(page.to_json()))
        }
        ("browser.navigation", "preview") => {
            if request.target.is_some() {
                return Err(ProviderError::new(
                    FailureCode::InvalidRequest,
                    "browser.navigation/preview does not accept a target field",
                ));
            }
            reject_navigation_arguments(request, &["page_id", "url", "redirect_chain"])?;
            let page_id = required_navigation_string(request, "page_id")?;
            let url = required_navigation_string(request, "url")?;
            let chain = optional_redirect_chain(request)?;
            let profile = orcel_provider_browser::ensure_isolated_profile(profile_root)
                .map_err(|error| ProviderError::new(error.code, error.message))?;
            let registry_path = orcel_provider_browser::default_page_registry_path(&profile.root);
            let store = orcel_provider_browser::PageStore::load_or_create(registry_path);
            let page = store.get(page_id).cloned().ok_or_else(|| {
                ProviderError::new(
                    FailureCode::TargetStale,
                    "browser page handle is unknown; stale page handles fail closed",
                )
            })?;
            check_page_binding(workspace, &profile.identity, &page)?;
            let preview = orcel_provider_browser::preview_navigation(&page, url, &chain, resolver)
                .map_err(|error| ProviderError::new(error.code, error.message))?;
            Ok(Some(preview.to_json()))
        }
        ("browser.navigation", "navigate") => {
            navigate_with_approval(workspace, approval, request, resolver, profile_root).map(Some)
        }
        _ => Ok(None),
    }
}

pub fn system_resolver() -> orcel_provider_browser::SystemResolver {
    orcel_provider_browser::SystemResolver
}

/// Dispatch SG-000023 read-only snapshot observation. Returns `Ok(None)`
/// for non-observation shapes so the caller falls through to the navigation
/// and SG-000021 dispatches. Snapshot observe requires no approval: it is a
/// bounded local read of an already-authorized active page and origin with
/// server-allocated typed node identities.
pub fn dispatch_observation(
    workspace: &Workspace,
    request: &RequestEnvelope,
    profile_root: &Path,
) -> Result<Option<Value>, ProviderError> {
    match (request.capability.as_str(), request.operation.as_str()) {
        ("browser.snapshot", "observe") => {
            observe_snapshot(workspace, request, profile_root).map(Some)
        }
        _ => Ok(None),
    }
}

fn observe_snapshot(
    workspace: &Workspace,
    request: &RequestEnvelope,
    profile_root: &Path,
) -> Result<Value, ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser.snapshot/observe does not accept a target field",
        ));
    }
    reject_observation_arguments(
        request,
        &[
            "page_id",
            "expected_origin",
            "expected_generation",
            "max_nodes",
            "max_depth",
            "max_bytes",
        ],
    )?;
    let page_id = required_observation_string(request, "page_id")?;
    if !page_id.starts_with(orcel_provider_browser::PAGE_ID_PREFIX) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser.snapshot/observe page_id is malformed",
        ));
    }
    let expected_origin = required_observation_string(request, "expected_origin")?;
    let expected_generation = request
        .arguments
        .get("expected_generation")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                "browser.snapshot/observe requires arguments.expected_generation",
            )
        })?;
    let (max_nodes, max_depth, max_bytes) = optional_snapshot_bounds(request)?;

    let profile = orcel_provider_browser::ensure_isolated_profile(profile_root)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let registry_path = orcel_provider_browser::default_page_registry_path(&profile.root);
    let store = orcel_provider_browser::PageStore::load_or_create(registry_path);
    let page = store.get(page_id).cloned().ok_or_else(|| {
        ProviderError::new(
            FailureCode::TargetStale,
            "browser page handle is unknown; stale page handles fail closed",
        )
    })?;
    check_page_binding(workspace, &profile.identity, &page)?;
    if page.current_origin != expected_origin {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page origin changed since navigation; stale page handles fail closed",
        ));
    }
    if page.generation != expected_generation {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page generation changed since navigation; stale page handles fail closed",
        ));
    }
    let snapshot = orcel_provider_browser::build_snapshot(
        &page,
        &profile.identity,
        orcel_policy::POLICY_REVISION,
        max_nodes,
        u32::try_from(max_depth).map_err(|_| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                "browser.snapshot/observe max_depth is out of range",
            )
        })?,
        max_bytes,
    )
    .map_err(|error| ProviderError::new(error.code, error.message))?;
    // Persist server-side node records so later structured actuation
    // verifies role and state against server records, never caller claims.
    let node_path = orcel_provider_browser::default_node_registry_path(&profile.root);
    let mut node_store = orcel_provider_browser::NodeStore::load_or_create(node_path);
    node_store.record_snapshot(
        &profile.identity,
        &page,
        orcel_policy::POLICY_REVISION,
        &snapshot.nodes,
    );
    Ok(snapshot.to_json())
}

fn reject_observation_arguments(
    request: &RequestEnvelope,
    allowed: &[&str],
) -> Result<(), ProviderError> {
    let arguments = request.arguments.as_object().ok_or_else(|| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "browser arguments must be an object",
        )
    })?;
    if let Some(key) = arguments
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
    {
        if matches!(
            key.as_str(),
            "profile_root"
                | "root"
                | "path"
                | "argv"
                | "executable"
                | "script"
                | "javascript"
                | "command"
                | "personal"
                | "credentials"
                | "cookies"
                | "passwords"
                | "session"
                | "extensions"
                | "devtools"
                | "cdp"
                | "approval"
                | "token"
                | "nonce"
                | "digest"
                | "node_id"
                | "selector"
        ) {
            return Err(ProviderError::new(
                FailureCode::CapabilityDenied,
                format!(
                    "browser request must not carry authority-widening field: {key}; caller-selected profiles and nodes, browser argv, scripting, credential material, and caller-supplied approval material are denied"
                ),
            ));
        }
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            format!("browser snapshot request does not accept argument field: {key}"),
        ));
    }
    Ok(())
}

fn required_observation_string<'a>(
    request: &'a RequestEnvelope,
    name: &str,
) -> Result<&'a str, ProviderError> {
    request
        .arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("browser.snapshot/observe requires arguments.{name}"),
            )
        })
}

fn optional_snapshot_bounds(request: &RequestEnvelope) -> Result<(u64, u64, usize), ProviderError> {
    let optional_u64 = |name: &str| -> Result<Option<u64>, ProviderError> {
        match request.arguments.get(name) {
            None => Ok(None),
            Some(value) => value.as_u64().map(Some).ok_or_else(|| {
                ProviderError::new(
                    FailureCode::InvalidRequest,
                    format!("browser.snapshot/observe {name} must be an unsigned integer"),
                )
            }),
        }
    };
    let max_nodes = optional_u64("max_nodes")?;
    let max_depth = optional_u64("max_depth")?;
    let max_bytes = optional_u64("max_bytes")?;
    orcel_provider_browser::resolve_snapshot_bounds(max_nodes, max_depth, max_bytes)
        .map_err(|error| ProviderError::new(error.code, error.message))
}

fn reject_browser_arguments(
    request: &RequestEnvelope,
    allowed: &[&str],
) -> Result<(), ProviderError> {
    let arguments = request.arguments.as_object().ok_or_else(|| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "browser arguments must be an object",
        )
    })?;
    if let Some(key) = arguments
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
    {
        if matches!(
            key.as_str(),
            "profile_root"
                | "root"
                | "path"
                | "argv"
                | "executable"
                | "script"
                | "javascript"
                | "command"
                | "personal"
                | "credentials"
                | "cookies"
                | "passwords"
                | "extensions"
                | "devtools"
                | "cdp"
        ) {
            return Err(ProviderError::new(
                FailureCode::CapabilityDenied,
                format!(
                    "browser request must not carry authority-widening field: {key}; caller-selected profiles, browser argv, scripting, and credential material are denied"
                ),
            ));
        }
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            format!("browser request does not accept argument field: {key}"),
        ));
    }
    Ok(())
}

fn required_string<'a>(request: &'a RequestEnvelope, name: &str) -> Result<&'a str, ProviderError> {
    request
        .arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("browser.destination/validate requires arguments.{name}"),
            )
        })
}

fn reject_navigation_arguments(
    request: &RequestEnvelope,
    allowed: &[&str],
) -> Result<(), ProviderError> {
    let arguments = request.arguments.as_object().ok_or_else(|| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "browser arguments must be an object",
        )
    })?;
    if let Some(key) = arguments
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
    {
        if matches!(
            key.as_str(),
            "profile_root"
                | "root"
                | "path"
                | "argv"
                | "executable"
                | "script"
                | "javascript"
                | "command"
                | "personal"
                | "credentials"
                | "cookies"
                | "passwords"
                | "extensions"
                | "devtools"
                | "cdp"
                | "approval"
                | "token"
                | "nonce"
                | "digest"
        ) {
            return Err(ProviderError::new(
                FailureCode::CapabilityDenied,
                format!(
                    "browser request must not carry authority-widening field: {key}; caller-selected profiles, browser argv, scripting, credential material, and caller-supplied approval material are denied"
                ),
            ));
        }
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            format!("browser navigation request does not accept argument field: {key}"),
        ));
    }
    Ok(())
}

fn required_navigation_string<'a>(
    request: &'a RequestEnvelope,
    name: &str,
) -> Result<&'a str, ProviderError> {
    request
        .arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("browser.navigation requires arguments.{name}"),
            )
        })
}

fn optional_redirect_chain(request: &RequestEnvelope) -> Result<Vec<String>, ProviderError> {
    match request.arguments.get("redirect_chain") {
        None => Ok(Vec::new()),
        Some(value) => {
            let hops = value.as_array().ok_or_else(|| {
                ProviderError::new(
                    FailureCode::InvalidRequest,
                    "browser.navigation redirect_chain must be an array of strings",
                )
            })?;
            if hops.len() > orcel_provider_browser::MAX_REDIRECT_HOPS {
                return Err(ProviderError::new(
                    FailureCode::InvalidRequest,
                    format!(
                        "browser.navigation redirect_chain exceeds at most {} hops",
                        orcel_provider_browser::MAX_REDIRECT_HOPS
                    ),
                ));
            }
            hops.iter()
                .map(|hop| {
                    hop.as_str().map(str::to_owned).ok_or_else(|| {
                        ProviderError::new(
                            FailureCode::InvalidRequest,
                            "browser.navigation redirect_chain entries must be strings",
                        )
                    })
                })
                .collect()
        }
    }
}

fn check_page_binding(
    workspace: &Workspace,
    profile_identity: &str,
    page: &orcel_provider_browser::PageRecord,
) -> Result<(), ProviderError> {
    if page.workspace_id != workspace.id {
        return Err(ProviderError::new(
            FailureCode::WorkspaceDenied,
            "browser page belongs to a different workspace; foreign page handles fail closed",
        ));
    }
    if page.profile_identity != profile_identity {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "browser page belongs to a different profile; foreign page handles fail closed",
        ));
    }
    if page.policy_revision != POLICY_REVISION {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page policy revision drifted; stale page handles fail closed",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn navigate_with_approval(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
    resolver: &impl DnsResolver,
    profile_root: &Path,
) -> Result<Value, ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser.navigation/navigate does not accept a target field",
        ));
    }
    reject_navigation_arguments(
        request,
        &[
            "page_id",
            "url",
            "expected_origin",
            "expected_generation",
            "expected_pinned_address",
            "redirect_chain",
        ],
    )?;
    let page_id = required_navigation_string(request, "page_id")?;
    if !page_id.starts_with(orcel_provider_browser::PAGE_ID_PREFIX) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser.navigation/navigate page_id is malformed",
        ));
    }
    let url = required_navigation_string(request, "url")?;
    let expected_origin = required_navigation_string(request, "expected_origin")?;
    let expected_pinned = required_navigation_string(request, "expected_pinned_address")?;
    let expected_generation = request
        .arguments
        .get("expected_generation")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                "browser.navigation/navigate requires arguments.expected_generation",
            )
        })?;
    let chain = optional_redirect_chain(request)?;

    let profile = orcel_provider_browser::ensure_isolated_profile(profile_root)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let registry_path = orcel_provider_browser::default_page_registry_path(&profile.root);
    let mut store = orcel_provider_browser::PageStore::load_or_create(registry_path);
    let page = store.get(page_id).cloned().ok_or_else(|| {
        ProviderError::new(
            FailureCode::TargetStale,
            "browser page handle is unknown; stale page handles fail closed",
        )
    })?;
    check_page_binding(workspace, &profile.identity, &page)?;

    if page.current_origin != expected_origin {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page origin changed since preview; stale page handles fail closed",
        ));
    }
    if page.generation != expected_generation {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page generation changed since preview; stale page handles fail closed",
        ));
    }

    let preview = orcel_provider_browser::preview_navigation(&page, url, &chain, resolver)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    if preview.pinned_address.to_string() != expected_pinned {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser destination address changed since preview; stale navigation fails closed",
        ));
    }

    let digest = orcel_provider_browser::navigation_approval_digest(
        &workspace.id,
        POLICY_REVISION,
        &profile.identity,
        page_id,
        expected_origin,
        expected_generation,
        &preview.target_origin,
        &preview.pinned_address,
        &chain,
        &preview.final_origin,
    );
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        "navigate isolated browser page",
        page_id.to_owned(),
        format!(
            "page={} origin={} -> {} pins={} redirects={}",
            page_id,
            if expected_origin.is_empty() {
                "(new)"
            } else {
                expected_origin
            },
            preview.final_origin,
            preview.pinned_address,
            preview.redirect_count
        ),
        digest.clone(),
    );
    let token = approval
        .request_token(&prompt)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    approval
        .consume(
            &token,
            &ConsumeExpectation::new(digest, workspace.id.clone(), POLICY_REVISION),
            now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;

    let (next, prior_origin, prior_generation) = store
        .apply_navigation(
            page_id,
            expected_origin,
            expected_generation,
            &preview.final_origin,
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let evidence = orcel_provider_browser::NavigationEvidence {
        page_id: next.page_id.clone(),
        workspace_id: next.workspace_id.clone(),
        policy_revision: POLICY_REVISION.to_owned(),
        profile_identity: next.profile_identity.clone(),
        prior_origin,
        prior_generation,
        target_origin: preview.target_origin.clone(),
        pinned_address: preview.pinned_address,
        redirect_count: preview.redirect_count,
        final_origin: preview.final_origin.clone(),
        new_generation: next.generation,
    };
    Ok(evidence.to_json(&token.record_id))
}

/// Dispatch SG-000024 structured actuation. Returns `Ok(None)` for
/// non-actuation shapes so the caller falls through to the observation,
/// navigation, and SG-000021 dispatches. Invoke (click) and value-entry
/// (fill) each require a fresh SOFT approval with digest binding over page,
/// node, role, state, action, and bounded value material. Structured denial
/// never silently falls back to coordinates, scripting, or CDP.
pub fn dispatch_actuation(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
    profile_root: &Path,
) -> Result<Option<Value>, ProviderError> {
    match (request.capability.as_str(), request.operation.as_str()) {
        ("browser.dom", "click") => {
            actuate_with_approval(workspace, approval, request, profile_root, "click").map(Some)
        }
        ("browser.dom", "fill") => {
            actuate_with_approval(workspace, approval, request, profile_root, "fill").map(Some)
        }
        _ => Ok(None),
    }
}

#[allow(clippy::too_many_arguments)]
fn actuate_with_approval(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
    profile_root: &Path,
    action: &str,
) -> Result<Value, ProviderError> {
    orcel_provider_browser::parse_actuation_action(action)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser actuation shapes do not accept a target field",
        ));
    }
    let mut allowed = vec![
        "page_id",
        "expected_origin",
        "expected_generation",
        "expected_document_generation",
        "node_id",
        "expected_role",
        "expected_state",
    ];
    if action == "fill" {
        allowed.push("value");
    }
    reject_actuation_arguments(request, &allowed)?;
    let page_id = required_actuation_string(request, "page_id")?;
    if !page_id.starts_with(orcel_provider_browser::PAGE_ID_PREFIX) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser actuation page_id is malformed",
        ));
    }
    let expected_origin = required_actuation_string(request, "expected_origin")?;
    let expected_generation = request
        .arguments
        .get("expected_generation")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                "browser actuation requires arguments.expected_generation",
            )
        })?;
    let expected_document_generation = request
        .arguments
        .get("expected_document_generation")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                "browser actuation requires arguments.expected_document_generation",
            )
        })?;
    let node_id = required_actuation_string(request, "node_id")?;
    if !node_id.starts_with(orcel_provider_browser::SNAPSHOT_NODE_PREFIX) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser actuation node_id is malformed",
        ));
    }
    let expected_role = required_actuation_string(request, "expected_role")?;
    let expected_state = required_actuation_string(request, "expected_state")?;
    if expected_state != orcel_provider_browser::ENABLED_NODE_STATE {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "browser actuation targets only enabled nodes; disabled nodes are denied",
        ));
    }
    let value = match action {
        "fill" => required_actuation_string(request, "value")?,
        _ => "",
    };
    if value.len() > orcel_provider_browser::MAX_FILL_VALUE_BYTES {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            format!(
                "browser fill value exceeds at most {} bytes",
                orcel_provider_browser::MAX_FILL_VALUE_BYTES
            ),
        ));
    }

    let profile = orcel_provider_browser::ensure_isolated_profile(profile_root)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let registry_path = orcel_provider_browser::default_page_registry_path(&profile.root);
    let mut page_store = orcel_provider_browser::PageStore::load_or_create(registry_path);
    let page = page_store.get(page_id).cloned().ok_or_else(|| {
        ProviderError::new(
            FailureCode::TargetStale,
            "browser page handle is unknown; stale page handles fail closed",
        )
    })?;
    check_page_binding(workspace, &profile.identity, &page)?;
    if page.current_origin != expected_origin {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page origin changed since observation; stale page handles fail closed",
        ));
    }
    if page.generation != expected_generation {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page generation changed since observation; stale page handles fail closed",
        ));
    }
    if page.generation != expected_document_generation {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser document was replaced since observation; stale page handles fail closed",
        ));
    }

    let node_path = orcel_provider_browser::default_node_registry_path(&profile.root);
    let node_store = orcel_provider_browser::NodeStore::load_or_create(node_path);
    let node = node_store.get(node_id).cloned().ok_or_else(|| {
        ProviderError::new(
            FailureCode::TargetStale,
            "browser node handle is unknown; stale node handles fail closed",
        )
    })?;
    orcel_provider_browser::check_node_for_actuation(
        &node,
        &page,
        &profile.identity,
        POLICY_REVISION,
        expected_role,
        expected_state,
        expected_generation,
        expected_document_generation,
        action,
    )
    .map_err(|error| ProviderError::new(error.code, error.message))?;

    let value_digest = if action == "fill" {
        orcel_provider_browser::fill_value_digest(value)
            .map_err(|error| ProviderError::new(error.code, error.message))?
    } else {
        String::new()
    };
    let digest = orcel_provider_browser::actuation_approval_digest(
        &workspace.id,
        POLICY_REVISION,
        &profile.identity,
        page_id,
        expected_origin,
        expected_generation,
        expected_document_generation,
        node_id,
        expected_role,
        expected_state,
        action,
        value,
    );
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        if action == "click" {
            "invoke isolated browser node"
        } else {
            "enter value into isolated browser node"
        },
        node_id.to_owned(),
        format!(
            "page={page_id} node={node_id} role={expected_role} action={action} origin={expected_origin} generation={expected_generation}"
        ),
        digest.clone(),
    );
    let token = approval
        .request_token(&prompt)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    approval
        .consume(
            &token,
            &ConsumeExpectation::new(digest, workspace.id.clone(), POLICY_REVISION),
            now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;

    let (next, prior_generation) = page_store
        .apply_actuation(page_id, expected_origin, expected_generation)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let actuation_id = orcel_provider_browser::actuation_id_for(
        page_id,
        node_id,
        action,
        &value_digest,
        prior_generation,
        next.generation,
    );
    let evidence = orcel_provider_browser::ActuationEvidence {
        actuation_id,
        page_id: next.page_id.clone(),
        workspace_id: next.workspace_id.clone(),
        policy_revision: POLICY_REVISION.to_owned(),
        profile_identity: next.profile_identity.clone(),
        node_id: node_id.to_owned(),
        action: action.to_owned(),
        role: expected_role.to_owned(),
        state: expected_state.to_owned(),
        origin: next.current_origin.clone(),
        prior_generation,
        new_generation: next.generation,
        value_digest,
    };
    Ok(evidence.to_json(&token.record_id))
}

fn reject_actuation_arguments(
    request: &RequestEnvelope,
    allowed: &[&str],
) -> Result<(), ProviderError> {
    let arguments = request.arguments.as_object().ok_or_else(|| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "browser arguments must be an object",
        )
    })?;
    if let Some(key) = arguments
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
    {
        if matches!(
            key.as_str(),
            "profile_root"
                | "root"
                | "path"
                | "argv"
                | "executable"
                | "script"
                | "javascript"
                | "command"
                | "personal"
                | "credentials"
                | "cookies"
                | "passwords"
                | "session"
                | "extensions"
                | "devtools"
                | "cdp"
                | "approval"
                | "token"
                | "nonce"
                | "digest"
                | "selector"
                | "coordinate"
                | "x"
                | "y"
        ) {
            return Err(ProviderError::new(
                FailureCode::CapabilityDenied,
                format!(
                    "browser request must not carry authority-widening field: {key}; caller-selected profiles, coordinates, selectors, browser argv, scripting, credential material, and caller-supplied approval material are denied"
                ),
            ));
        }
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            format!("browser actuation request does not accept argument field: {key}"),
        ));
    }
    Ok(())
}

fn required_actuation_string<'a>(
    request: &'a RequestEnvelope,
    name: &str,
) -> Result<&'a str, ProviderError> {
    request
        .arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("browser actuation requires arguments.{name}"),
            )
        })
}

/// Dispatch SG-000025 scoped bounded downloads. Returns `Ok(None)` for
/// non-download shapes so the caller falls through to the actuation,
/// observation, navigation, and SG-000021 dispatches. Preview requires no
/// approval, mutates nothing, and returns a server-allocated one-shot source
/// identity. Download requires a fresh SOFT approval with digest binding over
/// the full binding set including the actual content digest, then creates
/// exactly one new file at exactly one canonical relative destination inside
/// the approved workspace download root. Downloaded content is never executed,
/// opened, extracted, or launched.
pub fn dispatch_download(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
    resolver: &impl DnsResolver,
    profile_root: &Path,
) -> Result<Option<Value>, ProviderError> {
    match (request.capability.as_str(), request.operation.as_str()) {
        ("browser.download", "preview") => {
            preview_download(workspace, request, resolver, profile_root).map(Some)
        }
        ("browser.download", "download") => {
            download_with_approval(workspace, approval, request, profile_root).map(Some)
        }
        _ => Ok(None),
    }
}

const DOWNLOAD_PREVIEW_ARGUMENTS: &[&str] = &[
    "page_id",
    "expected_origin",
    "expected_generation",
    "expected_document_generation",
    "source_url",
    "declared_filename",
    "declared_media_type",
    "declared_size_bytes",
    "relative_destination",
    "redirect_chain",
];

const DOWNLOAD_BODY_ARGUMENTS: &[&str] = &[
    "page_id",
    "expected_origin",
    "expected_generation",
    "expected_document_generation",
    "source_id",
    "content_base64",
];

/// Require the page to be active on the authorized origin at the exact
/// expected generation and document generation.
#[allow(clippy::too_many_arguments)]
fn check_download_page_state(
    page: &orcel_provider_browser::PageRecord,
    page_store: &orcel_provider_browser::PageStore,
    page_id: &str,
    expected_origin: &str,
    expected_generation: u64,
    expected_document_generation: u64,
) -> Result<(), ProviderError> {
    if page.state != orcel_provider_browser::PageState::Active {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser download requires an active page with a current origin; pages with no document fail closed",
        ));
    }
    if page.current_origin != expected_origin {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page origin changed since observation; stale download sources fail closed",
        ));
    }
    if page.generation != expected_generation {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page generation changed since observation; stale download sources fail closed",
        ));
    }
    if page.generation != expected_document_generation {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser document was replaced since observation; stale download sources fail closed",
        ));
    }
    if page_store.get(page_id).is_none() {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser page handle is unknown; stale page handles fail closed",
        ));
    }
    Ok(())
}

fn preview_download(
    workspace: &Workspace,
    request: &RequestEnvelope,
    resolver: &impl DnsResolver,
    profile_root: &Path,
) -> Result<Value, ProviderError> {
    reject_download_target(request)?;
    reject_download_arguments(request, DOWNLOAD_PREVIEW_ARGUMENTS)?;
    let page_id = required_download_string(request, "page_id")?;
    if !page_id.starts_with(orcel_provider_browser::PAGE_ID_PREFIX) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser download page_id is malformed",
        ));
    }
    let expected_origin = required_download_string(request, "expected_origin")?;
    let expected_generation = required_download_u64(request, "expected_generation")?;
    let expected_document_generation =
        required_download_u64(request, "expected_document_generation")?;
    let source_url = required_download_string(request, "source_url")?;
    let declared_filename = required_download_string(request, "declared_filename")?;
    let declared_media_type = required_download_string(request, "declared_media_type")?;
    let declared_size_bytes = required_download_u64(request, "declared_size_bytes")?;
    let relative_destination = required_download_string(request, "relative_destination")?;
    let chain = optional_download_redirect_chain(request)?;

    let (canonical_relative, filename) =
        orcel_provider_browser::validate_download_relative_path(relative_destination)
            .map_err(|error| ProviderError::new(error.code, error.message))?;
    if filename != declared_filename {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser download declared_filename must equal the canonical destination file name",
        ));
    }
    if declared_size_bytes == 0 || declared_size_bytes > orcel_provider_browser::MAX_DOWNLOAD_BYTES
    {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            format!(
                "browser download declared_size_bytes must be between 1 and at most {} bytes",
                orcel_provider_browser::MAX_DOWNLOAD_BYTES
            ),
        ));
    }
    if !orcel_provider_browser::is_allowed_download_media_type(declared_media_type) {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "browser download declared media type is not in the authorized allowlist",
        ));
    }
    let extension_media_type = orcel_provider_browser::download_media_type_for_filename(&filename)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    if extension_media_type != declared_media_type {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "browser download declared media type does not match the destination extension; filename, declared type, and content must agree",
        ));
    }

    let profile = orcel_provider_browser::ensure_isolated_profile(profile_root)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let page_store = orcel_provider_browser::PageStore::load_or_create(
        orcel_provider_browser::default_page_registry_path(&profile.root),
    );
    let page = page_store.get(page_id).cloned().ok_or_else(|| {
        ProviderError::new(
            FailureCode::TargetStale,
            "browser page handle is unknown; stale page handles fail closed",
        )
    })?;
    check_page_binding(workspace, &profile.identity, &page)?;
    check_download_page_state(
        &page,
        &page_store,
        page_id,
        expected_origin,
        expected_generation,
        expected_document_generation,
    )?;

    let source = orcel_provider_browser::validate_destination(source_url, resolver)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    if source.origin != page.current_origin {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "browser download source origin is not the authorized current page origin; unauthorized download origins are denied",
        ));
    }
    let (pinned_address, redirect_count) = if chain.is_empty() {
        (source.pinned_address, 0)
    } else {
        let (final_destination, count, _final_origin) =
            orcel_provider_browser::validate_redirect_chain(&page.current_origin, &chain, resolver)
                .map_err(|error| ProviderError::new(error.code, error.message))?;
        if final_destination.origin != page.current_origin {
            return Err(ProviderError::new(
                FailureCode::CapabilityDenied,
                "browser download redirect widened beyond the authorized page origin; redirect widening is denied",
            ));
        }
        (final_destination.pinned_address, count)
    };

    let root = orcel_provider_browser::resolve_download_root(&workspace.root)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let destination =
        orcel_provider_browser::resolve_download_destination(&root, &canonical_relative)
            .map_err(|error| ProviderError::new(error.code, error.message))?;
    if destination.exists() {
        return Err(ProviderError::new(
            FailureCode::PostconditionFailed,
            "browser download destination already exists; downloads never overwrite existing files",
        ));
    }
    let destination_root_identity = orcel_provider_browser::download_root_identity(&root);

    let issued_at_ms = now_ms();
    let expires_at_ms = issued_at_ms.saturating_add(orcel_provider_browser::DOWNLOAD_SOURCE_TTL_MS);
    let source_url_digest = orcel_provider_browser::sha256_hex(source_url.as_bytes());
    let source_id = orcel_provider_browser::download_source_id_for(
        &workspace.id,
        POLICY_REVISION,
        &profile.identity,
        page_id,
        expected_origin,
        expected_generation,
        expected_document_generation,
        &page.current_origin,
        &source_url_digest,
        &canonical_relative,
        declared_media_type,
        declared_size_bytes,
        orcel_provider_browser::DOWNLOAD_POLICY_REVISION,
        issued_at_ms,
    );
    let preview_digest = orcel_provider_browser::download_approval_digest(
        &workspace.id,
        POLICY_REVISION,
        &profile.identity,
        page_id,
        expected_origin,
        expected_generation,
        expected_document_generation,
        &source_id,
        &page.current_origin,
        &canonical_relative,
        declared_media_type,
        declared_size_bytes,
        "",
        orcel_provider_browser::DOWNLOAD_POLICY_REVISION,
    );

    let mut download_store = orcel_provider_browser::DownloadStore::load_or_create(
        orcel_provider_browser::default_download_registry_path(&profile.root),
    );
    if download_store.pending_count(&workspace.id)
        >= orcel_provider_browser::MAX_PENDING_DOWNLOADS_PER_WORKSPACE
    {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            format!(
                "workspace already holds at most {} pending download sources; download holds are bounded",
                orcel_provider_browser::MAX_PENDING_DOWNLOADS_PER_WORKSPACE
            ),
        ));
    }
    download_store.record_pending(orcel_provider_browser::StoredDownload {
        schema: orcel_provider_browser::DOWNLOAD_REGISTRY_SCHEMA.to_owned(),
        source_id: source_id.clone(),
        workspace_id: workspace.id.clone(),
        policy_revision: POLICY_REVISION.to_owned(),
        profile_identity: profile.identity.clone(),
        page_id: page.page_id.clone(),
        origin: page.current_origin.clone(),
        page_generation: expected_generation,
        document_generation: expected_document_generation,
        source_origin: page.current_origin.clone(),
        source_url_digest: source_url_digest.clone(),
        canonical_relative_destination: canonical_relative.clone(),
        declared_filename: filename.clone(),
        declared_media_type: declared_media_type.to_owned(),
        declared_size_bytes,
        download_policy_revision: orcel_provider_browser::DOWNLOAD_POLICY_REVISION.to_owned(),
        issued_at_ms,
        expires_at_ms,
        state: orcel_provider_browser::DOWNLOAD_SOURCE_PENDING.to_owned(),
        download_id: String::new(),
        content_sha256: String::new(),
    });

    let preview = orcel_provider_browser::DownloadPreview {
        source_id,
        page_id: page.page_id.clone(),
        workspace_id: workspace.id.clone(),
        policy_revision: POLICY_REVISION.to_owned(),
        profile_identity: profile.identity.clone(),
        origin: page.current_origin.clone(),
        page_generation: expected_generation,
        document_generation: expected_document_generation,
        source_origin: page.current_origin.clone(),
        source_url_digest,
        pinned_address,
        redirect_count,
        declared_filename: filename,
        declared_media_type: declared_media_type.to_owned(),
        canonical_relative_destination: canonical_relative,
        destination_root_identity,
        declared_size_bytes,
        max_download_bytes: orcel_provider_browser::MAX_DOWNLOAD_BYTES,
        download_policy_revision: orcel_provider_browser::DOWNLOAD_POLICY_REVISION.to_owned(),
        issued_at_ms,
        expires_at_ms,
        preview_digest,
    };
    Ok(preview.to_json())
}

fn download_with_approval(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
    profile_root: &Path,
) -> Result<Value, ProviderError> {
    reject_download_target(request)?;
    reject_download_arguments(request, DOWNLOAD_BODY_ARGUMENTS)?;
    let page_id = required_download_string(request, "page_id")?;
    if !page_id.starts_with(orcel_provider_browser::PAGE_ID_PREFIX) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser download page_id is malformed",
        ));
    }
    let expected_origin = required_download_string(request, "expected_origin")?;
    let expected_generation = required_download_u64(request, "expected_generation")?;
    let expected_document_generation =
        required_download_u64(request, "expected_document_generation")?;
    let source_id = required_download_string(request, "source_id")?;
    if !source_id.starts_with(orcel_provider_browser::DOWNLOAD_SOURCE_PREFIX) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser download source_id is malformed",
        ));
    }
    let content_base64 = required_download_string(request, "content_base64")?;

    let profile = orcel_provider_browser::ensure_isolated_profile(profile_root)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let page_store = orcel_provider_browser::PageStore::load_or_create(
        orcel_provider_browser::default_page_registry_path(&profile.root),
    );
    let page = page_store.get(page_id).cloned().ok_or_else(|| {
        ProviderError::new(
            FailureCode::TargetStale,
            "browser page handle is unknown; stale page handles fail closed",
        )
    })?;
    check_page_binding(workspace, &profile.identity, &page)?;
    check_download_page_state(
        &page,
        &page_store,
        page_id,
        expected_origin,
        expected_generation,
        expected_document_generation,
    )?;

    let mut download_store = orcel_provider_browser::DownloadStore::load_or_create(
        orcel_provider_browser::default_download_registry_path(&profile.root),
    );
    let record = download_store.get(source_id).cloned().ok_or_else(|| {
        ProviderError::new(
            FailureCode::TargetStale,
            "browser download source handle is unknown; stale download sources fail closed",
        )
    })?;
    let now = now_ms();
    orcel_provider_browser::check_download_source(
        &record,
        &page,
        &profile.identity,
        POLICY_REVISION,
        expected_generation,
        expected_document_generation,
        now,
    )
    .map_err(|error| ProviderError::new(error.code, error.message))?;

    let bytes = orcel_provider_browser::decode_download_body(content_base64)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    if bytes.len() as u64 != record.declared_size_bytes {
        return Err(ProviderError::new(
            FailureCode::PostconditionFailed,
            "browser download payload size does not match the approved declared size; declared and actual size disagreement fails closed",
        ));
    }
    let sniffed_media_type = orcel_provider_browser::sniff_download_media_type(&bytes);
    if !orcel_provider_browser::is_allowed_download_media_type(sniffed_media_type) {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "browser download content is an executable, script, archive, macro-capable, or otherwise unauthorized class; such content never becomes an approved download",
        ));
    }
    if !orcel_provider_browser::content_matches_declared_media_type(
        &record.declared_media_type,
        sniffed_media_type,
    ) {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "browser download content does not match the declared media type; filename, declared type, and content must agree",
        ));
    }
    let extension_media_type =
        orcel_provider_browser::download_media_type_for_filename(&record.declared_filename)
            .map_err(|error| ProviderError::new(error.code, error.message))?;

    if extension_media_type != record.declared_media_type {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "browser download destination extension drifted from the declared media type; download policy drift fails closed",
        ));
    }

    let root = orcel_provider_browser::resolve_download_root(&workspace.root)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let destination = orcel_provider_browser::resolve_download_destination(
        &root,
        &record.canonical_relative_destination,
    )
    .map_err(|error| ProviderError::new(error.code, error.message))?;
    if destination.exists() {
        return Err(ProviderError::new(
            FailureCode::PostconditionFailed,
            "browser download destination already exists; downloads never overwrite existing files",
        ));
    }
    let destination_root_identity = orcel_provider_browser::download_root_identity(&root);
    let content_sha256 = orcel_provider_browser::sha256_hex(&bytes);

    let digest = orcel_provider_browser::download_approval_digest(
        &workspace.id,
        POLICY_REVISION,
        &profile.identity,
        page_id,
        expected_origin,
        expected_generation,
        expected_document_generation,
        source_id,
        &record.source_origin,
        &record.canonical_relative_destination,
        &record.declared_media_type,
        record.declared_size_bytes,
        &content_sha256,
        orcel_provider_browser::DOWNLOAD_POLICY_REVISION,
    );
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        "download approved file into the workspace",
        record.canonical_relative_destination.clone(),
        format!(
            "page={page_id} source={source_id} origin={expected_origin} type={} bytes={} -> {}",
            record.declared_media_type,
            record.declared_size_bytes,
            record.canonical_relative_destination
        ),
        digest.clone(),
    );
    let token = approval
        .request_token(&prompt)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    approval
        .consume(
            &token,
            &ConsumeExpectation::new(digest, workspace.id.clone(), POLICY_REVISION),
            now,
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;

    // The source identity is spent before the write so a failed write can
    // never be replayed against a second destination.
    let download_id = orcel_provider_browser::download_id_for(
        source_id,
        &record.canonical_relative_destination,
        &content_sha256,
    );
    download_store
        .mark_consumed_with_digest(source_id, &download_id, &content_sha256)
        .map_err(|error| ProviderError::new(error.code, error.message))?;

    orcel_provider_browser::write_download_file(&root, &destination, &bytes)
        .map_err(|error| ProviderError::new(error.code, error.message))?;

    let evidence = orcel_provider_browser::DownloadEvidence {
        download_id,
        source_id: source_id.to_owned(),
        page_id: page.page_id.clone(),
        workspace_id: workspace.id.clone(),
        policy_revision: POLICY_REVISION.to_owned(),
        profile_identity: profile.identity.clone(),
        origin: page.current_origin.clone(),
        page_generation: expected_generation,
        document_generation: expected_document_generation,
        source_origin: record.source_origin.clone(),
        source_url_digest: record.source_url_digest.clone(),
        canonical_relative_destination: record.canonical_relative_destination.clone(),
        destination_root_identity,
        declared_filename: record.declared_filename.clone(),
        declared_media_type: record.declared_media_type.clone(),
        extension_media_type: extension_media_type.to_owned(),
        sniffed_media_type: sniffed_media_type.to_owned(),
        content_type_consistent: true,
        declared_size_bytes: record.declared_size_bytes,
        actual_size_bytes: bytes.len() as u64,
        content_sha256,
        download_policy_revision: orcel_provider_browser::DOWNLOAD_POLICY_REVISION.to_owned(),
        state: orcel_provider_browser::DOWNLOAD_SOURCE_CONSUMED.to_owned(),
    };
    Ok(evidence.to_json(&token.record_id))
}

fn reject_download_target(request: &RequestEnvelope) -> Result<(), ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser download shapes do not accept a target field",
        ));
    }
    Ok(())
}

fn reject_download_arguments(
    request: &RequestEnvelope,
    allowed: &[&str],
) -> Result<(), ProviderError> {
    let arguments = request.arguments.as_object().ok_or_else(|| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "browser arguments must be an object",
        )
    })?;
    if let Some(key) = arguments
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
    {
        if matches!(
            key.as_str(),
            "profile_root"
                | "root"
                | "path"
                | "destination_root"
                | "download_root"
                | "absolute_destination"
                | "drive"
                | "unc"
                | "argv"
                | "executable"
                | "script"
                | "javascript"
                | "command"
                | "personal"
                | "credentials"
                | "cookies"
                | "passwords"
                | "session"
                | "extensions"
                | "devtools"
                | "cdp"
                | "approval"
                | "token"
                | "nonce"
                | "digest"
                | "selector"
                | "coordinate"
                | "x"
                | "y"
                | "execute"
                | "open"
                | "extract"
                | "spawn"
                | "shell"
                | "run"
                | "archive"
                | "output"
                | "overwrite"
        ) {
            return Err(ProviderError::new(
                FailureCode::CapabilityDenied,
                format!(
                    "browser request must not carry authority-widening field: {key}; caller-selected destinations, caller-selected profiles, coordinates, selectors, browser argv, scripting, credential material, caller-supplied approval material, and downloaded-file execution, opening, and extraction are denied"
                ),
            ));
        }
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            format!("browser download request does not accept argument field: {key}"),
        ));
    }
    Ok(())
}

fn required_download_string<'a>(
    request: &'a RequestEnvelope,
    name: &str,
) -> Result<&'a str, ProviderError> {
    request
        .arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("browser download requires arguments.{name}"),
            )
        })
}

fn required_download_u64(request: &RequestEnvelope, name: &str) -> Result<u64, ProviderError> {
    request
        .arguments
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("browser download requires arguments.{name} as an unsigned integer"),
            )
        })
}

fn optional_download_redirect_chain(
    request: &RequestEnvelope,
) -> Result<Vec<String>, ProviderError> {
    match request.arguments.get("redirect_chain") {
        None => Ok(Vec::new()),
        Some(value) => {
            let hops = value.as_array().ok_or_else(|| {
                ProviderError::new(
                    FailureCode::InvalidRequest,
                    "browser.download redirect_chain must be an array of strings",
                )
            })?;
            if hops.len() > orcel_provider_browser::MAX_REDIRECT_HOPS {
                return Err(ProviderError::new(
                    FailureCode::InvalidRequest,
                    format!(
                        "browser.download redirect_chain exceeds at most {} hops",
                        orcel_provider_browser::MAX_REDIRECT_HOPS
                    ),
                ));
            }
            hops.iter()
                .map(|hop| {
                    hop.as_str().map(str::to_owned).ok_or_else(|| {
                        ProviderError::new(
                            FailureCode::InvalidRequest,
                            "browser.download redirect_chain entries must be strings",
                        )
                    })
                })
                .collect()
        }
    }
}

/// Dispatch SG-000026 scoped bounded uploads. Returns `Ok(None)` for
/// non-upload shapes so the caller falls through to the download, actuation,
/// observation, navigation, and SG-000021 dispatches. Preview requires no
/// approval, mutates nothing, and returns a server-allocated one-shot upload
/// source identity. Submit requires fresh SOFT approval and records exactly one
/// approved upload of exactly one recorded download artifact to exactly one
/// typed file-input node. No path field is accepted, so a caller can never name
/// the file to read, and no page byte transfer is performed.
pub fn dispatch_upload(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
    trust_trusted: bool,
    trust_revision: u64,
    profile_root: &Path,
) -> Result<Option<Value>, ProviderError> {
    match (request.capability.as_str(), request.operation.as_str()) {
        ("browser.upload", "preview") => preview_upload(
            workspace,
            request,
            trust_trusted,
            trust_revision,
            profile_root,
        )
        .map(Some),
        ("browser.upload", "submit") => submit_upload(
            workspace,
            approval,
            request,
            trust_trusted,
            trust_revision,
            profile_root,
        )
        .map(Some),
        _ => Ok(None),
    }
}

const UPLOAD_PREVIEW_ARGUMENTS: &[&str] = &[
    "page_id",
    "expected_origin",
    "expected_generation",
    "expected_document_generation",
    "node_id",
    "expected_role",
    "expected_input_type",
    "expected_state",
    "expected_trust_revision",
    "artifact_source_id",
];

const UPLOAD_SUBMIT_ARGUMENTS: &[&str] = &[
    "page_id",
    "expected_origin",
    "expected_generation",
    "expected_document_generation",
    "source_id",
];

fn reject_upload_arguments(
    request: &RequestEnvelope,
    allowed: &[&str],
) -> Result<(), ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser upload shapes do not accept a target field",
        ));
    }
    let arguments = request.arguments.as_object().ok_or_else(|| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "browser arguments must be an object",
        )
    })?;
    const WIDENING: &[&str] = &[
        "path",
        "paths",
        "file",
        "files",
        "file_path",
        "source_path",
        "relative_path",
        "absolute_path",
        "destination",
        "directory",
        "directories",
        "root",
        "download_root",
        "destination_root",
        "drive",
        "unc",
        "content",
        "content_base64",
        "bytes",
        "data",
        "read",
        "recursive",
        "glob",
        "wildcard",
        "profile_root",
        "argv",
        "executable",
        "script",
        "javascript",
        "command",
        "personal",
        "credentials",
        "cookies",
        "passwords",
        "session",
        "extensions",
        "devtools",
        "cdp",
        "approval",
        "token",
        "nonce",
        "digest",
        "selector",
        "coordinate",
        "x",
        "y",
        "execute",
        "open",
        "extract",
        "spawn",
        "shell",
        "run",
        "submit_form",
        "transfer",
    ];
    if let Some(key) = arguments
        .keys()
        .find(|key| WIDENING.contains(&key.as_str()))
    {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            format!(
                "browser upload request must not carry authority-widening field: {key}; no path, file, content, directory, page-transfer, or execution field is accepted, and an upload source can only be named by a recorded approved download identity"
            ),
        ));
    }
    if let Some(key) = arguments
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
    {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            format!("browser upload request does not accept argument field: {key}"),
        ));
    }
    Ok(())
}

fn required_upload_string<'a>(
    request: &'a RequestEnvelope,
    name: &str,
) -> Result<&'a str, ProviderError> {
    request
        .arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("browser upload requires arguments.{name}"),
            )
        })
}

fn required_upload_u64(request: &RequestEnvelope, name: &str) -> Result<u64, ProviderError> {
    request
        .arguments
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("browser upload requires arguments.{name} as an unsigned integer"),
            )
        })
}

/// Resolve the one admissible upload source from the SG-000025 download
/// registry. A source must be a completed, digest-recorded download artifact
/// inside the approved workspace download root, and its bytes must still match
/// that record exactly.
fn resolve_upload_artifact(
    workspace_root: &Path,
    profile_root: &Path,
    artifact_source_id: &str,
) -> Result<orcel_provider_browser::VerifiedUploadArtifact, ProviderError> {
    let download_store = orcel_provider_browser::DownloadStore::load_or_create(
        orcel_provider_browser::default_download_registry_path(profile_root),
    );
    let record = download_store.get(artifact_source_id).cloned().ok_or_else(|| {
        ProviderError::new(
            FailureCode::TargetStale,
            "browser upload source is not a recorded approved download; unrecorded paths are denied",
        )
    })?;
    if record.state != orcel_provider_browser::DOWNLOAD_SOURCE_CONSUMED
        || record.download_id.is_empty()
    {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser upload source is not a completed approved download; pending or unknown downloads are denied",
        ));
    }
    if record.content_sha256.is_empty() {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "browser upload source has no recorded content digest; an unverifiable artifact is denied",
        ));
    }
    let root = orcel_provider_browser::resolve_download_root(workspace_root)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let destination = orcel_provider_browser::resolve_download_destination(
        &root,
        &record.canonical_relative_destination,
    )
    .map_err(|error| ProviderError::new(error.code, error.message))?;
    if !destination.exists() {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "browser upload source artifact is missing; a removed download fails closed",
        ));
    }
    if destination.is_dir() {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "browser upload source is a directory; directory and recursive upload are denied",
        ));
    }
    let bytes = std::fs::read(&destination)
        .map_err(|error| ProviderError::new(FailureCode::InternalError, error.to_string()))?;
    if bytes.len() as u64 != record.declared_size_bytes
        || orcel_provider_browser::sha256_hex(&bytes) != record.content_sha256
    {
        return Err(ProviderError::new(
            FailureCode::PostconditionFailed,
            "browser upload source no longer matches the recorded approved download",
        ));
    }
    Ok(orcel_provider_browser::VerifiedUploadArtifact {
        relative_destination: record.canonical_relative_destination.clone(),
        download_id: record.download_id.clone(),
        media_type: record.declared_media_type.clone(),
        sha256: record.content_sha256.clone(),
        size_bytes: record.declared_size_bytes,
    })
}

fn preview_upload(
    workspace: &Workspace,
    request: &RequestEnvelope,
    trust_trusted: bool,
    trust_revision: u64,
    profile_root: &Path,
) -> Result<Value, ProviderError> {
    reject_upload_arguments(request, UPLOAD_PREVIEW_ARGUMENTS)?;
    let page_id = required_upload_string(request, "page_id")?;
    if !page_id.starts_with(orcel_provider_browser::PAGE_ID_PREFIX) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser upload page_id is malformed",
        ));
    }
    let expected_origin = required_upload_string(request, "expected_origin")?;
    let expected_generation = required_upload_u64(request, "expected_generation")?;
    let expected_document_generation =
        required_upload_u64(request, "expected_document_generation")?;
    let node_id = required_upload_string(request, "node_id")?;
    if !node_id.starts_with(orcel_provider_browser::SNAPSHOT_NODE_PREFIX) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser upload node_id is malformed",
        ));
    }
    let expected_role = required_upload_string(request, "expected_role")?;
    let expected_input_type = required_upload_string(request, "expected_input_type")?;
    let expected_state = required_upload_string(request, "expected_state")?;
    let expected_trust_revision = required_upload_u64(request, "expected_trust_revision")?;
    let artifact_source_id = required_upload_string(request, "artifact_source_id")?;
    if !orcel_provider_browser::is_well_formed_download_source_id(artifact_source_id) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser upload artifact_source_id is malformed",
        ));
    }
    if expected_role != orcel_provider_browser::UPLOAD_NODE_ROLE
        || !expected_input_type.eq_ignore_ascii_case(orcel_provider_browser::UPLOAD_INPUT_TYPE)
        || expected_state != orcel_provider_browser::ENABLED_NODE_STATE
    {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "browser upload target must be an enabled textbox node with a file input type",
        ));
    }
    if !trust_trusted {
        return Err(ProviderError::new(
            FailureCode::WorkspaceDenied,
            "browser upload requires a trusted workspace; an emergency revoke fails closed",
        ));
    }
    if expected_trust_revision != trust_revision {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "workspace trust revision changed since the caller observed it; trust change fails closed",
        ));
    }
    let profile = orcel_provider_browser::ensure_isolated_profile(profile_root)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let page_store = orcel_provider_browser::PageStore::load_or_create(
        orcel_provider_browser::default_page_registry_path(&profile.root),
    );
    let page = page_store.get(page_id).cloned().ok_or_else(|| {
        ProviderError::new(
            FailureCode::TargetStale,
            "browser page handle is unknown; stale page handles fail closed",
        )
    })?;
    check_page_binding(workspace, &profile.identity, &page)?;
    check_download_page_state(
        &page,
        &page_store,
        page_id,
        expected_origin,
        expected_generation,
        expected_document_generation,
    )?;
    let node_store = orcel_provider_browser::NodeStore::load_or_create(
        orcel_provider_browser::default_node_registry_path(&profile.root),
    );
    let node = node_store.get(node_id).cloned().ok_or_else(|| {
        ProviderError::new(
            FailureCode::TargetStale,
            "browser node handle is unknown; stale node handles fail closed",
        )
    })?;
    orcel_provider_browser::check_node_for_upload(
        &node,
        &page,
        expected_role,
        expected_input_type,
        expected_state,
        &profile.identity,
        POLICY_REVISION,
        expected_generation,
        expected_document_generation,
    )
    .map_err(|error| ProviderError::new(error.code, error.message))?;
    let artifact = resolve_upload_artifact(&workspace.root, &profile.root, artifact_source_id)?;
    let issued_at_ms = now_ms();
    let expires_at_ms = issued_at_ms.saturating_add(orcel_provider_browser::UPLOAD_SOURCE_TTL_MS);
    let source_id = orcel_provider_browser::upload_source_id_for(
        &workspace.id,
        POLICY_REVISION,
        &profile.identity,
        page_id,
        expected_origin,
        expected_generation,
        expected_document_generation,
        node_id,
        expected_role,
        expected_input_type,
        expected_state,
        trust_revision,
        artifact_source_id,
        &artifact.relative_destination,
        &artifact.media_type,
        &artifact.sha256,
        artifact.size_bytes,
        orcel_provider_browser::UPLOAD_POLICY_REVISION,
        issued_at_ms,
    );
    let preview_digest = orcel_provider_browser::upload_approval_digest(
        &workspace.id,
        POLICY_REVISION,
        &profile.identity,
        page_id,
        expected_origin,
        expected_generation,
        expected_document_generation,
        node_id,
        expected_role,
        expected_input_type,
        expected_state,
        trust_revision,
        &source_id,
        &artifact.relative_destination,
        &artifact.media_type,
        &artifact.sha256,
        artifact.size_bytes,
    );

    let mut upload_store = orcel_provider_browser::UploadStore::load_or_create(
        orcel_provider_browser::default_upload_registry_path(&profile.root),
    );
    if upload_store.pending_count(&workspace.id)
        >= orcel_provider_browser::MAX_PENDING_UPLOADS_PER_WORKSPACE
    {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            format!(
                "workspace already holds at most {} pending upload sources; upload holds are bounded",
                orcel_provider_browser::MAX_PENDING_UPLOADS_PER_WORKSPACE
            ),
        ));
    }
    upload_store.record_pending(orcel_provider_browser::StoredUpload {
        schema: orcel_provider_browser::UPLOAD_REGISTRY_SCHEMA.to_owned(),
        source_id: source_id.clone(),
        workspace_id: workspace.id.clone(),
        policy_revision: POLICY_REVISION.to_owned(),
        profile_identity: profile.identity.clone(),
        page_id: page.page_id.clone(),
        origin: page.current_origin.clone(),
        page_generation: expected_generation,
        document_generation: expected_document_generation,
        node_id: node_id.to_owned(),
        node_role: expected_role.to_owned(),
        node_input_type: expected_input_type.to_owned(),
        node_state: expected_state.to_owned(),
        trust_revision,
        artifact_source_id: artifact_source_id.to_owned(),
        artifact_download_id: artifact.download_id.clone(),
        artifact_relative_destination: artifact.relative_destination.clone(),
        artifact_media_type: artifact.media_type.clone(),
        artifact_sha256: artifact.sha256.clone(),
        artifact_size_bytes: artifact.size_bytes,
        upload_policy_revision: orcel_provider_browser::UPLOAD_POLICY_REVISION.to_owned(),
        issued_at_ms,
        expires_at_ms,
        state: orcel_provider_browser::UPLOAD_SOURCE_PENDING.to_owned(),
        upload_id: String::new(),
    });
    let preview = orcel_provider_browser::UploadPreview {
        source_id,
        page_id: page.page_id.clone(),
        workspace_id: workspace.id.clone(),
        policy_revision: POLICY_REVISION.to_owned(),
        profile_identity: profile.identity.clone(),
        origin: page.current_origin.clone(),
        page_generation: expected_generation,
        document_generation: expected_document_generation,
        node_id: node_id.to_owned(),
        node_role: expected_role.to_owned(),
        node_input_type: expected_input_type.to_owned(),
        node_state: expected_state.to_owned(),
        trust_revision,
        artifact_source_id: artifact_source_id.to_owned(),
        artifact_download_id: artifact.download_id,
        artifact_relative_destination: artifact.relative_destination,
        artifact_media_type: artifact.media_type,
        artifact_sha256: artifact.sha256,
        artifact_size_bytes: artifact.size_bytes,
        max_upload_bytes: orcel_provider_browser::MAX_UPLOAD_BYTES,
        upload_policy_revision: orcel_provider_browser::UPLOAD_POLICY_REVISION.to_owned(),
        issued_at_ms,
        expires_at_ms,
        preview_digest,
    };
    Ok(preview.to_json())
}

fn submit_upload(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
    trust_trusted: bool,
    trust_revision: u64,
    profile_root: &Path,
) -> Result<Value, ProviderError> {
    reject_upload_arguments(request, UPLOAD_SUBMIT_ARGUMENTS)?;
    let page_id = required_upload_string(request, "page_id")?;
    if !page_id.starts_with(orcel_provider_browser::PAGE_ID_PREFIX) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser upload page_id is malformed",
        ));
    }
    let expected_origin = required_upload_string(request, "expected_origin")?;
    let expected_generation = required_upload_u64(request, "expected_generation")?;
    let expected_document_generation =
        required_upload_u64(request, "expected_document_generation")?;
    let source_id = required_upload_string(request, "source_id")?;
    if !orcel_provider_browser::is_well_formed_upload_source_id(source_id) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "browser upload source_id is malformed",
        ));
    }
    let profile = orcel_provider_browser::ensure_isolated_profile(profile_root)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let page_store = orcel_provider_browser::PageStore::load_or_create(
        orcel_provider_browser::default_page_registry_path(&profile.root),
    );
    let page = page_store.get(page_id).cloned().ok_or_else(|| {
        ProviderError::new(
            FailureCode::TargetStale,
            "browser page handle is unknown; stale page handles fail closed",
        )
    })?;
    check_page_binding(workspace, &profile.identity, &page)?;
    check_download_page_state(
        &page,
        &page_store,
        page_id,
        expected_origin,
        expected_generation,
        expected_document_generation,
    )?;
    let node_store = orcel_provider_browser::NodeStore::load_or_create(
        orcel_provider_browser::default_node_registry_path(&profile.root),
    );
    let mut upload_store = orcel_provider_browser::UploadStore::load_or_create(
        orcel_provider_browser::default_upload_registry_path(&profile.root),
    );
    let record = upload_store.get(source_id).cloned().ok_or_else(|| {
        ProviderError::new(
            FailureCode::TargetStale,
            "browser upload source handle is unknown; stale upload sources fail closed",
        )
    })?;
    let node = node_store.get(&record.node_id).cloned().ok_or_else(|| {
        ProviderError::new(
            FailureCode::TargetStale,
            "browser upload target node handle is unknown; stale node handles fail closed",
        )
    })?;
    let now = now_ms();
    let artifact = orcel_provider_browser::check_upload_source(
        &record,
        &page,
        &node,
        &profile.identity,
        POLICY_REVISION,
        expected_generation,
        expected_document_generation,
        &record.node_role,
        &record.node_input_type,
        &record.node_state,
        trust_revision,
        trust_trusted,
        &workspace.root,
        now,
    )
    .map_err(|error| ProviderError::new(error.code, error.message))?;
    let digest = orcel_provider_browser::upload_approval_digest(
        &workspace.id,
        POLICY_REVISION,
        &profile.identity,
        page_id,
        expected_origin,
        expected_generation,
        expected_document_generation,
        &record.node_id,
        &record.node_role,
        &record.node_input_type,
        &record.node_state,
        record.trust_revision,
        source_id,
        &artifact.relative_destination,
        &artifact.media_type,
        &artifact.sha256,
        artifact.size_bytes,
    );
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        "upload approved download artifact to a typed file input",
        record.node_id.clone(),
        format!(
            "page={page_id} node={} role={} input={} origin={expected_origin} artifact={} type={} bytes={}",
            record.node_id,

            record.node_role,
            record.node_input_type,
            artifact.relative_destination,
            artifact.media_type,
            artifact.size_bytes
        ),
        digest.clone(),
    );
    let token = approval
        .request_token(&prompt)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    approval
        .consume(
            &token,
            &ConsumeExpectation::new(digest, workspace.id.clone(), POLICY_REVISION),
            now,
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;

    let upload_id =
        orcel_provider_browser::upload_id_for(source_id, &record.node_id, &artifact.sha256);
    upload_store
        .mark_consumed(source_id, &upload_id)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let evidence = orcel_provider_browser::UploadEvidence {
        upload_id,
        source_id: source_id.to_owned(),
        page_id: page.page_id.clone(),
        workspace_id: workspace.id.clone(),
        policy_revision: POLICY_REVISION.to_owned(),
        profile_identity: profile.identity.clone(),
        origin: page.current_origin.clone(),
        page_generation: expected_generation,
        document_generation: expected_document_generation,
        node_id: record.node_id.clone(),
        node_role: record.node_role.clone(),
        node_input_type: record.node_input_type.clone(),
        node_state: record.node_state.clone(),
        trust_revision: record.trust_revision,
        artifact_source_id: record.artifact_source_id.clone(),
        artifact_download_id: artifact.download_id,
        artifact_relative_destination: artifact.relative_destination,
        artifact_media_type: artifact.media_type,
        artifact_sha256: artifact.sha256,
        artifact_size_bytes: artifact.size_bytes,
        upload_policy_revision: orcel_provider_browser::UPLOAD_POLICY_REVISION.to_owned(),
        state: orcel_provider_browser::UPLOAD_SOURCE_CONSUMED.to_owned(),
    };
    Ok(evidence.to_json(&token.record_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_contracts::INTERNAL_PROTOCOL_VERSION;
    use orcel_provider_browser::ProviderError as BrowserError;
    use serde_json::json;
    use std::net::IpAddr;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct StaticResolver {
        addresses: Vec<IpAddr>,
    }

    impl DnsResolver for StaticResolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, BrowserError> {
            Ok(self.addresses.clone())
        }
    }

    fn public_resolver() -> StaticResolver {
        StaticResolver {
            addresses: vec!["93.184.216.34".parse().unwrap()],
        }
    }

    fn next_temp_sequence() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        // macOS clocks tick in microseconds, so a timestamp alone can repeat
        // across parallel tests in one process.
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    }

    fn temp_root(label: &str) -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let suffix = format!("{suffix}-{}", next_temp_sequence());
        let root = std::env::temp_dir().join(format!(
            "orcel-browser-dispatch-{label}-{}-{suffix}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("root");
        root
    }

    fn workspace(root: &std::path::Path) -> Workspace {
        Workspace {
            id: "default".into(),
            root: std::fs::canonicalize(root).expect("canonical"),
        }
    }

    fn profile_dir(label: &str) -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let suffix = format!("{suffix}-{}", next_temp_sequence());
        std::env::temp_dir().join(format!(
            "orcel-browser-profile-{label}-{}-{suffix}",
            std::process::id()
        ))
    }

    fn request(capability: &str, operation: &str, arguments: Value) -> RequestEnvelope {
        RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "browser-dispatch".into(),
            client_session_id: "session".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: None,
            arguments,
        }
    }

    #[test]
    fn profile_status_returns_isolated_identity_bound_to_workspace() {
        let root = temp_root("status");
        let profile_root = profile_dir("status");
        let result = dispatch(
            &workspace(&root),
            &request("browser.profile", "status", json!({})),
            &public_resolver(),
            &profile_root,
        )
        .expect("dispatch")
        .expect("handled");
        assert_eq!(result["isolated"], true);
        assert_eq!(result["personal_data"], false);
        assert_eq!(result["workspace_id"], "default");
        assert_eq!(result["policy_revision"], POLICY_REVISION);
        assert!(result["profile_identity"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }

    #[test]
    fn destination_validate_accepts_public_and_denies_ssrf() {
        let root = temp_root("validate");
        let profile_root = profile_dir("validate");
        let accepted = dispatch(
            &workspace(&root),
            &request(
                "browser.destination",
                "validate",
                json!({"url": "https://example.com/docs"}),
            ),
            &public_resolver(),
            &profile_root,
        )
        .expect("dispatch")
        .expect("handled");
        assert_eq!(accepted["origin"], "https://example.com:443");
        assert_eq!(accepted["pinned_address"], "93.184.216.34");

        let loopback = StaticResolver {
            addresses: vec!["127.0.0.1".parse().unwrap()],
        };
        let error = dispatch(
            &workspace(&root),
            &request(
                "browser.destination",
                "validate",
                json!({"url": "https://example.com/"}),
            ),
            &loopback,
            &profile_root,
        )
        .expect_err("loopback must fail closed");
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }

    #[test]
    fn redirect_mismatch_and_widening_fields_fail_closed() {
        let root = temp_root("redirect");
        let profile_root = profile_dir("redirect");
        let same = dispatch(
            &workspace(&root),
            &request(
                "browser.destination",
                "validate",
                json!({"url": "https://example.com/next", "expected_origin": "https://example.com/"}),
            ),
            &public_resolver(),
            &profile_root,
        )
        .expect("dispatch")
        .expect("handled");
        assert_eq!(same["origin"], "https://example.com:443");

        let widened = dispatch(
            &workspace(&root),
            &request(
                "browser.destination",
                "validate",
                json!({"url": "https://evil.example.com/", "expected_origin": "https://example.com/"}),
            ),
            &public_resolver(),
            &profile_root,
        )
        .expect_err("redirect widening must fail closed");
        assert_eq!(widened.code, FailureCode::CapabilityDenied);

        for field in ["profile_root", "argv", "script", "cookies", "cdp"] {
            let error = dispatch(
                &workspace(&root),
                &request(
                    "browser.destination",
                    "validate",
                    json!({"url": "https://example.com/", field: "x"}),
                ),
                &public_resolver(),
                &profile_root,
            )
            .expect_err("widening field must fail");
            assert_eq!(error.code, FailureCode::CapabilityDenied, "{field}");
        }
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }

    #[test]
    fn unknown_browser_shapes_are_unreachable_at_dispatch() {
        let root = temp_root("unreachable");
        let profile_root = profile_dir("unreachable");
        for (capability, operation) in [
            ("browser.navigate", "navigate"),
            ("browser.dom", "click"),
            // NOTE (SG-000025 successor): browser.download/download is handled
            // by the dedicated SG-000025 download dispatch, not by the
            // SG-000021 base dispatch asserted here. Downloaded-file execution
            // stays unreachable from the base dispatch as well.
            ("browser.download", "download"),
            ("browser.download", "execute"),
        ] {
            let result = dispatch(
                &workspace(&root),
                &request(capability, operation, json!({})),
                &public_resolver(),
                &profile_root,
            )
            .expect("dispatch returns");
            assert!(
                result.is_none(),
                "{capability}/{operation} must be unhandled"
            );
        }
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }

    struct DenyBroker;

    impl ApprovalBroker for DenyBroker {
        fn request_token(
            &self,
            _prompt: &ApprovalPrompt,
        ) -> Result<orcel_approval::ApprovedToken, orcel_approval::ApprovalError> {
            Err(orcel_approval::ApprovalError {
                code: FailureCode::ApprovalDenied,
                message: "denied in test".into(),
            })
        }

        fn consume(
            &self,
            _token: &orcel_approval::ApprovedToken,
            _expected: &ConsumeExpectation,
            _now_ms: u64,
        ) -> Result<(), orcel_approval::ApprovalError> {
            Err(orcel_approval::ApprovalError {
                code: FailureCode::ApprovalDenied,
                message: "no approval".into(),
            })
        }
    }

    fn open_page_for_test(
        workspace_root: &std::path::Path,
        profile_root: &std::path::Path,
    ) -> Value {
        let workspace = workspace(workspace_root);
        dispatch_navigation(
            &workspace,
            &DenyBroker,
            &request("browser.page", "open", json!({})),
            &public_resolver(),
            profile_root,
        )
        .expect("open")
        .expect("handled")
    }

    #[test]
    fn page_open_allocates_server_identity_with_workspace_binding() {
        let root = temp_root("nav-open");
        let profile_root = profile_dir("nav-open");
        let page = open_page_for_test(&root, &profile_root);
        assert!(page["page_id"]
            .as_str()
            .is_some_and(|v| v.starts_with("pg-")));
        assert_eq!(page["workspace_id"], "default");
        assert_eq!(page["generation"], 0);
        let second = open_page_for_test(&root, &profile_root);
        assert_ne!(page["page_id"], second["page_id"]);
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }

    #[test]
    fn navigation_preview_validates_without_mutation_or_approval() {
        let root = temp_root("nav-preview");
        let profile_root = profile_dir("nav-preview");
        let page = open_page_for_test(&root, &profile_root);
        let page_id = page["page_id"].as_str().expect("page id").to_owned();
        let workspace = workspace(&root);
        let preview = dispatch_navigation(
            &workspace,
            &DenyBroker,
            &request(
                "browser.navigation",
                "preview",
                json!({"page_id": page_id, "url": "https://example.com/docs"}),
            ),
            &public_resolver(),
            &profile_root,
        )
        .expect("preview")
        .expect("handled");
        assert_eq!(preview["target_origin"], "https://example.com:443");
        assert_eq!(preview["final_origin"], "https://example.com:443");
        assert_eq!(preview["pinned_address"], "93.184.216.34");
        let loopback = StaticResolver {
            addresses: vec!["127.0.0.1".parse().unwrap()],
        };
        let error = dispatch_navigation(
            &workspace,
            &DenyBroker,
            &request(
                "browser.navigation",
                "preview",
                json!({"page_id": page_id, "url": "https://example.com/"}),
            ),
            &loopback,
            &profile_root,
        )
        .expect_err("SSRF preview must fail");
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        let forged = dispatch_navigation(
            &workspace,
            &DenyBroker,
            &request(
                "browser.navigation",
                "preview",
                json!({"page_id": "pg-forged", "url": "https://example.com/"}),
            ),
            &public_resolver(),
            &profile_root,
        )
        .expect_err("forged page must fail");
        assert_eq!(forged.code, FailureCode::TargetStale);
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }

    #[test]
    fn navigation_navigate_denies_without_approval_and_validates_stale_and_widening() {
        use orcel_approval::test_support::FixedApprovalBroker;
        use orcel_approval::ApprovalDecision;
        let root = temp_root("nav-navigate");
        let profile_root = profile_dir("nav-navigate");
        let page = open_page_for_test(&root, &profile_root);
        let page_id = page["page_id"].as_str().expect("page id").to_owned();
        let workspace = workspace(&root);

        let denied = dispatch_navigation(
            &workspace,
            &DenyBroker,
            &request(
                "browser.navigation",
                "navigate",
                json!({
                    "page_id": page_id,
                    "url": "https://example.com/",
                    "expected_origin": "",
                    "expected_generation": 0,
                    "expected_pinned_address": "93.184.216.34",
                }),
            ),
            &public_resolver(),
            &profile_root,
        )
        .expect_err("denied approval must fail");
        assert_eq!(denied.code, FailureCode::ApprovalDenied);

        let stale_origin = dispatch_navigation(
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request(
                "browser.navigation",
                "navigate",
                json!({
                    "page_id": page_id,
                    "url": "https://example.com/",
                    "expected_origin": "https://wrong.example:443",
                    "expected_generation": 0,
                    "expected_pinned_address": "93.184.216.34",
                }),
            ),
            &public_resolver(),
            &profile_root,
        )
        .expect_err("stale origin must fail");
        assert_eq!(stale_origin.code, FailureCode::TargetStale);

        let stale_generation = dispatch_navigation(
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request(
                "browser.navigation",
                "navigate",
                json!({
                    "page_id": page_id,
                    "url": "https://example.com/",
                    "expected_origin": "",
                    "expected_generation": 9,
                    "expected_pinned_address": "93.184.216.34",
                }),
            ),
            &public_resolver(),
            &profile_root,
        )
        .expect_err("stale generation must fail");
        assert_eq!(stale_generation.code, FailureCode::TargetStale);

        let drifted_pin = dispatch_navigation(
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request(
                "browser.navigation",
                "navigate",
                json!({
                    "page_id": page_id,
                    "url": "https://example.com/",
                    "expected_origin": "",
                    "expected_generation": 0,
                    "expected_pinned_address": "1.1.1.1",
                }),
            ),
            &public_resolver(),
            &profile_root,
        )
        .expect_err("drifted pin must fail");
        assert_eq!(drifted_pin.code, FailureCode::TargetStale);

        let widened = dispatch_navigation(
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request(
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
            ),
            &public_resolver(),
            &profile_root,
        )
        .expect_err("redirect widening must fail");
        assert_eq!(widened.code, FailureCode::CapabilityDenied);

        let download = dispatch_navigation(
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request(
                "browser.navigation",
                "navigate",
                json!({
                    "page_id": page_id,
                    "url": "https://example.com/tool.exe",
                    "expected_origin": "",
                    "expected_generation": 0,
                    "expected_pinned_address": "93.184.216.34",
                }),
            ),
            &public_resolver(),
            &profile_root,
        )
        .expect_err("download must fail");
        assert_eq!(download.code, FailureCode::CapabilityDenied);
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }

    #[test]
    fn navigation_navigate_succeeds_with_approval_and_bumps_generation() {
        use orcel_approval::test_support::FixedApprovalBroker;
        use orcel_approval::ApprovalDecision;
        let root = temp_root("nav-success");
        let profile_root = profile_dir("nav-success");
        let page = open_page_for_test(&root, &profile_root);
        let page_id = page["page_id"].as_str().expect("page id").to_owned();
        let workspace = workspace(&root);
        let evidence = dispatch_navigation(
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request(
                "browser.navigation",
                "navigate",
                json!({
                    "page_id": page_id,
                    "url": "https://example.com/docs",
                    "expected_origin": "",
                    "expected_generation": 0,
                    "expected_pinned_address": "93.184.216.34",
                }),
            ),
            &public_resolver(),
            &profile_root,
        )
        .expect("navigate")
        .expect("handled");
        assert_eq!(evidence["final_origin"], "https://example.com:443");
        assert_eq!(evidence["new_generation"], 1);
        assert_eq!(evidence["cookies"], false);
        let replay = dispatch_navigation(
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request(
                "browser.navigation",
                "navigate",
                json!({
                    "page_id": page_id,
                    "url": "https://example.com/other",
                    "expected_origin": "",
                    "expected_generation": 0,
                    "expected_pinned_address": "93.184.216.34",
                }),
            ),
            &public_resolver(),
            &profile_root,
        )
        .expect_err("replayed generation must fail");
        assert_eq!(replay.code, FailureCode::TargetStale);
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }
    fn active_page_id(workspace_root: &std::path::Path, profile_root: &std::path::Path) -> String {
        use orcel_approval::test_support::FixedApprovalBroker;
        use orcel_approval::ApprovalDecision;
        let workspace = workspace(workspace_root);
        let page = open_page_for_test(workspace_root, profile_root);
        let page_id = page["page_id"].as_str().expect("page id").to_owned();
        dispatch_navigation(
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request(
                "browser.navigation",
                "navigate",
                json!({
                    "page_id": page_id,
                    "url": "https://example.com/docs",
                    "expected_origin": "",
                    "expected_generation": 0,
                    "expected_pinned_address": "93.184.216.34",
                }),
            ),
            &public_resolver(),
            profile_root,
        )
        .expect("navigate")
        .expect("handled");
        page_id
    }

    fn preview_arguments(page_id: &str, destination: &str, filename: &str, size: u64) -> Value {
        json!({
            "page_id": page_id,
            "expected_origin": "https://example.com:443",
            "expected_generation": 1,
            "expected_document_generation": 1,
            "source_url": "https://example.com/files/notes.txt",
            "declared_filename": filename,
            "declared_media_type": "text/plain",
            "declared_size_bytes": size,
            "relative_destination": destination,
        })
    }

    fn body_arguments(page_id: &str, source_id: &str, body: &str) -> Value {
        json!({
            "page_id": page_id,
            "expected_origin": "https://example.com:443",
            "expected_generation": 1,
            "expected_document_generation": 1,
            "source_id": source_id,
            "content_base64": body,
        })
    }

    fn preview_download(
        workspace_root: &std::path::Path,
        profile_root: &std::path::Path,
        arguments: Value,
    ) -> Result<Option<Value>, ProviderError> {
        dispatch_download(
            &workspace(workspace_root),
            &DenyBroker,
            &request("browser.download", "preview", arguments),
            &public_resolver(),
            profile_root,
        )
    }

    #[test]
    fn download_preview_allocates_one_shot_source_without_approval_or_write() {
        use orcel_approval::test_support::FixedApprovalBroker;
        use orcel_approval::ApprovalDecision;
        let root = temp_root("dl-preview");
        let profile_root = profile_dir("dl-preview");
        let page_id = active_page_id(&root, &profile_root);
        let preview = preview_download(
            &root,
            &profile_root,
            preview_arguments(&page_id, "notes.txt", "notes.txt", 5),
        )
        .expect("preview")
        .expect("handled");
        assert!(preview["source_id"]
            .as_str()
            .is_some_and(|value| value.starts_with("dl-")));
        assert_eq!(preview["canonical_relative_destination"], "notes.txt");
        assert_eq!(preview["declared_media_type"], "text/plain");
        assert_eq!(preview["source_origin"], "https://example.com:443");
        assert!(preview["destination_root_identity"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        assert!(
            preview["expires_at_ms"].as_u64().expect("expiry")
                > preview["issued_at_ms"].as_u64().expect("issued")
        );
        assert_eq!(preview["executed"], false);
        assert_eq!(preview["opened"], false);
        assert_eq!(preview["extracted"], false);
        assert_eq!(preview["cookies"], false);
        assert_eq!(preview["credentials"], false);
        assert!(preview.get("source_url").is_none());
        assert!(
            !std::path::Path::new(&root).join("notes.txt").exists(),
            "preview must never write a file"
        );
        assert!(dispatch_download(
            &workspace(&root),
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request("browser.profile", "status", json!({})),
            &public_resolver(),
            &profile_root,
        )
        .expect("dispatch returns")
        .is_none());
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }

    #[test]
    fn download_requires_approval_and_creates_exactly_one_new_file() {
        use orcel_approval::test_support::FixedApprovalBroker;
        use orcel_approval::ApprovalDecision;
        let root = temp_root("dl-approve");
        let profile_root = profile_dir("dl-approve");
        let page_id = active_page_id(&root, &profile_root);
        let workspace = workspace(&root);

        let preview = preview_download(
            &root,
            &profile_root,
            preview_arguments(&page_id, "notes.txt", "notes.txt", 5),
        )
        .expect("preview")
        .expect("handled");
        let source_id = preview["source_id"].as_str().expect("source").to_owned();

        let denied = dispatch_download(
            &workspace,
            &DenyBroker,
            &request(
                "browser.download",
                "download",
                body_arguments(&page_id, &source_id, "aGVsbG8="),
            ),
            &public_resolver(),
            &profile_root,
        )
        .expect_err("download without approval must fail closed");
        assert_eq!(denied.code, FailureCode::ApprovalDenied);
        assert!(!std::path::Path::new(&root).join("notes.txt").exists());

        let evidence = dispatch_download(
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request(
                "browser.download",
                "download",
                body_arguments(&page_id, &source_id, "aGVsbG8="),
            ),
            &public_resolver(),
            &profile_root,
        )
        .expect("download")
        .expect("handled");
        assert!(evidence["download_id"]
            .as_str()
            .is_some_and(|value| value.starts_with("dn-")));
        assert_eq!(evidence["canonical_relative_destination"], "notes.txt");
        assert_eq!(evidence["declared_size_bytes"], 5);
        assert_eq!(evidence["actual_size_bytes"], 5);
        assert_eq!(evidence["sniffed_media_type"], "text/plain");
        assert_eq!(evidence["extension_media_type"], "text/plain");
        assert_eq!(evidence["content_type_consistent"], true);
        assert_eq!(evidence["state"], "consumed");
        assert_eq!(evidence["executed"], false);
        assert_eq!(evidence["opened"], false);
        assert_eq!(evidence["extracted"], false);
        assert_eq!(evidence["cookies"], false);
        assert_eq!(evidence["credentials"], false);
        assert!(evidence.get("approval_record_id").is_some());
        assert!(evidence.get("content_base64").is_none());
        let written = std::path::Path::new(&root).join("notes.txt");
        assert_eq!(std::fs::read(&written).expect("read"), &b"hello"[..]);

        let replay = dispatch_download(
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request(
                "browser.download",
                "download",
                body_arguments(&page_id, &source_id, "aGVsbG8="),
            ),
            &public_resolver(),
            &profile_root,
        )
        .expect_err("a consumed source must never authorize a second download");
        assert_eq!(replay.code, FailureCode::CapabilityDenied);
        assert_eq!(std::fs::read(&written).expect("read"), &b"hello"[..]);

        let existing = preview_download(
            &root,
            &profile_root,
            preview_arguments(&page_id, "notes.txt", "notes.txt", 5),
        )
        .expect_err("preview must refuse a destination that already exists");
        assert_eq!(existing.code, FailureCode::PostconditionFailed);
        assert_eq!(
            std::fs::read(&written).expect("read"),
            &b"hello"[..],
            "an approved download must never overwrite an existing file"
        );

        // A file that appears between preview and download must also fail
        // closed: create-only is enforced at write time, not only at preview.
        let racing = preview_download(
            &root,
            &profile_root,
            preview_arguments(&page_id, "racing.txt", "racing.txt", 5),
        )
        .expect("preview")
        .expect("handled");
        let racing_source = racing["source_id"].as_str().expect("source").to_owned();
        let seeded = std::path::Path::new(&root).join("racing.txt");
        std::fs::write(&seeded, b"taken").expect("seed");
        let race = dispatch_download(
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request(
                "browser.download",
                "download",
                body_arguments(&page_id, &racing_source, "aGVsbG8="),
            ),
            &public_resolver(),
            &profile_root,
        )
        .expect_err("an existing destination must fail closed");
        assert_eq!(race.code, FailureCode::PostconditionFailed);
        assert_eq!(
            std::fs::read(&seeded).expect("read"),
            &b"taken"[..],
            "an approved download must never overwrite a seeded file"
        );
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }

    #[test]
    fn download_denies_destination_type_origin_and_redirect_drift() {
        let root = temp_root("dl-dest");
        let profile_root = profile_dir("dl-dest");
        let page_id = active_page_id(&root, &profile_root);

        for (arguments, code) in [
            (
                preview_arguments(&page_id, "C:\\Windows\\notes.txt", "notes.txt", 5),
                FailureCode::PathEscape,
            ),
            (
                preview_arguments(&page_id, "../escape.txt", "notes.txt", 5),
                FailureCode::PathEscape,
            ),
            (
                preview_arguments(&page_id, "notes.txt:hidden", "notes.txt", 5),
                FailureCode::PathEscape,
            ),
            (
                preview_arguments(&page_id, "CON.txt", "CON.txt", 5),
                FailureCode::PathEscape,
            ),
            (
                preview_arguments(&page_id, "tool.exe", "tool.exe", 5),
                FailureCode::CapabilityDenied,
            ),
            (
                preview_arguments(&page_id, "archive.zip", "archive.zip", 5),
                FailureCode::CapabilityDenied,
            ),
            (
                preview_arguments(&page_id, "notes.txt", "other.txt", 5),
                FailureCode::InvalidRequest,
            ),
        ] {
            let error = preview_download(&root, &profile_root, arguments)
                .expect_err("destination policy must fail closed");
            assert_eq!(error.code, code);
        }

        let mut widening = preview_arguments(&page_id, "notes.txt", "notes.txt", 5);
        widening
            .as_object_mut()
            .expect("object")
            .insert("destination_root".to_owned(), json!("C:\\other"));
        assert_eq!(
            preview_download(&root, &profile_root, widening)
                .expect_err("caller-selected destinations must fail closed")
                .code,
            FailureCode::CapabilityDenied
        );

        let mut foreign_origin = preview_arguments(&page_id, "notes.txt", "notes.txt", 5);
        foreign_origin.as_object_mut().expect("object").insert(
            "source_url".to_owned(),
            json!("https://evil.example.com/files/notes.txt"),
        );
        assert_eq!(
            preview_download(&root, &profile_root, foreign_origin)
                .expect_err("an unauthorized download origin must fail closed")
                .code,
            FailureCode::CapabilityDenied
        );

        let mut widened = preview_arguments(&page_id, "notes.txt", "notes.txt", 5);
        widened.as_object_mut().expect("object").insert(
            "redirect_chain".to_owned(),
            json!(["https://evil.example.com/files/notes.txt"]),
        );
        assert_eq!(
            preview_download(&root, &profile_root, widened)
                .expect_err("redirect widening must fail closed")
                .code,
            FailureCode::CapabilityDenied
        );

        let mut ssrf = preview_arguments(&page_id, "notes.txt", "notes.txt", 5);
        ssrf.as_object_mut().expect("object").insert(
            "source_url".to_owned(),
            json!("https://localhost/notes.txt"),
        );
        assert!(preview_download(&root, &profile_root, ssrf).is_err());

        let mut stale = preview_arguments(&page_id, "notes.txt", "notes.txt", 5);
        stale
            .as_object_mut()
            .expect("object")
            .insert("expected_generation".to_owned(), json!(9));
        assert_eq!(
            preview_download(&root, &profile_root, stale)
                .expect_err("generation drift must fail closed")
                .code,
            FailureCode::TargetStale
        );

        let mut wrong_origin = preview_arguments(&page_id, "notes.txt", "notes.txt", 5);
        wrong_origin.as_object_mut().expect("object").insert(
            "expected_origin".to_owned(),
            json!("https://other.example:443"),
        );
        assert_eq!(
            preview_download(&root, &profile_root, wrong_origin)
                .expect_err("origin drift must fail closed")
                .code,
            FailureCode::TargetStale
        );
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }

    #[test]
    fn download_denies_unknown_source_size_and_content_drift() {
        use orcel_approval::test_support::FixedApprovalBroker;
        use orcel_approval::ApprovalDecision;
        let root = temp_root("dl-body");
        let profile_root = profile_dir("dl-body");
        let page_id = active_page_id(&root, &profile_root);
        let workspace = workspace(&root);
        let broker = FixedApprovalBroker(ApprovalDecision::Approved);

        assert_eq!(
            dispatch_download(
                &workspace,
                &broker,
                &request(
                    "browser.download",
                    "download",
                    body_arguments(&page_id, "dl-unknown", "aGVsbG8="),
                ),
                &public_resolver(),
                &profile_root,
            )
            .expect_err("an unknown source identity must fail closed")
            .code,
            FailureCode::TargetStale
        );

        let fresh = |name: &str, size: u64| {
            let preview = preview_download(
                &root,
                &profile_root,
                preview_arguments(&page_id, name, name, size),
            )
            .expect("preview")
            .expect("handled");
            preview["source_id"].as_str().expect("source").to_owned()
        };

        let size_source = fresh("size.txt", 5);
        assert_eq!(
            dispatch_download(
                &workspace,
                &broker,
                &request(
                    "browser.download",
                    "download",
                    body_arguments(&page_id, &size_source, "aGVsbG8h"),
                ),
                &public_resolver(),
                &profile_root,
            )
            .expect_err("declared and actual size disagreement must fail closed")
            .code,
            FailureCode::PostconditionFailed
        );

        let executable_source = fresh("payload.txt", 2);
        assert_eq!(
            dispatch_download(
                &workspace,
                &broker,
                &request(
                    "browser.download",
                    "download",
                    body_arguments(&page_id, &executable_source, "TVo="),
                ),
                &public_resolver(),
                &profile_root,
            )
            .expect_err("an executable payload must fail closed")
            .code,
            FailureCode::CapabilityDenied
        );

        let script_source = fresh("launcher.txt", 10);
        assert_eq!(
            dispatch_download(
                &workspace,
                &broker,
                &request(
                    "browser.download",
                    "download",
                    body_arguments(&page_id, &script_source, "IyEvYmluL3NoCg=="),
                ),
                &public_resolver(),
                &profile_root,
            )
            .expect_err("a script payload must fail closed")
            .code,
            FailureCode::CapabilityDenied
        );

        let image_source = fresh("picture.txt", 8);
        assert_eq!(
            dispatch_download(
                &workspace,
                &broker,
                &request(
                    "browser.download",
                    "download",
                    body_arguments(&page_id, &image_source, "iVBORw0KGgo="),
                ),
                &public_resolver(),
                &profile_root,
            )
            .expect_err("content that contradicts the declared type must fail closed")
            .code,
            FailureCode::CapabilityDenied
        );
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }
    fn upload_file_node_id(
        root: &std::path::Path,
        profile_root: &std::path::Path,
    ) -> (String, String) {
        let page_id = active_page_id(root, profile_root);
        let snapshot = dispatch_observation(
            &workspace(root),
            &request(
                "browser.snapshot",
                "observe",
                json!({
                    "page_id": page_id,
                    "expected_origin": "https://example.com:443",
                    "expected_generation": 1,
                }),
            ),
            profile_root,
        )
        .expect("observe")
        .expect("handled");
        let nodes = snapshot["nodes"].as_array().expect("nodes");
        let node = nodes
            .iter()
            .find(|node| node["input_type"] == "file")
            .expect("a typed file-input node must be observable");
        (
            page_id,
            node["node_id"].as_str().expect("node id").to_owned(),
        )
    }

    fn seed_upload_artifact(
        root: &std::path::Path,
        profile_root: &std::path::Path,
        name: &str,
        body: &str,
    ) -> String {
        std::fs::write(root.join(name), body).expect("artifact");
        let bytes = body.as_bytes();
        let digest = orcel_provider_browser::sha256_hex(bytes);
        // A well formed ORCEL_BROWSER_DOWNLOAD_SOURCE_V1 identity, so the strict
        // shape validator accepts it exactly as it accepts a real one.
        let source_id = format!("dl-{}", orcel_provider_browser::sha256_hex(name.as_bytes()));
        let mut store = orcel_provider_browser::DownloadStore::load_or_create(
            orcel_provider_browser::default_download_registry_path(profile_root),
        );
        store.record_pending(orcel_provider_browser::StoredDownload {
            schema: orcel_provider_browser::DOWNLOAD_REGISTRY_SCHEMA.to_owned(),
            source_id: source_id.clone(),
            workspace_id: "default".into(),
            policy_revision: POLICY_REVISION.to_owned(),
            profile_identity: orcel_provider_browser::profile_identity_for_root(profile_root),
            page_id: "pg-seed".into(),
            origin: "https://example.com:443".into(),
            page_generation: 1,
            document_generation: 1,
            source_origin: "https://example.com:443".into(),
            source_url_digest: "digest".into(),
            canonical_relative_destination: name.to_owned(),
            declared_filename: name.to_owned(),
            declared_media_type: "text/plain".into(),
            declared_size_bytes: bytes.len() as u64,
            download_policy_revision: orcel_provider_browser::DOWNLOAD_POLICY_REVISION.to_owned(),
            issued_at_ms: 1_000,
            expires_at_ms: 1_000 + orcel_provider_browser::DOWNLOAD_SOURCE_TTL_MS,
            state: orcel_provider_browser::DOWNLOAD_SOURCE_CONSUMED.to_owned(),
            download_id: "dn-seed".into(),
            content_sha256: digest,
        });
        source_id
    }

    fn upload_preview_arguments(
        page_id: &str,
        node_id: &str,
        trust_revision: u64,
        artifact_source_id: &str,
    ) -> Value {
        json!({
            "page_id": page_id,
            "expected_origin": "https://example.com:443",
            "expected_generation": 1,
            "expected_document_generation": 1,
            "node_id": node_id,
            "expected_role": "textbox",
            "expected_input_type": "file",
            "expected_state": "enabled",
            "expected_trust_revision": trust_revision,
            "artifact_source_id": artifact_source_id,
        })
    }

    fn upload_body_arguments(page_id: &str, source_id: &str) -> Value {
        json!({
            "page_id": page_id,
            "expected_origin": "https://example.com:443",
            "expected_generation": 1,
            "expected_document_generation": 1,
            "source_id": source_id,
        })
    }

    fn preview_upload_request(
        root: &std::path::Path,
        profile_root: &std::path::Path,
        arguments: Value,
        trust_trusted: bool,
        trust_revision: u64,
    ) -> Result<Option<Value>, ProviderError> {
        dispatch_upload(
            &workspace(root),
            &DenyBroker,
            &request("browser.upload", "preview", arguments),
            trust_trusted,
            trust_revision,
            profile_root,
        )
    }

    #[test]
    fn upload_preview_binds_a_file_input_to_a_recorded_download_artifact() {
        let root = temp_root("dl-upload-preview");
        let profile_root = profile_dir("dl-upload-preview");
        let (page_id, node_id) = upload_file_node_id(&root, &profile_root);
        let artifact = seed_upload_artifact(&root, &profile_root, "artifact.txt", "hello");
        let preview = preview_upload_request(
            &root,
            &profile_root,
            upload_preview_arguments(&page_id, &node_id, 1, &artifact),
            true,
            1,
        )
        .expect("preview")
        .expect("handled");
        assert!(preview["source_id"]
            .as_str()
            .is_some_and(|value| value.starts_with("ul-")));
        assert_eq!(preview["node_input_type"], "file");
        assert_eq!(preview["node_role"], "textbox");
        assert_eq!(preview["node_state"], "enabled");
        assert_eq!(preview["trust_revision"], 1);
        assert_eq!(preview["artifact_source_id"], artifact);
        assert_eq!(preview["artifact_relative_destination"], "artifact.txt");
        assert_eq!(preview["artifact_media_type"], "text/plain");
        assert_eq!(preview["artifact_size_bytes"], 5);
        assert_eq!(preview["page_transfer_performed"], false);
        assert_eq!(preview["executed"], false);
        assert_eq!(preview["cookies"], false);
        assert_eq!(preview["credentials"], false);
        for forbidden in [
            "content",
            "bytes",
            "data",
            "path",
            "source_path",
            "file_path",
            "absolute_path",
        ] {
            assert!(
                preview.get(forbidden).is_none(),
                "upload preview must not carry {forbidden}"
            );
        }
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }

    #[test]
    fn upload_requires_approval_is_one_shot_and_never_reads_any_other_file() {
        use orcel_approval::test_support::FixedApprovalBroker;
        use orcel_approval::ApprovalDecision;
        let root = temp_root("dl-upload-submit");
        let profile_root = profile_dir("dl-upload-submit");
        let (page_id, node_id) = upload_file_node_id(&root, &profile_root);
        let artifact = seed_upload_artifact(&root, &profile_root, "artifact.txt", "hello");
        // A credential-shaped file that is not a recorded download artifact
        // must be unreachable as an upload source.
        std::fs::write(root.join("id_rsa"), "PRIVATE KEY").expect("secret");
        let workspace = workspace(&root);

        let preview = preview_upload_request(
            &root,
            &profile_root,
            upload_preview_arguments(&page_id, &node_id, 1, &artifact),
            true,
            1,
        )
        .expect("preview")
        .expect("handled");
        let source_id = preview["source_id"].as_str().expect("source").to_owned();

        let denied = dispatch_upload(
            &workspace,
            &DenyBroker,
            &request(
                "browser.upload",
                "submit",
                upload_body_arguments(&page_id, &source_id),
            ),
            true,
            1,
            &profile_root,
        )
        .expect_err("upload without approval must fail closed");
        assert_eq!(denied.code, FailureCode::ApprovalDenied);

        let evidence = dispatch_upload(
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request(
                "browser.upload",
                "submit",
                upload_body_arguments(&page_id, &source_id),
            ),
            true,
            1,
            &profile_root,
        )
        .expect("submit")
        .expect("handled");
        assert!(evidence["upload_id"]
            .as_str()
            .is_some_and(|value| value.starts_with("up-")));
        assert_eq!(evidence["artifact_source_id"], artifact);
        assert_eq!(evidence["artifact_relative_destination"], "artifact.txt");
        assert_eq!(evidence["artifact_size_bytes"], 5);
        assert_eq!(evidence["node_input_type"], "file");
        assert_eq!(evidence["state"], "consumed");
        assert_eq!(evidence["page_transfer_performed"], false);
        assert_eq!(evidence["executed"], false);
        assert!(evidence.get("approval_record_id").is_some());

        let replay = dispatch_upload(
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &request(
                "browser.upload",
                "submit",
                upload_body_arguments(&page_id, &source_id),
            ),
            true,
            1,
            &profile_root,
        )
        .expect_err("a consumed upload source must fail closed");
        assert_eq!(replay.code, FailureCode::CapabilityDenied);

        // The unrelated credential-shaped file was never read or touched.
        assert_eq!(
            std::fs::read(root.join("id_rsa")).expect("read"),
            &b"PRIVATE KEY"[..]
        );
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }

    #[test]
    fn upload_denies_untrusted_workspace_trust_drift_and_unrecorded_source() {
        let root = temp_root("dl-upload-deny");
        let profile_root = profile_dir("dl-upload-deny");
        let (page_id, node_id) = upload_file_node_id(&root, &profile_root);
        let artifact = seed_upload_artifact(&root, &profile_root, "artifact.txt", "hello");

        // An untrusted workspace, exactly as an emergency revoke leaves it.
        assert_eq!(
            preview_upload_request(
                &root,
                &profile_root,
                upload_preview_arguments(&page_id, &node_id, 1, &artifact),
                false,
                1
            )
            .expect_err("an emergency revoke must fail closed")
            .code,
            FailureCode::WorkspaceDenied
        );

        // A trust revision change between the caller's view and the dispatch.
        assert_eq!(
            preview_upload_request(
                &root,
                &profile_root,
                upload_preview_arguments(&page_id, &node_id, 1, &artifact),
                true,
                2
            )
            .expect_err("a trust revision change must fail closed")
            .code,
            FailureCode::TargetStale
        );

        // A source that was never recorded by a completed SG-000025 download.
        // The identity is well formed, so the failure comes from the registry
        // miss rather than from request shape.
        let unregistered = format!("dl-{}", "0".repeat(64));
        let error = preview_upload_request(
            &root,
            &profile_root,
            upload_preview_arguments(&page_id, &node_id, 1, &unregistered),
            true,
            1,
        )
        .expect_err("an unrecorded source must fail closed");
        assert_eq!(error.code, FailureCode::TargetStale);

        // A malformed source identity never reaches the registry at all.
        for malformed in ["not-a-source", "", "../../id_rsa", "dl-zz"] {
            let error = preview_upload_request(
                &root,
                &profile_root,
                upload_preview_arguments(&page_id, &node_id, 1, malformed),
                true,
                1,
            )
            .expect_err("a malformed source identity must fail closed");
            assert_eq!(
                error.code,
                FailureCode::InvalidRequest,
                "malformed source {malformed:?} must be an invalid request, not {:?}",
                error.code
            );
        }
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }

    #[test]
    fn upload_denies_unauthorized_targets_and_every_widening_field() {
        let root = temp_root("dl-upload-widen");
        let profile_root = profile_dir("dl-upload-widen");
        let (page_id, node_id) = upload_file_node_id(&root, &profile_root);
        let artifact = seed_upload_artifact(&root, &profile_root, "artifact.txt", "hello");

        for (role, input_type, state) in [
            ("link", "file", "enabled"),
            ("textbox", "text", "enabled"),
            ("textbox", "password", "enabled"),
            ("textbox", "file", "disabled"),
        ] {
            let mut arguments = upload_preview_arguments(&page_id, &node_id, 1, &artifact);
            arguments
                .as_object_mut()
                .expect("object")
                .insert("expected_role".to_owned(), json!(role));
            arguments
                .as_object_mut()
                .expect("object")
                .insert("expected_input_type".to_owned(), json!(input_type));
            arguments
                .as_object_mut()
                .expect("object")
                .insert("expected_state".to_owned(), json!(state));
            let error = preview_upload_request(&root, &profile_root, arguments, true, 1)
                .expect_err("an unauthorized upload target must fail closed");
            assert_eq!(error.code, FailureCode::CapabilityDenied);
        }

        for field in [
            "path",
            "file",
            "files",
            "source_path",
            "relative_path",
            "absolute_path",
            "directory",
            "content",
            "bytes",
            "read",
            "recursive",
            "submit_form",
            "transfer",
        ] {
            let mut arguments = upload_preview_arguments(&page_id, &node_id, 1, &artifact);
            arguments
                .as_object_mut()
                .expect("object")
                .insert(field.to_owned(), json!("x"));
            let error = preview_upload_request(&root, &profile_root, arguments, true, 1)
                .expect_err("a widening field must fail closed");
            assert_eq!(
                error.code,
                FailureCode::CapabilityDenied,
                "widening field {field} must fail closed"
            );
        }
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }

    #[test]
    fn upload_denies_stale_page_drift_and_unknown_upload_shapes() {
        let root = temp_root("dl-upload-stale");
        let profile_root = profile_dir("dl-upload-stale");
        let (page_id, node_id) = upload_file_node_id(&root, &profile_root);
        let artifact = seed_upload_artifact(&root, &profile_root, "artifact.txt", "hello");
        let mut stale = upload_preview_arguments(&page_id, &node_id, 1, &artifact);
        stale
            .as_object_mut()
            .expect("object")
            .insert("expected_generation".to_owned(), json!(9));
        assert_eq!(
            preview_upload_request(&root, &profile_root, stale, true, 1)
                .expect_err("generation drift must fail closed")
                .code,
            FailureCode::TargetStale
        );
        let mut wrong_origin = upload_preview_arguments(&page_id, &node_id, 1, &artifact);
        wrong_origin.as_object_mut().expect("object").insert(
            "expected_origin".to_owned(),
            json!("https://other.example:443"),
        );
        assert_eq!(
            preview_upload_request(&root, &profile_root, wrong_origin, true, 1)
                .expect_err("origin drift must fail closed")
                .code,
            FailureCode::TargetStale
        );

        let workspace = workspace(&root);
        for (capability, operation) in [
            ("browser.upload", "upload"),
            ("browser.upload", "directory"),
            ("browser.upload", "multiple"),
            ("browser.upload", "execute"),
            ("browser.upload", "open"),
            ("browser.upload", "extract"),
            ("browser.file", "read"),
            ("browser.fs", "read"),
            ("browser.directory", "upload"),
        ] {
            assert!(
                dispatch_upload(
                    &workspace,
                    &DenyBroker,
                    &request(capability, operation, json!({})),
                    true,
                    1,
                    &profile_root,
                )
                .expect("dispatch returns")
                .is_none(),
                "{capability}/{operation} must be unhandled by the upload dispatch"
            );
        }
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }

    #[test]
    fn upload_denies_mutated_and_removed_artifacts() {
        use orcel_approval::test_support::FixedApprovalBroker;
        use orcel_approval::ApprovalDecision;
        let root = temp_root("dl-upload-mutate");
        let profile_root = profile_dir("dl-upload-mutate");
        let (page_id, node_id) = upload_file_node_id(&root, &profile_root);
        let artifact = seed_upload_artifact(&root, &profile_root, "artifact.txt", "hello");
        let workspace = workspace(&root);
        let broker = FixedApprovalBroker(ApprovalDecision::Approved);

        let preview = preview_upload_request(
            &root,
            &profile_root,
            upload_preview_arguments(&page_id, &node_id, 1, &artifact),
            true,
            1,
        )
        .expect("preview")
        .expect("handled");
        let source_id = preview["source_id"].as_str().expect("source").to_owned();

        std::fs::write(root.join("artifact.txt"), "mutated").expect("mutate");
        let mutated = dispatch_upload(
            &workspace,
            &broker,
            &request(
                "browser.upload",
                "submit",
                upload_body_arguments(&page_id, &source_id),
            ),
            true,
            1,
            &profile_root,
        )
        .expect_err("a mutated artifact must fail closed");
        assert_eq!(mutated.code, FailureCode::PostconditionFailed);

        std::fs::remove_file(root.join("artifact.txt")).expect("remove");
        let removed = dispatch_upload(
            &workspace,
            &broker,
            &request(
                "browser.upload",
                "submit",
                upload_body_arguments(&page_id, &source_id),
            ),
            true,
            1,
            &profile_root,
        )
        .expect_err("a removed artifact must fail closed");
        assert_eq!(removed.code, FailureCode::TargetStale);
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(profile_root);
    }
}
