//! SG-000037 human-interruption invalidation dispatch.
//!
//! This module dispatches the five retained SG-000027 observation shapes,
//! the retained SG-000028 `uia.element/invoke` shape, the retained
//! SG-000029 `uia.element/set_value` shape, the retained SG-000030
//! `uia.element/select` shape, the retained SG-000031 `uia.element/toggle`
//! shape, the retained SG-000032 `uia.element/scroll` shape, the retained
//! SG-000033 `uia.screenshot/capture` shape, the retained SG-000034
//! `uia.visual/propose` shape, the retained SG-000035
//! `uia.coordinates/propose` shape, plus the single SG-000036 bounded
//! execution shape `uia.input/execute` against a process-lifetime typed
//! identity registry backed by the native adapter. Observation remains
//! read-only with no approval. Invoke, set_value, select, toggle,
//! scroll, capture, propose, coordinate derivation, and bounded
//! execution each require fresh per-action SOFT approval with exact
//! digest binding and immediate pre-action stale-target revalidation.
//! Execution is click-only, confined to the exact owning window, gated
//! by an explicit single-use input lease that is consumed exactly once,
//! and bound to the SG-000037 monotonic human-interruption epoch: any
//! material human interaction after the lease grant revokes the lease,
//! the pre-interruption approval digest fails closed, interrupted actions
//! are never replayed, and a retry needs a fresh lease and fresh
//! approval. The interruption report path is reachable only through the
//! local session broker, never through MCP requests, and Orcel synthetic
//! execution never counts as human interruption. Every other UIA-like
//! shape returns `Ok(None)` so the caller fails closed through the
//! STRONG gate or the legacy denial.
//!
//! Identities are process-lifetime: a orceld restart drops the registry,
//! so pre-restart identities fail closed as unknown rather than retargeting.

use orcel_approval::{ApprovalBroker, ApprovalPrompt, ConsumeExpectation};
use orcel_contracts::{FailureCode, RequestEnvelope};
use orcel_policy::{full_control_store, Workspace, POLICY_REVISION};
use orcel_provider_fs::ProviderError;
use orcel_provider_uia::{
    capture_approval_digest, coordinate_derivation_digest, execute_approval_digest,
    invoke_approval_digest, scroll_approval_digest, select_approval_digest, toggle_approval_digest,
    value_approval_digest, visual_proposal_digest, ComputerHostAdapter, DesktopInputAction,
    DesktopWindowAction, NativeAdapter, UiaRegistry, VisualRegion, CAPTURE_SCOPE_TARGET_WINDOW,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Mutex, OnceLock};

fn registry() -> &'static Mutex<UiaRegistry> {
    static REGISTRY: OnceLock<Mutex<UiaRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(UiaRegistry::new()))
}

fn locked_registry() -> Result<std::sync::MutexGuard<'static, UiaRegistry>, ProviderError> {
    registry()
        .lock()
        .map_err(|_| ProviderError::new(FailureCode::InternalError, "uia registry is unavailable"))
}

/// Whether observation goes through the private computer host. On every OS
/// the host is selected by ORCEL_COMPUTER_HOST_BIN; unset, the fail-closed
/// NativeAdapter answers instead (rollback for XP-06 is unsetting it).
fn computer_host_selected() -> bool {
    std::env::var_os("ORCEL_COMPUTER_HOST_BIN").is_some()
}

/// XP-06: off Windows ORCEL_COMPUTER_HOST_BIN must name the pinned
/// `orcel-native-host`: an absolute canonical path next to orceld or at
/// `/usr/libexec/orcel/orcel-native-host`, owned by root or this user and
/// writable by nobody else, in directories nobody else can write
/// (`orcel_provider_uia::trusted_native_host_path`, the XP-10 rule). Any
/// other binary is refused before it is started. Whatever the host then
/// advertises, the kernel accepts only observation from it until XP-11.
#[cfg(not(windows))]
fn trusted_native_host(
    configured: Option<std::ffi::OsString>,
) -> Result<orcel_provider_uia::TrustedHostBinary, ProviderError> {
    let configured = configured.ok_or_else(|| {
        ProviderError::new(
            FailureCode::ProviderUnavailable,
            "ORCEL_COMPUTER_HOST_BIN is not configured",
        )
    })?;
    let orceld_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| std::fs::canonicalize(exe).ok())
        .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf));
    orcel_provider_uia::trusted_native_host_path(
        std::path::Path::new(&configured),
        orceld_dir.as_deref(),
    )
    .map_err(|error| ProviderError::new(error.code, error.message))
}

fn computer_host() -> Result<&'static ComputerHostAdapter, ProviderError> {
    static HOST: OnceLock<ComputerHostAdapter> = OnceLock::new();
    if let Some(host) = HOST.get() {
        return Ok(host);
    }
    #[cfg(not(windows))]
    let host = ComputerHostAdapter::from_trusted(&trusted_native_host(std::env::var_os(
        "ORCEL_COMPUTER_HOST_BIN",
    ))?)
    .map_err(|error| ProviderError::new(error.code, error.message))?;
    #[cfg(windows)]
    let host = ComputerHostAdapter::from_env()
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let _ = HOST.set(host);
    HOST.get().ok_or_else(|| {
        ProviderError::new(
            FailureCode::ProviderUnavailable,
            "computer host could not be retained",
        )
    })
}

/// XP-11: clears the approval `arm_semantic` armed, whatever the registry
/// call did. The adapter spends it when an action reaches it; this covers a
/// call that failed before that.
fn disarm_semantic(adapter: &ComputerHostAdapter) {
    adapter.disarm_semantic();
}

/// XP-11: on a macOS or Linux host the adapter delivers a semantic action only
/// while the approval just consumed is armed on the exact target. The
/// identity comes from the registry's server-resolved binding, never from the
/// request. A Windows host is unchanged and is not armed.
#[cfg(not(windows))]
fn arm_semantic(
    adapter: &ComputerHostAdapter,
    hwnd: u64,
    runtime_id: &str,
    verb: &str,
    value_digest: Option<&str>,
) -> Result<(), ProviderError> {
    adapter
        .authorize_semantic(orcel_provider_uia::ApprovedSemantic {
            hwnd,
            runtime_id: runtime_id.to_owned(),
            verb: verb.to_owned(),
            value_digest: value_digest.map(str::to_owned),
        })
        .map_err(|error| ProviderError::new(error.code, error.message))
}

#[cfg(windows)]
fn arm_semantic(
    _adapter: &ComputerHostAdapter,
    _hwnd: u64,
    _runtime_id: &str,
    _verb: &str,
    _value_digest: Option<&str>,
) -> Result<(), ProviderError> {
    Ok(())
}

fn require_full_user_desktop() -> Result<(), ProviderError> {
    full_control_store::check_current_desktop_input()
        .map(|_| ())
        .map_err(|error| ProviderError::new(error.code, error.message))
}

pub fn is_full_user_desktop_shape(capability: &str, operation: &str) -> bool {
    orcel_policy::is_full_user_desktop_shape(capability, operation)
        || orcel_provider_uia::is_invoke_shape(capability, operation)
        || orcel_provider_uia::is_value_shape(capability, operation)
        || orcel_provider_uia::is_select_shape(capability, operation)
        || orcel_provider_uia::is_toggle_shape(capability, operation)
        || orcel_provider_uia::is_scroll_shape(capability, operation)
        || orcel_provider_uia::is_capture_shape(capability, operation)
        || orcel_provider_uia::is_visual_propose_shape(capability, operation)
        || orcel_provider_uia::is_coordinate_propose_shape(capability, operation)
        || orcel_provider_uia::is_input_execute_shape(capability, operation)
}

fn desktop_request_digest(workspace: &Workspace, request: &RequestEnvelope) -> String {
    let material = format!(
        "orcel-sg95-full-user-v1|{}|{}|{}|{}|{}",
        workspace.id, POLICY_REVISION, request.capability, request.operation, request.arguments
    );
    let digest = Sha256::digest(material.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn full_user_cursor(request: &RequestEnvelope) -> Result<Value, ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "desktop cursor does not accept a target field",
        ));
    }
    reject_uia_arguments(request, &[])?;
    require_full_user_desktop()?;
    let cursor = computer_host()?
        .cursor_position()
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    Ok(json!({
        "schema": "orcel-desktop-cursor/1",
        "x": cursor.x,
        "y": cursor.y,
        "screen_width": cursor.screen_width,
        "screen_height": cursor.screen_height,
        "state": "completed",
        "policy_revision": POLICY_REVISION
    }))
}

fn desktop_input_action(
    request: &RequestEnvelope,
    action: &str,
) -> Result<DesktopInputAction, ProviderError> {
    match action {
        "move" => {
            reject_uia_arguments(
                request,
                &[
                    "window_id",
                    "expected_window_generation",
                    "action",
                    "x",
                    "y",
                ],
            )?;
            Ok(DesktopInputAction::Move {
                x: required_i32(request, "x")?,
                y: required_i32(request, "y")?,
            })
        }
        "click" | "double_click" | "right_click" => {
            reject_uia_arguments(
                request,
                &[
                    "window_id",
                    "expected_window_generation",
                    "action",
                    "x",
                    "y",
                ],
            )?;
            Ok(DesktopInputAction::Click {
                x: required_i32(request, "x")?,
                y: required_i32(request, "y")?,
                button: if action == "right_click" {
                    "right"
                } else {
                    "left"
                }
                .into(),
                count: if action == "double_click" { 2 } else { 1 },
            })
        }
        "drag" => {
            reject_uia_arguments(
                request,
                &[
                    "window_id",
                    "expected_window_generation",
                    "action",
                    "x",
                    "y",
                    "to_x",
                    "to_y",
                ],
            )?;
            Ok(DesktopInputAction::Drag {
                x: required_i32(request, "x")?,
                y: required_i32(request, "y")?,
                to_x: required_i32(request, "to_x")?,
                to_y: required_i32(request, "to_y")?,
            })
        }
        "scroll" => {
            reject_uia_arguments(
                request,
                &[
                    "window_id",
                    "expected_window_generation",
                    "action",
                    "x",
                    "y",
                    "scroll_x",
                    "scroll_y",
                ],
            )?;
            let scroll_x = required_i32_signed(request, "scroll_x")?;
            let scroll_y = required_i32_signed(request, "scroll_y")?;
            if scroll_x == 0 && scroll_y == 0 {
                return Err(ProviderError::new(
                    FailureCode::InvalidRequest,
                    "desktop scroll requires a non-zero bounded direction",
                ));
            }
            if !(-20..=20).contains(&scroll_x) || !(-20..=20).contains(&scroll_y) {
                return Err(ProviderError::new(
                    FailureCode::InvalidRequest,
                    "desktop scroll ticks must stay between -20 and 20",
                ));
            }
            Ok(DesktopInputAction::Scroll {
                x: required_i32(request, "x")?,
                y: required_i32(request, "y")?,
                scroll_x,
                scroll_y,
            })
        }
        "type_text" => {
            reject_uia_arguments(
                request,
                &["window_id", "expected_window_generation", "action", "text"],
            )?;
            let text = required_string(request, "text")?;
            if text.is_empty() || text.len() > 4096 || text.contains('\0') {
                return Err(ProviderError::new(
                    FailureCode::InvalidRequest,
                    "desktop text must be non-empty valid text of at most 4096 UTF-8 bytes",
                ));
            }
            Ok(DesktopInputAction::TypeText { text })
        }
        "key" | "hotkey" => {
            reject_uia_arguments(
                request,
                &["window_id", "expected_window_generation", "action", "key"],
            )?;
            let key = required_string(request, "key")?;
            if key.is_empty() || key.len() > 64 {
                return Err(ProviderError::new(
                    FailureCode::InvalidRequest,
                    "desktop key binding is empty or too large",
                ));
            }
            if action == "hotkey" {
                Ok(DesktopInputAction::Hotkey { key })
            } else {
                Ok(DesktopInputAction::Key { key })
            }
        }
        _ => Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "desktop input action is not mapped",
        )),
    }
}

fn full_user_input_with_approval(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "desktop input does not accept a target field",
        ));
    }
    let window_id = required_string(request, "window_id")?;
    if !orcel_provider_uia::is_well_formed_window_id(&window_id) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "desktop input window_id is malformed",
        ));
    }
    let expected_window_generation = required_u64(request, "expected_window_generation")?;
    let action_name = required_string(request, "action")?;
    let action = desktop_input_action(request, &action_name)?;

    require_full_user_desktop()?;
    let binding = {
        let guard = locked_registry()?;
        guard
            .capture_binding(
                &window_id,
                expected_window_generation,
                CAPTURE_SCOPE_TARGET_WINDOW,
                &workspace.id,
                POLICY_REVISION,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))?
    };

    let digest = desktop_request_digest(workspace, request);
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        "execute Full User desktop input",
        window_id.clone(),
        format!(
            "process={} window={} window_generation={} action={} arguments_digest={}",
            binding.process_id, binding.window_id, binding.window_generation, action_name, digest,
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
            orcel_approval::now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;

    let host = computer_host()?;
    let cursor = host
        .cursor_position()
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    require_full_user_desktop()?;
    let rebound = {
        let guard = locked_registry()?;
        guard
            .capture_binding(
                &window_id,
                expected_window_generation,
                CAPTURE_SCOPE_TARGET_WINDOW,
                &workspace.id,
                POLICY_REVISION,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))?
    };
    if rebound.process_id != binding.process_id
        || rebound.process_generation != binding.process_generation
        || rebound.window_id != binding.window_id
        || rebound.window_generation != binding.window_generation
        || rebound.hwnd != binding.hwnd
    {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "desktop input target changed after approval",
        ));
    }
    let outcome = host
        .execute_raw_input(rebound.hwnd, &action, cursor.last_input_tick)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    Ok(json!({
        "schema": "orcel-desktop-input/1",
        "state": outcome.state,
        "action": outcome.action,
        "message": outcome.message,
        "window_id": rebound.window_id,
        "process_id": rebound.process_id,
        "window_generation": rebound.window_generation,
        "approval_record": token.record_id,
        "policy_revision": POLICY_REVISION
    }))
}

fn full_user_window_action_with_approval(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "desktop window action does not accept a target field",
        ));
    }
    reject_uia_arguments(
        request,
        &["window_id", "expected_window_generation", "action"],
    )?;
    let window_id = required_string(request, "window_id")?;
    if !orcel_provider_uia::is_well_formed_window_id(&window_id) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "desktop window action window_id is malformed",
        ));
    }
    let expected_window_generation = required_u64(request, "expected_window_generation")?;
    let action_name = required_string(request, "action")?;
    let action = match action_name.as_str() {
        "focus" => DesktopWindowAction::Focus,
        "minimize" => DesktopWindowAction::Minimize,
        "maximize" => DesktopWindowAction::Maximize,
        "restore" => DesktopWindowAction::Restore,
        "close" => DesktopWindowAction::Close,
        _ => {
            return Err(ProviderError::new(
                FailureCode::CapabilityDenied,
                "desktop window action is not mapped",
            ))
        }
    };

    require_full_user_desktop()?;
    let binding = {
        let guard = locked_registry()?;
        guard
            .capture_binding(
                &window_id,
                expected_window_generation,
                CAPTURE_SCOPE_TARGET_WINDOW,
                &workspace.id,
                POLICY_REVISION,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))?
    };
    let digest = desktop_request_digest(workspace, request);
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        "execute Full User window lifecycle action",
        window_id.clone(),
        format!(
            "process={} window={} window_generation={} action={} arguments_digest={}",
            binding.process_id, binding.window_id, binding.window_generation, action_name, digest,
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
            orcel_approval::now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;

    let host = computer_host()?;
    let cursor = host
        .cursor_position()
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    require_full_user_desktop()?;
    let rebound = {
        let guard = locked_registry()?;
        guard
            .capture_binding(
                &window_id,
                expected_window_generation,
                CAPTURE_SCOPE_TARGET_WINDOW,
                &workspace.id,
                POLICY_REVISION,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))?
    };
    if rebound.process_id != binding.process_id
        || rebound.process_generation != binding.process_generation
        || rebound.window_id != binding.window_id
        || rebound.window_generation != binding.window_generation
        || rebound.hwnd != binding.hwnd
    {
        return Err(ProviderError::new(
            FailureCode::TargetStale,
            "desktop window target changed after approval",
        ));
    }
    let outcome = host
        .execute_window_action(rebound.hwnd, action, cursor.last_input_tick)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    Ok(json!({
        "schema": "orcel-desktop-window-action/1",
        "state": outcome.state,
        "action": outcome.action,
        "message": outcome.message,
        "window_id": rebound.window_id,
        "process_id": rebound.process_id,
        "window_generation": rebound.window_generation,
        "approval_record": token.record_id,
        "policy_revision": POLICY_REVISION
    }))
}

/// Dispatch the SG-000036 UIA shapes. Returns `Ok(None)` for non-UIA shapes
/// so the caller falls through to the browser, trust, Git, and legacy
/// dispatchers.
pub fn dispatch_uia(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Option<Value>, ProviderError> {
    match (request.capability.as_str(), request.operation.as_str()) {
        ("desktop.cursor", "get") => return full_user_cursor(request).map(Some),
        ("desktop.input", "execute") => {
            return full_user_input_with_approval(workspace, approval, request).map(Some)
        }
        ("desktop.window", "action") => {
            return full_user_window_action_with_approval(workspace, approval, request).map(Some)
        }
        _ => {}
    }
    if orcel_provider_uia::is_input_execute_shape(&request.capability, &request.operation) {
        return execute_with_approval(workspace, approval, request).map(Some);
    }
    if orcel_provider_uia::is_coordinate_propose_shape(&request.capability, &request.operation) {
        return derive_with_approval(workspace, approval, request).map(Some);
    }
    if orcel_provider_uia::is_visual_propose_shape(&request.capability, &request.operation) {
        return propose_with_approval(workspace, approval, request).map(Some);
    }
    if orcel_provider_uia::is_capture_shape(&request.capability, &request.operation) {
        return capture_with_approval(workspace, approval, request).map(Some);
    }
    if orcel_provider_uia::is_scroll_shape(&request.capability, &request.operation) {
        return scroll_with_approval(workspace, approval, request).map(Some);
    }
    if orcel_provider_uia::is_toggle_shape(&request.capability, &request.operation) {
        return toggle_with_approval(workspace, approval, request).map(Some);
    }
    if orcel_provider_uia::is_select_shape(&request.capability, &request.operation) {
        return select_with_approval(workspace, approval, request).map(Some);
    }
    if orcel_provider_uia::is_value_shape(&request.capability, &request.operation) {
        return set_value_with_approval(workspace, approval, request).map(Some);
    }
    if orcel_provider_uia::is_invoke_shape(&request.capability, &request.operation) {
        return invoke_with_approval(workspace, approval, request).map(Some);
    }
    if !orcel_provider_uia::is_allowed_uia_shape(&request.capability, &request.operation) {
        return Ok(None);
    }
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia observation shapes do not accept a target field",
        ));
    }
    match (request.capability.as_str(), request.operation.as_str()) {
        ("uia.process", "observe") => {
            let process_id = required_string(request, "process_id")?;
            let expected = required_u64(request, "expected_process_generation")?;
            let guard = locked_registry()?;
            guard
                .observe_process(&process_id, expected, &workspace.id, POLICY_REVISION)
                .map(Some)
                .map_err(|error| ProviderError::new(error.code, error.message))
        }
        ("uia.window", "list") => {
            reject_uia_arguments(request, &[])?;
            let mut guard = locked_registry()?;
            if computer_host_selected() {
                let adapter = computer_host()?;
                guard
                    .list_windows(adapter, &workspace.id, POLICY_REVISION)
                    .map(Some)
                    .map_err(|error| ProviderError::new(error.code, error.message))
            } else {
                let adapter = NativeAdapter::new();
                guard
                    .list_windows(&adapter, &workspace.id, POLICY_REVISION)
                    .map(Some)
                    .map_err(|error| ProviderError::new(error.code, error.message))
            }
        }
        ("uia.window", "observe") => {
            let window_id = required_string(request, "window_id")?;
            let expected = required_u64(request, "expected_window_generation")?;
            let guard = locked_registry()?;
            guard
                .observe_window(&window_id, expected, &workspace.id, POLICY_REVISION)
                .map(Some)
                .map_err(|error| ProviderError::new(error.code, error.message))
        }
        ("uia.tree", "observe") => {
            let window_id = required_string(request, "window_id")?;
            let expected = required_u64(request, "expected_window_generation")?;
            let max_depth = optional_u64(request, "max_depth")?;
            let max_nodes = optional_u64(request, "max_nodes")?;
            let mut guard = locked_registry()?;
            if computer_host_selected() {
                let adapter = computer_host()?;
                guard
                    .observe_tree(
                        adapter,
                        &window_id,
                        expected,
                        max_depth,
                        max_nodes,
                        &workspace.id,
                        POLICY_REVISION,
                    )
                    .map(Some)
                    .map_err(|error| ProviderError::new(error.code, error.message))
            } else {
                let adapter = NativeAdapter::new();
                guard
                    .observe_tree(
                        &adapter,
                        &window_id,
                        expected,
                        max_depth,
                        max_nodes,
                        &workspace.id,
                        POLICY_REVISION,
                    )
                    .map(Some)
                    .map_err(|error| ProviderError::new(error.code, error.message))
            }
        }
        ("uia.element", "observe") => {
            let element_id = required_string(request, "element_id")?;
            let expected = required_u64(request, "expected_tree_generation")?;
            let guard = locked_registry()?;
            guard
                .observe_element(&element_id, expected, &workspace.id, POLICY_REVISION)
                .map(Some)
                .map_err(|error| ProviderError::new(error.code, error.message))
        }
        _ => Ok(None),
    }
}

fn invoke_with_approval(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia invoke shapes do not accept a target field",
        ));
    }
    reject_uia_arguments(
        request,
        &[
            "element_id",
            "expected_tree_generation",
            "expected_control_type",
        ],
    )?;
    let element_id = required_string(request, "element_id")?;
    if !orcel_provider_uia::is_well_formed_element_id(&element_id) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia invoke element_id is malformed",
        ));
    }
    let expected_tree_generation = required_u64(request, "expected_tree_generation")?;
    let expected_control_type = required_string(request, "expected_control_type")?;
    if expected_control_type.is_empty() || expected_control_type.len() > 256 {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia invoke expected_control_type is empty or too large",
        ));
    }
    if !orcel_provider_uia::is_invoke_eligible_control_type(&expected_control_type) {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "uia invoke actuates only Button, Hyperlink, MenuItem, and SplitButton elements",
        ));
    }
    let binding = {
        let guard = locked_registry()?;
        guard
            .invoke_binding(
                &element_id,
                expected_tree_generation,
                &expected_control_type,
                &workspace.id,
                POLICY_REVISION,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))?
    };
    let digest = invoke_approval_digest(&workspace.id, POLICY_REVISION, &binding);
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        "invoke UIA element",
        element_id.clone(),
        format!(
            "process={} window={} element={} control={} tree={} action=invoke",
            binding.process_id,
            binding.window_id,
            binding.element_id,
            binding.control_type,
            binding.tree_generation,
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
            orcel_approval::now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    require_full_user_desktop()?;
    let adapter = computer_host()?;
    arm_semantic(adapter, binding.hwnd, &binding.runtime_id, "invoke", None)?;
    let result = locked_registry().and_then(|mut guard| {
        guard
            .invoke_element(
                adapter,
                &element_id,
                expected_tree_generation,
                &expected_control_type,
                &workspace.id,
                POLICY_REVISION,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))
    });
    disarm_semantic(adapter);
    let evidence = result?;
    let mut stamped = evidence;
    stamped["approval_record"] = Value::String(token.record_id);
    Ok(stamped)
}

fn set_value_with_approval(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia set_value shapes do not accept a target field",
        ));
    }
    reject_uia_arguments(
        request,
        &[
            "element_id",
            "expected_tree_generation",
            "expected_control_type",
            "value",
        ],
    )?;
    let element_id = required_string(request, "element_id")?;
    if !orcel_provider_uia::is_well_formed_element_id(&element_id) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia set_value element_id is malformed",
        ));
    }
    let expected_tree_generation = required_u64(request, "expected_tree_generation")?;
    let expected_control_type = required_string(request, "expected_control_type")?;
    if expected_control_type.is_empty() || expected_control_type.len() > 256 {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia set_value expected_control_type is empty or too large",
        ));
    }
    if !orcel_provider_uia::is_value_eligible_control_type(&expected_control_type) {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "uia set_value actuates only Edit, Document, and ComboBox elements",
        ));
    }
    let value = required_string(request, "value")?;
    if value.chars().count() > orcel_provider_uia::MAX_VALUE_CHARS {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia set_value value exceeds the bounded length",
        ));
    }
    if value.contains('\0') {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia set_value value contains a NUL byte",
        ));
    }
    let binding = {
        let guard = locked_registry()?;
        guard
            .value_binding(
                &element_id,
                expected_tree_generation,
                &expected_control_type,
                &value,
                &workspace.id,
                POLICY_REVISION,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))?
    };
    let digest = value_approval_digest(&workspace.id, POLICY_REVISION, &binding);
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        "set UIA element value",
        element_id.clone(),
        format!(
            "process={} window={} element={} control={} tree={} action=set_value value_digest={}",
            binding.process_id,
            binding.window_id,
            binding.element_id,
            binding.control_type,
            binding.tree_generation,
            binding.value_digest,
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
            orcel_approval::now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    require_full_user_desktop()?;
    let adapter = computer_host()?;
    arm_semantic(
        adapter,
        binding.hwnd,
        &binding.runtime_id,
        "set_value",
        Some(&binding.value_digest),
    )?;
    let result = locked_registry().and_then(|mut guard| {
        guard
            .set_value_element(
                adapter,
                &element_id,
                expected_tree_generation,
                &expected_control_type,
                &value,
                &workspace.id,
                POLICY_REVISION,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))
    });
    disarm_semantic(adapter);
    let evidence = result?;
    let mut stamped = evidence;
    stamped["approval_record"] = Value::String(token.record_id);
    Ok(stamped)
}

fn select_with_approval(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia select shapes do not accept a target field",
        ));
    }
    reject_uia_arguments(
        request,
        &[
            "element_id",
            "expected_tree_generation",
            "expected_control_type",
            "expected_selected",
            "selected",
        ],
    )?;
    let element_id = required_string(request, "element_id")?;
    if !orcel_provider_uia::is_well_formed_element_id(&element_id) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia select element_id is malformed",
        ));
    }
    let expected_tree_generation = required_u64(request, "expected_tree_generation")?;
    let expected_control_type = required_string(request, "expected_control_type")?;
    if expected_control_type.is_empty() || expected_control_type.len() > 256 {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia select expected_control_type is empty or too large",
        ));
    }
    if !orcel_provider_uia::is_select_eligible_control_type(&expected_control_type) {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "uia select actuates only ListItem, TreeItem, and TabItem elements",
        ));
    }
    let expected_selected = required_bool(request, "expected_selected")?;
    let selected = required_bool(request, "selected")?;
    let binding = {
        let guard = locked_registry()?;
        guard
            .select_binding(
                &element_id,
                expected_tree_generation,
                &expected_control_type,
                expected_selected,
                selected,
                &workspace.id,
                POLICY_REVISION,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))?
    };
    let digest = select_approval_digest(&workspace.id, POLICY_REVISION, &binding);
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        "select UIA element",
        element_id.clone(),
        format!(
            "process={} window={} element={} control={} tree={} action=select expected_selected={} selected={}",
            binding.process_id,
            binding.window_id,
            binding.element_id,
            binding.control_type,
            binding.tree_generation,
            binding.expected_selected,
            binding.selected,
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
            orcel_approval::now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    require_full_user_desktop()?;
    let adapter = computer_host()?;
    arm_semantic(adapter, binding.hwnd, &binding.runtime_id, "select", None)?;
    let result = locked_registry().and_then(|mut guard| {
        guard
            .select_element(
                adapter,
                &element_id,
                expected_tree_generation,
                &expected_control_type,
                expected_selected,
                selected,
                &workspace.id,
                POLICY_REVISION,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))
    });
    disarm_semantic(adapter);
    let evidence = result?;
    let mut stamped = evidence;
    stamped["approval_record"] = Value::String(token.record_id);
    Ok(stamped)
}

fn execute_with_approval(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia bounded execution shapes do not accept a target field",
        ));
    }
    reject_uia_arguments(
        request,
        &["coord_id", "expected_derivation_generation", "operation"],
    )?;
    let coord_id = required_string(request, "coord_id")?;
    if !orcel_provider_uia::is_well_formed_coord_id(&coord_id) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia bounded execution coord_id is malformed",
        ));
    }
    let expected_derivation_generation = required_u64(request, "expected_derivation_generation")?;
    let operation = required_string(request, "operation")?;
    if !orcel_provider_uia::is_execute_operation(&operation) {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "uia bounded execution operation is fixed to click",
        ));
    }
    let binding = {
        let mut guard = locked_registry()?;
        guard
            .grant_input_lease(
                &coord_id,
                expected_derivation_generation,
                &operation,
                &workspace.id,
                POLICY_REVISION,
                orcel_approval::now_ms(),
            )
            .map_err(|error| ProviderError::new(error.code, error.message))?
    };
    let digest = execute_approval_digest(&workspace.id, POLICY_REVISION, &binding);
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        "execute bounded click",
        coord_id.clone(),
        format!(
            "coord={} derivation_generation={} window={} coordinates={},{} operation={} lease={} interruption_epoch={} action=execute",
            binding.coord_id,
            binding.derivation_generation,
            binding.window_id,
            binding.x,
            binding.y,
            binding.operation,
            binding.lease_id,
            binding.interruption_epoch,
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
            orcel_approval::now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let adapter = NativeAdapter::new();
    let mut guard = locked_registry()?;
    let evidence = guard
        .execute_input(
            &adapter,
            &binding.lease_id,
            &workspace.id,
            POLICY_REVISION,
            orcel_approval::now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let mut stamped = evidence;
    stamped["approval_record"] = Value::String(token.record_id);
    Ok(stamped)
}

fn derive_with_approval(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia coordinate derivation shapes do not accept a target field",
        ));
    }
    reject_uia_arguments(request, &["proposal_id", "expected_proposal_generation"])?;
    let proposal_id = required_string(request, "proposal_id")?;
    if !orcel_provider_uia::is_well_formed_proposal_id(&proposal_id) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia coordinate derivation proposal_id is malformed",
        ));
    }
    let expected_proposal_generation = required_u64(request, "expected_proposal_generation")?;
    let binding = {
        let guard = locked_registry()?;
        guard
            .derivation_binding(
                &proposal_id,
                expected_proposal_generation,
                &workspace.id,
                POLICY_REVISION,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))?
    };
    let digest = coordinate_derivation_digest(&workspace.id, POLICY_REVISION, &binding);
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        "derive proposal coordinates",
        proposal_id.clone(),
        format!(
            "proposal={} proposal_generation={} frame={} coordinates={},{} action=derive",
            binding.proposal_id,
            binding.proposal_generation,
            binding.frame_id,
            binding.x,
            binding.y,
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
            orcel_approval::now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let mut guard = locked_registry()?;
    let evidence = guard
        .derive_coordinates(
            &proposal_id,
            expected_proposal_generation,
            &workspace.id,
            POLICY_REVISION,
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let mut stamped = evidence;
    stamped["approval_record"] = Value::String(token.record_id);
    Ok(stamped)
}

fn propose_with_approval(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia visual proposal shapes do not accept a target field",
        ));
    }
    reject_uia_arguments(
        request,
        &[
            "frame_id",
            "expected_capture_generation",
            "x",
            "y",
            "width",
            "height",
        ],
    )?;
    let frame_id = required_string(request, "frame_id")?;
    if !orcel_provider_uia::is_well_formed_frame_id(&frame_id) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia visual proposal frame_id is malformed",
        ));
    }
    let expected_capture_generation = required_u64(request, "expected_capture_generation")?;
    let x = required_u64(request, "x")?;
    let y = required_u64(request, "y")?;
    let width = required_u64(request, "width")?;
    if width == 0 {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia visual proposal width must be nonzero",
        ));
    }
    let height = required_u64(request, "height")?;
    if height == 0 {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia visual proposal height must be nonzero",
        ));
    }
    let region = VisualRegion {
        x,
        y,
        width,
        height,
    };
    let binding = {
        let guard = locked_registry()?;
        guard
            .proposal_binding(
                &frame_id,
                expected_capture_generation,
                region,
                &workspace.id,
                POLICY_REVISION,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))?
    };
    let digest = visual_proposal_digest(&workspace.id, POLICY_REVISION, &binding);
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        "propose visual target",
        frame_id.clone(),
        format!(
            "frame={} capture_generation={} window={} region={},{},{}x{} action=propose",
            binding.frame_id,
            binding.capture_generation,
            binding.window_id,
            binding.region.x,
            binding.region.y,
            binding.region.width,
            binding.region.height,
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
            orcel_approval::now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let mut guard = locked_registry()?;
    let evidence = guard
        .propose_visual_target(
            &frame_id,
            expected_capture_generation,
            region,
            &workspace.id,
            POLICY_REVISION,
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let mut stamped = evidence;
    stamped["approval_record"] = Value::String(token.record_id);
    Ok(stamped)
}

fn capture_with_approval(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia screenshot capture shapes do not accept a target field",
        ));
    }
    reject_uia_arguments(
        request,
        &["window_id", "expected_window_generation", "scope"],
    )?;
    let window_id = required_string(request, "window_id")?;
    if !orcel_provider_uia::is_well_formed_window_id(&window_id) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia screenshot capture window_id is malformed",
        ));
    }
    let expected_window_generation = required_u64(request, "expected_window_generation")?;
    let scope = required_string(request, "scope")?;
    if !orcel_provider_uia::is_capture_scope(&scope) {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "uia screenshot capture scope is fixed to target-window; monitor scope, desktop scope, and caller-selected regions are denied",
        ));
    }
    let binding = {
        let guard = locked_registry()?;
        guard
            .capture_binding(
                &window_id,
                expected_window_generation,
                &scope,
                &workspace.id,
                POLICY_REVISION,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))?
    };
    let digest = capture_approval_digest(&workspace.id, POLICY_REVISION, &binding);
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        "capture window screenshot",
        window_id.clone(),
        format!(
            "process={} window={} window_generation={} scope={} action=capture",
            binding.process_id, binding.window_id, binding.window_generation, binding.scope,
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
            orcel_approval::now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    require_full_user_desktop()?;
    let adapter = computer_host()?;
    let mut guard = locked_registry()?;
    let evidence = guard
        .capture_window(
            adapter,
            &window_id,
            expected_window_generation,
            &scope,
            &workspace.id,
            POLICY_REVISION,
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let mut stamped = evidence;
    stamped["approval_record"] = Value::String(token.record_id);
    Ok(stamped)
}

fn scroll_with_approval(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia scroll shapes do not accept a target field",
        ));
    }
    reject_uia_arguments(
        request,
        &[
            "element_id",
            "expected_tree_generation",
            "expected_control_type",
            "direction",
            "amount",
            "expected_horizontal_percent",
            "expected_vertical_percent",
        ],
    )?;
    let element_id = required_string(request, "element_id")?;
    if !orcel_provider_uia::is_well_formed_element_id(&element_id) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia scroll element_id is malformed",
        ));
    }
    let expected_tree_generation = required_u64(request, "expected_tree_generation")?;
    let expected_control_type = required_string(request, "expected_control_type")?;
    if expected_control_type.is_empty() || expected_control_type.len() > 256 {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia scroll expected_control_type is empty or too large",
        ));
    }
    if !orcel_provider_uia::is_scroll_eligible_control_type(&expected_control_type) {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "uia scroll actuates only ScrollBar, Pane, List, and Tree elements",
        ));
    }
    let direction = required_string(request, "direction")?;
    if !orcel_provider_uia::is_scroll_direction(&direction) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia scroll direction must be one of up, down, left, or right",
        ));
    }
    let amount = required_u64(request, "amount")?;
    if !(1..=20).contains(&amount) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia scroll amount must be between 1 and 20 inclusive under SG-000095 Full User control",
        ));
    }
    let expected_horizontal_percent = required_u64(request, "expected_horizontal_percent")?;
    if expected_horizontal_percent > 100 {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia scroll expected_horizontal_percent must be between 0 and 100 inclusive",
        ));
    }
    let expected_vertical_percent = required_u64(request, "expected_vertical_percent")?;
    if expected_vertical_percent > 100 {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia scroll expected_vertical_percent must be between 0 and 100 inclusive",
        ));
    }
    let binding = {
        let guard = locked_registry()?;
        guard
            .scroll_binding(
                &element_id,
                expected_tree_generation,
                &expected_control_type,
                expected_horizontal_percent,
                expected_vertical_percent,
                &direction,
                amount,
                &workspace.id,
                POLICY_REVISION,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))?
    };
    let digest = scroll_approval_digest(&workspace.id, POLICY_REVISION, &binding);
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        "scroll UIA element",
        element_id.clone(),
        format!(
            "process={} window={} element={} control={} tree={} action=scroll direction={} amount={} expected_h={} expected_v={}",
            binding.process_id,
            binding.window_id,
            binding.element_id,
            binding.control_type,
            binding.tree_generation,
            binding.direction,
            binding.amount,
            binding.expected_horizontal_percent,
            binding.expected_vertical_percent,
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
            orcel_approval::now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    require_full_user_desktop()?;
    let adapter = computer_host()?;
    let mut guard = locked_registry()?;
    let evidence = guard
        .scroll_element(
            adapter,
            &element_id,
            expected_tree_generation,
            &expected_control_type,
            expected_horizontal_percent,
            expected_vertical_percent,
            &direction,
            amount,
            &workspace.id,
            POLICY_REVISION,
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let mut stamped = evidence;
    stamped["approval_record"] = Value::String(token.record_id);
    Ok(stamped)
}

fn toggle_with_approval(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Value, ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia toggle shapes do not accept a target field",
        ));
    }
    reject_uia_arguments(
        request,
        &[
            "element_id",
            "expected_tree_generation",
            "expected_control_type",
            "expected_toggled",
            "toggled",
        ],
    )?;
    let element_id = required_string(request, "element_id")?;
    if !orcel_provider_uia::is_well_formed_element_id(&element_id) {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia toggle element_id is malformed",
        ));
    }
    let expected_tree_generation = required_u64(request, "expected_tree_generation")?;
    let expected_control_type = required_string(request, "expected_control_type")?;
    if expected_control_type.is_empty() || expected_control_type.len() > 256 {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "uia toggle expected_control_type is empty or too large",
        ));
    }
    if !orcel_provider_uia::is_toggle_eligible_control_type(&expected_control_type) {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "uia toggle actuates only CheckBox and RadioButton elements",
        ));
    }
    let expected_toggled = required_bool(request, "expected_toggled")?;
    let toggled = required_bool(request, "toggled")?;
    let binding = {
        let guard = locked_registry()?;
        guard
            .toggle_binding(
                &element_id,
                expected_tree_generation,
                &expected_control_type,
                expected_toggled,
                toggled,
                &workspace.id,
                POLICY_REVISION,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))?
    };
    let digest = toggle_approval_digest(&workspace.id, POLICY_REVISION, &binding);
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        "toggle UIA element",
        element_id.clone(),
        format!(
            "process={} window={} element={} control={} tree={} action=toggle expected_toggled={} toggled={}",
            binding.process_id,
            binding.window_id,
            binding.element_id,
            binding.control_type,
            binding.tree_generation,
            binding.expected_toggled,
            binding.toggled,
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
            orcel_approval::now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    require_full_user_desktop()?;
    let adapter = computer_host()?;
    arm_semantic(
        adapter,
        binding.hwnd,
        &binding.runtime_id,
        "toggle",
        Some(&orcel_provider_uia::value_content_digest(if toggled {
            "true"
        } else {
            "false"
        })),
    )?;
    let result = locked_registry().and_then(|mut guard| {
        guard
            .toggle_element(
                adapter,
                &element_id,
                expected_tree_generation,
                &expected_control_type,
                expected_toggled,
                toggled,
                &workspace.id,
                POLICY_REVISION,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))
    });
    disarm_semantic(adapter);
    let evidence = result?;
    let mut stamped = evidence;
    stamped["approval_record"] = Value::String(token.record_id);
    Ok(stamped)
}

fn required_string(request: &RequestEnvelope, name: &str) -> Result<String, ProviderError> {
    request
        .arguments
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("uia shape requires arguments.{name} as a string"),
            )
        })
}

fn required_u64(request: &RequestEnvelope, name: &str) -> Result<u64, ProviderError> {
    request
        .arguments
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("uia shape requires arguments.{name} as an unsigned integer"),
            )
        })
}

fn required_i32(request: &RequestEnvelope, name: &str) -> Result<i32, ProviderError> {
    let value = request
        .arguments
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("desktop shape requires arguments.{name} as a non-negative integer"),
            )
        })?;
    i32::try_from(value).map_err(|_| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            format!("desktop shape arguments.{name} is out of range"),
        )
    })
}

fn required_i32_signed(request: &RequestEnvelope, name: &str) -> Result<i32, ProviderError> {
    let value = request
        .arguments
        .get(name)
        .and_then(Value::as_i64)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("desktop shape requires arguments.{name} as an integer"),
            )
        })?;
    i32::try_from(value).map_err(|_| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            format!("desktop shape arguments.{name} is out of range"),
        )
    })
}

fn required_bool(request: &RequestEnvelope, name: &str) -> Result<bool, ProviderError> {
    request
        .arguments
        .get(name)
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("uia shape requires arguments.{name} as a boolean"),
            )
        })
}

fn optional_u64(request: &RequestEnvelope, name: &str) -> Result<Option<u64>, ProviderError> {
    match request.arguments.get(name) {
        None => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("uia shape requires arguments.{name} as an unsigned integer"),
            )
        }),
    }
}

fn reject_uia_arguments(request: &RequestEnvelope, allowed: &[&str]) -> Result<(), ProviderError> {
    let arguments = request.arguments.as_object().ok_or_else(|| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "uia arguments must be an object",
        )
    })?;
    if let Some(key) = arguments
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
    {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            format!("uia shape does not accept argument field: {key}"),
        ));
    }
    Ok(())
}

#[cfg(all(test, not(windows)))]
mod xp06_tests {
    use super::trusted_native_host;

    /// The path rule itself is tested in orcel-provider-uia
    /// (native_host_path); this checks orceld applies it.
    #[test]
    fn xp06_unpinned_host_bins_are_refused() {
        for value in [
            None,
            Some("orcel-native-host"),
            Some("/tmp/x/orcel-native-host"),
            Some("/usr/bin/orcel-native-host"),
        ] {
            let error = trusted_native_host(value.map(Into::into)).unwrap_err();
            assert_eq!(
                error.code,
                orcel_contracts::FailureCode::ProviderUnavailable,
                "{value:?}"
            );
        }
    }
}
