//! SG-000037 deterministic human-interruption invalidation tests.
//!
//! These tests use an injected fake adapter, so they prove interruption
//! epoch policy, lease epoch binding, approval digest epoch binding,
//! pre-execution interruption revalidation, Orcel-synthetic exclusion
//! with fail-closed ambiguity, no replay or continuation after override,
//! and protected-surface retention deterministically on every platform
//! without a live desktop. Real Windows process identity is proven
//! separately through the native adapter test, and live desktop
//! interaction is reported as unavailable instead of fabricated.

use super::*;
use std::cell::RefCell;
use std::collections::HashMap;

const WORKSPACE: &str = "interrupt-test-workspace";
const POLICY: &str = "sg-000037-v1";
const NOW: u64 = 2_000_000;

fn fake_process(pid: u32, exe: &str, generation: u64) -> NativeProcess {
    NativeProcess {
        pid,
        exe_name: format!("{exe}.exe"),
        exe_id: digest_hex(&format!("{UIA_SCHEMA}|exe|{exe}"), ID_HEX_CHARS),
        session_id: 1,
        session_verified: true,
        start_generation: generation,
        generation_source: "fake-adapter",
        signature: SignatureState::Unknown.into(),
    }
}

fn fake_window(hwnd: u64, title: &str, class: &str, nonce: u64) -> NativeWindow {
    NativeWindow {
        hwnd,
        title: title.to_owned(),
        class: class.to_owned(),
        visible: true,
        window_nonce: nonce,
    }
}

fn deterministic_image(hwnd: u64) -> CapturedImage {
    let width = 8u32;
    let height = 6u32;
    let mut bytes = Vec::with_capacity((width as usize) * (height as usize) * 4);
    for index in 0..(width as usize) * (height as usize) {
        let base = ((hwnd as usize) + index) & 0xFF;
        bytes.push(base as u8);
        bytes.push((base.wrapping_add(1)) as u8);
        bytes.push((base.wrapping_add(2)) as u8);
        bytes.push(255u8);
    }
    CapturedImage {
        width,
        height,
        bytes,
    }
}

#[derive(Default)]
struct FakeInterruptState {
    processes: Vec<NativeProcess>,
    windows_by_pid: HashMap<u32, Vec<NativeWindow>>,
    images_by_hwnd: HashMap<u64, CapturedImage>,
    clicks: Vec<(u64, u64, u64)>,
}

#[derive(Default)]
struct FakeInterruptAdapter {
    state: RefCell<FakeInterruptState>,
}

impl FakeInterruptAdapter {
    fn with_process(pid: u32, exe: &str, generation: u64) -> Self {
        let adapter = Self::default();
        adapter
            .state
            .borrow_mut()
            .processes
            .push(fake_process(pid, exe, generation));
        adapter
    }

    fn set_windows(&self, pid: u32, windows: Vec<NativeWindow>) {
        self.state.borrow_mut().windows_by_pid.insert(pid, windows);
    }

    fn set_image(&self, hwnd: u64, image: CapturedImage) {
        self.state.borrow_mut().images_by_hwnd.insert(hwnd, image);
    }

    fn click_count(&self) -> usize {
        self.state.borrow().clicks.len()
    }
}

impl UiaAdapter for FakeInterruptAdapter {
    fn list_processes(&self) -> Result<Vec<NativeProcess>, UiaError> {
        Ok(self.state.borrow().processes.clone())
    }

    fn list_windows(&self, pid: u32) -> Result<Vec<NativeWindow>, UiaError> {
        Ok(self
            .state
            .borrow()
            .windows_by_pid
            .get(&pid)
            .cloned()
            .unwrap_or_default())
    }

    fn read_tree(&self, _hwnd: u64) -> Result<Vec<NativeElement>, UiaError> {
        Ok(Vec::new())
    }

    fn capture_window(&self, hwnd: u64) -> Result<CapturedImage, UiaError> {
        self.state
            .borrow()
            .images_by_hwnd
            .get(&hwnd)
            .cloned()
            .ok_or_else(|| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "no fake capture image is registered for this window",
                )
            })
    }

    fn execute_click(&self, hwnd: u64, x: u64, y: u64) -> Result<(), UiaError> {
        self.state.borrow_mut().clicks.push((hwnd, x, y));
        Ok(())
    }
}

fn setup_coord() -> (FakeInterruptAdapter, UiaRegistry, String, u64) {
    let adapter = FakeInterruptAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    adapter.set_image(100, deterministic_image(100));
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    let window_id = list["windows"][0]["window_id"]
        .as_str()
        .expect("window id")
        .to_owned();
    let window_generation = list["windows"][0]["window_generation"]
        .as_u64()
        .expect("window generation");
    let capture = registry
        .capture_window(
            &adapter,
            &window_id,
            window_generation,
            "target-window",
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    let frame_id = capture["frame_id"].as_str().expect("frame id").to_owned();
    let capture_generation = capture["capture_generation"]
        .as_u64()
        .expect("capture generation");
    let proposal = registry
        .propose_visual_target(
            &frame_id,
            capture_generation,
            VisualRegion {
                x: 1,
                y: 1,
                width: 4,
                height: 3,
            },
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    let proposal_id = proposal["proposal_id"]
        .as_str()
        .expect("proposal id")
        .to_owned();
    let proposal_generation = proposal["proposal_generation"]
        .as_u64()
        .expect("proposal generation");
    let derived = registry
        .derive_coordinates(&proposal_id, proposal_generation, WORKSPACE, POLICY)
        .unwrap();
    let coord_id = derived["coord_id"].as_str().expect("coord id").to_owned();
    let derivation_generation = derived["derivation_generation"]
        .as_u64()
        .expect("derivation generation");
    (adapter, registry, coord_id, derivation_generation)
}

fn grant(registry: &mut UiaRegistry, coord_id: &str, derivation_generation: u64) -> ExecuteBinding {
    registry
        .grant_input_lease(
            coord_id,
            derivation_generation,
            "click",
            WORKSPACE,
            POLICY,
            NOW,
        )
        .expect("lease grant")
}

#[test]
fn interrupt_reason_and_origin_helpers_behave() {
    for reason in [
        "human-keyboard",
        "human-mouse-move",
        "human-mouse-button",
        "human-touch-pen",
        "human-foreground-change",
        "human-presence",
        "emergency-stop",
        "approval-pending-suspension",
    ] {
        assert!(
            is_human_interrupt_reason(reason),
            "reason must be accepted: {reason}"
        );
    }
    assert!(!is_human_interrupt_reason(""));
    assert!(!is_human_interrupt_reason("human-keystroke-content"));
    assert!(!is_human_interrupt_reason("orcel-synthetic"));
    assert!(!is_human_interrupt_reason("os-synthetic"));
    assert!(!is_human_interrupt_reason("unknown-source"));
    assert!(!is_human_interrupt_reason(
        &"x".repeat(MAX_INTERRUPT_REASON_CHARS + 1)
    ));
    assert_eq!(INTERRUPT_SCHEMA, "orcel-human-interruption-v1");
    assert_eq!(
        classify_input_event(false, true, true),
        InputOrigin::OrcelSynthetic
    );
    assert_eq!(
        classify_input_event(true, false, true),
        InputOrigin::OsSynthetic
    );
    assert_eq!(
        classify_input_event(false, false, true),
        InputOrigin::HumanPhysical
    );
    assert_eq!(
        classify_input_event(false, false, false),
        InputOrigin::Unknown
    );
    assert_eq!(
        classify_input_event(true, true, true),
        InputOrigin::OrcelSynthetic
    );
    assert!(!should_interrupt_on_origin(InputOrigin::OrcelSynthetic));
    assert!(should_interrupt_on_origin(InputOrigin::OsSynthetic));
    assert!(should_interrupt_on_origin(InputOrigin::HumanPhysical));
    assert!(should_interrupt_on_origin(InputOrigin::Unknown));
}

#[test]
fn epoch_starts_at_zero_and_increments_on_valid_reports() {
    let (_adapter, mut registry, _coord, _generation) = setup_coord();
    assert_eq!(registry.interruption_epoch(), 0);
    let first = registry
        .report_human_interruption("human-mouse-move", WORKSPACE, POLICY, NOW)
        .unwrap();
    assert_eq!(first["schema"], INTERRUPT_SCHEMA);
    assert_eq!(first["action"], "human-interruption");
    assert_eq!(first["interruption_epoch"], 1);
    assert_eq!(first["reason"], "human-mouse-move");
    assert_eq!(registry.interruption_epoch(), 1);
    let second = registry
        .report_human_interruption("human-keyboard", WORKSPACE, POLICY, NOW + 1)
        .unwrap();
    assert_eq!(second["interruption_epoch"], 2);
    assert_eq!(registry.interruption_epoch(), 2);
}

#[test]
fn invalid_reasons_are_rejected_without_epoch_mutation() {
    let (_adapter, mut registry, _coord, _generation) = setup_coord();
    for reason in [
        "",
        "human-keystroke-content",
        "orcel-synthetic",
        "os-synthetic",
        "unknown-source",
        "human-mouse-move ",
        "HUMAN-KEYBOARD",
    ] {
        let error = registry
            .report_human_interruption(reason, WORKSPACE, POLICY, NOW)
            .expect_err("invalid reason must fail");
        assert_eq!(error.code, FailureCode::InvalidRequest);
    }
    let oversized = "x".repeat(MAX_INTERRUPT_REASON_CHARS + 1);
    let error = registry
        .report_human_interruption(&oversized, WORKSPACE, POLICY, NOW)
        .expect_err("oversized reason must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);
    assert_eq!(registry.interruption_epoch(), 0);
    let empty_workspace = registry
        .report_human_interruption("human-keyboard", "", POLICY, NOW)
        .expect_err("empty workspace must fail");
    assert_eq!(empty_workspace.code, FailureCode::InvalidRequest);
    assert_eq!(registry.interruption_epoch(), 0);
}

#[test]
fn leases_bind_the_current_epoch_at_grant_time() {
    let (_adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let before = grant(&mut registry, &coord_id, derivation_generation);
    assert_eq!(before.interruption_epoch, 0);
    assert_eq!(registry.lease_interruption_epoch(&before.lease_id), Some(0));
    registry
        .report_human_interruption("human-mouse-move", WORKSPACE, POLICY, NOW + 1)
        .unwrap();
    let after = grant(&mut registry, &coord_id, derivation_generation);
    assert_eq!(after.interruption_epoch, 1);
    assert_eq!(registry.lease_interruption_epoch(&after.lease_id), Some(1));
    assert_ne!(before.lease_id, after.lease_id);
}

#[test]
fn human_mouse_move_during_live_lease_revokes_execution() {
    let (adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let binding = grant(&mut registry, &coord_id, derivation_generation);
    registry
        .report_human_interruption("human-mouse-move", WORKSPACE, POLICY, NOW + 1)
        .unwrap();
    let error = registry
        .execute_input(&adapter, &binding.lease_id, WORKSPACE, POLICY, NOW + 2)
        .expect_err("interrupted lease must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.click_count(), 0);
}

#[test]
fn physical_click_key_and_foreground_change_each_revoke() {
    for reason in [
        "human-mouse-button",
        "human-keyboard",
        "human-foreground-change",
        "human-touch-pen",
        "human-presence",
    ] {
        let (adapter, mut registry, coord_id, derivation_generation) = setup_coord();
        let binding = grant(&mut registry, &coord_id, derivation_generation);
        registry
            .report_human_interruption(reason, WORKSPACE, POLICY, NOW + 1)
            .unwrap();
        let error = registry
            .execute_input(&adapter, &binding.lease_id, WORKSPACE, POLICY, NOW + 2)
            .expect_err("interrupted lease must fail");
        assert_eq!(error.code, FailureCode::TargetStale, "reason: {reason}");
        assert_eq!(adapter.click_count(), 0, "reason: {reason}");
    }
}

#[test]
fn emergency_stop_and_approval_suspension_revoke() {
    for reason in ["emergency-stop", "approval-pending-suspension"] {
        let (adapter, mut registry, coord_id, derivation_generation) = setup_coord();
        let binding = grant(&mut registry, &coord_id, derivation_generation);
        let evidence = registry
            .report_human_interruption(reason, WORKSPACE, POLICY, NOW + 1)
            .unwrap();
        assert_eq!(evidence["reason"], reason);
        let error = registry
            .execute_input(&adapter, &binding.lease_id, WORKSPACE, POLICY, NOW + 2)
            .expect_err("revoked lease must fail");
        assert_eq!(error.code, FailureCode::TargetStale);
        assert_eq!(adapter.click_count(), 0);
    }
}

#[test]
fn replayed_pre_interruption_lease_never_executes_twice() {
    let (adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let binding = grant(&mut registry, &coord_id, derivation_generation);
    registry
        .report_human_interruption("human-keyboard", WORKSPACE, POLICY, NOW + 1)
        .unwrap();
    for attempt in [NOW + 2, NOW + 3] {
        let error = registry
            .execute_input(&adapter, &binding.lease_id, WORKSPACE, POLICY, attempt)
            .expect_err("interrupted lease must keep failing");
        assert_eq!(error.code, FailureCode::TargetStale);
    }
    assert_eq!(adapter.click_count(), 0);
}

#[test]
fn pre_interruption_approval_digest_does_not_survive_override() {
    let (_adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let before = grant(&mut registry, &coord_id, derivation_generation);
    let digest_before = execute_approval_digest(WORKSPACE, POLICY, &before);
    assert_eq!(digest_before.len(), 64);
    registry
        .report_human_interruption("human-mouse-button", WORKSPACE, POLICY, NOW + 1)
        .unwrap();
    let after = grant(&mut registry, &coord_id, derivation_generation);
    let digest_after = execute_approval_digest(WORKSPACE, POLICY, &after);
    assert_eq!(digest_after.len(), 64);
    assert_ne!(
        digest_before, digest_after,
        "approval digest must bind the interruption epoch"
    );
}

#[test]
fn fresh_lease_after_interruption_executes_with_fresh_approval() {
    let (adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let stale = grant(&mut registry, &coord_id, derivation_generation);
    registry
        .report_human_interruption("human-mouse-move", WORKSPACE, POLICY, NOW + 1)
        .unwrap();
    stale.lease_id.clone().chars().for_each(|_| ());
    let denied = registry.execute_input(&adapter, &stale.lease_id, WORKSPACE, POLICY, NOW + 2);
    assert_eq!(
        denied.expect_err("stale lease must fail").code,
        FailureCode::TargetStale
    );
    let fresh = grant(&mut registry, &coord_id, derivation_generation);
    let result = registry
        .execute_input(&adapter, &fresh.lease_id, WORKSPACE, POLICY, NOW + 3)
        .unwrap();
    assert_eq!(result["action"], "execute");
    assert_eq!(result["interruption_epoch"], 1);
    assert_eq!(result["lease_id"], fresh.lease_id);
    assert_eq!(adapter.click_count(), 1);
}

#[test]
fn forged_synthetic_origin_claim_cannot_suppress_override() {
    let (adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let binding = grant(&mut registry, &coord_id, derivation_generation);
    assert_eq!(
        classify_input_event(true, true, true),
        InputOrigin::OrcelSynthetic
    );
    assert!(!should_interrupt_on_origin(InputOrigin::OrcelSynthetic));
    registry
        .report_human_interruption("human-keyboard", WORKSPACE, POLICY, NOW + 1)
        .unwrap();
    let error = registry
        .execute_input(&adapter, &binding.lease_id, WORKSPACE, POLICY, NOW + 2)
        .expect_err("epoch check has no synthetic bypass");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.click_count(), 0);
}

#[test]
fn malformed_and_foreign_leases_still_fail_closed() {
    let (adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let binding = grant(&mut registry, &coord_id, derivation_generation);
    let malformed = registry.execute_input(&adapter, "caller-lease-1", WORKSPACE, POLICY, NOW + 1);
    assert_eq!(
        malformed.expect_err("malformed lease must fail").code,
        FailureCode::InvalidRequest
    );
    let foreign_workspace = registry.execute_input(
        &adapter,
        &binding.lease_id,
        "other-workspace",
        POLICY,
        NOW + 1,
    );
    assert_eq!(
        foreign_workspace
            .expect_err("foreign workspace must fail")
            .code,
        FailureCode::TargetStale
    );
    assert_eq!(adapter.click_count(), 0);
}

#[test]
fn interruption_is_global_across_workspaces() {
    let (adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let binding = grant(&mut registry, &coord_id, derivation_generation);
    registry
        .report_human_interruption("human-presence", "other-workspace", POLICY, NOW + 1)
        .unwrap();
    let error = registry
        .execute_input(&adapter, &binding.lease_id, WORKSPACE, POLICY, NOW + 2)
        .expect_err("human input is global and revokes every workspace lease");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.click_count(), 0);
}

#[test]
fn policy_drift_still_fails_closed_with_epoch_binding() {
    let (adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let binding = grant(&mut registry, &coord_id, derivation_generation);
    let drifted = registry.execute_input(
        &adapter,
        &binding.lease_id,
        WORKSPACE,
        "sg-000036-v1",
        NOW + 1,
    );
    assert_eq!(
        drifted.expect_err("policy drift must fail").code,
        FailureCode::TargetStale
    );
    assert_eq!(adapter.click_count(), 0);
}

#[test]
fn interruption_evidence_is_bounded_and_secret_free() {
    let (_adapter, mut registry, _coord, _generation) = setup_coord();
    let evidence = registry
        .report_human_interruption("human-mouse-move", WORKSPACE, POLICY, NOW)
        .unwrap();
    assert_eq!(evidence["schema"], INTERRUPT_SCHEMA);
    for key in [
        "keystroke",
        "keys",
        "text",
        "pointer",
        "path",
        "pixels",
        "password",
        "secret",
        "token",
        "cookie",
        "approval",
    ] {
        assert!(
            evidence.get(key).is_none(),
            "interruption evidence must not carry {key}"
        );
    }
    let serialized = serde_json::to_vec(&evidence).expect("evidence serializes");
    assert!(serialized.len() <= MAX_RESPONSE_BYTES);
}

#[test]
fn protected_surface_remains_denied_with_epoch_binding() {
    let adapter = FakeInterruptAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(
        4242,
        vec![fake_window(200, "Orcel Approval", "orcelapprove-dialog", 1)],
    );
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    assert_eq!(list["window_count"], 0);
    assert_eq!(list["protected_omitted"], 1);
}

#[test]
fn execution_evidence_carries_the_grant_epoch() {
    let (adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let binding = grant(&mut registry, &coord_id, derivation_generation);
    let result = registry
        .execute_input(&adapter, &binding.lease_id, WORKSPACE, POLICY, NOW + 1)
        .unwrap();
    assert_eq!(result["interruption_epoch"], 0);
    assert_eq!(result["lease_id"], binding.lease_id);
}

#[test]
fn native_adapter_reports_execution_unavailable_without_fabrication() {
    let (_adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    assert_eq!(registry.interruption_epoch(), 0);
    let binding = grant(&mut registry, &coord_id, derivation_generation);
    let native = NativeAdapter::new();
    let live = registry.execute_input(&native, &binding.lease_id, WORKSPACE, POLICY, NOW + 1);
    assert_eq!(
        live.expect_err("live execution must be unavailable").code,
        FailureCode::ProviderUnavailable
    );
    assert_eq!(registry.lease_consumed(&binding.lease_id), Some(false));
}
