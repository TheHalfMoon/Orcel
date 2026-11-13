//! SG-000036 deterministic bounded coordinate execution tests.
//!
//! These tests use an injected fake adapter, so they prove lease grant,
//! single-use consumption, expiry, operation confinement, stale
//! fail-closed behavior, protected-surface exclusion, approval digest
//! shape, and window confinement deterministically on every platform
//! without a live desktop. Real Windows process identity is proven
//! separately through the native adapter test, and live execution is
//! reported as unavailable instead of fabricated.

use super::*;
use std::cell::RefCell;
use std::collections::HashMap;

const WORKSPACE: &str = "execute-test-workspace";
const POLICY: &str = "sg-000036-v1";
const NOW: u64 = 1_000_000;

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
struct FakeExecuteState {
    processes: Vec<NativeProcess>,
    windows_by_pid: HashMap<u32, Vec<NativeWindow>>,
    images_by_hwnd: HashMap<u64, CapturedImage>,
    clicks: Vec<(u64, u64, u64)>,
    fail_execute: bool,
}

#[derive(Default)]
struct FakeExecuteAdapter {
    state: RefCell<FakeExecuteState>,
}

impl FakeExecuteAdapter {
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

    fn set_fail_execute(&self, fail: bool) {
        self.state.borrow_mut().fail_execute = fail;
    }

    fn click_count(&self) -> usize {
        self.state.borrow().clicks.len()
    }
}

impl UiaAdapter for FakeExecuteAdapter {
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
        let mut state = self.state.borrow_mut();
        if state.fail_execute {
            return Err(UiaError::new(
                FailureCode::ProviderUnavailable,
                "fake execution broker is unavailable",
            ));
        }
        state.clicks.push((hwnd, x, y));
        Ok(())
    }
}

fn setup_coord() -> (FakeExecuteAdapter, UiaRegistry, String, u64) {
    let adapter = FakeExecuteAdapter::with_process(4242, "notepad", 9001);
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

fn mint_coord(adapter: &FakeExecuteAdapter, registry: &mut UiaRegistry) -> (String, u64) {
    let list = registry.list_windows(adapter, WORKSPACE, POLICY).unwrap();
    let window_id = list["windows"][0]["window_id"]
        .as_str()
        .expect("window id")
        .to_owned();
    let window_generation = list["windows"][0]["window_generation"]
        .as_u64()
        .expect("window generation");
    let capture = registry
        .capture_window(
            adapter,
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
                x: 0,
                y: 0,
                width: 2,
                height: 2,
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
    (
        derived["coord_id"].as_str().expect("coord id").to_owned(),
        derived["derivation_generation"]
            .as_u64()
            .expect("derivation generation"),
    )
}

#[test]
fn execute_shape_operation_and_lease_helpers_behave() {
    assert!(is_input_execute_shape("uia.input", "execute"));
    assert!(!is_input_execute_shape("uia.input", "keyboard"));
    assert!(!is_input_execute_shape("uia.input", "mouse"));
    assert!(!is_input_execute_shape("uia.input", "sendinput"));
    assert!(!is_input_execute_shape("uia.coordinates", "propose"));
    assert!(!is_input_execute_shape("uia.visual", "propose"));
    assert!(!is_input_execute_shape("uia.elevation", "request"));
    assert!(is_execute_operation("click"));
    assert!(!is_execute_operation("double-click"));
    assert!(!is_execute_operation("keyboard"));
    assert!(!is_execute_operation("drag"));
    assert!(!is_execute_operation(""));
    assert!(is_well_formed_lease_id("uia-lease-0123456789abcdef"));
    assert!(!is_well_formed_lease_id("uia-lease-0123456789ABCDEF"));
    assert!(!is_well_formed_lease_id("uia-lease-short"));
    assert!(!is_well_formed_lease_id("uia-coord-0123456789abcdef"));
    assert!(!is_well_formed_lease_id("caller-lease-1"));
    assert!(is_denied_uia_shape("uia.input", "keyboard"));
    assert!(is_denied_uia_shape("uia.input", "mouse"));
    assert!(is_denied_uia_shape("uia.input", "sendinput"));
    assert!(!is_denied_uia_shape("uia.input", "execute"));
    assert!(!is_allowed_uia_shape("uia.input", "execute"));
    assert_eq!(LEASE_TTL_MS, 60_000);
}

#[test]
fn happy_path_click_executes_once_with_lease_evidence() {
    let (adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let binding = grant(&mut registry, &coord_id, derivation_generation);
    assert_eq!(binding.operation, "click");
    assert!(is_well_formed_lease_id(&binding.lease_id));
    assert_eq!(binding.lease_expires_at_ms, NOW + LEASE_TTL_MS);
    assert_eq!((binding.x, binding.y), (3, 2));
    assert_eq!(registry.lease_count(), 1);
    let result = registry
        .execute_input(&adapter, &binding.lease_id, WORKSPACE, POLICY, NOW + 1)
        .unwrap();
    assert_eq!(result["schema"], EXECUTE_SCHEMA);
    assert_eq!(result["action"], "execute");
    assert_eq!(result["operation"], "click");
    assert_eq!(result["lease_id"], binding.lease_id);
    assert_eq!(result["coord_id"], coord_id);
    assert_eq!(result["x"], 3);
    assert_eq!(result["y"], 2);
    assert_eq!(adapter.click_count(), 1);
    let clicks = adapter.state.borrow().clicks.clone();
    assert_eq!(clicks[0], (100, 3, 2));
    assert_eq!(registry.lease_consumed(&binding.lease_id), Some(true));
    for key in [
        "keyboard",
        "drag",
        "sendinput",
        "mouse",
        "lease_transfer",
        "pixels",
    ] {
        assert!(result.get(key).is_none(), "execution must not carry {key}");
    }
}

#[test]
fn replayed_lease_fails_closed_without_second_actuation() {
    let (adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let binding = grant(&mut registry, &coord_id, derivation_generation);
    registry
        .execute_input(&adapter, &binding.lease_id, WORKSPACE, POLICY, NOW + 1)
        .unwrap();
    let replay = registry.execute_input(&adapter, &binding.lease_id, WORKSPACE, POLICY, NOW + 2);
    assert_eq!(
        replay.expect_err("lease replay must fail").code,
        FailureCode::TargetStale
    );
    assert_eq!(adapter.click_count(), 1);
}

#[test]
fn non_click_operations_are_denied_without_minting_leases() {
    let (_adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    for operation in ["keyboard", "drag", "double-click", "wheel", "focus", ""] {
        let error = registry
            .grant_input_lease(
                &coord_id,
                derivation_generation,
                operation,
                WORKSPACE,
                POLICY,
                NOW,
            )
            .expect_err("non-click operation must fail");
        assert_eq!(error.code, FailureCode::CapabilityDenied);
    }
    assert_eq!(registry.lease_count(), 0);
}

#[test]
fn malformed_and_foreign_leases_fail_closed() {
    let (adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let malformed = registry.execute_input(&adapter, "not-a-lease", WORKSPACE, POLICY, NOW);
    assert_eq!(
        malformed.expect_err("malformed lease must fail").code,
        FailureCode::InvalidRequest
    );
    let forged = registry.execute_input(
        &adapter,
        "uia-lease-ffffffffffffffff",
        WORKSPACE,
        POLICY,
        NOW,
    );
    assert_eq!(
        forged.expect_err("foreign lease must fail").code,
        FailureCode::TargetStale
    );
    let binding = grant(&mut registry, &coord_id, derivation_generation);
    let foreign_workspace = registry.execute_input(
        &adapter,
        &binding.lease_id,
        "other-workspace",
        POLICY,
        NOW + 1,
    );
    assert_eq!(
        foreign_workspace
            .expect_err("workspace drift must fail")
            .code,
        FailureCode::TargetStale
    );
    let drifted_policy = registry.execute_input(
        &adapter,
        &binding.lease_id,
        WORKSPACE,
        "sg-000035-v1",
        NOW + 1,
    );
    assert_eq!(
        drifted_policy.expect_err("policy drift must fail").code,
        FailureCode::TargetStale
    );
    assert_eq!(adapter.click_count(), 0);
}

#[test]
fn expired_lease_fails_closed_and_is_swept() {
    let (adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let binding = grant(&mut registry, &coord_id, derivation_generation);
    let expired = registry.execute_input(
        &adapter,
        &binding.lease_id,
        WORKSPACE,
        POLICY,
        NOW + LEASE_TTL_MS + 1,
    );
    assert_eq!(
        expired.expect_err("expired lease must fail").code,
        FailureCode::TargetStale
    );
    assert_eq!(adapter.click_count(), 0);
    assert_eq!(registry.lease_count(), 0);
}

#[test]
fn stale_chain_grants_and_executions_fail_closed() {
    let (_adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let unknown = registry.grant_input_lease(
        "uia-coord-ffffffffffffffff",
        derivation_generation,
        "click",
        WORKSPACE,
        POLICY,
        NOW,
    );
    assert_eq!(
        unknown.expect_err("unknown coordinate must fail").code,
        FailureCode::TargetStale
    );
    let drifted = registry.grant_input_lease(
        &coord_id,
        derivation_generation + 1,
        "click",
        WORKSPACE,
        POLICY,
        NOW,
    );
    assert_eq!(
        drifted.expect_err("generation drift must fail").code,
        FailureCode::TargetStale
    );
    let foreign = registry.grant_input_lease(
        &coord_id,
        derivation_generation,
        "click",
        "other-workspace",
        POLICY,
        NOW,
    );
    assert_eq!(
        foreign.expect_err("workspace drift must fail").code,
        FailureCode::TargetStale
    );
    assert_eq!(registry.lease_count(), 0);
}

#[test]
fn replaced_window_revokes_live_lease() {
    let (adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let binding = grant(&mut registry, &coord_id, derivation_generation);
    let window_id = binding.window_id.clone();
    assert!(registry.bump_window_generation(&window_id));
    let error = registry.execute_input(&adapter, &binding.lease_id, WORKSPACE, POLICY, NOW + 1);
    assert_eq!(
        error
            .expect_err("replaced window must revoke the lease")
            .code,
        FailureCode::TargetStale
    );
    assert_eq!(adapter.click_count(), 0);
}

#[test]
fn superseded_process_revokes_live_lease() {
    let (adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let binding = grant(&mut registry, &coord_id, derivation_generation);
    let list = registry
        .list_windows(&adapter, WORKSPACE, POLICY)
        .expect("re-list");
    let process_id = list["windows"][0]["process_id"]
        .as_str()
        .expect("process id")
        .to_owned();
    assert!(registry.mark_process_superseded(&process_id));
    let error = registry.execute_input(&adapter, &binding.lease_id, WORKSPACE, POLICY, NOW + 1);
    assert_eq!(
        error
            .expect_err("superseded process must revoke the lease")
            .code,
        FailureCode::TargetStale
    );
    assert_eq!(adapter.click_count(), 0);
}

#[test]
fn execution_approval_digest_binds_complete_material() {
    let (_adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let binding = grant(&mut registry, &coord_id, derivation_generation);
    let first = execute_approval_digest(WORKSPACE, POLICY, &binding);
    assert_eq!(first.len(), 64);
    assert!(first.chars().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(first, execute_approval_digest(WORKSPACE, POLICY, &binding));
    assert_ne!(first, execute_approval_digest("other", POLICY, &binding));
    assert_ne!(
        first,
        execute_approval_digest(WORKSPACE, "sg-000035-v1", &binding)
    );
    let mut drifted_lease = binding.clone();
    drifted_lease.lease_id = "uia-lease-ffffffffffffffff".to_owned();
    assert_ne!(
        first,
        execute_approval_digest(WORKSPACE, POLICY, &drifted_lease)
    );
    let mut drifted_coords = binding.clone();
    drifted_coords.x += 1;
    assert_ne!(
        first,
        execute_approval_digest(WORKSPACE, POLICY, &drifted_coords)
    );
    let mut drifted_op = binding.clone();
    drifted_op.operation = "drag".to_owned();
    assert_ne!(
        first,
        execute_approval_digest(WORKSPACE, POLICY, &drifted_op)
    );
}

#[test]
fn adapter_failure_does_not_consume_the_lease() {
    let (adapter, mut registry, coord_id, derivation_generation) = setup_coord();
    let binding = grant(&mut registry, &coord_id, derivation_generation);
    adapter.set_fail_execute(true);
    let error = registry.execute_input(&adapter, &binding.lease_id, WORKSPACE, POLICY, NOW + 1);
    assert_eq!(
        error.expect_err("adapter failure must fail").code,
        FailureCode::ProviderUnavailable
    );
    assert_eq!(registry.lease_consumed(&binding.lease_id), Some(false));
    adapter.set_fail_execute(false);
    registry
        .execute_input(&adapter, &binding.lease_id, WORKSPACE, POLICY, NOW + 2)
        .expect("retry after adapter recovery executes");
    assert_eq!(adapter.click_count(), 1);
}

#[test]
fn lease_bound_denies_standing_input_sessions() {
    let (adapter, mut registry, _coord_id, _derivation_generation) = setup_coord();
    let mut leases = Vec::new();
    for _ in 0..MAX_LEASES {
        let (fresh_id, fresh_generation) = mint_coord(&adapter, &mut registry);
        let binding = registry
            .grant_input_lease(&fresh_id, fresh_generation, "click", WORKSPACE, POLICY, NOW)
            .expect("grant within bound");
        leases.push(binding.lease_id);
    }
    assert_eq!(leases.len(), MAX_LEASES);
    let (fresh_id, fresh_generation) = mint_coord(&adapter, &mut registry);
    let overflow =
        registry.grant_input_lease(&fresh_id, fresh_generation, "click", WORKSPACE, POLICY, NOW);
    assert_eq!(
        overflow.expect_err("lease bound must fail closed").code,
        FailureCode::OutputLimit
    );
    let recovered = registry.grant_input_lease(
        &fresh_id,
        fresh_generation,
        "click",
        WORKSPACE,
        POLICY,
        NOW + LEASE_TTL_MS + 1,
    );
    assert!(recovered.is_ok(), "expiry sweep must free the bound");
}

#[test]
fn native_adapter_reports_execution_unavailable_without_fabrication() {
    let adapter = NativeAdapter::new();
    let error = adapter
        .execute_click(12345, 3, 2)
        .expect_err("headless execution must fail closed");
    assert_eq!(error.code, FailureCode::ProviderUnavailable);
}
