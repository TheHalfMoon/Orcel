//! SG-000034 deterministic non-actuating visual target proposal tests.
//!
//! These tests use an injected fake adapter for the underlying capture,
//! so they prove proposal binding, proposal identity, stale fail-closed
//! behavior, region confinement, protected-surface exclusion, approval
//! digest shape, and non-actuation deterministically on every platform
//! without a live desktop. Proposals mint no pixels and perform no input.

use super::*;
use std::cell::RefCell;
use std::collections::HashMap;

const WORKSPACE: &str = "visual-test-workspace";
const POLICY: &str = "sg-000034-v1";

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
struct FakeProposalState {
    processes: Vec<NativeProcess>,
    windows_by_pid: HashMap<u32, Vec<NativeWindow>>,
    images_by_hwnd: HashMap<u64, CapturedImage>,
}

#[derive(Default)]
struct FakeProposalAdapter {
    state: RefCell<FakeProposalState>,
}

impl FakeProposalAdapter {
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
}

impl UiaAdapter for FakeProposalAdapter {
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
}

fn setup_frame() -> (FakeProposalAdapter, UiaRegistry, String, u64) {
    let adapter = FakeProposalAdapter::with_process(4242, "notepad", 9001);
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
    (adapter, registry, frame_id, capture_generation)
}

fn region(x: u64, y: u64, width: u64, height: u64) -> VisualRegion {
    VisualRegion {
        x,
        y,
        width,
        height,
    }
}

#[test]
fn visual_shape_and_proposal_identity_helpers_behave() {
    assert!(is_visual_propose_shape("uia.visual", "propose"));
    assert!(!is_visual_propose_shape("uia.visual", "capture"));
    assert!(!is_visual_propose_shape("uia.visual", "execute"));
    assert!(!is_visual_propose_shape("uia.coordinates", "propose"));
    assert!(!is_visual_propose_shape("uia.coordinates", "request"));
    assert!(!is_visual_propose_shape("uia.screenshot", "capture"));
    assert!(!is_visual_propose_shape("uia.input", "mouse"));
    assert!(!is_visual_propose_shape("uia.input", "keyboard"));
    assert!(!is_visual_propose_shape("uia.element", "scroll"));
    assert!(is_capture_shape("uia.screenshot", "capture"));
    assert!(is_well_formed_proposal_id("uia-prop-0123456789abcdef"));
    assert!(!is_well_formed_proposal_id("uia-prop-0123456789ABCDEF"));
    assert!(!is_well_formed_proposal_id("uia-prop-short"));
    assert!(!is_well_formed_proposal_id("uia-frame-0123456789abcdef"));
    assert!(!is_well_formed_proposal_id("caller-prop-1"));
    assert!(!is_allowed_uia_shape("uia.visual", "propose"));
    assert!(!is_denied_uia_shape("uia.visual", "propose"));
    assert!(is_denied_uia_shape("uia.coordinates", "request"));
    assert!(is_denied_uia_shape("uia.input", "mouse"));
    assert!(is_denied_uia_shape("uia.clipboard", "read"));
    assert!(is_denied_uia_shape("uia.network", "fetch"));
    assert!(is_denied_uia_shape("uia.elevation", "request"));
}

#[test]
fn happy_path_proposal_mints_server_allocated_identity() {
    let (_adapter, mut registry, frame_id, capture_generation) = setup_frame();
    let result = registry
        .propose_visual_target(
            &frame_id,
            capture_generation,
            region(1, 1, 4, 3),
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    assert_eq!(result["schema"], VISUAL_SCHEMA);
    assert_eq!(result["action"], "propose");
    assert_eq!(result["frame_id"], frame_id);
    assert_eq!(result["capture_generation"], capture_generation);
    assert_eq!(result["proposal_generation"], 1);
    assert_eq!(result["region"]["x"], 1);
    assert_eq!(result["region"]["y"], 1);
    assert_eq!(result["region"]["width"], 4);
    assert_eq!(result["region"]["height"], 3);
    assert_eq!(result["frame_width"], 8);
    assert_eq!(result["frame_height"], 6);
    assert_eq!(result["truncated"], false);
    let proposal_id = result["proposal_id"].as_str().expect("proposal id");
    assert!(is_well_formed_proposal_id(proposal_id));
    assert_eq!(registry.proposal_count(), 1);
    assert!(result.get("coordinates").is_none());
    assert!(result.get("click").is_none());
    assert!(result.get("mouse").is_none());
    assert!(result.get("keyboard").is_none());
    assert!(result.get("pixels").is_none());
}

#[test]
fn full_frame_region_is_accepted_and_second_proposal_advances() {
    let (_adapter, mut registry, frame_id, capture_generation) = setup_frame();
    let first = registry
        .propose_visual_target(
            &frame_id,
            capture_generation,
            region(0, 0, 8, 6),
            WORKSPACE,
            POLICY,
        )
        .expect("full-frame region is inside the geometry");
    let second = registry
        .propose_visual_target(
            &frame_id,
            capture_generation,
            region(0, 0, 1, 1),
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    assert_ne!(first["proposal_id"], second["proposal_id"]);
    assert_eq!(second["proposal_generation"], 2);
    assert_eq!(registry.proposal_count(), 2);
}

#[test]
fn describe_proposal_validates_generation_workspace_and_policy() {
    let (_adapter, mut registry, frame_id, capture_generation) = setup_frame();
    let result = registry
        .propose_visual_target(
            &frame_id,
            capture_generation,
            region(2, 2, 2, 2),
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    let proposal_id = result["proposal_id"]
        .as_str()
        .expect("proposal id")
        .to_owned();
    let generation = result["proposal_generation"].as_u64().expect("generation");
    let described = registry
        .describe_proposal(&proposal_id, generation, WORKSPACE, POLICY)
        .unwrap();
    assert_eq!(described["proposal_id"], proposal_id);
    assert_eq!(described["frame_id"], frame_id);
    assert_eq!(described["region"]["width"], 2);
    let drifted = registry.describe_proposal(&proposal_id, generation + 1, WORKSPACE, POLICY);
    assert_eq!(
        drifted.expect_err("generation drift must fail").code,
        FailureCode::TargetStale
    );
    let foreign = registry.describe_proposal(&proposal_id, generation, "other", POLICY);
    assert_eq!(
        foreign.expect_err("workspace drift must fail").code,
        FailureCode::TargetStale
    );
    let policy = registry.describe_proposal(&proposal_id, generation, WORKSPACE, "sg-000033-v1");
    assert_eq!(
        policy.expect_err("policy drift must fail").code,
        FailureCode::TargetStale
    );
    let malformed = registry.describe_proposal("caller-prop-1", generation, WORKSPACE, POLICY);
    assert_eq!(
        malformed.expect_err("malformed proposal must fail").code,
        FailureCode::InvalidRequest
    );
    let forged =
        registry.describe_proposal("uia-prop-ffffffffffffffff", generation, WORKSPACE, POLICY);
    assert_eq!(
        forged.expect_err("forged proposal must fail").code,
        FailureCode::TargetStale
    );
}

#[test]
fn malformed_unknown_and_stale_frames_fail_closed() {
    let (_adapter, mut registry, frame_id, capture_generation) = setup_frame();
    let malformed = registry.propose_visual_target(
        "not-a-frame",
        capture_generation,
        region(0, 0, 1, 1),
        WORKSPACE,
        POLICY,
    );
    assert_eq!(
        malformed.expect_err("malformed frame must fail").code,
        FailureCode::InvalidRequest
    );
    let unknown = registry.propose_visual_target(
        "uia-frame-ffffffffffffffff",
        capture_generation,
        region(0, 0, 1, 1),
        WORKSPACE,
        POLICY,
    );
    assert_eq!(
        unknown.expect_err("unknown frame must fail").code,
        FailureCode::TargetStale
    );
    let drifted = registry.propose_visual_target(
        &frame_id,
        capture_generation + 1,
        region(0, 0, 1, 1),
        WORKSPACE,
        POLICY,
    );
    assert_eq!(
        drifted.expect_err("generation drift must fail").code,
        FailureCode::TargetStale
    );
    assert_eq!(registry.proposal_count(), 0);
}

#[test]
fn replaced_window_stales_frame_and_proposal() {
    let (_adapter, mut registry, frame_id, capture_generation) = setup_frame();
    let proposal = registry
        .propose_visual_target(
            &frame_id,
            capture_generation,
            region(0, 0, 2, 2),
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
        .expect("generation");
    let window_id = proposal["window_id"]
        .as_str()
        .expect("window id")
        .to_owned();
    assert!(registry.bump_window_generation(&window_id));
    let stale_propose = registry.propose_visual_target(
        &frame_id,
        capture_generation,
        region(0, 0, 1, 1),
        WORKSPACE,
        POLICY,
    );
    assert_eq!(
        stale_propose.expect_err("replaced window must fail").code,
        FailureCode::TargetStale
    );
    let stale_describe =
        registry.describe_proposal(&proposal_id, proposal_generation, WORKSPACE, POLICY);
    assert_eq!(
        stale_describe.expect_err("proposal must stale").code,
        FailureCode::TargetStale
    );
}

#[test]
fn empty_oversized_external_and_overflowing_regions_fail_closed() {
    let (_adapter, mut registry, frame_id, capture_generation) = setup_frame();
    for bad in [
        region(0, 0, 0, 1),
        region(0, 0, 1, 0),
        region(0, 0, 9, 6),
        region(0, 0, 8, 7),
        region(7, 5, 2, 2),
        region(8, 0, 1, 1),
        region(0, 6, 1, 1),
        region(u64::MAX, 0, 1, 1),
        region(0, 0, u64::MAX, 1),
    ] {
        let error = registry
            .propose_visual_target(&frame_id, capture_generation, bad, WORKSPACE, POLICY)
            .expect_err("bad region must fail");
        assert_eq!(error.code, FailureCode::InvalidRequest);
    }
    assert_eq!(registry.proposal_count(), 0);
}

#[test]
fn workspace_and_policy_drift_fail_closed() {
    let (_adapter, mut registry, frame_id, capture_generation) = setup_frame();
    let foreign = registry.propose_visual_target(
        &frame_id,
        capture_generation,
        region(0, 0, 1, 1),
        "other-workspace",
        POLICY,
    );
    assert_eq!(
        foreign.expect_err("workspace drift must fail").code,
        FailureCode::TargetStale
    );
    let drifted = registry.propose_visual_target(
        &frame_id,
        capture_generation,
        region(0, 0, 1, 1),
        WORKSPACE,
        "sg-000033-v1",
    );
    assert_eq!(
        drifted.expect_err("policy drift must fail").code,
        FailureCode::TargetStale
    );
    assert_eq!(registry.proposal_count(), 0);
}

#[test]
fn superseded_process_stales_frame_and_proposal() {
    let (adapter, mut registry, frame_id, capture_generation) = setup_frame();
    let proposal = registry
        .propose_visual_target(
            &frame_id,
            capture_generation,
            region(0, 0, 2, 2),
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
        .expect("generation");
    let list = registry
        .list_windows(&adapter, WORKSPACE, POLICY)
        .expect("re-list");
    let process_id = list["windows"][0]["process_id"]
        .as_str()
        .expect("process id")
        .to_owned();
    assert!(registry.mark_process_superseded(&process_id));
    let error = registry
        .propose_visual_target(
            &frame_id,
            capture_generation,
            region(0, 0, 1, 1),
            WORKSPACE,
            POLICY,
        )
        .expect_err("superseded process must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    let stale = registry.describe_proposal(&proposal_id, proposal_generation, WORKSPACE, POLICY);
    assert_eq!(
        stale.expect_err("proposal must stale").code,
        FailureCode::TargetStale
    );
    assert_eq!(registry.proposal_count(), 1);
}

#[test]
fn protected_orcel_surface_cannot_yield_frames_or_proposals() {
    let adapter = FakeProposalAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(
        4242,
        vec![fake_window(
            200,
            "Orcel Approval Dialog",
            "OrcelApproveWnd",
            7,
        )],
    );
    adapter.set_image(200, deterministic_image(200));
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    assert_eq!(list["window_count"], 0);
    assert_eq!(list["protected_omitted"], 1);
    assert_eq!(registry.frame_count(), 0);
    let forged = registry.propose_visual_target(
        "uia-frame-ffffffffffffffff",
        1,
        region(0, 0, 1, 1),
        WORKSPACE,
        POLICY,
    );
    assert_eq!(
        forged.expect_err("no proposal without a frame").code,
        FailureCode::TargetStale
    );
    assert_eq!(registry.proposal_count(), 0);
}

#[test]
fn proposal_approval_digest_binds_complete_material() {
    let (_adapter, registry, frame_id, capture_generation) = setup_frame();
    let binding = registry
        .proposal_binding(
            &frame_id,
            capture_generation,
            region(1, 1, 4, 3),
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    let first = visual_proposal_digest(WORKSPACE, POLICY, &binding);
    assert_eq!(first.len(), 64);
    assert!(first.chars().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(first, visual_proposal_digest(WORKSPACE, POLICY, &binding));
    assert_ne!(first, visual_proposal_digest("other", POLICY, &binding));
    assert_ne!(
        first,
        visual_proposal_digest(WORKSPACE, "sg-000033-v1", &binding)
    );
    let mut moved_region = binding.clone();
    moved_region.region.x += 1;
    assert_ne!(
        first,
        visual_proposal_digest(WORKSPACE, POLICY, &moved_region)
    );
    let mut drifted_frame = binding.clone();
    drifted_frame.capture_generation += 1;
    assert_ne!(
        first,
        visual_proposal_digest(WORKSPACE, POLICY, &drifted_frame)
    );
}

#[test]
fn proposal_binding_matches_pre_proposal_revalidation() {
    let (_adapter, mut registry, frame_id, capture_generation) = setup_frame();
    let binding = registry
        .proposal_binding(
            &frame_id,
            capture_generation,
            region(0, 0, 2, 2),
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    assert_eq!(binding.frame_id, frame_id);
    assert_eq!(binding.capture_generation, capture_generation);
    assert_eq!(binding.frame_width, 8);
    assert_eq!(binding.frame_height, 6);
    let window_id = binding.window_id.clone();
    assert!(registry.bump_window_generation(&window_id));
    let stale = registry.proposal_binding(
        &frame_id,
        capture_generation,
        region(0, 0, 2, 2),
        WORKSPACE,
        POLICY,
    );
    assert_eq!(
        stale.expect_err("binding must revalidate").code,
        FailureCode::TargetStale
    );
}

#[test]
fn proposals_grant_no_coordinate_or_input_authority() {
    let (_adapter, mut registry, frame_id, capture_generation) = setup_frame();
    let result = registry
        .propose_visual_target(
            &frame_id,
            capture_generation,
            region(3, 2, 2, 2),
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    assert_eq!(result["action"], "propose");
    for key in [
        "coordinate",
        "coordinates",
        "click",
        "mouse",
        "keyboard",
        "sendinput",
        "input",
        "lease",
        "execute",
        "execution",
    ] {
        assert!(result.get(key).is_none(), "proposal must not carry {key}");
    }
    assert!(!is_visual_propose_shape("uia.input", "mouse"));
    assert!(!is_visual_propose_shape("uia.coordinates", "request"));
    assert!(!is_visual_propose_shape("uia.elevation", "request"));
}
