//! SG-000035 deterministic proposal-only coordinate derivation tests.
//!
//! These tests use an injected fake adapter for the underlying capture,
//! so they prove derivation binding, coordinate identity, stale
//! fail-closed behavior, caller-coordinate denial, protected-surface
//! exclusion, approval digest shape, and non-actuation deterministically
//! on every platform without a live desktop. Derivation is pure registry
//! computation and never calls any input API.

use super::*;
use std::cell::RefCell;
use std::collections::HashMap;

const WORKSPACE: &str = "coordinate-test-workspace";
const POLICY: &str = "sg-000035-v1";

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
struct FakeDerivationState {
    processes: Vec<NativeProcess>,
    windows_by_pid: HashMap<u32, Vec<NativeWindow>>,
    images_by_hwnd: HashMap<u64, CapturedImage>,
}

#[derive(Default)]
struct FakeDerivationAdapter {
    state: RefCell<FakeDerivationState>,
}

impl FakeDerivationAdapter {
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

impl UiaAdapter for FakeDerivationAdapter {
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

fn setup_proposal() -> (FakeDerivationAdapter, UiaRegistry, String, u64) {
    let adapter = FakeDerivationAdapter::with_process(4242, "notepad", 9001);
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
    (adapter, registry, proposal_id, proposal_generation)
}

#[test]
fn coordinate_shape_and_identity_helpers_behave() {
    assert!(is_coordinate_propose_shape("uia.coordinates", "propose"));
    assert!(!is_coordinate_propose_shape("uia.coordinates", "request"));
    assert!(!is_coordinate_propose_shape("uia.coordinates", "execute"));
    assert!(!is_coordinate_propose_shape("uia.visual", "propose"));
    assert!(!is_coordinate_propose_shape("uia.screenshot", "capture"));
    assert!(!is_coordinate_propose_shape("uia.input", "mouse"));
    assert!(!is_coordinate_propose_shape("uia.elevation", "request"));
    assert!(is_denied_uia_shape("uia.coordinates", "request"));
    assert!(!is_denied_uia_shape("uia.coordinates", "propose"));
    assert!(!is_allowed_uia_shape("uia.coordinates", "propose"));
    assert!(is_well_formed_coord_id("uia-coord-0123456789abcdef"));
    assert!(!is_well_formed_coord_id("uia-coord-0123456789ABCDEF"));
    assert!(!is_well_formed_coord_id("uia-coord-short"));
    assert!(!is_well_formed_coord_id("uia-prop-0123456789abcdef"));
    assert!(!is_well_formed_coord_id("caller-coord-1"));
    let center = derive_region_center(VisualRegion {
        x: 1,
        y: 1,
        width: 4,
        height: 3,
    });
    assert_eq!(center, DerivedCoordinate { x: 3, y: 2 });
    assert!(is_denied_uia_shape("uia.input", "mouse"));
    assert!(is_denied_uia_shape("uia.input", "keyboard"));
    assert!(is_denied_uia_shape("uia.input", "sendinput"));
    assert!(is_denied_uia_shape("uia.clipboard", "read"));
    assert!(is_denied_uia_shape("uia.network", "fetch"));
    assert!(is_denied_uia_shape("uia.elevation", "request"));
}

#[test]
fn happy_path_derivation_mints_server_allocated_identity() {
    let (_adapter, mut registry, proposal_id, proposal_generation) = setup_proposal();
    let result = registry
        .derive_coordinates(&proposal_id, proposal_generation, WORKSPACE, POLICY)
        .unwrap();
    assert_eq!(result["schema"], COORD_SCHEMA);
    assert_eq!(result["action"], "propose");
    assert_eq!(result["proposal_id"], proposal_id);
    assert_eq!(result["proposal_generation"], proposal_generation);
    assert_eq!(result["derivation_generation"], 1);
    assert_eq!(result["x"], 3);
    assert_eq!(result["y"], 2);
    assert_eq!(result["frame_width"], 8);
    assert_eq!(result["frame_height"], 6);
    assert_eq!(result["truncated"], false);
    let coord_id = result["coord_id"].as_str().expect("coord id");
    assert!(is_well_formed_coord_id(coord_id));
    assert_eq!(registry.coordinate_count(), 1);
    for key in [
        "click",
        "mouse",
        "keyboard",
        "sendinput",
        "input",
        "lease",
        "execute",
        "execution",
        "pixels",
    ] {
        assert!(result.get(key).is_none(), "derivation must not carry {key}");
    }
}

#[test]
fn derivation_is_deterministic_and_second_derivation_advances() {
    let (_adapter, mut registry, proposal_id, proposal_generation) = setup_proposal();
    let first = registry
        .derive_coordinates(&proposal_id, proposal_generation, WORKSPACE, POLICY)
        .unwrap();
    let second = registry
        .derive_coordinates(&proposal_id, proposal_generation, WORKSPACE, POLICY)
        .unwrap();
    assert_eq!(first["x"], second["x"]);
    assert_eq!(first["y"], second["y"]);
    assert_ne!(first["coord_id"], second["coord_id"]);
    assert_eq!(second["derivation_generation"], 2);
    assert_eq!(registry.coordinate_count(), 2);
}

#[test]
fn describe_coordinates_validates_generation_workspace_and_policy() {
    let (_adapter, mut registry, proposal_id, proposal_generation) = setup_proposal();
    let result = registry
        .derive_coordinates(&proposal_id, proposal_generation, WORKSPACE, POLICY)
        .unwrap();
    let coord_id = result["coord_id"].as_str().expect("coord id").to_owned();
    let generation = result["derivation_generation"]
        .as_u64()
        .expect("generation");
    let described = registry
        .describe_coordinates(&coord_id, generation, WORKSPACE, POLICY)
        .unwrap();
    assert_eq!(described["coord_id"], coord_id);
    assert_eq!(described["proposal_id"], proposal_id);
    assert_eq!(described["x"], 3);
    assert_eq!(described["y"], 2);
    let drifted = registry.describe_coordinates(&coord_id, generation + 1, WORKSPACE, POLICY);
    assert_eq!(
        drifted.expect_err("generation drift must fail").code,
        FailureCode::TargetStale
    );
    let foreign = registry.describe_coordinates(&coord_id, generation, "other", POLICY);
    assert_eq!(
        foreign.expect_err("workspace drift must fail").code,
        FailureCode::TargetStale
    );
    let policy = registry.describe_coordinates(&coord_id, generation, WORKSPACE, "sg-000034-v1");
    assert_eq!(
        policy.expect_err("policy drift must fail").code,
        FailureCode::TargetStale
    );
    let malformed = registry.describe_coordinates("caller-coord-1", generation, WORKSPACE, POLICY);
    assert_eq!(
        malformed.expect_err("malformed identity must fail").code,
        FailureCode::InvalidRequest
    );
    let forged =
        registry.describe_coordinates("uia-coord-ffffffffffffffff", generation, WORKSPACE, POLICY);
    assert_eq!(
        forged.expect_err("forged identity must fail").code,
        FailureCode::TargetStale
    );
}

#[test]
fn malformed_unknown_and_stale_proposals_fail_closed() {
    let (_adapter, mut registry, proposal_id, proposal_generation) = setup_proposal();
    let malformed =
        registry.derive_coordinates("not-a-proposal", proposal_generation, WORKSPACE, POLICY);
    assert_eq!(
        malformed.expect_err("malformed proposal must fail").code,
        FailureCode::InvalidRequest
    );
    let unknown = registry.derive_coordinates(
        "uia-prop-ffffffffffffffff",
        proposal_generation,
        WORKSPACE,
        POLICY,
    );
    assert_eq!(
        unknown.expect_err("unknown proposal must fail").code,
        FailureCode::TargetStale
    );
    let drifted =
        registry.derive_coordinates(&proposal_id, proposal_generation + 1, WORKSPACE, POLICY);
    assert_eq!(
        drifted.expect_err("generation drift must fail").code,
        FailureCode::TargetStale
    );
    assert_eq!(registry.coordinate_count(), 0);
}

#[test]
fn replaced_window_stales_proposal_and_coordinates() {
    let (_adapter, mut registry, proposal_id, proposal_generation) = setup_proposal();
    let derived = registry
        .derive_coordinates(&proposal_id, proposal_generation, WORKSPACE, POLICY)
        .unwrap();
    let coord_id = derived["coord_id"].as_str().expect("coord id").to_owned();
    let derivation_generation = derived["derivation_generation"]
        .as_u64()
        .expect("generation");
    let window_id = derived["window_id"].as_str().expect("window id").to_owned();
    assert!(registry.bump_window_generation(&window_id));
    let stale = registry.derive_coordinates(&proposal_id, proposal_generation, WORKSPACE, POLICY);
    assert_eq!(
        stale.expect_err("replaced window must fail").code,
        FailureCode::TargetStale
    );
    let stale_describe =
        registry.describe_coordinates(&coord_id, derivation_generation, WORKSPACE, POLICY);
    assert_eq!(
        stale_describe.expect_err("coordinates must stale").code,
        FailureCode::TargetStale
    );
}

#[test]
fn workspace_and_policy_drift_fail_closed() {
    let (_adapter, mut registry, proposal_id, proposal_generation) = setup_proposal();
    let foreign =
        registry.derive_coordinates(&proposal_id, proposal_generation, "other-workspace", POLICY);
    assert_eq!(
        foreign.expect_err("workspace drift must fail").code,
        FailureCode::TargetStale
    );
    let drifted =
        registry.derive_coordinates(&proposal_id, proposal_generation, WORKSPACE, "sg-000034-v1");
    assert_eq!(
        drifted.expect_err("policy drift must fail").code,
        FailureCode::TargetStale
    );
    assert_eq!(registry.coordinate_count(), 0);
}

#[test]
fn superseded_process_stales_proposal_and_coordinates() {
    let (adapter, mut registry, proposal_id, proposal_generation) = setup_proposal();
    let derived = registry
        .derive_coordinates(&proposal_id, proposal_generation, WORKSPACE, POLICY)
        .unwrap();
    let coord_id = derived["coord_id"].as_str().expect("coord id").to_owned();
    let derivation_generation = derived["derivation_generation"]
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
        .derive_coordinates(&proposal_id, proposal_generation, WORKSPACE, POLICY)
        .expect_err("superseded process must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    let stale = registry.describe_coordinates(&coord_id, derivation_generation, WORKSPACE, POLICY);
    assert_eq!(
        stale.expect_err("coordinates must stale").code,
        FailureCode::TargetStale
    );
    assert_eq!(registry.coordinate_count(), 1);
}

#[test]
fn protected_orcel_surface_cannot_yield_proposals_or_coordinates() {
    let adapter = FakeDerivationAdapter::with_process(4242, "notepad", 9001);
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
    assert_eq!(registry.proposal_count(), 0);
    let forged = registry.derive_coordinates("uia-prop-ffffffffffffffff", 1, WORKSPACE, POLICY);
    assert_eq!(
        forged.expect_err("no derivation without a proposal").code,
        FailureCode::TargetStale
    );
    assert_eq!(registry.coordinate_count(), 0);
}

#[test]
fn derivation_approval_digest_binds_complete_material() {
    let (_adapter, registry, proposal_id, proposal_generation) = setup_proposal();
    let binding = registry
        .derivation_binding(&proposal_id, proposal_generation, WORKSPACE, POLICY)
        .unwrap();
    assert_eq!((binding.x, binding.y), (3, 2));
    let first = coordinate_derivation_digest(WORKSPACE, POLICY, &binding);
    assert_eq!(first.len(), 64);
    assert!(first.chars().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        first,
        coordinate_derivation_digest(WORKSPACE, POLICY, &binding)
    );
    assert_ne!(
        first,
        coordinate_derivation_digest("other", POLICY, &binding)
    );
    assert_ne!(
        first,
        coordinate_derivation_digest(WORKSPACE, "sg-000034-v1", &binding)
    );
    let mut drifted_proposal = binding.clone();
    drifted_proposal.proposal_generation += 1;
    assert_ne!(
        first,
        coordinate_derivation_digest(WORKSPACE, POLICY, &drifted_proposal)
    );
    let mut drifted_coords = binding.clone();
    drifted_coords.x += 1;
    assert_ne!(
        first,
        coordinate_derivation_digest(WORKSPACE, POLICY, &drifted_coords)
    );
}

#[test]
fn derivation_binding_matches_pre_derivation_revalidation() {
    let (_adapter, mut registry, proposal_id, proposal_generation) = setup_proposal();
    let binding = registry
        .derivation_binding(&proposal_id, proposal_generation, WORKSPACE, POLICY)
        .unwrap();
    assert_eq!(binding.proposal_id, proposal_id);
    assert_eq!(binding.proposal_generation, proposal_generation);
    assert_eq!(binding.frame_width, 8);
    assert_eq!(binding.frame_height, 6);
    let window_id = binding.window_id.clone();
    assert!(registry.bump_window_generation(&window_id));
    let stale = registry.derivation_binding(&proposal_id, proposal_generation, WORKSPACE, POLICY);
    assert_eq!(
        stale.expect_err("binding must revalidate").code,
        FailureCode::TargetStale
    );
}

#[test]
fn derivations_grant_no_input_authority_and_raw_requests_stay_denied() {
    let (_adapter, mut registry, proposal_id, proposal_generation) = setup_proposal();
    let result = registry
        .derive_coordinates(&proposal_id, proposal_generation, WORKSPACE, POLICY)
        .unwrap();
    assert_eq!(result["action"], "propose");
    for key in [
        "click",
        "mouse",
        "keyboard",
        "sendinput",
        "input",
        "lease",
        "execute",
        "execution",
    ] {
        assert!(result.get(key).is_none(), "derivation must not carry {key}");
    }
    assert!(is_denied_uia_shape("uia.coordinates", "request"));
    assert!(!is_coordinate_propose_shape("uia.coordinates", "request"));
    assert!(!is_coordinate_propose_shape("uia.input", "mouse"));
    assert!(!is_coordinate_propose_shape("uia.elevation", "request"));
}
