//! SG-000033 deterministic window-scoped screenshot capture tests.
//!
//! These tests use an injected fake adapter, so they prove capture binding,
//! frame identity, stale fail-closed behavior, protected-surface exclusion,
//! scope confinement, approval digest shape, and fallback denial
//! deterministically on every platform without a live desktop. Real Windows
//! process identity is proven separately through the native adapter test,
//! and live capture is reported as unavailable instead of fabricated.

use super::*;
use std::cell::RefCell;
use std::collections::HashMap;

const WORKSPACE: &str = "screenshot-test-workspace";
const POLICY: &str = "sg-000033-v1";

fn fake_process(pid: u32, exe: &str, generation: u64) -> NativeProcess {
    NativeProcess {
        pid,
        exe_name: format!("{exe}.exe"),
        exe_id: digest_hex(&format!("{UIA_SCHEMA}|exe|{exe}"), ID_HEX_CHARS),
        session_id: 1,
        session_verified: true,
        start_generation: generation,
        generation_source: "fake-adapter",
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
struct FakeCaptureState {
    processes: Vec<NativeProcess>,
    windows_by_pid: HashMap<u32, Vec<NativeWindow>>,
    images_by_hwnd: HashMap<u64, CapturedImage>,
    capture_calls: Vec<u64>,
    fail_capture: bool,
}

#[derive(Default)]
struct FakeCaptureAdapter {
    state: RefCell<FakeCaptureState>,
}

impl FakeCaptureAdapter {
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

    fn set_fail_capture(&self, fail: bool) {
        self.state.borrow_mut().fail_capture = fail;
    }

    fn capture_call_count(&self) -> usize {
        self.state.borrow().capture_calls.len()
    }
}

impl UiaAdapter for FakeCaptureAdapter {
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
        let mut state = self.state.borrow_mut();
        state.capture_calls.push(hwnd);
        if state.fail_capture {
            return Err(UiaError::new(
                FailureCode::ProviderUnavailable,
                "fake capture broker is unavailable",
            ));
        }
        state.images_by_hwnd.get(&hwnd).cloned().ok_or_else(|| {
            UiaError::new(
                FailureCode::ProviderUnavailable,
                "no fake capture image is registered for this window",
            )
        })
    }
}

fn setup_window() -> (FakeCaptureAdapter, UiaRegistry, String, u64) {
    let adapter = FakeCaptureAdapter::with_process(4242, "notepad", 9001);
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
    (adapter, registry, window_id, window_generation)
}

#[test]
fn capture_shape_and_scope_helpers_behave() {
    assert!(is_capture_shape("uia.screenshot", "capture"));
    assert!(!is_capture_shape("uia.screenshot", "observe"));
    assert!(!is_capture_shape("uia.screenshot", "propose"));
    assert!(!is_capture_shape("uia.coordinates", "request"));
    assert!(!is_capture_shape("uia.element", "scroll"));
    assert!(!is_capture_shape("uia.input", "mouse"));
    assert!(!is_capture_shape("uia.clipboard", "read"));
    assert!(!is_capture_shape("uia.network", "fetch"));
    assert!(!is_capture_shape("uia.elevation", "request"));
    assert!(is_capture_scope("target-window"));
    assert!(!is_capture_scope("monitor"));
    assert!(!is_capture_scope("desktop"));
    assert!(!is_capture_scope("region"));
    assert!(!is_capture_scope(""));
    assert!(!is_capture_scope("target-window "));
    assert!(!is_capture_scope("TARGET-WINDOW"));
    assert!(!is_allowed_uia_shape("uia.screenshot", "capture"));
    assert!(!is_denied_uia_shape("uia.screenshot", "capture"));
    assert!(is_denied_uia_shape("uia.coordinates", "request"));
    assert!(is_denied_uia_shape("uia.input", "mouse"));
    assert!(is_denied_uia_shape("uia.input", "keyboard"));
    assert!(is_denied_uia_shape("uia.input", "sendinput"));
    assert!(is_denied_uia_shape("uia.clipboard", "read"));
    assert!(is_denied_uia_shape("uia.clipboard", "write"));
    assert!(is_denied_uia_shape("uia.network", "fetch"));
    assert!(is_denied_uia_shape("uia.elevation", "request"));
    assert!(is_well_formed_frame_id("uia-frame-0123456789abcdef"));
    assert!(!is_well_formed_frame_id("uia-frame-0123456789ABCDEF"));
    assert!(!is_well_formed_frame_id("uia-frame-short"));
    assert!(!is_well_formed_frame_id("uia-win-0123456789abcdef"));
    assert!(!is_well_formed_frame_id("caller-frame-1"));
}

#[test]
fn happy_path_capture_mints_server_allocated_frame() {
    let (adapter, mut registry, window_id, window_generation) = setup_window();
    let result = registry
        .capture_window(
            &adapter,
            &window_id,
            window_generation,
            "target-window",
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    assert_eq!(result["schema"], CAPTURE_SCHEMA);
    assert_eq!(result["action"], "capture");
    assert_eq!(result["scope"], "target-window");
    assert_eq!(result["pixel_format"], CAPTURE_PIXEL_FORMAT);
    assert_eq!(result["window_id"], window_id);
    assert_eq!(result["window_generation"], window_generation);
    assert_eq!(result["width"], 8);
    assert_eq!(result["height"], 6);
    assert_eq!(result["truncated"], false);
    let frame_id = result["frame_id"].as_str().expect("frame id");
    assert!(is_well_formed_frame_id(frame_id));
    assert_eq!(result["encoding"], "base64");
    let expected_image = deterministic_image(100);
    assert_eq!(
        result["pixels_b64"].as_str().expect("base64 pixels"),
        base64_encode(&expected_image.bytes)
    );
    assert!(result.get("pixels").is_none());
    let expected_digest = capture_payload_digest(&expected_image.bytes);
    assert_eq!(result["payload_digest"], expected_digest);
    assert_eq!(result["capture_generation"], 1);
    assert_eq!(registry.frame_count(), 1);
    assert_eq!(adapter.capture_call_count(), 1);
    assert!(result.get("x").is_none());
    assert!(result.get("y").is_none());
    assert!(result.get("coordinates").is_none());
}

#[test]
fn second_capture_mints_new_frame_with_higher_generation() {
    let (adapter, mut registry, window_id, window_generation) = setup_window();
    let first = registry
        .capture_window(
            &adapter,
            &window_id,
            window_generation,
            "target-window",
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    let second = registry
        .capture_window(
            &adapter,
            &window_id,
            window_generation,
            "target-window",
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    let first_id = first["frame_id"].as_str().expect("first frame");
    let second_id = second["frame_id"].as_str().expect("second frame");
    assert_ne!(first_id, second_id);
    assert_eq!(second["capture_generation"], 2);
    assert_eq!(registry.frame_count(), 2);
}

#[test]
fn describe_frame_validates_generation_workspace_and_policy() {
    let (adapter, mut registry, window_id, window_generation) = setup_window();
    let result = registry
        .capture_window(
            &adapter,
            &window_id,
            window_generation,
            "target-window",
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    let frame_id = result["frame_id"].as_str().expect("frame id").to_owned();
    let generation = result["capture_generation"].as_u64().expect("generation");
    let described = registry
        .describe_frame(&frame_id, generation, WORKSPACE, POLICY)
        .unwrap();
    assert_eq!(described["frame_id"], frame_id);
    assert_eq!(described["window_id"], window_id);
    assert_eq!(described["payload_digest"], result["payload_digest"]);
    assert!(described.get("pixels").is_none());
    let stale = registry.describe_frame(&frame_id, generation + 1, WORKSPACE, POLICY);
    assert_eq!(
        stale.expect_err("generation drift must fail").code,
        FailureCode::TargetStale
    );
    let foreign_workspace = registry.describe_frame(&frame_id, generation, "other", POLICY);
    assert_eq!(
        foreign_workspace
            .expect_err("workspace drift must fail")
            .code,
        FailureCode::TargetStale
    );
    let drifted_policy = registry.describe_frame(&frame_id, generation, WORKSPACE, "sg-000027-v1");
    assert_eq!(
        drifted_policy.expect_err("policy drift must fail").code,
        FailureCode::TargetStale
    );
    let malformed = registry.describe_frame("caller-frame-1", generation, WORKSPACE, POLICY);
    assert_eq!(
        malformed.expect_err("malformed frame must fail").code,
        FailureCode::InvalidRequest
    );
    let forged_id = "uia-frame-ffffffffffffffff";
    let forged = registry.describe_frame(forged_id, 1, WORKSPACE, POLICY);
    assert_eq!(
        forged.expect_err("forged frame must fail").code,
        FailureCode::TargetStale
    );
}

#[test]
fn describe_frame_fails_closed_after_window_replacement() {
    let (adapter, mut registry, window_id, window_generation) = setup_window();
    let result = registry
        .capture_window(
            &adapter,
            &window_id,
            window_generation,
            "target-window",
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    let frame_id = result["frame_id"].as_str().expect("frame id").to_owned();
    let generation = result["capture_generation"].as_u64().expect("generation");
    assert!(registry.bump_window_generation(&window_id));
    let stale = registry.describe_frame(&frame_id, generation, WORKSPACE, POLICY);
    assert_eq!(
        stale
            .expect_err("replaced window must stale the frame")
            .code,
        FailureCode::TargetStale
    );
}

#[test]
fn widened_scopes_are_denied_without_adapter_access() {
    let (adapter, mut registry, window_id, window_generation) = setup_window();
    for scope in [
        "monitor",
        "desktop",
        "region",
        "",
        "target-window ",
        "TARGET-WINDOW",
    ] {
        let error = registry
            .capture_window(
                &adapter,
                &window_id,
                window_generation,
                scope,
                WORKSPACE,
                POLICY,
            )
            .expect_err("widened scope must fail");
        assert_eq!(error.code, FailureCode::CapabilityDenied);
    }
    assert_eq!(adapter.capture_call_count(), 0);
    assert_eq!(registry.frame_count(), 0);
}

#[test]
fn malformed_and_unknown_windows_fail_closed() {
    let (adapter, mut registry, _, _) = setup_window();
    let malformed = registry.capture_window(
        &adapter,
        "not-a-window",
        1,
        "target-window",
        WORKSPACE,
        POLICY,
    );
    assert_eq!(
        malformed.expect_err("malformed window must fail").code,
        FailureCode::InvalidRequest
    );
    let unknown = registry.capture_window(
        &adapter,
        "uia-win-ffffffffffffffff",
        1,
        "target-window",
        WORKSPACE,
        POLICY,
    );
    assert_eq!(
        unknown.expect_err("unknown window must fail").code,
        FailureCode::TargetStale
    );
    assert_eq!(adapter.capture_call_count(), 0);
}

#[test]
fn stale_window_generation_and_replacement_fail_closed() {
    let (adapter, mut registry, window_id, window_generation) = setup_window();
    let drifted = registry.capture_window(
        &adapter,
        &window_id,
        window_generation + 1,
        "target-window",
        WORKSPACE,
        POLICY,
    );
    assert_eq!(
        drifted.expect_err("generation drift must fail").code,
        FailureCode::TargetStale
    );
    assert!(registry.bump_window_generation(&window_id));
    let replaced = registry.capture_window(
        &adapter,
        &window_id,
        window_generation,
        "target-window",
        WORKSPACE,
        POLICY,
    );
    assert_eq!(
        replaced.expect_err("replaced window must fail").code,
        FailureCode::TargetStale
    );
    let (current, _) = registry
        .window_generations(&window_id)
        .expect("generations");
    registry
        .capture_window(
            &adapter,
            &window_id,
            current,
            "target-window",
            WORKSPACE,
            POLICY,
        )
        .expect("current generation captures");
}

#[test]
fn superseded_process_fails_closed() {
    let (adapter, mut registry, window_id, window_generation) = setup_window();
    let list = registry
        .list_windows(&adapter, WORKSPACE, POLICY)
        .expect("re-list");
    let process_id = list["windows"][0]["process_id"]
        .as_str()
        .expect("process id")
        .to_owned();
    assert!(registry.mark_process_superseded(&process_id));
    let error = registry
        .capture_window(
            &adapter,
            &window_id,
            window_generation,
            "target-window",
            WORKSPACE,
            POLICY,
        )
        .expect_err("superseded process must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(registry.frame_count(), 0);
}

#[test]
fn restarted_process_invalidates_old_identity_and_frame_binding() {
    let adapter = FakeCaptureAdapter::with_process(4242, "notepad", 9001);
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
    let process_id = list["windows"][0]["process_id"]
        .as_str()
        .expect("process id")
        .to_owned();
    let first = registry
        .capture_window(
            &adapter,
            &window_id,
            window_generation,
            "target-window",
            WORKSPACE,
            POLICY,
        )
        .expect("pre-restart capture");
    assert_eq!(first["process_generation"], 9001);
    let frame_id = first["frame_id"].as_str().expect("frame id").to_owned();
    let frame_generation = first["capture_generation"].as_u64().expect("generation");
    // The OS restarts the process behind the same PID; the adapter reports
    // the new start generation and the registry supersedes the old record.
    adapter
        .state
        .borrow_mut()
        .processes
        .push(fake_process(4242, "notepad", 9002));
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    // The pre-restart process identity no longer observes as live.
    let stale_process = registry.observe_process(&process_id, 9001, WORKSPACE, POLICY);
    assert_eq!(
        stale_process.expect_err("restarted process must fail").code,
        FailureCode::TargetStale
    );
    // The pre-restart frame is stale once its owning process drifted and is
    // never actionable again.
    let stale_frame = registry.describe_frame(&frame_id, frame_generation, WORKSPACE, POLICY);
    assert_eq!(
        stale_frame.expect_err("pre-restart frame must stale").code,
        FailureCode::TargetStale
    );
    // A fresh capture binds the live restarted generation explicitly, so a
    // pre-restart approval digest can never be replayed against it.
    let second = registry
        .capture_window(
            &adapter,
            &window_id,
            window_generation,
            "target-window",
            WORKSPACE,
            POLICY,
        )
        .expect("post-restart capture binds the live generation");
    assert_eq!(second["process_generation"], 9002);
    assert_ne!(second["frame_id"], first["frame_id"]);
}

#[test]
fn workspace_and_policy_drift_fail_closed() {
    let (adapter, mut registry, window_id, window_generation) = setup_window();
    let foreign_workspace = registry.capture_window(
        &adapter,
        &window_id,
        window_generation,
        "target-window",
        "other-workspace",
        POLICY,
    );
    assert_eq!(
        foreign_workspace
            .expect_err("workspace drift must fail")
            .code,
        FailureCode::TargetStale
    );
    let drifted_policy = registry.capture_window(
        &adapter,
        &window_id,
        window_generation,
        "target-window",
        WORKSPACE,
        "sg-000027-v1",
    );
    assert_eq!(
        drifted_policy.expect_err("policy drift must fail").code,
        FailureCode::TargetStale
    );
    assert_eq!(adapter.capture_call_count(), 0);
}

#[test]
fn protected_orcel_surface_is_omitted_and_denied() {
    let adapter = FakeCaptureAdapter::with_process(4242, "notepad", 9001);
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
    assert!(is_protected_window(
        "Orcel Approval Dialog",
        "OrcelApproveWnd"
    ));
    // Reconstruct the server-allocated identity exactly as the registry
    // allocates it; callers can never do this, but the test proves the
    // registered-but-omitted record still denies capture.
    let exe_id = digest_hex(&format!("{UIA_SCHEMA}|exe|notepad"), ID_HEX_CHARS);
    let process_id = allocate_process_id(4242, &exe_id);
    let window_id = allocate_window_id(&process_id, 200);
    let (generation, _) = registry
        .window_generations(&window_id)
        .expect("protected window is registered but omitted");
    let observed = registry.observe_window(&window_id, generation, WORKSPACE, POLICY);
    assert_eq!(
        observed.expect_err("protected observation must fail").code,
        FailureCode::CapabilityDenied
    );
    let error = registry.capture_window(
        &adapter,
        &window_id,
        generation,
        "target-window",
        WORKSPACE,
        POLICY,
    );
    assert_eq!(
        error.expect_err("protected surface must fail").code,
        FailureCode::CapabilityDenied
    );
    assert_eq!(registry.frame_count(), 0);
}

#[test]
fn oversized_and_mismatched_payloads_fail_closed() {
    let (adapter, mut registry, window_id, window_generation) = setup_window();
    adapter.set_image(
        100,
        CapturedImage {
            width: MAX_CAPTURE_WIDTH + 1,
            height: 10,
            bytes: vec![0u8; 40],
        },
    );
    let oversized = registry.capture_window(
        &adapter,
        &window_id,
        window_generation,
        "target-window",
        WORKSPACE,
        POLICY,
    );
    assert_eq!(
        oversized.expect_err("oversized geometry must fail").code,
        FailureCode::InvalidRequest
    );
    adapter.set_image(
        100,
        CapturedImage {
            width: 8,
            height: 6,
            bytes: vec![0u8; 10],
        },
    );
    let mismatched = registry.capture_window(
        &adapter,
        &window_id,
        window_generation,
        "target-window",
        WORKSPACE,
        POLICY,
    );
    assert_eq!(
        mismatched.expect_err("mismatched payload must fail").code,
        FailureCode::OutputLimit
    );
    adapter.set_image(
        100,
        CapturedImage {
            width: 0,
            height: 0,
            bytes: Vec::new(),
        },
    );
    let empty = registry.capture_window(
        &adapter,
        &window_id,
        window_generation,
        "target-window",
        WORKSPACE,
        POLICY,
    );
    assert_eq!(
        empty.expect_err("empty geometry must fail").code,
        FailureCode::InvalidRequest
    );
    assert_eq!(registry.frame_count(), 0);
}

#[test]
fn capture_approval_digest_binds_complete_material() {
    let (adapter, registry, window_id, window_generation) = setup_window();
    let binding = registry
        .capture_binding(
            &window_id,
            window_generation,
            "target-window",
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    let first = capture_approval_digest(WORKSPACE, POLICY, &binding);
    assert_eq!(first.len(), 64);
    assert!(first.chars().all(|byte| byte.is_ascii_hexdigit()));
    let again = capture_approval_digest(WORKSPACE, POLICY, &binding);
    assert_eq!(first, again);
    let drifted_workspace = capture_approval_digest("other", POLICY, &binding);
    assert_ne!(first, drifted_workspace);
    let drifted_policy = capture_approval_digest(WORKSPACE, "sg-000027-v1", &binding);
    assert_ne!(first, drifted_policy);
    let mut other = binding.clone();
    other.window_generation += 1;
    assert_ne!(first, capture_approval_digest(WORKSPACE, POLICY, &other));
    let _ = adapter;
}

#[test]
fn capture_binding_matches_pre_capture_revalidation() {
    let (adapter, mut registry, window_id, window_generation) = setup_window();
    let binding = registry
        .capture_binding(
            &window_id,
            window_generation,
            "target-window",
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    assert_eq!(binding.window_id, window_id);
    assert_eq!(binding.window_generation, window_generation);
    assert_eq!(binding.scope, "target-window");
    assert_eq!(binding.hwnd, 100);
    assert!(registry.bump_window_generation(&window_id));
    let stale = registry.capture_binding(
        &window_id,
        window_generation,
        "target-window",
        WORKSPACE,
        POLICY,
    );
    assert_eq!(
        stale.expect_err("binding must revalidate").code,
        FailureCode::TargetStale
    );
    let _ = adapter;
}

/// Approval prompts name the application from the registry's own records: the verified
/// process's executable and the observed window's title. An unknown window has none.
#[test]
fn a_registered_window_names_its_application_for_prompts() {
    let (adapter, registry, window_id, _) = setup_window();
    assert_eq!(
        registry.window_application(&window_id),
        Some(("notepad.exe".to_owned(), "Document".to_owned()))
    );
    assert_eq!(registry.window_application("w-unknown"), None);
    let _ = adapter;
}

#[test]
fn adapter_failure_reports_without_minting_frame() {
    let (adapter, mut registry, window_id, window_generation) = setup_window();
    adapter.set_fail_capture(true);
    let error = registry
        .capture_window(
            &adapter,
            &window_id,
            window_generation,
            "target-window",
            WORKSPACE,
            POLICY,
        )
        .expect_err("adapter failure must fail");
    assert_eq!(error.code, FailureCode::ProviderUnavailable);
    assert_eq!(registry.frame_count(), 0);
}

#[test]
fn native_adapter_reports_capture_unavailable_without_fabrication() {
    let adapter = NativeAdapter::new();
    let error = adapter
        .capture_window(12345)
        .expect_err("headless capture must fail closed");
    assert_eq!(error.code, FailureCode::ProviderUnavailable);
}
