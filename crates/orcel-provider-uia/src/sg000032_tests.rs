//! SG-000032 deterministic structured ScrollPattern actuation tests.
//!
//! These tests use an injected fake adapter, so they prove scroll binding,
//! approval digest shape, stale fail-closed behavior, protected-surface
//! exclusion, password denial, expected-position enforcement, bounded
//! direction and amount, and fallback denial deterministically on every
//! platform without a live desktop. Real Windows process identity is proven
//! separately through the native adapter test on Windows.

use super::*;
use std::cell::RefCell;
use std::collections::HashMap;

const WORKSPACE: &str = "uia-scroll-test-workspace";
const POLICY: &str = "sg-000032-v1";

fn fake_process(pid: u32, exe: &str, generation: u64) -> NativeProcess {
    NativeProcess {
        pid,
        exe_name: format!("{exe}.exe"),
        exe_id: digest_hex(&format!("{UIA_SCHEMA}|exe|{exe}"), ID_HEX_CHARS),
        session_id: 1,
        session_verified: true,
        start_generation: generation,
        generation_source: "fake-adapter",
        signature: SignatureState::Unknown,
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

fn scroll_item(runtime: &str) -> NativeElement {
    NativeElement {
        runtime_id: runtime.to_owned(),
        control_type: "Pane".to_owned(),
        automation_id: format!("auto-{runtime}"),
        name: "Content".to_owned(),
        enabled: true,
        selected: false,
        toggled: false,
        scroll_horizontal_percent: 0,
        scroll_vertical_percent: 0,
        patterns: vec![SCROLL_PATTERN_NAME.to_owned()],
        value: None,
        value_is_password: false,
        children: Vec::new(),
    }
}

fn scrolled_item(runtime: &str) -> NativeElement {
    let mut element = scroll_item(runtime);
    element.scroll_horizontal_percent = 30;
    element.scroll_vertical_percent = 40;
    element
}

fn disabled_item(runtime: &str) -> NativeElement {
    let mut element = scroll_item(runtime);
    element.enabled = false;
    element
}

fn no_pattern_item(runtime: &str) -> NativeElement {
    let mut element = scroll_item(runtime);
    element.patterns = vec!["LegacyIAccessible".to_owned()];
    element
}

fn button_element(runtime: &str) -> NativeElement {
    NativeElement {
        runtime_id: runtime.to_owned(),
        control_type: "Button".to_owned(),
        automation_id: format!("auto-{runtime}"),
        name: "Submit".to_owned(),
        enabled: true,
        selected: false,
        toggled: false,
        scroll_horizontal_percent: 0,
        scroll_vertical_percent: 0,
        patterns: vec![INVOKE_PATTERN_NAME.to_owned()],
        value: None,
        value_is_password: false,
        children: Vec::new(),
    }
}

fn checkbox_element(runtime: &str) -> NativeElement {
    NativeElement {
        runtime_id: runtime.to_owned(),
        control_type: "CheckBox".to_owned(),
        automation_id: format!("auto-{runtime}"),
        name: "Option".to_owned(),
        enabled: true,
        selected: false,
        toggled: false,
        scroll_horizontal_percent: 0,
        scroll_vertical_percent: 0,
        patterns: vec![TOGGLE_PATTERN_NAME.to_owned()],
        value: None,
        value_is_password: false,
        children: Vec::new(),
    }
}

fn password_item(runtime: &str) -> NativeElement {
    NativeElement {
        runtime_id: runtime.to_owned(),
        control_type: "Pane".to_owned(),
        automation_id: "secret-scroll".to_owned(),
        name: "Secret".to_owned(),
        enabled: true,
        selected: false,
        toggled: false,
        scroll_horizontal_percent: 0,
        scroll_vertical_percent: 0,
        patterns: vec![SCROLL_PATTERN_NAME.to_owned()],
        value: None,
        value_is_password: false,
        children: Vec::new(),
    }
}

#[derive(Default)]
struct FakeScrollState {
    processes: Vec<NativeProcess>,
    windows_by_pid: HashMap<u32, Vec<NativeWindow>>,
    trees_by_hwnd: HashMap<u64, Vec<NativeElement>>,
    scrolls: Vec<(u64, String, String, u64)>,
}

#[derive(Default)]
struct FakeScrollAdapter {
    state: RefCell<FakeScrollState>,
}

impl FakeScrollAdapter {
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

    fn set_tree(&self, hwnd: u64, roots: Vec<NativeElement>) {
        self.state.borrow_mut().trees_by_hwnd.insert(hwnd, roots);
    }

    fn scroll_count(&self) -> usize {
        self.state.borrow().scrolls.len()
    }
}

impl UiaAdapter for FakeScrollAdapter {
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

    fn read_tree(&self, hwnd: u64) -> Result<Vec<NativeElement>, UiaError> {
        Ok(self
            .state
            .borrow()
            .trees_by_hwnd
            .get(&hwnd)
            .cloned()
            .unwrap_or_default())
    }

    fn scroll_element(
        &self,
        hwnd: u64,
        runtime_id: &str,
        direction: &str,
        amount: u64,
    ) -> Result<(), UiaError> {
        self.state.borrow_mut().scrolls.push((
            hwnd,
            runtime_id.to_owned(),
            direction.to_owned(),
            amount,
        ));
        Ok(())
    }
}

fn setup_item() -> (FakeScrollAdapter, UiaRegistry, String, u64, String) {
    let adapter = FakeScrollAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    adapter.set_tree(100, vec![scroll_item("item-1")]);
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    let window_id = list["windows"][0]["window_id"]
        .as_str()
        .expect("window id")
        .to_owned();
    let window_generation = list["windows"][0]["window_generation"]
        .as_u64()
        .expect("window generation");
    let tree = registry
        .observe_tree(
            &adapter,
            &window_id,
            window_generation,
            None,
            None,
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    let tree_generation = tree["tree_generation"].as_u64().expect("tree generation");
    let element_id = tree["nodes"][0]["element_id"]
        .as_str()
        .expect("element id")
        .to_owned();
    (adapter, registry, element_id, tree_generation, window_id)
}

#[test]
fn scroll_shape_and_eligibility_helpers_behave() {
    assert!(is_scroll_shape("uia.element", "scroll"));
    assert!(!is_scroll_shape("uia.element", "toggle"));
    assert!(!is_scroll_shape("uia.element", "select"));
    assert!(!is_scroll_shape("uia.element", "set_value"));
    assert!(!is_scroll_shape("uia.element", "invoke"));
    assert!(!is_scroll_shape("uia.element", "observe"));
    assert!(is_scroll_eligible_control_type("ScrollBar"));
    assert!(is_scroll_eligible_control_type("Pane"));
    assert!(is_scroll_eligible_control_type("List"));
    assert!(is_scroll_eligible_control_type("Tree"));
    assert!(!is_scroll_eligible_control_type("Button"));
    assert!(!is_scroll_eligible_control_type("CheckBox"));
    assert!(!is_scroll_eligible_control_type("ListItem"));
    assert!(!is_scroll_eligible_control_type("Edit"));
    assert!(!is_scroll_eligible_control_type(""));
    assert!(is_scroll_direction("up"));
    assert!(is_scroll_direction("down"));
    assert!(is_scroll_direction("left"));
    assert!(is_scroll_direction("right"));
    assert!(!is_scroll_direction("diagonal"));
    assert!(!is_scroll_direction(""));
    assert_eq!(MAX_SCROLL_AMOUNT, 100);
    assert_eq!(SCROLL_PATTERN_NAME, "Scroll");
    assert_eq!(SCROLL_SCHEMA, "orcel-uia-scroll-v1");
    assert!(!is_denied_uia_shape("uia.element", "scroll"));
    assert!(!is_denied_uia_shape("uia.element", "toggle"));
    assert!(!is_denied_uia_shape("uia.element", "select"));
    assert!(is_denied_uia_shape("uia.element", "focus"));
    assert!(is_denied_uia_shape("uia.input", "mouse"));
    assert!(is_denied_uia_shape("uia.input", "keyboard"));
    assert!(is_denied_uia_shape("uia.input", "sendinput"));
    assert!(is_denied_uia_shape("uia.coordinates", "request"));
    assert!(is_denied_uia_shape("uia.elevation", "request"));
}

#[test]
fn happy_path_scroll_actuates_and_invalidates_old_tree() {
    let (adapter, mut registry, element_id, tree_generation, window_id) = setup_item();
    let binding = registry
        .scroll_binding(
            &element_id,
            tree_generation,
            "Pane",
            0,
            0,
            "down",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect("binding resolves");
    assert_eq!(binding.element_id, element_id);
    assert_eq!(binding.control_type, "Pane");
    assert_eq!(binding.direction, "down");
    assert_eq!(binding.amount, 10);
    let digest = scroll_approval_digest(WORKSPACE, POLICY, &binding);
    assert_eq!(digest.len(), 64);
    let evidence = registry
        .scroll_element(
            &adapter,
            &element_id,
            tree_generation,
            "Pane",
            0,
            0,
            "down",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect("scroll succeeds");
    assert_eq!(evidence["action"], "scroll");
    assert_eq!(evidence["element_id"], element_id.as_str());
    assert_eq!(evidence["control_type"], "Pane");
    assert_eq!(evidence["pattern"], "Scroll");
    assert_eq!(evidence["direction"], "down");
    assert_eq!(evidence["amount"], 10);
    assert_eq!(evidence["expected_horizontal_percent"], 0);
    assert_eq!(evidence["expected_vertical_percent"], 0);
    assert_eq!(adapter.scroll_count(), 1);
    let error = registry
        .scroll_element(
            &adapter,
            &element_id,
            tree_generation,
            "Pane",
            0,
            0,
            "down",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect_err("replay against the old tree must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.scroll_count(), 1);
    let (_, new_tree) = registry
        .window_generations(&window_id)
        .expect("window remains");
    assert!(new_tree > tree_generation);
}

#[test]
fn scroll_in_each_direction_actuates() {
    for direction in ["up", "down", "left", "right"] {
        let (adapter, mut registry, element_id, tree_generation, _) = setup_item();
        registry
            .scroll_element(
                &adapter,
                &element_id,
                tree_generation,
                "Pane",
                0,
                0,
                direction,
                5,
                WORKSPACE,
                POLICY,
            )
            .unwrap_or_else(|error| panic!("scroll {direction} must succeed: {}", error.message));
        assert_eq!(adapter.scroll_count(), 1);
    }
}

#[test]
fn scroll_digest_binds_material_state() {
    let (adapter, registry, element_id, tree_generation, _) = setup_item();
    let first = registry
        .scroll_binding(
            &element_id,
            tree_generation,
            "Pane",
            0,
            0,
            "down",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect("binding");
    let base_digest = scroll_approval_digest(WORKSPACE, POLICY, &first);
    let other_direction = registry
        .scroll_binding(
            &element_id,
            tree_generation,
            "Pane",
            0,
            0,
            "up",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect("binding");
    assert_ne!(
        base_digest,
        scroll_approval_digest(WORKSPACE, POLICY, &other_direction)
    );
    let other_amount = registry
        .scroll_binding(
            &element_id,
            tree_generation,
            "Pane",
            0,
            0,
            "down",
            11,
            WORKSPACE,
            POLICY,
        )
        .expect("binding");
    assert_ne!(
        base_digest,
        scroll_approval_digest(WORKSPACE, POLICY, &other_amount)
    );
    assert_ne!(
        base_digest,
        scroll_approval_digest("foreign-workspace", POLICY, &first)
    );
    assert_ne!(
        base_digest,
        scroll_approval_digest(WORKSPACE, "sg-000031-v1", &first)
    );
    let _ = adapter;
}

#[test]
fn malformed_and_ineligible_scroll_targets_fail_closed() {
    let (adapter, mut registry, element_id, tree_generation, _) = setup_item();
    let error = registry
        .scroll_element(
            &adapter,
            "uia-el-short",
            tree_generation,
            "Pane",
            0,
            0,
            "down",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect_err("malformed element must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);
    let error = registry
        .scroll_element(
            &adapter,
            &element_id,
            tree_generation,
            "",
            0,
            0,
            "down",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect_err("empty control type must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);
    let error = registry
        .scroll_element(
            &adapter,
            &element_id,
            tree_generation,
            "Button",
            0,
            0,
            "down",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect_err("ineligible control type must fail");
    assert!(matches!(
        error.code,
        FailureCode::CapabilityDenied | FailureCode::TargetStale
    ));
    let error = registry
        .scroll_element(
            &adapter,
            &element_id,
            tree_generation,
            "CheckBox",
            0,
            0,
            "down",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect_err("toggle control type must fail for scroll");
    assert!(matches!(
        error.code,
        FailureCode::CapabilityDenied | FailureCode::TargetStale
    ));
    let forged = format!("{ELEMENT_ID_PREFIX}{}", "d".repeat(ID_HEX_CHARS));
    let error = registry
        .scroll_element(
            &adapter,
            &forged,
            tree_generation,
            "Pane",
            0,
            0,
            "down",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect_err("unknown element must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.scroll_count(), 0);
}

#[test]
fn direction_and_amount_bounds_fail_closed() {
    let (adapter, mut registry, element_id, tree_generation, _) = setup_item();
    for direction in ["diagonal", "", "page-down", "wheel"] {
        let error = registry
            .scroll_element(
                &adapter,
                &element_id,
                tree_generation,
                "Pane",
                0,
                0,
                direction,
                10,
                WORKSPACE,
                POLICY,
            )
            .expect_err("invalid direction must fail");
        assert_eq!(error.code, FailureCode::InvalidRequest);
    }
    for amount in [0, 101, 1000, u64::MAX] {
        let error = registry
            .scroll_element(
                &adapter,
                &element_id,
                tree_generation,
                "Pane",
                0,
                0,
                "down",
                amount,
                WORKSPACE,
                POLICY,
            )
            .expect_err("out-of-range amount must fail");
        assert_eq!(error.code, FailureCode::InvalidRequest);
    }
    for (horizontal, vertical) in [(101, 0), (0, 101), (101, 101)] {
        let error = registry
            .scroll_element(
                &adapter,
                &element_id,
                tree_generation,
                "Pane",
                horizontal,
                vertical,
                "down",
                10,
                WORKSPACE,
                POLICY,
            )
            .expect_err("out-of-range expected position must fail");
        assert_eq!(error.code, FailureCode::InvalidRequest);
    }
    assert_eq!(adapter.scroll_count(), 0);
}

#[test]
fn expected_position_drift_fails_closed() {
    let (adapter, mut registry, element_id, tree_generation, _) = setup_item();
    let error = registry
        .scroll_element(
            &adapter,
            &element_id,
            tree_generation,
            "Pane",
            50,
            0,
            "down",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect_err("wrong expected horizontal position must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    let error = registry
        .scroll_element(
            &adapter,
            &element_id,
            tree_generation,
            "Pane",
            0,
            50,
            "down",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect_err("wrong expected vertical position must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.scroll_count(), 0);
}

#[test]
fn stale_tree_and_control_type_drift_fail_closed() {
    let (adapter, mut registry, element_id, tree_generation, window_id) = setup_item();
    let error = registry
        .scroll_element(
            &adapter,
            &element_id,
            tree_generation + 1,
            "Pane",
            0,
            0,
            "down",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect_err("wrong tree generation must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    let error = registry
        .scroll_element(
            &adapter,
            &element_id,
            tree_generation,
            "List",
            0,
            0,
            "down",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect_err("changed control type must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert!(registry.invalidate_tree(&window_id));
    let error = registry
        .scroll_element(
            &adapter,
            &element_id,
            tree_generation,
            "Pane",
            0,
            0,
            "down",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect_err("regenerated tree must fail the old identity");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.scroll_count(), 0);
}

#[test]
fn unsupported_pattern_disabled_ineligible_and_secret_targets_are_denied() {
    let adapter = FakeScrollAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    adapter.set_tree(
        100,
        vec![
            no_pattern_item("item-no-pattern"),
            disabled_item("item-disabled"),
            button_element("btn-1"),
            checkbox_element("chk-1"),
            password_item("item-password"),
        ],
    );
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    let window_id = list["windows"][0]["window_id"]
        .as_str()
        .expect("window id")
        .to_owned();
    let window_generation = list["windows"][0]["window_generation"]
        .as_u64()
        .expect("window generation");
    let tree = registry
        .observe_tree(
            &adapter,
            &window_id,
            window_generation,
            None,
            None,
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    let nodes = tree["nodes"].as_array().expect("nodes");
    assert_eq!(nodes.len(), 5);
    for node in nodes {
        let element_id = node["element_id"].as_str().expect("element id");
        let tree_generation = tree["tree_generation"].as_u64().expect("tree generation");
        let control_type = node["control_type"].as_str().expect("control type");
        let expected_h = node["scroll_horizontal_percent"].as_u64().unwrap_or(0);
        let expected_v = node["scroll_vertical_percent"].as_u64().unwrap_or(0);
        let error = registry
            .scroll_element(
                &adapter,
                element_id,
                tree_generation,
                control_type,
                expected_h,
                expected_v,
                "down",
                10,
                WORKSPACE,
                POLICY,
            )
            .expect_err("unsupported, disabled, ineligible, or secret target must be denied");
        assert!(matches!(
            error.code,
            FailureCode::CapabilityDenied | FailureCode::TargetStale
        ));
    }
    assert_eq!(adapter.scroll_count(), 0);
}

#[test]
fn protected_window_scroll_is_denied() {
    let adapter = FakeScrollAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(
        4242,
        vec![fake_window(100, "Orcel Approval", "OrcelApproveDialog", 1)],
    );
    adapter.set_tree(100, vec![scroll_item("item-1")]);
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    assert_eq!(list["window_count"], 0);
    assert_eq!(list["protected_omitted"], 1);
}

#[test]
fn scrolled_item_requires_matching_expected_position() {
    let adapter = FakeScrollAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    adapter.set_tree(100, vec![scrolled_item("item-scrolled")]);
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    let window_id = list["windows"][0]["window_id"]
        .as_str()
        .expect("window id")
        .to_owned();
    let window_generation = list["windows"][0]["window_generation"]
        .as_u64()
        .expect("window generation");
    let tree = registry
        .observe_tree(
            &adapter,
            &window_id,
            window_generation,
            None,
            None,
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    let tree_generation = tree["tree_generation"].as_u64().expect("tree generation");
    let element_id = tree["nodes"][0]["element_id"]
        .as_str()
        .expect("element id")
        .to_owned();
    registry
        .scroll_element(
            &adapter,
            &element_id,
            tree_generation,
            "Pane",
            30,
            40,
            "up",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect("scroll of a scrolled item with matching expected position succeeds");
    assert_eq!(adapter.scroll_count(), 1);
}

#[test]
fn workspace_policy_and_disappearance_drift_fail_closed() {
    let (adapter, mut registry, element_id, tree_generation, _) = setup_item();
    let error = registry
        .scroll_element(
            &adapter,
            &element_id,
            tree_generation,
            "Pane",
            0,
            0,
            "down",
            10,
            "foreign-workspace",
            POLICY,
        )
        .expect_err("foreign workspace must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    let error = registry
        .scroll_element(
            &adapter,
            &element_id,
            tree_generation,
            "Pane",
            0,
            0,
            "down",
            10,
            WORKSPACE,
            "sg-000031-v1",
        )
        .expect_err("policy drift must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert!(registry.remove_element(&element_id));
    let error = registry
        .scroll_element(
            &adapter,
            &element_id,
            tree_generation,
            "Pane",
            0,
            0,
            "down",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect_err("disappeared element must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.scroll_count(), 0);
}

#[test]
fn superseded_process_scroll_fails_closed() {
    let (adapter, mut registry, element_id, tree_generation, _) = setup_item();
    let native = fake_process(4242, "notepad", 9001);
    let (process_id, _) = registry.register_process(&native, WORKSPACE, POLICY);
    assert!(registry.mark_process_superseded(&process_id));
    let error = registry
        .scroll_binding(
            &element_id,
            tree_generation,
            "Pane",
            0,
            0,
            "down",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect_err("superseded process binding must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.scroll_count(), 0);
}

#[test]
fn native_adapter_scroll_reports_unavailable_without_fabrication() {
    let native = NativeAdapter::new();
    let error = native
        .scroll_element(123, "runtime-1", "down", 10)
        .expect_err("native scroll without a broker must be unavailable");
    assert_eq!(error.code, FailureCode::ProviderUnavailable);
}

#[test]
fn adapter_failure_is_reported_without_generation_bump() {
    struct FailingAdapter {
        processes: Vec<NativeProcess>,
        windows: Vec<NativeWindow>,
        tree: Vec<NativeElement>,
    }
    impl UiaAdapter for FailingAdapter {
        fn list_processes(&self) -> Result<Vec<NativeProcess>, UiaError> {
            Ok(self.processes.clone())
        }
        fn list_windows(&self, _pid: u32) -> Result<Vec<NativeWindow>, UiaError> {
            Ok(self.windows.clone())
        }
        fn read_tree(&self, _hwnd: u64) -> Result<Vec<NativeElement>, UiaError> {
            Ok(self.tree.clone())
        }
        fn scroll_element(
            &self,
            _hwnd: u64,
            _runtime_id: &str,
            _direction: &str,
            _amount: u64,
        ) -> Result<(), UiaError> {
            Err(UiaError::new(
                FailureCode::ProviderUnavailable,
                "broker unavailable in test",
            ))
        }
    }
    let failing = FailingAdapter {
        processes: vec![fake_process(4242, "notepad", 9001)],
        windows: vec![fake_window(100, "Document", "Notepad", 1)],
        tree: vec![scroll_item("item-1")],
    };
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&failing, WORKSPACE, POLICY).unwrap();
    let window_id = list["windows"][0]["window_id"]
        .as_str()
        .expect("window id")
        .to_owned();
    let window_generation = list["windows"][0]["window_generation"]
        .as_u64()
        .expect("window generation");
    let tree = registry
        .observe_tree(
            &failing,
            &window_id,
            window_generation,
            None,
            None,
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    let tree_generation = tree["tree_generation"].as_u64().expect("tree generation");
    let element_id = tree["nodes"][0]["element_id"]
        .as_str()
        .expect("element id")
        .to_owned();
    let (_, before_tree) = registry
        .window_generations(&window_id)
        .expect("generations");
    let error = registry
        .scroll_element(
            &failing,
            &element_id,
            tree_generation,
            "Pane",
            0,
            0,
            "down",
            10,
            WORKSPACE,
            POLICY,
        )
        .expect_err("adapter failure must fail closed");
    assert_eq!(error.code, FailureCode::ProviderUnavailable);
    let (_, after_tree) = registry
        .window_generations(&window_id)
        .expect("generations");
    assert_eq!(before_tree, after_tree);
}
