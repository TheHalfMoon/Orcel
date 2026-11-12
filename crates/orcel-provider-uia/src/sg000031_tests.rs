//! SG-000031 deterministic structured TogglePattern actuation tests.
//!
//! These tests use an injected fake adapter, so they prove toggle binding,
//! approval digest shape, stale fail-closed behavior, protected-surface
//! exclusion, password denial, expected-state enforcement, and fallback
//! denial deterministically on every platform without a live desktop. Real
//! Windows process identity is proven separately through the native adapter
//! test on Windows.

use super::*;
use std::cell::RefCell;
use std::collections::HashMap;

const WORKSPACE: &str = "uia-toggle-test-workspace";
const POLICY: &str = "sg-000031-v1";

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

fn toggle_item(runtime: &str) -> NativeElement {
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

fn toggled_item(runtime: &str) -> NativeElement {
    let mut element = toggle_item(runtime);
    element.toggled = true;
    element
}

fn disabled_item(runtime: &str) -> NativeElement {
    let mut element = toggle_item(runtime);
    element.enabled = false;
    element
}

fn no_pattern_item(runtime: &str) -> NativeElement {
    let mut element = toggle_item(runtime);
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

fn list_item_element(runtime: &str) -> NativeElement {
    NativeElement {
        runtime_id: runtime.to_owned(),
        control_type: "ListItem".to_owned(),
        automation_id: format!("auto-{runtime}"),
        name: "Option".to_owned(),
        enabled: true,
        selected: false,
        toggled: false,
        scroll_horizontal_percent: 0,
        scroll_vertical_percent: 0,
        patterns: vec![SELECT_PATTERN_NAME.to_owned()],
        value: None,
        value_is_password: false,
        children: Vec::new(),
    }
}

fn password_item(runtime: &str) -> NativeElement {
    NativeElement {
        runtime_id: runtime.to_owned(),
        control_type: "CheckBox".to_owned(),
        automation_id: "login-password".to_owned(),
        name: "Password".to_owned(),
        enabled: true,
        selected: false,
        toggled: false,
        scroll_horizontal_percent: 0,
        scroll_vertical_percent: 0,
        patterns: vec![TOGGLE_PATTERN_NAME.to_owned()],
        value: Some("hunter2".to_owned()),
        value_is_password: true,
        children: Vec::new(),
    }
}

#[derive(Default)]
struct FakeToggleState {
    processes: Vec<NativeProcess>,
    windows_by_pid: HashMap<u32, Vec<NativeWindow>>,
    trees_by_hwnd: HashMap<u64, Vec<NativeElement>>,
    toggles: Vec<(u64, String, bool)>,
}

#[derive(Default)]
struct FakeToggleAdapter {
    state: RefCell<FakeToggleState>,
}

impl FakeToggleAdapter {
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

    fn toggle_count(&self) -> usize {
        self.state.borrow().toggles.len()
    }
}

impl UiaAdapter for FakeToggleAdapter {
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

    fn toggle_element(&self, hwnd: u64, runtime_id: &str, toggled: bool) -> Result<(), UiaError> {
        self.state
            .borrow_mut()
            .toggles
            .push((hwnd, runtime_id.to_owned(), toggled));
        Ok(())
    }
}

fn setup_item() -> (FakeToggleAdapter, UiaRegistry, String, u64, String) {
    let adapter = FakeToggleAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    adapter.set_tree(100, vec![toggle_item("item-1")]);
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
fn toggle_shape_and_eligibility_helpers_behave() {
    assert!(is_toggle_shape("uia.element", "toggle"));
    assert!(!is_toggle_shape("uia.element", "invoke"));
    assert!(!is_toggle_shape("uia.element", "set_value"));
    assert!(!is_toggle_shape("uia.element", "select"));
    assert!(!is_toggle_shape("uia.element", "observe"));
    assert!(is_toggle_eligible_control_type("CheckBox"));
    assert!(is_toggle_eligible_control_type("RadioButton"));
    assert!(!is_toggle_eligible_control_type("Button"));
    assert!(!is_toggle_eligible_control_type("ListItem"));
    assert!(!is_toggle_eligible_control_type("Edit"));
    assert!(!is_toggle_eligible_control_type(""));
    assert_eq!(TOGGLE_PATTERN_NAME, "Toggle");
    assert_eq!(TOGGLE_SCHEMA, "orcel-uia-toggle-v1");
    assert!(!is_denied_uia_shape("uia.element", "toggle"));
    assert!(!is_denied_uia_shape("uia.element", "select"));
    assert!(!is_denied_uia_shape("uia.element", "set_value"));
    assert!(!is_denied_uia_shape("uia.element", "invoke"));
    // NOTE (SG-000032 successor): `uia.element/scroll` is lawfully
    // authorized by the SG-000032 successor grain, so it is no longer
    // denied for current-tree authority. Focus, synthetic input,
    // coordinates, screenshots, clipboard, network, and elevation remain
    // denied.
    assert!(!is_denied_uia_shape("uia.element", "scroll"));
    assert!(is_denied_uia_shape("uia.input", "mouse"));
    assert!(is_denied_uia_shape("uia.input", "keyboard"));
    assert!(is_denied_uia_shape("uia.input", "sendinput"));
    assert!(is_denied_uia_shape("uia.coordinates", "request"));
    assert!(is_denied_uia_shape("uia.elevation", "request"));
}

#[test]
fn happy_path_toggle_actuates_and_invalidates_old_tree() {
    let (adapter, mut registry, element_id, tree_generation, window_id) = setup_item();
    let binding = registry
        .toggle_binding(
            &element_id,
            tree_generation,
            "CheckBox",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect("binding resolves");
    assert_eq!(binding.element_id, element_id);
    assert_eq!(binding.control_type, "CheckBox");
    assert!(!binding.expected_toggled);
    assert!(binding.toggled);
    let digest = toggle_approval_digest(WORKSPACE, POLICY, &binding);
    assert_eq!(digest.len(), 64);
    let evidence = registry
        .toggle_element(
            &adapter,
            &element_id,
            tree_generation,
            "CheckBox",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect("toggle succeeds");
    assert_eq!(evidence["action"], "toggle");
    assert_eq!(evidence["element_id"], element_id.as_str());
    assert_eq!(evidence["control_type"], "CheckBox");
    assert_eq!(evidence["pattern"], "Toggle");
    assert_eq!(evidence["expected_toggled"], false);
    assert_eq!(evidence["toggled"], true);
    assert_eq!(adapter.toggle_count(), 1);
    let error = registry
        .toggle_element(
            &adapter,
            &element_id,
            tree_generation,
            "CheckBox",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("replay against the old tree must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.toggle_count(), 1);
    let (_, new_tree) = registry
        .window_generations(&window_id)
        .expect("window remains");
    assert!(new_tree > tree_generation);
}

#[test]
fn toggle_digest_binds_material_state() {
    let (adapter, registry, element_id, tree_generation, _) = setup_item();
    let first = registry
        .toggle_binding(
            &element_id,
            tree_generation,
            "CheckBox",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect("binding");
    let base_digest = toggle_approval_digest(WORKSPACE, POLICY, &first);
    let second = registry
        .toggle_binding(
            &element_id,
            tree_generation,
            "CheckBox",
            false,
            false,
            WORKSPACE,
            POLICY,
        )
        .expect("binding");
    assert_ne!(
        base_digest,
        toggle_approval_digest(WORKSPACE, POLICY, &second)
    );
    assert_ne!(
        base_digest,
        toggle_approval_digest("foreign-workspace", POLICY, &first)
    );
    assert_ne!(
        base_digest,
        toggle_approval_digest(WORKSPACE, "sg-000030-v1", &first)
    );
    let _ = adapter;
}

#[test]
fn malformed_and_ineligible_toggle_targets_fail_closed() {
    let (adapter, mut registry, element_id, tree_generation, _) = setup_item();
    let error = registry
        .toggle_element(
            &adapter,
            "uia-el-short",
            tree_generation,
            "CheckBox",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("malformed element must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);
    let error = registry
        .toggle_element(
            &adapter,
            &element_id,
            tree_generation,
            "",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("empty control type must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);
    let error = registry
        .toggle_element(
            &adapter,
            &element_id,
            tree_generation,
            "Button",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("ineligible control type must fail");
    assert!(matches!(
        error.code,
        FailureCode::CapabilityDenied | FailureCode::TargetStale
    ));
    let error = registry
        .toggle_element(
            &adapter,
            &element_id,
            tree_generation,
            "ListItem",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("selection control type must fail for toggle");
    assert!(matches!(
        error.code,
        FailureCode::CapabilityDenied | FailureCode::TargetStale
    ));
    let forged = format!("{ELEMENT_ID_PREFIX}{}", "d".repeat(ID_HEX_CHARS));
    let error = registry
        .toggle_element(
            &adapter,
            &forged,
            tree_generation,
            "CheckBox",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("unknown element must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.toggle_count(), 0);
}

#[test]
fn expected_state_drift_fails_closed() {
    let (adapter, mut registry, element_id, tree_generation, _) = setup_item();
    let error = registry
        .toggle_element(
            &adapter,
            &element_id,
            tree_generation,
            "CheckBox",
            true,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("wrong expected toggle must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.toggle_count(), 0);
}

#[test]
fn stale_tree_and_control_type_drift_fail_closed() {
    let (adapter, mut registry, element_id, tree_generation, window_id) = setup_item();
    let error = registry
        .toggle_element(
            &adapter,
            &element_id,
            tree_generation + 1,
            "CheckBox",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("wrong tree generation must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    let error = registry
        .toggle_element(
            &adapter,
            &element_id,
            tree_generation,
            "RadioButton",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("changed control type must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert!(registry.invalidate_tree(&window_id));
    let error = registry
        .toggle_element(
            &adapter,
            &element_id,
            tree_generation,
            "CheckBox",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("regenerated tree must fail the old identity");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.toggle_count(), 0);
}

#[test]
fn unsupported_pattern_disabled_ineligible_and_secret_targets_are_denied() {
    let adapter = FakeToggleAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    adapter.set_tree(
        100,
        vec![
            no_pattern_item("item-no-pattern"),
            disabled_item("item-disabled"),
            button_element("btn-1"),
            list_item_element("item-list"),
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
        let expected_toggled = node["toggled"].as_bool().unwrap_or(false);
        let error = registry
            .toggle_element(
                &adapter,
                element_id,
                tree_generation,
                control_type,
                expected_toggled,
                true,
                WORKSPACE,
                POLICY,
            )
            .expect_err("unsupported, disabled, ineligible, or secret target must be denied");
        assert!(matches!(
            error.code,
            FailureCode::CapabilityDenied | FailureCode::TargetStale
        ));
    }
    assert_eq!(adapter.toggle_count(), 0);
}

#[test]
fn protected_window_toggle_is_denied() {
    let adapter = FakeToggleAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(
        4242,
        vec![fake_window(100, "Orcel Approval", "OrcelApproveDialog", 1)],
    );
    adapter.set_tree(100, vec![toggle_item("item-1")]);
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    assert_eq!(list["window_count"], 0);
    assert_eq!(list["protected_omitted"], 1);
}

#[test]
fn toggled_item_requires_true_expected_state() {
    let adapter = FakeToggleAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    adapter.set_tree(100, vec![toggled_item("item-toggled")]);
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
        .toggle_element(
            &adapter,
            &element_id,
            tree_generation,
            "CheckBox",
            true,
            false,
            WORKSPACE,
            POLICY,
        )
        .expect("untoggle of a toggled item succeeds");
    assert_eq!(adapter.toggle_count(), 1);
}

#[test]
fn workspace_policy_and_disappearance_drift_fail_closed() {
    let (adapter, mut registry, element_id, tree_generation, _) = setup_item();
    let error = registry
        .toggle_element(
            &adapter,
            &element_id,
            tree_generation,
            "CheckBox",
            false,
            true,
            "foreign-workspace",
            POLICY,
        )
        .expect_err("foreign workspace must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    let error = registry
        .toggle_element(
            &adapter,
            &element_id,
            tree_generation,
            "CheckBox",
            false,
            true,
            WORKSPACE,
            "sg-000030-v1",
        )
        .expect_err("policy drift must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert!(registry.remove_element(&element_id));
    let error = registry
        .toggle_element(
            &adapter,
            &element_id,
            tree_generation,
            "CheckBox",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("disappeared element must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.toggle_count(), 0);
}

#[test]
fn superseded_process_toggle_fails_closed() {
    let (adapter, mut registry, element_id, tree_generation, _) = setup_item();
    let native = fake_process(4242, "notepad", 9001);
    let (process_id, _) = registry.register_process(&native, WORKSPACE, POLICY);
    assert!(registry.mark_process_superseded(&process_id));
    let error = registry
        .toggle_binding(
            &element_id,
            tree_generation,
            "CheckBox",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("superseded process binding must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.toggle_count(), 0);
}

#[test]
fn native_adapter_toggle_reports_unavailable_without_fabrication() {
    let native = NativeAdapter::new();
    let error = native
        .toggle_element(123, "runtime-1", true)
        .expect_err("native toggle without a broker must be unavailable");
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
        fn toggle_element(
            &self,
            _hwnd: u64,
            _runtime_id: &str,
            _toggled: bool,
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
        tree: vec![toggle_item("item-1")],
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
        .toggle_element(
            &failing,
            &element_id,
            tree_generation,
            "CheckBox",
            false,
            true,
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
