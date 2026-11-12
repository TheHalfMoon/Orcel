//! SG-000030 deterministic structured SelectionPattern actuation tests.
//!
//! These tests use an injected fake adapter, so they prove select binding,
//! approval digest shape, stale fail-closed behavior, protected-surface
//! exclusion, password denial, expected-state enforcement, and fallback
//! denial deterministically on every platform without a live desktop. Real
//! Windows process identity is proven separately through the native adapter
//! test on Windows.

use super::*;
use std::cell::RefCell;
use std::collections::HashMap;

const WORKSPACE: &str = "uia-select-test-workspace";
const POLICY: &str = "sg-000030-v1";

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

fn select_item(runtime: &str) -> NativeElement {
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

fn selected_item(runtime: &str) -> NativeElement {
    let mut element = select_item(runtime);
    element.selected = true;
    element
}

fn disabled_item(runtime: &str) -> NativeElement {
    let mut element = select_item(runtime);
    element.enabled = false;
    element
}

fn no_pattern_item(runtime: &str) -> NativeElement {
    let mut element = select_item(runtime);
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

fn password_item(runtime: &str) -> NativeElement {
    NativeElement {
        runtime_id: runtime.to_owned(),
        control_type: "ListItem".to_owned(),
        automation_id: "login-password".to_owned(),
        name: "Password".to_owned(),
        enabled: true,
        selected: false,
        toggled: false,
        scroll_horizontal_percent: 0,
        scroll_vertical_percent: 0,
        patterns: vec![SELECT_PATTERN_NAME.to_owned()],
        value: Some("hunter2".to_owned()),
        value_is_password: true,
        children: Vec::new(),
    }
}

#[derive(Default)]
struct FakeSelectState {
    processes: Vec<NativeProcess>,
    windows_by_pid: HashMap<u32, Vec<NativeWindow>>,
    trees_by_hwnd: HashMap<u64, Vec<NativeElement>>,
    selects: Vec<(u64, String, bool)>,
}

#[derive(Default)]
struct FakeSelectAdapter {
    state: RefCell<FakeSelectState>,
}

impl FakeSelectAdapter {
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

    fn select_count(&self) -> usize {
        self.state.borrow().selects.len()
    }
}

impl UiaAdapter for FakeSelectAdapter {
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

    fn select_element(&self, hwnd: u64, runtime_id: &str, selected: bool) -> Result<(), UiaError> {
        self.state
            .borrow_mut()
            .selects
            .push((hwnd, runtime_id.to_owned(), selected));
        Ok(())
    }
}

fn setup_item() -> (FakeSelectAdapter, UiaRegistry, String, u64, String) {
    let adapter = FakeSelectAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    adapter.set_tree(100, vec![select_item("item-1")]);
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
fn select_shape_and_eligibility_helpers_behave() {
    assert!(is_select_shape("uia.element", "select"));
    assert!(!is_select_shape("uia.element", "invoke"));
    assert!(!is_select_shape("uia.element", "set_value"));
    assert!(!is_select_shape("uia.element", "observe"));
    assert!(is_select_eligible_control_type("ListItem"));
    assert!(is_select_eligible_control_type("TreeItem"));
    assert!(is_select_eligible_control_type("TabItem"));
    assert!(!is_select_eligible_control_type("Button"));
    assert!(!is_select_eligible_control_type("Edit"));
    assert!(!is_select_eligible_control_type("CheckBox"));
    assert!(!is_select_eligible_control_type(""));
    assert_eq!(SELECT_PATTERN_NAME, "SelectionItem");
    assert_eq!(SELECT_SCHEMA, "orcel-uia-select-v1");
    assert!(!is_denied_uia_shape("uia.element", "select"));
    // NOTE (SG-000031 successor): `uia.element/toggle` is lawfully
    // authorized by the SG-000031 successor grain, so it is no longer
    // denied for current-tree authority. Scroll, synthetic input,
    // coordinates, screenshots, clipboard, network, and elevation remain
    // denied.
    assert!(!is_denied_uia_shape("uia.element", "toggle"));
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
fn happy_path_select_actuates_and_invalidates_old_tree() {
    let (adapter, mut registry, element_id, tree_generation, window_id) = setup_item();
    let binding = registry
        .select_binding(
            &element_id,
            tree_generation,
            "ListItem",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect("binding resolves");
    assert_eq!(binding.element_id, element_id);
    assert_eq!(binding.control_type, "ListItem");
    assert!(!binding.expected_selected);
    assert!(binding.selected);
    let digest = select_approval_digest(WORKSPACE, POLICY, &binding);
    assert_eq!(digest.len(), 64);
    let evidence = registry
        .select_element(
            &adapter,
            &element_id,
            tree_generation,
            "ListItem",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect("select succeeds");
    assert_eq!(evidence["action"], "select");
    assert_eq!(evidence["element_id"], element_id.as_str());
    assert_eq!(evidence["control_type"], "ListItem");
    assert_eq!(evidence["pattern"], "SelectionItem");
    assert_eq!(evidence["expected_selected"], false);
    assert_eq!(evidence["selected"], true);
    assert_eq!(adapter.select_count(), 1);
    let error = registry
        .select_element(
            &adapter,
            &element_id,
            tree_generation,
            "ListItem",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("replay against the old tree must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.select_count(), 1);
    let (_, new_tree) = registry
        .window_generations(&window_id)
        .expect("window remains");
    assert!(new_tree > tree_generation);
}

#[test]
fn select_digest_binds_material_state() {
    let (adapter, registry, element_id, tree_generation, _) = setup_item();
    let first = registry
        .select_binding(
            &element_id,
            tree_generation,
            "ListItem",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect("binding");
    let base_digest = select_approval_digest(WORKSPACE, POLICY, &first);
    let second = registry
        .select_binding(
            &element_id,
            tree_generation,
            "ListItem",
            false,
            false,
            WORKSPACE,
            POLICY,
        )
        .expect("binding");
    assert_ne!(
        base_digest,
        select_approval_digest(WORKSPACE, POLICY, &second)
    );
    assert_ne!(
        base_digest,
        select_approval_digest("foreign-workspace", POLICY, &first)
    );
    assert_ne!(
        base_digest,
        select_approval_digest(WORKSPACE, "sg-000029-v1", &first)
    );
    let _ = adapter;
}

#[test]
fn malformed_and_ineligible_select_targets_fail_closed() {
    let (adapter, mut registry, element_id, tree_generation, _) = setup_item();
    let error = registry
        .select_element(
            &adapter,
            "uia-el-short",
            tree_generation,
            "ListItem",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("malformed element must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);
    let error = registry
        .select_element(
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
        .select_element(
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
    let forged = format!("{ELEMENT_ID_PREFIX}{}", "d".repeat(ID_HEX_CHARS));
    let error = registry
        .select_element(
            &adapter,
            &forged,
            tree_generation,
            "ListItem",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("unknown element must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.select_count(), 0);
}

#[test]
fn expected_state_drift_fails_closed() {
    let (adapter, mut registry, element_id, tree_generation, _) = setup_item();
    let error = registry
        .select_element(
            &adapter,
            &element_id,
            tree_generation,
            "ListItem",
            true,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("wrong expected selection must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.select_count(), 0);
}

#[test]
fn stale_tree_and_control_type_drift_fail_closed() {
    let (adapter, mut registry, element_id, tree_generation, window_id) = setup_item();
    let error = registry
        .select_element(
            &adapter,
            &element_id,
            tree_generation + 1,
            "ListItem",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("wrong tree generation must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    let error = registry
        .select_element(
            &adapter,
            &element_id,
            tree_generation,
            "TreeItem",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("changed control type must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert!(registry.invalidate_tree(&window_id));
    let error = registry
        .select_element(
            &adapter,
            &element_id,
            tree_generation,
            "ListItem",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("regenerated tree must fail the old identity");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.select_count(), 0);
}

#[test]
fn unsupported_pattern_disabled_ineligible_and_secret_targets_are_denied() {
    let adapter = FakeSelectAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    adapter.set_tree(
        100,
        vec![
            no_pattern_item("item-no-pattern"),
            disabled_item("item-disabled"),
            button_element("btn-1"),
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
    assert_eq!(nodes.len(), 4);
    for node in nodes {
        let element_id = node["element_id"].as_str().expect("element id");
        let tree_generation = tree["tree_generation"].as_u64().expect("tree generation");
        let control_type = node["control_type"].as_str().expect("control type");
        let expected_selected = node["selected"].as_bool().unwrap_or(false);
        let error = registry
            .select_element(
                &adapter,
                element_id,
                tree_generation,
                control_type,
                expected_selected,
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
    assert_eq!(adapter.select_count(), 0);
}

#[test]
fn protected_window_select_is_denied() {
    let adapter = FakeSelectAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(
        4242,
        vec![fake_window(100, "Orcel Approval", "OrcelApproveDialog", 1)],
    );
    adapter.set_tree(100, vec![select_item("item-1")]);
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    assert_eq!(list["window_count"], 0);
    assert_eq!(list["protected_omitted"], 1);
}

#[test]
fn selected_item_requires_true_expected_state() {
    let adapter = FakeSelectAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    adapter.set_tree(100, vec![selected_item("item-selected")]);
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
        .select_element(
            &adapter,
            &element_id,
            tree_generation,
            "ListItem",
            true,
            false,
            WORKSPACE,
            POLICY,
        )
        .expect("deselect of a selected item succeeds");
    assert_eq!(adapter.select_count(), 1);
}

#[test]
fn workspace_policy_and_disappearance_drift_fail_closed() {
    let (adapter, mut registry, element_id, tree_generation, _) = setup_item();
    let error = registry
        .select_element(
            &adapter,
            &element_id,
            tree_generation,
            "ListItem",
            false,
            true,
            "foreign-workspace",
            POLICY,
        )
        .expect_err("foreign workspace must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    let error = registry
        .select_element(
            &adapter,
            &element_id,
            tree_generation,
            "ListItem",
            false,
            true,
            WORKSPACE,
            "sg-000029-v1",
        )
        .expect_err("policy drift must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert!(registry.remove_element(&element_id));
    let error = registry
        .select_element(
            &adapter,
            &element_id,
            tree_generation,
            "ListItem",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("disappeared element must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.select_count(), 0);
}

#[test]
fn superseded_process_select_fails_closed() {
    let (adapter, mut registry, element_id, tree_generation, _) = setup_item();
    let native = fake_process(4242, "notepad", 9001);
    let (process_id, _) = registry.register_process(&native, WORKSPACE, POLICY);
    assert!(registry.mark_process_superseded(&process_id));
    let error = registry
        .select_binding(
            &element_id,
            tree_generation,
            "ListItem",
            false,
            true,
            WORKSPACE,
            POLICY,
        )
        .expect_err("superseded process binding must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.select_count(), 0);
}

#[test]
fn native_adapter_select_reports_unavailable_without_fabrication() {
    let native = NativeAdapter::new();
    let error = native
        .select_element(123, "runtime-1", true)
        .expect_err("native select without a broker must be unavailable");
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
        fn select_element(
            &self,
            _hwnd: u64,
            _runtime_id: &str,
            _selected: bool,
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
        tree: vec![select_item("item-1")],
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
        .select_element(
            &failing,
            &element_id,
            tree_generation,
            "ListItem",
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
