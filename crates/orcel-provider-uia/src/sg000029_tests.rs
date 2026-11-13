//! SG-000029 deterministic structured ValuePattern actuation tests.
//!
//! These tests use an injected fake adapter, so they prove value binding,
//! approval digest shape, stale fail-closed behavior, protected-surface
//! exclusion, password and oversized denial, and fallback denial
//! deterministically on every platform without a live desktop. Real Windows
//! process identity is proven separately through the native adapter test on
//! Windows.

use super::*;
use std::cell::RefCell;
use std::collections::HashMap;

const WORKSPACE: &str = "uia-value-test-workspace";
const POLICY: &str = "sg-000029-v1";

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

fn value_edit(runtime: &str) -> NativeElement {
    NativeElement {
        runtime_id: runtime.to_owned(),
        control_type: "Edit".to_owned(),
        automation_id: format!("auto-{runtime}"),
        name: "Name".to_owned(),
        enabled: true,
        selected: false,
        toggled: false,
        scroll_horizontal_percent: 0,
        scroll_vertical_percent: 0,
        patterns: vec![VALUE_PATTERN_NAME.to_owned()],
        value: Some("old".to_owned()),
        value_is_password: false,
        children: Vec::new(),
    }
}

fn disabled_edit(runtime: &str) -> NativeElement {
    let mut element = value_edit(runtime);
    element.enabled = false;
    element
}

fn no_pattern_edit(runtime: &str) -> NativeElement {
    let mut element = value_edit(runtime);
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

fn password_edit(runtime: &str) -> NativeElement {
    NativeElement {
        runtime_id: runtime.to_owned(),
        control_type: "Edit".to_owned(),
        automation_id: "login-password".to_owned(),
        name: "Password".to_owned(),
        enabled: true,
        selected: false,
        toggled: false,
        scroll_horizontal_percent: 0,
        scroll_vertical_percent: 0,
        patterns: vec![VALUE_PATTERN_NAME.to_owned()],
        value: Some("hunter2".to_owned()),
        value_is_password: true,
        children: Vec::new(),
    }
}

#[derive(Default)]
struct FakeValueState {
    processes: Vec<NativeProcess>,
    windows_by_pid: HashMap<u32, Vec<NativeWindow>>,
    trees_by_hwnd: HashMap<u64, Vec<NativeElement>>,
    writes: Vec<(u64, String, String)>,
}

#[derive(Default)]
struct FakeValueAdapter {
    state: RefCell<FakeValueState>,
}

impl FakeValueAdapter {
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

    fn write_count(&self) -> usize {
        self.state.borrow().writes.len()
    }
}

impl UiaAdapter for FakeValueAdapter {
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

    fn set_value_element(&self, hwnd: u64, runtime_id: &str, value: &str) -> Result<(), UiaError> {
        self.state
            .borrow_mut()
            .writes
            .push((hwnd, runtime_id.to_owned(), value.to_owned()));
        Ok(())
    }
}

fn setup_edit() -> (FakeValueAdapter, UiaRegistry, String, u64, String) {
    let adapter = FakeValueAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    adapter.set_tree(100, vec![value_edit("edit-1")]);
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
fn value_shape_and_eligibility_helpers_behave() {
    assert!(is_value_shape("uia.element", "set_value"));
    assert!(!is_value_shape("uia.element", "invoke"));
    assert!(!is_value_shape("uia.element", "observe"));
    assert!(is_value_eligible_control_type("Edit"));
    assert!(is_value_eligible_control_type("Document"));
    assert!(is_value_eligible_control_type("ComboBox"));
    assert!(!is_value_eligible_control_type("Button"));
    assert!(!is_value_eligible_control_type("CheckBox"));
    assert!(!is_value_eligible_control_type(""));
    assert_eq!(VALUE_PATTERN_NAME, "Value");
    assert_eq!(MAX_VALUE_CHARS, 1024);
    assert_eq!(value_content_digest("hello").len(), 64);
    assert_eq!(value_content_digest("hello"), value_content_digest("hello"));
    assert_ne!(value_content_digest("hello"), value_content_digest("world"));
}

#[test]
fn happy_path_set_value_actuates_and_invalidates_old_tree() {
    let (adapter, mut registry, element_id, tree_generation, window_id) = setup_edit();
    let binding = registry
        .value_binding(
            &element_id,
            tree_generation,
            "Edit",
            "Ada",
            WORKSPACE,
            POLICY,
        )
        .expect("binding resolves");
    assert_eq!(binding.element_id, element_id);
    assert_eq!(binding.control_type, "Edit");
    assert_eq!(binding.value_digest, value_content_digest("Ada"));
    let digest = value_approval_digest(WORKSPACE, POLICY, &binding);
    assert_eq!(digest.len(), 64);
    let evidence = registry
        .set_value_element(
            &adapter,
            &element_id,
            tree_generation,
            "Edit",
            "Ada",
            WORKSPACE,
            POLICY,
        )
        .expect("set_value succeeds");
    assert_eq!(evidence["action"], "set_value");
    assert_eq!(evidence["element_id"], element_id.as_str());
    assert_eq!(evidence["control_type"], "Edit");
    assert_eq!(evidence["pattern"], "Value");
    assert_eq!(
        evidence["value_digest"],
        value_content_digest("Ada").as_str()
    );
    assert!(evidence.get("value").is_none());
    assert_eq!(adapter.write_count(), 1);
    let error = registry
        .set_value_element(
            &adapter,
            &element_id,
            tree_generation,
            "Edit",
            "Ada",
            WORKSPACE,
            POLICY,
        )
        .expect_err("replay against the old tree must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.write_count(), 1);
    let (_, new_tree) = registry
        .window_generations(&window_id)
        .expect("window remains");
    assert!(new_tree > tree_generation);
}

#[test]
fn value_digest_binds_material_state() {
    let (adapter, registry, element_id, tree_generation, _) = setup_edit();
    let first = registry
        .value_binding(
            &element_id,
            tree_generation,
            "Edit",
            "Ada",
            WORKSPACE,
            POLICY,
        )
        .expect("binding");
    let base_digest = value_approval_digest(WORKSPACE, POLICY, &first);
    let second = registry
        .value_binding(
            &element_id,
            tree_generation,
            "Edit",
            "Grace",
            WORKSPACE,
            POLICY,
        )
        .expect("binding");
    assert_ne!(
        base_digest,
        value_approval_digest(WORKSPACE, POLICY, &second)
    );
    assert_ne!(
        base_digest,
        value_approval_digest("foreign-workspace", POLICY, &first)
    );
    assert_ne!(
        base_digest,
        value_approval_digest(WORKSPACE, "sg-000028-v1", &first)
    );
    let _ = adapter;
}

#[test]
fn malformed_oversized_and_ineligible_value_targets_fail_closed() {
    let (adapter, mut registry, element_id, tree_generation, _) = setup_edit();
    let error = registry
        .set_value_element(
            &adapter,
            "uia-el-short",
            tree_generation,
            "Edit",
            "Ada",
            WORKSPACE,
            POLICY,
        )
        .expect_err("malformed element must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);
    let error = registry
        .set_value_element(
            &adapter,
            &element_id,
            tree_generation,
            "",
            "Ada",
            WORKSPACE,
            POLICY,
        )
        .expect_err("empty control type must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);
    let error = registry
        .set_value_element(
            &adapter,
            &element_id,
            tree_generation,
            "Button",
            "Ada",
            WORKSPACE,
            POLICY,
        )
        .expect_err("ineligible control type must fail");
    assert!(matches!(
        error.code,
        FailureCode::CapabilityDenied | FailureCode::TargetStale
    ));
    let oversized = "x".repeat(MAX_VALUE_CHARS + 1);
    let error = registry
        .set_value_element(
            &adapter,
            &element_id,
            tree_generation,
            "Edit",
            &oversized,
            WORKSPACE,
            POLICY,
        )
        .expect_err("oversized value must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);
    let error = registry
        .set_value_element(
            &adapter,
            &element_id,
            tree_generation,
            "Edit",
            "bad\0value",
            WORKSPACE,
            POLICY,
        )
        .expect_err("NUL value must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);
    let forged = format!("{ELEMENT_ID_PREFIX}{}", "d".repeat(ID_HEX_CHARS));
    let error = registry
        .set_value_element(
            &adapter,
            &forged,
            tree_generation,
            "Edit",
            "Ada",
            WORKSPACE,
            POLICY,
        )
        .expect_err("unknown element must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.write_count(), 0);
}

#[test]
fn stale_tree_and_control_type_drift_fail_closed() {
    let (adapter, mut registry, element_id, tree_generation, window_id) = setup_edit();
    let error = registry
        .set_value_element(
            &adapter,
            &element_id,
            tree_generation + 1,
            "Edit",
            "Ada",
            WORKSPACE,
            POLICY,
        )
        .expect_err("wrong tree generation must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    let error = registry
        .set_value_element(
            &adapter,
            &element_id,
            tree_generation,
            "Document",
            "Ada",
            WORKSPACE,
            POLICY,
        )
        .expect_err("changed control type must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert!(registry.invalidate_tree(&window_id));
    let error = registry
        .set_value_element(
            &adapter,
            &element_id,
            tree_generation,
            "Edit",
            "Ada",
            WORKSPACE,
            POLICY,
        )
        .expect_err("regenerated tree must fail the old identity");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.write_count(), 0);
}

#[test]
fn unsupported_pattern_disabled_ineligible_and_secret_targets_are_denied() {
    let adapter = FakeValueAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    adapter.set_tree(
        100,
        vec![
            no_pattern_edit("edit-no-pattern"),
            disabled_edit("edit-disabled"),
            button_element("btn-1"),
            password_edit("edit-password"),
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
        let error = registry
            .set_value_element(
                &adapter,
                element_id,
                tree_generation,
                control_type,
                "Ada",
                WORKSPACE,
                POLICY,
            )
            .expect_err("unsupported, disabled, ineligible, or secret target must be denied");
        assert!(matches!(
            error.code,
            FailureCode::CapabilityDenied | FailureCode::TargetStale
        ));
    }
    assert_eq!(adapter.write_count(), 0);
}

#[test]
fn protected_window_invoke_is_denied_for_value() {
    let adapter = FakeValueAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(
        4242,
        vec![fake_window(100, "Orcel Approval", "OrcelApproveDialog", 1)],
    );
    adapter.set_tree(100, vec![value_edit("edit-1")]);
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    assert_eq!(list["window_count"], 0);
    assert_eq!(list["protected_omitted"], 1);
}

#[test]
fn workspace_policy_and_disappearance_drift_fail_closed() {
    let (adapter, mut registry, element_id, tree_generation, _) = setup_edit();
    let error = registry
        .set_value_element(
            &adapter,
            &element_id,
            tree_generation,
            "Edit",
            "Ada",
            "foreign-workspace",
            POLICY,
        )
        .expect_err("foreign workspace must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    let error = registry
        .set_value_element(
            &adapter,
            &element_id,
            tree_generation,
            "Edit",
            "Ada",
            WORKSPACE,
            "sg-000028-v1",
        )
        .expect_err("policy drift must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert!(registry.remove_element(&element_id));
    let error = registry
        .set_value_element(
            &adapter,
            &element_id,
            tree_generation,
            "Edit",
            "Ada",
            WORKSPACE,
            POLICY,
        )
        .expect_err("disappeared element must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.write_count(), 0);
}

#[test]
fn superseded_process_value_fails_closed() {
    let (adapter, mut registry, element_id, tree_generation, _) = setup_edit();
    let native = fake_process(4242, "notepad", 9001);
    let (process_id, _) = registry.register_process(&native, WORKSPACE, POLICY);
    assert!(registry.mark_process_superseded(&process_id));
    let error = registry
        .value_binding(
            &element_id,
            tree_generation,
            "Edit",
            "Ada",
            WORKSPACE,
            POLICY,
        )
        .expect_err("superseded process binding must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    assert_eq!(adapter.write_count(), 0);
}

#[test]
fn native_adapter_set_value_reports_unavailable_without_fabrication() {
    let native = NativeAdapter::new();
    let error = native
        .set_value_element(123, "runtime-1", "Ada")
        .expect_err("native set_value without a broker must be unavailable");
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
        fn set_value_element(
            &self,
            _hwnd: u64,
            _runtime_id: &str,
            _value: &str,
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
        tree: vec![value_edit("edit-1")],
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
        .set_value_element(
            &failing,
            &element_id,
            tree_generation,
            "Edit",
            "Ada",
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
