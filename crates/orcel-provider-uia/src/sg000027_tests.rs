//! SG-000027 deterministic read-only UIA observation tests.
//!
//! These tests use an injected fake adapter, so they prove policy logic,
//! typed identity binding, stale fail-closed behavior, redaction, bounds,
//! and protected-surface exclusion deterministically on every platform
//! without a live desktop. Real Windows process identity is proven
//! separately through the native adapter test on Windows.

use super::*;
use std::cell::RefCell;
use std::collections::HashMap;

const WORKSPACE: &str = "uia-test-workspace";
const POLICY: &str = "sg-000027-v1";

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

fn fake_element(
    runtime: &str,
    control: &str,
    name: &str,
    value: Option<&str>,
    children: Vec<NativeElement>,
) -> NativeElement {
    NativeElement {
        runtime_id: runtime.to_owned(),
        control_type: control.to_owned(),
        automation_id: format!("auto-{runtime}"),
        name: name.to_owned(),
        enabled: true,
        selected: false,
        toggled: false,
        scroll_horizontal_percent: 0,
        scroll_vertical_percent: 0,
        patterns: vec!["LegacyIAccessible".to_owned()],
        value: value.map(str::to_owned),
        value_is_password: false,
        children,
    }
}

fn password_element(runtime: &str) -> NativeElement {
    NativeElement {
        runtime_id: runtime.to_owned(),
        control_type: "password".to_owned(),
        automation_id: "login-password".to_owned(),
        name: "Password".to_owned(),
        enabled: true,
        selected: false,
        toggled: false,
        scroll_horizontal_percent: 0,
        scroll_vertical_percent: 0,
        patterns: vec!["Value".to_owned()],
        value: Some("hunter2".to_owned()),
        value_is_password: true,
        children: Vec::new(),
    }
}

#[derive(Default)]
struct FakeState {
    processes: Vec<NativeProcess>,
    windows_by_pid: HashMap<u32, Vec<NativeWindow>>,
    trees_by_hwnd: HashMap<u64, Vec<NativeElement>>,
}

#[derive(Default)]
struct FakeAdapter {
    state: RefCell<FakeState>,
}

impl FakeAdapter {
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
}

impl UiaAdapter for FakeAdapter {
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
}

fn listed_window_id(list: &Value, index: usize) -> (String, u64, String, u64) {
    let entry = &list["windows"][index];
    (
        entry["process_id"].as_str().expect("process id").to_owned(),
        entry["process_generation"]
            .as_u64()
            .expect("process generation"),
        entry["window_id"].as_str().expect("window id").to_owned(),
        entry["window_generation"]
            .as_u64()
            .expect("window generation"),
    )
}

#[test]
fn process_identity_binds_server_facts_and_rejects_forgery() {
    let adapter = FakeAdapter::with_process(4242, "notepad", 9001);
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    assert_eq!(list["window_count"], 0);
    let native = fake_process(4242, "notepad", 9001);
    let (process_id, generation) = registry.register_process(&native, WORKSPACE, POLICY);
    assert!(is_well_formed_process_id(&process_id));
    let observed = registry
        .observe_process(&process_id, generation, WORKSPACE, POLICY)
        .unwrap();
    assert_eq!(observed["pid"], 4242);
    assert_eq!(observed["exe_name"], "notepad.exe");
    assert_eq!(observed["process_generation"], 9001);
    assert_eq!(observed["session_verified"], true);

    let forged = format!("{PROCESS_ID_PREFIX}{}", "a".repeat(ID_HEX_CHARS));
    let error = registry
        .observe_process(&forged, generation, WORKSPACE, POLICY)
        .expect_err("forged process identity must fail");
    assert_eq!(error.code, FailureCode::TargetStale);

    let error = registry
        .observe_process("uia-proc-short", generation, WORKSPACE, POLICY)
        .expect_err("malformed process identity must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);

    let error = registry
        .observe_process(&process_id, generation + 1, WORKSPACE, POLICY)
        .expect_err("wrong process generation must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    let _ = list;
}

#[test]
fn pid_reuse_and_restart_fail_closed() {
    let adapter = FakeAdapter::with_process(4242, "notepad", 9001);
    let mut registry = UiaRegistry::new();
    let native = fake_process(4242, "notepad", 9001);
    let (process_id, generation) = registry.register_process(&native, WORKSPACE, POLICY);
    assert!(registry.mark_process_superseded(&process_id));
    let error = registry
        .observe_process(&process_id, generation, WORKSPACE, POLICY)
        .expect_err("superseded process must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    let _ = adapter;
}

#[test]
fn wrong_workspace_and_policy_revision_fail_closed() {
    let mut registry = UiaRegistry::new();
    let native = fake_process(1111, "calc", 7);
    let (process_id, generation) = registry.register_process(&native, WORKSPACE, POLICY);
    let error = registry
        .observe_process(&process_id, generation, "foreign-workspace", POLICY)
        .expect_err("foreign workspace must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    let error = registry
        .observe_process(&process_id, generation, WORKSPACE, "sg-000026-v1")
        .expect_err("policy drift must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
}

#[test]
fn window_list_binds_typed_identities_and_omits_protected_surfaces() {
    let adapter = FakeAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(
        4242,
        vec![
            fake_window(100, "Document", "Notepad", 1),
            fake_window(200, "Orcel Approval", "OrcelApproveDialog", 1),
        ],
    );
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    assert_eq!(list["window_count"], 1);
    assert_eq!(list["protected_omitted"], 1);
    let (process_id, process_generation, window_id, window_generation) = listed_window_id(&list, 0);
    assert!(is_well_formed_process_id(&process_id));
    assert!(is_well_formed_window_id(&window_id));
    let observed = registry
        .observe_window(&window_id, window_generation, WORKSPACE, POLICY)
        .unwrap();
    assert_eq!(observed["title"], "Document");
    assert_eq!(observed["process_generation"], process_generation);
}

#[test]
fn stale_and_malformed_window_identities_fail_closed() {
    let registry = UiaRegistry::new();
    let forged = format!("{WINDOW_ID_PREFIX}{}", "b".repeat(ID_HEX_CHARS));
    let error = registry
        .observe_window(&forged, 1, WORKSPACE, POLICY)
        .expect_err("unknown window must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    let error = registry
        .observe_window("uia-win-short", 1, WORKSPACE, POLICY)
        .expect_err("malformed window must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);
}

#[test]
fn reused_window_handle_with_replacement_fails_old_generation() {
    let adapter = FakeAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    let mut registry = UiaRegistry::new();
    let first = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    let (_, _, window_id, old_generation) = listed_window_id(&first, 0);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 2)]);
    let second = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    let (_, _, same_id, new_generation) = listed_window_id(&second, 0);
    assert_eq!(window_id, same_id);
    assert!(new_generation > old_generation);
    let error = registry
        .observe_window(&window_id, old_generation, WORKSPACE, POLICY)
        .expect_err("replaced window must fail its old generation");
    assert_eq!(error.code, FailureCode::TargetStale);
    registry
        .observe_window(&window_id, new_generation, WORKSPACE, POLICY)
        .expect("current window generation observes");
}

#[test]
fn window_without_live_owning_process_fails_closed() {
    let adapter = FakeAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    let (process_id, process_generation, window_id, window_generation) = listed_window_id(&list, 0);
    assert!(registry.mark_process_superseded(&process_id));
    let error = registry
        .observe_window(&window_id, window_generation, WORKSPACE, POLICY)
        .expect_err("window of a restarted process must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
    let _ = process_generation;
}

#[test]
fn protected_window_direct_observation_is_denied() {
    let adapter = FakeAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    let (_, _, window_id, _) = listed_window_id(&list, 0);
    adapter.set_windows(
        4242,
        vec![fake_window(100, "Orcel Approval", "OrcelApproveDialog", 1)],
    );
    let relist = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    assert_eq!(relist["window_count"], 0);
    assert_eq!(relist["protected_omitted"], 1);
    let (current_window_generation, _) = registry
        .window_generations(&window_id)
        .expect("protected record retained");
    let error = registry
        .observe_window(&window_id, current_window_generation, WORKSPACE, POLICY)
        .expect_err("protected Orcel surface must be denied");
    assert_eq!(error.code, FailureCode::CapabilityDenied);
}

#[test]
fn tree_observation_is_bounded_and_reports_truncation() {
    let adapter = FakeAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    let mut children = Vec::new();
    for index in 0..20u32 {
        children.push(fake_element(
            &format!("child-{index}"),
            "button",
            &format!("Button {index}"),
            None,
            Vec::new(),
        ));
    }
    adapter.set_tree(
        100,
        vec![fake_element("root", "window", "Root", None, children)],
    );
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    let (_, _, window_id, window_generation) = listed_window_id(&list, 0);
    let tree = registry
        .observe_tree(
            &adapter,
            &window_id,
            window_generation,
            Some(1),
            Some(5),
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    assert_eq!(tree["node_count"], 5);
    assert_eq!(tree["truncated"], true);
    let full = registry
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
    assert_eq!(full["node_count"], 21);
    assert_eq!(full["truncated"], false);
    let error = registry
        .observe_tree(
            &adapter,
            &window_id,
            window_generation,
            None,
            Some(0),
            WORKSPACE,
            POLICY,
        )
        .expect_err("zero node budget must fail");
    assert_eq!(error.code, FailureCode::InvalidRequest);
}

#[test]
fn password_and_secret_values_are_redacted() {
    let adapter = FakeAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Login", "Dialog", 1)]);
    adapter.set_tree(
        100,
        vec![
            password_element("pwd-1"),
            fake_element("token-1", "edit", "API Token", Some("abc123"), Vec::new()),
            fake_element("user-1", "edit", "Username", Some("ada"), Vec::new()),
        ],
    );
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    let (_, _, window_id, window_generation) = listed_window_id(&list, 0);
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
    assert_eq!(nodes.len(), 3);
    for node in nodes.iter().take(2) {
        assert_eq!(node["redacted"], true);
        assert!(node["value"].is_null());
    }
    assert_eq!(nodes[2]["redacted"], false);
    assert_eq!(nodes[2]["value"], "ada");
    let serialized = serde_json::to_string(&tree).expect("serialize");
    assert!(!serialized.contains("hunter2"));
    assert!(!serialized.contains("abc123"));
}

#[test]
fn stale_removed_and_replaced_elements_fail_closed() {
    let adapter = FakeAdapter::with_process(4242, "notepad", 9001);
    adapter.set_windows(4242, vec![fake_window(100, "Document", "Notepad", 1)]);
    adapter.set_tree(
        100,
        vec![fake_element("btn-1", "button", "Save", None, Vec::new())],
    );
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    let (_, _, window_id, window_generation) = listed_window_id(&list, 0);
    let first = registry
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
    let element_id = first["nodes"][0]["element_id"]
        .as_str()
        .expect("element id")
        .to_owned();
    let tree_generation = first["tree_generation"].as_u64().expect("tree generation");
    assert!(is_well_formed_element_id(&element_id));
    registry
        .observe_element(&element_id, tree_generation, WORKSPACE, POLICY)
        .expect("fresh element observes");

    assert!(registry.invalidate_tree(&window_id));
    let error = registry
        .observe_element(&element_id, tree_generation, WORKSPACE, POLICY)
        .expect_err("regenerated tree must stale old elements");
    assert_eq!(error.code, FailureCode::TargetStale);

    adapter.set_tree(
        100,
        vec![fake_element("btn-1", "checkbox", "Save", None, Vec::new())],
    );
    let second = registry
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
    assert_eq!(second["nodes"][0]["control_type"], "checkbox");
    let new_generation = second["tree_generation"].as_u64().expect("generation");
    assert!(new_generation > tree_generation);
    registry
        .observe_element(&element_id, new_generation, WORKSPACE, POLICY)
        .expect("re-observed element uses the new generation");

    assert!(registry.remove_element(&element_id));
    let error = registry
        .observe_element(&element_id, new_generation, WORKSPACE, POLICY)
        .expect_err("removed element must fail");
    assert_eq!(error.code, FailureCode::TargetStale);
}

#[test]
fn long_strings_are_truncated_and_responses_stay_bounded() {
    let adapter = FakeAdapter::with_process(4242, "notepad", 9001);
    let long_title = "t".repeat(MAX_STRING_CHARS + 40);
    adapter.set_windows(4242, vec![fake_window(100, &long_title, "Notepad", 1)]);
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    let (_, _, window_id, window_generation) = listed_window_id(&list, 0);
    let observed = registry
        .observe_window(&window_id, window_generation, WORKSPACE, POLICY)
        .unwrap();
    assert_eq!(
        observed["title"].as_str().expect("title").chars().count(),
        MAX_STRING_CHARS
    );
    let bytes = serde_json::to_vec(&observed).expect("bytes").len();
    assert!(bytes <= MAX_RESPONSE_BYTES);
}

#[test]
fn uia_shape_catalog_authorizes_only_read_only_observation() {
    assert!(is_allowed_uia_shape("uia.process", "observe"));
    assert!(is_allowed_uia_shape("uia.window", "list"));
    assert!(is_allowed_uia_shape("uia.window", "observe"));
    assert!(is_allowed_uia_shape("uia.tree", "observe"));
    assert!(is_allowed_uia_shape("uia.element", "observe"));
    for (capability, operation) in DENIED_UIA_SHAPES {
        assert!(!is_allowed_uia_shape(capability, operation));
        assert!(is_denied_uia_shape(capability, operation));
    }
    assert!(!is_allowed_uia_shape("uia.element", "invoke"));
    assert!(!is_allowed_uia_shape("uia.input", "keyboard"));
    assert!(!is_allowed_uia_shape("uia.coordinates", "request"));
    assert!(!is_allowed_uia_shape("uia.screenshot", "capture"));
    assert!(!is_allowed_uia_shape("uia.elevation", "request"));
    assert!(!is_allowed_uia_shape("browser.dom", "click"));
}

#[test]
fn native_adapter_reports_real_process_without_fabricating_desktop() {
    let adapter = NativeAdapter::new();
    #[cfg(not(windows))]
    {
        let processes = adapter.list_processes().expect("native processes");
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].pid, std::process::id());
        assert!(!processes[0].exe_name.is_empty());
        assert!(processes[0]
            .exe_id
            .chars()
            .all(|byte| byte.is_ascii_hexdigit()));
        let error = adapter
            .list_windows(processes[0].pid)
            .expect_err("desktop enumeration off Windows must fail closed");
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
        let error = adapter
            .read_tree(12345)
            .expect_err("tree enumeration off Windows must fail closed");
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
    }
    // SG-000063: on Windows the adapter reports only real window owners in
    // the caller's session, never this process, and fails closed as
    // unavailable outside the interactive window station.
    #[cfg(windows)]
    match adapter.list_processes() {
        Ok(processes) => {
            for process in &processes {
                assert_ne!(process.pid, std::process::id());
                assert!(!process.exe_name.is_empty());
                assert!(process.exe_id.chars().all(|byte| byte.is_ascii_hexdigit()));
                assert_eq!(process.generation_source, "win32-creation-time");
                assert!(process.session_verified);
                assert_ne!(process.start_generation, 0);
            }
        }
        Err(error) => assert_eq!(error.code, FailureCode::ProviderUnavailable),
    }
}
