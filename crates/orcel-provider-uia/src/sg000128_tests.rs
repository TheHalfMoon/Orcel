//! SG-000128 deterministic scoped subtree observation tests, on an injected
//! fake adapter: root validation before replacement, every fail-closed root,
//! the cumulative-exposure budget and its resets, staleness after a scoped
//! call, redaction and bounds below the root.
use super::*;
use std::cell::RefCell;

const WORKSPACE: &str = "uia-test-workspace";
const POLICY: &str = "sg-000128-v1";

fn element(
    runtime: &str,
    control: &str,
    name: &str,
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
        patterns: vec!["Invoke".to_owned(), "Value".to_owned()],
        value: None,
        value_is_password: false,
        children,
    }
}

fn password(runtime: &str) -> NativeElement {
    NativeElement {
        value: Some("hunter2".to_owned()),
        value_is_password: true,
        ..element(runtime, "Edit", "Password", Vec::new())
    }
}

#[derive(Default)]
struct State {
    windows: Vec<NativeWindow>,
    tree: Vec<NativeElement>,
    subtree_fails: Option<FailureCode>,
    invoke_fails: bool,
    subtree_reads: Vec<String>,
}

#[derive(Default)]
struct Fake {
    state: RefCell<State>,
}

fn find<'a>(nodes: &'a [NativeElement], runtime: &str) -> Option<&'a NativeElement> {
    for node in nodes {
        if node.runtime_id == runtime {
            return Some(node);
        }
        if let Some(found) = find(&node.children, runtime) {
            return Some(found);
        }
    }
    None
}

impl UiaAdapter for Fake {
    fn list_processes(&self) -> Result<Vec<NativeProcess>, UiaError> {
        Ok(vec![NativeProcess {
            pid: 4242,
            exe_name: "electron.exe".into(),
            exe_id: digest_hex(&format!("{UIA_SCHEMA}|exe|electron"), ID_HEX_CHARS),
            session_id: 1,
            session_verified: true,
            start_generation: 7,
            generation_source: "fake-adapter",
        }])
    }
    fn list_windows(&self, _pid: u32) -> Result<Vec<NativeWindow>, UiaError> {
        Ok(self.state.borrow().windows.clone())
    }
    fn read_tree(&self, _hwnd: u64) -> Result<Vec<NativeElement>, UiaError> {
        Ok(self.state.borrow().tree.clone())
    }
    fn read_subtree(&self, _hwnd: u64, runtime_id: &str) -> Result<Vec<NativeElement>, UiaError> {
        let mut state = self.state.borrow_mut();
        state.subtree_reads.push(runtime_id.to_owned());
        if let Some(code) = state.subtree_fails.clone() {
            return Err(UiaError::new(code, "fake subtree failure"));
        }
        find(&state.tree, runtime_id)
            .cloned()
            .map(|node| vec![node])
            .ok_or_else(|| UiaError::new(FailureCode::TargetStale, "gone"))
    }
    fn invoke_element(&self, _hwnd: u64, _runtime_id: &str) -> Result<(), UiaError> {
        if self.state.borrow().invoke_fails {
            return Err(UiaError::new(
                FailureCode::ProviderUnavailable,
                "fake invoke failure",
            ));
        }
        Ok(())
    }
}

fn window(hwnd: u64, title: &str, nonce: u64) -> NativeWindow {
    NativeWindow {
        hwnd,
        title: title.into(),
        class: "Chrome_WidgetWin_1".into(),
        visible: true,
        window_nonce: nonce,
    }
}

/// A frame nine levels deep ending in a web Document that holds a form, as
/// Electron windows do: the unscoped tree stops at the Document.
fn electron_tree() -> Vec<NativeElement> {
    let form = vec![
        element("field-conflict", "Edit", "Conflict ID", Vec::new()),
        element("field-reason", "Edit", "Reason", Vec::new()),
        password("field-secret"),
        element("submit", "Button", "Record blocker", Vec::new()),
    ];
    let mut node = element("doc", "Document", "Signal Quay Chat", form);
    for level in (0..8).rev() {
        node = element(&format!("pane-{level}"), "Pane", "", vec![node]);
    }
    vec![node]
}

struct Setup {
    fake: Fake,
    registry: UiaRegistry,
    window_id: String,
    window_generation: u64,
}

fn setup() -> Setup {
    let fake = Fake::default();
    fake.state.borrow_mut().windows = vec![window(100, "Signal Quay Chat", 1)];
    fake.state.borrow_mut().tree = electron_tree();
    let mut registry = UiaRegistry::new();
    let list = registry.list_windows(&fake, WORKSPACE, POLICY).unwrap();
    let window_id = list["windows"][0]["window_id"].as_str().unwrap().to_owned();
    let window_generation = list["windows"][0]["window_generation"].as_u64().unwrap();
    Setup {
        fake,
        registry,
        window_id,
        window_generation,
    }
}

fn node<'a>(tree: &'a Value, name: &str) -> &'a Value {
    tree["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["name"] == name)
        .unwrap_or_else(|| panic!("no node {name}"))
}

fn tree(s: &mut Setup) -> Value {
    s.registry
        .observe_tree(
            &s.fake,
            &s.window_id,
            s.window_generation,
            None,
            None,
            WORKSPACE,
            POLICY,
        )
        .unwrap()
}

fn scoped(s: &mut Setup, root: &str, generation: u64) -> Result<Value, UiaError> {
    s.registry.observe_subtree(
        &s.fake,
        &s.window_id,
        s.window_generation,
        root,
        generation,
        None,
        None,
        WORKSPACE,
        POLICY,
    )
}

#[test]
fn a_scoped_root_reaches_the_form_below_the_document() {
    let mut s = setup();
    let full = tree(&mut s);
    assert_eq!(
        full["truncated"], true,
        "the unscoped tree stops at the Document"
    );
    let doc = node(&full, "Signal Quay Chat");
    let generation = full["tree_generation"].as_u64().unwrap();
    let sub = scoped(&mut s, doc["element_id"].as_str().unwrap(), generation).unwrap();
    assert_eq!(sub["root_element_id"], doc["element_id"]);
    assert!(
        sub["tree_generation"].as_u64().unwrap() > generation,
        "a scoped call starts a new generation"
    );
    for name in ["Conflict ID", "Reason", "Record blocker"] {
        node(&sub, name);
    }
    // Redaction applies below the root too.
    assert_eq!(node(&sub, "Password")["value"], Value::Null);
    assert!(sub["node_count"].as_u64().unwrap() <= MAX_TREE_NODES as u64);
}

#[test]
fn every_invalid_root_fails_closed_and_replaces_nothing() {
    let mut s = setup();
    let full = tree(&mut s);
    let generation = full["tree_generation"].as_u64().unwrap();
    let doc = node(&full, "Signal Quay Chat")["element_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let pane = node(&full, "")["element_id"].as_str().unwrap().to_owned();
    // Malformed, unknown, and an earlier generation.
    assert_eq!(
        scoped(&mut s, "not an id", generation).unwrap_err().code,
        FailureCode::InvalidRequest
    );
    let unknown = allocate_element_id(&s.window_id, "never-issued");
    assert_eq!(
        scoped(&mut s, &unknown, generation).unwrap_err().code,
        FailureCode::TargetStale
    );
    assert_eq!(
        scoped(&mut s, &doc, generation - 1).unwrap_err().code,
        FailureCode::TargetStale
    );
    // Gone or denied by UI Automation when read: typed, nothing replaced.
    for code in [FailureCode::TargetStale, FailureCode::CapabilityDenied] {
        s.fake.state.borrow_mut().subtree_fails = Some(code.clone());
        assert_eq!(scoped(&mut s, &doc, generation).unwrap_err().code, code);
    }
    s.fake.state.borrow_mut().subtree_fails = None;
    // Nothing above replaced the element set: the first tree's ids still work.
    s.registry
        .observe_element(&pane, generation, WORKSPACE, POLICY)
        .expect("still current");
    assert!(scoped(&mut s, &doc, generation).is_ok());
}

#[test]
fn a_root_of_another_window_or_without_stable_identity_is_refused() {
    let mut s = setup();
    s.fake
        .state
        .borrow_mut()
        .windows
        .push(window(200, "Other", 2));
    let list = s.registry.list_windows(&s.fake, WORKSPACE, POLICY).unwrap();
    let other = list["windows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["title"] == "Other")
        .unwrap();
    let other_id = other["window_id"].as_str().unwrap().to_owned();
    let other_tree = s
        .registry
        .observe_tree(
            &s.fake,
            &other_id,
            other["window_generation"].as_u64().unwrap(),
            None,
            None,
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    let foreign = node(&other_tree, "Signal Quay Chat")["element_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let foreign_generation = other_tree["tree_generation"].as_u64().unwrap();
    assert_eq!(
        scoped(&mut s, &foreign, foreign_generation)
            .unwrap_err()
            .code,
        FailureCode::TargetStale
    );
    // A root whose runtime identity was only a fallback cannot be resolved.
    s.fake.state.borrow_mut().tree = vec![element(
        "unidentified.1",
        "Document",
        "Anonymous",
        Vec::new(),
    )];
    let full = tree(&mut s);
    let anon = node(&full, "Anonymous")["element_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        scoped(&mut s, &anon, full["tree_generation"].as_u64().unwrap())
            .unwrap_err()
            .code,
        FailureCode::TargetStale
    );
}

#[test]
fn a_window_that_became_protected_supplies_no_root() {
    let mut s = setup();
    let full = tree(&mut s);
    let doc = node(&full, "Signal Quay Chat")["element_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let generation = full["tree_generation"].as_u64().unwrap();
    s.fake.state.borrow_mut().windows = vec![window(100, "Orcel Approval", 1)];
    let list = s.registry.list_windows(&s.fake, WORKSPACE, POLICY).unwrap();
    // The protected window is not listed, and the old identity no longer binds.
    assert!(list["windows"]
        .as_array()
        .unwrap()
        .iter()
        .all(|w| w["title"] != "Orcel Approval"));
    assert!(scoped(&mut s, &doc, generation).is_err());
}

#[test]
fn a_scoped_call_makes_earlier_elements_stale_for_actions() {
    let mut s = setup();
    let full = tree(&mut s);
    let doc = node(&full, "Signal Quay Chat")["element_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let generation = full["tree_generation"].as_u64().unwrap();
    let sub = scoped(&mut s, &doc, generation).unwrap();
    let button = node(&sub, "Record blocker");
    let sub_generation = sub["tree_generation"].as_u64().unwrap();
    // The new subtree's button is actionable; the earlier Document is stale.
    s.registry
        .invoke_binding(
            button["element_id"].as_str().unwrap(),
            sub_generation,
            "Button",
            WORKSPACE,
            POLICY,
        )
        .expect("current element binds");
    assert!(s
        .registry
        .observe_element(&doc, generation, WORKSPACE, POLICY)
        .is_err());
}

#[test]
fn the_cumulative_budget_holds_until_a_real_change_or_an_approved_action() {
    let mut s = setup();
    let mut full = tree(&mut s);
    let use_one = |s: &mut Setup, full: &Value| -> Result<Value, UiaError> {
        let doc = node(full, "Signal Quay Chat")["element_id"]
            .as_str()
            .unwrap()
            .to_owned();
        scoped(s, &doc, full["tree_generation"].as_u64().unwrap())
    };
    for _ in 0..MAX_SCOPED_OBSERVATIONS {
        use_one(&mut s, &full).expect("within budget");
        full = tree(&mut s);
    }
    // The ninth is refused, and relisting the unchanged window does not reset it.
    assert_eq!(
        use_one(&mut s, &full).unwrap_err().code,
        FailureCode::CapabilityDenied
    );
    s.registry.list_windows(&s.fake, WORKSPACE, POLICY).unwrap();
    full = tree(&mut s);
    assert_eq!(
        use_one(&mut s, &full).unwrap_err().code,
        FailureCode::CapabilityDenied
    );
    // A successful approved action resets it (the approval is orceld's; the
    // registry sees only the successful actuation).
    s.fake.state.borrow_mut().tree = vec![
        element("submit", "Button", "Record blocker", Vec::new()),
        electron_tree().remove(0),
    ];
    full = tree(&mut s);
    let button = node(&full, "Record blocker");
    let tree_generation = full["tree_generation"].as_u64().unwrap();
    s.registry
        .invoke_element(
            &s.fake,
            button["element_id"].as_str().unwrap(),
            tree_generation,
            "Button",
            WORKSPACE,
            POLICY,
        )
        .expect("invoke");
    full = tree(&mut s);
    use_one(&mut s, &full).expect("budget reset by the approved action");
    // A failed action does not reset it.
    for _ in 1..MAX_SCOPED_OBSERVATIONS {
        full = tree(&mut s);
        use_one(&mut s, &full).unwrap();
    }
    full = tree(&mut s);
    assert!(use_one(&mut s, &full).is_err(), "spent again");
    s.fake.state.borrow_mut().invoke_fails = true;
    full = tree(&mut s);
    let button = node(&full, "Record blocker")["element_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let tree_generation = full["tree_generation"].as_u64().unwrap();
    assert!(s
        .registry
        .invoke_element(
            &s.fake,
            &button,
            tree_generation,
            "Button",
            WORKSPACE,
            POLICY
        )
        .is_err());
    s.fake.state.borrow_mut().invoke_fails = false;
    full = tree(&mut s);
    assert_eq!(
        use_one(&mut s, &full).unwrap_err().code,
        FailureCode::CapabilityDenied,
        "a failed action keeps it spent"
    );
    // A title-only change (a web page's title) does not reset it either.
    s.fake.state.borrow_mut().windows = vec![window(100, "Signal Quay Chat - 3 unread", 1)];
    let list = s.registry.list_windows(&s.fake, WORKSPACE, POLICY).unwrap();
    s.window_generation = list["windows"][0]["window_generation"].as_u64().unwrap();
    full = tree(&mut s);
    assert_eq!(
        use_one(&mut s, &full).unwrap_err().code,
        FailureCode::CapabilityDenied,
        "a title change keeps it spent"
    );
    // A changed window identity (a new nonce: the window itself changed)
    // resets it.
    s.fake.state.borrow_mut().windows = vec![window(100, "Signal Quay Chat - 3 unread", 2)];
    let list = s.registry.list_windows(&s.fake, WORKSPACE, POLICY).unwrap();
    s.window_generation = list["windows"][0]["window_generation"].as_u64().unwrap();
    full = tree(&mut s);
    use_one(&mut s, &full).expect("budget reset by a changed window");
}

#[test]
fn bounds_apply_below_the_root() {
    let mut s = setup();
    let mut deep = element("leaf", "Edit", "Leaf", Vec::new());
    for level in (0..20).rev() {
        deep = element(&format!("d{level}"), "Group", "", vec![deep]);
    }
    // Within the response byte bound (which refuses, rather than truncates,
    // an oversized response).
    let wide: Vec<NativeElement> = (0..60)
        .map(|i| element(&format!("w{i}"), "Text", "", Vec::new()))
        .collect();
    s.fake.state.borrow_mut().tree = vec![element(
        "doc",
        "Document",
        "Doc",
        vec![deep, element("wide", "List", "Wide", wide)],
    )];
    let full = tree(&mut s);
    let doc = node(&full, "Doc")["element_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let sub = scoped(&mut s, &doc, full["tree_generation"].as_u64().unwrap()).unwrap();
    assert_eq!(sub["truncated"], true);
    assert!(sub["node_count"].as_u64().unwrap() <= MAX_TREE_NODES as u64);
    let deepest = sub["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|n| n["depth"].as_u64())
        .max()
        .unwrap();
    assert!(deepest <= MAX_TREE_DEPTH as u64);
}

/// An adapter without scoped reads (the computer host until slice 1b)
/// fails closed through the trait default, after the root validated.
#[test]
fn an_adapter_without_scoped_reads_fails_closed() {
    struct Plain(Fake);
    impl UiaAdapter for Plain {
        fn list_processes(&self) -> Result<Vec<NativeProcess>, UiaError> {
            self.0.list_processes()
        }
        fn list_windows(&self, pid: u32) -> Result<Vec<NativeWindow>, UiaError> {
            self.0.list_windows(pid)
        }
        fn read_tree(&self, hwnd: u64) -> Result<Vec<NativeElement>, UiaError> {
            self.0.read_tree(hwnd)
        }
    }
    let s = setup();
    let plain = Plain(s.fake);
    let mut registry = s.registry;
    let full = registry
        .observe_tree(
            &plain,
            &s.window_id,
            s.window_generation,
            None,
            None,
            WORKSPACE,
            POLICY,
        )
        .unwrap();
    let doc = node(&full, "Signal Quay Chat")["element_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let error = registry
        .observe_subtree(
            &plain,
            &s.window_id,
            s.window_generation,
            &doc,
            full["tree_generation"].as_u64().unwrap(),
            None,
            None,
            WORKSPACE,
            POLICY,
        )
        .unwrap_err();
    assert_eq!(error.code, FailureCode::ProviderUnavailable);
}
