//! Structured desktop qualification regression tests.
//!
//! SG-000063 established the read-only baseline. SG-000095 is the governed
//! successor that exposes exact semantic actions and target-window capture
//! through ComputerHostAdapter under Full User authority. The legacy
//! NativeAdapter remains non-actuating and fail-closed.

use super::*;

const WORKSPACE: &str = "uia-sg63-workspace";
const POLICY: &str = "sg-000063-v1";

#[test]
fn sg95_successor_exposes_only_the_qualified_retained_uia_shapes() {
    let exposed: Vec<(&str, &str)> = DESKTOP_SHAPE_QUALIFICATIONS
        .iter()
        .filter(|(_, _, qualification)| *qualification == DesktopShapeQualification::LiveExposed)
        .map(|(capability, operation, _)| (*capability, *operation))
        .collect();
    assert_eq!(
        exposed,
        vec![
            ("uia.window", "list"),
            ("uia.tree", "observe"),
            ("uia.element", "invoke"),
            ("uia.element", "set_value"),
            ("uia.element", "select"),
            ("uia.element", "toggle"),
            ("uia.element", "scroll"),
            ("uia.screenshot", "capture"),
        ]
    );
    for (capability, operation, qualification) in DESKTOP_SHAPE_QUALIFICATIONS {
        assert_eq!(
            is_mcp_exposed_desktop_shape(capability, operation),
            *qualification == DesktopShapeQualification::LiveExposed
        );
    }
    for (capability, operation) in [
        ("uia.visual", "propose"),
        ("uia.coordinates", "propose"),
        ("uia.input", "execute"),
        ("uia.input", "keyboard"),
        ("uia.input", "mouse"),
        ("uia.window", "focus"),
        ("uia.window", "activate"),
        ("uia.process", "terminate"),
        ("uia.clipboard", "read"),
        ("browser.dom", "observe"),
        ("network.fetch", "fetch"),
    ] {
        assert!(!is_mcp_exposed_desktop_shape(capability, operation));
    }
}

#[test]
fn sg95_successor_decisions_are_explicit_for_every_retained_action_shape() {
    let exposed = [
        (
            "uia.element",
            "invoke",
            is_invoke_shape("uia.element", "invoke"),
        ),
        (
            "uia.element",
            "set_value",
            is_value_shape("uia.element", "set_value"),
        ),
        (
            "uia.element",
            "select",
            is_select_shape("uia.element", "select"),
        ),
        (
            "uia.element",
            "toggle",
            is_toggle_shape("uia.element", "toggle"),
        ),
        (
            "uia.element",
            "scroll",
            is_scroll_shape("uia.element", "scroll"),
        ),
        (
            "uia.screenshot",
            "capture",
            is_capture_shape("uia.screenshot", "capture"),
        ),
    ];
    for (capability, operation, retained_shape) in exposed {
        assert!(
            retained_shape,
            "{capability}/{operation} is a retained shape"
        );
        let decision = DESKTOP_SHAPE_QUALIFICATIONS
            .iter()
            .find(|(c, o, _)| *c == capability && *o == operation)
            .map(|(_, _, qualification)| *qualification);
        assert_eq!(decision, Some(DesktopShapeQualification::LiveExposed));
    }

    for (capability, operation, retained_shape) in [
        (
            "uia.visual",
            "propose",
            is_visual_propose_shape("uia.visual", "propose"),
        ),
        (
            "uia.coordinates",
            "propose",
            is_coordinate_propose_shape("uia.coordinates", "propose"),
        ),
        (
            "uia.input",
            "execute",
            is_input_execute_shape("uia.input", "execute"),
        ),
    ] {
        assert!(
            retained_shape,
            "{capability}/{operation} is a retained shape"
        );
        let decision = DESKTOP_SHAPE_QUALIFICATIONS
            .iter()
            .find(|(c, o, _)| *c == capability && *o == operation)
            .map(|(_, _, qualification)| *qualification);
        assert_eq!(decision, Some(DesktopShapeQualification::NotLive));
    }
}

#[test]
fn native_adapter_implements_no_actuation_capture_or_input() {
    let native = NativeAdapter::new();
    let unavailable = |result: Result<(), UiaError>| {
        assert_eq!(
            result.expect_err("not live").code,
            FailureCode::ProviderUnavailable
        );
    };
    unavailable(native.invoke_element(1, "1"));
    unavailable(native.set_value_element(1, "1", "x"));
    unavailable(native.select_element(1, "1", true));
    unavailable(native.toggle_element(1, "1", true));
    unavailable(native.scroll_element(1, "1", "down", 1));
    unavailable(native.execute_click(1, 1, 1));
    assert_eq!(
        native.capture_window(1).expect_err("not live").code,
        FailureCode::ProviderUnavailable
    );
}

struct ReuseAdapter {
    windows: std::cell::RefCell<Vec<NativeWindow>>,
}

impl ReuseAdapter {
    fn window(nonce: u64, class: &str) -> NativeWindow {
        NativeWindow {
            hwnd: 0x5150,
            title: "Editor".to_owned(),
            class: class.to_owned(),
            visible: true,
            window_nonce: nonce,
        }
    }
}

impl UiaAdapter for ReuseAdapter {
    fn list_processes(&self) -> Result<Vec<NativeProcess>, UiaError> {
        Ok(vec![NativeProcess {
            pid: 4242,
            exe_name: "editor.exe".to_owned(),
            exe_id: "0123456789abcdef".to_owned(),
            session_id: 1,
            session_verified: true,
            start_generation: 7,
            generation_source: "win32-creation-time",
            signature: SignatureState::Unsigned.into(),
        }])
    }

    fn list_windows(&self, _pid: u32) -> Result<Vec<NativeWindow>, UiaError> {
        Ok(self.windows.borrow().clone())
    }

    fn read_tree(&self, _hwnd: u64) -> Result<Vec<NativeElement>, UiaError> {
        Ok(vec![NativeElement {
            runtime_id: "1.2".to_owned(),
            control_type: "Window".to_owned(),
            automation_id: String::new(),
            name: "Editor".to_owned(),
            enabled: true,
            selected: false,
            toggled: false,
            scroll_horizontal_percent: 0,
            scroll_vertical_percent: 0,
            patterns: Vec::new(),
            value: None,
            value_is_password: false,
            children: Vec::new(),
        }])
    }
}

#[test]
fn tree_reads_fail_closed_when_the_handle_was_reused_or_closed() {
    let adapter = ReuseAdapter {
        windows: std::cell::RefCell::new(vec![ReuseAdapter::window(11, "EditorClass")]),
    };
    let mut registry = UiaRegistry::new();
    let listing = registry.list_windows(&adapter, WORKSPACE, POLICY).unwrap();
    let window_id = listing["windows"][0]["window_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let generation = listing["windows"][0]["window_generation"].as_u64().unwrap();
    let tree = registry
        .observe_tree(
            &adapter, &window_id, generation, None, None, WORKSPACE, POLICY,
        )
        .expect("same live window");
    assert_eq!(tree["node_count"], 1);

    // The same handle now belongs to another process instance.
    *adapter.windows.borrow_mut() = vec![ReuseAdapter::window(12, "EditorClass")];
    let error = registry
        .observe_tree(
            &adapter, &window_id, generation, None, None, WORKSPACE, POLICY,
        )
        .expect_err("reused handle must fail closed");
    assert_eq!(error.code, FailureCode::TargetStale);

    // The same handle now hosts a different window class.
    *adapter.windows.borrow_mut() = vec![ReuseAdapter::window(11, "OtherClass")];
    let error = registry
        .observe_tree(
            &adapter, &window_id, generation, None, None, WORKSPACE, POLICY,
        )
        .expect_err("re-classed handle must fail closed");
    assert_eq!(error.code, FailureCode::TargetStale);

    // The window closed.
    adapter.windows.borrow_mut().clear();
    let error = registry
        .observe_tree(
            &adapter, &window_id, generation, None, None, WORKSPACE, POLICY,
        )
        .expect_err("closed window must fail closed");
    assert_eq!(error.code, FailureCode::TargetStale);
}

#[cfg(windows)]
mod live {
    use super::*;
    use crate::native_desktop;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    use windows::core::w;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, WINDOW_EX_STYLE, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
    };

    const VISIBLE_TEXT: &str = "sg63-visible-probe-text";
    const HIDDEN_TEXT: &str = "sg63-hidden-probe-credential";

    struct Probe(Child);

    impl Drop for Probe {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Start a child process that shows a probe form with one plain text box
    /// and one system password box (named without any password marker, so
    /// redaction must come from the live `IsPassword` property), and a second
    /// form titled as a protected Orcel approval surface.
    fn spawn_probe(nonce: &str) -> Probe {
        let script = format!(
            "Add-Type -AssemblyName System.Windows.Forms; \
             $f = New-Object System.Windows.Forms.Form; $f.Text = 'Orcel SG63 Probe {nonce}'; \
             $t = New-Object System.Windows.Forms.TextBox; $t.Name = 'probeVisible'; $t.Text = '{VISIBLE_TEXT}'; $t.Top = 10; $f.Controls.Add($t); \
             $p = New-Object System.Windows.Forms.TextBox; $p.Name = 'probeHidden'; $p.UseSystemPasswordChar = $true; $p.Text = '{HIDDEN_TEXT}'; $p.Top = 40; $f.Controls.Add($p); \
             $g = New-Object System.Windows.Forms.Form; $g.Text = 'Orcel Approval Probe {nonce}'; $g.Show(); \
             [System.Windows.Forms.Application]::Run($f)"
        );
        let child = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn probe window process");
        Probe(child)
    }

    fn find_probe(registry: &mut UiaRegistry, title: &str) -> (Value, Value) {
        let adapter = NativeAdapter::new();
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            let listing = registry
                .list_windows(&adapter, WORKSPACE, POLICY)
                .expect("live window listing");
            let found = listing["windows"]
                .as_array()
                .expect("windows array")
                .iter()
                .find(|entry| entry["title"] == title)
                .cloned();
            if let Some(entry) = found {
                return (listing, entry);
            }
            assert!(Instant::now() < deadline, "probe window never appeared");
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    #[test]
    fn interactive_station_predicate_fails_closed() {
        assert!(native_desktop::is_interactive_station("WinSta0"));
        assert!(native_desktop::is_interactive_station("winsta0"));
        assert!(!native_desktop::is_interactive_station("Service-0x0-3e7$"));
        assert!(!native_desktop::is_interactive_station("WinSta0x"));
        assert!(!native_desktop::is_interactive_station(""));
    }

    #[test]
    fn orcel_and_windows_security_prompt_hosts_are_excluded() {
        for exe in [
            "orcel.exe",
            "ORCELD.EXE",
            "orcel-mcp-host.exe",
            "CredentialUIBroker.exe",
            "consent.exe",
            "LogonUI.exe",
        ] {
            assert!(native_desktop::is_excluded_executable(exe), "{exe}");
        }
        for exe in [
            "powershell.exe",
            "notepad.exe",
            "orcel.exe.bak",
            "credentialuibroker",
        ] {
            assert!(!native_desktop::is_excluded_executable(exe), "{exe}");
        }
    }

    /// Real Windows evidence for A1 and A2: listing and bounded tree
    /// observation on a window the test creates, with the password value
    /// never read, the protected surface omitted, and this process's own
    /// windows never observed. Outside the interactive window station the
    /// same calls must fail closed as unavailable.
    #[test]
    fn live_desktop_observation_is_bounded_redacted_and_excludes_protected_surfaces() {
        let adapter = NativeAdapter::new();
        if native_desktop::require_interactive_station().is_err() {
            let mut registry = UiaRegistry::new();
            let error = registry
                .list_windows(&adapter, WORKSPACE, POLICY)
                .expect_err("non-interactive station must fail closed");
            assert_eq!(error.code, FailureCode::ProviderUnavailable);
            assert_eq!(
                adapter.read_tree(1).expect_err("fail closed").code,
                FailureCode::ProviderUnavailable
            );
            eprintln!(
                "SG-000063 live evidence: NON-INTERACTIVE station; observation failed closed"
            );
            return;
        }
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let title = format!("Orcel SG63 Probe {nonce}");
        let _probe = spawn_probe(&nonce);
        let mut registry = UiaRegistry::new();
        let (listing, entry) = find_probe(&mut registry, &title);

        assert!(listing["window_count"].as_u64().unwrap() <= MAX_WINDOWS as u64);
        assert!(listing["protected_omitted"].as_u64().unwrap() >= 1);
        let protected_title = format!("Orcel Approval Probe {nonce}");
        for window in listing["windows"].as_array().unwrap() {
            assert_ne!(window["title"], protected_title.as_str());
        }
        assert_eq!(
            entry["exe_name"].as_str().unwrap().to_ascii_lowercase(),
            "powershell.exe"
        );
        let process_id = entry["process_id"].as_str().unwrap().to_owned();
        let process_generation = entry["process_generation"].as_u64().unwrap();
        let process = registry
            .observe_process(&process_id, process_generation, WORKSPACE, POLICY)
            .expect("observe probe process");
        assert_eq!(process["generation_source"], "win32-creation-time");
        assert_eq!(process["session_verified"], true);

        let window_id = entry["window_id"].as_str().unwrap().to_owned();
        let window_generation = entry["window_generation"].as_u64().unwrap();
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
            .expect("live bounded tree");
        let serialized = serde_json::to_string(&tree).unwrap();
        assert!(
            !serialized.contains(HIDDEN_TEXT),
            "password value must never be read"
        );
        let nodes = tree["nodes"].as_array().unwrap();
        assert!(!nodes.is_empty() && nodes.len() <= MAX_TREE_NODES);
        assert_eq!(nodes[0]["control_type"], "Window");
        for node in nodes {
            assert!(node["depth"].as_u64().unwrap() <= MAX_TREE_DEPTH as u64);
        }
        assert!(
            nodes.iter().any(|node| node["value"] == VISIBLE_TEXT),
            "plain text value is observed"
        );
        let hidden = nodes
            .iter()
            .find(|node| node["value_is_password"] == true)
            .expect("live IsPassword element");
        assert_eq!(hidden["redacted"], true);
        assert!(hidden["value"].is_null());

        let bounded = registry
            .observe_tree(
                &adapter,
                &window_id,
                window_generation,
                Some(0),
                Some(1),
                WORKSPACE,
                POLICY,
            )
            .expect("bounded tree");
        assert_eq!(bounded["node_count"], 1);
        assert_eq!(bounded["truncated"], true);

        eprintln!(
            "SG-000063 live evidence: INTERACTIVE station; windows={} protected_omitted={} probe_nodes={}",
            listing["window_count"], listing["protected_omitted"], tree["node_count"]
        );
    }

    #[test]
    fn own_process_windows_are_never_observed() {
        if native_desktop::require_interactive_station().is_err() {
            return;
        }
        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("STATIC"),
                w!("Orcel SG63 own-process window"),
                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                0,
                0,
                200,
                100,
                None,
                None,
                None,
                None,
            )
        }
        .expect("create own-process window");
        let raw = hwnd.0 as usize as u64;
        let windows = native_desktop::visible_windows().expect("live windows");
        assert!(windows.iter().all(|window| window.hwnd != raw));
        assert!(windows
            .iter()
            .all(|window| window.pid != std::process::id()));
        let error = native_desktop::read_tree(raw).expect_err("own window must be denied");
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        unsafe { DestroyWindow(hwnd) }.expect("destroy own-process window");
    }
}
