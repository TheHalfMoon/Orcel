//! #694 follow-up: a desktop action's approval prompt names the application it targets,
//! through orceld's own request entry (`handle_envelope`: policy, dispatch, the UIA provider,
//! the broker). The window comes from a fake adapter seeded into orceld's registry, so this
//! needs no live desktop and runs on every OS.

use super::*;
use orcel_approval::{
    ApprovalDecision, NoPresenceVerifier, RunningImage, SignatureState, TargetApplication,
};
use orcel_provider_uia::{NativeElement, NativeProcess, NativeWindow, UiaAdapter, UiaError};
use std::sync::{Arc, Mutex};

/// One verified process with one visible window. Only listing is needed: the prompt is asked
/// before anything is captured.
struct OneWindow {
    pid: u32,
    hwnd: u64,
}

impl UiaAdapter for OneWindow {
    fn list_processes(&self) -> Result<Vec<NativeProcess>, UiaError> {
        Ok(vec![NativeProcess {
            pid: self.pid,
            exe_name: "notepad.exe".into(),
            exe_id: "e".repeat(16),
            session_id: 1,
            session_verified: true,
            start_generation: 77,
            generation_source: "fake-adapter",
            signature: SignatureState::Verified {
                subject: "Microsoft Windows".into(),
            }
            .into(),
        }])
    }

    fn list_windows(&self, pid: u32) -> Result<Vec<NativeWindow>, UiaError> {
        Ok(if pid == self.pid {
            vec![NativeWindow {
                hwnd: self.hwnd,
                title: "Quarterly notes".into(),
                class: "Notepad".into(),
                visible: true,
                window_nonce: 1,
            }]
        } else {
            Vec::new()
        })
    }

    fn read_tree(&self, _hwnd: u64) -> Result<Vec<NativeElement>, UiaError> {
        Ok(Vec::new())
    }
}

#[test]
fn a_desktop_prompt_names_the_target_application_through_orceld() {
    let dir = std::env::temp_dir().join(format!("orcel-desktop-prompt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("workspace")).unwrap();
    let root = std::fs::canonicalize(dir.join("workspace")).unwrap();
    let policy = PolicyEngine::new(vec![Workspace {
        id: "default".into(),
        root: root.clone(),
    }])
    .unwrap();
    let audit = AuditLogger::new(dir.join("audit.jsonl")).unwrap();
    let workspaces = remote_lease::WorkspaceSet::from_pairs(&[("default".into(), root)]);

    // A pid and handle no other test uses: the registry is shared by the process.
    let listed = uia::seed_registry_for_test(
        &OneWindow {
            pid: 69_401,
            hwnd: 69_402,
        },
        "default",
    );
    let window = listed["windows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|window| window["title"] == "Quarterly notes")
        .expect("the seeded window is listed")
        .clone();

    let seen: Arc<Mutex<Vec<Option<TargetApplication>>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let broker = LocalApprovalBroker::with_path_and_soft_decider(
        dir.join("approvals.json"),
        Arc::new(NoPresenceVerifier),
        Arc::new(move |prompt| {
            recorded.lock().unwrap().push(prompt.application.clone());
            ApprovalDecision::Denied
        }),
    );
    let response = handle_envelope(
        &policy,
        &audit,
        &broker,
        &workspaces,
        RemoteRequestEnvelope {
            request: RequestEnvelope {
                version: INTERNAL_PROTOCOL_VERSION,
                request_id: "desktop-prompt".into(),
                client_session_id: "desktop-prompt".into(),
                workspace_id: "default".into(),
                capability: "uia.screenshot".into(),
                operation: "capture".into(),
                target: None,
                arguments: json!({
                    "window_id": window["window_id"],
                    "expected_window_generation": window["window_generation"],
                    "scope": "target-window",
                }),
            },
            remote: None,
            profile: None,
        },
    );

    assert!(
        !response.ok,
        "a denied approval captures nothing: {response:?}"
    );
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "exactly one prompt was asked: {response:?}");
    assert_eq!(
        seen[0],
        Some(TargetApplication {
            executable: "notepad.exe".into(),
            window_title: "Quarterly notes".into(),
            signature: SignatureState::Verified {
                subject: "Microsoft Windows".into(),
            },
            // The fake adapter reports a state, not a file, so nothing was compared.
            running_image: RunningImage::Unconfirmed,
        })
    );
    drop(seen);
    let _ = std::fs::remove_dir_all(&dir);
}
