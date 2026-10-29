//! SG-000128: the scoped `uia.tree observe` through orceld's own request
//! entry (`handle_envelope`: profile gate, policy, dispatch, audit). Every
//! refusal is audited; nothing here needs a live desktop.

use super::*;
use orcel_approval::{ApprovalDecision, NoPresenceVerifier};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct Bench {
    dir: PathBuf,
    policy: PolicyEngine,
    audit: AuditLogger,
    workspaces: remote_lease::WorkspaceSet,
}

impl Bench {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "orcel-sg128-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("workspace")).unwrap();
        let root = std::fs::canonicalize(dir.join("workspace")).unwrap();
        Self {
            policy: PolicyEngine::new(vec![Workspace {
                id: "default".into(),
                root: root.clone(),
            }])
            .unwrap(),
            audit: AuditLogger::new(dir.join("audit.jsonl")).unwrap(),
            workspaces: remote_lease::WorkspaceSet::from_pairs(&[("default".into(), root)]),
            dir,
        }
    }

    fn call(&self, arguments: Value) -> ResponseEnvelope {
        let broker = LocalApprovalBroker::with_path_and_soft_decider(
            self.dir.join("approvals.json"),
            Arc::new(NoPresenceVerifier),
            // Observation never asks; any prompt would be a test failure.
            Arc::new(|_| ApprovalDecision::Denied),
        );
        handle_envelope(
            &self.policy,
            &self.audit,
            &broker,
            &self.workspaces,
            RemoteRequestEnvelope {
                request: RequestEnvelope {
                    version: INTERNAL_PROTOCOL_VERSION,
                    request_id: "sg128".into(),
                    client_session_id: "sg128".into(),
                    workspace_id: "default".into(),
                    capability: "uia.tree".into(),
                    operation: "observe".into(),
                    target: None,
                    arguments,
                },
                remote: None,
                profile: None,
            },
        )
    }

    fn audit_lines(&self) -> usize {
        std::fs::read_to_string(self.dir.join("audit.jsonl"))
            .map(|t| t.lines().count())
            .unwrap_or(0)
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn window_id() -> String {
    format!("{}{}", orcel_provider_uia::WINDOW_ID_PREFIX, "a".repeat(16))
}

fn element_id() -> String {
    format!(
        "{}{}",
        orcel_provider_uia::ELEMENT_ID_PREFIX,
        "b".repeat(16)
    )
}

#[test]
fn a_half_scoped_or_malformed_root_is_refused_by_policy_and_audited() {
    let bench = Bench::new();
    let malformed = FailureCode::InvalidRequest;
    for (arguments, expected) in [
        (
            json!({"window_id": window_id(), "expected_window_generation": 1, "root_element_id": element_id()}),
            malformed.clone(),
        ),
        (
            json!({"window_id": window_id(), "expected_window_generation": 1, "expected_tree_generation": 2}),
            malformed.clone(),
        ),
        (
            json!({"window_id": window_id(), "expected_window_generation": 1, "root_element_id": "nope", "expected_tree_generation": 2}),
            malformed.clone(),
        ),
        // A caller-supplied native handle is a widening field: denied
        // outright, scoped or not.
        (
            json!({"window_id": window_id(), "expected_window_generation": 1, "root_element_id": element_id(), "expected_tree_generation": 2, "hwnd": 1}),
            FailureCode::CapabilityDenied,
        ),
    ] {
        let before = bench.audit_lines();
        let response = bench.call(arguments);
        assert!(!response.ok);
        assert_eq!(response.error.unwrap().code, expected);
        assert_eq!(bench.audit_lines(), before + 1, "the refusal is audited");
    }
}

#[test]
fn a_scoped_call_on_an_unknown_window_fails_closed_and_is_audited() {
    let bench = Bench::new();
    let before = bench.audit_lines();
    let response = bench.call(json!({
        "window_id": window_id(), "expected_window_generation": 1,
        "root_element_id": element_id(), "expected_tree_generation": 2,
    }));
    assert!(!response.ok, "nothing was observed");
    assert_eq!(bench.audit_lines(), before + 1);
    // The unscoped call fails the same way: the scoped shape adds no route.
    let unscoped = bench.call(json!({"window_id": window_id(), "expected_window_generation": 1}));
    assert!(!unscoped.ok);
}
