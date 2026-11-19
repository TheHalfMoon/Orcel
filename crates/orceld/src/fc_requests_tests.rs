//! SG132_SLICE8.md: the Full Control request capabilities (`fc.fs`,
//! `fc.process`, `fc.git`, `fc.status`) against the dispatcher's fake
//! authority service and fake worker launcher (`full_control_dispatch_tests`),
//! on every OS, and orceld's entry for the remote and tool surface
//! refusals. No SOFT or STRONG prompt is ever shown: the approvals here are
//! scripted brokers.

use crate::fc_requests::{
    describe, dispatch, refuse_untrusted, status, validate, BrokerApproval, FC_SHAPES,
    FS_CAPABILITY, GIT_CAPABILITY, PROCESS_CAPABILITY, STATUS_CAPABILITY,
};
use crate::fc_worker::WorkerOp;
use crate::full_control_dispatch::{ActionApproval, Family};
use crate::full_control_dispatch_tests::{
    full_scope, launcher, lease, request, FakeApproval, FakePort,
};
use orcel_approval::test_support::FixedApprovalBroker;
use orcel_approval::{
    ApprovalBroker, ApprovalClass, ApprovalDecision, ApprovalError, ApprovalPrompt, ApprovedToken,
    ConsumeExpectation,
};
use orcel_authority::lease::LeaseScope;
use orcel_contracts::{ExecutorClass, FailureCode, RemoteRequestEnvelope, RequestEnvelope};
use orcel_policy::browser_lease::client_ref;
use orcel_provider_fs::ProviderError;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::path::PathBuf;

/// One sample of every worker operation, with paths inside the test
/// lease's root (`C:\work`).
fn every_op() -> Vec<WorkerOp> {
    let repository = r"C:\work\repo".to_owned();
    vec![
        WorkerOp::Stat {
            path: r"C:\work\a.txt".to_owned(),
        },
        WorkerOp::List {
            path: r"C:\work".to_owned(),
            max_entries: 10,
        },
        WorkerOp::ReadText {
            path: r"C:\work\a.txt".to_owned(),
            max_bytes: 64,
        },
        WorkerOp::WriteText {
            path: r"C:\work\a.txt".to_owned(),
            text: "hello".to_owned(),
            create_new: false,
        },
        WorkerOp::Mkdir {
            path: r"C:\work\new".to_owned(),
        },
        WorkerOp::Run {
            program: r"C:\work\tools\tool.exe".to_owned(),
            args: vec!["--check".to_owned()],
            cwd: r"C:\work".to_owned(),
            timeout_ms: 1_000,
            max_output_bytes: 1_024,
        },
        WorkerOp::GitStatus {
            repository: repository.clone(),
        },
        WorkerOp::GitDiff {
            repository: repository.clone(),
            staged: true,
        },
        WorkerOp::GitLog {
            repository: repository.clone(),
            max_count: 5,
        },
        WorkerOp::GitAdd {
            repository: repository.clone(),
            paths: vec!["a.txt".to_owned()],
        },
        WorkerOp::GitUnstage {
            repository: repository.clone(),
            paths: vec!["a.txt".to_owned()],
        },
        WorkerOp::GitCommit {
            repository: repository.clone(),
            message: "change".to_owned(),
        },
        WorkerOp::GitBranchCreate {
            repository,
            branch: "topic".to_owned(),
        },
    ]
}

fn capability_of(op: &WorkerOp) -> &'static str {
    match op.family() {
        Family::Filesystem => FS_CAPABILITY,
        Family::Process => PROCESS_CAPABILITY,
        Family::Git => GIT_CAPABILITY,
        Family::DesktopInput => "not a worker family",
    }
}

/// The request an `fc_*` tool sends for `op`, from client session `c`.
fn fc_request(op: &WorkerOp) -> RequestEnvelope {
    request(
        capability_of(op),
        op.name(),
        serde_json::to_value(op).expect("op"),
    )
}

fn status_request() -> RequestEnvelope {
    request(STATUS_CAPABILITY, "get", Value::Null)
}

fn code<T: std::fmt::Debug>(result: Result<T, ProviderError>) -> Option<FailureCode> {
    result.err().map(|error| error.code)
}

#[test]
fn fc_requests_every_worker_operation_has_exactly_one_shape() {
    let ops = every_op();
    let mut names: Vec<&str> = ops.iter().map(WorkerOp::name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 13, "one sample per worker operation");
    for op in &ops {
        let shape = (capability_of(op), op.name());
        assert_eq!(
            FC_SHAPES.iter().filter(|known| **known == shape).count(),
            1,
            "{shape:?}"
        );
        // The operation name alone selects the family's capability.
        for (capability, operation) in FC_SHAPES {
            if *operation == op.name() {
                assert_eq!(*capability, capability_of(op));
            }
        }
    }
    assert_eq!(
        FC_SHAPES.len(),
        ops.len() + 1,
        "the worker operations and status"
    );
    assert!(FC_SHAPES.contains(&(STATUS_CAPABILITY, "get")));
    for (capability, _) in FC_SHAPES {
        assert!(crate::fc_requests::is_request(capability));
        assert!(orcel_policy::remote_session::is_local_only_capability(
            capability
        ));
    }
}

#[test]
fn fc_requests_a_remote_caller_and_other_surfaces_are_refused() {
    let remote = refuse_untrusted(true, None).expect_err("remote");
    assert_eq!(remote.code, FailureCode::CapabilityDenied);
    assert!(remote.message.contains("local-only"), "{}", remote.message);
    // A remote caller is refused whatever profile it claims.
    assert_eq!(
        code(refuse_untrusted(true, Some("desktop_structured"))),
        Some(FailureCode::CapabilityDenied)
    );
    for profile in ["browser_structured", "browser_full", "core", ""] {
        assert_eq!(
            code(refuse_untrusted(false, Some(profile))),
            Some(FailureCode::CapabilityDenied),
            "{profile}"
        );
    }
    refuse_untrusted(false, Some("desktop_structured")).expect("the local tool list");
    refuse_untrusted(false, None).expect("a local caller naming no surface");
}

fn entry_fixture() -> (
    orcel_policy::PolicyEngine,
    orcel_audit::AuditLogger,
    PathBuf,
) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let root = std::env::temp_dir().join(format!(
        "orcel-fc-requests-{}-{nanos}-{}",
        std::process::id(),
        crate::tests::next_temp_sequence()
    ));
    std::fs::create_dir_all(root.join("workspace")).expect("workspace");
    let workspace = orcel_policy::Workspace {
        id: "default".into(),
        root: std::fs::canonicalize(root.join("workspace")).expect("canonical"),
    };
    let policy = orcel_policy::PolicyEngine::new(vec![workspace]).expect("policy");
    let audit = orcel_audit::AuditLogger::new(root.join("audit.jsonl")).expect("audit");
    (policy, audit, root)
}

fn remote_context() -> orcel_contracts::RemoteContext {
    orcel_contracts::RemoteContext {
        principal: format!("rp-{}", "1".repeat(32)),
        remote_connection_id: format!("rc-{}", "2".repeat(32)),
        connection_id: "conn-fc-test".into(),
        device_id: format!("dev-{}", "3".repeat(32)),
        device_epoch: 1,
        provider_kind: "generic".into(),
        client_profile_id: "profile-test".into(),
        client_profile_revision: 1,
        tool_surface_profile: "core".into(),
        scopes: vec![
            "orcel.read".into(),
            "orcel.write".into(),
            "orcel.execute".into(),
        ],
    }
}

/// A broker that fails the test if anything asks it.
struct NeverAsked;

impl ApprovalBroker for NeverAsked {
    fn request_token(&self, prompt: &ApprovalPrompt) -> Result<ApprovedToken, ApprovalError> {
        unreachable!("nothing may be asked: {}", prompt.action)
    }

    fn consume(
        &self,
        _token: &ApprovedToken,
        _expected: &ConsumeExpectation,
        _now_ms: u64,
    ) -> Result<(), ApprovalError> {
        unreachable!("nothing may be consumed")
    }
}

/// Through orceld's entry: every `fc.*` shape (and an unknown `fc.*` name)
/// from a remote caller, or under another tool surface, is refused before
/// the remote-session lease, the policy, the workspace or any approval;
/// with no remote-session lease at all the answer is still the local-only
/// refusal, never `REMOTE_SESSION_INACTIVE`.
#[test]
fn fc_requests_the_entry_refuses_remote_callers_before_dispatch() {
    let (policy, audit, root) = entry_fixture();
    let workspaces = crate::remote_lease::WorkspaceSet::from_pairs(&[]);
    let mut requests: Vec<RequestEnvelope> = every_op().iter().map(fc_request).collect();
    requests.push(status_request());
    let mut unknown = status_request();
    unknown.capability = "fc.shell".into();
    unknown.operation = "open".into();
    requests.push(unknown);
    for mut request in requests {
        // A workspace that is not configured: the refusal comes first.
        request.workspace_id = "not-configured".into();
        for (remote, profile, expected) in [
            (Some(remote_context()), None, "local-only"),
            (
                Some(remote_context()),
                Some("desktop_structured".to_owned()),
                "local-only",
            ),
            (None, Some("browser_full".to_owned()), "desktop_structured"),
            (
                None,
                Some("browser_structured".to_owned()),
                "desktop_structured",
            ),
        ] {
            let response = crate::handle_envelope(
                &policy,
                &audit,
                &NeverAsked,
                &workspaces,
                RemoteRequestEnvelope {
                    request: request.clone(),
                    remote,
                    profile,
                },
            );
            assert!(!response.ok);
            let error = response.error.expect("refused");
            assert_eq!(
                error.code,
                FailureCode::CapabilityDenied,
                "{}/{}: {}",
                request.capability,
                request.operation,
                error.message
            );
            assert!(error.message.contains(expected), "{}", error.message);
        }
    }
    let _ = std::fs::remove_dir_all(root);
}

/// Through orceld's entry, locally: a malformed `fc.*` request is refused
/// on its own form, and an unconfigured workspace is refused, before the
/// dispatch record or any service call.
#[test]
fn fc_requests_the_entry_checks_form_and_workspace_locally() {
    let (policy, audit, root) = entry_fixture();
    let workspaces = crate::remote_lease::WorkspaceSet::from_pairs(&[]);
    let send = |request: RequestEnvelope| {
        crate::handle_envelope(
            &policy,
            &audit,
            &NeverAsked,
            &workspaces,
            RemoteRequestEnvelope {
                request,
                remote: None,
                profile: Some("desktop_structured".to_owned()),
            },
        )
    };
    let mut wrong_family = fc_request(&every_op()[5]);
    wrong_family.capability = FS_CAPABILITY.into();
    let mut targeted = status_request();
    targeted.target = Some("C:\\work".into());
    let mut unconfigured = status_request();
    unconfigured.workspace_id = "not-configured".into();
    for (request, expected) in [
        (wrong_family, FailureCode::CapabilityDenied),
        (targeted, FailureCode::InvalidRequest),
        (unconfigured, FailureCode::WorkspaceDenied),
    ] {
        let response = send(request);
        assert_eq!(response.error.expect("refused").code, expected);
    }
    let _ = std::fs::remove_dir_all(root);
}

/// The entry routes every `fc.*` request to its own handler before the
/// remote-session gate and the Safe dispatcher.
#[test]
fn fc_requests_the_entry_routes_fc_before_the_remote_gate() {
    let source = include_str!("sg000039_main.rs");
    let entry = source.find("fn handle_envelope(").expect("entry");
    let body = &source[entry..];
    let routed = body
        .find("fc_requests::is_request(&request.capability)")
        .expect("fc routing");
    let remote_gate = body
        .find("if let Some(remote) = &remote {")
        .expect("remote gate");
    let safe = body
        .find("handle_request(policy, audit, approval, request)")
        .expect("safe dispatch");
    assert!(routed < remote_gate && routed < safe);
}

#[test]
fn fc_requests_shapes_are_validated_before_anything_is_asked() {
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    let launched = launcher(&port);
    let approval = FakeApproval::default();
    let read = WorkerOp::ReadText {
        path: r"C:\work\a.txt".to_owned(),
        max_bytes: 64,
    };
    let mut cases = Vec::new();
    // A process operation under the filesystem capability.
    let mut wrong = fc_request(&every_op()[5]);
    wrong.capability = FS_CAPABILITY.into();
    cases.push((wrong, FailureCode::CapabilityDenied));
    // An operation that is not a worker operation.
    let mut unknown = fc_request(&read);
    unknown.operation = "delete".into();
    cases.push((unknown, FailureCode::CapabilityDenied));
    // The operation names one thing and the arguments another.
    let mut mismatched = fc_request(&read);
    mismatched.operation = "stat".into();
    cases.push((mismatched, FailureCode::InvalidRequest));
    // Arguments that are no worker operation.
    let mut free = fc_request(&read);
    free.arguments = json!({ "op": "read_text", "path": r"C:\work\a.txt" });
    cases.push((free, FailureCode::InvalidRequest));
    // A target, an old protocol, and arguments for the status.
    let mut targeted = fc_request(&read);
    targeted.target = Some(r"C:\work\a.txt".into());
    cases.push((targeted, FailureCode::InvalidRequest));
    let mut old = fc_request(&read);
    old.version = 0;
    cases.push((old, FailureCode::InvalidRequest));
    let mut status_args = status_request();
    status_args.arguments = json!({ "lease_id": "al-1" });
    cases.push((status_args, FailureCode::InvalidRequest));
    for (request, expected) in cases {
        assert_eq!(
            code(dispatch(&port, &launched, &approval, &request, 5)),
            Some(expected),
            "{}/{}",
            request.capability,
            request.operation
        );
    }
    assert!(port.0.borrow().authorized.is_empty());
    assert!(approval.asked.borrow().is_empty());
    assert_eq!(launched.runs.get(), 0);
}

#[test]
fn fc_requests_without_a_lease_every_tool_refuses_lease_required() {
    let port = FakePort::installed(Vec::new());
    let launched = launcher(&port);
    let approval = FakeApproval::default();
    for op in every_op() {
        assert_eq!(
            code(dispatch(&port, &launched, &approval, &fc_request(&op), 5)),
            Some(FailureCode::LeaseRequired),
            "{op:?}"
        );
    }
    // A lease without shells covers files only.
    let files_only = FakePort::installed(vec![lease(
        '2',
        LeaseScope::DesktopFullUser {
            executors: vec![ExecutorClass::Filesystem],
            roots: vec![r"C:\work".to_owned()],
            shells: false,
        },
    )]);
    for op in every_op() {
        let result = dispatch(
            &files_only,
            &launcher(&files_only),
            &approval,
            &fc_request(&op),
            5,
        );
        if op.family() == Family::Filesystem {
            result.expect("files are covered");
        } else {
            assert_eq!(code(result), Some(FailureCode::LeaseRequired), "{op:?}");
        }
    }
    // The person is never asked without a covering lease.
    assert!(approval.asked.borrow().is_empty());
    assert!(port.0.borrow().authorized.is_empty());
    assert_eq!(launched.runs.get(), 0);
    // No service: the worker families need it.
    let absent = FakePort::default();
    assert_eq!(
        code(dispatch(
            &absent,
            &launcher(&absent),
            &approval,
            &fc_request(&every_op()[0]),
            5
        )),
        Some(FailureCode::AuthorityUnavailable)
    );
}

#[test]
fn fc_requests_the_principal_is_the_calling_clients_reference() {
    // The test lease is bound to the client reference of session `c`.
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    let launched = launcher(&port);
    let approval = FakeApproval::default();
    for op in every_op() {
        dispatch(&port, &launched, &approval, &fc_request(&op), 5).expect("bound client");
    }
    for (_, _, claims) in &port.0.borrow().authorized {
        assert_eq!(claims.principal_id, client_ref("c"));
        assert!(claims.capability.starts_with("fc."));
    }
    let mut other = fc_request(&every_op()[0]);
    other.client_session_id = "another-session".into();
    let before = port.0.borrow().authorized.len();
    assert_eq!(
        code(dispatch(&port, &launched, &approval, &other, 6)),
        Some(FailureCode::CapabilityDenied)
    );
    assert_eq!(port.0.borrow().authorized.len(), before);
}

/// Founder decision of 2026-11-19 (amendment to decision 2): Full Control
/// file writes are covered by the lease and ask nothing per call; the
/// service's audit-first `Authorize`, the job and the outcome still happen.
#[test]
fn fc_requests_file_writes_are_lease_covered_and_ask_nothing() {
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    let launched = launcher(&port);
    let approval = FakeApproval::default();
    for op in every_op()
        .into_iter()
        .filter(|op| matches!(op, WorkerOp::WriteText { .. } | WorkerOp::Mkdir { .. }))
    {
        assert!(!op.needs_approval(), "{op:?}");
        dispatch(&port, &launched, &approval, &fc_request(&op), 5).expect("written");
    }
    assert!(approval.asked.borrow().is_empty());
    let service = port.0.borrow();
    assert_eq!(service.authorized.len(), 2);
    for (_, executor, claims) in &service.authorized {
        assert_eq!(*executor, ExecutorClass::Filesystem);
        assert_eq!(claims.capability, FS_CAPABILITY);
        assert!(claims.paths.is_some());
    }
    assert_eq!(service.outcomes.len(), 2);
    assert_eq!(
        service
            .calls
            .iter()
            .filter(|call| **call == "authorize")
            .count(),
        2
    );
    assert_eq!(launched.runs.get(), 2);
}

/// SG-000096 A3: a program run and every git change ask a fresh approval
/// on every call, bound to the digest the service records; reads ask
/// nothing.
#[test]
fn fc_requests_process_and_git_mutations_ask_every_call() {
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    let launched = launcher(&port);
    let approval = FakeApproval::default();
    let asking = [
        "run",
        "git_add",
        "git_unstage",
        "git_commit",
        "git_branch_create",
    ];
    for round in 0..2u64 {
        for op in every_op() {
            let before = approval.asked.borrow().len();
            dispatch(&port, &launched, &approval, &fc_request(&op), 10 + round).expect("ran");
            let asked = approval.asked.borrow().len() - before;
            assert_eq!(asked, usize::from(asking.contains(&op.name())), "{op:?}");
            assert_eq!(op.needs_approval(), asking.contains(&op.name()));
        }
    }
    let asked = approval.asked.borrow();
    assert_eq!(asked.len(), 2 * asking.len());
    let service = port.0.borrow();
    for (name, digest) in asked.iter() {
        // The person approved exactly what the service recorded.
        assert!(
            service
                .authorized
                .iter()
                .any(|(_, _, claims)| claims.operation == *name && claims.action_digest == *digest),
            "{name}"
        );
    }
    // A fresh approval per call: no digest is approved twice.
    let mut digests: Vec<&String> = asked.iter().map(|(_, digest)| digest).collect();
    digests.sort();
    digests.dedup();
    assert_eq!(digests.len(), asked.len());
    // A declined run authorizes nothing and runs nothing.
    drop(service);
    drop(asked);
    let declined = FakeApproval {
        deny: true,
        ..FakeApproval::default()
    };
    let authorized = port.0.borrow().authorized.len();
    let runs = launched.runs.get();
    assert_eq!(
        code(dispatch(
            &port,
            &launched,
            &declined,
            &fc_request(&every_op()[5]),
            20
        )),
        Some(FailureCode::ApprovalDenied)
    );
    assert_eq!(port.0.borrow().authorized.len(), authorized);
    assert_eq!(launched.runs.get(), runs);
}

#[test]
fn fc_requests_status_shows_the_lease_scope_and_grants_nothing() {
    let browser = lease(
        'b',
        LeaseScope::BrowserFullAccess {
            client_ref: client_ref("c"),
            session_id: "bs-1".to_owned(),
            origins: vec!["https://example.com".to_owned()],
            families: Vec::new(),
            task: None,
        },
    );
    let mut foreign = lease('2', full_scope());
    foreign.principal_id = client_ref("someone-else");
    let port = FakePort::installed(vec![lease('1', full_scope()), foreign, browser]);
    let launched = launcher(&port);
    let approval = FakeApproval::default();
    let answer = dispatch(&port, &launched, &approval, &status_request(), 2_000).expect("status");
    assert_eq!(answer["client_ref"], json!(client_ref("c")));
    assert_eq!(answer["authority"], json!("installed"));
    assert_eq!(answer["grants"], json!("nothing"));
    let leases = answer["leases"].as_array().expect("leases");
    assert_eq!(leases.len(), 2, "browser leases are not listed");
    let own = &leases[0];
    assert_eq!(own["roots"], json!([r"C:\work"]));
    assert_eq!(
        own["executors"],
        json!(["desktop_input", "filesystem", "shell_process"])
    );
    assert_eq!(own["shells"], json!(true));
    assert_eq!(own["expires_at_ms"], json!(1_000 + 30 * 60_000));
    assert_eq!(own["expires_in_ms"], json!(1_000 + 30 * 60_000 - 2_000));
    assert_eq!(own["bound_to_this_client"], json!(true));
    assert_eq!(
        own["usable_capabilities"],
        json!([FS_CAPABILITY, PROCESS_CAPABILITY, GIT_CAPABILITY])
    );
    let theirs = &leases[1];
    assert_eq!(theirs["bound_to_this_client"], json!(false));
    assert_eq!(theirs["usable_capabilities"], json!([]));
    // Read-only: no Authorize, no job, no outcome, no approval.
    {
        let service = port.0.borrow();
        assert!(service.authorized.is_empty());
        assert!(service.outcomes.is_empty());
        assert!(service.calls.is_empty());
    }
    assert!(approval.asked.borrow().is_empty());
    assert_eq!(launched.runs.get(), 0);
    // An expired lease is not shown.
    let late = status(&port, &client_ref("c"), 1_000 + 30 * 60_000).expect("status");
    assert_eq!(late["leases"], json!([]));
    // No service: the client still learns its reference.
    let absent = FakePort::default();
    let answer = status(&absent, &client_ref("c"), 5).expect("status");
    assert_eq!(answer["authority"], json!("not_installed"));
    assert_eq!(answer["client_ref"], json!(client_ref("c")));
    assert_eq!(answer["leases"], json!([]));
    // An installed service that does not answer refuses.
    let silent = FakePort::installed(Vec::new());
    silent.0.borrow_mut().unreachable = true;
    assert_eq!(
        code(status(&silent, &client_ref("c"), 5)),
        Some(FailureCode::AuthorityUnavailable)
    );
}

/// A broker that records each prompt and answers with a fixed decision or
/// error.
struct RecordingBroker {
    inner: FixedApprovalBroker,
    unavailable: bool,
    prompts: RefCell<Vec<ApprovalPrompt>>,
}

impl RecordingBroker {
    fn new(decision: ApprovalDecision) -> Self {
        Self {
            inner: FixedApprovalBroker(decision),
            unavailable: false,
            prompts: RefCell::new(Vec::new()),
        }
    }
}

impl ApprovalBroker for RecordingBroker {
    fn request_token(&self, prompt: &ApprovalPrompt) -> Result<ApprovedToken, ApprovalError> {
        self.prompts.borrow_mut().push(prompt.clone());
        if self.unavailable {
            return Err(ApprovalError {
                code: FailureCode::ApprovalUnavailable,
                message: "no approval surface".to_owned(),
            });
        }
        self.inner.request_token(prompt)
    }

    fn consume(
        &self,
        token: &ApprovedToken,
        expected: &ConsumeExpectation,
        now_ms: u64,
    ) -> Result<(), ApprovalError> {
        self.inner.consume(token, expected, now_ms)
    }
}

/// The production approval: a SOFT, single-use prompt through orceld's
/// broker (the Windows dialog), bound to the action digest, naming the
/// program or repository; a No or an unavailable prompt refuses.
#[test]
fn fc_requests_the_windows_approval_is_soft_and_bound_to_the_digest() {
    let run = every_op()[5].clone();
    let request = fc_request(&run);
    let digest = "d".repeat(64);
    let approving = RecordingBroker::new(ApprovalDecision::Approved);
    BrokerApproval::new(&approving)
        .approve(&run, &request, &digest)
        .expect("approved");
    {
        let prompts = approving.prompts.borrow();
        assert_eq!(prompts.len(), 1);
        let prompt = &prompts[0];
        assert_eq!(prompt.approval_class, ApprovalClass::Soft);
        assert_eq!(prompt.digest, digest);
        assert_eq!(prompt.workspace_id, "default");
        assert_eq!(prompt.target, r"C:\work\tools\tool.exe");
        assert!(prompt.action.contains("run a program"), "{}", prompt.action);
        assert!(prompt.summary.contains("\"--check\""), "{}", prompt.summary);
        assert!(prompt.summary.contains(r"C:\work"), "{}", prompt.summary);
        assert_eq!(prompt.origin, orcel_approval::RequestOrigin::Local);
    }
    let denying = RecordingBroker::new(ApprovalDecision::Denied);
    assert_eq!(
        code(BrokerApproval::new(&denying).approve(&run, &request, &digest)),
        Some(FailureCode::ApprovalDenied)
    );
    let mut unavailable = RecordingBroker::new(ApprovalDecision::Approved);
    unavailable.unavailable = true;
    assert_eq!(
        code(BrokerApproval::new(&unavailable).approve(&run, &request, &digest)),
        Some(FailureCode::ApprovalUnavailable)
    );
    // Each git change names its repository and what it changes.
    for op in every_op().iter().filter(|op| op.needs_approval()) {
        let (action, target, summary) = describe(op);
        assert!(action.starts_with("Full Control: "), "{action}");
        assert!(!target.is_empty() && !summary.is_empty(), "{op:?}");
    }
}

/// The request capabilities really validate what orceld's entry checks.
#[test]
fn fc_requests_validate_accepts_every_tool_request() {
    for op in every_op() {
        validate(&fc_request(&op)).expect("valid");
    }
    validate(&status_request()).expect("status");
    let mut empty = status_request();
    empty.arguments = json!({});
    validate(&empty).expect("empty status arguments");
}
