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

/// The number of `WorkerOp` variants, and each variant's place: the match
/// is exhaustive, so a new operation does not compile until it is added
/// here, and `every_op` must then carry a sample of it
/// (`fc_requests_every_worker_operation_has_exactly_one_shape`).
const VARIANTS: usize = 13;

fn variant_index(op: &WorkerOp) -> usize {
    match op {
        WorkerOp::Stat { .. } => 0,
        WorkerOp::List { .. } => 1,
        WorkerOp::ReadText { .. } => 2,
        WorkerOp::WriteText { .. } => 3,
        WorkerOp::Mkdir { .. } => 4,
        WorkerOp::Run { .. } => 5,
        WorkerOp::GitStatus { .. } => 6,
        WorkerOp::GitDiff { .. } => 7,
        WorkerOp::GitLog { .. } => 8,
        WorkerOp::GitAdd { .. } => 9,
        WorkerOp::GitUnstage { .. } => 10,
        WorkerOp::GitCommit { .. } => 11,
        WorkerOp::GitBranchCreate { .. } => 12,
    }
}

/// One sample of every worker operation (checked against `variant_index`),
/// with paths inside the test lease's root (`C:\work`).
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
    let mut covered: Vec<usize> = ops.iter().map(variant_index).collect();
    covered.sort_unstable();
    assert_eq!(
        covered,
        (0..VARIANTS).collect::<Vec<_>>(),
        "one sample per WorkerOp variant"
    );
    let mut names: Vec<&str> = ops.iter().map(WorkerOp::name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), VARIANTS);
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
            code(dispatch(&port, &launched, &approval, &request, false, 5)),
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
            code(dispatch(
                &port,
                &launched,
                &approval,
                &fc_request(&op),
                false,
                5
            )),
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
            false,
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
            false,
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
        dispatch(&port, &launched, &approval, &fc_request(&op), false, 5).expect("bound client");
    }
    for (_, _, claims) in &port.0.borrow().authorized {
        assert_eq!(claims.principal_id, client_ref("c"));
        assert!(claims.capability.starts_with("fc."));
    }
    let mut other = fc_request(&every_op()[0]);
    other.client_session_id = "another-session".into();
    let before = port.0.borrow().authorized.len();
    assert_eq!(
        code(dispatch(&port, &launched, &approval, &other, false, 6)),
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
        dispatch(&port, &launched, &approval, &fc_request(&op), false, 5).expect("written");
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
            dispatch(
                &port,
                &launched,
                &approval,
                &fc_request(&op),
                false,
                10 + round,
            )
            .expect("ran");
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
            false,
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
    let mut unbound = lease('3', full_scope());
    unbound.principal_id = "orcel-owner".to_owned();
    let port = FakePort::installed(vec![lease('1', full_scope()), foreign, unbound, browser]);
    let launched = launcher(&port);
    let approval = FakeApproval::default();
    let answer =
        dispatch(&port, &launched, &approval, &status_request(), false, 2_000).expect("status");
    assert_eq!(answer["client_ref"], json!(client_ref("c")));
    assert_eq!(answer["authority"], json!("installed"));
    assert_eq!(answer["grants"], json!("nothing"));
    let leases = answer["leases"].as_array().expect("leases");
    assert_eq!(
        leases.len(),
        2,
        "another client's lease and browser leases are not listed"
    );
    assert!(leases
        .iter()
        .all(|listed| listed["lease_id"] != json!(format!("al-{}", "2".repeat(32)))));
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
    // An unbound lease admits this client for desktop input only.
    let unbound = &leases[1];
    assert_eq!(unbound["lease_id"], json!(format!("al-{}", "3".repeat(32))));
    assert_eq!(unbound["bound_to_this_client"], json!(false));
    assert_eq!(unbound["usable_capabilities"], json!([]));
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
        assert!(
            prompt.summary.contains("[\"--check\"]"),
            "{}",
            prompt.summary
        );
        // The asking client's reference, as fc.status shows it.
        assert!(
            prompt.summary.contains(&client_ref("c")),
            "{}",
            prompt.summary
        );
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
        let (action, target, summary) = describe(op, "cl-test");
        assert!(action.starts_with("Full Control: "), "{action}");
        assert!(!target.is_empty(), "{op:?}");
        assert!(
            summary.starts_with("asked by client cl-test; "),
            "{summary}"
        );
    }
}

/// The dialog text cannot be forged by an argument: embedded quotes,
/// backslashes and line breaks are escaped, and the working folder comes
/// before the arguments.
#[test]
fn fc_requests_the_dialog_text_escapes_arguments_and_names_the_folder_first() {
    let run = WorkerOp::Run {
        program: r"C:\work\tools\tool.exe".to_owned(),
        args: vec![
            r#"a" "b"#.to_owned(),
            "line\nbreak".to_owned(),
            r"C:\work\".to_owned(),
        ],
        cwd: r"C:\work".to_owned(),
        timeout_ms: 1_000,
        max_output_bytes: 1_024,
    };
    let (_, target, summary) = describe(&run, "cl-1");
    assert_eq!(target, r"C:\work\tools\tool.exe");
    assert!(
        summary.contains(r#"arguments: ["a\" \"b","line\nbreak","C:\\work\\"]"#),
        "{summary}"
    );
    assert!(!summary.contains('\n'), "{summary}");
    let folder = summary.find("working folder").expect("folder");
    let arguments = summary.find("arguments").expect("arguments");
    assert!(folder < arguments, "{summary}");
    let commit = WorkerOp::GitCommit {
        repository: r"C:\work\repo".to_owned(),
        message: "subject\n\nbody with \"quotes\"".to_owned(),
    };
    let (_, _, summary) = describe(&commit, "cl-1");
    assert!(
        summary.contains(r#"message: "subject\n\nbody with \"quotes\"""#),
        "{summary}"
    );
}

/// The operation's own bounds (the worker's and the Git provider's rules)
/// are checked before the lease is used or the person is asked: a bad
/// request is `INVALID_REQUEST` (an oversized write `OUTPUT_LIMIT`) and
/// costs no prompt.
#[test]
fn fc_requests_bad_arguments_are_refused_before_the_prompt() {
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    let launched = launcher(&port);
    let approval = FakeApproval::default();
    let repository = r"C:\work\repo".to_owned();
    let run = |timeout_ms: u64, max_output_bytes: usize, args: Vec<String>| WorkerOp::Run {
        program: r"C:\work\tools\tool.exe".to_owned(),
        args,
        cwd: r"C:\work".to_owned(),
        timeout_ms,
        max_output_bytes,
    };
    let add = |paths: &[&str]| WorkerOp::GitAdd {
        repository: repository.clone(),
        paths: paths.iter().map(|path| (*path).to_owned()).collect(),
    };
    let cases = vec![
        (run(0, 1_024, Vec::new()), FailureCode::InvalidRequest),
        (run(50_001, 1_024, Vec::new()), FailureCode::InvalidRequest),
        (run(1_000, 0, Vec::new()), FailureCode::InvalidRequest),
        (run(1_000, 65_537, Vec::new()), FailureCode::InvalidRequest),
        (
            run(1_000, 1_024, vec!["x".to_owned(); 65]),
            FailureCode::InvalidRequest,
        ),
        (
            run(1_000, 1_024, vec!["nul\0".to_owned()]),
            FailureCode::InvalidRequest,
        ),
        (add(&[]), FailureCode::InvalidRequest),
        (add(&["../outside.txt"]), FailureCode::InvalidRequest),
        (add(&[".git/config"]), FailureCode::InvalidRequest),
        // An absolute path, as this OS spells one (the provider's rule).
        (
            add(&[if cfg!(windows) {
                r"C:\work\repo\a.txt"
            } else {
                "/work/repo/a.txt"
            }]),
            FailureCode::InvalidRequest,
        ),
        (add(&[":(glob)*"]), FailureCode::InvalidRequest),
        (add(&["a.txt", "a.txt"]), FailureCode::InvalidRequest),
        (
            WorkerOp::GitUnstage {
                repository: repository.clone(),
                paths: vec![".gitmodules".to_owned()],
            },
            FailureCode::InvalidRequest,
        ),
        (
            WorkerOp::GitCommit {
                repository: repository.clone(),
                message: "   ".to_owned(),
            },
            FailureCode::InvalidRequest,
        ),
        (
            WorkerOp::GitCommit {
                repository: repository.clone(),
                message: "x".repeat(8 * 1_024 + 1),
            },
            FailureCode::InvalidRequest,
        ),
        (
            WorkerOp::GitBranchCreate {
                repository: repository.clone(),
                branch: "-delete".to_owned(),
            },
            FailureCode::InvalidRequest,
        ),
        (
            WorkerOp::GitBranchCreate {
                repository: repository.clone(),
                branch: "a\nb".to_owned(),
            },
            FailureCode::InvalidRequest,
        ),
        (
            WorkerOp::GitLog {
                repository: repository.clone(),
                max_count: 0,
            },
            FailureCode::InvalidRequest,
        ),
        (
            WorkerOp::List {
                path: r"C:\work".to_owned(),
                max_entries: 1_001,
            },
            FailureCode::InvalidRequest,
        ),
        (
            WorkerOp::ReadText {
                path: r"C:\work\a.txt".to_owned(),
                max_bytes: 0,
            },
            FailureCode::InvalidRequest,
        ),
        (
            WorkerOp::WriteText {
                path: r"C:\work\a.txt".to_owned(),
                text: "x".repeat(256 * 1_024 + 1),
                create_new: false,
            },
            FailureCode::OutputLimit,
        ),
    ];
    for (op, expected) in cases {
        assert_eq!(
            op.check_arguments().err().map(|error| error.code),
            Some(expected.clone())
        );
        assert_eq!(
            code(dispatch(
                &port,
                &launched,
                &approval,
                &fc_request(&op),
                false,
                5
            )),
            Some(expected),
            "{}",
            op.name()
        );
    }
    assert!(approval.asked.borrow().is_empty(), "no prompt was shown");
    assert!(port.0.borrow().authorized.is_empty());
    assert_eq!(launched.runs.get(), 0);
    // Every sample request passes the same checks.
    for op in every_op() {
        op.check_arguments().expect("valid sample");
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

/// Spec 4.14, kept by the SG-000132 amendment of 2026-11-19: a lease-covered
/// file write never reaches Orcel's own state (the authority's state folder
/// or a protected state root), even inside the lease's roots.
#[test]
fn fc_requests_file_writes_never_reach_orcel_state() {
    use crate::fc_worker::is_protected_write;
    use std::path::Path;
    let base = Path::new("base");
    let protected = vec![base.join("state")];
    assert!(is_protected_write(&base.join("state"), &protected));
    assert!(is_protected_write(
        &base.join("state").join("approvals.jsonl"),
        &protected
    ));
    assert!(is_protected_write(
        &base.join("Orcel").join("authority").join("leases.json"),
        &protected
    ));
    assert!(!is_protected_write(
        &base.join("work").join("a.txt"),
        &protected
    ));
    assert!(!is_protected_write(&base.join("statement.txt"), &protected));
    assert!(!is_protected_write(
        &base.join("Orcel").join("authority-notes.txt"),
        &protected
    ));
}

/// The same refusal in the worker's own resolution of a write target
/// (Windows: real folders, resolved names).
#[cfg(windows)]
#[test]
fn fc_requests_the_worker_refuses_writes_into_orcel_state() {
    use crate::fc_worker::creatable_with;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let base = std::env::temp_dir().join(format!(
        "orcel-fc-state-{}-{nanos}-{}",
        std::process::id(),
        crate::tests::next_temp_sequence()
    ));
    let work = base.join("work");
    std::fs::create_dir_all(work.join("state")).expect("state");
    std::fs::create_dir_all(work.join("Orcel").join("authority")).expect("authority");
    let root = work.to_string_lossy().into_owned();
    let roots = vec![root.clone()];
    let protected =
        vec![
            orcel_policy::protected_state::resolve_protected_root(&work.join("state"))
                .expect("resolved"),
        ];
    for refused in [
        format!(r"{root}\state\approvals.jsonl"),
        format!(r"{root}\STATE\new-folder"),
        format!(r"{root}\Orcel\authority\leases.json"),
    ] {
        assert_eq!(
            code(creatable_with(&refused, &roots, &protected)),
            Some(FailureCode::CapabilityDenied),
            "{refused}"
        );
    }
    creatable_with(&format!(r"{root}\notes.txt"), &roots, &protected).expect("an ordinary file");
    creatable_with(&format!(r"{root}\Orcel\notes.txt"), &roots, &protected)
        .expect("a folder merely named Orcel");
    let _ = std::fs::remove_dir_all(base);
}

/// The re-check by handle (every OS, on paths): an opened target must still
/// be inside the roots, outside `.git` and outside Orcel's state.
#[test]
fn fc_requests_the_opened_target_is_checked_again() {
    use crate::fc_worker::check_final_path;
    use std::path::Path;
    let base = Path::new("base");
    let roots = vec![base.join("work")];
    let protected = vec![base.join("work").join("state")];
    check_final_path(&base.join("work").join("a.txt"), &roots, &protected).expect("inside");
    for (actual, label) in [
        (base.join("elsewhere").join("a.txt"), "outside the roots"),
        (base.join("work").join(".git").join("config"), ".git"),
        (
            base.join("work").join("state").join("ledger"),
            "Orcel state",
        ),
        (
            base.join("work").join("Orcel").join("authority").join("x"),
            "authority state",
        ),
    ] {
        assert_eq!(
            code(check_final_path(&actual, &roots, &protected)),
            Some(FailureCode::PathRaceDetected),
            "{label}"
        );
    }
}

/// Windows helpers for the worker's real-folder tests.
#[cfg(windows)]
mod windows_folders {
    use std::path::{Path, PathBuf};

    pub(super) fn scratch(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let base = std::env::temp_dir().join(format!(
            "orcel-fc-{label}-{}-{nanos}-{}",
            std::process::id(),
            crate::tests::next_temp_sequence()
        ));
        std::fs::create_dir_all(&base).expect("scratch");
        base
    }

    /// A junction at `link` to `target` (`mklink /J` needs no elevation).
    pub(super) fn junction(link: &Path, target: &Path) {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .status()
            .expect("mklink");
        assert!(status.success(), "mklink /J failed");
    }

    /// The 8.3 short name of an existing path, if the volume makes them.
    pub(super) fn short_name(path: &Path) -> Option<PathBuf> {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut buffer = vec![0u16; 1024];
        // SAFETY: a NUL-terminated input and a buffer as long as stated.
        let len =
            unsafe { GetShortPathNameW(wide.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) };
        if len == 0 || len as usize >= buffer.len() {
            return None;
        }
        let short = PathBuf::from(std::ffi::OsString::from_wide(&buffer[..len as usize]));
        (short != path).then_some(short)
    }
}

/// A folder inside the roots swapped for a junction into Orcel's state
/// after the path checks and before the open: the write is refused by the
/// handle re-check and the file it created there is removed by its handle;
/// a folder created through the swap is removed as well.
#[cfg(windows)]
#[test]
fn fc_requests_a_junction_swapped_in_after_the_checks_is_caught() {
    use crate::fc_worker::{creatable_with, opened};
    use windows_folders::{junction, scratch};
    let base = scratch("swap");
    let work = base.join("work");
    let state = work.join("protected-state");
    std::fs::create_dir_all(work.join("safe")).expect("safe");
    std::fs::create_dir_all(&state).expect("state");
    let root = work.to_string_lossy().into_owned();
    let roots = vec![root.clone()];
    let resolved_roots = vec![std::fs::canonicalize(&work).expect("root")];
    let protected =
        vec![orcel_policy::protected_state::resolve_protected_root(&state).expect("resolved")];
    let file = creatable_with(&format!(r"{root}\safe\x.txt"), &roots, &protected)
        .expect("checked while safe is a folder");
    let folder = creatable_with(&format!(r"{root}\safe\new"), &roots, &protected)
        .expect("checked while safe is a folder");
    // The swap: `safe` becomes a junction into the protected state.
    std::fs::rename(work.join("safe"), work.join("safe-old")).expect("rename");
    junction(&work.join("safe"), &state);
    let (opened_file, created) = opened::open_for_write(&file, false).expect("opened");
    assert!(created);
    assert!(
        state.join("x.txt").exists(),
        "the open went through the junction"
    );
    assert_eq!(
        code(opened::recheck(&opened_file, &resolved_roots, &protected)),
        Some(FailureCode::PathRaceDetected)
    );
    opened::discard(&opened_file);
    drop(opened_file);
    assert!(!state.join("x.txt").exists(), "removed by its handle");
    // SG132_SLICE8.md residual 7: `mkdir` opens the parent by its handle
    // without following the junction now at its name, and refuses it;
    // nothing is created through the swap.
    assert_eq!(
        code(opened::make_folder(&folder, &resolved_roots, &protected)),
        Some(FailureCode::PathRaceDetected)
    );
    assert!(!state.join("new").exists(), "nothing created in the state");
    assert!(!work.join("safe-old").join("new").exists());
    // A swap one level higher: the parent is reached through a junction
    // at an ancestor, so its handle is in the state; refused by where it
    // really is.
    std::fs::create_dir_all(state.join("deep")).expect("deep");
    std::fs::create_dir_all(work.join("safe-old").join("deep")).expect("deep");
    let deep = creatable_with(&format!(r"{root}\safe-old\deep\new"), &roots, &protected)
        .expect("checked while safe-old is a folder");
    std::fs::rename(work.join("safe-old"), work.join("safe-older")).expect("rename");
    junction(&work.join("safe-old"), &state);
    assert_eq!(
        code(opened::make_folder(&deep, &resolved_roots, &protected)),
        Some(FailureCode::PathRaceDetected)
    );
    assert!(!state.join("deep").join("new").exists(), "nothing created");
    std::fs::remove_dir(work.join("safe-old")).expect("junction removed");
    std::fs::rename(work.join("safe-older"), work.join("safe-old")).expect("rename back");
    // Without a swap the same open passes the re-check.
    let plain =
        creatable_with(&format!(r"{root}\safe-old\y.txt"), &roots, &protected).expect("checked");
    let (opened_plain, _) = opened::open_for_write(&plain, true).expect("opened");
    opened::recheck(&opened_plain, &resolved_roots, &protected).expect("inside the roots");
    drop(opened_plain);
    let _ = std::fs::remove_dir(work.join("safe"));
    let _ = std::fs::remove_dir_all(base);
}

/// SG132_SLICE8.md residual 7, the converse case: once `mkdir` holds the
/// checked parent's handle, the folder is created inside that very folder
/// and the handle it re-checks (and would remove) is the folder it created.
/// Moving the parent away and putting a junction at its old name after the
/// open changes nothing: the new folder is made in the real (moved) parent,
/// never through the junction, and a folder that already existed is never
/// opened, checked or removed.
#[cfg(windows)]
#[test]
fn fc_requests_mkdir_creates_relative_to_the_checked_parent_handle() {
    use crate::fc_worker::{creatable_with, opened};
    use windows_folders::{junction, scratch};
    let base = scratch("relative");
    let work = base.join("work");
    let elsewhere = base.join("elsewhere");
    std::fs::create_dir_all(work.join("parent")).expect("parent");
    // A pre-existing empty folder outside the roots with the same name.
    std::fs::create_dir_all(elsewhere.join("new")).expect("pre-existing");
    let root = work.to_string_lossy().into_owned();
    let roots = vec![root.clone()];
    let resolved_roots = vec![std::fs::canonicalize(&work).expect("root")];
    let folder = creatable_with(&format!(r"{root}\parent\new"), &roots, &[]).expect("checked");
    let parent =
        opened::open_checked_parent(folder.parent().expect("a parent"), &resolved_roots, &[])
            .expect("the parent passes");
    // The racer: the parent moves within the roots and a junction to
    // `elsewhere` takes its name.
    std::fs::rename(work.join("parent"), work.join("moved")).expect("rename");
    junction(&work.join("parent"), &elsewhere);
    let created = opened::create_folder_in(&parent, folder.file_name().expect("a name"))
        .expect("created in the held parent");
    opened::recheck(&created, &resolved_roots, &[]).expect("where the held parent is");
    drop(created);
    assert!(
        work.join("moved").join("new").is_dir(),
        "made in the real parent"
    );
    assert!(
        elsewhere.join("new").is_dir(),
        "the other folder is untouched"
    );
    // An existing name is never opened: FILE_CREATE refuses it.
    let again =
        opened::create_folder_in(&parent, folder.file_name().expect("a name")).expect_err("exists");
    assert_eq!(again.kind(), std::io::ErrorKind::AlreadyExists);
    drop(parent);
    // Through `perform`: the ordinary case still works and an existing
    // folder is refused.
    std::fs::remove_dir(work.join("parent")).expect("junction removed");
    std::fs::create_dir(work.join("plain")).expect("plain");
    let made = format!(r"{root}\plain\made");
    crate::fc_worker::opened::make_folder(
        &creatable_with(&made, &roots, &[]).expect("checked"),
        &resolved_roots,
        &[],
    )
    .expect("made");
    assert!(work.join("plain").join("made").is_dir());
    assert!(crate::fc_worker::opened::make_folder(
        &creatable_with(&made, &roots, &[]).expect("checked"),
        &resolved_roots,
        &[],
    )
    .is_err());
    let _ = std::fs::remove_dir_all(base);
}

/// SG132_SLICE8.md residual 7: no name-based reopen of a created folder is
/// left in the worker. The source of `fc_worker.rs` names neither the
/// removed reopen helper nor a `create_dir` on the Windows path; `mkdir`
/// goes through `opened::make_folder` only.
#[test]
fn fc_requests_mkdir_has_no_name_based_reopen() {
    let source = include_str!("fc_worker.rs");
    let removed = ["open_", "created_", "folder"].concat();
    assert!(!source.contains(&removed), "the name-based reopen is gone");
    let mkdir = source
        .split("WorkerOp::Mkdir { path } =>")
        .nth(1)
        .and_then(|rest| rest.split("WorkerOp::Run").next())
        .expect("the mkdir arm");
    let compact: String = mkdir.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.contains("#[cfg(windows)]opened::make_folder("));
    let create_dir = ["std::fs::", "create_dir("].concat();
    assert_eq!(compact.matches(&create_dir).count(), 1);
    assert!(compact.contains(&["#[cfg(not(windows))]", &create_dir].concat()));
}

/// A junction inside the roots that points into Orcel's state, and an 8.3
/// short name of the state folder: both resolve to the state folder and are
/// refused before anything is opened.
#[cfg(windows)]
#[test]
fn fc_requests_junctions_and_short_names_into_state_are_refused() {
    use crate::fc_worker::creatable_with;
    use windows_folders::{junction, scratch, short_name};
    let base = scratch("names");
    let work = base.join("work");
    let state = work.join("protected-state");
    std::fs::create_dir_all(&state).expect("state");
    let root = work.to_string_lossy().into_owned();
    let roots = vec![root.clone()];
    let protected =
        vec![orcel_policy::protected_state::resolve_protected_root(&state).expect("resolved")];
    junction(&work.join("into-state"), &state);
    assert_eq!(
        code(creatable_with(
            &format!(r"{root}\into-state\ledger.json"),
            &roots,
            &protected
        )),
        Some(FailureCode::CapabilityDenied)
    );
    match short_name(&state) {
        Some(short) => {
            let name = short
                .file_name()
                .expect("a short name")
                .to_string_lossy()
                .into_owned();
            assert_eq!(
                code(creatable_with(
                    &format!(r"{root}\{name}\ledger.json"),
                    &roots,
                    &protected
                )),
                Some(FailureCode::CapabilityDenied),
                "{name}"
            );
        }
        None => eprintln!(
            "skipped the 8.3 case: this volume makes no short names for {}",
            state.display()
        ),
    }
    let _ = std::fs::remove_dir(work.join("into-state"));
    let _ = std::fs::remove_dir_all(base);
}

/// An existing file is opened for writing without delete access: another
/// program holding it open without delete sharing does not make the write
/// fail; only a file this call creates is opened with delete access.
#[cfg(windows)]
#[test]
fn fc_requests_existing_files_are_opened_without_delete_access() {
    use crate::fc_worker::opened;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_folders::scratch;
    use windows_sys::Win32::Storage::FileSystem::{DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE};
    assert_eq!(opened::write_access(false) & DELETE, 0);
    assert_eq!(opened::write_access(true) & DELETE, DELETE);
    let base = scratch("share");
    let existing = base.join("held.txt");
    std::fs::write(&existing, "before").expect("existing");
    // Another program's handle: read and write sharing, no delete sharing.
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&existing)
        .expect("holder");
    let (file, created) = opened::open_for_write(&existing, false).expect("opened while held");
    assert!(!created);
    let roots = vec![std::fs::canonicalize(&base).expect("root")];
    opened::recheck(&file, &roots, &[]).expect("rechecked without delete access");
    drop(file);
    drop(holder);
    let _ = std::fs::remove_dir_all(base);
}
