//! SG-000132 WP1-12: the Full Control dispatcher against a fake authority
//! service and a fake worker launcher, on every OS. The real Job Objects and
//! the real `orceld fc-worker` are in `fc_worker_tests.rs` (Windows).

use crate::fc_worker::WorkerOp;
use crate::full_control_dispatch::{
    action_digest, authorize, desktop_gate, run_in_worker as dispatch_worker,
    with_desktop_outcomes, Action, AuthorityPort, Family, JobGrant, Ticket, WorkerLauncher,
};
use orcel_authority::lease::{
    BrowserFamily, GrantEvidence, LeaseBody, LeaseScope, ObservedRequester, LEASE_CONTRACT,
};
use orcel_authority::protocol::{AuthorizeClaims, DispatchOutcome};
use orcel_contracts::{ExecutorClass, FailureCode, RequestEnvelope};
use orcel_provider_fs::ProviderError;
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::rc::Rc;

const CLIENT: &str = "cl-abababababababababababababababab";

pub(crate) fn lease(id: char, scope: LeaseScope) -> LeaseBody {
    LeaseBody {
        contract: LEASE_CONTRACT.to_owned(),
        lease_id: format!("al-{}", id.to_string().repeat(32)),
        scope,
        windows_user_sid: "S-1-5-21-1".to_owned(),
        logon_session_id: 7,
        ts_session_id: 1,
        principal_id: CLIENT.to_owned(),
        task: "tidy the work folder".to_owned(),
        requester: ObservedRequester {
            pid: 9,
            image: r"C:\Program Files\Orcel\orcel.exe".to_owned(),
        },
        authority_epoch: 1,
        revocations_at_issue: 0,
        issued_at_ms: 1_000,
        expires_at_ms: 1_000 + 30 * 60_000,
        key_id: "k".to_owned(),
        grant: GrantEvidence {
            intent_digest: "0".repeat(64),
            confirmation_text_digest: "1".repeat(64),
            confirmation: "service_rendered".to_owned(),
            confirmation_input_protected: false,
            presence: "windows_hello_key_credential".to_owned(),
            presence_key_digest: "2".repeat(64),
        },
    }
}

pub(crate) fn full_scope() -> LeaseScope {
    LeaseScope::DesktopFullUser {
        executors: vec![
            ExecutorClass::DesktopInput,
            ExecutorClass::Filesystem,
            ExecutorClass::ShellProcess,
        ],
        roots: vec![r"C:\work".to_owned()],
        shells: true,
    }
}

pub(crate) fn request(capability: &str, operation: &str, arguments: Value) -> RequestEnvelope {
    RequestEnvelope {
        version: orcel_contracts::INTERNAL_PROTOCOL_VERSION,
        request_id: "req-7".into(),
        client_session_id: "c".into(),
        workspace_id: "default".into(),
        capability: capability.into(),
        operation: operation.into(),
        target: None,
        arguments,
    }
}

/// A fake authority service: what it holds and what it was asked.
#[derive(Default)]
struct FakeService {
    installed: bool,
    unreachable: bool,
    leases: Vec<LeaseBody>,
    /// Replaces the Authorize answer when set.
    answer: Option<Value>,
    /// Ends the dispatch's job right after answering (a revoke that lands
    /// between Authorize and the launch).
    revoke_after_authorize: bool,
    live_jobs: BTreeSet<String>,
    /// Authorization id to its job id.
    job_of: std::collections::BTreeMap<String, String>,
    /// Job handles the dispatcher gave back unused.
    released: Vec<u64>,
    authorized: Vec<(String, ExecutorClass, AuthorizeClaims)>,
    outcomes: Vec<(String, DispatchOutcome, Option<FailureCode>)>,
    deprecated_checks: u32,
    next: u32,
}

#[derive(Clone, Default)]
struct FakePort(Rc<RefCell<FakeService>>);

impl FakePort {
    fn installed(leases: Vec<LeaseBody>) -> Self {
        let port = Self::default();
        port.0.borrow_mut().installed = true;
        port.0.borrow_mut().leases = leases;
        port
    }

    fn with(&self, change: impl FnOnce(&mut FakeService)) -> &Self {
        change(&mut self.0.borrow_mut());
        self
    }
}

fn unavailable() -> ProviderError {
    ProviderError::new(
        FailureCode::AuthorityUnavailable,
        "the service is not answering",
    )
}

impl AuthorityPort for FakePort {
    fn installed(&self) -> bool {
        self.0.borrow().installed
    }

    fn deprecated_desktop_check(&self) -> Result<(), ProviderError> {
        self.0.borrow_mut().deprecated_checks += 1;
        Ok(())
    }

    fn leases(&self) -> Result<Vec<LeaseBody>, ProviderError> {
        let service = self.0.borrow();
        if service.unreachable {
            return Err(unavailable());
        }
        Ok(service.leases.clone())
    }

    fn authorize(
        &self,
        lease_id: &str,
        executor: ExecutorClass,
        claims: AuthorizeClaims,
    ) -> Result<Value, ProviderError> {
        let mut service = self.0.borrow_mut();
        if service.unreachable {
            return Err(unavailable());
        }
        service.next += 1;
        let job = matches!(
            executor,
            ExecutorClass::Filesystem | ExecutorClass::ShellProcess
        )
        .then(|| format!("fcj-{:032x}", service.next));
        let authorization = format!("az-{:032x}", service.next);
        if let Some(job) = &job {
            service.live_jobs.insert(job.clone());
            service.job_of.insert(authorization.clone(), job.clone());
            if service.revoke_after_authorize {
                // The revoke lands after the answer and before the resume.
                service.live_jobs.remove(job);
            }
        }
        service
            .authorized
            .push((lease_id.to_owned(), executor, claims));
        let handle = job.as_ref().map(|_| 0x4000 + 4 * u64::from(service.next));
        Ok(service.answer.clone().unwrap_or_else(|| {
            json!({
                "authorization_id": authorization,
                "lease_id": lease_id,
                "job_id": job,
                "job_handle": handle,
            })
        }))
    }

    fn outcome(
        &self,
        authorization_id: &str,
        outcome: DispatchOutcome,
        code: Option<FailureCode>,
    ) -> Result<(), ProviderError> {
        self.0
            .borrow_mut()
            .outcomes
            .push((authorization_id.to_owned(), outcome, code));
        Ok(())
    }

    fn dispatch_active(&self, authorization_id: &str) -> Result<(), ProviderError> {
        let service = self.0.borrow();
        match service.job_of.get(authorization_id) {
            Some(job) if service.live_jobs.contains(job) => Ok(()),
            _ => Err(ProviderError::new(
                FailureCode::LeaseInvalid,
                "the dispatch's lease ended or its Job Object was terminated",
            )),
        }
    }

    fn release_job_handle(&self, handle: u64) {
        self.0.borrow_mut().released.push(handle);
    }
}

/// A fake launcher: "assigns" the suspended worker, then resumes it only if
/// `confirm` (the service's DispatchActive) succeeds, as the real one does.
struct FakeLauncher {
    service: FakePort,
    fails: Option<FailureCode>,
    runs: Cell<u32>,
}

impl WorkerLauncher for FakeLauncher {
    fn run(
        &self,
        job: &JobGrant,
        roots: &[String],
        op: &WorkerOp,
        confirm: &dyn Fn() -> Result<(), ProviderError>,
    ) -> Result<Value, ProviderError> {
        assert!(job.handle != 0 && job.id.starts_with("fcj-"));
        let _ = &self.service;
        confirm()?;
        self.runs.set(self.runs.get() + 1);
        assert_eq!(roots, [r"C:\work".to_owned()]);
        match &self.fails {
            Some(code) => Err(ProviderError::new(code.clone(), "the operation failed")),
            None => Ok(json!({ "ran": op.paths() })),
        }
    }
}

fn launcher(service: &FakePort) -> FakeLauncher {
    FakeLauncher {
        service: service.clone(),
        fails: None,
        runs: Cell::new(0),
    }
}

fn read_op(path: &str) -> WorkerOp {
    WorkerOp::ReadText {
        path: path.to_owned(),
        max_bytes: 64,
    }
}

fn fs_request() -> RequestEnvelope {
    request(
        "full_control.fs",
        "read_text",
        serde_json::to_value(read_op(r"C:\work\a.txt")).expect("op"),
    )
}

/// `run_in_worker` with `op` as the request's arguments (the dispatcher
/// runs exactly what the request says).
fn run_in_worker(
    port: &dyn AuthorityPort,
    launcher: &dyn WorkerLauncher,
    base: &RequestEnvelope,
    principal_id: Option<&str>,
    op: &WorkerOp,
    now_ms: u64,
) -> Result<Value, ProviderError> {
    let mut request = base.clone();
    request.arguments = serde_json::to_value(op).expect("op");
    dispatch_worker(port, launcher, &request, principal_id, now_ms)
}

fn code<T: std::fmt::Debug>(result: Result<T, ProviderError>) -> Option<FailureCode> {
    result.err().map(|error| error.code)
}

#[test]
fn fc_dispatch_an_unreachable_service_refuses_and_never_uses_the_store() {
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    port.with(|service| service.unreachable = true);
    let desktop = request("desktop.input", "execute", json!({"x": 1}));
    assert_eq!(
        code(desktop_gate(&port, &desktop, 5)),
        Some(FailureCode::AuthorityUnavailable)
    );
    assert_eq!(
        code(run_in_worker(
            &port,
            &launcher(&port),
            &fs_request(),
            None,
            &read_op(r"C:\work\a.txt"),
            5
        )),
        Some(FailureCode::AuthorityUnavailable)
    );
    assert_eq!(
        port.0.borrow().deprecated_checks,
        0,
        "no fallback to the store"
    );
}

#[test]
fn fc_dispatch_without_a_service_only_desktop_keeps_the_deprecated_store() {
    let port = FakePort::default();
    let desktop = request("desktop.input", "execute", json!({"x": 1}));
    let ticket = authorize(
        &port,
        &Action {
            family: Family::DesktopInput,
            request: &desktop,
            principal_id: None,
            paths: Vec::new(),
        },
        5,
    );
    assert_eq!(ticket.ok(), Some(Ticket::DeprecatedStore));
    for family in [Family::Filesystem, Family::Process, Family::Git] {
        let refused = authorize(
            &port,
            &Action {
                family,
                request: &fs_request(),
                principal_id: None,
                paths: vec![r"C:\work\a.txt".to_owned()],
            },
            5,
        );
        assert_eq!(
            code(refused),
            Some(FailureCode::AuthorityUnavailable),
            "{family:?}"
        );
    }
    assert_eq!(port.0.borrow().deprecated_checks, 1);
    assert!(port.0.borrow().authorized.is_empty());
}

#[test]
fn fc_dispatch_a_wrong_family_or_scope_is_refused_before_authorize() {
    let narrow = LeaseScope::DesktopFullUser {
        executors: vec![ExecutorClass::DesktopInput],
        roots: Vec::new(),
        shells: false,
    };
    let browser = LeaseScope::BrowserFullAccess {
        client_ref: CLIENT.to_owned(),
        session_id: "bs-0123456789abcdef-1-0001020304050607".to_owned(),
        origins: vec!["https://fixture.test".to_owned()],
        families: vec![BrowserFamily::Click],
        task: None,
    };
    let port = FakePort::installed(vec![lease('1', narrow), lease('2', browser)]);
    let run = |op: WorkerOp, principal: Option<&str>| {
        run_in_worker(&port, &launcher(&port), &fs_request(), principal, &op, 5)
    };
    // The narrow default and a browser lease cover no filesystem work.
    assert_eq!(
        code(run(read_op(r"C:\work\a.txt"), None)),
        Some(FailureCode::LeaseRequired)
    );
    let process = authorize(
        &port,
        &Action {
            family: Family::Process,
            request: &fs_request(),
            principal_id: None,
            paths: Vec::new(),
        },
        5,
    );
    assert_eq!(code(process), Some(FailureCode::LeaseRequired));
    assert!(port.0.borrow().authorized.is_empty());

    port.with(|service| service.leases = vec![lease('3', full_scope())]);
    assert_eq!(
        code(run(read_op(r"C:\workshop\a.txt"), None)),
        Some(FailureCode::PathEscape)
    );
    assert_eq!(
        code(run(read_op(r"C:\work\..\x"), None)),
        Some(FailureCode::InvalidRequest)
    );
    assert_eq!(
        code(run(read_op(r"C:\work\a.txt"), Some("cl-another"))),
        Some(FailureCode::CapabilityDenied)
    );
    let git_without_paths = authorize(
        &port,
        &Action {
            family: Family::Git,
            request: &fs_request(),
            principal_id: None,
            paths: Vec::new(),
        },
        5,
    );
    assert_eq!(code(git_without_paths), Some(FailureCode::InvalidRequest));
    assert!(
        port.0.borrow().authorized.is_empty(),
        "no refusal reached Authorize"
    );
}

#[test]
fn fc_dispatch_the_digest_binds_family_target_arguments_and_paths() {
    let base_request = fs_request();
    let action = |family, request: &RequestEnvelope, paths: &[&str]| {
        action_digest(
            &Action {
                family,
                request,
                principal_id: None,
                paths: paths.iter().map(|p| (*p).to_owned()).collect(),
            },
            5,
        )
    };
    let base = action(Family::Filesystem, &base_request, &[r"C:\work\a.txt"]);
    assert_eq!(base.len(), 64);
    assert_eq!(
        base,
        action(Family::Filesystem, &base_request, &[r"C:\work\a.txt"])
    );
    let mut targeted = fs_request();
    targeted.target = Some("t".into());
    let other_args = request(
        "full_control.fs",
        "read_text",
        serde_json::to_value(read_op(r"C:\work\b.txt")).expect("op"),
    );
    for other in [
        action(Family::Git, &base_request, &[r"C:\work\a.txt"]),
        action(Family::Filesystem, &base_request, &[r"C:\work\b.txt"]),
        action(
            Family::Filesystem,
            &base_request,
            &[r"C:\work\a.txt", r"C:\work\b.txt"],
        ),
        action(Family::Filesystem, &targeted, &[r"C:\work\a.txt"]),
        action(Family::Filesystem, &other_args, &[r"C:\work\a.txt"]),
    ] {
        assert_ne!(base, other);
    }
    // Desktop input keeps slice 2's digest.
    let desktop = request("desktop.input", "execute", json!({"x": 1}));
    assert_eq!(
        action(Family::DesktopInput, &desktop, &[]),
        crate::authority_link::desktop_action_digest(&desktop, 5)
    );
    // What Authorize was asked carries the digest, the paths and the
    // lease's own client and task.
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    run_in_worker(
        &port,
        &launcher(&port),
        &base_request,
        None,
        &read_op(r"C:\work\a.txt"),
        5,
    )
    .expect("allowed");
    let service = port.0.borrow();
    let (lease_id, executor, claims) = &service.authorized[0];
    assert_eq!(lease_id, &format!("al-{}", "1".repeat(32)));
    assert_eq!(*executor, ExecutorClass::Filesystem);
    assert_eq!(claims.action_digest, base);
    assert_eq!(claims.paths, Some(vec![r"C:\work\a.txt".to_owned()]));
    assert_eq!(claims.principal_id, CLIENT);
    assert_eq!(claims.task, "tidy the work folder");
    assert_eq!(claims.request_id, "req-7");
}

#[test]
fn fc_dispatch_a_job_family_needs_its_service_made_job() {
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    let lease_id = format!("al-{}", "1".repeat(32));
    let good_job = format!("fcj-{}", "0".repeat(32));
    for answer in [
        json!({"authorization_id": "az-1", "lease_id": lease_id, "job_id": null}),
        json!({"authorization_id": "az-1", "lease_id": lease_id, "job_id": "Local\\someone-elses-job", "job_handle": 12}),
        json!({"authorization_id": "az-1", "lease_id": lease_id, "job_id": good_job}),
        json!({"authorization_id": "az-1", "lease_id": lease_id, "job_id": good_job, "job_handle": 0}),
        json!({"authorization_id": "az-1", "lease_id": format!("al-{}", "9".repeat(32)), "job_id": good_job, "job_handle": 16}),
        json!({"lease_id": lease_id, "job_id": good_job, "job_handle": 20}),
    ] {
        port.with(|service| service.answer = Some(answer.clone()));
        let launched = launcher(&port);
        let refused = run_in_worker(
            &port,
            &launched,
            &fs_request(),
            None,
            &read_op(r"C:\work\a.txt"),
            5,
        );
        assert_eq!(
            code(refused),
            Some(FailureCode::AuthorityUnavailable),
            "{answer}"
        );
        assert_eq!(launched.runs.get(), 0, "nothing ran outside a job");
    }
    // A desktop answer that names a job is refused too.
    port.with(|service| {
        service.answer = Some(json!({
            "authorization_id": "az-1",
            "lease_id": lease_id,
            "job_id": format!("fcj-{}", "0".repeat(32)),
            "job_handle": 24,
        }))
    });
    let desktop = request("desktop.input", "execute", json!({"x": 1}));
    assert_eq!(
        code(desktop_gate(&port, &desktop, 5)),
        Some(FailureCode::AuthorityUnavailable)
    );
    // Every handle the service sent with a refused answer was closed.
    assert_eq!(port.0.borrow().released, vec![12, 16, 20, 24]);
}

/// Review of 291e045e (low 2): the operation that runs is the request's own
/// arguments, which the digest covers; anything else is refused before
/// Authorize.
#[test]
fn fc_dispatch_the_operation_is_the_request_arguments_or_nothing() {
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    for arguments in [
        json!({"path": r"C:\work\a.txt"}),
        json!({"op": "read_text", "path": r"C:\work\a.txt", "max_bytes": 4, "also": 1}),
        json!({"op": "delete_tree", "path": r"C:\work"}),
        json!([]),
    ] {
        let mut request = fs_request();
        request.arguments = arguments.clone();
        let refused = dispatch_worker(&port, &launcher(&port), &request, None, 5);
        assert_eq!(
            code(refused),
            Some(FailureCode::InvalidRequest),
            "{arguments}"
        );
    }
    assert!(port.0.borrow().authorized.is_empty());
    let ran = dispatch_worker(&port, &launcher(&port), &fs_request(), None, 5).expect("ran");
    assert_eq!(ran["ran"][0], r"C:\work\a.txt");
    let service = port.0.borrow();
    let digest = &service.authorized[0].2.action_digest;
    let expected = action_digest(
        &Action {
            family: Family::Filesystem,
            request: &fs_request(),
            principal_id: None,
            paths: vec![r"C:\work\a.txt".to_owned()],
        },
        5,
    );
    assert_eq!(digest, &expected);
}

#[test]
fn fc_dispatch_a_revoke_between_authorize_and_run_refuses_and_is_recorded() {
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    port.with(|service| service.revoke_after_authorize = true);
    let launched = launcher(&port);
    let refused = run_in_worker(
        &port,
        &launched,
        &fs_request(),
        None,
        &read_op(r"C:\work\a.txt"),
        5,
    );
    assert_eq!(code(refused), Some(FailureCode::LeaseInvalid));
    assert_eq!(launched.runs.get(), 0);
    let service = port.0.borrow();
    assert_eq!(service.outcomes.len(), 1);
    assert_eq!(service.outcomes[0].1, DispatchOutcome::Failed);
    assert_eq!(service.outcomes[0].2, Some(FailureCode::LeaseInvalid));
}

#[test]
fn fc_dispatch_every_outcome_is_recorded() {
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    let launched = launcher(&port);
    let ran = run_in_worker(
        &port,
        &launched,
        &fs_request(),
        None,
        &read_op(r"C:\work\a.txt"),
        5,
    )
    .expect("ran");
    assert_eq!(ran["ran"][0], r"C:\work\a.txt");
    let failing = FakeLauncher {
        fails: Some(FailureCode::PathEscape),
        ..launcher(&port)
    };
    assert_eq!(
        code(run_in_worker(
            &port,
            &failing,
            &fs_request(),
            None,
            &read_op(r"C:\work\b.txt"),
            6
        )),
        Some(FailureCode::PathEscape)
    );
    let service = port.0.borrow();
    let outcomes: Vec<(DispatchOutcome, Option<FailureCode>)> = service
        .outcomes
        .iter()
        .map(|(_, outcome, code)| (*outcome, code.clone()))
        .collect();
    assert_eq!(
        outcomes,
        vec![
            (DispatchOutcome::Succeeded, None),
            (DispatchOutcome::Failed, Some(FailureCode::PathEscape)),
        ]
    );
    assert_eq!(service.outcomes[0].0, format!("az-{:032x}", 1));
}

#[test]
fn fc_dispatch_desktop_requests_report_each_authorization_once() {
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    let desktop = request("desktop.input", "execute", json!({"x": 1}));
    let made = Cell::new(0);
    let result: Result<(), ProviderError> = with_desktop_outcomes(
        || {
            made.set(made.get() + 1);
            Box::new(port.clone())
        },
        || {
            desktop_gate(&port, &desktop, 5)?;
            desktop_gate(&port, &desktop, 6)?;
            Err(ProviderError::new(FailureCode::ApprovalDenied, "declined"))
        },
    );
    assert_eq!(code(result), Some(FailureCode::ApprovalDenied));
    assert_eq!(made.get(), 1);
    {
        let service = port.0.borrow();
        assert_eq!(service.outcomes.len(), 2);
        assert!(service
            .outcomes
            .iter()
            .all(|(_, outcome, code)| *outcome == DispatchOutcome::Failed
                && *code == Some(FailureCode::ApprovalDenied)));
        // Desktop input runs in orceld as before: no job was asked for.
        assert!(service.live_jobs.is_empty());
    }
    // A request that took no desktop authorization reports nothing.
    let quiet: Result<u8, ProviderError> = with_desktop_outcomes(
        || {
            made.set(made.get() + 1);
            Box::new(port.clone())
        },
        || Ok(1),
    );
    assert_eq!(quiet.ok(), Some(1));
    assert_eq!(made.get(), 1);
    assert_eq!(port.0.borrow().outcomes.len(), 2);
}
