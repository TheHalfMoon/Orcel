//! SG-000132 WP1-10: the Full Control dispatcher against a fake authority
//! service, a fake worker launcher and a fake per-action approval, on every
//! OS, including the WP1-15 process and git families (SG132_SLICE4.md). The
//! real Job Objects and the real `orceld fc-worker` are in
//! `fc_worker_tests.rs` (Windows).

use crate::fc_worker::WorkerOp;
use crate::full_control_dispatch::{
    action_digest, authorize, bounded_execution_gate, desktop_gate, ensure_lease_host,
    run_in_worker as dispatch_worker, with_desktop_outcomes, Action, ActionApproval, AuthorityPort,
    BoundedExecution, Family, HostLauncher, JobGrant, Ticket, WorkerLauncher,
};
use orcel_authority::core::standing::{PinnedProgram, StandingApproval};
use orcel_authority::lease::{
    BrowserFamily, GrantEvidence, LeaseBody, LeaseScope, ObservedRequester, LEASE_CONTRACT,
};
use orcel_authority::protocol::{AuthorizeClaims, DispatchOutcome, StandingClaim};
use orcel_contracts::{ExecutorClass, FailureCode, RequestEnvelope};
use orcel_provider_fs::ProviderError;
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::rc::Rc;

/// The calling MCP client of `request` (client session `c`), as orceld
/// identifies it (SG132_SLICE6.md); the test leases are bound to it.
fn client() -> String {
    orcel_policy::browser_lease::client_ref("c")
}

pub(crate) fn lease(id: char, scope: LeaseScope) -> LeaseBody {
    LeaseBody {
        contract: LEASE_CONTRACT.to_owned(),
        lease_id: format!("al-{}", id.to_string().repeat(32)),
        scope,
        windows_user_sid: "S-1-5-21-1".to_owned(),
        logon_session_id: 7,
        ts_session_id: 1,
        principal_id: client(),
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
pub(crate) struct FakeService {
    installed: bool,
    pub(crate) unreachable: bool,
    leases: Vec<LeaseBody>,
    /// WP1-14: the standing approvals the service reports in effect, and a
    /// refusal of every `Authorize` that names one.
    pub(crate) standing: Vec<StandingApproval>,
    pub(crate) refuse_standing: Option<FailureCode>,
    /// The standing approval each `Authorize` named, in order.
    pub(crate) named_standing: Vec<Option<StandingClaim>>,
    /// Replaces the Authorize answer when set.
    answer: Option<Value>,
    /// Ends the dispatch's job right after answering (a revoke that lands
    /// between Authorize and the launch).
    revoke_after_authorize: bool,
    live_jobs: BTreeSet<String>,
    /// Authorization id to its job id.
    job_of: std::collections::BTreeMap<String, String>,
    /// SG132_SLICE5.md: the acknowledgements orceld sent (authorization,
    /// handle), and the code to refuse them with.
    acks: Vec<(String, u64)>,
    refuse_ack: Option<FailureCode>,
    /// Desktop host jobs asked for (lease ids), the answer's override, and
    /// a refusal.
    desktop_hosts: Vec<String>,
    host_answer: Option<Value>,
    refuse_host: Option<FailureCode>,
    /// What happened, in order ("authorize", "ack", "active", "host").
    pub(crate) calls: Vec<&'static str>,
    pub(crate) authorized: Vec<(String, ExecutorClass, AuthorizeClaims)>,
    pub(crate) outcomes: Vec<(String, DispatchOutcome, Option<FailureCode>)>,
    deprecated_checks: u32,
    next: u32,
}

#[derive(Clone, Default)]
pub(crate) struct FakePort(pub(crate) Rc<RefCell<FakeService>>);

impl FakePort {
    pub(crate) fn installed(leases: Vec<LeaseBody>) -> Self {
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

    fn standing(&self) -> Result<Vec<StandingApproval>, ProviderError> {
        let service = self.0.borrow();
        if service.unreachable {
            return Err(unavailable());
        }
        Ok(service.standing.clone())
    }

    fn authorize(
        &self,
        lease_id: &str,
        executor: ExecutorClass,
        claims: AuthorizeClaims,
        standing: Option<&StandingClaim>,
    ) -> Result<Value, ProviderError> {
        let mut service = self.0.borrow_mut();
        if service.unreachable {
            return Err(unavailable());
        }
        service.named_standing.push(standing.cloned());
        if let (Some(_), Some(code)) = (standing, &service.refuse_standing) {
            return Err(ProviderError::new(
                code.clone(),
                "the service refused the standing approval",
            ));
        }
        service.calls.push("authorize");
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
                "standing_id": standing.map(|claim| claim.standing_id.clone()),
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
        let mut service = self.0.borrow_mut();
        service.calls.push("active");
        match service.job_of.get(authorization_id) {
            Some(job) if service.live_jobs.contains(job) => Ok(()),
            _ => Err(ProviderError::new(
                FailureCode::LeaseInvalid,
                "the dispatch's lease ended or its Job Object was terminated",
            )),
        }
    }

    fn job_ack(&self, authorization_id: &str, job_handle: u64) -> Result<(), ProviderError> {
        let mut service = self.0.borrow_mut();
        service.calls.push("ack");
        service.acks.push((authorization_id.to_owned(), job_handle));
        match &service.refuse_ack {
            Some(code) => Err(ProviderError::new(code.clone(), "the ack was refused")),
            None => Ok(()),
        }
    }

    fn desktop_host_job(&self, lease_id: &str) -> Result<Value, ProviderError> {
        let mut service = self.0.borrow_mut();
        service.calls.push("host");
        if let Some(code) = &service.refuse_host {
            return Err(ProviderError::new(code.clone(), "no desktop host job"));
        }
        service.next += 1;
        let job = format!("fcj-{:032x}", service.next);
        let authorization = format!("az-{:032x}", service.next);
        service.live_jobs.insert(job.clone());
        service.job_of.insert(authorization.clone(), job.clone());
        service.desktop_hosts.push(lease_id.to_owned());
        let handle = 0x8000 + 4 * u64::from(service.next);
        Ok(service.host_answer.clone().unwrap_or_else(|| {
            json!({
                "authorization_id": authorization,
                "lease_id": lease_id,
                "job_id": job,
                "job_handle": handle,
            })
        }))
    }
}

/// A fake launcher: "assigns" the suspended worker, then resumes it only if
/// `confirm` (the service's DispatchActive) succeeds, as the real one does.
pub(crate) struct FakeLauncher {
    service: FakePort,
    fails: Option<FailureCode>,
    pub(crate) runs: Cell<u32>,
    /// The pinned program each run was handed (review of #844).
    pub(crate) pinned: RefCell<Vec<Option<PinnedProgram>>>,
}

impl WorkerLauncher for FakeLauncher {
    fn run(
        &self,
        job: &JobGrant,
        roots: &[String],
        op: &WorkerOp,
        pinned: Option<&PinnedProgram>,
        confirm: &dyn Fn() -> Result<(), ProviderError>,
    ) -> Result<Value, ProviderError> {
        assert!(job.handle != 0 && job.id.starts_with("fcj-"));
        let _ = &self.service;
        self.pinned.borrow_mut().push(pinned.cloned());
        confirm()?;
        self.runs.set(self.runs.get() + 1);
        assert_eq!(roots, [r"C:\work".to_owned()]);
        match &self.fails {
            Some(code) => Err(ProviderError::new(code.clone(), "the operation failed")),
            None => Ok(json!({ "ran": op.paths() })),
        }
    }
}

/// A fake per-action approval: what it was asked, and its answer.
#[derive(Default)]
pub(crate) struct FakeApproval {
    pub(crate) deny: bool,
    pub(crate) asked: RefCell<Vec<(String, String)>>,
}

impl ActionApproval for FakeApproval {
    fn approve(
        &self,
        op: &WorkerOp,
        _request: &RequestEnvelope,
        action_digest: &str,
    ) -> Result<(), ProviderError> {
        self.asked
            .borrow_mut()
            .push((op.name().to_owned(), action_digest.to_owned()));
        if self.deny {
            Err(ProviderError::new(
                FailureCode::ApprovalDenied,
                "the person declined",
            ))
        } else {
            Ok(())
        }
    }
}

pub(crate) fn launcher(service: &FakePort) -> FakeLauncher {
    FakeLauncher {
        service: service.clone(),
        fails: None,
        runs: Cell::new(0),
        pinned: RefCell::new(Vec::new()),
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
    request.operation = op.name().to_owned();
    request.arguments = serde_json::to_value(op).expect("op");
    dispatch_worker(
        port,
        launcher,
        &FakeApproval::default(),
        &request,
        principal_id,
        false,
        now_ms,
    )
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
        client_ref: client(),
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
            paths: vec![r"C:\work".to_owned(), r"C:\work\tool.exe".to_owned()],
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
    for family in [Family::Git, Family::Process] {
        let without_paths = authorize(
            &port,
            &Action {
                family,
                request: &fs_request(),
                principal_id: None,
                paths: Vec::new(),
            },
            5,
        );
        assert_eq!(
            code(without_paths),
            Some(FailureCode::InvalidRequest),
            "{family:?}"
        );
    }
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
    assert_eq!(claims.principal_id, client());
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
    // SG132_SLICE5.md: no handle that came with a refused answer was
    // acknowledged (so none was used or closed here; the service withdraws
    // unacknowledged handles itself).
    assert!(port.0.borrow().acks.is_empty());
}

/// SG132_SLICE5.md: the job handle is acknowledged (authorization id and
/// handle value) right after Authorize and before the worker is started;
/// a refused acknowledgement runs nothing, closes nothing and is reported
/// as a failed outcome.
#[test]
fn fc_dispatch_acknowledges_the_job_handle_before_using_it() {
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    let launched = launcher(&port);
    run_in_worker(
        &port,
        &launched,
        &fs_request(),
        None,
        &read_op(r"C:\work\a.txt"),
        5,
    )
    .expect("runs");
    {
        let service = port.0.borrow();
        assert_eq!(service.calls, vec!["authorize", "ack", "active"]);
        assert_eq!(
            service.acks,
            vec![(format!("az-{:032x}", 1), 0x4000 + 4)],
            "the authorization and the handle value it carried"
        );
    }
    // A desktop authorization carries no job and acknowledges nothing.
    let desktop = request("desktop.input", "execute", json!({"x": 1}));
    desktop_gate(&port, &desktop, 5).expect("desktop");
    assert_eq!(port.0.borrow().acks.len(), 1);

    // Refused: nothing runs, the outcome is recorded as failed.
    port.with(|service| {
        service.refuse_ack = Some(FailureCode::LeaseInvalid);
        service.outcomes.clear();
    });
    let refused = run_in_worker(
        &port,
        &launched,
        &fs_request(),
        None,
        &read_op(r"C:\work\a.txt"),
        6,
    );
    assert_eq!(code(refused), Some(FailureCode::LeaseInvalid));
    assert_eq!(launched.runs.get(), 1, "nothing ran after the refusal");
    let service = port.0.borrow();
    assert_eq!(service.outcomes.len(), 1);
    assert_eq!(service.outcomes[0].1, DispatchOutcome::Failed);
    assert_eq!(service.outcomes[0].2, Some(FailureCode::LeaseInvalid));
}

/// A fake desktop host launcher: "assigns" the suspended host and resumes
/// it only if `confirm` succeeds, as the real one does.
#[derive(Default)]
struct FakeHosts {
    running: Cell<bool>,
    /// The generation of the host in use (moves on every replacement, as
    /// the adapter's does).
    generation: Cell<u64>,
    started: RefCell<Vec<u64>>,
    fails: Cell<bool>,
}

impl HostLauncher for FakeHosts {
    fn running(&self, generation: u64) -> bool {
        self.running.get() && self.generation.get() == generation
    }

    fn start_in_job(
        &self,
        job_handle: u64,
        confirm: &dyn Fn() -> Result<(), ProviderError>,
    ) -> Result<u64, ProviderError> {
        if self.fails.get() {
            return Err(ProviderError::new(
                FailureCode::ProviderUnavailable,
                "the host did not start",
            ));
        }
        confirm()?;
        self.started.borrow_mut().push(job_handle);
        self.running.set(true);
        self.generation.set(self.generation.get() + 1);
        Ok(self.generation.get())
    }
}

/// SG132_SLICE5.md: one desktop input host per lease, in that lease's
/// service-made job: kept while it runs in the same lease's job, started
/// fresh for a new lease or once it ended (the service ends it with the
/// lease), after the handle is acknowledged and the job confirmed.
#[test]
fn fc_dispatch_the_desktop_host_runs_in_its_leases_job_and_a_new_lease_gets_a_fresh_one() {
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    let hosts = FakeHosts::default();
    let current = std::sync::Mutex::new(None);
    let first_lease = format!("al-{}", "1".repeat(32));
    let second_lease = format!("al-{}", "2".repeat(32));

    let first = ensure_lease_host(&port, &hosts, &current, &first_lease).expect("first host");
    assert_eq!(first.lease_id, first_lease);
    assert!(first.job_id.starts_with("fcj-"));
    assert_eq!(port.0.borrow().calls, vec!["host", "ack", "active"]);
    assert_eq!(hosts.started.borrow().len(), 1);
    // The same lease, host running: kept, no new job.
    let again = ensure_lease_host(&port, &hosts, &current, &first_lease).expect("same host");
    assert_eq!(again, first);
    assert_eq!(hosts.started.borrow().len(), 1);
    assert_eq!(port.0.borrow().desktop_hosts.len(), 1);
    // The host ended (the service terminated the lease's job): a fresh one.
    hosts.running.set(false);
    let restarted = ensure_lease_host(&port, &hosts, &current, &first_lease).expect("restarted");
    assert_ne!(restarted.job_id, first.job_id);
    assert_eq!(hosts.started.borrow().len(), 2);
    // Review of c02942bc: another host replaced the lease's one (an
    // observation restarted a plain host after the leased one ended), and
    // the replacement runs. It is not the lease's host: a fresh one in a
    // fresh job, never the running plain host.
    hosts.generation.set(hosts.generation.get() + 1);
    assert!(!hosts.running(restarted.generation));
    let replaced = ensure_lease_host(&port, &hosts, &current, &first_lease).expect("replaced");
    assert_ne!(replaced.job_id, restarted.job_id);
    assert_ne!(replaced.generation, restarted.generation);
    assert_eq!(hosts.started.borrow().len(), 3);
    // A new lease gets a fresh host in its own job.
    let second = ensure_lease_host(&port, &hosts, &current, &second_lease).expect("second lease");
    assert_eq!(second.lease_id, second_lease);
    assert_eq!(hosts.started.borrow().len(), 4);
    assert_eq!(
        port.0.borrow().desktop_hosts,
        vec![
            first_lease.clone(),
            first_lease.clone(),
            first_lease.clone(),
            second_lease.clone()
        ]
    );
    // Each started host used the handle its own answer carried, acknowledged
    // first.
    let service = port.0.borrow();
    let acked: Vec<u64> = service.acks.iter().map(|(_, handle)| *handle).collect();
    assert_eq!(*hosts.started.borrow(), acked);
}

/// SG132_SLICE5.md: the desktop host never runs outside its job: a job
/// that cannot be made, a malformed answer, a refused acknowledgement, a
/// refused confirmation (a revoke before the resume) or a failed start
/// refuses the desktop action and leaves the previous state alone.
#[test]
fn fc_dispatch_the_desktop_host_fails_closed_without_its_job() {
    let lease_id = format!("al-{}", "1".repeat(32));
    let fresh = || {
        (
            FakePort::installed(vec![lease('1', full_scope())]),
            FakeHosts::default(),
            std::sync::Mutex::new(None),
        )
    };
    // No job.
    let (port, hosts, current) = fresh();
    port.with(|service| service.refuse_host = Some(FailureCode::AuthorityUnavailable));
    assert_eq!(
        code(ensure_lease_host(&port, &hosts, &current, &lease_id)),
        Some(FailureCode::AuthorityUnavailable)
    );
    assert!(hosts.started.borrow().is_empty() && current.lock().expect("state").is_none());
    // Malformed answers: nothing acknowledged, nothing started.
    for answer in [
        json!({"lease_id": lease_id, "job_id": format!("fcj-{}", "0".repeat(32)), "job_handle": 8}),
        json!({"authorization_id": "az-1", "lease_id": lease_id, "job_id": "Local\\x", "job_handle": 8}),
        json!({"authorization_id": "az-1", "lease_id": lease_id, "job_id": format!("fcj-{}", "0".repeat(32)), "job_handle": 0}),
        json!({"authorization_id": "az-1", "lease_id": format!("al-{}", "9".repeat(32)), "job_id": format!("fcj-{}", "0".repeat(32)), "job_handle": 8}),
    ] {
        let (port, hosts, current) = fresh();
        port.with(|service| service.host_answer = Some(answer.clone()));
        assert_eq!(
            code(ensure_lease_host(&port, &hosts, &current, &lease_id)),
            Some(FailureCode::AuthorityUnavailable),
            "{answer}"
        );
        assert!(port.0.borrow().acks.is_empty(), "{answer}");
        assert!(hosts.started.borrow().is_empty(), "{answer}");
    }
    // A refused acknowledgement starts nothing.
    let (port, hosts, current) = fresh();
    port.with(|service| service.refuse_ack = Some(FailureCode::CapabilityDenied));
    assert_eq!(
        code(ensure_lease_host(&port, &hosts, &current, &lease_id)),
        Some(FailureCode::CapabilityDenied)
    );
    assert!(hosts.started.borrow().is_empty());
    // The job ends between the answer and the resume: DispatchActive refuses
    // and the suspended host is never resumed.
    let (port, hosts, current) = fresh();
    let answer = port.desktop_host_job(&lease_id).expect("answer");
    port.with(|service| {
        service.live_jobs.clear();
        service.host_answer = Some(answer.clone());
    });
    assert_eq!(
        code(ensure_lease_host(&port, &hosts, &current, &lease_id)),
        Some(FailureCode::LeaseInvalid)
    );
    assert!(hosts.started.borrow().is_empty());
    assert!(current.lock().expect("state").is_none());
    // A host that does not start leaves the earlier lease host recorded as
    // it was (and not running, so the next action tries again).
    let (port, hosts, current) = fresh();
    ensure_lease_host(&port, &hosts, &current, &lease_id).expect("first");
    hosts.running.set(false);
    hosts.fails.set(true);
    let before = current.lock().expect("state").clone();
    assert_eq!(
        code(ensure_lease_host(&port, &hosts, &current, &lease_id)),
        Some(FailureCode::ProviderUnavailable)
    );
    assert_eq!(*current.lock().expect("state"), before);
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
        let refused = dispatch_worker(
            &port,
            &launcher(&port),
            &FakeApproval::default(),
            &request,
            None,
            false,
            5,
        );
        assert_eq!(
            code(refused),
            Some(FailureCode::InvalidRequest),
            "{arguments}"
        );
    }
    // An operation name that differs from the arguments' is refused too.
    let mut renamed = fs_request();
    renamed.operation = "stat".into();
    assert_eq!(
        code(dispatch_worker(
            &port,
            &launcher(&port),
            &FakeApproval::default(),
            &renamed,
            None,
            false,
            5
        )),
        Some(FailureCode::InvalidRequest)
    );
    assert!(port.0.borrow().authorized.is_empty());
    let ran = dispatch_worker(
        &port,
        &launcher(&port),
        &FakeApproval::default(),
        &fs_request(),
        None,
        false,
        5,
    )
    .expect("ran");
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

/// SG132_SLICE6.md (slice 2 residual): the desktop gate names the calling
/// MCP client (the client reference of the request's client session, as
/// orceld identifies clients for browser leases) in `Authorize`, never the
/// lease's own principal. A lease bound to another client is refused before
/// the service is asked; an unbound lease is authorized for the real client.
#[test]
fn fc_dispatch_the_desktop_gate_names_the_calling_client() {
    // Bound to client session `c`: that client is admitted and named.
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    let desktop = request("desktop.input", "execute", json!({"x": 1}));
    desktop_gate(&port, &desktop, 5).expect("the bound client");
    assert_eq!(port.0.borrow().authorized[0].2.principal_id, client());
    // Another client session: refused here, the service never asked.
    let mut other = desktop.clone();
    other.client_session_id = "another-mcp-client".into();
    let other_ref = orcel_policy::browser_lease::client_ref("another-mcp-client");
    assert_ne!(other_ref, client());
    assert_eq!(
        code(desktop_gate(&port, &other, 6)),
        Some(FailureCode::CapabilityDenied)
    );
    assert_eq!(port.0.borrow().authorized.len(), 1);
    // An unbound lease (the default label): the real client is named, not
    // the label.
    let mut unbound = lease('2', full_scope());
    unbound.principal_id = "orcel-owner".to_owned();
    let port = FakePort::installed(vec![unbound]);
    desktop_gate(&port, &other, 7).expect("an unbound lease");
    {
        let service = port.0.borrow();
        assert_eq!(service.authorized.len(), 1);
        assert_eq!(service.authorized[0].2.principal_id, other_ref);
        assert_eq!(service.authorized[0].1, ExecutorClass::DesktopInput);
    }
    // The unbound relaxation is desktop input's only: a filesystem dispatch
    // naming a client keeps the exact match and is refused before Authorize.
    assert_eq!(
        code(run_in_worker(
            &port,
            &launcher(&port),
            &fs_request(),
            Some(&other_ref),
            &read_op(r"C:\work\a.txt"),
            8
        )),
        Some(FailureCode::CapabilityDenied)
    );
    assert_eq!(port.0.borrow().authorized.len(), 1);
}

/// SG132_SLICE7.md (slice 6 residual 5): the SG-000036 bounded execution
/// shape `uia.input/execute`.
fn bounded_request() -> RequestEnvelope {
    request(
        "uia.input",
        "execute",
        json!({
            "coord_id": "c",
            "expected_derivation_generation": 1,
            "operation": "click",
        }),
    )
}

/// The resolved click the registry bound and the person approved.
fn resolved(x: u64, y: u64) -> Value {
    json!({
        "process_id": "p",
        "window_id": "w",
        "window_generation": 1,
        "hwnd": 12345,
        "x": x,
        "y": y,
        "operation": "click",
        "input_lease_id": "l",
        "approval_digest": "d",
    })
}

#[test]
fn fc_dispatch_bounded_execution_without_the_service_is_unchanged() {
    // No service: the deprecated in-process route, as before; the
    // deprecated store is not consulted (it never was for this shape) and
    // nothing is authorized or reported.
    let port = FakePort::default();
    assert_eq!(
        bounded_execution_gate(&port, &bounded_request(), &resolved(3, 2), 5).expect("unchanged"),
        BoundedExecution::InProcess
    );
    let service = port.0.borrow();
    assert_eq!(service.deprecated_checks, 0);
    assert!(service.authorized.is_empty());
    assert!(service.calls.is_empty());
}

#[test]
fn fc_dispatch_bounded_execution_with_the_service_needs_a_lease_and_authorize() {
    // Installed, a lease covering desktop input for this client: the
    // service authorizes it (desktop input, the calling client) and the
    // action runs only in that lease's host; the outcome is reported.
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    let routed = with_desktop_outcomes(
        || Box::new(port.clone()),
        || bounded_execution_gate(&port, &bounded_request(), &resolved(3, 2), 5),
    )
    .expect("leased");
    assert_eq!(
        routed,
        BoundedExecution::Leased(format!("al-{}", "1".repeat(32)))
    );
    {
        let service = port.0.borrow();
        assert_eq!(service.calls, vec!["authorize"]);
        let (lease_id, executor, claims) = &service.authorized[0];
        assert_eq!(lease_id, &format!("al-{}", "1".repeat(32)));
        assert_eq!(*executor, ExecutorClass::DesktopInput);
        assert_eq!(claims.principal_id, client());
        assert_eq!(claims.capability, "uia.input");
        assert_eq!(claims.operation, "execute");
        assert_eq!(service.outcomes.len(), 1);
        assert_eq!(service.outcomes[0].1, DispatchOutcome::Succeeded);
        assert_eq!(service.deprecated_checks, 0);
    }

    // Installed, no lease: refused, never in process, nothing authorized.
    let port = FakePort::installed(Vec::new());
    assert_eq!(
        code(bounded_execution_gate(
            &port,
            &bounded_request(),
            &resolved(3, 2),
            6
        )),
        Some(FailureCode::LeaseRequired)
    );
    assert!(port.0.borrow().authorized.is_empty());
    assert_eq!(port.0.borrow().deprecated_checks, 0);

    // Installed, a lease without desktop input: refused.
    let filesystem_only = LeaseScope::DesktopFullUser {
        executors: vec![ExecutorClass::Filesystem],
        roots: vec![r"C:\work".to_owned()],
        shells: false,
    };
    let port = FakePort::installed(vec![lease('2', filesystem_only)]);
    assert_eq!(
        code(bounded_execution_gate(
            &port,
            &bounded_request(),
            &resolved(3, 2),
            7
        )),
        Some(FailureCode::LeaseRequired)
    );
    assert!(port.0.borrow().authorized.is_empty());

    // Installed, a lease bound to another client: refused before Authorize.
    let mut other = bounded_request();
    other.client_session_id = "another-mcp-client".into();
    let port = FakePort::installed(vec![lease('3', full_scope())]);
    assert_eq!(
        code(bounded_execution_gate(&port, &other, &resolved(3, 2), 8)),
        Some(FailureCode::CapabilityDenied)
    );
    assert!(port.0.borrow().authorized.is_empty());

    // Installed but not answering: refused, never the store or in process.
    let port = FakePort::installed(vec![lease('4', full_scope())]);
    port.with(|service| service.unreachable = true);
    assert_eq!(
        code(bounded_execution_gate(
            &port,
            &bounded_request(),
            &resolved(3, 2),
            9
        )),
        Some(FailureCode::AuthorityUnavailable)
    );
    assert_eq!(port.0.borrow().deprecated_checks, 0);

    // The service refuses Authorize (a malformed answer stands in for any
    // refusal): refused, nothing runs.
    let port = FakePort::installed(vec![lease('5', full_scope())]);
    port.with(|service| service.answer = Some(json!({})));
    assert!(bounded_execution_gate(&port, &bounded_request(), &resolved(3, 2), 10).is_err());
}

#[test]
fn fc_dispatch_bounded_execution_audit_names_the_resolved_click() {
    // The service's action digest covers the resolved click: other
    // coordinates (or another window handle) give another digest, at the
    // same time and for the same request.
    let digest_for = |resolved: &Value| {
        let port = FakePort::installed(vec![lease('1', full_scope())]);
        bounded_execution_gate(&port, &bounded_request(), resolved, 5).expect("leased");
        let service = port.0.borrow();
        let claims = &service.authorized[0].2;
        assert_eq!(claims.capability, "uia.input");
        assert_eq!(claims.operation, "execute");
        claims.action_digest.clone()
    };
    let base = digest_for(&resolved(3, 2));
    assert_eq!(base, digest_for(&resolved(3, 2)));
    assert_ne!(base, digest_for(&resolved(4, 2)));
    assert_ne!(base, digest_for(&resolved(3, 9)));
    let mut other_window = resolved(3, 2);
    other_window["hwnd"] = json!(54321);
    assert_ne!(base, digest_for(&other_window));
    // It is the slice 2 desktop digest over the request with the resolved
    // click added; the request's own arguments stay in it.
    let audited = crate::full_control_dispatch::bounded_execution_audit_request(
        &bounded_request(),
        &resolved(3, 2),
    );
    assert_eq!(audited.arguments["request"], bounded_request().arguments);
    assert_eq!(audited.arguments["resolved"]["x"], json!(3));
    assert_eq!(
        base,
        crate::authority_link::desktop_action_digest(&audited, 5)
    );
}

#[test]
fn fc_dispatch_bounded_execution_runs_only_in_the_leases_host() {
    // The leased route, behaviourally, with the fake service and host
    // launcher: the lease the gate returns gets its host started into that
    // lease's service-made job (as `desktop_host_job::require_for` does),
    // after Authorize; no lease, no host.
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    let hosts = FakeHosts::default();
    let current = std::sync::Mutex::new(None);
    let BoundedExecution::Leased(lease_id) =
        bounded_execution_gate(&port, &bounded_request(), &resolved(3, 2), 5).expect("leased")
    else {
        unreachable!("the service is installed");
    };
    let host = ensure_lease_host(&port, &hosts, &current, &lease_id).expect("the lease's host");
    assert_eq!(host.lease_id, lease_id);
    assert_eq!(
        port.0.borrow().calls,
        vec!["authorize", "host", "ack", "active"]
    );
    assert_eq!(port.0.borrow().desktop_hosts, vec![lease_id.clone()]);
    assert!(hosts.running(host.generation));
    // The service refuses the host job: nothing runs.
    let port = FakePort::installed(vec![lease('2', full_scope())]);
    port.with(|service| service.refuse_host = Some(FailureCode::LeaseInvalid));
    let hosts = FakeHosts::default();
    let current = std::sync::Mutex::new(None);
    let BoundedExecution::Leased(lease_id) =
        bounded_execution_gate(&port, &bounded_request(), &resolved(3, 2), 6).expect("leased")
    else {
        unreachable!("the service is installed");
    };
    assert_eq!(
        code(ensure_lease_host(&port, &hosts, &current, &lease_id)),
        Some(FailureCode::LeaseInvalid)
    );
    assert!(hosts.started.borrow().is_empty());
}

#[test]
fn fc_dispatch_bounded_execution_uses_the_in_process_adapter_only_without_the_service() {
    // Structural: in `uia.rs` the bounded execution path asks the gate first,
    // builds the in-process adapter only on the deprecated route, and runs
    // the leased route in the lease's host.
    let source = include_str!("uia.rs");
    let start = source
        .find("fn execute_with_approval(")
        .expect("execute_with_approval");
    let end = start
        + source[start..]
            .find("\nfn derive_with_approval(")
            .expect("the next function");
    let body = &source[start..end];
    let gate = body
        .find("bounded_execution_gate(request, &resolved)?")
        .expect("the gate");
    let in_process = body
        .find("BoundedExecution::InProcess =>")
        .expect("the deprecated route");
    let leased = body
        .find("BoundedExecution::Leased(lease_id) =>")
        .expect("the leased route");
    let native: Vec<usize> = body
        .match_indices("NativeAdapter::new()")
        .map(|(at, _)| at)
        .collect();
    assert_eq!(native.len(), 1, "one in-process adapter, on one route");
    assert!(gate < in_process && in_process < native[0] && native[0] < leased);
    let leased_route = &body[leased..];
    let require = leased_route
        .find("desktop_host_job::require_for(&lease_id)?")
        .expect("the lease's host");
    let host = leased_route
        .find("computer_host()?")
        .expect("the computer host");
    assert!(require < host);
}

// ---------------------------------------------------------------------
// WP1-15 (SG132_SLICE4.md): the process and git families.
// ---------------------------------------------------------------------

fn run_op(program: &str, cwd: &str) -> WorkerOp {
    WorkerOp::Run {
        program: program.to_owned(),
        args: vec!["--version".to_owned()],
        cwd: cwd.to_owned(),
        timeout_ms: 5_000,
        max_output_bytes: 1_024,
    }
}

fn worker_request(op: &WorkerOp) -> RequestEnvelope {
    request(
        "full_control.process",
        op.name(),
        serde_json::to_value(op).expect("op"),
    )
}

#[test]
fn fc_dispatch_process_and_git_mutations_need_a_fresh_approval_bound_to_the_digest() {
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    let approval = FakeApproval::default();
    let launched = launcher(&port);
    let run = run_op(r"C:\work\tools\tool.exe", r"C:\work");
    let ran = dispatch_worker(
        &port,
        &launched,
        &approval,
        &worker_request(&run),
        None,
        false,
        5,
    )
    .expect("approved and ran");
    assert_eq!(ran["ran"], json!([r"C:\work", r"C:\work\tools\tool.exe"]));
    {
        let service = port.0.borrow();
        let (_, executor, claims) = &service.authorized[0];
        assert_eq!(*executor, ExecutorClass::ShellProcess);
        assert_eq!(
            claims.paths,
            Some(vec![
                r"C:\work".to_owned(),
                r"C:\work\tools\tool.exe".to_owned()
            ])
        );
        // The person approved exactly what the service recorded.
        assert_eq!(
            approval.asked.borrow().as_slice(),
            [("run".to_owned(), claims.action_digest.clone())]
        );
    }
    // Git reads and filesystem operations do not ask; git mutations do.
    let repository = r"C:\work\repo".to_owned();
    for (op, asks) in [
        (
            WorkerOp::GitStatus {
                repository: repository.clone(),
            },
            false,
        ),
        (
            WorkerOp::GitLog {
                repository: repository.clone(),
                max_count: 5,
            },
            false,
        ),
        (read_op(r"C:\work\a.txt"), false),
        (
            WorkerOp::GitAdd {
                repository: repository.clone(),
                paths: vec!["a.txt".to_owned()],
            },
            true,
        ),
        (
            WorkerOp::GitCommit {
                repository: repository.clone(),
                message: "change".to_owned(),
            },
            true,
        ),
        (
            WorkerOp::GitBranchCreate {
                repository: repository.clone(),
                branch: "topic".to_owned(),
            },
            true,
        ),
    ] {
        let before = approval.asked.borrow().len();
        dispatch_worker(
            &port,
            &launched,
            &approval,
            &worker_request(&op),
            None,
            false,
            6,
        )
        .expect("ran");
        assert_eq!(
            approval.asked.borrow().len() - before,
            usize::from(asks),
            "{op:?}"
        );
    }
    assert_eq!(launched.runs.get(), 7);

    // A declined approval authorizes nothing, runs nothing, records nothing.
    let declined = FakeApproval {
        deny: true,
        ..FakeApproval::default()
    };
    let authorized = port.0.borrow().authorized.len();
    let outcomes = port.0.borrow().outcomes.len();
    assert_eq!(
        code(dispatch_worker(
            &port,
            &launched,
            &declined,
            &worker_request(&run),
            None,
            false,
            7
        )),
        Some(FailureCode::ApprovalDenied)
    );
    assert_eq!(declined.asked.borrow().len(), 1);
    assert_eq!(port.0.borrow().authorized.len(), authorized);
    assert_eq!(port.0.borrow().outcomes.len(), outcomes);
    assert_eq!(launched.runs.get(), 7);

    // No lease that covers the action: the person is never asked.
    let narrow = FakePort::installed(vec![lease(
        '2',
        LeaseScope::DesktopFullUser {
            executors: vec![ExecutorClass::Filesystem],
            roots: vec![r"C:\work".to_owned()],
            shells: false,
        },
    )]);
    let unasked = FakeApproval::default();
    assert_eq!(
        code(dispatch_worker(
            &narrow,
            &launcher(&narrow),
            &unasked,
            &worker_request(&run),
            None,
            false,
            8
        )),
        Some(FailureCode::LeaseRequired)
    );
    assert!(unasked.asked.borrow().is_empty());
}

#[test]
fn fc_dispatch_process_and_git_paths_stay_in_the_roots_and_take_no_free_arguments() {
    let port = FakePort::installed(vec![lease('1', full_scope())]);
    let approval = FakeApproval::default();
    for op in [
        run_op(r"C:\Windows\System32\cmd.exe", r"C:\work"),
        run_op(r"C:\work\tool.exe", r"C:\Windows"),
        run_op(r"C:\work\tool.exe", r"C:\workshop"),
        WorkerOp::GitStatus {
            repository: r"C:\other\repo".to_owned(),
        },
    ] {
        assert_eq!(
            code(dispatch_worker(
                &port,
                &launcher(&port),
                &approval,
                &worker_request(&op),
                None,
                false,
                5
            )),
            Some(FailureCode::PathEscape),
            "{op:?}"
        );
    }
    // Relative, stream and dot paths are refused before any lease is chosen.
    for op in [
        run_op("tool.exe", r"C:\work"),
        run_op(r"C:\work\tool.exe:evil", r"C:\work"),
        run_op(r"C:\work\..\Windows\System32\cmd.exe", r"C:\work"),
    ] {
        assert_eq!(
            code(dispatch_worker(
                &port,
                &launcher(&port),
                &approval,
                &worker_request(&op),
                None,
                false,
                5
            )),
            Some(FailureCode::InvalidRequest),
            "{op:?}"
        );
    }
    // Git takes no free argument list and no operation outside the fixed
    // set (fetch, push, config, ...); a run takes no shell, environment or
    // command string: such arguments are not one worker operation.
    for arguments in [
        json!({"op": "git_status", "repository": r"C:\work\repo", "args": ["-c", "core.sshCommand=evil"]}),
        json!({"op": "git_fetch", "repository": r"C:\work\repo", "remote": "--upload-pack=evil"}),
        json!({"op": "git_push", "repository": r"C:\work\repo"}),
        json!({"op": "git_config", "repository": r"C:\work\repo", "key": "core.hooksPath"}),
        json!({"op": "run", "program": r"C:\work\tool.exe", "args": [], "cwd": r"C:\work", "timeout_ms": 5, "max_output_bytes": 5, "shell": true}),
        json!({"op": "run", "program": r"C:\work\tool.exe", "args": [], "cwd": r"C:\work", "timeout_ms": 5, "max_output_bytes": 5, "env": {"GIT_SSH_COMMAND": "evil"}}),
        json!({"op": "run", "command_line": "tool.exe && evil"}),
    ] {
        let mut request = worker_request(&run_op(r"C:\work\tool.exe", r"C:\work"));
        if let Some(name) = arguments["op"].as_str() {
            request.operation = name.to_owned();
        }
        request.arguments = arguments.clone();
        assert_eq!(
            code(dispatch_worker(
                &port,
                &launcher(&port),
                &approval,
                &request,
                None,
                false,
                5
            )),
            Some(FailureCode::InvalidRequest),
            "{arguments}"
        );
    }
    assert!(port.0.borrow().authorized.is_empty());
    assert!(approval.asked.borrow().is_empty());
}

// ---------------------------------------------------------------------
// WP1-14 (SG132_SLICE10.md): standing approvals at the dispatcher.
// ---------------------------------------------------------------------

const REPO: &str = r"C:\work\repo";
const REPO_TOOL: &str = r"C:\work\repo\tool.exe";

fn standing_approval(lease: &LeaseBody) -> StandingApproval {
    StandingApproval {
        contract: orcel_authority::core::standing::STANDING_CONTRACT.to_owned(),
        id: format!("sa-{}", "5".repeat(32)),
        lease_id: lease.lease_id.clone(),
        principal_id: lease.principal_id.clone(),
        task: lease.task.clone(),
        executors: vec![ExecutorClass::ShellProcess],
        operations: vec!["run".to_owned(), "git_commit".to_owned()],
        roots: vec![REPO.to_owned()],
        origins: Vec::new(),
        commands: vec![test_pin(REPO_TOOL)],
        issued_at_ms: 1_000,
        expires_at_ms: 1_000 + 10 * 60_000,
    }
}

/// The request as `fc_requests` names it (`fc.fs`, `fc.process`, `fc.git`):
/// a standing approval covers an operation only under its own capability.
fn fc_request(op: &WorkerOp) -> RequestEnvelope {
    let capability = match op.family() {
        Family::Filesystem => "fc.fs",
        Family::Process => "fc.process",
        Family::Git | Family::DesktopInput => "fc.git",
    };
    request(capability, op.name(), serde_json::to_value(op).expect("op"))
}

fn commit_op(repository: &str) -> WorkerOp {
    WorkerOp::GitCommit {
        repository: repository.to_owned(),
        message: "tidy".to_owned(),
    }
}

/// A port with one lease and one standing approval in effect, as `change`
/// leaves it.
fn standing_port(change: impl FnOnce(&mut StandingApproval)) -> FakePort {
    let body = lease('1', full_scope());
    let mut approval = standing_approval(&body);
    change(&mut approval);
    let port = FakePort::installed(vec![body]);
    port.with(|service| service.standing = vec![approval]);
    port
}

/// One worker operation as the calling client `principal`, local or
/// remote.
fn dispatch_as(
    port: &FakePort,
    approval: &FakeApproval,
    op: &WorkerOp,
    principal: Option<&str>,
    remote: bool,
    now_ms: u64,
) -> Result<Value, ProviderError> {
    dispatch_pinned(port, approval, op, principal, remote, now_ms, &|path| {
        Some(test_pin(path))
    })
}

/// [`dispatch_as`] with `pinner` standing in for reading the program now.
fn dispatch_pinned(
    port: &FakePort,
    approval: &FakeApproval,
    op: &WorkerOp,
    principal: Option<&str>,
    remote: bool,
    now_ms: u64,
    pinner: &dyn Fn(&str) -> Option<PinnedProgram>,
) -> Result<Value, ProviderError> {
    crate::full_control_dispatch::run_in_worker_pinned(
        port,
        &launcher(port),
        approval,
        &fc_request(op),
        principal,
        remote,
        now_ms,
        pinner,
    )
}

/// A program as pinned at grant (a fixed SHA-256 and file identity).
fn test_pin(path: &str) -> PinnedProgram {
    PinnedProgram {
        path: path.to_owned(),
        sha256: "ab".repeat(32),
        identity: "0000000a-0000000000000001".to_owned(),
    }
}

#[test]
fn fc_dispatch_standing_covers_a_run_only_with_its_pinned_contents_and_file() {
    let client = client();
    let run = run_op(REPO_TOOL, REPO);
    let cases: Vec<(&str, Option<PinnedProgram>)> = vec![
        (
            "rewritten since the grant",
            Some(PinnedProgram {
                sha256: "cd".repeat(32),
                ..test_pin(REPO_TOOL)
            }),
        ),
        (
            "replaced by another file",
            Some(PinnedProgram {
                identity: "0000000a-0000000000000002".to_owned(),
                ..test_pin(REPO_TOOL)
            }),
        ),
        ("unreadable now", None),
    ];
    for (name, now) in cases {
        let port = standing_port(|_| {});
        let approval = FakeApproval::default();
        dispatch_pinned(&port, &approval, &run, Some(&client), false, 5, &|_| {
            now.clone()
        })
        .expect(name);
        assert_eq!(approval.asked.borrow().len(), 1, "{name}: asked");
        assert_eq!(last_named(&port), None, "{name}: not covered");
    }
    // Re-review of #844: a program no approval in effect pins is never read
    // or hashed (asked unread), and neither is a remote caller's.
    let read = Cell::new(0u32);
    for (program, remote) in [(r"C:\work\repo\other.exe", false), (REPO_TOOL, true)] {
        let port = standing_port(|_| {});
        let approval = FakeApproval::default();
        dispatch_pinned(
            &port,
            &approval,
            &run_op(program, REPO),
            Some(&client),
            remote,
            5,
            &|path| {
                read.set(read.get() + 1);
                Some(test_pin(path))
            },
        )
        .expect("asked");
        assert_eq!(approval.asked.borrow().len(), 1);
    }
    assert_eq!(read.get(), 0, "nothing was hashed");
    // Covered: the worker is handed the pin to check on the file it holds.
    let port = standing_port(|_| {});
    let launched = launcher(&port);
    crate::full_control_dispatch::run_in_worker_pinned(
        &port,
        &launched,
        &FakeApproval::default(),
        &fc_request(&run),
        Some(&client),
        false,
        5,
        &|path| Some(test_pin(path)),
    )
    .expect("covered");
    assert_eq!(*launched.pinned.borrow(), vec![Some(test_pin(REPO_TOOL))]);
    // A commit is covered without a program, and the worker gets no pin.
    let launched = launcher(&port);
    crate::full_control_dispatch::run_in_worker_pinned(
        &port,
        &launched,
        &FakeApproval::default(),
        &fc_request(&commit_op(REPO)),
        Some(&client),
        false,
        5,
        &|_| None,
    )
    .expect("covered commit");
    assert_eq!(*launched.pinned.borrow(), vec![None]);
}

/// The standing approval the last `Authorize` named.
fn last_named(port: &FakePort) -> Option<StandingClaim> {
    port.0
        .borrow()
        .named_standing
        .last()
        .cloned()
        .unwrap_or_default()
}

#[test]
fn fc_dispatch_standing_covers_a_matching_run_and_commit_without_asking() {
    let port = standing_port(|_| {});
    let approval = FakeApproval::default();
    let client = client();
    let run = run_op(REPO_TOOL, REPO);
    dispatch_as(&port, &approval, &run, Some(&client), false, 5).expect("covered run");
    assert_eq!(
        last_named(&port),
        Some(StandingClaim {
            standing_id: format!("sa-{}", "5".repeat(32)),
            program: Some(test_pin(REPO_TOOL)),
        })
    );
    dispatch_as(&port, &approval, &commit_op(REPO), Some(&client), false, 5)
        .expect("covered commit");
    assert_eq!(
        last_named(&port).map(|claim| claim.program),
        Some(None),
        "a commit names no program"
    );
    assert!(approval.asked.borrow().is_empty(), "nothing was asked");
    // Each covered dispatch still had its own audit-first Authorize.
    assert_eq!(port.0.borrow().authorized.len(), 2);
    // fc.status shows the agent what will not ask.
    let status = crate::fc_requests::status(&port, &client, 5).expect("status");
    assert_eq!(
        status["standing"][0]["operations"],
        json!(["run", "git_commit"])
    );
    assert_eq!(status["standing"][0]["folders"], json!([REPO]));
}

#[test]
fn fc_dispatch_standing_mismatches_ask_as_before() {
    let client = client();
    let other_client = format!("cl-{}", "e".repeat(32));
    let cases: Vec<(&str, FakePort, WorkerOp, u64)> = vec![
        (
            "another program",
            standing_port(|_| {}),
            run_op(r"C:\work\repo\other.exe", REPO),
            5,
        ),
        (
            "a folder outside",
            standing_port(|_| {}),
            run_op(r"C:\work\tool.exe", r"C:\work"),
            5,
        ),
        (
            "an operation not named",
            standing_port(|_| {}),
            WorkerOp::GitAdd {
                repository: REPO.to_owned(),
                paths: vec!["a.txt".to_owned()],
            },
            5,
        ),
        (
            "another client",
            standing_port(|approval| approval.principal_id = other_client.clone()),
            run_op(REPO_TOOL, REPO),
            5,
        ),
        (
            "another task",
            standing_port(|approval| approval.task = "another task".to_owned()),
            run_op(REPO_TOOL, REPO),
            5,
        ),
        (
            "another lease",
            standing_port(|approval| approval.lease_id = format!("al-{}", "9".repeat(32))),
            run_op(REPO_TOOL, REPO),
            5,
        ),
        (
            "expired",
            standing_port(|_| {}),
            run_op(REPO_TOOL, REPO),
            1_000 + 10 * 60_000,
        ),
        (
            "an executor not named",
            standing_port(|approval| approval.executors = vec![ExecutorClass::Filesystem]),
            run_op(REPO_TOOL, REPO),
            5,
        ),
    ];
    for (name, port, op, now) in cases {
        let approval = FakeApproval::default();
        dispatch_as(&port, &approval, &op, Some(&client), false, now).expect(name);
        assert_eq!(approval.asked.borrow().len(), 1, "{name}: asked once");
        assert_eq!(
            last_named(&port),
            None,
            "{name}: no standing approval named"
        );
    }
    // A declined prompt still refuses, standing approvals or not.
    let port = standing_port(|_| {});
    let declining = FakeApproval {
        deny: true,
        ..FakeApproval::default()
    };
    let refused = dispatch_as(
        &port,
        &declining,
        &run_op(r"C:\work\repo\other.exe", REPO),
        Some(&client),
        false,
        5,
    );
    assert_eq!(code(refused), Some(FailureCode::ApprovalDenied));
    assert!(port.0.borrow().authorized.is_empty());
}

#[test]
fn fc_dispatch_standing_never_covers_a_remote_or_unidentified_caller() {
    let port = standing_port(|_| {});
    let approval = FakeApproval::default();
    let client = client();
    let run = run_op(REPO_TOOL, REPO);
    // Remote: asked, whatever matches.
    dispatch_as(&port, &approval, &run, Some(&client), true, 5).expect("asked");
    assert_eq!(approval.asked.borrow().len(), 1);
    assert_eq!(last_named(&port), None);
    // No client named: asked.
    dispatch_as(&port, &approval, &run, None, false, 5).expect("asked");
    assert_eq!(approval.asked.borrow().len(), 2);
    assert_eq!(last_named(&port), None);
    // The rule itself refuses remote callers and operations that never ask.
    let body = lease('1', full_scope());
    let standing = [standing_approval(&body)];
    let request = fc_request(&run);
    assert!(crate::full_control_dispatch::covering_standing(
        &standing,
        &body,
        &run,
        &request,
        Some(&client),
        true,
        Some(&test_pin(REPO_TOOL)),
        5
    )
    .is_none());
    assert!(crate::full_control_dispatch::covering_standing(
        &standing,
        &body,
        &run,
        &request,
        Some(&client),
        false,
        Some(&test_pin(REPO_TOOL)),
        5
    )
    .is_some());
    // A run with no pin (the program could not be read) is never covered.
    assert!(crate::full_control_dispatch::covering_standing(
        &standing,
        &body,
        &run,
        &request,
        Some(&client),
        false,
        None,
        5
    )
    .is_none());
    let write = WorkerOp::WriteText {
        path: r"C:\work\repo\a.txt".to_owned(),
        text: "x".to_owned(),
        create_new: true,
    };
    assert!(crate::full_control_dispatch::covering_standing(
        &standing,
        &body,
        &write,
        &fc_request(&write),
        Some(&client),
        false,
        None,
        5
    )
    .is_none());
    // A lease-covered write asks nothing and names no standing approval.
    dispatch_as(&port, &approval, &write, Some(&client), false, 5).expect("write");
    assert_eq!(approval.asked.borrow().len(), 2);
    assert_eq!(last_named(&port), None);
}

#[test]
fn fc_dispatch_a_refused_or_unconfirmed_standing_authorize_runs_nothing() {
    let client = client();
    // A covered commit (no program to pin).
    let run = commit_op(REPO);
    // The service refuses (no live indicator, revoked meanwhile, ...).
    let port = standing_port(|_| {});
    port.with(|service| service.refuse_standing = Some(FailureCode::IndicatorUnavailable));
    let approval = FakeApproval::default();
    let launched = launcher(&port);
    let refused = dispatch_worker(
        &port,
        &launched,
        &approval,
        &fc_request(&run),
        Some(&client),
        false,
        5,
    );
    assert_eq!(code(refused), Some(FailureCode::IndicatorUnavailable));
    assert_eq!(launched.runs.get(), 0);
    assert!(approval.asked.borrow().is_empty());
    // An answer that does not confirm the named approval runs nothing.
    let port = standing_port(|_| {});
    port.with(|service| {
        service.answer = Some(json!({
            "authorization_id": format!("az-{}", "1".repeat(32)),
            "lease_id": lease('1', full_scope()).lease_id,
            "job_id": format!("fcj-{}", "1".repeat(32)),
            "job_handle": 0x4004,
            "standing_id": null,
        }))
    });
    let launched = launcher(&port);
    let refused = dispatch_worker(
        &port,
        &launched,
        &approval,
        &fc_request(&run),
        Some(&client),
        false,
        5,
    );
    assert_eq!(code(refused), Some(FailureCode::AuthorityUnavailable));
    assert_eq!(launched.runs.get(), 0);
    // An unreachable service lists nothing and refuses.
    let port = standing_port(|_| {});
    port.with(|service| service.unreachable = true);
    assert_eq!(
        code(dispatch_as(&port, &approval, &run, Some(&client), false, 5)),
        Some(FailureCode::AuthorityUnavailable)
    );
}
