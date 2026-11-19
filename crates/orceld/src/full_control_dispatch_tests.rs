//! SG-000132 WP1-10: the Full Control dispatcher against a fake authority
//! service, a fake worker launcher and a fake per-action approval, on every
//! OS, including the WP1-15 process and git families (SG132_SLICE4.md). The
//! real Job Objects and the real `orceld fc-worker` are in
//! `fc_worker_tests.rs` (Windows).

use crate::fc_worker::WorkerOp;
use crate::full_control_dispatch::{
    action_digest, authorize, desktop_gate, ensure_lease_host, run_in_worker as dispatch_worker,
    with_desktop_outcomes, Action, ActionApproval, AuthorityPort, Family, HostLauncher, JobGrant,
    Ticket, WorkerLauncher,
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
    calls: Vec<&'static str>,
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
    request.operation = op.name().to_owned();
    request.arguments = serde_json::to_value(op).expect("op");
    dispatch_worker(
        port,
        launcher,
        &FakeApproval::default(),
        &request,
        principal_id,
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
    let ran = dispatch_worker(&port, &launched, &approval, &worker_request(&run), None, 5)
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
        dispatch_worker(&port, &launched, &approval, &worker_request(&op), None, 6).expect("ran");
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
                5
            )),
            Some(FailureCode::InvalidRequest),
            "{arguments}"
        );
    }
    assert!(port.0.borrow().authorized.is_empty());
    assert!(approval.asked.borrow().is_empty());
}
