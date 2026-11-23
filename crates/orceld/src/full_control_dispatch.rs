//! SG-000132 WP1-10: the Full Control dispatcher, the only path a
//! lease-gated executor (desktop input, filesystem, process, git) takes.
//! The worker operations themselves (filesystem, process, git) are WP1-15's
//! executors (SG-000097, SG-000096).
//!
//! For every dispatch it:
//!
//! 1. names the executor family and the canonical action digest (workspace,
//!    capability, operation, target, arguments, the paths it touches and the
//!    time; the desktop digest is the existing `orcel-desktop-lease-action/2`);
//! 2. finds an active lease of this Windows user and logon session that the
//!    verified service reported and whose ECDSA signature verified with the
//!    service's key, and that covers the family (executor, client principal,
//!    roots for paths); a process run or a git operation that changes the
//!    repository then needs the person's fresh per-action approval
//!    ([`ActionApproval`], SG-000096), bound to the action digest, before
//!    anything is authorized, unless a standing approval (spec 4.15, WP1-14,
//!    SG132_SLICE10.md) the service reports in effect covers it for the
//!    same lease, client and task, inside its operations, folders and
//!    programs ([`covering_standing`]); a remote caller is never covered;
//! 3. asks the service's `Authorize`, which checks lease, epoch, binding,
//!    executor and roots again (and the standing approval, when one is
//!    named) and writes its audit record before it answers; for the filesystem and process/git families the answer must
//!    carry the dispatch's service-made, unnamed Job Object as an
//!    assign-only handle the service duplicated into this process
//!    (`job_id`, `job_handle`), or nothing runs; SG132_SLICE5.md: the handle
//!    is acknowledged (`JobAck`) before it is used;
//! 4. runs the action: desktop input through orceld's computer host as
//!    before (SG-000095's per-action approval unchanged), SG132_SLICE5.md:
//!    in a host inside the lease's service-made Job Object
//!    ([`ensure_lease_host`]); filesystem, process and git operations
//!    only in `orceld fc-worker` inside that Job Object ([`crate::fc_worker`]),
//!    never in this long-lived process. The worker is assigned while
//!    suspended and resumed only after the service confirms the
//!    authorization still stands (`DispatchActive`);
//! 5. reports the outcome (`Outcome`), on which the service terminates the
//!    job.
//!
//! Fail closed: when the service is installed, an unreachable or failing
//! service refuses (`AUTHORITY_UNAVAILABLE`) and the deprecated user-readable
//! store is never consulted. Only desktop input, and only where no service
//! is installed at all, keeps the deprecated store's existing behaviour
//! (slice 2, section 5); the filesystem, process and git families need the
//! service. A revoke, Stop or expiry between `Authorize` and the resume
//! refuses at `DispatchActive` (`LEASE_INVALID`) and the suspended worker is
//! terminated; one during the run kills the worker with its job.
//!
//! Approvals and grants stay with the service's own Windows dialogs and the
//! per-action approval; nothing here approves or grants anything.

use orcel_authority::core::dispatch_jobs::is_job_id;
use orcel_authority::core::standing::{Cover, StandingApproval};
use orcel_authority::lease::{check_dispatch_path, path_within_roots, LeaseBody, LeaseScope};
use orcel_authority::protocol::{AuthorizeClaims, DispatchOutcome, StandingClaim};
use orcel_contracts::{ExecutorClass, FailureCode, RequestEnvelope};
use orcel_provider_fs::ProviderError;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cell::RefCell;

/// The executor families the dispatcher admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    DesktopInput,
    Filesystem,
    Process,
    Git,
}

impl Family {
    /// The lease executor class the family needs. Process and git run
    /// programs, so they need the shell/process executor (granted only with
    /// `shells`); git also names its repository, inside the roots.
    pub(crate) fn executor(self) -> ExecutorClass {
        match self {
            Self::DesktopInput => ExecutorClass::DesktopInput,
            Self::Filesystem => ExecutorClass::Filesystem,
            Self::Process | Self::Git => ExecutorClass::ShellProcess,
        }
    }

    /// Whether the family runs in `orceld fc-worker` inside a service-made
    /// Job Object.
    pub(crate) fn runs_in_job(self) -> bool {
        !matches!(self, Self::DesktopInput)
    }

    /// Whether the family names the paths it touches (checked against the
    /// lease's roots here and by the service): the path of a filesystem
    /// operation, the working folder and program of a run, the repository
    /// of a git operation.
    pub(crate) fn names_paths(self) -> bool {
        matches!(self, Self::Filesystem | Self::Process | Self::Git)
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::DesktopInput => "desktop_input",
            Self::Filesystem => "filesystem",
            Self::Process => "process",
            Self::Git => "git",
        }
    }
}

/// One dispatch as the dispatcher sees it.
pub(crate) struct Action<'a> {
    pub family: Family,
    pub request: &'a RequestEnvelope,
    /// The client the request came from: SG132_SLICE6.md, the calling MCP
    /// client's reference (`client_ref`), which the desktop gate always
    /// names. `None` (a caller that does not know it) names the lease's own
    /// principal. A lease bound to a client admits only that client
    /// (`LeaseBody::admits_client`), here and again at the service.
    pub principal_id: Option<&'a str>,
    /// Absolute paths the action touches (filesystem and git).
    pub paths: Vec<String>,
}

/// What the service's `Authorize` answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Grant {
    pub authorization_id: String,
    pub lease_id: String,
    /// The dispatch's Job Object, for the job families.
    pub job: Option<JobGrant>,
    /// The lease's roots, which `fc-worker` resolves before acting.
    pub roots: Vec<String>,
}

/// A dispatch Job Object as `Authorize` handed it over: its id (for the
/// audit) and the value of the assign-only handle the service duplicated
/// into this process. The launcher owns and closes the handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JobGrant {
    pub id: String,
    pub handle: u64,
}

/// The dispatcher's answer: the deprecated store (desktop input, no service
/// installed) or a service authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ticket {
    DeprecatedStore,
    Service(Grant),
}

/// The authority service as the dispatcher uses it
/// (`authority_link::ServicePort` in production; a fake in tests).
pub(crate) trait AuthorityPort {
    /// Whether the service is installed (registered with the SCM). An SCM
    /// that cannot be asked counts as installed (fail closed).
    fn installed(&self) -> bool;
    /// DEPRECATED: the user-readable store's desktop check, used only for
    /// desktop input and only when no service is installed.
    fn deprecated_desktop_check(&self) -> Result<(), ProviderError>;
    /// The active leases of this user and logon session the verified
    /// service reported, each with a verified signature.
    fn leases(&self) -> Result<Vec<LeaseBody>, ProviderError>;
    /// WP1-14: the standing approvals of this user and logon session the
    /// verified service reports in effect (in force, with a live indicator).
    /// The service checks the one named again at `Authorize`.
    fn standing(&self) -> Result<Vec<StandingApproval>, ProviderError>;
    /// `standing`: WP1-14, the standing approval named in place of the
    /// action's own approval (`None` for every other dispatch).
    fn authorize(
        &self,
        lease_id: &str,
        executor: ExecutorClass,
        claims: AuthorizeClaims,
        standing: Option<&StandingClaim>,
    ) -> Result<Value, ProviderError>;
    fn outcome(
        &self,
        authorization_id: &str,
        outcome: DispatchOutcome,
        code: Option<FailureCode>,
    ) -> Result<(), ProviderError>;
    /// Whether the authorization still stands (lease active, job held);
    /// asked after the worker is assigned and before it is resumed.
    fn dispatch_active(&self, authorization_id: &str) -> Result<(), ProviderError>;
    /// SG132_SLICE5.md: acknowledges the job handle an answer carried,
    /// before it is used. A handle whose acknowledgement fails is neither
    /// used nor closed here: the service closes an unacknowledged handle in
    /// this process itself (after its acknowledgement timeout), and closing
    /// it here too could close a reused handle value.
    fn job_ack(&self, authorization_id: &str, job_handle: u64) -> Result<(), ProviderError>;
    /// SG132_SLICE5.md: a Job Object for the desktop input host under
    /// `lease_id` (`authorization_id`, `lease_id`, `job_id`, `job_handle`).
    fn desktop_host_job(&self, lease_id: &str) -> Result<Value, ProviderError>;
}

/// The person's fresh approval of one worker operation (SG-000096's
/// per-action SOFT approval), asked through orceld's approval broker, whose
/// prompt is a Windows dialog, never an in-app control. SG132_SLICE8.md:
/// the production adapter is `fc_requests::BrokerApproval`, used by the
/// `fc.*` request capabilities; which operations ask is
/// [`crate::fc_worker::WorkerOp::needs_approval`].
pub(crate) trait ActionApproval {
    /// Asks the person to approve `op`, whose digest the service will
    /// record; an error (`APPROVAL_DENIED`, `APPROVAL_UNAVAILABLE`, ...)
    /// refuses it before anything is authorized.
    fn approve(
        &self,
        op: &crate::fc_worker::WorkerOp,
        request: &RequestEnvelope,
        action_digest: &str,
    ) -> Result<(), ProviderError>;
}

/// Runs a worker operation inside a dispatch job (`fc_worker::JobLauncher`
/// on Windows; a fake in tests).
pub(crate) trait WorkerLauncher {
    /// Starts the worker suspended, assigns it with `job.handle` (and closes
    /// that handle on every path), calls `confirm`, and resumes the worker
    /// only if it succeeds (terminating it otherwise).
    fn run(
        &self,
        job: &JobGrant,
        roots: &[String],
        op: &crate::fc_worker::WorkerOp,
        confirm: &dyn Fn() -> Result<(), ProviderError>,
    ) -> Result<Value, ProviderError>;
}

fn unavailable(message: impl Into<String>) -> ProviderError {
    ProviderError::new(FailureCode::AuthorityUnavailable, message)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The SHA-256 the service's audit records for one dispatch. Desktop input
/// keeps slice 2's digest; the other families bind the family and the
/// paths too. Every part is length-prefixed.
pub(crate) fn action_digest(action: &Action<'_>, now_ms: u64) -> String {
    if action.family == Family::DesktopInput {
        return crate::authority_link::desktop_action_digest(action.request, now_ms);
    }
    let request = action.request;
    let mut hasher = Sha256::new();
    let mut parts = vec![
        "orcel-full-control-action/1".to_owned(),
        action.family.as_str().to_owned(),
        request.workspace_id.clone(),
        request.capability.clone(),
        request.operation.clone(),
        request.target.clone().unwrap_or_default(),
        request.arguments.to_string(),
        action.paths.len().to_string(),
    ];
    parts.extend(action.paths.iter().cloned());
    parts.push(now_ms.to_string());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hex(&hasher.finalize())
}

fn request_id_for_audit(request: &RequestEnvelope, now_ms: u64) -> String {
    let id = &request.request_id;
    if !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control) {
        id.clone()
    } else {
        format!("fc-{now_ms}")
    }
}

fn roots_of(body: &LeaseBody) -> Vec<String> {
    match &body.scope {
        LeaseScope::DesktopFullUser { roots, .. } => roots.clone(),
        LeaseScope::BrowserFullAccess { .. } => Vec::new(),
    }
}

/// Steps 1 to 3: the lease and the service's audit-first `Authorize`.
pub(crate) fn authorize(
    port: &dyn AuthorityPort,
    action: &Action<'_>,
    now_ms: u64,
) -> Result<Ticket, ProviderError> {
    authorize_with(port, action, now_ms, &|_, _| Ok(None))
}

/// What runs between the lease check and `Authorize`: given the action
/// digest and the chosen lease, the per-action approval (`Ok(None)`) or the
/// standing approval that stands in for it.
type BeforeAuthorize<'a> =
    dyn Fn(&str, &LeaseBody) -> Result<Option<StandingClaim>, ProviderError> + 'a;

/// [`authorize`], calling `before` with the action digest and the chosen
/// lease once a lease covers the action and before the service is asked:
/// the per-action approval (a refusal there authorizes nothing), or the
/// standing approval that stands in for it, which `Authorize` then names.
fn authorize_with(
    port: &dyn AuthorityPort,
    action: &Action<'_>,
    now_ms: u64,
    before: &BeforeAuthorize<'_>,
) -> Result<Ticket, ProviderError> {
    if !port.installed() {
        return match action.family {
            // DEPRECATED path, unchanged: only where no service exists.
            Family::DesktopInput => port
                .deprecated_desktop_check()
                .map(|()| Ticket::DeprecatedStore),
            _ => Err(unavailable(format!(
                "Full Control {} operations run only through the Orcel authority service, which is not installed",
                action.family.as_str()
            ))),
        };
    }
    if action.family.names_paths() && action.paths.is_empty() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            format!(
                "a Full Control {} operation names the paths it touches",
                action.family.as_str()
            ),
        ));
    }
    for path in &action.paths {
        check_dispatch_path(path).map_err(|error| ProviderError::new(error.code, error.message))?;
    }
    let executor = action.family.executor();
    let mut nearest: Option<ProviderError> = None;
    let mut chosen: Option<LeaseBody> = None;
    for body in port.leases()? {
        if !body.scope.admits(executor) {
            continue;
        }
        if action
            .principal_id
            .is_some_and(|principal| !body.admits_client(executor, principal))
        {
            nearest = Some(ProviderError::new(
                FailureCode::CapabilityDenied,
                "the active Full User lease was granted to another client",
            ));
            continue;
        }
        let roots = roots_of(&body);
        if !action
            .paths
            .iter()
            .all(|path| path_within_roots(path, &roots))
        {
            nearest = Some(ProviderError::new(
                FailureCode::PathEscape,
                "a path lies outside the Full User lease's roots",
            ));
            continue;
        }
        chosen = Some(body);
        break;
    }
    let Some(body) = chosen else {
        return Err(nearest.unwrap_or_else(|| {
            ProviderError::new(
                FailureCode::LeaseRequired,
                format!(
                    "no active Full User lease from the Orcel authority service covers {}; run `orcel full-control grant`",
                    action.family.as_str()
                ),
            )
        }));
    };
    let digest = action_digest(action, now_ms);
    let standing = before(&digest, &body)?;
    let claims = AuthorizeClaims {
        request_id: request_id_for_audit(action.request, now_ms),
        capability: action.request.capability.clone(),
        operation: action.request.operation.clone(),
        principal_id: action
            .principal_id
            .map(str::to_owned)
            .unwrap_or_else(|| body.principal_id.clone()),
        task: body.task.clone(),
        action_digest: digest,
        origin: None,
        paths: (!action.paths.is_empty()).then(|| action.paths.clone()),
    };
    let answer = port.authorize(&body.lease_id, executor, claims, standing.as_ref())?;
    // SG132_SLICE5.md: a job handle that came with an answer refused here
    // is left alone (never acknowledged, used or closed): the service
    // closes it in this process after its acknowledgement timeout.
    let Some(authorization_id) = answer["authorization_id"]
        .as_str()
        .filter(|id| id.starts_with("az-"))
        .map(str::to_owned)
    else {
        return Err(unavailable(
            "the authority's Authorize answer names no authorization",
        ));
    };
    if answer["lease_id"].as_str() != Some(body.lease_id.as_str()) {
        return Err(unavailable(
            "the authority authorized a different lease than the one asked for",
        ));
    }
    // WP1-14: a dispatch admitted in place of its own approval must be
    // admitted under exactly the standing approval named.
    if let Some(claim) = &standing {
        if answer["standing_id"].as_str() != Some(claim.standing_id.as_str()) {
            return Err(unavailable(
                "the authority did not confirm the standing approval this dispatch named",
            ));
        }
    }
    let handle = answer["job_handle"].as_u64().filter(|handle| *handle != 0);
    let job = match (&answer["job_id"], handle, action.family.runs_in_job()) {
        (Value::String(id), Some(handle), true) if is_job_id(id) => Some(JobGrant {
            id: id.clone(),
            handle,
        }),
        (Value::Null, None, false) => None,
        (Value::Null, None, true) => {
            return Err(unavailable(
                "the authority made no Job Object for this dispatch; nothing runs outside one",
            ))
        }
        _ => {
            return Err(unavailable(
                "the authority's job is malformed or unexpected for this family",
            ))
        }
    };
    // SG132_SLICE5.md: acknowledged before anything uses the handle. A
    // refused acknowledgement runs nothing; its outcome is reported, which
    // ends the job (the service also closes the unacknowledged handle).
    if let Some(job) = &job {
        if let Err(error) = port.job_ack(&authorization_id, job.handle) {
            let _ = port.outcome(
                &authorization_id,
                DispatchOutcome::Failed,
                Some(error.code.clone()),
            );
            return Err(error);
        }
    }
    Ok(Ticket::Service(Grant {
        authorization_id,
        lease_id: body.lease_id.clone(),
        job,
        roots: roots_of(&body),
    }))
}

/// Step 5: the outcome, reported to the service (which terminates the
/// dispatch's job). The action already ran, so a failure to report is
/// written to orceld's error output rather than changing the answer; the
/// service's idle reaper and the lease's end close the job regardless.
pub(crate) fn record_outcome<T>(
    port: &dyn AuthorityPort,
    ticket: &Ticket,
    result: &Result<T, ProviderError>,
) {
    let Ticket::Service(grant) = ticket else {
        return;
    };
    let (outcome, code) = match result {
        Ok(_) => (DispatchOutcome::Succeeded, None),
        Err(error) => (DispatchOutcome::Failed, Some(error.code.clone())),
    };
    if let Err(error) = port.outcome(&grant.authorization_id, outcome, code) {
        eprintln!(
            "orceld full control: the outcome of {} was not recorded: {}",
            grant.authorization_id, error.message
        );
    }
}

/// The filesystem, process and git families end to end: the operation is
/// the request's own arguments (so the digest the service records is over
/// exactly what runs), the person's per-action approval where the operation
/// needs one, authorize, run it in `orceld fc-worker` inside the dispatch's
/// Job Object, report the outcome. SG132_SLICE8.md: its request-facing
/// caller is `fc_requests` (`fc.fs`, `fc.process`, `fc.git`), which names
/// the calling client's reference as `principal_id`; the MCP tools are the
/// next slice.
///
/// WP1-14: `remote` is whether the request came from a remote caller
/// (refused before this by `fc_requests::refuse_untrusted`); a remote caller
/// is never covered by a standing approval, whatever else holds.
pub(crate) fn run_in_worker(
    port: &dyn AuthorityPort,
    launcher: &dyn WorkerLauncher,
    approval: &dyn ActionApproval,
    request: &RequestEnvelope,
    principal_id: Option<&str>,
    remote: bool,
    now_ms: u64,
) -> Result<Value, ProviderError> {
    let op: crate::fc_worker::WorkerOp = serde_json::from_value(request.arguments.clone())
        .map_err(|error| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("the arguments are not one Full Control worker operation: {error}"),
            )
        })?;
    if request.operation != op.name() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "the request's operation does not name the worker operation in its arguments",
        ));
    }
    let action = Action {
        family: op.family(),
        request,
        principal_id,
        paths: op.paths(),
    };
    let approve = |digest: &str, body: &LeaseBody| {
        if !op.needs_approval() {
            return Ok(None);
        }
        // WP1-14: a standing approval in effect that covers exactly this
        // operation stands in for the person's per-action approval; the
        // service checks it again. Otherwise the person is asked.
        if !remote {
            let standing = port.standing()?;
            if let Some(covering) =
                covering_standing(&standing, body, &op, request, principal_id, remote, now_ms)
            {
                return Ok(Some(StandingClaim {
                    standing_id: covering.id.clone(),
                    program: run_program(&op).map(str::to_owned),
                }));
            }
        }
        approval.approve(&op, request, digest).map(|()| None)
    };
    let ticket = authorize_with(port, &action, now_ms, &approve)?;
    let Ticket::Service(grant) = &ticket else {
        return Err(unavailable(
            "Full Control worker operations run only through the Orcel authority service",
        ));
    };
    let Some(job) = grant.job.as_ref() else {
        return Err(unavailable(
            "the authority made no Job Object for this dispatch",
        ));
    };
    let confirm = || port.dispatch_active(&grant.authorization_id);
    let result = launcher.run(job, &grant.roots, &op, &confirm);
    record_outcome(port, &ticket, &result);
    result
}

/// The program a process run starts (`None` for every other operation).
fn run_program(op: &crate::fc_worker::WorkerOp) -> Option<&str> {
    match op {
        crate::fc_worker::WorkerOp::Run { program, .. } => Some(program.as_str()),
        _ => None,
    }
}

/// WP1-14 (spec 4.15, SG132_SLICE10.md): the standing approval, among
/// `standing` (those the service reports in effect), that covers `op` under
/// the lease `body` for the calling client `principal_id`: the same lease,
/// client and task, the operation's executor and name, its capability, every
/// path it touches inside the approval's folders, and for a run its program
/// among the approval's programs when it names any. Only operations that
/// otherwise ask a per-action approval are covered; a remote caller, an
/// unidentified client and anything else never are (the person is asked).
/// The rule is `StandingApproval::check_cover`, which the service's
/// `Authorize` applies again.
pub(crate) fn covering_standing<'a>(
    standing: &'a [StandingApproval],
    body: &LeaseBody,
    op: &crate::fc_worker::WorkerOp,
    request: &RequestEnvelope,
    principal_id: Option<&str>,
    remote: bool,
    now_ms: u64,
) -> Option<&'a StandingApproval> {
    if remote || !op.needs_approval() {
        return None;
    }
    let principal = principal_id?;
    let paths = op.paths();
    let cover = Cover {
        lease_id: &body.lease_id,
        principal_id: principal,
        task: &body.task,
        executor: op.family().executor(),
        capability: &request.capability,
        operation: op.name(),
        paths: &paths,
        program: run_program(op),
        origin: None,
        now_ms,
    };
    standing
        .iter()
        .find(|approval| approval.check_cover(&cover).is_ok())
}

thread_local! {
    /// Desktop authorizations of the request this thread is dispatching,
    /// whose outcome is reported when it returns.
    static DESKTOP_GRANTS: RefCell<Vec<Ticket>> = const { RefCell::new(Vec::new()) };
}

/// The desktop input gate (SG-000095's `require_full_user_desktop`): the
/// dispatcher's steps 1 to 3 for desktop input. A service authorization is
/// remembered so [`with_desktop_outcomes`] reports how the request ended,
/// and its lease is returned: SG132_SLICE5.md, the desktop input then runs
/// only in that lease's computer host ([`ensure_lease_host`]). `None`
/// means the deprecated store admitted it (no service installed).
///
/// SG132_SLICE6.md (slice 2 residual): `Authorize` names the calling MCP
/// client, identified the way orceld identifies it for browser leases: the
/// client reference of the request's client session
/// (`orcel_policy::browser_lease::client_ref`), not the lease's own
/// principal; a lease bound to another client refuses (`CAPABILITY_DENIED`).
pub(crate) fn desktop_gate(
    port: &dyn AuthorityPort,
    request: &RequestEnvelope,
    now_ms: u64,
) -> Result<Option<String>, ProviderError> {
    let client = orcel_policy::browser_lease::client_ref(&request.client_session_id);
    let ticket = authorize(
        port,
        &Action {
            family: Family::DesktopInput,
            request,
            principal_id: Some(&client),
            paths: Vec::new(),
        },
        now_ms,
    )?;
    let lease = match &ticket {
        Ticket::Service(grant) => Some(grant.lease_id.clone()),
        Ticket::DeprecatedStore => None,
    };
    if lease.is_some() {
        DESKTOP_GRANTS.with(|grants| grants.borrow_mut().push(ticket));
    }
    Ok(lease)
}

/// How the SG-000036 bounded execution shape (`uia.input/execute`) may run
/// ([`bounded_execution_gate`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BoundedExecution {
    /// DEPRECATED, unchanged: no service is installed, so the action keeps
    /// its SG-000036 single-use input lease and per-action approval only,
    /// through the in-process adapter (which actuates nothing today).
    InProcess,
    /// The service admitted the action under this lease: it runs only in
    /// that lease's computer host, inside the lease's service-made Job
    /// Object, with the host generation checked on every message.
    Leased(String),
}

/// SG132_SLICE7.md (slice 6 residual 5): the gate of the SG-000036 bounded
/// execution shape. With the service installed it is a lease-gated desktop
/// action like every other one (SG-000132: the dispatcher is the only path
/// for lease-gated executors; spec 4.14: desktop input runs in a host in a
/// service-owned Job Object, never in orceld): [`desktop_gate`] (a service
/// lease admitting the calling client, the service's audit-first
/// `Authorize`, the outcome reported), and the action then runs only in the
/// lease's host. Its own SG-000036 input lease and approval stay (a lease
/// alone never replaces an approval). Where no service is installed nothing
/// changes: the deprecated store is not consulted, as it never was for this
/// shape.
///
/// `resolved` is the server-resolved click the person approved (the
/// registry's binding: window, handle, coordinates, the SG-000036 input
/// lease and the approval digest). The request names only a coordinate
/// identity, so the action digest the service records covers `resolved`
/// too ([`bounded_execution_audit_request`]): the audit names the click,
/// not only the identity. The digest is computed here; nothing on the wire
/// changes.
pub(crate) fn bounded_execution_gate(
    port: &dyn AuthorityPort,
    request: &RequestEnvelope,
    resolved: &Value,
    now_ms: u64,
) -> Result<BoundedExecution, ProviderError> {
    if !port.installed() {
        return Ok(BoundedExecution::InProcess);
    }
    let audited = bounded_execution_audit_request(request, resolved);
    match desktop_gate(port, &audited, now_ms)? {
        Some(lease) => Ok(BoundedExecution::Leased(lease)),
        // The deprecated store never admits anything once a service is
        // installed; refuse rather than run in process.
        None => Err(unavailable(
            "bounded desktop execution runs only under an Orcel authority service lease while the service is installed",
        )),
    }
}

/// The request whose action digest the service records for one bounded
/// execution: the caller's request (same client, workspace, capability and
/// operation) with its arguments and the resolved click together.
pub(crate) fn bounded_execution_audit_request(
    request: &RequestEnvelope,
    resolved: &Value,
) -> RequestEnvelope {
    let mut audited = request.clone();
    audited.arguments = serde_json::json!({
        "request": request.arguments,
        "resolved": resolved,
    });
    audited
}

/// SG132_SLICE5.md: starts the desktop input host into a service-made Job
/// Object (`full_control_dispatch::ensure_lease_host`; the computer host on
/// Windows, a fake in tests).
pub(crate) trait HostLauncher {
    /// Whether the host of `generation` (as [`Self::start_in_job`] returned
    /// it) is still the one desktop requests use, and still running.
    fn running(&self, generation: u64) -> bool;
    /// Starts a fresh host suspended, assigns it with `job_handle` (and
    /// closes that handle on every path), calls `confirm`, resumes it only
    /// if that succeeds (terminating it otherwise), and makes it the host
    /// desktop requests use; the host it replaces is ended. Returns the new
    /// host's generation: any later host replacement (an observation
    /// restarting a plain host) moves it.
    fn start_in_job(
        &self,
        job_handle: u64,
        confirm: &dyn Fn() -> Result<(), ProviderError>,
    ) -> Result<u64, ProviderError>;
}

/// The lease whose job the running desktop input host is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LeaseHost {
    pub lease_id: String,
    pub authorization_id: String,
    pub job_id: String,
    /// The host process started into that job ([`HostLauncher`]); a host
    /// of another generation is not this lease's, whatever else holds.
    pub generation: u64,
}

/// SG132_SLICE5.md: makes sure desktop input for `lease_id` runs in a
/// computer host inside that lease's service-made Job Object. A host that
/// is already running in this lease's job is kept (one host per lease, not
/// per dispatch, because the host is long-lived across dispatches); any
/// other case (no host in a job yet, a host in another lease's job, or a
/// host that ended, as it does when the service ends the job on revoke,
/// Stop, lock, sign-out or expiry) asks the service for a fresh job
/// (`DesktopHostJob`), acknowledges its handle, starts a fresh host
/// suspended, assigns it, confirms with `DispatchActive` and resumes it.
/// Every failure refuses the desktop action (fail closed); the host and the
/// state from before are left as they were.
pub(crate) fn ensure_lease_host(
    port: &dyn AuthorityPort,
    launcher: &dyn HostLauncher,
    current: &std::sync::Mutex<Option<LeaseHost>>,
    lease_id: &str,
) -> Result<LeaseHost, ProviderError> {
    let mut current = current
        .lock()
        .map_err(|_| unavailable("the desktop host state is poisoned"))?;
    if let Some(host) = current.as_ref() {
        if host.lease_id == lease_id && launcher.running(host.generation) {
            return Ok(host.clone());
        }
    }
    let answer = port.desktop_host_job(lease_id)?;
    let authorization_id = answer["authorization_id"]
        .as_str()
        .filter(|id| id.starts_with("az-"))
        .map(str::to_owned);
    let job_id = answer["job_id"]
        .as_str()
        .filter(|id| is_job_id(id))
        .map(str::to_owned);
    let handle = answer["job_handle"].as_u64().filter(|handle| *handle != 0);
    let (Some(authorization_id), Some(job_id), Some(handle)) = (authorization_id, job_id, handle)
    else {
        return Err(unavailable(
            "the authority's desktop host job is malformed; the desktop host runs only in one",
        ));
    };
    if answer["lease_id"].as_str() != Some(lease_id) {
        return Err(unavailable(
            "the authority made the desktop host job for a different lease",
        ));
    }
    port.job_ack(&authorization_id, handle)?;
    let generation = launcher.start_in_job(handle, &|| port.dispatch_active(&authorization_id))?;
    let host = LeaseHost {
        lease_id: lease_id.to_owned(),
        authorization_id,
        job_id,
        generation,
    };
    *current = Some(host.clone());
    Ok(host)
}

/// Runs one desktop request and reports the outcome of every desktop
/// authorization it took (step 5). `port` is made only when there is
/// something to report.
pub(crate) fn with_desktop_outcomes<T>(
    port: impl FnOnce() -> Box<dyn AuthorityPort>,
    dispatch: impl FnOnce() -> Result<T, ProviderError>,
) -> Result<T, ProviderError> {
    DESKTOP_GRANTS.with(|grants| grants.borrow_mut().clear());
    let result = dispatch();
    let taken = DESKTOP_GRANTS.with(|grants| std::mem::take(&mut *grants.borrow_mut()));
    if !taken.is_empty() {
        let port = port();
        for ticket in &taken {
            record_outcome(port.as_ref(), ticket, &result);
        }
    }
    result
}
