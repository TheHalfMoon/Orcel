//! SG-000132 WP1-12: the Full Control dispatcher, the only path a
//! lease-gated executor (desktop input, filesystem, process, git) takes.
//!
//! For every dispatch it:
//!
//! 1. names the executor family and the canonical action digest (workspace,
//!    capability, operation, target, arguments, the paths it touches and the
//!    time; the desktop digest is the existing `orcel-desktop-lease-action/2`);
//! 2. finds an active lease of this Windows user and logon session that the
//!    verified service reported and whose ECDSA signature verified with the
//!    service's key, and that covers the family (executor, client principal,
//!    roots for paths);
//! 3. asks the service's `Authorize`, which checks lease, epoch, binding,
//!    executor and roots again and writes its audit record before it
//!    answers; for the filesystem and process/git families the answer must
//!    name the dispatch's service-made Job Object (`job_name`), or nothing
//!    runs;
//! 4. runs the action: desktop input in orceld as before (SG-000095's
//!    per-action approval unchanged); filesystem, process and git operations
//!    only in `orceld fc-worker` inside that Job Object ([`crate::fc_worker`]),
//!    never in this long-lived process;
//! 5. reports the outcome (`Outcome`), on which the service terminates the
//!    job.
//!
//! Fail closed: when the service is installed, an unreachable or failing
//! service refuses (`AUTHORITY_UNAVAILABLE`) and the deprecated user-readable
//! store is never consulted. Only desktop input, and only where no service
//! is installed at all, keeps the deprecated store's existing behaviour
//! (slice 2, section 5); the filesystem, process and git families need the
//! service. A revoke, Stop or expiry between `Authorize` and the launch
//! ends the job, so the launch refuses (`LEASE_INVALID`); one during the
//! run kills the worker.
//!
//! Approvals and grants stay with the service's own Windows dialogs and the
//! per-action approval; nothing here approves or grants anything.

use orcel_authority::core::dispatch_jobs::is_job_name;
use orcel_authority::lease::{check_dispatch_path, path_within_roots, LeaseBody, LeaseScope};
use orcel_authority::protocol::{AuthorizeClaims, DispatchOutcome};
use orcel_contracts::{ExecutorClass, FailureCode, RequestEnvelope};
use orcel_provider_fs::ProviderError;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cell::RefCell;

/// The executor families the dispatcher admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    DesktopInput,
    #[cfg_attr(not(test), allow(dead_code))]
    Filesystem,
    #[cfg_attr(not(test), allow(dead_code))]
    Process,
    #[cfg_attr(not(test), allow(dead_code))]
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
    /// lease's roots here and by the service).
    pub(crate) fn names_paths(self) -> bool {
        matches!(self, Self::Filesystem | Self::Git)
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
    /// The client the request came from, when the caller knows it. The
    /// desktop gate does not (slice 2 residual): the lease's own principal
    /// is named then.
    pub principal_id: Option<&'a str>,
    /// Absolute paths the action touches (filesystem and git).
    pub paths: Vec<String>,
}

/// What the service's `Authorize` answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Grant {
    pub authorization_id: String,
    pub lease_id: String,
    pub job_name: Option<String>,
    /// The lease's roots, which `fc-worker` resolves before acting.
    pub roots: Vec<String>,
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
    fn authorize(
        &self,
        lease_id: &str,
        executor: ExecutorClass,
        claims: AuthorizeClaims,
    ) -> Result<Value, ProviderError>;
    fn outcome(
        &self,
        authorization_id: &str,
        outcome: DispatchOutcome,
        code: Option<FailureCode>,
    ) -> Result<(), ProviderError>;
    /// Whether the jobs come from the installed service, so this session
    /// must be unable to terminate them (false for the console harness).
    fn jobs_are_service_owned(&self) -> bool;
}

/// Runs a worker operation inside a dispatch job (`fc_worker::JobLauncher`
/// on Windows; a fake in tests).
pub(crate) trait WorkerLauncher {
    fn run(
        &self,
        job_name: &str,
        roots: &[String],
        op: &crate::fc_worker::WorkerOp,
        service_owned: bool,
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
            .is_some_and(|principal| principal != body.principal_id)
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
    let claims = AuthorizeClaims {
        request_id: request_id_for_audit(action.request, now_ms),
        capability: action.request.capability.clone(),
        operation: action.request.operation.clone(),
        principal_id: action
            .principal_id
            .map(str::to_owned)
            .unwrap_or_else(|| body.principal_id.clone()),
        task: body.task.clone(),
        action_digest: action_digest(action, now_ms),
        origin: None,
        paths: (!action.paths.is_empty()).then(|| action.paths.clone()),
    };
    let answer = port.authorize(&body.lease_id, executor, claims)?;
    let authorization_id = answer["authorization_id"]
        .as_str()
        .filter(|id| id.starts_with("az-"))
        .ok_or_else(|| unavailable("the authority's Authorize answer names no authorization"))?
        .to_owned();
    if answer["lease_id"].as_str() != Some(body.lease_id.as_str()) {
        return Err(unavailable(
            "the authority authorized a different lease than the one asked for",
        ));
    }
    let job_name = match (&answer["job_name"], action.family.runs_in_job()) {
        (Value::String(name), true) if is_job_name(name) => Some(name.clone()),
        (Value::Null, false) => None,
        (Value::Null, true) => {
            return Err(unavailable(
                "the authority made no Job Object for this dispatch; nothing runs outside one",
            ))
        }
        _ => {
            return Err(unavailable(
                "the authority's job_name is malformed or unexpected for this family",
            ))
        }
    };
    Ok(Ticket::Service(Grant {
        authorization_id,
        lease_id: body.lease_id.clone(),
        job_name,
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

/// The filesystem, process and git families end to end: authorize, run the
/// operation in `orceld fc-worker` inside the dispatch's Job Object, report
/// the outcome. Its request-facing caller (SG-000097's filesystem, process
/// and git capabilities) is a later WP1-12 step.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn run_in_worker(
    port: &dyn AuthorityPort,
    launcher: &dyn WorkerLauncher,
    request: &RequestEnvelope,
    principal_id: Option<&str>,
    op: &crate::fc_worker::WorkerOp,
    now_ms: u64,
) -> Result<Value, ProviderError> {
    let action = Action {
        family: op.family(),
        request,
        principal_id,
        paths: op.paths(),
    };
    let ticket = authorize(port, &action, now_ms)?;
    let Ticket::Service(grant) = &ticket else {
        return Err(unavailable(
            "Full Control worker operations run only through the Orcel authority service",
        ));
    };
    let Some(job_name) = grant.job_name.as_deref() else {
        return Err(unavailable(
            "the authority made no Job Object for this dispatch",
        ));
    };
    let result = launcher.run(job_name, &grant.roots, op, port.jobs_are_service_owned());
    record_outcome(port, &ticket, &result);
    result
}

thread_local! {
    /// Desktop authorizations of the request this thread is dispatching,
    /// whose outcome is reported when it returns.
    static DESKTOP_GRANTS: RefCell<Vec<Ticket>> = const { RefCell::new(Vec::new()) };
}

/// The desktop input gate (SG-000095's `require_full_user_desktop`): the
/// dispatcher's steps 1 to 3 for desktop input. A service authorization is
/// remembered so [`with_desktop_outcomes`] reports how the request ended.
pub(crate) fn desktop_gate(
    port: &dyn AuthorityPort,
    request: &RequestEnvelope,
    now_ms: u64,
) -> Result<(), ProviderError> {
    let ticket = authorize(
        port,
        &Action {
            family: Family::DesktopInput,
            request,
            principal_id: None,
            paths: Vec::new(),
        },
        now_ms,
    )?;
    if matches!(ticket, Ticket::Service(_)) {
        DESKTOP_GRANTS.with(|grants| grants.borrow_mut().push(ticket));
    }
    Ok(())
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
