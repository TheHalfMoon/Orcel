//! SG132_SLICE8.md: the Full Control request capabilities, the request-side
//! caller of the WP1-10 dispatcher's worker path
//! ([`crate::full_control_dispatch::run_in_worker`]).
//!
//! Founder decision of 2026-11-19 (option B of
//! `docs/orcel/implementation-readiness/prep/FC_TOOL_SURFACE_OPTIONS.md`):
//! one local-only tool per worker operation, so the request names exactly
//! one [`WorkerOp`]:
//!
//! - `fc.fs`: `stat`, `list`, `read_text`, `write_text`, `mkdir`;
//! - `fc.process`: `run`;
//! - `fc.git`: `git_status`, `git_diff`, `git_log`, `git_add`,
//!   `git_unstage`, `git_commit`, `git_branch_create`;
//! - `fc.status`: `get`, read-only: the active Full User leases' executors,
//!   roots and expiry, and this client's reference. It grants nothing and
//!   asks the service for no authorization.
//!
//! The request's `operation` is the worker operation's name and its
//! `arguments` are that operation as the worker reads it (`{"op": ...}`),
//! so the action digest the service records, and the person approves where
//! an approval is asked, is over exactly what runs. The principal is the
//! calling MCP client's reference (`client_ref` of the request's client
//! session), as the desktop gate names it since SG132_SLICE6.md.
//!
//! Approvals (the SG-000132 amendment "Full Control file writes covered by
//! the lease, and the fc_* tool surface", 2026-11-19, recording the
//! founder's answers in FC_TOOL_SURFACE_OPTIONS.md section 8): file writes
//! (`write_text`, `mkdir`) are covered by the lease and ask nothing;
//! a program run and the four git changes ask a fresh SOFT approval on
//! every call (SG-000096 A3), through orceld's approval broker, whose prompt
//! is the Windows approval dialog, never an in-app control
//! ([`BrokerApproval`]), unless a standing approval (spec 4.15, WP1-14,
//! SG132_SLICE10.md) granted by the owner through the authority service
//! covers them for this client and task; reads ask nothing. Every worker
//! call, asked or not, still gets the service's audit-first `Authorize`
//! before it runs. `fc.status` also lists this client's standing approvals
//! in effect.
//!
//! Local only: a remote request to any `fc.*` capability is refused before
//! any remote-session lease, policy or dispatch step ([`refuse_untrusted`],
//! called first by orceld's entry), and `fc.` is also a local-only prefix of
//! the remote-session gate (`orcel_policy::remote_session`). Remote Full
//! Control is SG-000105 and is not built.

use crate::fc_worker::WorkerOp;
use crate::full_control_dispatch::{
    run_in_worker, ActionApproval, AuthorityPort, JobGrant, WorkerLauncher,
};
use orcel_approval::{ApprovalBroker, ApprovalDecision, ApprovalPrompt};
use orcel_authority::lease::{executor_name, LeaseScope};
use orcel_contracts::{ExecutorClass, FailureCode, RequestEnvelope, INTERNAL_PROTOCOL_VERSION};
use orcel_policy::POLICY_REVISION;
use orcel_provider_fs::ProviderError;
use serde_json::{json, Value};

/// Every Full Control capability starts with this prefix; orceld's entry
/// routes all of them here, including names this table does not know
/// (refused).
pub(crate) const PREFIX: &str = "fc.";
pub(crate) const FS_CAPABILITY: &str = "fc.fs";
pub(crate) const PROCESS_CAPABILITY: &str = "fc.process";
pub(crate) const GIT_CAPABILITY: &str = "fc.git";
pub(crate) const STATUS_CAPABILITY: &str = "fc.status";

/// The only tool surface that serves the Full Control tools (founder
/// decision 3: the normal local tool list).
pub(crate) const LOCAL_PROFILE: &str = "desktop_structured";

/// Every Full Control request shape (capability, operation): one per
/// worker operation, and the status.
pub(crate) const FC_SHAPES: &[(&str, &str)] = &[
    (FS_CAPABILITY, "stat"),
    (FS_CAPABILITY, "list"),
    (FS_CAPABILITY, "read_text"),
    (FS_CAPABILITY, "write_text"),
    (FS_CAPABILITY, "mkdir"),
    (PROCESS_CAPABILITY, "run"),
    (GIT_CAPABILITY, "git_status"),
    (GIT_CAPABILITY, "git_diff"),
    (GIT_CAPABILITY, "git_log"),
    (GIT_CAPABILITY, "git_add"),
    (GIT_CAPABILITY, "git_unstage"),
    (GIT_CAPABILITY, "git_commit"),
    (GIT_CAPABILITY, "git_branch_create"),
    (STATUS_CAPABILITY, "get"),
];

/// Whether orceld's entry hands the request to this module.
pub(crate) fn is_request(capability: &str) -> bool {
    capability.starts_with(PREFIX)
}

fn denied(message: &str) -> ProviderError {
    ProviderError::new(FailureCode::CapabilityDenied, message)
}

fn invalid(message: &str) -> ProviderError {
    ProviderError::new(FailureCode::InvalidRequest, message)
}

/// Refuses a remote caller and any tool surface other than the local
/// `desktop_structured` one, before anything is read, asked or dispatched.
/// A local caller that names no surface (the owner's own tools) passes; the
/// profile is the sender's claim and grants nothing by itself.
pub(crate) fn refuse_untrusted(remote: bool, profile: Option<&str>) -> Result<(), ProviderError> {
    if remote {
        return Err(denied(
            "Full Control tools (fc.*) are local-only; Remote Full Control (SG-000105) is unavailable",
        ));
    }
    match profile {
        None => Ok(()),
        Some(LOCAL_PROFILE) => Ok(()),
        Some(_) => Err(denied(
            "Full Control tools (fc.*) are served only on the local desktop_structured tool surface",
        )),
    }
}

/// The request's own form: a known shape, the current protocol, no
/// `target` (every path is in the operation), and no arguments for the
/// status.
pub(crate) fn validate(request: &RequestEnvelope) -> Result<(), ProviderError> {
    if request.version != INTERNAL_PROTOCOL_VERSION {
        return Err(invalid("unsupported internal protocol version"));
    }
    let known = FC_SHAPES.iter().any(|(capability, operation)| {
        *capability == request.capability && *operation == request.operation
    });
    if !known {
        return Err(denied(
            "not a Full Control request shape: fc.fs, fc.process and fc.git take their worker operation's name, fc.status takes get",
        ));
    }
    if request.target.is_some() {
        return Err(invalid(
            "Full Control requests do not accept a target field; the paths are in the operation",
        ));
    }
    if request.capability == STATUS_CAPABILITY {
        let empty = match &request.arguments {
            Value::Null => true,
            Value::Object(map) => map.is_empty(),
            _ => false,
        };
        if !empty {
            return Err(invalid("fc.status takes no arguments"));
        }
    }
    Ok(())
}

/// One Full Control request after orceld's entry admitted it (local, the
/// right surface, a configured workspace, the dispatch record written):
/// the status, or the worker operation through the dispatcher with the
/// calling client's reference as the principal. `remote` is the entry's own
/// flag (a remote request was refused before this); the dispatcher never
/// lets a standing approval cover a remote caller.
pub(crate) fn dispatch(
    port: &dyn AuthorityPort,
    launcher: &dyn WorkerLauncher,
    approval: &dyn ActionApproval,
    request: &RequestEnvelope,
    remote: bool,
    now_ms: u64,
) -> Result<Value, ProviderError> {
    validate(request)?;
    let client = orcel_policy::browser_lease::client_ref(&request.client_session_id);
    if request.capability == STATUS_CAPABILITY {
        return status(port, &client, now_ms);
    }
    // The operation's own bounds (the worker's and the Git provider's
    // rules) before anything else, so a malformed request never costs the
    // person a prompt. Arguments that are no operation at all are refused
    // by `run_in_worker` itself.
    if let Ok(op) = serde_json::from_value::<WorkerOp>(request.arguments.clone()) {
        op.check_arguments()?;
    }
    run_in_worker(
        port,
        launcher,
        approval,
        request,
        Some(&client),
        remote,
        now_ms,
    )
}

/// [`dispatch`] against the installed authority service, this orceld's own
/// worker image and orceld's approval broker.
pub(crate) fn dispatch_installed(
    broker: &impl ApprovalBroker,
    request: &RequestEnvelope,
    remote: bool,
) -> Result<Value, ProviderError> {
    let port = crate::authority_link::ServicePort::installed_service();
    let approval = BrokerApproval::new(broker);
    let now_ms = orcel_approval::now_ms();
    if request.capability == STATUS_CAPABILITY {
        return dispatch(&port, &NoWorker, &approval, request, remote, now_ms);
    }
    let launcher = ThisLauncher::this_orceld()?;
    dispatch(&port, &launcher, &approval, request, remote, now_ms)
}

#[cfg(windows)]
type ThisLauncher = crate::fc_worker::JobLauncher;

#[cfg(not(windows))]
type ThisLauncher = NoWorker;

/// A launcher that runs nothing: the status (which never launches), and
/// every build other than Windows, where the authority service, and so a
/// dispatch job, does not exist (the dispatcher refuses before any launch).
pub(crate) struct NoWorker;

impl NoWorker {
    #[cfg_attr(windows, allow(dead_code))]
    fn this_orceld() -> Result<Self, ProviderError> {
        Ok(Self)
    }
}

impl WorkerLauncher for NoWorker {
    fn run(
        &self,
        _job: &JobGrant,
        _roots: &[String],
        _op: &WorkerOp,
        _confirm: &dyn Fn() -> Result<(), ProviderError>,
    ) -> Result<Value, ProviderError> {
        Err(ProviderError::new(
            FailureCode::LeaseUnsupportedPlatform,
            "Full Control worker operations run only in a Windows dispatch job",
        ))
    }
}

/// `fc.status`: what the active Full User leases of this Windows user and
/// logon session cover for this client, for the agent to show the person,
/// and this client's reference, which the person names at grant.
/// Read-only: no `Authorize`, no job, no approval. Only leases this client
/// can use are listed: a lease bound to it, or an unbound lease (one not
/// granted to a client reference), which admits it for desktop input only
/// (`usable_capabilities` then empty). Another client's lease and browser
/// leases are not listed.
pub(crate) fn status(
    port: &dyn AuthorityPort,
    client: &str,
    now_ms: u64,
) -> Result<Value, ProviderError> {
    if !port.installed() {
        return Ok(json!({
            "client_ref": client,
            "authority": "not_installed",
            "leases": [],
            "grants": "nothing",
        }));
    }
    let mut leases = Vec::new();
    for body in port.leases()? {
        let LeaseScope::DesktopFullUser {
            executors,
            roots,
            shells,
        } = &body.scope
        else {
            continue;
        };
        if body.expires_at_ms <= now_ms {
            continue;
        }
        let usable_by_this_client = ExecutorClass::ALL
            .into_iter()
            .any(|executor| body.scope.admits(executor) && body.admits_client(executor, client));
        if !usable_by_this_client {
            continue;
        }
        let usable: Vec<&str> = [
            (FS_CAPABILITY, ExecutorClass::Filesystem),
            (PROCESS_CAPABILITY, ExecutorClass::ShellProcess),
            (GIT_CAPABILITY, ExecutorClass::ShellProcess),
        ]
        .into_iter()
        .filter(|(_, executor)| {
            body.scope.admits(*executor) && body.admits_client(*executor, client)
        })
        .map(|(capability, _)| capability)
        .collect();
        leases.push(json!({
            "lease_id": body.lease_id,
            "executors": executors.iter().map(|executor| executor_name(*executor)).collect::<Vec<_>>(),
            "roots": roots,
            "shells": shells,
            "task": body.task,
            "expires_at_ms": body.expires_at_ms,
            "expires_in_ms": body.expires_at_ms.saturating_sub(now_ms),
            "bound_to_this_client": body.principal_id == client,
            "usable_capabilities": usable,
        }));
    }
    // WP1-14: the standing approvals in effect for this client, so the
    // agent can tell the person which actions will not ask.
    let standing: Vec<Value> = port
        .standing()?
        .into_iter()
        .filter(|approval| approval.principal_id == client && approval.expires_at_ms > now_ms)
        .map(|approval| {
            json!({
                "standing_id": approval.id,
                "lease_id": approval.lease_id,
                "task": approval.task,
                "operations": approval.operations,
                "folders": approval.roots,
                "programs": approval.commands,
                "expires_at_ms": approval.expires_at_ms,
                "expires_in_ms": approval.expires_at_ms.saturating_sub(now_ms),
            })
        })
        .collect();
    Ok(json!({
        "client_ref": client,
        "authority": "installed",
        "leases": leases,
        "standing": standing,
        "grants": "nothing",
    }))
}

/// The production per-action approval (SG132_SLICE4.md section 3, the
/// adapter that slice left for this one): a fresh SOFT approval through
/// orceld's approval broker, whose prompt is the Windows approval dialog
/// (never an in-app control), single-use and bound to the action digest the
/// service then records. Approvals stay with Windows: nothing here
/// approves, and a refused, unanswered or unavailable prompt refuses the
/// action before anything is authorized.
pub(crate) struct BrokerApproval<'a, B: ApprovalBroker> {
    broker: &'a B,
}

impl<'a, B: ApprovalBroker> BrokerApproval<'a, B> {
    pub(crate) fn new(broker: &'a B) -> Self {
        Self { broker }
    }
}

/// JSON text of a value: every argument, path, message and branch the
/// dialog shows is quoted and escaped this way, so an embedded quote,
/// backslash or line break cannot make one argument look like several.
fn json_text<T: serde::Serialize + ?Sized>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "(unprintable)".to_owned())
}

/// What the Windows dialog shows for one worker operation: the action, its
/// target and a summary that starts with the asking client's reference
/// (`client`, as `fc.status` shows it to the agent), then the operation's
/// details: for a run the working folder before the arguments. The dialog
/// bounds long fields; the approval itself is bound to the digest over the
/// whole operation.
pub(crate) fn describe(op: &WorkerOp, client: &str) -> (String, String, String) {
    let asked_by = format!("asked by client {client}");
    match op {
        WorkerOp::Run {
            program,
            args,
            cwd,
            timeout_ms,
            max_output_bytes,
        } => (
            "Full Control: run a program".to_owned(),
            program.clone(),
            format!(
                "{asked_by}; working folder: {}; arguments: {}; stops after {timeout_ms} ms; output up to {max_output_bytes} bytes",
                json_text(cwd),
                json_text(args),
            ),
        ),
        WorkerOp::GitAdd { repository, paths } => (
            "Full Control: stage files in Git".to_owned(),
            repository.clone(),
            format!("{asked_by}; paths: {}", json_text(paths)),
        ),
        WorkerOp::GitUnstage { repository, paths } => (
            "Full Control: unstage files in Git".to_owned(),
            repository.clone(),
            format!("{asked_by}; paths: {}", json_text(paths)),
        ),
        WorkerOp::GitCommit {
            repository,
            message,
        } => (
            "Full Control: commit in Git".to_owned(),
            repository.clone(),
            format!("{asked_by}; message: {}", json_text(message)),
        ),
        WorkerOp::GitBranchCreate { repository, branch } => (
            "Full Control: create a Git branch".to_owned(),
            repository.clone(),
            format!("{asked_by}; branch: {}", json_text(branch)),
        ),
        other => (
            format!("Full Control: {}", other.name()),
            other.paths().join(", "),
            asked_by,
        ),
    }
}

impl<B: ApprovalBroker> ActionApproval for BrokerApproval<'_, B> {
    fn approve(
        &self,
        op: &WorkerOp,
        request: &RequestEnvelope,
        action_digest: &str,
    ) -> Result<(), ProviderError> {
        let client = orcel_policy::browser_lease::client_ref(&request.client_session_id);
        let (action, target, summary) = describe(op, &client);
        // `ApprovalPrompt::new` is SOFT, single-operation and expires on
        // its own; the broker consumes the token against the same digest.
        let prompt = ApprovalPrompt::new(
            request.workspace_id.clone(),
            POLICY_REVISION,
            action,
            target,
            summary,
            action_digest.to_owned(),
        );
        match self.broker.request(&prompt) {
            Ok(ApprovalDecision::Approved) => Ok(()),
            Ok(ApprovalDecision::Denied | ApprovalDecision::Unanswered) => Err(ProviderError::new(
                FailureCode::ApprovalDenied,
                "the person did not approve this Full Control action",
            )),
            Err(error) => Err(ProviderError::new(error.code, error.message)),
        }
    }
}
