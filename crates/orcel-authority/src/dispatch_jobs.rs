//! WP1-10 (SG-000132): the Job Object of each Full Control dispatch.
//!
//! For the filesystem and shell/process executors (filesystem, process and
//! git operations), `Authorize` creates a fresh UNNAMED Job Object for that
//! one dispatch before it writes the allow record, keeps its full-access
//! handle, and duplicates one handle with only `JOB_OBJECT_ASSIGN_PROCESS`
//! into the verified orceld process; the answer carries that handle value
//! (`job_handle`) and the job's id (`job_id`, for the audit). orceld starts
//! `orceld fc-worker` suspended, assigns it with that handle, closes the
//! handle, asks `DispatchActive` whether the authorization still stands, and
//! only then resumes it (otherwise it terminates the worker). The job is
//! kill-on-close with no breakaway limit, so nothing the worker starts can
//! leave it, and carries UI restrictions (`win::jobs::JOB_UI_LIMITS`, WP1-15)
//! that close window-message, DDE, desktop and clipboard routes out of it.
//!
//! No names: review of `291e045e` showed a standard user can create
//! `Global\` objects and hold a named job open past its end, so a name could
//! be squatted or a revoked job reused. An unnamed job can be reached only
//! through a handle.
//!
//! Decision: one job per dispatch, not per lease. A dispatch's processes end
//! with its outcome (`Outcome` terminates the job), and one dispatch cannot
//! add processes to another's job. The service ends a lease's jobs whenever
//! the lease stops being active: revoke, Stop, session lock, sign-out,
//! disconnect, expiry, an epoch move, re-enrollment and reset. Jobs whose
//! processes all exited are closed after [`JOB_IDLE_MS`], and every job is
//! terminated [`JOB_MAX_MS`] after it was made whatever it holds; a lease
//! holds at most [`MAX_JOBS_PER_LEASE`] jobs and the service [`MAX_JOBS`].
//!
//! The service holds jobs in memory only: a restarted service holds no
//! handle, so kill-on-close has ended whatever ran in them once orceld
//! closed its own handle (it does right after assigning its worker).
//!
//! SG132_SLICE5.md adds two things:
//!
//! - **Handle acknowledgement.** orceld acknowledges each duplicated handle
//!   (`JobAck`: the authorization id and the handle value) before it uses
//!   it. The service accepts that only from the user, logon session and
//!   orceld instance (PID and creation time) the handle went to, and only
//!   with the value it duplicated. A job that `DispatchActive` has not
//!   confirmed within [`JOB_ACK_TIMEOUT_MS`] of its creation is ended; when
//!   it was never acknowledged, the service also closes the handle it
//!   duplicated into orceld (orceld never uses or closes a handle it could
//!   not acknowledge), so a lost `Authorize` reply no longer leaks a
//!   handle. The timeout never touches a confirmed job.
//! - **The desktop input host's job.** `DesktopHostJob` makes one job per
//!   desktop Full User lease for orceld's computer host
//!   ([`JobProfile::DesktopHost`]): lease lifetime rather than per dispatch,
//!   no age limit, ended with the lease (revoke, Stop, lock, sign-out,
//!   expiry, epoch move), and replaced when orceld asks again for the same
//!   lease. Its UI restrictions leave out the two that would break desktop
//!   input on the user's desktop (`win::jobs::DESKTOP_HOST_UI_LIMITS`).

use super::{observed, AuthorityCore};
use crate::caller::{CallerFacts, CallerRole};
use crate::error::AuthorityError;
use crate::lease::{check_dispatch_path, path_within_roots, LeaseScope, MAX_DISPATCH_PATHS};
use crate::protocol::DispatchOutcome;
use crate::{hex, unhex};
use orcel_contracts::{ExecutorClass, FailureCode};
use serde_json::{json, Value};

/// Jobs one lease may hold at once.
pub const MAX_JOBS_PER_LEASE: usize = 16;
/// Jobs the service holds at once.
pub const MAX_JOBS: usize = 128;
/// A job whose processes all exited is closed this long after it was made.
pub const JOB_IDLE_MS: u64 = 60_000;
/// Every job is terminated this long after it was made, busy or not (a
/// worker operation is bounded at 60 s; process and git families that need
/// longer arrive with SG-000134's long-running jobs).
pub const JOB_MAX_MS: u64 = 10 * 60_000;
/// Authorizations whose outcome is still expected (the oldest is dropped).
pub const MAX_OPEN_DISPATCHES: usize = 256;
/// Every dispatch job id starts with this, then 32 lowercase hex.
pub const JOB_ID_PREFIX: &str = "fcj-";
/// SG132_SLICE5.md: a job that `DispatchActive` has not confirmed this long
/// after it was made is ended (and, if orceld never acknowledged its handle,
/// that handle is closed in orceld). orceld acknowledges, starts its process
/// suspended, assigns it and asks `DispatchActive` within milliseconds; the
/// per-frame pipe timeout is 10 s.
pub const JOB_ACK_TIMEOUT_MS: u64 = 15_000;

/// What a job is for, which sets its limits and lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobProfile {
    /// One filesystem, process or git dispatch (`orceld fc-worker`): every
    /// UI restriction, terminated at [`JOB_MAX_MS`] or with its outcome.
    Dispatch,
    /// The desktop input host of one lease (`apps/orcel-computer-host`):
    /// the UI restrictions that leave desktop input working, no age limit,
    /// ended with the lease.
    DesktopHost,
}

/// A dispatch job as `Authorize` hands it to orceld: its id and the value of
/// the assign-only handle the service duplicated into the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchJob {
    pub id: String,
    pub handle: u64,
}

/// Creates, terminates and inspects the dispatch Job Objects. The Windows
/// implementation is `win::jobs::ServiceJobs`.
pub trait JobHost: Send {
    /// Creates an unnamed, kill-on-close, no-breakaway job `id` with the
    /// limits of `profile` and duplicates an assign-only, non-inheritable
    /// handle to it into the caller's process (the observed pipe client).
    fn create(
        &mut self,
        id: &str,
        caller: &CallerFacts,
        profile: JobProfile,
    ) -> Result<DispatchJob, AuthorityError>;
    /// Terminates every process in the job and closes the service's handle.
    fn terminate(&mut self, id: &str);
    /// As [`JobHost::terminate`], and also closes the handle duplicated into
    /// the caller: only for a job whose answer was never sent.
    fn withdraw(&mut self, id: &str);
    /// How many processes the job holds now, when that can be read.
    fn active_processes(&self, id: &str) -> Option<u32>;
}

/// Whether `text` is a dispatch job id as the service makes them.
pub fn is_job_id(text: &str) -> bool {
    text.strip_prefix(JOB_ID_PREFIX).is_some_and(|random| {
        random.len() == 32
            && random
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Whether a dispatch of `executor` runs in a service-made Job Object.
pub fn executor_runs_in_job(executor: ExecutorClass) -> bool {
    matches!(
        executor,
        ExecutorClass::Filesystem | ExecutorClass::ShellProcess
    )
}

/// A dispatch job the service holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldJob {
    id: String,
    lease_id: String,
    created_ms: u64,
    profile: JobProfile,
    /// The authorization the job was made for (the `DesktopHostJob`
    /// answer's own id for a desktop host job).
    authorization_id: String,
    /// Who the handle went to: user, logon session and process instance.
    user_sid: String,
    logon_session_id: u64,
    pid: u32,
    process_generation: u64,
    /// The handle's value in that process.
    handle: u64,
    /// orceld acknowledged the handle (`JobAck`).
    acknowledged: bool,
    /// `DispatchActive` confirmed it; the acknowledgement timeout no longer
    /// applies.
    confirmed: bool,
}

impl HeldJob {
    fn owned_by(&self, caller: &CallerFacts) -> bool {
        self.user_sid == caller.user_sid
            && self.logon_session_id == caller.logon_session_id
            && self.pid == caller.pid
            && self.process_generation != 0
            && self.process_generation == caller.process_generation
    }
}

/// An authorization whose outcome orceld has not reported yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpenDispatch {
    authorization_id: String,
    user_sid: String,
    logon_session_id: u64,
    lease_id: String,
    job_id: Option<String>,
}

fn is_authorization_id(text: &str) -> bool {
    text.strip_prefix("az-")
        .is_some_and(|rest| rest.len() == 32 && unhex(rest).is_some())
}

impl AuthorityCore {
    /// The paths a dispatch names lie inside the lease's roots; a
    /// filesystem dispatch names at least one.
    pub(super) fn check_dispatch_paths(
        scope: &LeaseScope,
        executor: ExecutorClass,
        paths: Option<&[String]>,
    ) -> Result<(), AuthorityError> {
        let paths = paths.unwrap_or_default();
        if executor == ExecutorClass::Filesystem && paths.is_empty() {
            return Err(AuthorityError::invalid(
                "a filesystem dispatch names the paths it touches",
            ));
        }
        if paths.is_empty() {
            return Ok(());
        }
        if paths.len() > MAX_DISPATCH_PATHS {
            return Err(AuthorityError::invalid("a dispatch names at most 8 paths"));
        }
        let LeaseScope::DesktopFullUser { roots, .. } = scope else {
            return Err(AuthorityError::denied(
                "only a desktop Full User lease with roots covers paths",
            ));
        };
        for path in paths {
            check_dispatch_path(path)?;
            if !path_within_roots(path, roots) {
                return Err(AuthorityError::denied(
                    "a dispatch path lies outside the lease's roots",
                ));
            }
        }
        Ok(())
    }

    /// Creates the dispatch's Job Object for the filesystem and
    /// shell/process executors (none for the others).
    pub(super) fn create_dispatch_job(
        &mut self,
        caller: &CallerFacts,
        executor: ExecutorClass,
        lease_id: &str,
        authorization_id: &str,
    ) -> Result<Option<DispatchJob>, AuthorityError> {
        if !executor_runs_in_job(executor) {
            return Ok(None);
        }
        let now = self.now();
        self.reap_idle_jobs(now);
        let held = self
            .jobs
            .iter()
            .filter(|job| job.lease_id == lease_id)
            .count();
        if held >= MAX_JOBS_PER_LEASE || self.jobs.len() >= MAX_JOBS {
            return Err(AuthorityError::denied(
                "too many dispatch Job Objects are held; earlier dispatches must report their outcome",
            ));
        }
        self.make_job(caller, lease_id, authorization_id, JobProfile::Dispatch)
            .map(Some)
    }

    /// Makes one job of `profile` for `authorization_id` and holds it.
    fn make_job(
        &mut self,
        caller: &CallerFacts,
        lease_id: &str,
        authorization_id: &str,
        profile: JobProfile,
    ) -> Result<DispatchJob, AuthorityError> {
        let now = self.now();
        let id = format!("{JOB_ID_PREFIX}{}", hex(&self.random(16)?));
        let job = self
            .services
            .jobs
            .create(&id, caller, profile)
            .map_err(|error| {
                AuthorityError::unavailable(format!(
                    "the Job Object for {authorization_id} could not be created: {}",
                    error.message
                ))
            })?;
        self.jobs.push(HeldJob {
            id,
            lease_id: lease_id.to_owned(),
            created_ms: now,
            profile,
            authorization_id: authorization_id.to_owned(),
            user_sid: caller.user_sid.clone(),
            logon_session_id: caller.logon_session_id,
            pid: caller.pid,
            process_generation: caller.process_generation,
            handle: job.handle,
            acknowledged: false,
            confirmed: false,
        });
        Ok(job)
    }

    /// Terminates and forgets one held job. A job whose handle orceld never
    /// acknowledged is withdrawn instead: orceld never uses or closes a
    /// handle it could not acknowledge, so the service closes it there.
    pub(super) fn end_job(&mut self, id: &str) {
        if let Some(index) = self.jobs.iter().position(|job| job.id == id) {
            let job = self.jobs.remove(index);
            if job.acknowledged {
                self.services.jobs.terminate(id);
            } else {
                self.services.jobs.withdraw(id);
            }
        }
    }

    /// Terminates a job whose answer was never sent, closing the handle the
    /// service duplicated into the caller too.
    pub(super) fn withdraw_job(&mut self, id: &str) {
        if let Some(index) = self.jobs.iter().position(|job| job.id == id) {
            self.jobs.remove(index);
            self.services.jobs.withdraw(id);
        }
    }

    /// Remembers an authorization until its outcome arrives.
    pub(super) fn open_dispatch(
        &mut self,
        caller: &CallerFacts,
        authorization_id: &str,
        lease_id: &str,
        job_id: Option<&str>,
    ) {
        while self.open_dispatches.len() >= MAX_OPEN_DISPATCHES {
            // An evicted dispatch can no longer be confirmed or reported, so
            // its job ends with it.
            if let Some(evicted) = self.open_dispatches.pop_front() {
                if let Some(id) = &evicted.job_id {
                    self.end_job(id);
                }
            }
        }
        self.open_dispatches.push_back(OpenDispatch {
            authorization_id: authorization_id.to_owned(),
            user_sid: caller.user_sid.clone(),
            logon_session_id: caller.logon_session_id,
            lease_id: lease_id.to_owned(),
            job_id: job_id.map(str::to_owned),
        });
    }

    fn lease_active(&self, lease_id: &str, now: u64) -> bool {
        self.state.leases.iter().any(|record| {
            record.lease.body.lease_id == lease_id && self.effective_state(record, now) == "active"
        })
    }

    /// Ends every held job whose lease is no longer active (revoked,
    /// stopped, expired, from an older epoch, or gone). Their open
    /// dispatches stay, so the outcome is still recorded.
    pub(super) fn sweep_jobs(&mut self) {
        let now = self.now();
        let dead: Vec<String> = self
            .jobs
            .iter()
            .filter(|job| !self.lease_active(&job.lease_id, now))
            .map(|job| job.id.clone())
            .collect();
        for id in dead {
            self.end_job(&id);
        }
    }

    /// Closes jobs older than [`JOB_IDLE_MS`] whose processes all exited,
    /// terminates every dispatch job older than [`JOB_MAX_MS`] (a desktop
    /// host job lives with its lease instead), and ends every job that
    /// `DispatchActive` did not confirm within [`JOB_ACK_TIMEOUT_MS`].
    pub(super) fn reap_idle_jobs(&mut self, now: u64) {
        let stale: Vec<String> = self
            .jobs
            .iter()
            .filter(|job| {
                let age = now.saturating_sub(job.created_ms);
                (age >= JOB_MAX_MS && job.profile == JobProfile::Dispatch)
                    || (age >= JOB_ACK_TIMEOUT_MS && !job.confirmed)
                    || (age >= JOB_IDLE_MS
                        && self.services.jobs.active_processes(&job.id) == Some(0))
            })
            .map(|job| job.id.clone())
            .collect();
        for id in stale {
            self.end_job(&id);
        }
    }

    /// What `Status` reports about the dispatch jobs.
    pub(super) fn job_status(&self) -> Value {
        json!({
            "named": false,
            "held": self.jobs.len(),
            "per_dispatch": true,
            "per_lease_limit": MAX_JOBS_PER_LEASE,
            "max_age_ms": JOB_MAX_MS,
            "kill_on_close": true,
            "breakaway": false,
            "ui_restrictions": [
                "handles",
                "global_atoms",
                "desktop",
                "exit_windows",
                "system_parameters",
                "display_settings",
                "read_clipboard",
                "write_clipboard",
            ],
            "client_access": "JOB_OBJECT_ASSIGN_PROCESS (duplicated handle)",
            "acknowledgement": {
                "required": true,
                "timeout_ms": JOB_ACK_TIMEOUT_MS,
                "binds": [
                    "authorization_id",
                    "job_handle",
                    "user",
                    "logon_session",
                    "pid",
                    "process_creation_time",
                ],
            },
            "desktop_host": {
                "per_lease": true,
                "lifetime": "lease",
                "held": self
                    .jobs
                    .iter()
                    .filter(|job| job.profile == JobProfile::DesktopHost)
                    .count(),
                "ui_restrictions": [
                    "desktop",
                    "exit_windows",
                    "system_parameters",
                    "display_settings",
                    "read_clipboard",
                    "write_clipboard",
                ],
            },
        })
    }

    /// The held job of `authorization_id`, which must be the caller's: the
    /// orceld role, and the user, logon session and process instance its
    /// handle went to.
    fn held_job_of(
        &self,
        caller: &CallerFacts,
        role: CallerRole,
        authorization_id: &str,
    ) -> Result<usize, AuthorityError> {
        if role != CallerRole::Orceld {
            return Err(AuthorityError::denied(
                "only orceld (a configured trusted image) uses dispatch Job Objects",
            ));
        }
        if !is_authorization_id(authorization_id) {
            return Err(AuthorityError::invalid(
                "authorization_id is az- and 32 lowercase hex characters",
            ));
        }
        let index = self
            .jobs
            .iter()
            .position(|job| job.authorization_id == authorization_id)
            .ok_or_else(|| {
                AuthorityError::lease_invalid(
                    "no Job Object is held for that authorization (ended, withdrawn after the acknowledgement timeout, or never made)",
                )
            })?;
        if !self.jobs[index].owned_by(caller) {
            return Err(AuthorityError::denied(
                "the job's handle went to another user, logon session or orceld instance",
            ));
        }
        Ok(index)
    }

    /// SG132_SLICE5.md: orceld acknowledges the handle the service
    /// duplicated into it, naming the authorization and the handle's value,
    /// before it uses it. Only the process instance the handle went to, in
    /// the same user and logon session, with the exact value; once.
    pub(super) fn job_ack(
        &mut self,
        caller: &CallerFacts,
        role: CallerRole,
        authorization_id: &str,
        job_handle: u64,
    ) -> Result<Value, AuthorityError> {
        let index = self.held_job_of(caller, role, authorization_id)?;
        let job = &mut self.jobs[index];
        if job.handle != job_handle {
            return Err(AuthorityError::denied(
                "that is not the handle the service duplicated for this authorization",
            ));
        }
        if job.acknowledged {
            return Err(AuthorityError::invalid(
                "the job's handle was acknowledged already",
            ));
        }
        job.acknowledged = true;
        Ok(json!({
            "authorization_id": authorization_id,
            "job_id": job.id,
            "acknowledged": true,
        }))
    }

    /// Confirms the acknowledged job of `authorization_id` (the caller's)
    /// while its lease is active; afterwards the acknowledgement timeout no
    /// longer applies to it.
    fn confirm_job(
        &mut self,
        caller: &CallerFacts,
        role: CallerRole,
        authorization_id: &str,
        now: u64,
    ) -> Result<(), AuthorityError> {
        let index = self
            .held_job_of(caller, role, authorization_id)
            .map_err(|error| {
                if error.code == FailureCode::LeaseInvalid {
                    AuthorityError::lease_invalid(
                        "the dispatch's lease ended or its Job Object was terminated",
                    )
                } else {
                    error
                }
            })?;
        if !self.jobs[index].acknowledged {
            return Err(AuthorityError::invalid(
                "the job's handle was not acknowledged (JobAck comes first)",
            ));
        }
        if !self.lease_active(&self.jobs[index].lease_id, now) {
            return Err(AuthorityError::lease_invalid(
                "the dispatch's lease ended or its Job Object was terminated",
            ));
        }
        self.jobs[index].confirmed = true;
        Ok(())
    }

    /// SG132_SLICE5.md: a Job Object for orceld's desktop input host under
    /// `lease_id` (an active desktop Full User lease of the caller that
    /// covers desktop input). One per lease: asking again ends the earlier
    /// one first (orceld starts a fresh host). The record is written before
    /// the answer, like an allow record; a job that cannot be made, or a
    /// record that cannot be written, refuses.
    pub(super) fn desktop_host_job(
        &mut self,
        caller: &CallerFacts,
        role: CallerRole,
        lease_id: &str,
    ) -> Result<Value, AuthorityError> {
        if role != CallerRole::Orceld {
            return Err(AuthorityError::denied(
                "only orceld (a configured trusted image) asks for the desktop host's Job Object",
            ));
        }
        let now = self.now();
        let index = self.active_lease(caller, lease_id, now)?;
        let scope = self.state.leases[index].lease.body.scope.clone();
        if !matches!(scope, LeaseScope::DesktopFullUser { .. })
            || !scope.admits(ExecutorClass::DesktopInput)
        {
            return Err(AuthorityError::denied(
                "the lease does not cover the desktop_input executor",
            ));
        }
        let earlier: Vec<String> = self
            .jobs
            .iter()
            .filter(|job| job.profile == JobProfile::DesktopHost && job.lease_id == lease_id)
            .map(|job| job.id.clone())
            .collect();
        for id in earlier {
            self.end_job(&id);
        }
        self.reap_idle_jobs(now);
        if self.jobs.len() >= MAX_JOBS {
            return Err(AuthorityError::denied(
                "too many Job Objects are held; earlier dispatches must report their outcome",
            ));
        }
        let authorization_id = format!("az-{}", hex(&self.random(16)?));
        let job = self.make_job(caller, lease_id, &authorization_id, JobProfile::DesktopHost)?;
        let recorded = self.audit(
            "desktop_host_job",
            json!({ "lease_id": lease_id }),
            observed(caller, role),
            json!({
                "decision": "allow",
                "authorization_id": authorization_id,
                "lease_id": lease_id,
                "epoch": self.state.epoch,
                "job_id": job.id,
                "profile": "desktop_host",
            }),
        );
        if let Err(error) = recorded {
            self.withdraw_job(&job.id);
            return Err(error);
        }
        Ok(json!({
            "authorization_id": authorization_id,
            "lease_id": lease_id,
            "epoch": self.state.epoch,
            "job_id": job.id,
            "job_handle": job.handle,
        }))
    }

    fn open_dispatch_of(
        &self,
        caller: &CallerFacts,
        role: CallerRole,
        authorization_id: &str,
    ) -> Result<usize, AuthorityError> {
        if role != CallerRole::Orceld {
            return Err(AuthorityError::denied(
                "only orceld (a configured trusted image) asks about its dispatches",
            ));
        }
        if !is_authorization_id(authorization_id) {
            return Err(AuthorityError::invalid(
                "authorization_id is az- and 32 lowercase hex characters",
            ));
        }
        self.open_dispatches
            .iter()
            .position(|open| {
                open.authorization_id == authorization_id
                    && open.user_sid == caller.user_sid
                    && open.logon_session_id == caller.logon_session_id
            })
            .ok_or_else(|| {
                AuthorityError::invalid(
                    "no open dispatch of this caller has that authorization (reported already, or ended)",
                )
            })
    }

    /// orceld asks, after assigning its suspended worker and before resuming
    /// it, whether the authorization still stands: its lease is active and
    /// its job still held. Anything else is `LEASE_INVALID`.
    ///
    /// SG132_SLICE5.md: for an authorization that holds a job (a dispatch
    /// job, or the desktop host job `DesktopHostJob` answered), only the
    /// orceld instance the handle went to, and only after its `JobAck`; the
    /// answer confirms the job, so the acknowledgement timeout no longer
    /// applies to it.
    pub(super) fn dispatch_active(
        &mut self,
        caller: &CallerFacts,
        role: CallerRole,
        authorization_id: &str,
    ) -> Result<Value, AuthorityError> {
        let now = self.now();
        let desktop_host = self.jobs.iter().any(|job| {
            job.authorization_id == authorization_id && job.profile == JobProfile::DesktopHost
        });
        if desktop_host {
            self.confirm_job(caller, role, authorization_id, now)?;
            return Ok(json!({ "authorization_id": authorization_id, "active": true }));
        }
        let index = self.open_dispatch_of(caller, role, authorization_id)?;
        let open = &self.open_dispatches[index];
        let lease_id = open.lease_id.clone();
        if open.job_id.is_some() {
            self.confirm_job(caller, role, authorization_id, now)?;
        } else if !self.lease_active(&lease_id, now) {
            return Err(AuthorityError::lease_invalid(
                "the dispatch's lease ended or its Job Object was terminated",
            ));
        }
        Ok(json!({ "authorization_id": authorization_id, "active": true }))
    }

    /// orceld reports how an authorized dispatch ended; the service
    /// terminates its job first (authority reducing), then records it.
    pub(super) fn outcome(
        &mut self,
        caller: &CallerFacts,
        role: CallerRole,
        authorization_id: &str,
        outcome: DispatchOutcome,
        code: Option<FailureCode>,
    ) -> Result<Value, AuthorityError> {
        let index = self.open_dispatch_of(caller, role, authorization_id)?;
        let open = self
            .open_dispatches
            .remove(index)
            .ok_or_else(|| AuthorityError::internal("the open dispatch vanished"))?;
        let held = open
            .job_id
            .as_ref()
            .is_some_and(|id| self.jobs.iter().any(|job| &job.id == id));
        if let Some(id) = &open.job_id {
            self.end_job(id);
        }
        self.audit(
            "outcome",
            json!({
                "authorization_id": authorization_id,
                "outcome": outcome,
                "code": code,
            }),
            observed(caller, role),
            json!({
                "lease_id": open.lease_id,
                "job_id": open.job_id,
                "job_terminated": held,
            }),
        )?;
        Ok(json!({
            "authorization_id": authorization_id,
            "recorded": true,
            "job_terminated": held,
        }))
    }
}
