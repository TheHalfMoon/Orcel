//! WP1-12 (SG-000132): the Job Object of each Full Control dispatch.
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
//! leave it.
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
    /// Creates an unnamed, kill-on-close, no-breakaway job `id` and
    /// duplicates an assign-only, non-inheritable handle to it into the
    /// caller's process (the observed pipe client).
    fn create(&mut self, id: &str, caller: &CallerFacts) -> Result<DispatchJob, AuthorityError>;
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
        let id = format!("{JOB_ID_PREFIX}{}", hex(&self.random(16)?));
        let job = self.services.jobs.create(&id, caller).map_err(|error| {
            AuthorityError::unavailable(format!(
                "the dispatch Job Object for {authorization_id} could not be created: {}",
                error.message
            ))
        })?;
        self.jobs.push(HeldJob {
            id,
            lease_id: lease_id.to_owned(),
            created_ms: now,
        });
        Ok(Some(job))
    }

    /// Terminates and forgets one held job.
    pub(super) fn end_job(&mut self, id: &str) {
        if let Some(index) = self.jobs.iter().position(|job| job.id == id) {
            self.jobs.remove(index);
            self.services.jobs.terminate(id);
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
    /// and terminates every job older than [`JOB_MAX_MS`].
    pub(super) fn reap_idle_jobs(&mut self, now: u64) {
        let stale: Vec<String> = self
            .jobs
            .iter()
            .filter(|job| {
                let age = now.saturating_sub(job.created_ms);
                age >= JOB_MAX_MS
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
            "client_access": "JOB_OBJECT_ASSIGN_PROCESS (duplicated handle)",
        })
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
    pub(super) fn dispatch_active(
        &mut self,
        caller: &CallerFacts,
        role: CallerRole,
        authorization_id: &str,
    ) -> Result<Value, AuthorityError> {
        let index = self.open_dispatch_of(caller, role, authorization_id)?;
        let now = self.now();
        let open = &self.open_dispatches[index];
        let job_held = open
            .job_id
            .as_ref()
            .is_none_or(|id| self.jobs.iter().any(|job| &job.id == id));
        if !self.lease_active(&open.lease_id, now) || !job_held {
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
