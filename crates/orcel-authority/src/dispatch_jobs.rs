//! WP1-12 (SG-000132): the Job Object of each Full Control dispatch.
//!
//! For the filesystem and shell/process executors (filesystem, process and
//! git operations), `Authorize` creates a fresh named Job Object for that one
//! dispatch before it writes the allow record, holds its only full-access
//! handle, and returns its `job_name`. orceld opens the job by name with
//! `JOB_OBJECT_ASSIGN_PROCESS` (the only right the job's DACL gives the
//! caller's user), starts `orceld fc-worker` suspended, assigns it, closes its
//! handle and resumes it. The job is kill-on-close with no breakaway limit,
//! so nothing the worker starts can leave it.
//!
//! Decision: one job per dispatch, not per lease. A dispatch's processes end
//! with its outcome (`Outcome` terminates the job), one dispatch cannot add
//! processes to another's job, and a job's name is useful for exactly one
//! launch. The service ends a lease's jobs whenever the lease stops being
//! active: revoke, Stop, session lock, sign-out, disconnect, expiry, an
//! epoch move, re-enrollment and reset. Jobs whose processes all exited are
//! closed after [`JOB_IDLE_MS`]; a lease holds at most
//! [`MAX_JOBS_PER_LEASE`] jobs and the service [`MAX_JOBS`].
//!
//! The service holds jobs in memory only: a restarted service holds no
//! handle, so kill-on-close has already ended whatever ran in them (unless
//! a client still holds a handle, which orceld closes before it resumes the
//! worker).

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
/// Authorizations whose outcome is still expected (the oldest is dropped).
pub const MAX_OPEN_DISPATCHES: usize = 256;
/// Every dispatch job's name, after its namespace.
pub const JOB_NAME_STEM: &str = "orcel-fc-";

/// Creates, terminates and inspects the dispatch Job Objects. The Windows
/// implementation is `win::jobs::ServiceJobs`.
pub trait JobHost: Send {
    /// `Global` for the installed service, `Local` for the console harness
    /// (a standard user cannot create `Global\` objects).
    fn namespace(&self) -> &'static str;
    /// Creates the job `name` (refusing a name that already exists),
    /// kill-on-close with no breakaway, whose DACL gives the service
    /// terminate and query and `assign_sid` only assign-process.
    fn create(&mut self, name: &str, assign_sid: &str) -> Result<(), AuthorityError>;
    /// Terminates every process in the job and closes the service's handle.
    fn terminate(&mut self, name: &str);
    /// How many processes the job holds now, when that can be read.
    fn active_processes(&self, name: &str) -> Option<u32>;
}

/// The name of a dispatch job: `<namespace>\orcel-fc-<32 hex>`.
pub fn job_name(namespace: &str, random_hex: &str) -> String {
    format!("{namespace}\\{JOB_NAME_STEM}{random_hex}")
}

/// Whether `text` is a dispatch job name as the service makes them.
pub fn is_job_name(text: &str) -> bool {
    let rest = text
        .strip_prefix("Global\\")
        .or_else(|| text.strip_prefix("Local\\"));
    rest.and_then(|rest| rest.strip_prefix(JOB_NAME_STEM))
        .is_some_and(|random| {
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
    name: String,
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
    job_name: Option<String>,
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
    ) -> Result<Option<String>, AuthorityError> {
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
        let name = job_name(self.services.jobs.namespace(), &hex(&self.random(16)?));
        self.services
            .jobs
            .create(&name, &caller.user_sid)
            .map_err(|error| {
                AuthorityError::unavailable(format!(
                    "the dispatch Job Object for {authorization_id} could not be created: {}",
                    error.message
                ))
            })?;
        self.jobs.push(HeldJob {
            name: name.clone(),
            lease_id: lease_id.to_owned(),
            created_ms: now,
        });
        Ok(Some(name))
    }

    /// Terminates and forgets one held job.
    pub(super) fn end_job(&mut self, name: &str) {
        if let Some(index) = self.jobs.iter().position(|job| job.name == name) {
            self.jobs.remove(index);
            self.services.jobs.terminate(name);
        }
    }

    /// Remembers an authorization until its outcome arrives.
    pub(super) fn open_dispatch(
        &mut self,
        caller: &CallerFacts,
        authorization_id: &str,
        lease_id: &str,
        job_name: Option<&str>,
    ) {
        while self.open_dispatches.len() >= MAX_OPEN_DISPATCHES {
            self.open_dispatches.pop_front();
        }
        self.open_dispatches.push_back(OpenDispatch {
            authorization_id: authorization_id.to_owned(),
            user_sid: caller.user_sid.clone(),
            logon_session_id: caller.logon_session_id,
            lease_id: lease_id.to_owned(),
            job_name: job_name.map(str::to_owned),
        });
    }

    /// Ends every held job whose lease is no longer active (revoked,
    /// stopped, expired, from an older epoch, or gone).
    pub(super) fn sweep_jobs(&mut self) {
        let now = self.now();
        let dead: Vec<String> = self
            .jobs
            .iter()
            .filter(|job| {
                !self.state.leases.iter().any(|record| {
                    record.lease.body.lease_id == job.lease_id
                        && self.effective_state(record, now) == "active"
                })
            })
            .map(|job| job.name.clone())
            .collect();
        // Their open dispatches stay, so the outcome is still recorded.
        for name in dead {
            self.end_job(&name);
        }
    }

    /// Closes jobs older than [`JOB_IDLE_MS`] whose processes all exited.
    pub(super) fn reap_idle_jobs(&mut self, now: u64) {
        let idle: Vec<String> = self
            .jobs
            .iter()
            .filter(|job| {
                now.saturating_sub(job.created_ms) >= JOB_IDLE_MS
                    && self.services.jobs.active_processes(&job.name) == Some(0)
            })
            .map(|job| job.name.clone())
            .collect();
        for name in idle {
            self.end_job(&name);
        }
    }

    /// What `Status` reports about the dispatch jobs.
    pub(super) fn job_status(&self) -> Value {
        json!({
            "namespace": self.services.jobs.namespace(),
            "held": self.jobs.len(),
            "per_dispatch": true,
            "per_lease_limit": MAX_JOBS_PER_LEASE,
            "kill_on_close": true,
            "breakaway": false,
            "client_access": "JOB_OBJECT_ASSIGN_PROCESS",
        })
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
        if role != CallerRole::Orceld {
            return Err(AuthorityError::denied(
                "only orceld (a configured trusted image) reports dispatch outcomes",
            ));
        }
        if !is_authorization_id(authorization_id) {
            return Err(AuthorityError::invalid(
                "authorization_id is az- and 32 lowercase hex characters",
            ));
        }
        let index = self
            .open_dispatches
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
            })?;
        let open = self
            .open_dispatches
            .remove(index)
            .ok_or_else(|| AuthorityError::internal("the open dispatch vanished"))?;
        let held = open
            .job_name
            .as_ref()
            .is_some_and(|name| self.jobs.iter().any(|job| &job.name == name));
        if let Some(name) = &open.job_name {
            self.end_job(name);
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
                "job_name": open.job_name,
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
