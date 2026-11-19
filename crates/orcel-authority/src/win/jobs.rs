//! WP1-10 (SG-000132): the dispatch Job Objects, made and held by the
//! service (spec 4.14).
//!
//! Each job is UNNAMED: no process can open it by name, squat its name, or
//! keep it alive under a name after the service ends it. Review of
//! `291e045e`: a standard user can create `Global\` objects on this PC, so
//! named jobs could be pre-created or held open, and the earlier name-based
//! design was replaced.
//!
//! The service creates the job (default security of its own token), sets
//! the limits, and duplicates ONE handle into the verified orceld process
//! (the pipe client whose PID and creation time the service observed) with
//! exactly `JOB_OBJECT_ASSIGN_PROCESS`, not inheritable. The process handle
//! it needs for that (`PROCESS_DUP_HANDLE`) is opened while impersonating
//! the pipe client ([`ClientProcess::open_impersonating`]), because the
//! service account has no rights on user processes. orceld assigns its
//! suspended worker with that handle and closes it. The service keeps the
//! creating handle (every right) and the client process handle, so it can
//! also close the duplicated handle in orceld when it ends the job.
//!
//! Limits: `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`,
//! `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION` and an active-process limit
//! of [`ACTIVE_PROCESS_LIMIT`]; never `JOB_OBJECT_LIMIT_BREAKAWAY_OK` or
//! `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK`, so `CREATE_BREAKAWAY_FROM_JOB`
//! fails inside the job.
//!
//! WP1-15 (SG-000097, SG-000096; SG132_SLICE4.md): every dispatch job also
//! carries the UI restrictions of [`JOB_UI_LIMITS`]. The worker and the
//! console programs it runs need none of what they take away, and they
//! reduce the window-message and DDE routes to processes outside the job
//! (they are not a boundary: no job restriction covers synthesized input,
//! and a GUI program can still make its own windows): a process in
//! the job cannot use USER handles (windows, hooks) of processes outside it,
//! has its own global atom table (DDE conversations with the shell need the
//! shared one), cannot create or switch desktops, read or write the
//! clipboard, log off or shut down, or change system parameters or display
//! settings. They do not close COM, WMI, RPC or Task Scheduler requests to
//! out-of-job brokers (SG132_SLICE4.md, residuals).
//!
//! Residual: a process running as the user can duplicate the assign-only
//! handle out of orceld (it holds `PROCESS_DUP_HANDLE` on orceld) and assign
//! its own processes to the job. That only puts them where the service will
//! terminate them, and can hold a dispatch's job busy until the service's
//! age limit ends it (SG132_SLICE3.md). A desktop host job has no age limit:
//! such processes stay until the lease ends (SG132_SLICE5.md).
//!
//! SG132_SLICE5.md: a desktop host job ([`JobProfile::DesktopHost`]) carries
//! [`DESKTOP_HOST_UI_LIMITS`] instead of [`JOB_UI_LIMITS`].

use super::{os_error, Owned};
use crate::caller::CallerFacts;
use crate::core::dispatch_jobs::{DispatchJob, JobHost, JobProfile};
use crate::error::AuthorityError;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::{DuplicateHandle, DUPLICATE_CLOSE_SOURCE, FILETIME, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JobObjectBasicAccountingInformation, JobObjectBasicUIRestrictions,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_BASIC_UI_RESTRICTIONS,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

/// `JOB_OBJECT_ASSIGN_PROCESS`: the only right orceld's handle carries.
pub const JOB_ASSIGN_PROCESS: u32 = 0x0001;
/// `JOB_OBJECT_QUERY`.
pub const JOB_QUERY: u32 = 0x0004;
/// `JOB_OBJECT_TERMINATE`.
pub const JOB_TERMINATE: u32 = 0x0008;
/// Processes one dispatch job may hold at once (a git operation starts a
/// few helpers; a worker may start a tool).
pub const ACTIVE_PROCESS_LIMIT: u32 = 64;
/// The limit flags every dispatch job carries.
pub const JOB_LIMIT_FLAGS: u32 = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
    | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
/// The UI restrictions every dispatch job carries (WP1-15): no USER
/// handles of processes outside the job, a separate global atom table, no
/// desktop creation or switching, no clipboard, no log off or shutdown, no
/// system parameter or display setting changes.
pub const JOB_UI_LIMITS: u32 = JOB_OBJECT_UILIMIT_HANDLES
    | JOB_OBJECT_UILIMIT_GLOBALATOMS
    | JOB_OBJECT_UILIMIT_DESKTOP
    | JOB_OBJECT_UILIMIT_EXITWINDOWS
    | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
    | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
    | JOB_OBJECT_UILIMIT_READCLIPBOARD
    | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
/// SG132_SLICE5.md: the UI restrictions of the desktop input host's job
/// (`apps/orcel-computer-host` and its per-request workers). Desktop input
/// on the user's desktop (the Full User model) needs the windows of other
/// processes: listing them, reading their UI Automation trees (which uses
/// window messages to them), `SetForegroundWindow`, `PostMessage(WM_CLOSE)`.
/// So `HANDLES` is left out (it would refuse every USER handle of a process
/// outside the job), and so is `GLOBALATOMS` (UI Automation and OLE in the
/// host are not verified to work with a private global atom table; nothing
/// in the host needs DDE). The host never uses the clipboard, never makes or
/// switches desktops, and never changes system parameters or display
/// settings or logs off, so those stay restricted. Synthesized input
/// (`SendInput`) is what the host is for; no job restriction covers it.
pub const DESKTOP_HOST_UI_LIMITS: u32 = JOB_OBJECT_UILIMIT_DESKTOP
    | JOB_OBJECT_UILIMIT_EXITWINDOWS
    | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
    | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
    | JOB_OBJECT_UILIMIT_READCLIPBOARD
    | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;

/// The UI restrictions of a job of `profile`.
pub fn ui_limits_for(profile: JobProfile) -> u32 {
    match profile {
        JobProfile::Dispatch => JOB_UI_LIMITS,
        JobProfile::DesktopHost => DESKTOP_HOST_UI_LIMITS,
    }
}

/// A pipe client's process, opened for handle duplication, with the
/// creation time it was opened at.
pub struct ClientProcess {
    pub pid: u32,
    pub generation: u64,
    handle: Owned,
}

fn creation_time(process: HANDLE) -> Result<u64, AuthorityError> {
    let mut times = [FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    }; 4];
    let [creation, exit, kernel, user] = &mut times;
    // SAFETY: a live handle with query rights and four live FILETIMEs.
    if unsafe { GetProcessTimes(process, creation, exit, kernel, user) } == 0 {
        return Err(os_error("GetProcessTimes"));
    }
    Ok(((times[0].dwHighDateTime as u64) << 32) | times[0].dwLowDateTime as u64)
}

impl ClientProcess {
    /// Opens `pid` with `PROCESS_DUP_HANDLE` as this process (tests: a
    /// process of the same user).
    pub fn open(pid: u32) -> Result<Self, AuthorityError> {
        // SAFETY: plain call; the handle is owned below.
        let handle = unsafe {
            OpenProcess(
                PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            )
        };
        if handle == 0 {
            return Err(os_error("OpenProcess(PROCESS_DUP_HANDLE)"));
        }
        let handle = Owned(handle);
        let generation = creation_time(handle.0)?;
        Ok(Self {
            pid,
            generation,
            handle,
        })
    }

    /// Opens the client of `pipe` (the process the service observed in
    /// `facts`) while impersonating it, and checks it is the same process
    /// instance (creation time), not a recycled PID.
    pub fn open_impersonating(pipe: HANDLE, facts: &CallerFacts) -> Result<Self, AuthorityError> {
        let opened = super::identity::as_client(pipe, || Self::open(facts.pid))??;
        // Checked after the revert: the instance must be the observed one.
        if facts.process_generation == 0 || opened.generation != facts.process_generation {
            return Err(AuthorityError::denied(
                "the pipe client's process is not the instance the service observed",
            ));
        }
        Ok(opened)
    }
}

/// Where the runtime puts the current Authorize caller's process for the
/// job host (set and cleared under the core lock).
pub type ClientSlot = Arc<Mutex<Option<ClientProcess>>>;

/// The job's limit flags as the kernel reports them.
pub fn limit_flags(job: HANDLE) -> Result<u32, AuthorityError> {
    // SAFETY: zeroed limit information is a valid out-parameter.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: pointer and size describe `limits`.
    if unsafe {
        QueryInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(os_error("QueryInformationJobObject(limits)"));
    }
    Ok(limits.BasicLimitInformation.LimitFlags)
}

/// The job's UI restrictions as the kernel reports them.
pub fn ui_limits(job: HANDLE) -> Result<u32, AuthorityError> {
    let mut limits = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: 0,
    };
    // SAFETY: pointer and size describe `limits`.
    if unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicUIRestrictions,
            (&mut limits as *mut JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
            std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(os_error("QueryInformationJobObject(UI restrictions)"));
    }
    Ok(limits.UIRestrictionsClass)
}

/// Processes in the job now.
pub fn active_processes(job: HANDLE) -> Result<u32, AuthorityError> {
    // SAFETY: zeroed accounting information is a valid out-parameter.
    let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: pointer and size describe `info`.
    if unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(os_error("QueryInformationJobObject(accounting)"));
    }
    Ok(info.ActiveProcesses)
}

/// Creates an unnamed job with the dispatch limits and UI restrictions.
pub fn create_job() -> Result<Owned, AuthorityError> {
    create_job_for(JobProfile::Dispatch)
}

/// Creates an unnamed job with the limits and UI restrictions of
/// `profile` (the limit flags and process limit are the same for both).
pub fn create_job_for(profile: JobProfile) -> Result<Owned, AuthorityError> {
    // SAFETY: no attributes and no name: an unnamed job, not inheritable.
    let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if handle == 0 {
        return Err(os_error("CreateJobObjectW"));
    }
    let job = Owned(handle);
    // SAFETY: zeroed limit information is valid before the fields are set.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_LIMIT_FLAGS;
    limits.BasicLimitInformation.ActiveProcessLimit = ACTIVE_PROCESS_LIMIT;
    // SAFETY: pointer and size describe `limits`; the handle has every right.
    if unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(os_error("SetInformationJobObject(dispatch limits)"));
    }
    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: ui_limits_for(profile),
    };
    // SAFETY: pointer and size describe `ui`; the handle has every right.
    if unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectBasicUIRestrictions,
            (&ui as *const JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
            std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        )
    } == 0
    {
        return Err(os_error("SetInformationJobObject(UI restrictions)"));
    }
    Ok(job)
}

struct Held {
    job: Owned,
    client: ClientProcess,
    remote: u64,
}

impl Held {
    /// Closes orceld's duplicated handle, if it still has it.
    fn close_remote(&mut self) {
        if self.remote == 0 {
            return;
        }
        // SAFETY: closes the handle value in the client process that the
        // service itself duplicated there; nothing is duplicated back.
        unsafe {
            DuplicateHandle(
                self.client.handle.0,
                self.remote as HANDLE,
                0,
                std::ptr::null_mut(),
                0,
                0,
                DUPLICATE_CLOSE_SOURCE,
            )
        };
        self.remote = 0;
    }
}

/// The service's dispatch jobs.
pub struct ServiceJobs {
    slot: ClientSlot,
    held: BTreeMap<String, Held>,
}

impl ServiceJobs {
    /// `slot` is where the runtime puts the Authorize caller's process.
    pub fn new(slot: ClientSlot) -> Self {
        Self {
            slot,
            held: BTreeMap::new(),
        }
    }
}

impl JobHost for ServiceJobs {
    fn create(
        &mut self,
        id: &str,
        caller: &CallerFacts,
        profile: JobProfile,
    ) -> Result<DispatchJob, AuthorityError> {
        let client = self
            .slot
            .lock()
            .map_err(|_| AuthorityError::internal("the client slot is poisoned"))?
            .take()
            .ok_or_else(|| AuthorityError::internal("the caller's process was not opened"))?;
        if client.pid != caller.pid || client.generation != caller.process_generation {
            return Err(AuthorityError::denied(
                "the opened process is not the observed caller",
            ));
        }
        let job = create_job_for(profile)?;
        let mut remote: HANDLE = 0;
        // SAFETY: duplicates the job handle into the verified client with
        // exactly assign-process, not inheritable.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                job.0,
                client.handle.0,
                &mut remote,
                JOB_ASSIGN_PROCESS,
                0,
                0,
            )
        } == 0
        {
            return Err(os_error("DuplicateHandle(job into orceld)"));
        }
        let handle = remote as u64;
        self.held.insert(
            id.to_owned(),
            Held {
                job,
                client,
                remote: handle,
            },
        );
        Ok(DispatchJob {
            id: id.to_owned(),
            handle,
        })
    }

    fn terminate(&mut self, id: &str) {
        if let Some(held) = self.held.remove(id) {
            // SAFETY: the creating handle has JOB_OBJECT_TERMINATE. orceld
            // acknowledged its handle, so the handle is orceld's own to close
            // (it may already have, and the value may be reused): a process
            // orceld assigns afterwards is never resumed, because
            // `DispatchActive` refuses first.
            unsafe { TerminateJobObject(held.job.0, 1) };
        }
    }

    fn withdraw(&mut self, id: &str) {
        if let Some(mut held) = self.held.remove(id) {
            // The answer carrying the handle was never sent, or orceld never
            // acknowledged it (SG132_SLICE5.md): orceld uses and closes only
            // a handle whose acknowledgement the service accepted, so it
            // has not used or closed this value and closing it there is
            // safe.
            held.close_remote();
            // SAFETY: the creating handle has JOB_OBJECT_TERMINATE.
            unsafe { TerminateJobObject(held.job.0, 1) };
        }
    }

    fn active_processes(&self, id: &str) -> Option<u32> {
        self.held
            .get(id)
            .and_then(|held| active_processes(held.job.0).ok())
    }
}
