//! WP1-12 (SG-000132): the dispatch Job Objects, made and held by the
//! service (spec 4.14).
//!
//! Each job is created under a random name (`Global\orcel-fc-<32 hex>` for
//! the installed service, `Local\` in console mode, where a standard user
//! cannot create `Global\` objects), refusing a name that already exists.
//! Its security descriptor is protected (no inherited ACEs) and its DACL has
//! exactly two entries:
//!
//! - the service's SID: `JOB_OBJECT_TERMINATE | JOB_OBJECT_QUERY`;
//! - the calling user's SID: `JOB_OBJECT_ASSIGN_PROCESS`, nothing else.
//!
//! The owner is the service (its token's default owner), so the user gets
//! no implicit `WRITE_DAC` or `READ_CONTROL` either. The service keeps the
//! creating handle, which has every right. The limits are
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`
//! and an active-process limit of [`ACTIVE_PROCESS_LIMIT`]; neither
//! `JOB_OBJECT_LIMIT_BREAKAWAY_OK` nor `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK`,
//! so `CREATE_BREAKAWAY_FROM_JOB` fails for every process in the job.
//!
//! In console mode the service SID is the console user's, so that user also
//! holds terminate and query: console mode shows the mechanism, not the
//! separation (SG132_SLICE3.md).

use super::{os_error, wide, Owned};
use crate::core::dispatch_jobs::JobHost;
use crate::error::AuthorityError;
use std::collections::BTreeMap;
use windows_sys::Win32::Foundation::{GetLastError, LocalFree, ERROR_ALREADY_EXISTS};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

/// `JOB_OBJECT_ASSIGN_PROCESS`: the only right the calling user gets.
pub const JOB_ASSIGN_PROCESS: u32 = 0x0001;
/// `JOB_OBJECT_QUERY`.
pub const JOB_QUERY: u32 = 0x0004;
/// `JOB_OBJECT_TERMINATE`.
pub const JOB_TERMINATE: u32 = 0x0008;
/// The service's rights through the DACL (it also keeps the creating
/// handle).
pub const SERVICE_JOB_ACCESS: u32 = JOB_TERMINATE | JOB_QUERY;
/// Processes one dispatch job may hold at once (a git operation starts a
/// few helpers; a worker may start a tool).
pub const ACTIVE_PROCESS_LIMIT: u32 = 64;
/// The limit flags every dispatch job carries.
pub const JOB_LIMIT_FLAGS: u32 = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
    | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;

fn is_sid(text: &str) -> bool {
    text.strip_prefix("S-1-").is_some_and(|rest| {
        !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'-')
    })
}

/// The job's security descriptor as SDDL: protected DACL, the service
/// terminate and query, `assign_sid` assign-process only.
pub fn job_sddl(service_sid: &str, assign_sid: &str) -> Result<String, AuthorityError> {
    if !is_sid(service_sid) || !is_sid(assign_sid) {
        return Err(AuthorityError::invalid("a job ACE names a malformed SID"));
    }
    Ok(format!(
        "D:P(A;;0x{SERVICE_JOB_ACCESS:x};;;{service_sid})(A;;0x{JOB_ASSIGN_PROCESS:x};;;{assign_sid})"
    ))
}

/// Creates the named job with `sddl`, refusing an existing name, and sets
/// the dispatch limits. The returned handle has every right.
pub fn create_job(name: &str, sddl: &str) -> Result<Owned, AuthorityError> {
    let wide_sddl = wide(sddl);
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: NUL-terminated SDDL and a valid out-pointer; the descriptor is
    // freed below with LocalFree.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(os_error(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW(job)",
        ));
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let wide_name = wide(name);
    // SAFETY: the attributes and the name outlive the call.
    let handle = unsafe { CreateJobObjectW(&attributes, wide_name.as_ptr()) };
    // SAFETY: read before any other call can change it.
    let last = unsafe { GetLastError() };
    // SAFETY: allocated by the conversion above, freed once.
    unsafe { LocalFree(descriptor as _) };
    if handle == 0 {
        return Err(os_error("CreateJobObjectW"));
    }
    let job = Owned(handle);
    if last == ERROR_ALREADY_EXISTS {
        return Err(AuthorityError::denied(format!(
            "the job name {name} already exists; refusing a job the service did not make"
        )));
    }
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
    Ok(job)
}

/// The job's limit flags as the kernel reports them.
pub fn limit_flags(job: &Owned) -> Result<u32, AuthorityError> {
    // SAFETY: zeroed limit information is a valid out-parameter.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: pointer and size describe `limits`.
    if unsafe {
        QueryInformationJobObject(
            job.0,
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

/// Processes in the job now.
pub fn active_processes(job: &Owned) -> Result<u32, AuthorityError> {
    // SAFETY: zeroed accounting information is a valid out-parameter.
    let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: pointer and size describe `info`.
    if unsafe {
        QueryInformationJobObject(
            job.0,
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

/// Client side (orceld): opens the dispatch job `name` asking for exactly
/// `access`. The OS error is kept so a caller can tell "gone" from
/// "denied".
pub fn open_job(name: &str, access: u32) -> Result<Owned, std::io::Error> {
    use windows_sys::Win32::System::JobObjects::OpenJobObjectW;
    let wide_name = wide(name);
    // SAFETY: NUL-terminated name; the handle is not inheritable.
    let handle = unsafe { OpenJobObjectW(access, 0, wide_name.as_ptr()) };
    if handle == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Owned(handle))
}

/// The service's dispatch jobs.
pub struct ServiceJobs {
    namespace: &'static str,
    service_sid: String,
    /// A BTreeMap, not a HashMap: std's HashMap seeds itself through
    /// bcryptprimitives.dll, which is not a KnownDLL (install_script.rs).
    held: BTreeMap<String, Owned>,
}

impl ServiceJobs {
    /// `namespace` is `Global` for the installed service and `Local` for
    /// the console harness; `service_sid` is the SID the service runs as.
    pub fn new(namespace: &'static str, service_sid: &str) -> Self {
        Self {
            namespace,
            service_sid: service_sid.to_owned(),
            held: BTreeMap::new(),
        }
    }
}

impl JobHost for ServiceJobs {
    fn namespace(&self) -> &'static str {
        self.namespace
    }

    fn create(&mut self, name: &str, assign_sid: &str) -> Result<(), AuthorityError> {
        let job = create_job(name, &job_sddl(&self.service_sid, assign_sid)?)?;
        self.held.insert(name.to_owned(), job);
        Ok(())
    }

    fn terminate(&mut self, name: &str) {
        if let Some(job) = self.held.remove(name) {
            // SAFETY: the creating handle has JOB_OBJECT_TERMINATE. Closing
            // it afterwards (kill-on-close) ends anything assigned later.
            unsafe { TerminateJobObject(job.0, 1) };
        }
    }

    fn active_processes(&self, name: &str) -> Option<u32> {
        self.held
            .get(name)
            .and_then(|job| active_processes(job).ok())
    }
}
