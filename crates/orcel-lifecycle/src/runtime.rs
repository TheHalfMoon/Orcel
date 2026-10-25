//! Windows process primitives for the supervisor: verified process identity,
//! kill-on-close Job Objects, suspended launch with job assignment before
//! resume, and a per-install named stop event.

use crate::LifecycleError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetExitCodeProcess, GetProcessTimes, OpenEventW, OpenProcess, OpenThread,
    QueryFullProcessImageNameW, ResumeThread, SetEvent, TerminateProcess, WaitForMultipleObjects,
    WaitForSingleObject, EVENT_MODIFY_STATE, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, THREAD_SUSPEND_RESUME,
};

/// An owned kernel handle closed on drop.
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> Option<Self> {
        (handle != 0 && handle != -1).then_some(Self(handle))
    }
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by a successful open/create call and
        // is closed exactly once here.
        unsafe { CloseHandle(self.0) };
    }
}

fn last_error(context: &str) -> LifecycleError {
    LifecycleError::platform(format!("{context}: {}", std::io::Error::last_os_error()))
}

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

/// A process identified by pid, creation time, and image path, so a reused
/// pid is never mistaken for the recorded process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub creation_time: u64,
    pub image: String,
}

/// An opened, identity-verified, still-running process.
pub struct LiveProcess {
    handle: OwnedHandle,
    pub identity: ProcessIdentity,
}

fn open_process(pid: u32, access: u32) -> Option<OwnedHandle> {
    // SAFETY: OpenProcess has no memory-safety preconditions; the returned
    // handle is owned by OwnedHandle.
    OwnedHandle::new(unsafe { OpenProcess(access, 0, pid) })
}

/// Whether the process has not exited. A zero-timeout wait is used instead
/// of comparing the exit code with `STILL_ACTIVE`, because a process may
/// legitimately exit with code 259.
fn is_running(handle: &OwnedHandle) -> bool {
    // SAFETY: the handle was opened with SYNCHRONIZE access.
    unsafe { WaitForSingleObject(handle.raw(), 0) == WAIT_TIMEOUT }
}

fn identity_of(handle: &OwnedHandle, pid: u32) -> Option<ProcessIdentity> {
    if !is_running(handle) {
        return None;
    }
    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut unused = [creation, creation, creation];
    // SAFETY: valid handle and out-pointers to locals.
    let ok = unsafe {
        GetProcessTimes(
            handle.raw(),
            &mut creation,
            &mut unused[0],
            &mut unused[1],
            &mut unused[2],
        )
    };
    if ok == 0 {
        return None;
    }
    let mut buffer = vec![0u16; 32_768];
    let mut size = buffer.len() as u32;
    // SAFETY: buffer length is passed in `size`.
    if unsafe {
        QueryFullProcessImageNameW(
            handle.raw(),
            PROCESS_NAME_WIN32,
            buffer.as_mut_ptr(),
            &mut size,
        )
    } == 0
    {
        return None;
    }
    Some(ProcessIdentity {
        pid,
        creation_time: (u64::from(creation.dwHighDateTime) << 32)
            | u64::from(creation.dwLowDateTime),
        image: String::from_utf16_lossy(&buffer[..size as usize]),
    })
}

/// Returns the identity of a running process, or `None` if it is not running
/// or cannot be inspected.
pub fn identify(pid: u32) -> Option<ProcessIdentity> {
    let handle = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE)?;
    identity_of(&handle, pid)
}

/// Opens the recorded process only if it is still running with the exact
/// recorded creation time and image path.
pub fn open_verified(recorded: &ProcessIdentity) -> Option<LiveProcess> {
    let handle = open_process(
        recorded.pid,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE,
    )?;
    let identity = identity_of(&handle, recorded.pid)?;
    (identity.creation_time == recorded.creation_time
        && identity.image.eq_ignore_ascii_case(&recorded.image))
    .then_some(LiveProcess { handle, identity })
}

impl LiveProcess {
    /// Waits until the process exits; returns true only if exit was observed.
    pub fn wait(&self, timeout: Duration) -> bool {
        wait_any(&[self.handle.raw()], timeout) == Some(0)
    }

    pub fn terminate(&self) -> bool {
        // SAFETY: handle opened with PROCESS_TERMINATE.
        unsafe { TerminateProcess(self.handle.raw(), 1) != 0 }
    }
}

/// Waits for any handle; returns its index, or `None` on timeout or failure.
pub fn wait_any(handles: &[HANDLE], timeout: Duration) -> Option<usize> {
    let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
    // SAFETY: the slice pointer and length describe valid handles.
    let result =
        unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, millis) };
    if result == WAIT_TIMEOUT {
        return None;
    }
    let index = result.wrapping_sub(WAIT_OBJECT_0) as usize;
    (index < handles.len()).then_some(index)
}

pub fn child_handle(child: &std::process::Child) -> HANDLE {
    child.as_raw_handle() as HANDLE
}

/// A Job Object that terminates every assigned process when its last handle
/// closes, including when the supervisor itself dies.
pub struct Job(OwnedHandle);

impl Job {
    pub fn kill_on_close() -> Result<Self, LifecycleError> {
        // SAFETY: null attributes and name are permitted.
        let job = OwnedHandle::new(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) })
            .ok_or_else(|| last_error("CreateJobObjectW"))?;
        // SAFETY: zeroed JOBOBJECT_EXTENDED_LIMIT_INFORMATION is a valid value.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: pointer and size describe `limits`.
        let ok = unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(last_error("SetInformationJobObject"));
        }
        Ok(Self(job))
    }

    pub fn assign(&self, process: HANDLE) -> Result<(), LifecycleError> {
        // SAFETY: both handles are valid for the duration of the call.
        if unsafe { AssignProcessToJobObject(self.0.raw(), process) } == 0 {
            return Err(last_error("AssignProcessToJobObject"));
        }
        Ok(())
    }

    pub fn terminate(&self) -> bool {
        // SAFETY: valid job handle.
        unsafe { TerminateJobObject(self.0.raw(), 1) != 0 }
    }

    pub fn active_processes(&self) -> Result<u32, LifecycleError> {
        // SAFETY: zeroed accounting information is a valid value.
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: pointer and size describe `info`.
        let ok = unsafe {
            QueryInformationJobObject(
                self.0.raw(),
                JobObjectBasicAccountingInformation,
                &mut info as *mut _ as *mut c_void,
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error("QueryInformationJobObject"));
        }
        Ok(info.ActiveProcesses)
    }

    /// Terminates the job and waits until no process remains in it.
    pub fn terminate_and_confirm_empty(&self, timeout: Duration) -> Result<bool, LifecycleError> {
        self.terminate();
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if self.active_processes()? == 0 {
                return Ok(true);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Resumes every thread of a process created with `CREATE_SUSPENDED`.
pub fn resume_process(pid: u32) -> Result<(), LifecycleError> {
    // SAFETY: snapshot flags and pid have no memory-safety preconditions.
    let snapshot = OwnedHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) })
        .ok_or_else(|| last_error("CreateToolhelp32Snapshot"))?;
    // SAFETY: zeroed THREADENTRY32 with dwSize set is the documented input.
    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    let mut resumed = 0;
    // SAFETY: valid snapshot handle and entry pointer.
    let mut more = unsafe { Thread32First(snapshot.raw(), &mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == pid {
            // SAFETY: OpenThread has no memory-safety preconditions.
            if let Some(thread) = OwnedHandle::new(unsafe {
                OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID)
            }) {
                // SAFETY: handle opened with THREAD_SUSPEND_RESUME.
                if unsafe { ResumeThread(thread.raw()) } != u32::MAX {
                    resumed += 1;
                }
            }
        }
        // SAFETY: valid snapshot handle and entry pointer.
        more = unsafe { Thread32Next(snapshot.raw(), &mut entry) } != 0;
    }
    if resumed == 0 {
        return Err(LifecycleError::platform(
            "the suspended child process could not be resumed",
        ));
    }
    Ok(())
}

/// Clears the inherit flag on this process's standard handles. Child
/// processes launched afterwards receive only the handles passed to them
/// explicitly, so a long-lived detached child cannot keep a caller's pipe
/// open (which would make anyone capturing this process's output wait for
/// the child to exit).
pub fn disinherit_standard_handles() {
    use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: GetStdHandle has no preconditions; SetHandleInformation is
        // only called on a non-null, non-invalid handle it returned.
        unsafe {
            let handle = GetStdHandle(which);
            if handle != 0 && handle != -1 {
                SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}

/// An exclusive per-install lifecycle lock (a session-local named mutex), held
/// by every state-changing lifecycle command so install, update, rollback,
/// start, stop, and uninstall never interleave. A mutex abandoned by a
/// crashed holder is acquired normally.
pub struct LifecycleLock(OwnedHandle);

impl LifecycleLock {
    pub fn acquire(root: &Path, timeout: Duration) -> Result<Self, LifecycleError> {
        use windows_sys::Win32::Foundation::WAIT_ABANDONED;
        use windows_sys::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};
        let digest = Sha256::digest(root.to_string_lossy().to_ascii_lowercase().as_bytes());
        let hex = digest
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let name = wide(std::ffi::OsStr::new(&format!(
            "Local\\Orcel-Lifecycle-{hex}"
        )));
        // SAFETY: null attributes are permitted; the name is NUL-terminated.
        let mutex = OwnedHandle::new(unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) })
            .ok_or_else(|| last_error("CreateMutexW"))?;
        let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
        // SAFETY: valid mutex handle.
        match unsafe { WaitForSingleObject(mutex.raw(), millis) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self(mutex)),
            WAIT_TIMEOUT => Err(LifecycleError::conflict(
                "another Orcel lifecycle command is running for this install; try again when it finishes",
            )),
            _ => Err(last_error("WaitForSingleObject")),
        }
    }
}

impl Drop for LifecycleLock {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Threading::ReleaseMutex;
        // SAFETY: this thread owns the mutex acquired in `acquire`.
        unsafe { ReleaseMutex(self.0.raw()) };
    }
}

/// A detached process started by [`spawn_detached`].
pub struct DetachedProcess {
    handle: OwnedHandle,
    pub pid: u32,
}

impl DetachedProcess {
    /// Returns the exit code once the process has exited.
    pub fn exit_code(&self) -> Option<u32> {
        if is_running(&self.handle) {
            return None;
        }
        let mut code = 0u32;
        // SAFETY: valid process handle and out-pointer to a local.
        if unsafe { GetExitCodeProcess(self.handle.raw(), &mut code) } == 0 {
            return None;
        }
        Some(code)
    }
}

fn quote_argument(argument: &str) -> String {
    if !argument.is_empty() && !argument.contains([' ', '\t', '"']) {
        return argument.to_string();
    }
    let mut quoted = String::from('"');
    let mut backslashes = 0;
    for c in argument.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(backslashes));
                quoted.push(c);
                backslashes = 0;
            }
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

/// Starts a detached process whose only inherited handles are NUL for stdin
/// and `log` for stdout and stderr, enforced with
/// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. No other inheritable handle of this
/// process (for example a pipe a caller is reading) can reach the child.
pub fn spawn_detached(
    program: &Path,
    args: &[&str],
    env: &std::collections::BTreeMap<String, String>,
    log: &std::fs::File,
) -> Result<DetachedProcess, LifecycleError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
        UpdateProcThreadAttribute, CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP,
        CREATE_UNICODE_ENVIRONMENT, DETACHED_PROCESS, EXTENDED_STARTUPINFO_PRESENT,
        PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES,
        STARTUPINFOEXW,
    };

    let null = std::fs::OpenOptions::new()
        .read(true)
        .open("NUL")
        .map_err(|error| LifecycleError::io("open NUL", error))?;
    let output = log
        .try_clone()
        .map_err(|error| LifecycleError::io("duplicate log handle", error))?;
    let handles = [
        null.as_raw_handle() as HANDLE,
        output.as_raw_handle() as HANDLE,
    ];
    for handle in handles {
        // SAFETY: both handles are owned by live File values above.
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(last_error("SetHandleInformation"));
        }
    }

    let mut size = 0usize;
    // SAFETY: a null list with a size out-pointer queries the required size.
    unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut size) };
    let mut attributes = vec![0u8; size];
    let list = attributes.as_mut_ptr() as *mut c_void;
    // SAFETY: `attributes` provides `size` bytes for one attribute.
    if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
        return Err(last_error("InitializeProcThreadAttributeList"));
    }
    struct ListGuard(*mut c_void);
    impl Drop for ListGuard {
        fn drop(&mut self) {
            // SAFETY: the list was initialized successfully.
            unsafe { DeleteProcThreadAttributeList(self.0) };
        }
    }
    let _guard = ListGuard(list);
    // SAFETY: `handles` outlives the CreateProcessW call below.
    if unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_ptr() as *const c_void,
            std::mem::size_of_val(&handles),
            ptr::null_mut(),
            ptr::null(),
        )
    } == 0
    {
        return Err(last_error("UpdateProcThreadAttribute"));
    }

    let mut command_line = std::iter::once(quote_argument(&program.to_string_lossy()))
        .chain(args.iter().map(|arg| quote_argument(arg)))
        .collect::<Vec<_>>()
        .join(" ")
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<u16>>();
    let mut environment = Vec::<u16>::new();
    for (name, value) in env {
        environment.extend(format!("{name}={value}").encode_utf16());
        environment.push(0);
    }
    environment.push(0);
    let application = wide(program.as_os_str());

    // SAFETY: zeroed STARTUPINFOEXW is valid before the fields are set.
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[1];
    startup.lpAttributeList = list;

    let base = EXTENDED_STARTUPINFO_PRESENT
        | CREATE_UNICODE_ENVIRONMENT
        | DETACHED_PROCESS
        | CREATE_NEW_PROCESS_GROUP;
    for flags in [base | CREATE_BREAKAWAY_FROM_JOB, base] {
        // SAFETY: zeroed PROCESS_INFORMATION is a valid out value.
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: every pointer refers to a live, NUL-terminated buffer or
        // initialized structure for the duration of the call.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                flags,
                environment.as_ptr() as *const c_void,
                ptr::null(),
                &startup.StartupInfo,
                &mut info,
            )
        };
        if created != 0 {
            // SAFETY: the thread handle is owned and not needed.
            unsafe { CloseHandle(info.hThread) };
            return Ok(DetachedProcess {
                handle: OwnedHandle(info.hProcess),
                pid: info.dwProcessId,
            });
        }
    }
    Err(last_error("CreateProcessW"))
}

/// Name of the per-install stop event in the session-local namespace.
pub fn stop_event_name(root: &Path) -> String {
    let digest = Sha256::digest(root.to_string_lossy().to_ascii_lowercase().as_bytes());
    let hex = digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("Local\\Orcel-Stop-{hex}")
}

/// The supervisor's manual-reset stop event. Creation fails if another
/// supervisor for the same install already owns it.
pub struct StopEvent(OwnedHandle);

impl StopEvent {
    pub fn create(name: &str) -> Result<Self, LifecycleError> {
        let name = wide(std::ffi::OsStr::new(name));
        // SAFETY: null attributes are permitted; the name is NUL-terminated.
        let handle = unsafe { CreateEventW(ptr::null(), 1, 0, name.as_ptr()) };
        // SAFETY: GetLastError has no preconditions.
        let already = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        let handle = OwnedHandle::new(handle).ok_or_else(|| last_error("CreateEventW"))?;
        if already {
            return Err(LifecycleError::conflict(
                "another Orcel supervisor for this install is already running",
            ));
        }
        Ok(Self(handle))
    }

    pub fn raw(&self) -> HANDLE {
        self.0.raw()
    }

    /// Signals an existing stop event; returns false if none exists.
    pub fn signal(name: &str) -> bool {
        let name = wide(std::ffi::OsStr::new(name));
        // SAFETY: the name is NUL-terminated.
        match OwnedHandle::new(unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr()) }) {
            // SAFETY: handle opened with EVENT_MODIFY_STATE.
            Some(event) => unsafe { SetEvent(event.raw()) != 0 },
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

    fn ping() -> Command {
        let mut command = Command::new(
            std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
                .join("System32")
                .join("ping.exe"),
        );
        command
            .args(["-n", "30", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    #[test]
    fn identity_detects_pid_reuse_shape_and_exit() {
        let mut child = ping().spawn().unwrap();
        let identity = identify(child.id()).unwrap();
        assert!(identity.image.to_ascii_lowercase().ends_with("ping.exe"));
        assert!(open_verified(&identity).is_some());
        let mut forged = identity.clone();
        forged.creation_time += 1;
        assert!(open_verified(&forged).is_none());
        let live = open_verified(&identity).unwrap();
        assert!(live.terminate());
        assert!(live.wait(Duration::from_secs(10)));
        let _ = child.wait();
        assert!(identify(identity.pid).is_none() || open_verified(&identity).is_none());
    }

    #[test]
    fn suspended_child_is_jobbed_before_resume_and_job_termination_empties_it() {
        let job = Job::kill_on_close().unwrap();
        let mut child = ping().creation_flags(CREATE_SUSPENDED).spawn().unwrap();
        job.assign(child_handle(&child)).unwrap();
        resume_process(child.id()).unwrap();
        assert_eq!(job.active_processes().unwrap(), 1);
        assert!(job
            .terminate_and_confirm_empty(Duration::from_secs(10))
            .unwrap());
        let _ = child.wait();
    }

    #[test]
    fn stop_event_is_exclusive_and_signalable() {
        let name = format!("Local\\Orcel-Test-{}", crate::nonce());
        assert!(!StopEvent::signal(&name));
        let event = StopEvent::create(&name).unwrap();
        assert!(StopEvent::create(&name).is_err());
        assert!(StopEvent::signal(&name));
        assert_eq!(wait_any(&[event.raw()], Duration::from_secs(1)), Some(0));
    }
}
