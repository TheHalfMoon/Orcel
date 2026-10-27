//! SG-000108 worker process supervision on Windows.
//!
//! The worker (Node.js running the private browser worker) starts
//! suspended, is assigned to a kill-on-close Job Object with the SG-000074
//! active-process limit, and only then resumes, so neither it nor the engine
//! it launches ever runs outside the job. Inheritance is restricted with
//! `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` to exactly the child's stdin read end,
//! stdout write end and a `NUL` stderr: no other inheritable handle of the
//! host reaches the worker. The job can be inspected (process ids, image
//! paths, OS command lines split with `CommandLineToArgvW`) and is
//! terminated, with confirmation, when supervision ends.

use crate::error::HostError;
use crate::supervise::platform::{Job, OwnedHandle};
use crate::supervise::CleanEnv;
use crate::worker_launch::JobProcess;
use std::ffi::c_void;
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{Duration, Instant};
use windows_sys::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessCommandLineInformation,
};
use windows_sys::Win32::Foundation::{
    LocalFree, SetHandleInformation, BOOL, GENERIC_WRITE, HANDLE, HANDLE_FLAG_INHERIT,
    STATUS_INFO_LENGTH_MISMATCH, STILL_ACTIVE, UNICODE_STRING, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, CREATE_ALWAYS, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::{
    JobObjectBasicAccountingInformation, JobObjectBasicProcessIdList, QueryInformationJobObject,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, OpenProcess, QueryFullProcessImageNameW, ResumeThread,
    TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, DETACHED_PROCESS, EXTENDED_STARTUPINFO_PRESENT,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};
use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

/// Upper bound on process ids read from one job snapshot.
const MAX_JOB_SNAPSHOT: usize = 64;

/// The worker process and its job. Dropping it terminates the job.
pub(crate) struct WorkerProcess {
    job: std::sync::Arc<Job>,
    process: OwnedHandle,
    pid: u32,
}

/// The host's ends of the worker's stdio pipes.
pub(crate) struct WorkerPipes {
    pub stdin: File,
    pub stdout: File,
}

fn platform_error(context: &str) -> HostError {
    HostError::Platform(format!("{context}: {}", std::io::Error::last_os_error()))
}

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

/// Quote one argument with the rules `CommandLineToArgvW` reverses:
/// backslashes are literal unless they precede a quote, so runs before a
/// quote (or the closing quote) are doubled.
pub(crate) fn quote_argument(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\u{b}', '"']) {
        return arg.to_owned();
    }
    let mut quoted = String::from("\"");
    let mut slashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => slashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(slashes * 2 + 1));
                quoted.push('"');
                slashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(slashes));
                quoted.push(ch);
                slashes = 0;
            }
        }
    }
    quoted.push_str(&"\\".repeat(slashes * 2));
    quoted.push('"');
    quoted
}

/// Split a command line with the OS function the comparison relies on.
pub(crate) fn split_command_line(line: &[u16]) -> Result<Vec<String>, HostError> {
    let mut terminated: Vec<u16> = line.to_vec();
    terminated.push(0);
    let mut count: i32 = 0;
    // SAFETY: `terminated` is NUL-terminated and outlives the call; the
    // returned block is freed once below.
    let argv = unsafe { CommandLineToArgvW(terminated.as_ptr(), &mut count) };
    if argv.is_null() {
        return Err(platform_error("CommandLineToArgvW"));
    }
    let mut out = Vec::with_capacity(count.max(0) as usize);
    for index in 0..count.max(0) as usize {
        // SAFETY: CommandLineToArgvW returns `count` NUL-terminated strings.
        let arg = unsafe { *argv.add(index) };
        let mut len = 0usize;
        // SAFETY: walk to the terminator of a string owned by the block.
        while unsafe { *arg.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: `len` code units are readable.
        let slice = unsafe { std::slice::from_raw_parts(arg, len) };
        out.push(String::from_utf16_lossy(slice));
    }
    // SAFETY: the block came from CommandLineToArgvW and is freed once.
    unsafe { LocalFree(argv as _) };
    Ok(out)
}

struct AttributeList {
    buffer: Vec<u64>,
}

impl AttributeList {
    /// A one-entry attribute list restricting inheritance to `handles`.
    fn handle_list(handles: &[HANDLE]) -> Result<Self, HostError> {
        let mut size = 0usize;
        // SAFETY: a null list with a size query is the documented first call.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut size) };
        if size == 0 {
            return Err(platform_error("InitializeProcThreadAttributeList size"));
        }
        let mut list = Self {
            buffer: vec![0u64; size.div_ceil(8)],
        };
        // SAFETY: the buffer is at least `size` bytes and 8-byte aligned.
        if unsafe { InitializeProcThreadAttributeList(list.raw(), 1, 0, &mut size) } == 0 {
            let error = platform_error("InitializeProcThreadAttributeList");
            // Never initialized: Drop must not delete it.
            list.buffer.clear();
            return Err(error);
        }
        // SAFETY: `handles` outlives CreateProcessW (the caller keeps it
        // alive); the size covers exactly the slice.
        if unsafe {
            UpdateProcThreadAttribute(
                list.raw(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr() as *const c_void,
                std::mem::size_of_val(handles),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            let error = platform_error("UpdateProcThreadAttribute(HANDLE_LIST)");
            // SAFETY: the list was initialized above.
            unsafe { DeleteProcThreadAttributeList(list.raw()) };
            list.buffer.clear();
            return Err(error);
        }
        Ok(list)
    }

    fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buffer.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        if !self.buffer.is_empty() {
            // SAFETY: initialized list, deleted exactly once.
            unsafe { DeleteProcThreadAttributeList(self.raw()) };
        }
    }
}

fn inheritable() -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1 as BOOL,
    }
}

/// An anonymous pipe whose `child` end is inheritable and whose `host` end
/// is not.
fn pipe(child_reads: bool) -> Result<(OwnedHandle, OwnedHandle), HostError> {
    let attributes = inheritable();
    let mut read: HANDLE = 0;
    let mut write: HANDLE = 0;
    // SAFETY: out-pointers are valid; attributes outlive the call.
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
        return Err(platform_error("CreatePipe"));
    }
    let read = OwnedHandle::new(read).ok_or_else(|| platform_error("CreatePipe read"))?;
    let write = OwnedHandle::new(write).ok_or_else(|| platform_error("CreatePipe write"))?;
    let (child, host) = if child_reads {
        (read, write)
    } else {
        (write, read)
    };
    // SAFETY: valid handle; clears only the inherit flag of the host end.
    if unsafe { SetHandleInformation(host.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(platform_error("SetHandleInformation"));
    }
    Ok((child, host))
}

fn null_output() -> Result<OwnedHandle, HostError> {
    let attributes = inheritable();
    let name = wide(std::ffi::OsStr::new("NUL"));
    // SAFETY: NUL-terminated name and valid attributes for the call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attributes,
            OPEN_EXISTING,
            0,
            0,
        )
    };
    OwnedHandle::new(handle).ok_or_else(|| platform_error("CreateFileW(NUL)"))
}

/// #438 (test builds only): the worker's stderr into a new file, so a
/// failed launch's reason can be read back.
fn file_output(path: &Path) -> Result<OwnedHandle, HostError> {
    let attributes = inheritable();
    let name = wide(path.as_os_str());
    // SAFETY: NUL-terminated name and valid attributes for the call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attributes,
            CREATE_ALWAYS,
            0,
            0,
        )
    };
    OwnedHandle::new(handle).ok_or_else(|| platform_error("CreateFileW(stderr log)"))
}

/// Start `program args…` suspended in a fresh job with exactly the stdio
/// handles inherited and the given environment, then resume it. Stderr goes
/// to `NUL`, or (test builds only, #438) to `stderr_log`.
pub(crate) fn spawn(
    program: &Path,
    args: &[String],
    env: &CleanEnv,
    stderr_log: Option<&Path>,
) -> Result<(WorkerProcess, WorkerPipes), HostError> {
    let job = Job::create()?;
    let (child_stdin, host_stdin) = pipe(true)?;
    let (child_stdout, host_stdout) = pipe(false)?;
    let child_stderr = match stderr_log {
        // Best effort: a log that cannot be created (held by a scanner, say)
        // falls back to NUL rather than failing the launch.
        Some(path) => match file_output(path) {
            Ok(handle) => handle,
            Err(_) => null_output()?,
        },
        None => null_output()?,
    };
    let inherited = [child_stdin.raw(), child_stdout.raw(), child_stderr.raw()];
    let mut attributes = AttributeList::handle_list(&inherited)?;

    let program_text = program.to_string_lossy();
    let mut command = quote_argument(&program_text);
    for arg in args {
        command.push(' ');
        command.push_str(&quote_argument(arg));
    }
    let mut command: Vec<u16> = command.encode_utf16().chain(Some(0)).collect();
    let mut environment: Vec<u16> = Vec::new();
    for (key, value) in env {
        environment.extend(key.encode_wide());
        environment.push('=' as u16);
        environment.extend(value.encode_wide());
        environment.push(0);
    }
    environment.push(0);
    let application = wide(program.as_os_str());

    // SAFETY: zeroed STARTUPINFOEXW is valid before the fields are set.
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = child_stdin.raw();
    startup.StartupInfo.hStdOutput = child_stdout.raw();
    startup.StartupInfo.hStdError = child_stderr.raw();
    startup.lpAttributeList = attributes.raw();
    // SAFETY: zeroed PROCESS_INFORMATION is a valid out-parameter.
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: every buffer is NUL-terminated and outlives the call; the
    // attribute list restricts inheritance to `inherited`, which is alive.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT
                | CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | DETACHED_PROCESS,
            environment.as_ptr() as *const c_void,
            ptr::null(),
            &startup.StartupInfo,
            &mut info,
        )
    };
    drop(attributes);
    if created == 0 {
        // node.exe was validated as an existing file; a failure here is a
        // launch failure (access, resources), not a runtime refusal.
        return Err(platform_error("CreateProcessW(worker)"));
    }
    let process =
        OwnedHandle::new(info.hProcess).ok_or_else(|| platform_error("CreateProcessW process"))?;
    let thread =
        OwnedHandle::new(info.hThread).ok_or_else(|| platform_error("CreateProcessW thread"))?;
    // The child owns its copies now.
    drop(child_stdin);
    drop(child_stdout);
    drop(child_stderr);
    if let Err(error) = job.assign(process.raw()) {
        // SAFETY: valid handle of the still-suspended process.
        unsafe { TerminateProcess(process.raw(), 1) };
        return Err(error);
    }
    // SAFETY: valid primary thread handle of a suspended process.
    if unsafe { ResumeThread(thread.raw()) } == u32::MAX {
        let error = platform_error("ResumeThread");
        job.terminate();
        return Err(error);
    }
    // SAFETY: the host ends are owned here and transferred to `File`.
    let stdin = unsafe { File::from_raw_handle(host_stdin.into_raw() as _) };
    // SAFETY: as above.
    let stdout = unsafe { File::from_raw_handle(host_stdout.into_raw() as _) };
    Ok((
        WorkerProcess {
            job: std::sync::Arc::new(job),
            process,
            pid: info.dwProcessId,
        },
        WorkerPipes { stdin, stdout },
    ))
}

impl WorkerProcess {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    /// Wait up to `timeout` for the worker to exit; its exit code if it did.
    pub(crate) fn wait_exit(&self, timeout: Duration) -> Option<u32> {
        let millis = timeout.as_millis().min(u32::MAX as u128 - 1) as u32;
        // SAFETY: valid process handle.
        if unsafe { WaitForSingleObject(self.process.raw(), millis) } != WAIT_OBJECT_0 {
            return None;
        }
        let mut code = 0u32;
        // SAFETY: valid process handle and out-pointer.
        (unsafe { GetExitCodeProcess(self.process.raw(), &mut code) } != 0).then_some(code)
    }

    /// Processes currently assigned to the job.
    pub(crate) fn active_processes(&self) -> Result<u32, HostError> {
        // SAFETY: zeroed accounting information is a valid out-parameter.
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: pointer and size describe `info`.
        if unsafe {
            QueryInformationJobObject(
                self.job.handle(),
                JobObjectBasicAccountingInformation,
                &mut info as *mut _ as *mut c_void,
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(platform_error("QueryInformationJobObject(accounting)"));
        }
        Ok(info.ActiveProcesses)
    }

    /// Every process in the job with its image path and OS command line. A
    /// process that exits during the snapshot is skipped; any other failure
    /// to inspect a member fails closed.
    pub(crate) fn snapshot(&self) -> Result<Vec<JobProcess>, HostError> {
        let ids = self.member_ids()?;
        let mut processes = Vec::with_capacity(ids.len());
        for pid in ids {
            match inspect(pid) {
                Ok(Some(process)) => processes.push(process),
                Ok(None) => {}
                // A member that cannot be inspected is acceptable only if it
                // has left the job in the meantime; otherwise fail closed.
                Err(error) => {
                    if self.member_ids()?.contains(&pid) {
                        return Err(error);
                    }
                }
            }
        }
        Ok(processes)
    }

    /// The process ids currently in the job.
    fn member_ids(&self) -> Result<Vec<u32>, HostError> {
        const HEADER: usize = 2;
        let mut buffer = vec![0usize; HEADER + MAX_JOB_SNAPSHOT];
        // SAFETY: the buffer is laid out as JOBOBJECT_BASIC_PROCESS_ID_LIST
        // (two u32 counts, then pointer-sized ids at the next aligned offset).
        if unsafe {
            QueryInformationJobObject(
                self.job.handle(),
                JobObjectBasicProcessIdList,
                buffer.as_mut_ptr() as *mut c_void,
                std::mem::size_of_val(buffer.as_slice()) as u32,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(platform_error("QueryInformationJobObject(process ids)"));
        }
        // SAFETY: the first 8 bytes hold the two u32 counts.
        let counts = unsafe { std::slice::from_raw_parts(buffer.as_ptr() as *const u32, 2) };
        let (assigned, listed) = (counts[0] as usize, counts[1] as usize);
        if assigned > listed || listed > MAX_JOB_SNAPSHOT {
            return Err(HostError::Invalid(
                "browser job holds more processes than can be inspected".into(),
            ));
        }
        let ids_offset = std::mem::size_of::<u32>() * 2;
        let ids = &buffer[ids_offset / std::mem::size_of::<usize>()..][..listed];
        Ok(ids.iter().map(|&pid| pid as u32).collect())
    }

    /// A reference to the job that never keeps it alive (for cancellation
    /// from another thread).
    pub(crate) fn job_weak(&self) -> std::sync::Weak<Job> {
        std::sync::Arc::downgrade(&self.job)
    }

    /// Terminate the whole job and wait until no process remains.
    pub(crate) fn terminate_and_confirm(&self, timeout: Duration) -> bool {
        self.job.terminate();
        let deadline = Instant::now() + timeout;
        loop {
            if matches!(self.active_processes(), Ok(0)) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Test-only: put another process into the worker's job.
    #[cfg(test)]
    pub(crate) fn assign_pid(&self, pid: u32) -> Result<(), HostError> {
        use windows_sys::Win32::System::Threading::{PROCESS_SET_QUOTA, PROCESS_TERMINATE};
        // SAFETY: plain open of a process the test owns.
        let handle = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };
        let handle = OwnedHandle::new(handle).ok_or_else(|| platform_error("OpenProcess"))?;
        self.job.assign(handle.raw())
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        self.job.terminate();
    }
}

/// Every process on the machine whose command line contains `marker`,
/// except the calling process. Processes that cannot be opened (other
/// users, protected) are skipped: an engine this host started can always be
/// opened by it.
#[cfg(test)]
pub(crate) fn processes_with_command_line_containing(marker: &str) -> Vec<JobProcess> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    // SAFETY: a process snapshot with documented flags.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let snapshot = OwnedHandle::new(snapshot).expect("process snapshot");
    // SAFETY: zeroed PROCESSENTRY32W with dwSize set is the documented input.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut found = Vec::new();
    // SAFETY: valid snapshot handle and entry out-pointer.
    let mut more = unsafe { Process32FirstW(snapshot.raw(), &mut entry) } != 0;
    while more {
        let pid = entry.th32ProcessID;
        if pid != std::process::id() && pid != 0 {
            if let Ok(Some(process)) = inspect(pid) {
                if process.argv.iter().any(|arg| arg.contains(marker)) {
                    found.push(process);
                }
            }
        }
        // SAFETY: as above.
        more = unsafe { Process32NextW(snapshot.raw(), &mut entry) } != 0;
    }
    found
}

pub(crate) fn inspect(pid: u32) -> Result<Option<JobProcess>, HostError> {
    // SAFETY: plain open with query-only rights.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    let Some(handle) = OwnedHandle::new(handle) else {
        return Err(platform_error("OpenProcess(job member)"));
    };
    // Chromium starts and ends short-lived helpers; a member that exits
    // while it is inspected is skipped, a live one that cannot be inspected
    // fails closed.
    match read_member(&handle, pid) {
        Ok(process) => Ok(Some(process)),
        Err(_) if has_exited(&handle) => Ok(None),
        Err(error) => Err(error),
    }
}

fn has_exited(handle: &OwnedHandle) -> bool {
    let mut code = 0u32;
    // SAFETY: valid handle and out-pointer.
    let queried = unsafe { GetExitCodeProcess(handle.raw(), &mut code) } != 0;
    queried && code != STILL_ACTIVE as u32
}

fn read_member(handle: &OwnedHandle, pid: u32) -> Result<JobProcess, HostError> {
    let mut image = vec![0u16; 32_768];
    let mut size = image.len() as u32;
    // SAFETY: buffer and size describe `image`.
    if unsafe { QueryFullProcessImageNameW(handle.raw(), 0, image.as_mut_ptr(), &mut size) } == 0 {
        return Err(platform_error("QueryFullProcessImageNameW"));
    }
    let image = PathBuf::from(String::from_utf16_lossy(&image[..size as usize]));
    let mut buffer = vec![0u64; 8192];
    let mut needed = 0u32;
    // Bounded: a size that does not grow (or a persistent mismatch) fails
    // closed instead of retrying forever.
    let mut attempts = 0;
    loop {
        attempts += 1;
        let bytes = std::mem::size_of_val(buffer.as_slice()) as u32;
        // SAFETY: buffer and size describe `buffer`; the API writes a
        // UNICODE_STRING followed by its characters.
        let status = unsafe {
            NtQueryInformationProcess(
                handle.raw(),
                ProcessCommandLineInformation,
                buffer.as_mut_ptr() as *mut c_void,
                bytes,
                &mut needed,
            )
        };
        let current = std::mem::size_of_val(buffer.as_slice());
        if status == STATUS_INFO_LENGTH_MISMATCH
            && attempts < 4
            && (needed as usize) > current
            && (needed as usize) <= 1 << 20
        {
            buffer = vec![0u64; (needed as usize).div_ceil(8) + 1];
            continue;
        }
        if status < 0 {
            return Err(HostError::Platform(format!(
                "NtQueryInformationProcess(command line) status {status:#x}"
            )));
        }
        break;
    }
    // SAFETY: the buffer starts with the UNICODE_STRING the API wrote (the
    // u64 buffer satisfies its alignment).
    let string = unsafe { &*(buffer.as_ptr() as *const UNICODE_STRING) };
    let text: &[u16] = if string.Buffer.is_null() || string.Length == 0 {
        // An empty command line may come with a null Buffer, which must not
        // reach from_raw_parts.
        &[]
    } else {
        // SAFETY: a non-null Buffer points into `buffer` and holds `Length`
        // bytes of UTF-16.
        unsafe { std::slice::from_raw_parts(string.Buffer, string.Length as usize / 2) }
    };
    let argv = split_command_line(text)?;
    Ok(JobProcess { pid, image, argv })
}
