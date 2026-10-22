//! SG-000096 Windows launch of an ordinary current-user child. It reuses the
//! parent module's owned handles, Job Object, suspended `ChildProcess`,
//! pipes and token snapshot; it adds no AppContainer and never elevates.
use super::{
    command_line_for_paths, environment_block, last_error, native_sid_equal, null_input,
    path_for_process_api, wide, AttributeList, ChildProcess, CreateProcessW, ExecutionPlanError,
    GetExitCodeProcess, GetLastError, GetTokenInformation, Handle, JobObject, NativeOwnerSnapshot,
    OpenProcessToken, OwnedHandle, PeekNamedPipe, PrivatePipe, ProcessInformation, ReadFile, Sleep,
    StartupInfoExW, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, ERROR_BROKEN_PIPE, EXTENDED_STARTUPINFO_PRESENT,
    POST_EXIT_DRAIN_TIMEOUT_MS, POST_TERMINATION_DRAIN_TIMEOUT_MS, QUIESCENCE_POLL_MS,
    TOKEN_IS_APP_CONTAINER, TOKEN_QUERY, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use crate::native_path_identity_windows::{FileKey, HeldPath, Kind};
use crate::shell::{
    validate_command, validate_owner, CapturedStream, ExecutableIdentity, ExpectedNativeOwner,
    NativeProcessIdentity, OneShotEnd, OneShotOutcome, ShellCommand, ShellFailure,
    MAX_COMMAND_LINE_UNITS,
};
use std::ffi::OsString;
use std::mem;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{Duration, Instant};

const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
const READ_CHUNK_BYTES: usize = 64 * 1024;
const MAX_IMAGE_PATH_UNITS: u32 = 32_768;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(desired_access: u32, inherit: i32, process_id: u32) -> Handle;
    fn QueryFullProcessImageNameW(
        process: Handle,
        flags: u32,
        name: *mut u16,
        size: *mut u32,
    ) -> i32;
    fn GetProcessId(process: Handle) -> u32;
}

/// Test-only fault injection between creation and resume. Production builds
/// only have `None`, so no production path can reach a fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fault {
    None,
    #[cfg(test)]
    ForeignJob,
    #[cfg(test)]
    InvalidTokenProcess,
    #[cfg(test)]
    WrongSid,
    #[cfg(test)]
    WrongLuid,
    #[cfg(test)]
    WrongSession,
    #[cfg(test)]
    WrongElevation,
    #[cfg(test)]
    WrongGeneration,
    #[cfg(test)]
    WrongImage,
    #[cfg(test)]
    OwnerGone,
}

#[cfg(test)]
pub(super) static LAUNCHES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
pub(super) static LAST_CHILD_PID: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

fn denied(message: impl Into<String>) -> ShellFailure {
    ShellFailure::Denied(message.into())
}

fn unavailable(error: ExecutionPlanError) -> ShellFailure {
    ShellFailure::Unavailable(error.message)
}

pub(crate) fn measure_executable(path: &Path) -> Result<ExecutableIdentity, ShellFailure> {
    let held = HeldPath::open(path, Kind::File).map_err(denied)?;
    let sha256 = held
        .sha
        .ok_or_else(|| denied("executable identity has no digest"))?;
    Ok(ExecutableIdentity {
        path: path.to_path_buf(),
        sha256,
        volume_serial: held.key.volume,
        file_index: held.key.index,
    })
}

/// The expected owner process, reopened by PID and proven to be the same
/// instance (creation generation) with the lease's user and logon session.
pub(super) struct OwnerProcess {
    handle: OwnedHandle,
    snapshot: NativeOwnerSnapshot,
}

impl OwnerProcess {
    pub(super) fn open(expected: &ExpectedNativeOwner) -> Result<Self, ShellFailure> {
        validate_owner(expected)?;
        // SAFETY: OpenProcess takes no pointers; a null result is checked.
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                0,
                expected.owner_pid,
            )
        };
        if raw.is_null() {
            return Err(denied("the Orcel runtime owner is no longer running"));
        }
        let handle = OwnedHandle::new(raw, "OpenProcess(runtime owner)").map_err(unavailable)?;
        let owner = Self {
            snapshot: ChildProcess::snapshot_native_owner(handle.raw()).map_err(unavailable)?,
            handle,
        };
        owner.check_live(expected)?;
        if !native_sid_equal(&owner.snapshot.sid, &expected.user_sid).map_err(unavailable)? {
            return Err(denied(
                "runtime owner user differs from the Full User lease",
            ));
        }
        if owner.snapshot.logon_luid != expected.logon_luid {
            return Err(denied(
                "runtime owner logon session differs from the Full User lease",
            ));
        }
        if owner.snapshot.elevation != 0 {
            return Err(denied(
                "Full User never runs elevated; Full Admin is a separate, unarmed grain",
            ));
        }
        Ok(owner)
    }

    /// Still running and still the instance the runtime record names.
    fn check_live(&self, expected: &ExpectedNativeOwner) -> Result<(), ShellFailure> {
        // SAFETY: the handle is owned and has SYNCHRONIZE access.
        if unsafe { WaitForSingleObject(self.handle.raw(), 0) } != WAIT_TIMEOUT {
            return Err(denied("the Orcel runtime owner exited"));
        }
        if self.snapshot.creation_generation != expected.owner_creation {
            return Err(denied(
                "the runtime owner PID was reused; the authority is stale",
            ));
        }
        Ok(())
    }
}

/// Pins the approved executable and cwd. The handles stay open until after
/// the child resumes, so neither path can be rewritten, renamed or rebound.
pub(super) struct PinnedLaunch {
    pub(super) executable: HeldPath,
    pub(super) cwd: HeldPath,
}

impl PinnedLaunch {
    pub(super) fn open(command: &ShellCommand) -> Result<Self, ShellFailure> {
        let executable = HeldPath::open(&command.executable.path, Kind::File).map_err(denied)?;
        let approved = FileKey {
            volume: command.executable.volume_serial,
            index: command.executable.file_index,
        };
        if executable.key != approved || executable.sha != Some(command.executable.sha256) {
            return Err(denied("the executable changed after it was approved"));
        }
        let cwd = HeldPath::open(&command.cwd, Kind::Directory).map_err(denied)?;
        Ok(Self { executable, cwd })
    }
}

/// The child's stdio. Orcel keeps the read ends; the child's ends are
/// closed here once it is created. A one-shot child reads `NUL`.
pub(super) struct ChildStdio {
    pub(super) stdout: PrivatePipe,
    pub(super) stderr: PrivatePipe,
}

/// Creates the child suspended, puts it in `job`, and verifies it before it
/// runs. On any failure the child is terminated and proven gone.
pub(super) fn launch_verified(
    command: &ShellCommand,
    expected: &ExpectedNativeOwner,
    owner: &OwnerProcess,
    pinned: &PinnedLaunch,
    job: &JobObject,
    fault: Fault,
) -> Result<(ChildProcess, ChildStdio, NativeProcessIdentity), ShellFailure> {
    let environment =
        environment_block(&command.env).map_err(|error| ShellFailure::Invalid(error.message))?;
    let (stdout, stdout_write) = PrivatePipe::create().map_err(unavailable)?;
    let (stderr, stderr_write) = PrivatePipe::create().map_err(unavailable)?;
    let child_stdin = null_input().map_err(unavailable)?;
    let mut child = create_suspended(
        &pinned.executable.path,
        &command.argv,
        &pinned.cwd.path,
        environment,
        [child_stdin.raw(), stdout_write.raw(), stderr_write.raw()],
    )?;
    // The child holds its own duplicates; closing these makes EOF reach the
    // read ends when the child (and its tree) close theirs.
    drop((child_stdin, stdout_write, stderr_write));

    let verified = job
        .assign_before_resume(&child)
        .map_err(|error| error.message)
        .and_then(|()| verify_before_resume(&child, job, expected, owner, pinned, fault));
    let identity = match verified {
        Ok(identity) => identity,
        Err(reason) => return Err(deny_before_resume(&mut child, job, reason)),
    };
    if let Err(error) = child.resume() {
        return Err(deny_before_resume(&mut child, job, error.message));
    }
    Ok((child, ChildStdio { stdout, stderr }, identity))
}

fn create_suspended(
    executable: &Path,
    argv: &[String],
    cwd: &Path,
    mut environment: Vec<u16>,
    handles: [Handle; 3],
) -> Result<ChildProcess, ShellFailure> {
    let attributes = AttributeList::with_handle_list(&handles).map_err(unavailable)?;
    let process_executable = path_for_process_api(executable);
    let application = wide(process_executable.as_os_str());
    let mut command_line = command_line_for_paths(&process_executable, argv);
    if command_line.len() > MAX_COMMAND_LINE_UNITS {
        return Err(ShellFailure::Invalid(
            "shell command line exceeds the CreateProcessW limit".into(),
        ));
    }
    let process_cwd = path_for_process_api(cwd);
    let current_directory = wide(process_cwd.as_os_str());
    // SAFETY: an all-zero STARTUPINFOEXW is a valid empty structure.
    let mut startup: StartupInfoExW = unsafe { mem::zeroed() };
    startup.startup_info.cb = mem::size_of::<StartupInfoExW>() as u32;
    startup.startup_info.h_std_input = handles[0];
    startup.startup_info.h_std_output = handles[1];
    startup.startup_info.h_std_error = handles[2];
    startup.startup_info.dw_flags = STARTF_USESTDHANDLES;
    startup.attribute_list = attributes.raw();
    // SAFETY: an all-zero PROCESS_INFORMATION is a valid out-parameter.
    let mut information: ProcessInformation = unsafe { mem::zeroed() };
    // SAFETY: every pointer is to a NUL-terminated buffer or structure that
    // outlives the call; the attribute list names only the three stdio
    // handles, so the child inherits nothing else even with inheritance on.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT
                | CREATE_NO_WINDOW,
            environment.as_mut_ptr().cast(),
            current_directory.as_ptr(),
            (&startup as *const StartupInfoExW).cast(),
            &mut information,
        )
    };
    if created == 0 {
        return Err(unavailable(last_error("CreateProcessW(current user)")));
    }
    let child = ChildProcess::from_created_process(information).map_err(|error| {
        // from_created_process proved the child gone, or reports it was not.
        if error.message.contains("unverified") {
            ShellFailure::TerminationUnverified(error.message)
        } else {
            ShellFailure::Denied(error.message)
        }
    })?;
    #[cfg(test)]
    {
        LAUNCHES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // SAFETY: the process handle is owned by `child`.
        let pid = unsafe { GetProcessId(child.process.raw()) };
        LAST_CHILD_PID.store(pid, std::sync::atomic::Ordering::SeqCst);
    }
    Ok(child)
}

fn verify_before_resume(
    child: &ChildProcess,
    job: &JobObject,
    expected: &ExpectedNativeOwner,
    owner: &OwnerProcess,
    pinned: &PinnedLaunch,
    fault: Fault,
) -> Result<NativeProcessIdentity, String> {
    #[cfg(not(test))]
    let Fault::None = fault;
    #[cfg(test)]
    let foreign_job;
    #[cfg(test)]
    let job = if fault == Fault::ForeignJob {
        foreign_job = JobObject::kill_on_close().map_err(|error| error.message)?;
        &foreign_job
    } else {
        job
    };
    job.verify_member_before_resume(child)
        .map_err(|error| error.message)?;

    #[cfg(test)]
    let token_process = if fault == Fault::InvalidTokenProcess {
        ptr::null_mut()
    } else {
        child.process.raw()
    };
    #[cfg(not(test))]
    let token_process = child.process.raw();
    if is_app_container(token_process)? {
        return Err("a Full User child must not have an AppContainer token".into());
    }
    #[allow(unused_mut)]
    let mut actual =
        ChildProcess::snapshot_native_owner(token_process).map_err(|error| error.message)?;
    #[allow(unused_mut)]
    let mut expected_sid = expected.user_sid.clone();
    #[allow(unused_mut)]
    let mut expected_luid = expected.logon_luid;
    #[allow(unused_mut)]
    let mut expected_session = owner.snapshot.session_id;
    #[cfg(test)]
    match fault {
        Fault::WrongSid => expected_sid = "S-1-5-18".into(),
        Fault::WrongLuid => expected_luid ^= 1,
        Fault::WrongSession => expected_session ^= 0x8000_0000,
        Fault::WrongElevation => actual.elevation = 1,
        Fault::WrongGeneration => actual.creation_generation = 0,
        _ => {}
    }
    if !native_sid_equal(&actual.sid, &expected_sid).map_err(|error| error.message)? {
        return Err("child user differs from the Full User lease".into());
    }
    if actual.logon_luid != expected_luid {
        return Err("child logon session differs from the Full User lease".into());
    }
    if actual.session_id != expected_session {
        return Err("child Windows session differs from the runtime owner".into());
    }
    if actual.elevation != 0 {
        return Err("a Full User child must not be elevated".into());
    }
    if actual.creation_generation == 0 {
        return Err("child has no native creation generation".into());
    }

    #[allow(unused_mut)]
    let mut image_key = image_key(child)?;
    #[cfg(test)]
    if fault == Fault::WrongImage {
        image_key.index ^= 1;
    }
    let held = pinned.executable.held_key()?;
    if image_key != pinned.executable.key || held != pinned.executable.key {
        return Err("child image is not the approved executable".into());
    }

    #[cfg(test)]
    let owner_expected = if fault == Fault::OwnerGone {
        ExpectedNativeOwner {
            owner_creation: expected.owner_creation ^ 1,
            ..expected.clone()
        }
    } else {
        expected.clone()
    };
    #[cfg(not(test))]
    let owner_expected = expected.clone();
    owner
        .check_live(&owner_expected)
        .map_err(|failure| failure.message().to_owned())?;

    // SAFETY: the process handle is owned by `child`.
    let pid = unsafe { GetProcessId(child.process.raw()) };
    if pid == 0 {
        return Err(last_error("GetProcessId").message);
    }
    Ok(NativeProcessIdentity {
        pid,
        creation_generation: actual.creation_generation,
        user_sid: actual.sid,
        logon_luid: actual.logon_luid,
        session_id: actual.session_id,
    })
}

fn is_app_container(process: Handle) -> Result<bool, String> {
    let mut raw: Handle = ptr::null_mut();
    // SAFETY: `raw` is a valid out-pointer; a failure is checked.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(last_error("OpenProcessToken(AppContainer check)").message);
    }
    let token = OwnedHandle::new(raw, "OpenProcessToken(AppContainer check)")
        .map_err(|error| error.message)?;
    let mut value = 0u32;
    let mut returned = 0u32;
    // SAFETY: `value` is a writable u32, the size TokenIsAppContainer returns.
    if unsafe {
        GetTokenInformation(
            token.raw(),
            TOKEN_IS_APP_CONTAINER,
            (&mut value as *mut u32).cast(),
            mem::size_of::<u32>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(last_error("GetTokenInformation(TokenIsAppContainer)").message);
    }
    Ok(value != 0)
}

/// The file identity of the image the kernel actually mapped for `child`.
fn image_key(child: &ChildProcess) -> Result<FileKey, String> {
    let mut buffer = vec![0u16; MAX_IMAGE_PATH_UNITS as usize];
    let mut size = MAX_IMAGE_PATH_UNITS;
    // SAFETY: `buffer` holds `size` UTF-16 units; the call writes at most that.
    if unsafe { QueryFullProcessImageNameW(child.process.raw(), 0, buffer.as_mut_ptr(), &mut size) }
        == 0
    {
        return Err(last_error("QueryFullProcessImageNameW").message);
    }
    buffer.truncate(size as usize);
    let image = PathBuf::from(OsString::from_wide(&buffer));
    // The mapped image denies writers, so a read-only open sharing reads is
    // enough to name it; the key is compared, the bytes were hashed already.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .open(&image)
        .map_err(|error| format!("open child image: {error}"))?;
    crate::native_path_identity_windows::key(&file)
}

/// Terminates a child that has not run, and the Job, and proves both empty.
fn deny_before_resume(child: &mut ChildProcess, job: &JobObject, reason: String) -> ShellFailure {
    let killed = child.terminate_verified().is_ok();
    let _ = job.terminate();
    let quiet = matches!(job.wait_for_quiescence(), Ok(true));
    if killed && quiet {
        ShellFailure::Denied(reason)
    } else {
        ShellFailure::TerminationUnverified(format!(
            "{reason}; the denied child could not be proven gone"
        ))
    }
}

pub(super) enum PumpState {
    Open,
    Closed,
}

/// Reads what is available on `pipe` into `stream` without blocking.
pub(super) fn pump(
    pipe: &PrivatePipe,
    stream: &mut CapturedStream,
    limit: usize,
    scratch: &mut [u8],
) -> Result<PumpState, String> {
    loop {
        let mut available = 0u32;
        // SAFETY: the read handle is owned; only `available` is written.
        if unsafe {
            PeekNamedPipe(
                pipe.read.raw(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut available,
                ptr::null_mut(),
            )
        } == 0
        {
            // SAFETY: reads the calling thread's last error.
            if unsafe { GetLastError() } == ERROR_BROKEN_PIPE {
                return Ok(PumpState::Closed);
            }
            return Err(last_error("PeekNamedPipe").message);
        }
        if available == 0 {
            return Ok(PumpState::Open);
        }
        let want = (available as usize).min(scratch.len());
        let mut read = 0u32;
        // SAFETY: `scratch` has at least `want` writable bytes; the pipe has
        // `available` bytes, so this ReadFile does not block.
        if unsafe {
            ReadFile(
                pipe.read.raw(),
                scratch.as_mut_ptr().cast(),
                want as u32,
                &mut read,
                ptr::null_mut(),
            )
        } == 0
        {
            // SAFETY: reads the calling thread's last error.
            if unsafe { GetLastError() } == ERROR_BROKEN_PIPE {
                return Ok(PumpState::Closed);
            }
            return Err(last_error("ReadFile").message);
        }
        stream.push(&scratch[..read as usize], limit);
    }
}

/// Pumps both streams until both close or `deadline` passes.
fn drain(
    stdio: &ChildStdio,
    stdout: &mut CapturedStream,
    stderr: &mut CapturedStream,
    limits: (usize, usize),
    deadline: Instant,
    scratch: &mut [u8],
) -> Result<(), String> {
    loop {
        if !stdout.complete {
            if let PumpState::Closed = pump(&stdio.stdout, stdout, limits.0, scratch)? {
                stdout.complete = true;
            }
        }
        if !stderr.complete {
            if let PumpState::Closed = pump(&stdio.stderr, stderr, limits.1, scratch)? {
                stderr.complete = true;
            }
        }
        if (stdout.complete && stderr.complete) || Instant::now() >= deadline {
            return Ok(());
        }
        // SAFETY: Sleep takes no pointers.
        unsafe { Sleep(QUIESCENCE_POLL_MS as u32) };
    }
}

/// Terminates every process left in the Job and proves the Job empty.
pub(super) fn end_job(job: &JobObject) -> Result<(), ShellFailure> {
    let terminated = job.terminate().is_ok();
    if terminated && matches!(job.wait_for_quiescence(), Ok(true)) {
        Ok(())
    } else {
        Err(ShellFailure::TerminationUnverified(
            "the shell Job could not be proven empty".into(),
        ))
    }
}

pub(crate) fn run_one_shot(
    command: &ShellCommand,
    expected: &ExpectedNativeOwner,
) -> Result<OneShotOutcome, ShellFailure> {
    run_one_shot_with(command, expected, Fault::None)
}

pub(super) fn run_one_shot_with(
    command: &ShellCommand,
    expected: &ExpectedNativeOwner,
    fault: Fault,
) -> Result<OneShotOutcome, ShellFailure> {
    validate_command(command)?;
    let owner = OwnerProcess::open(expected)?;
    let pinned = PinnedLaunch::open(command)?;
    let job = JobObject::kill_on_close_with_process_limit(Some(command.limits.max_processes))
        .map_err(unavailable)?;
    let started = Instant::now();
    let (mut child, stdio, process) =
        launch_verified(command, expected, &owner, &pinned, &job, fault)?;
    // The child runs from here. Nothing below retries or relaunches it.
    drop(pinned);
    let limits = (command.limits.stdout_bytes, command.limits.stderr_bytes);
    let mut stdout = CapturedStream::default();
    let mut stderr = CapturedStream::default();
    let mut scratch = vec![0u8; READ_CHUNK_BYTES];
    let deadline = started + command.limits.timeout;

    let ended = supervise(
        &mut child,
        &stdio,
        &mut stdout,
        &mut stderr,
        limits,
        deadline,
    );
    let end = match ended {
        Ok(end) => end,
        Err(message) => {
            // Whatever failed, nothing may outlive the launch.
            end_job(&job)?;
            child.completed = true;
            return Err(ShellFailure::OutcomeUnknown(message));
        }
    };
    let descendants_terminated = match end {
        OneShotEnd::Exited { .. } => {
            let _ = drain(
                &stdio,
                &mut stdout,
                &mut stderr,
                limits,
                Instant::now() + Duration::from_millis(POST_EXIT_DRAIN_TIMEOUT_MS),
                &mut scratch,
            );
            let remaining = job.active_processes().map_err(|error| {
                ShellFailure::OutcomeUnknown(format!("shell Job state unknown: {}", error.message))
            });
            match remaining {
                Ok(0) if stdout.complete && stderr.complete => false,
                Ok(count) => {
                    end_job(&job)?;
                    count > 0
                }
                Err(failure) => {
                    end_job(&job)?;
                    return Err(failure);
                }
            }
        }
        OneShotEnd::TimedOut => {
            end_job(&job)?;
            child.completed = true;
            true
        }
    };
    let _ = drain(
        &stdio,
        &mut stdout,
        &mut stderr,
        limits,
        Instant::now() + Duration::from_millis(POST_TERMINATION_DRAIN_TIMEOUT_MS),
        &mut scratch,
    );
    Ok(OneShotOutcome {
        process,
        end,
        stdout,
        stderr,
        descendants_terminated,
    })
}

fn supervise(
    child: &mut ChildProcess,
    stdio: &ChildStdio,
    stdout: &mut CapturedStream,
    stderr: &mut CapturedStream,
    limits: (usize, usize),
    deadline: Instant,
) -> Result<OneShotEnd, String> {
    let mut scratch = vec![0u8; READ_CHUNK_BYTES];
    loop {
        if !stdout.complete {
            if let PumpState::Closed = pump(&stdio.stdout, stdout, limits.0, &mut scratch)? {
                stdout.complete = true;
            }
        }
        if !stderr.complete {
            if let PumpState::Closed = pump(&stdio.stderr, stderr, limits.1, &mut scratch)? {
                stderr.complete = true;
            }
        }
        // SAFETY: the process handle is owned by `child`.
        match unsafe { WaitForSingleObject(child.process.raw(), 0) } {
            WAIT_OBJECT_0 => {
                let mut exit_code = 0u32;
                // SAFETY: `exit_code` is a valid out-pointer.
                if unsafe { GetExitCodeProcess(child.process.raw(), &mut exit_code) } == 0 {
                    return Err(last_error("GetExitCodeProcess").message);
                }
                child.completed = true;
                return Ok(OneShotEnd::Exited { exit_code });
            }
            WAIT_TIMEOUT => {}
            _ => return Err(last_error("WaitForSingleObject(shell child)").message),
        }
        if Instant::now() >= deadline {
            return Ok(OneShotEnd::TimedOut);
        }
        // SAFETY: Sleep takes no pointers.
        unsafe { Sleep(QUIESCENCE_POLL_MS as u32) };
    }
}

#[cfg(test)]
#[path = "shell_tests.rs"]
mod tests;
