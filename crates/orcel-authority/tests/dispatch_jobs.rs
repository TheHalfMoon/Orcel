//! WP1-10 (SG-000132): the dispatch Job Objects the service makes, created
//! for real in this unelevated test process. The test process plays both
//! sides: the service (creating the unnamed job and holding the full
//! handle) and orceld (receiving the duplicated assign-only handle).
//!
//! What these tests show: the duplicated handle carries assign-process only
//! (terminate and query are refused through it, assign works) and is not
//! inheritable; a job is made only for the process the service observed
//! (same PID and creation time); the kill-on-close and no-breakaway limits;
//! that `CREATE_BREAKAWAY_FROM_JOB` fails inside the job; and that
//! terminating or closing the job ends its processes within one second.
//! Jobs have no name, so there is nothing to pre-create or squat. What only
//! the installed service can show (a handle duplicated from
//! `NT SERVICE\OrcelAuthority` into orceld after impersonating it) is
//! UNVERIFIED (founder run) in SG132_SLICE3.md.
#![cfg(windows)]

use orcel_authority::caller::CallerFacts;
use orcel_authority::core::dispatch_jobs::{DispatchJob, JobHost};
use orcel_authority::win::jobs::{
    active_processes, create_job, limit_flags, ui_limits, ClientProcess, ClientSlot, ServiceJobs,
    JOB_UI_LIMITS,
};
use std::io::Write;
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetHandleInformation, GetLastError, ERROR_ACCESS_DENIED, HANDLE,
    HANDLE_FLAG_INHERIT,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, TerminateJobObject, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
};

/// The helper's environment variable (see `job_helper_child`).
const HELPER: &str = "ORCEL_DISPATCH_JOB_HELPER";

/// Not a test of its own: the child process the tests below start. Without
/// the environment variable it does nothing.
#[test]
fn job_helper_child() {
    let Ok(mode) = std::env::var(HELPER) else {
        return;
    };
    match mode.as_str() {
        "sleep" => {
            std::thread::sleep(Duration::from_secs(60));
            std::process::exit(0);
        }
        "breakaway" => {
            // Wait until the parent assigned this process to the job.
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            use std::os::windows::process::CommandExt;
            const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
            let spawned = Command::new(std::env::current_exe().expect("exe"))
                .arg("--list")
                .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
            std::process::exit(match spawned {
                Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => 0,
                Ok(mut child) => {
                    let _ = child.kill();
                    1
                }
                Err(_) => 2,
            });
        }
        _ => std::process::exit(3),
    }
}

fn helper(mode: &str) -> Child {
    Command::new(std::env::current_exe().expect("this test's path"))
        .args([
            "--exact",
            "job_helper_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(HELPER, mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the helper")
}

/// This process as the service observed it.
fn me() -> (CallerFacts, ClientSlot) {
    let opened = ClientProcess::open(std::process::id()).expect("open this process");
    let facts = CallerFacts {
        pid: opened.pid,
        process_generation: opened.generation,
        image: String::new(),
        user_sid: orcel_authority::win::current_process_sid().expect("sid"),
        logon_session_id: 1,
        ts_session_id: 1,
        interactive: true,
        console_session: true,
        elevated: false,
    };
    (facts, Arc::new(Mutex::new(Some(opened))))
}

fn service_job(jobs: &mut ServiceJobs, slot: &ClientSlot, facts: &CallerFacts) -> DispatchJob {
    if slot.lock().expect("slot").is_none() {
        *slot.lock().expect("slot") =
            Some(ClientProcess::open(std::process::id()).expect("open this process"));
    }
    let id = format!(
        "fcj-{:08x}{:024x}",
        std::process::id(),
        orcel_authority::now_ms()
    );
    jobs.create(&id, facts).expect("create the job")
}

fn assign(handle: HANDLE, child: &Child) {
    // SAFETY: both handles are valid for the call.
    let assigned = unsafe { AssignProcessToJobObject(handle, child.as_raw_handle() as _) };
    assert_ne!(assigned, 0, "assign: {}", std::io::Error::last_os_error());
}

fn exits_within(child: &mut Child, limit: Duration) -> Option<i32> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status.code().unwrap_or(-1));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

#[test]
fn wp110_the_duplicated_handle_carries_assign_process_only() {
    let (facts, slot) = me();
    let mut jobs = ServiceJobs::new(slot.clone());
    let job = service_job(&mut jobs, &slot, &facts);
    let handle = job.handle as HANDLE;
    assert_ne!(handle, 0);
    // SAFETY: a handle this process holds; the call only reads its flags.
    let mut flags = 0u32;
    assert_ne!(unsafe { GetHandleInformation(handle, &mut flags) }, 0);
    assert_eq!(flags & HANDLE_FLAG_INHERIT, 0, "never inheritable");
    // SAFETY: the call is refused for lack of JOB_OBJECT_TERMINATE.
    assert_eq!(unsafe { TerminateJobObject(handle, 1) }, 0);
    // SAFETY: plain call right after the failure.
    assert_eq!(unsafe { GetLastError() }, ERROR_ACCESS_DENIED);
    assert!(limit_flags(handle).is_err(), "no JOB_OBJECT_QUERY");
    assert!(active_processes(handle).is_err(), "no JOB_OBJECT_QUERY");
    let mut sleeper = helper("sleep");
    assign(handle, &sleeper);
    assert_eq!(jobs.active_processes(&job.id), Some(1));
    // SAFETY: orceld closes its handle right after assigning.
    unsafe { CloseHandle(handle) };
    jobs.terminate(&job.id);
    assert!(exits_within(&mut sleeper, Duration::from_secs(1)).is_some());
}

#[test]
fn wp110_a_job_is_made_only_for_the_observed_caller_instance() {
    let (facts, slot) = me();
    let mut jobs = ServiceJobs::new(slot.clone());
    // Another PID than the opened process: refused.
    let other = CallerFacts {
        pid: facts.pid.wrapping_add(4),
        ..facts.clone()
    };
    assert!(jobs
        .create(&format!("fcj-{}", "1".repeat(32)), &other)
        .is_err());
    // Same PID, another creation time (a recycled PID): refused.
    *slot.lock().expect("slot") = Some(ClientProcess::open(std::process::id()).expect("open"));
    let recycled = CallerFacts {
        process_generation: facts.process_generation.wrapping_add(1),
        ..facts.clone()
    };
    assert!(jobs
        .create(&format!("fcj-{}", "2".repeat(32)), &recycled)
        .is_err());
    // Nothing opened for this request: refused.
    assert!(slot.lock().expect("slot").is_none());
    assert!(jobs
        .create(&format!("fcj-{}", "3".repeat(32)), &facts)
        .is_err());
}

#[test]
fn wp110_the_job_kills_on_close_and_allows_no_breakaway() {
    let job = create_job().expect("create the job");
    let flags = limit_flags(job.0).expect("limits");
    assert_ne!(flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, 0);
    assert_eq!(flags & JOB_OBJECT_LIMIT_BREAKAWAY_OK, 0);
    assert_eq!(flags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, 0);
    // WP1-15: the UI restrictions (USER handles, atoms, desktop, clipboard,
    // exit, system parameters, display settings) are set on every job.
    assert_eq!(ui_limits(job.0).expect("UI restrictions"), JOB_UI_LIMITS);
    assert_eq!(JOB_UI_LIMITS, 0xff);

    let mut child = helper("breakaway");
    assign(job.0, &child);
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"go\n")
        .expect("release the helper");
    assert_eq!(
        exits_within(&mut child, Duration::from_secs(30)),
        Some(0),
        "CREATE_BREAKAWAY_FROM_JOB must fail with access denied inside the job"
    );

    let mut sleeper = helper("sleep");
    assign(job.0, &sleeper);
    drop(job);
    assert!(
        exits_within(&mut sleeper, Duration::from_secs(1)).is_some(),
        "closing the last handle ends the job's processes"
    );
}

#[test]
fn wp110_the_service_terminates_a_dispatch_job_within_a_second() {
    let (facts, slot) = me();
    let mut jobs = ServiceJobs::new(slot.clone());
    let job = service_job(&mut jobs, &slot, &facts);
    assert_eq!(jobs.active_processes(&job.id), Some(0));
    let mut sleeper = helper("sleep");
    assign(job.handle as HANDLE, &sleeper);
    assert_eq!(jobs.active_processes(&job.id), Some(1));
    let started = Instant::now();
    jobs.terminate(&job.id);
    assert!(
        exits_within(&mut sleeper, Duration::from_secs(1)).is_some(),
        "terminated within a second"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(jobs.active_processes(&job.id), None);
    // SAFETY: the duplicated handle is this process's to close.
    unsafe { CloseHandle(job.handle as HANDLE) };
}
