//! WP1-12 (SG-000132): the dispatch Job Objects the service makes, created
//! for real in this unelevated test process (in its session's `Local\`
//! namespace, as the console harness does) with a stand-in service SID.
//!
//! What these tests show: the protected two-entry DACL (the service SID
//! terminate and query, the caller's user assign-process only), that the
//! caller cannot open the job to terminate it, query it, change its limits
//! or its DACL, that an existing name is refused, the kill-on-close and
//! no-breakaway limits, that `CREATE_BREAKAWAY_FROM_JOB` fails inside the
//! job, and that terminating or closing the job ends its processes within
//! one second. What only the installed service can show (a `Global\` job
//! owned by `NT SERVICE\OrcelAuthority`, opened from the user's session) is
//! UNVERIFIED (founder run) in SG132_SLICE3.md.
#![cfg(windows)]

use orcel_authority::core::dispatch_jobs::{job_name, JobHost};
use orcel_authority::win::jobs::{
    create_job, job_sddl, limit_flags, open_job, ServiceJobs, JOB_ASSIGN_PROCESS, JOB_QUERY,
    JOB_TERMINATE, SERVICE_JOB_ACCESS,
};
use std::io::Write;
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
};

/// A stand-in for the service's SID: any SID this test process is not.
const STAND_IN_SERVICE_SID: &str = "S-1-5-18";
/// `JOB_OBJECT_SET_ATTRIBUTES`.
const JOB_SET_ATTRIBUTES: u32 = 0x0010;
/// The helper's environment variable (see `job_helper_child`).
const HELPER: &str = "ORCEL_DISPATCH_JOB_HELPER";

static NEXT: AtomicU32 = AtomicU32::new(0);

fn fresh_name() -> String {
    let random = format!(
        "{:08x}{:08x}{:016x}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
        orcel_authority::now_ms()
    );
    job_name("Local", &random)
}

fn me() -> String {
    orcel_authority::win::current_process_sid().expect("this process's SID")
}

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

/// As orceld does: open by name with assign-process only, assign, close.
fn assign_by_name(name: &str, child: &Child) {
    let job = open_job(name, JOB_ASSIGN_PROCESS).expect("open with assign-process");
    // SAFETY: both handles are valid for the call.
    let assigned = unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle() as _) };
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
fn wp112_the_job_dacl_gives_the_caller_assign_process_only() {
    let name = fresh_name();
    let user = me();
    let job = create_job(&name, &job_sddl(STAND_IN_SERVICE_SID, &user).expect("sddl"))
        .expect("create the job");
    let (_owner, aces) = orcel_authority::win::pipe::pipe_security(job.0).expect("read the DACL");
    let mut aces = aces;
    aces.sort();
    let mut expected = vec![
        (STAND_IN_SERVICE_SID.to_owned(), SERVICE_JOB_ACCESS),
        (user.clone(), JOB_ASSIGN_PROCESS),
    ];
    expected.sort();
    assert_eq!(aces, expected, "exactly the service and the caller");
    assert_eq!(SERVICE_JOB_ACCESS, JOB_TERMINATE | JOB_QUERY);

    // Even as this job's owner, the caller gets nothing but assign-process.
    assert!(open_job(&name, JOB_ASSIGN_PROCESS).is_ok());
    for (what, access) in [
        ("terminate", JOB_TERMINATE),
        ("query", JOB_QUERY),
        ("set attributes", JOB_SET_ATTRIBUTES),
    ] {
        let refused = open_job(&name, access).err();
        assert_eq!(
            refused.and_then(|error| error.raw_os_error()),
            Some(ERROR_ACCESS_DENIED as i32),
            "{what}"
        );
    }
    // Owner rights here (the test is the owner) are the implicit
    // READ_CONTROL and WRITE_DAC; the installed service owns its jobs, so
    // the user has neither there (UNVERIFIED, founder run).

    // A name that exists is refused, never reused.
    let again = create_job(&name, &job_sddl(STAND_IN_SERVICE_SID, &user).expect("sddl"));
    assert!(again.is_err());
    // Malformed SIDs never reach the SDDL.
    assert!(job_sddl("S-1-5-18)(A;;GA;;;WD", &user).is_err());
    assert!(job_sddl(STAND_IN_SERVICE_SID, "WD").is_err());
}

#[test]
fn wp112_the_job_kills_on_close_and_allows_no_breakaway() {
    let name = fresh_name();
    let job = create_job(&name, &job_sddl(STAND_IN_SERVICE_SID, &me()).expect("sddl"))
        .expect("create the job");
    let flags = limit_flags(&job).expect("limits");
    assert_ne!(flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, 0);
    assert_eq!(flags & JOB_OBJECT_LIMIT_BREAKAWAY_OK, 0);
    assert_eq!(flags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, 0);

    let mut child = helper("breakaway");
    assign_by_name(&name, &child);
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
    assign_by_name(&name, &sleeper);
    drop(job);
    assert!(
        exits_within(&mut sleeper, Duration::from_secs(1)).is_some(),
        "closing the last handle ends the job's processes"
    );
}

#[test]
fn wp112_the_service_terminates_a_dispatch_job_within_a_second() {
    let mut jobs = ServiceJobs::new("Local", STAND_IN_SERVICE_SID);
    let name = fresh_name();
    jobs.create(&name, &me()).expect("create");
    assert_eq!(jobs.active_processes(&name), Some(0));
    let mut sleeper = helper("sleep");
    assign_by_name(&name, &sleeper);
    assert_eq!(jobs.active_processes(&name), Some(1));
    let started = Instant::now();
    jobs.terminate(&name);
    assert!(
        exits_within(&mut sleeper, Duration::from_secs(1)).is_some(),
        "terminated within a second"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    // The name is gone with the service's handle: nothing can be assigned
    // to it any more (a revoke between Authorize and the launch).
    assert!(open_job(&name, JOB_ASSIGN_PROCESS).is_err());
    assert_eq!(jobs.active_processes(&name), None);
}
