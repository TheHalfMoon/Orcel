//! SG-000096 T02/T02-C native Windows qualification of the current-user
//! launcher. Every expected owner comes from a MAC-verified Full User lease
//! in a disposable store, as orceld derives it; nothing here is granted to a
//! real user or reachable outside tests.
use super::super::{fixed_system_executable, GetCurrentProcess};
use super::*;
use crate::shell::ShellLimits;
use std::collections::BTreeMap;
use std::io::Write as _;
use std::sync::atomic::Ordering;
use std::sync::MutexGuard;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const FIXTURE_PREFIX: &str = "windows_contained_launch::shell::tests::";

/// Only a child launched by `fixture` passes this extra filter (it names no
/// test), so `cargo test -- --exact <fixture>` never runs a fixture body.
pub(crate) const FIXTURE_CHILD_ARG: &str = "sg96-fixture-child";

pub(crate) fn fixture_mode() -> bool {
    std::env::args().any(|argument| argument == FIXTURE_CHILD_ARG)
}

pub(crate) fn serial() -> MutexGuard<'static, ()> {
    crate::contained_launch_tests::ENVIRONMENT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) struct Disposable(pub(crate) PathBuf);
impl Drop for Disposable {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}

pub(crate) fn disposable(label: &str) -> Disposable {
    let root = std::env::temp_dir().join(format!(
        "orcel-sg96-shell-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("disposable root");
    Disposable(root)
}

/// The expected owner exactly as orceld derives it: from the lease that a
/// MAC-verified store returns and the runtime session it names. The test
/// can only grant a disposable lease to itself, so the lease's SID and logon
/// LUID are this process's; they reach the launcher through the store.
pub(crate) fn protected_owner(root: &Path) -> ExpectedNativeOwner {
    use orcel_policy::full_control::{
        check_full_control, AuthorityContext, AuthorityMode, ElevationState,
    };
    use orcel_policy::full_control_store;
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no close.
    let me =
        ChildProcess::snapshot_native_owner(unsafe { GetCurrentProcess() }).expect("own token");
    let session_id = format!(
        "orcel-session-{}-{:016x}-0123456789abcdef0123456789abcdef",
        std::process::id(),
        me.creation_generation
    );
    let store = root.join("full-control.json");
    let key = [0x3cu8; 32];
    full_control_store::grant_local(
        &store,
        &key,
        AuthorityMode::FullUser,
        60_000,
        me.sid,
        me.logon_luid,
        session_id,
        now_ms(),
    )
    .expect("disposable lease");
    let status = full_control_store::load_store(&store, &key).expect("MAC-verified store");
    let lease = status.lease.expect("live lease");
    let device = full_control_store::derive_device_id(&key);
    check_full_control(
        &lease,
        &AuthorityContext {
            windows_user_sid: &lease.windows_user_sid,
            logon_session_id: lease.logon_session_id,
            device_id: &device,
            orcel_session_id: &lease.orcel_session_id,
            policy_revision: &lease.policy_revision,
            authority_epoch: status.authority_epoch,
            now_ms: now_ms(),
            elevation_state: ElevationState::Standard,
            elevation_proof_id: None,
        },
    )
    .expect("lease checks");
    full_control_store::validate_runtime_session(&lease.orcel_session_id)
        .expect("runtime owner live");
    let rest = lease
        .orcel_session_id
        .strip_prefix("orcel-session-")
        .expect("session prefix");
    let mut parts = rest.splitn(3, '-');
    let owner_pid = parts.next().unwrap().parse().unwrap();
    let owner_creation = u64::from_str_radix(parts.next().unwrap(), 16).unwrap();
    ExpectedNativeOwner {
        user_sid: lease.windows_user_sid,
        logon_luid: lease.logon_session_id,
        owner_pid,
        owner_creation,
    }
}

pub(crate) fn environment() -> BTreeMap<String, String> {
    let source: BTreeMap<String, String> = std::env::vars().collect();
    let mut env = crate::sanitized_execution_env(&source);
    let temp = std::env::temp_dir().to_string_lossy().into_owned();
    for name in ["TEMP", "TMP"] {
        if !env.keys().any(|key| key.eq_ignore_ascii_case(name)) {
            env.insert(name.into(), temp.clone());
        }
    }
    env
}

pub(crate) fn limits() -> ShellLimits {
    ShellLimits {
        timeout: Duration::from_secs(30),
        stdout_bytes: 64 * 1024,
        stderr_bytes: 64 * 1024,
        max_processes: 8,
    }
}

pub(crate) fn command_for(executable: &Path, argv: Vec<String>, cwd: &Path) -> ShellCommand {
    ShellCommand {
        executable: measure_executable(executable).expect("measure executable"),
        argv,
        cwd: cwd.to_path_buf(),
        env: environment(),
        limits: limits(),
    }
}

pub(crate) fn fixture(name: &str, cwd: &Path) -> ShellCommand {
    fixture_at(FIXTURE_PREFIX, name, cwd)
}

/// A fixture test function under `prefix` (its module path), run as a child.
pub(crate) fn fixture_at(prefix: &str, name: &str, cwd: &Path) -> ShellCommand {
    let exe = std::env::current_exe().expect("test binary");
    command_for(
        &exe,
        vec![
            "--exact".into(),
            format!("{prefix}{name}"),
            "--nocapture".into(),
            "--test-threads=1".into(),
            FIXTURE_CHILD_ARG.into(),
        ],
        cwd,
    )
}

pub(crate) fn system_tool(name: &str) -> PathBuf {
    fixed_system_executable()
        .expect("system directory")
        .with_file_name(name)
}

/// The process is gone: it cannot be opened, or its handle is signaled.
pub(crate) fn process_gone(pid: u32) -> bool {
    // SAFETY: OpenProcess takes no pointers; a null result is checked.
    let raw = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
    if raw.is_null() {
        return true;
    }
    let handle = OwnedHandle::new(raw, "OpenProcess(test)").expect("handle");
    // SAFETY: the handle is owned and has SYNCHRONIZE access.
    unsafe { WaitForSingleObject(handle.raw(), 2_000) == WAIT_OBJECT_0 }
}

fn launches() -> usize {
    LAUNCHES.load(Ordering::SeqCst)
}

/// Whether this test process runs with an elevated token. GitHub's
/// `windows-latest` runner runs tests elevated (an administrator with UAC
/// off), and a standard-user desktop does not.
pub(crate) fn elevated_host() -> bool {
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no close.
    ChildProcess::snapshot_native_owner(unsafe { GetCurrentProcess() })
        .expect("own token")
        .elevation
        != 0
}

/// On an elevated host the launcher must refuse: Full User never runs
/// elevated, and Full Admin is a separate, unarmed grain. This asserts that
/// refusal with zero launches and returns true, so the caller stops there.
/// The positive native paths are qualified on a standard-user host.
pub(crate) fn refuses_on_elevated_host(
    command: &ShellCommand,
    owner: &ExpectedNativeOwner,
) -> bool {
    if !elevated_host() {
        return false;
    }
    let before = launches();
    let result = run_one_shot(command, owner);
    assert!(
        matches!(&result, Err(ShellFailure::Denied(message)) if message.contains("elevated")),
        "an elevated host must refuse Full User: {result:?}"
    );
    assert_eq!(launches(), before, "an elevated host created a process");
    true
}

// ---- fixtures: no-ops unless run as a child with --exact ----

#[test]
fn sg96_fixture_sleep() {
    if fixture_mode() {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[test]
fn sg96_fixture_marker() {
    if fixture_mode() {
        let _ = std::fs::write("ran.marker", b"ran");
    }
}

#[test]
fn sg96_fixture_flood() {
    if fixture_mode() {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(&vec![b'o'; 1 << 20]);
        let _ = out.flush();
        let mut err = std::io::stderr().lock();
        let _ = err.write_all(&vec![b'e'; 300_000]);
        let _ = err.flush();
    }
}

#[test]
fn sg96_fixture_endless_output() {
    if fixture_mode() {
        let mut out = std::io::stdout().lock();
        let chunk = vec![b'z'; 64 * 1024];
        while out.write_all(&chunk).is_ok() {}
    }
}

#[test]
fn sg96_fixture_unicode() {
    if fixture_mode() {
        let mut err = std::io::stderr().lock();
        let _ = err.write_all("h\u{e9}llo \u{2713} \u{65e5}\u{672c}\n".as_bytes());
        let _ = err.write_all(&[0, 0xff, 0xfe, b'\n']);
        let _ = err.flush();
    }
}

#[test]
fn sg96_fixture_descendant() {
    if fixture_mode() {
        let exe = std::env::current_exe().expect("exe");
        let child = std::process::Command::new(exe)
            .args([
                "--exact",
                &format!("{FIXTURE_PREFIX}sg96_fixture_sleep"),
                "--nocapture",
                FIXTURE_CHILD_ARG,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn descendant");
        eprintln!("descendant={}", child.id());
        std::mem::forget(child);
    }
}

#[test]
fn sg96_fixture_spawn_probe() {
    if fixture_mode() {
        let spawned = std::process::Command::new(system_tool("whoami.exe"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        eprintln!(
            "{}",
            if spawned.is_ok() {
                "spawn-ok"
            } else {
                "spawn-denied"
            }
        );
    }
}

#[test]
fn sg96_fixture_env() {
    if fixture_mode() {
        for (name, _) in std::env::vars() {
            eprintln!("env={name}");
        }
    }
}

// ---- qualification ----

#[test]
fn sg000096_t02_current_user_one_shot_is_verified_bounded_and_quiescent() {
    let _serial = serial();
    let root = disposable("ok");
    let owner = protected_owner(&root.0);
    let command = command_for(&system_tool("whoami.exe"), Vec::new(), &root.0);
    if refuses_on_elevated_host(&command, &owner) {
        return;
    }
    let outcome = run_one_shot(&command, &owner).expect("approved current-user launch");
    assert_eq!(outcome.end, OneShotEnd::Exited { exit_code: 0 });
    assert!(outcome.stdout.complete && outcome.stderr.complete);
    assert!(!outcome.stdout.bytes.is_empty());
    assert_eq!(outcome.stdout.dropped_bytes, 0);
    assert!(!outcome.descendants_terminated);
    assert_eq!(outcome.process.user_sid, owner.user_sid);
    assert_eq!(outcome.process.logon_luid, owner.logon_luid);
    assert_ne!(outcome.process.creation_generation, 0);
    assert!(process_gone(outcome.process.pid));
}

#[test]
fn sg000096_t02c_owner_mismatch_is_denied_before_any_process_exists() {
    let _serial = serial();
    let root = disposable("owner");
    let owner = protected_owner(&root.0);
    let command = command_for(&system_tool("whoami.exe"), Vec::new(), &root.0);
    let exited = std::process::Command::new(system_tool("whoami.exe"))
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("short-lived process");
    let exited_pid = exited.id();
    let _ = exited.wait_with_output();
    let cases: Vec<(&str, ExpectedNativeOwner)> = vec![
        (
            "wrong SID",
            ExpectedNativeOwner {
                user_sid: "S-1-5-18".into(),
                ..owner.clone()
            },
        ),
        (
            "wrong logon LUID",
            ExpectedNativeOwner {
                logon_luid: owner.logon_luid ^ 1,
                ..owner.clone()
            },
        ),
        (
            "owner generation drift (PID reuse)",
            ExpectedNativeOwner {
                owner_creation: owner.owner_creation ^ 1,
                ..owner.clone()
            },
        ),
        (
            "owner exited",
            ExpectedNativeOwner {
                owner_pid: exited_pid,
                ..owner.clone()
            },
        ),
        (
            "malformed SID",
            ExpectedNativeOwner {
                user_sid: "not-a-sid".into(),
                ..owner.clone()
            },
        ),
    ];
    for (label, expected) in cases {
        let before = launches();
        let result = run_one_shot(&command, &expected);
        assert!(
            matches!(result, Err(ShellFailure::Denied(_))),
            "{label}: {result:?}"
        );
        assert_eq!(launches(), before, "{label}: no process may be created");
    }
}

#[test]
fn sg000096_t02c_pre_resume_faults_terminate_a_child_that_never_ran() {
    let _serial = serial();
    let root = disposable("faults");
    let owner = protected_owner(&root.0);
    if refuses_on_elevated_host(&fixture("sg96_fixture_marker", &root.0), &owner) {
        return;
    }
    for fault in [
        Fault::ForeignJob,
        Fault::InvalidTokenProcess,
        Fault::WrongSid,
        Fault::WrongLuid,
        Fault::WrongSession,
        Fault::WrongElevation,
        Fault::WrongGeneration,
        Fault::WrongImage,
        Fault::OwnerGone,
    ] {
        let cwd = root.0.join(format!("{fault:?}"));
        std::fs::create_dir_all(&cwd).expect("cwd");
        let command = fixture("sg96_fixture_marker", &cwd);
        let before = launches();
        let result = run_one_shot_with(&command, &owner, fault);
        assert!(
            matches!(result, Err(ShellFailure::Denied(_))),
            "{fault:?}: {result:?}"
        );
        assert_eq!(launches(), before + 1, "{fault:?}: the child was created");
        let pid = LAST_CHILD_PID.load(Ordering::SeqCst);
        assert!(
            process_gone(pid),
            "{fault:?}: denied child {pid} still alive"
        );
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            !cwd.join("ran.marker").exists(),
            "{fault:?}: a denied child ran user code"
        );
    }
    // The same fixture, unfaulted, does run: the marker proves the probe.
    let cwd = root.0.join("unfaulted");
    std::fs::create_dir_all(&cwd).expect("cwd");
    let outcome = run_one_shot(&fixture("sg96_fixture_marker", &cwd), &owner).expect("runs");
    assert_eq!(outcome.end, OneShotEnd::Exited { exit_code: 0 });
    assert!(cwd.join("ran.marker").exists());
}

#[test]
fn sg000096_t02_executable_and_cwd_drift_are_denied_before_creation() {
    let _serial = serial();
    let root = disposable("drift");
    let owner = protected_owner(&root.0);
    let copy = root.0.join("tool.exe");
    std::fs::copy(system_tool("whoami.exe"), &copy).expect("copy tool");
    let approved = command_for(&copy, Vec::new(), &root.0);
    // On an elevated host the owner check refuses first, so the drift
    // checks below would not be the cause of a denial: assert the elevation
    // refusal there instead, and qualify drift on a standard-user host.
    if refuses_on_elevated_host(&approved, &owner) {
        return;
    }

    let mut wrong_hash = approved.clone();
    wrong_hash.executable.sha256[0] ^= 1;
    let mut wrong_index = approved.clone();
    wrong_index.executable.file_index ^= 1;
    for (label, command) in [("hash", wrong_hash), ("file index", wrong_index)] {
        let before = launches();
        assert!(
            matches!(run_one_shot(&command, &owner), Err(ShellFailure::Denied(_))),
            "{label}"
        );
        assert_eq!(launches(), before, "{label}");
    }

    // The bytes change after approval: the pinned digest no longer matches.
    std::fs::copy(system_tool("hostname.exe"), &copy).expect("replace tool");
    let before = launches();
    assert!(matches!(
        run_one_shot(&approved, &owner),
        Err(ShellFailure::Denied(_))
    ));
    assert_eq!(launches(), before);

    // A cwd reached through a junction is refused.
    let real = root.0.join("real");
    std::fs::create_dir_all(&real).expect("real");
    let junction = root.0.join("junction");
    let made = std::process::Command::new(fixed_system_executable().expect("cmd"))
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&real)
        .output()
        .expect("mklink");
    assert!(made.status.success());
    let mut through_junction = command_for(&system_tool("whoami.exe"), Vec::new(), &root.0);
    through_junction.cwd = junction;
    let before = launches();
    assert!(matches!(
        run_one_shot(&through_junction, &owner),
        Err(ShellFailure::Denied(_))
    ));
    assert_eq!(launches(), before);
}

#[test]
fn sg000096_t02_timeout_is_typed_with_no_exit_status_and_an_empty_job() {
    let _serial = serial();
    let root = disposable("timeout");
    let owner = protected_owner(&root.0);
    let mut command = fixture("sg96_fixture_sleep", &root.0);
    command.limits.timeout = Duration::from_secs(1);
    if refuses_on_elevated_host(&command, &owner) {
        return;
    }
    let started = Instant::now();
    let outcome = run_one_shot(&command, &owner).expect("timeout is an outcome");
    assert_eq!(outcome.end, OneShotEnd::TimedOut);
    assert!(outcome.descendants_terminated);
    assert!(started.elapsed() < Duration::from_secs(15));
    assert!(process_gone(outcome.process.pid));
}

#[test]
fn sg000096_t02_output_is_separated_bounded_and_counts_dropped_bytes() {
    let _serial = serial();
    let root = disposable("flood");
    let owner = protected_owner(&root.0);
    let mut command = fixture("sg96_fixture_flood", &root.0);
    command.limits.stdout_bytes = 4096;
    command.limits.stderr_bytes = 4096;
    if refuses_on_elevated_host(&command, &owner) {
        return;
    }
    let outcome = run_one_shot(&command, &owner).expect("flood runs");
    assert_eq!(outcome.end, OneShotEnd::Exited { exit_code: 0 });
    assert_eq!(outcome.stderr.bytes, vec![b'e'; 4096]);
    assert_eq!(outcome.stderr.total_bytes, 300_000);
    assert_eq!(outcome.stderr.dropped_bytes, 300_000 - 4096);
    assert!(outcome.stderr.complete);
    assert_eq!(outcome.stdout.bytes.len(), 4096);
    assert!(outcome.stdout.total_bytes >= 1 << 20);
    assert_eq!(
        outcome.stdout.dropped_bytes,
        outcome.stdout.total_bytes - 4096
    );
    assert!(outcome.stdout.complete);
}

#[test]
fn sg000096_t02_unicode_and_binary_output_is_returned_exactly() {
    let _serial = serial();
    let root = disposable("unicode");
    let owner = protected_owner(&root.0);
    if refuses_on_elevated_host(&fixture("sg96_fixture_unicode", &root.0), &owner) {
        return;
    }
    let outcome = run_one_shot(&fixture("sg96_fixture_unicode", &root.0), &owner).expect("runs");
    let mut expected = "h\u{e9}llo \u{2713} \u{65e5}\u{672c}\n".as_bytes().to_vec();
    expected.extend_from_slice(&[0, 0xff, 0xfe, b'\n']);
    assert_eq!(outcome.stderr.bytes, expected);
}

#[test]
fn sg000096_t02_a_descendant_left_behind_is_terminated_not_detached() {
    let _serial = serial();
    let root = disposable("descendant");
    let owner = protected_owner(&root.0);
    if refuses_on_elevated_host(&fixture("sg96_fixture_descendant", &root.0), &owner) {
        return;
    }
    let outcome = run_one_shot(&fixture("sg96_fixture_descendant", &root.0), &owner).expect("runs");
    assert_eq!(outcome.end, OneShotEnd::Exited { exit_code: 0 });
    assert!(outcome.descendants_terminated);
    let text = String::from_utf8_lossy(&outcome.stderr.bytes);
    let pid: u32 = text
        .lines()
        .find_map(|line| line.strip_prefix("descendant="))
        .expect("descendant pid")
        .trim()
        .parse()
        .expect("pid");
    assert!(process_gone(pid), "descendant {pid} outlived the launch");
}

#[test]
fn sg000096_t02_job_process_limit_bounds_the_tree() {
    let _serial = serial();
    let root = disposable("limit");
    let owner = protected_owner(&root.0);
    let mut command = fixture("sg96_fixture_spawn_probe", &root.0);
    command.limits.max_processes = 1;
    if refuses_on_elevated_host(&command, &owner) {
        return;
    }
    let outcome = run_one_shot(&command, &owner).expect("runs");
    assert!(String::from_utf8_lossy(&outcome.stderr.bytes).contains("spawn-denied"));
    command.limits.max_processes = 4;
    let outcome = run_one_shot(&command, &owner).expect("runs");
    assert!(String::from_utf8_lossy(&outcome.stderr.bytes).contains("spawn-ok"));
}

#[test]
fn sg000096_t02_child_environment_is_exactly_the_allowlisted_set() {
    let _serial = serial();
    let root = disposable("env");
    let owner = protected_owner(&root.0);
    let command = fixture("sg96_fixture_env", &root.0);
    if refuses_on_elevated_host(&command, &owner) {
        return;
    }
    let outcome = run_one_shot(&command, &owner).expect("runs");
    let text = String::from_utf8_lossy(&outcome.stderr.bytes);
    let names: Vec<&str> = text
        .lines()
        .filter_map(|line| line.strip_prefix("env="))
        .collect();
    assert!(!names.is_empty());
    for name in &names {
        assert!(
            crate::shell::environment_name_allowed(name),
            "child saw {name:?}"
        );
    }
    let mut leaking = command.clone();
    leaking.env.insert("ORCEL_DAEMON".into(), "x".into());
    assert!(matches!(
        run_one_shot(&leaking, &owner),
        Err(ShellFailure::Invalid(_))
    ));
}

/// A child that writes without pause still times out: reading output can
/// never starve the exit and deadline checks.
#[test]
fn sg000096_t02_endless_output_cannot_starve_the_timeout() {
    let _serial = serial();
    let root = disposable("endless");
    let owner = protected_owner(&root.0);
    let mut command = fixture("sg96_fixture_endless_output", &root.0);
    command.limits.timeout = Duration::from_secs(2);
    command.limits.stdout_bytes = 4096;
    let started = Instant::now();
    if refuses_on_elevated_host(&command, &owner) {
        return;
    }
    let outcome = run_one_shot(&command, &owner).expect("timeout is an outcome");
    assert_eq!(outcome.end, OneShotEnd::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(20));
    assert_eq!(outcome.stdout.bytes.len(), 4096);
    assert!(outcome.stdout.dropped_bytes > 0);
    assert!(process_gone(outcome.process.pid));
}

/// The native creation generation of `pid`, as the runtime record keeps it.
pub(crate) fn creation_generation_of(pid: u32) -> u64 {
    // SAFETY: OpenProcess takes no pointers; a null result is checked.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
    let handle = OwnedHandle::new(raw, "OpenProcess(test owner)").expect("owner handle");
    ChildProcess::snapshot_native_owner(handle.raw())
        .expect("owner snapshot")
        .creation_generation
}
