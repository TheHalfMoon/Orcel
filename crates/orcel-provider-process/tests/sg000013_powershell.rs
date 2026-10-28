#![cfg(windows)]

use orcel_provider_process::{
    build_execution_plan, execute_contained, ExecutionLimits, ExecutionPlan, OutputStream,
    PrivateExecutionFailure,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[link(name = "kernel32")]
extern "system" {
    fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
}

fn system_directory() -> PathBuf {
    const CAPACITY: usize = 32_768;
    let mut buffer = vec![0u16; CAPACITY];
    let copied = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), CAPACITY as u32) };
    assert!(copied > 0, "GetSystemDirectoryW failed");
    let copied = usize::try_from(copied).expect("system directory length");
    assert!(copied < CAPACITY, "system directory path exceeded buffer");
    PathBuf::from(OsString::from_wide(&buffer[..copied]))
}

fn powershell_executable() -> PathBuf {
    let path = system_directory()
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    let path = std::fs::canonicalize(path).expect("canonical inbox Windows PowerShell");
    assert!(path.is_file(), "inbox Windows PowerShell must exist");
    path
}

fn qualification_env() -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for key in [
        "LOCALAPPDATA",
        "SystemRoot",
        "TEMP",
        "TMP",
        "PATH",
        "ComSpec",
    ] {
        env.insert(
            key.to_owned(),
            std::env::var(key).expect("required Windows qualification environment"),
        );
    }
    env.insert("ORCEL_TUNNEL_KEY_FILE".into(), "must-not-leak".into());
    env.insert("OPENAI_API_KEY".into(), "must-not-leak".into());
    env.insert("TEST_SECRET".into(), "must-not-leak".into());
    env
}

fn workspace(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("Orcel.SG000013.{label}.{suffix}"));
    std::fs::create_dir_all(&path).expect("create qualification workspace");
    path
}

fn powershell_plan(root: &PathBuf, script: &str, limits: ExecutionLimits) -> ExecutionPlan {
    let argv = vec![
        "-NoLogo".to_owned(),
        "-NoProfile".to_owned(),
        "-NonInteractive".to_owned(),
        "-Command".to_owned(),
        script.to_owned(),
    ];
    let plan = build_execution_plan(
        root,
        powershell_executable(),
        &argv,
        ".",
        &qualification_env(),
        limits,
    )
    .expect("build fixed bounded PowerShell plan");

    assert_eq!(
        &plan.argv[..4],
        ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]
    );
    assert!(!plan.env.keys().any(|key| key.starts_with("ORCEL_")));
    assert!(!plan.env.keys().any(|key| key.contains("API_KEY")));
    assert!(!plan.env.keys().any(|key| key.contains("SECRET")));
    plan
}

fn profile(label: &str) -> String {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("Orcel.SG000013.{label}.{suffix}")
}

/// #292: the success test's own limit. This test qualifies containment
/// (AppContainer, job assignment before resume, quiescence), not start-up
/// latency: Windows PowerShell 5.1 has twice taken more than 30 s to start
/// inside the AppContainer on a loaded hosted runner (median about 0.4 s
/// locally). Production keeps `ExecutionLimits::default()` (30 s); the
/// timeout path itself is qualified by the 3 s timeout test below.
const COLD_START_ALLOWANCE: Duration = Duration::from_secs(120);

/// How long an uncontained `powershell -Command exit` takes right now: on a
/// failure this separates a slow runner from a containment-specific stall.
fn uncontained_start_millis() -> Option<u128> {
    let started = std::time::Instant::now();
    let status = std::process::Command::new(powershell_executable())
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "exit 0",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()?;
    status.success().then(|| started.elapsed().as_millis())
}

#[test]
fn windows_private_powershell_success_is_bounded_and_quiescent() {
    let root = workspace("Success");
    let script = "$inputText=[Console]::In.ReadToEnd(); if($inputText.Length -ne 0){exit 23}; [Console]::Out.Write('ORCEL_POWERSHELL_OK')";
    let limits = ExecutionLimits {
        timeout: COLD_START_ALLOWANCE,
        ..ExecutionLimits::default()
    };
    assert_eq!(
        ExecutionLimits::default().timeout,
        Duration::from_secs(30),
        "the production default is not changed by this test"
    );
    let plan = powershell_plan(&root, script, limits);
    let started = std::time::Instant::now();
    let result = execute_contained(plan, &profile("Success"));
    let elapsed = started.elapsed();
    // Always in the log, so a slow start is visible even when it passes.
    eprintln!(
        "SG013-EVIDENCE contained PowerShell success took {} ms",
        elapsed.as_millis()
    );
    let result = result.unwrap_or_else(|failure| {
        panic!(
            "contained PowerShell: {failure:?} after {} ms; uncontained start now: {:?} ms; {} CPUs",
            elapsed.as_millis(),
            uncontained_start_millis(),
            std::thread::available_parallelism().map_or(0, usize::from)
        )
    });

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout, b"ORCEL_POWERSHELL_OK");
    assert!(result.stderr.is_empty());
    assert!(result.appcontainer_verified);
    assert!(result.assigned_to_job_before_resume);
    assert!(result.job_quiescent);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn windows_private_powershell_timeout_is_verified_and_typed() {
    let root = workspace("Timeout");
    let limits = ExecutionLimits {
        timeout: Duration::from_secs(3),
        stdout_bytes: 1024,
        stderr_bytes: 1024,
    };
    let plan = powershell_plan(&root, "[Threading.Thread]::Sleep(30000)", limits);
    let result = execute_contained(plan, &profile("Timeout"));
    assert_eq!(result, Err(PrivateExecutionFailure::ProcessTimeout));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn windows_private_powershell_stdout_limit_is_verified_and_typed() {
    let root = workspace("StdoutLimit");
    let limits = ExecutionLimits {
        // A cold, zero-capability AppContainer PowerShell can take well over
        // ten seconds to start on a loaded runner. The generous timeout only
        // gives it time to write; the script then sleeps far longer than the
        // timeout, so the asserted OutputLimit can come only from the limit
        // being enforced, not from a normal exit or the timeout.
        timeout: Duration::from_secs(60),
        stdout_bytes: 32,
        stderr_bytes: 1024,
    };
    let plan = powershell_plan(
        &root,
        "[Console]::Out.Write(('x' * 4096)); [Threading.Thread]::Sleep(120000)",
        limits,
    );
    let result = execute_contained(plan, &profile("StdoutLimit"));
    assert_eq!(
        result,
        Err(PrivateExecutionFailure::OutputLimit(OutputStream::Stdout))
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn windows_private_powershell_stderr_limit_is_verified_and_typed() {
    let root = workspace("StderrLimit");
    let limits = ExecutionLimits {
        // A cold, zero-capability AppContainer PowerShell can take well over
        // ten seconds to start on a loaded runner. The generous timeout only
        // gives it time to write; the script then sleeps far longer than the
        // timeout, so the asserted OutputLimit can come only from the limit
        // being enforced, not from a normal exit or the timeout.
        timeout: Duration::from_secs(60),
        stdout_bytes: 1024,
        stderr_bytes: 32,
    };
    let plan = powershell_plan(
        &root,
        "[Console]::Error.Write(('e' * 4096)); [Threading.Thread]::Sleep(120000)",
        limits,
    );
    let result = execute_contained(plan, &profile("StderrLimit"));
    assert_eq!(
        result,
        Err(PrivateExecutionFailure::OutputLimit(OutputStream::Stderr))
    );
    let _ = std::fs::remove_dir_all(root);
}
