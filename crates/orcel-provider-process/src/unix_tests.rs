//! XP-13b tests for the Linux and macOS Safe tier. Each run starts this test
//! binary again as the registered executable, running one of the
//! `fixture_*` functions below (they do nothing unless started with
//! `--exact`, as the Windows fixtures in `lib.rs` do). Fixtures report
//! through `ORCEL:` lines on stdout or files in the run's working directory.
//!
//! `ORCEL_REQUIRE_SAFE_CGROUP=1` makes the cgroup tests fail instead of
//! skipping when this process's cgroup is not delegated; CI sets it for a
//! run under `systemd-run -p Delegate=yes`.

use super::*;
use crate::{build_execution_plan, ExecutionLimits};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_WORKSPACE: AtomicU64 = AtomicU64::new(0);

struct Workspace(PathBuf);

impl Workspace {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "orcel-xp13b-{}-{}",
            std::process::id(),
            NEXT_WORKSPACE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        // Explicit, whatever the umask (a systemd unit may use 0002): the
        // Safe tier refuses executables under group-writable directories.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self(std::fs::canonicalize(path).unwrap())
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture_mode() -> bool {
    std::env::args().any(|argument| argument == "--exact")
}

fn fixture_argv(name: &str) -> Vec<String> {
    vec![
        "--exact".to_owned(),
        format!("unix::tests::{name}"),
        "--nocapture".to_owned(),
    ]
}

fn source_env() -> BTreeMap<String, String> {
    std::env::vars()
        .filter(|(name, _)| matches!(name.as_str(), "PATH" | "HOME" | "LANG"))
        .collect()
}

fn plan(workspace: &Workspace, fixture: &str, limits: ExecutionLimits) -> ExecutionPlan {
    build_execution_plan(
        &workspace.0,
        std::env::current_exe().unwrap(),
        &fixture_argv(fixture),
        ".",
        &source_env(),
        limits,
    )
    .unwrap()
}

fn limits(timeout_secs: u64) -> ExecutionLimits {
    ExecutionLimits {
        timeout: Duration::from_secs(timeout_secs),
        stdout_bytes: 64 * 1024,
        stderr_bytes: 64 * 1024,
    }
}

fn reported(stdout: &[u8], key: &str) -> Option<String> {
    let text = std::str::from_utf8(stdout).ok()?;
    let prefix = format!("ORCEL:{key}=");
    text.lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .map(str::to_owned)
}

fn require_cgroup() -> bool {
    std::env::var_os("ORCEL_REQUIRE_SAFE_CGROUP").is_some_and(|value| value == "1")
}

fn wait_for_file(path: &Path, limit: Duration) -> String {
    let deadline = Instant::now() + limit;
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if !text.is_empty() {
                return text;
            }
        }
        assert!(
            Instant::now() < deadline,
            "{} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Alive means signalable and not a zombie.
fn alive(pid: c_int) -> bool {
    // SAFETY: kill with signal 0 only checks that `pid` exists and can be signalled.
    if unsafe { kill(pid, 0) } != 0 {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        let state = stat
            .rfind(')')
            .and_then(|index| stat[index + 1..].split_whitespace().next());
        !matches!(state, Some("Z") | Some("X"))
    }
    #[cfg(not(target_os = "linux"))]
    true
}

fn assert_gone_within(pid: c_int, limit: Duration) {
    let deadline = Instant::now() + limit;
    while alive(pid) {
        assert!(Instant::now() < deadline, "process {pid} outlived the run");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn kill_stray(pid: c_int) {
    // SAFETY: kill takes two integers; this ends a fixture this test started.
    let _ = unsafe { kill(pid, SIGKILL) };
}

// ---- fixtures (run only as the registered executable) ----

#[test]
fn fixture_report_and_exit() {
    if !fixture_mode() {
        return;
    }
    let mut core = Rlimit {
        current: 1,
        maximum: 1,
    };
    let mut cpu = Rlimit {
        current: 0,
        maximum: 0,
    };
    // SAFETY: both are live, writable rlimit structs.
    unsafe {
        getrlimit(RLIMIT_CORE, &mut core);
        getrlimit(RLIMIT_CPU, &mut cpu);
    }
    extern "C" {
        fn getpgrp() -> c_int;
    }
    // SAFETY: getpgrp takes no arguments and cannot fail.
    let leader = unsafe { getpgrp() } == std::process::id() as c_int;
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "ORCEL:leader={leader}");
    let _ = writeln!(stdout, "ORCEL:core={}", core.current);
    let _ = writeln!(stdout, "ORCEL:cpu={}/{}", cpu.current, cpu.maximum);
    let _ = writeln!(stdout, "ORCEL:cgroup={}", cgroup.trim());
    let _ = stdout.flush();
    let _ = writeln!(std::io::stderr(), "ORCEL:stderr=relayed");
    std::process::exit(7);
}

#[test]
fn fixture_sleep() {
    if fixture_mode() {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[test]
fn fixture_flood_stdout() {
    if fixture_mode() {
        let _ = std::io::stdout().write_all(&vec![b'x'; 8192]);
        let _ = std::io::stdout().flush();
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[test]
fn fixture_flood_stderr() {
    if fixture_mode() {
        let _ = std::io::stderr().write_all(&vec![b'x'; 8192]);
        std::thread::sleep(Duration::from_secs(60));
    }
}

/// Write this process's id to `holder.pid` in the working directory, then
/// wait to be killed.
#[test]
fn fixture_hold() {
    if fixture_mode() {
        let _ = std::fs::write("holder.pid", std::process::id().to_string());
        std::thread::sleep(Duration::from_secs(60));
    }
}

fn spawn_grandchild(stdio_inherited: bool, own_group: bool) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(fixture_argv("fixture_sleep"));
    if !stdio_inherited {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    }
    if own_group {
        command.process_group(0);
    }
    let grandchild = command.spawn().unwrap();
    std::fs::write("grandchild.pid", grandchild.id().to_string()).unwrap();
    // Exit without waiting: the grandchild is left behind.
    std::mem::forget(grandchild);
}

#[test]
fn fixture_fork_grandchild_and_exit() {
    if fixture_mode() {
        spawn_grandchild(false, false);
        std::process::exit(0);
    }
}

#[test]
fn fixture_fork_grandchild_holding_stdout_and_exit() {
    if fixture_mode() {
        spawn_grandchild(true, false);
        std::process::exit(0);
    }
}

#[test]
fn fixture_fork_grandchild_into_its_own_group_and_exit() {
    if fixture_mode() {
        spawn_grandchild(false, true);
        std::process::exit(0);
    }
}

/// Plays orceld for the parent-death test: runs `fixture_hold` through the
/// Safe tier with the working directory as the workspace.
#[test]
fn fixture_supervise_a_holder() {
    if fixture_mode() {
        let workspace = std::env::current_dir().unwrap();
        let plan = build_execution_plan(
            &workspace,
            std::env::current_exe().unwrap(),
            &fixture_argv("fixture_hold"),
            ".",
            &source_env(),
            limits(120),
        )
        .unwrap();
        let _ = execute(plan);
    }
}

// ---- tests ----

#[test]
fn xp13b_a_registered_executable_runs_with_bounded_relayed_output() {
    let workspace = Workspace::new();
    let (result, ownership) =
        execute_reporting(plan(&workspace, "fixture_report_and_exit", limits(20))).unwrap();
    assert_eq!(result.exit_code, 7);
    assert_eq!(
        reported(&result.stderr, "stderr").as_deref(),
        Some("relayed")
    );
    assert!(result.job_quiescent && result.assigned_to_job_before_resume);
    assert!(!result.appcontainer_verified);
    // The child leads its own process group and carries the rlimits.
    assert_eq!(reported(&result.stdout, "leader").as_deref(), Some("true"));
    assert_eq!(reported(&result.stdout, "core").as_deref(), Some("0"));
    let cpu = reported(&result.stdout, "cpu").unwrap();
    let (soft, hard) = cpu.split_once('/').unwrap();
    assert!(soft.parse::<u64>().unwrap() <= 21, "cpu soft limit {cpu}");
    assert!(hard.parse::<u64>().unwrap() <= 22, "cpu hard limit {cpu}");
    let cgroup = reported(&result.stdout, "cgroup").unwrap_or_default();
    match ownership {
        TreeOwnership::ProcessGroupAndCgroup => {
            assert!(cgroup.contains("/orcel-exec-"), "{cgroup}")
        }
        TreeOwnership::ProcessGroup => {
            assert!(
                !require_cgroup(),
                "a delegated cgroup was required but not used"
            );
            assert!(!cgroup.contains("/orcel-exec-"), "{cgroup}");
        }
    }
}

#[test]
fn xp13b_a_run_past_its_timeout_is_killed_and_typed() {
    let workspace = Workspace::new();
    let started = Instant::now();
    let error = execute(plan(&workspace, "fixture_sleep", limits(1))).unwrap_err();
    assert_eq!(error, PrivateExecutionFailure::ProcessTimeout);
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn xp13b_output_past_its_bound_is_killed_and_stream_typed() {
    let workspace = Workspace::new();
    let mut bounded = limits(20);
    bounded.stdout_bytes = 1024;
    let error = execute(plan(&workspace, "fixture_flood_stdout", bounded.clone())).unwrap_err();
    assert_eq!(
        error,
        PrivateExecutionFailure::OutputLimit(OutputStream::Stdout)
    );
    bounded.stdout_bytes = 64 * 1024;
    bounded.stderr_bytes = 1024;
    let error = execute(plan(&workspace, "fixture_flood_stderr", bounded)).unwrap_err();
    assert_eq!(
        error,
        PrivateExecutionFailure::OutputLimit(OutputStream::Stderr)
    );
}

/// The card's negative test: a child that forks a grandchild and exits. The
/// run succeeds, and the grandchild does not outlive it.
#[test]
fn xp13b_a_child_that_forks_a_grandchild_is_cleaned_up() {
    for fixture in [
        "fixture_fork_grandchild_and_exit",
        // The grandchild keeps the run's stdout open: the bounded drain
        // ends, the tree is killed, and the run still completes.
        "fixture_fork_grandchild_holding_stdout_and_exit",
    ] {
        let workspace = Workspace::new();
        let result = execute(plan(&workspace, fixture, limits(20)))
            .unwrap_or_else(|error| panic!("{fixture}: {error:?}"));
        assert_eq!(result.exit_code, 0, "{fixture}");
        assert!(result.job_quiescent);
        let pid: c_int = wait_for_file(&workspace.0.join("grandchild.pid"), Duration::from_secs(1))
            .parse()
            .unwrap();
        assert_gone_within(pid, Duration::from_secs(5));
    }
}

/// A grandchild that leaves the process group. With a delegated cgroup it is
/// still killed. Without one it survives: the documented residual risk
/// (`unix.rs`), pinned here and cleaned up by the test.
#[test]
fn xp13b_a_grandchild_that_leaves_the_group() {
    let workspace = Workspace::new();
    let (result, ownership) = execute_reporting(plan(
        &workspace,
        "fixture_fork_grandchild_into_its_own_group_and_exit",
        limits(20),
    ))
    .unwrap();
    assert_eq!(result.exit_code, 0);
    let pid: c_int = wait_for_file(&workspace.0.join("grandchild.pid"), Duration::from_secs(1))
        .parse()
        .unwrap();
    match ownership {
        TreeOwnership::ProcessGroupAndCgroup => assert_gone_within(pid, Duration::from_secs(5)),
        TreeOwnership::ProcessGroup => {
            assert!(
                !require_cgroup(),
                "a delegated cgroup was required but not used"
            );
            assert!(
                alive(pid),
                "the residual risk changed: update unix.rs and this test"
            );
            kill_stray(pid);
        }
    }
}

/// The card's recovery test on Linux: killing the supervising process (here
/// a fixture standing in for orceld) kills the child, through
/// `PR_SET_PDEATHSIG`. macOS has no equivalent (documented in `unix.rs`).
#[cfg(target_os = "linux")]
#[test]
fn xp13b_killing_the_supervisor_kills_the_child() {
    let workspace = Workspace::new();
    let mut supervisor = Command::new(std::env::current_exe().unwrap())
        .args(fixture_argv("fixture_supervise_a_holder"))
        .current_dir(&workspace.0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let holder: c_int = wait_for_file(&workspace.0.join("holder.pid"), Duration::from_secs(20))
        .parse()
        .unwrap();
    assert!(alive(holder));
    supervisor.kill().unwrap();
    supervisor.wait().unwrap();
    let started = Instant::now();
    while alive(holder) && started.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    let survived = alive(holder);
    if survived {
        kill_stray(holder);
    }
    assert!(!survived, "the child outlived its supervisor");
}

#[test]
fn xp13b_an_invalid_plan_is_refused_before_anything_starts() {
    let workspace = Workspace::new();
    let mut bad = plan(&workspace, "fixture_sleep", limits(20));
    bad.limits.timeout = Duration::ZERO;
    assert!(matches!(
        execute(bad),
        Err(PrivateExecutionFailure::InvalidPlan(_))
    ));
}

#[test]
fn xp13b_cpu_limits_never_exceed_the_current_hard_limit() {
    let limits = child_rlimits(Duration::from_secs(30)).unwrap();
    let (_, core) = limits[0];
    assert_eq!((core.current, core.maximum), (0, 0));
    let (_, cpu) = limits[1];
    assert!(cpu.current <= cpu.maximum);
    assert!(cpu.maximum <= 32);
}

/// A copy of this test binary in a fresh directory, both owner-only writable.
fn copied_executable(workspace: &Workspace, name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = workspace.0.join(format!("{name}-bin"));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let copy = dir.join(name);
    std::fs::copy(std::env::current_exe().unwrap(), &copy).unwrap();
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755)).unwrap();
    copy
}

fn digest_of(path: &Path) -> String {
    crate::contained::sha256_hex(&std::fs::read(path).unwrap())
}

/// XP-13b (judge M1): the launched file is the one whose digest matched.
/// The right digest runs; a wrong one, or a file swapped in after the
/// digest was taken, is refused before anything starts.
#[test]
fn xp13b_the_launched_file_must_match_the_registered_digest() {
    let workspace = Workspace::new();
    let mut good = plan(&workspace, "fixture_report_and_exit", limits(20));
    good.registered_sha256 = Some(digest_of(&good.executable));
    assert_eq!(execute(good.clone()).unwrap().exit_code, 7);

    let mut wrong = good.clone();
    wrong.registered_sha256 = Some("0".repeat(64));
    assert_eq!(
        execute(wrong).unwrap_err(),
        PrivateExecutionFailure::IdentityChanged
    );

    // Pin a copy, then swap other bytes in under the same name.
    let copy = copied_executable(&workspace, "swapped");
    let mut swapped = good.clone();
    swapped.executable = copy.clone();
    swapped.registered_sha256 = Some(digest_of(&copy));
    let replacement = copy.with_file_name("replacement");
    std::fs::write(&replacement, b"\x7fELF not the registered bytes").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::rename(&replacement, &copy).unwrap();
    assert_eq!(
        execute(swapped).unwrap_err(),
        PrivateExecutionFailure::IdentityChanged
    );
}

/// XP-13b (judge M1): an executable another local user could replace is
/// refused before it is opened: a group- or world-writable file, or a
/// group- or world-writable directory above it (a user-owned sticky one too).
#[test]
fn xp13b_an_executable_others_can_replace_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let workspace = Workspace::new();
    let copy = copied_executable(&workspace, "shared");
    let mut shared = plan(&workspace, "fixture_report_and_exit", limits(20));
    shared.executable = copy.clone();
    let rejected = |plan: &ExecutionPlan| {
        matches!(
            execute(plan.clone()),
            Err(PrivateExecutionFailure::ExecutableRejected(_))
        )
    };
    for mode in [0o775, 0o757] {
        std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(rejected(&shared), "file mode {mode:o}");
    }
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755)).unwrap();
    let dir = copy.parent().unwrap().to_path_buf();
    for mode in [0o775, 0o777, 0o1777] {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(rejected(&shared), "directory mode {mode:o}");
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!rejected(&shared));
}
