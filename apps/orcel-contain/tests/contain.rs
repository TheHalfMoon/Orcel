//! XP-13 end-to-end tests: the real `orcel-contain` helper, started the way
//! orceld starts it (the std-only client in
//! `crates/orcel-provider-process/src/contained.rs`, pinned by SHA-256), runs
//! the `orcel-contain-probe` fixture. Each denial is paired with the same
//! probe run uncontained, which must succeed, so a denial cannot pass merely
//! because the operation was broken.
//!
//! Nothing here skips: on a platform where the helper cannot install every
//! boundary these tests fail, they do not pass vacuously.

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use orcel_provider_process::contained::{
    decode_result, encode_spec, run_contained, sha256_hex, ContainedError, ContainedLimits,
    ContainedOutcome, ContainedRun, ContainedSpec, ContainedStream, HelperPin, RefusalKind,
};

const WRITE_FAILED: i64 = 10;
const READ_FAILED: i64 = 11;
const NETWORK_FAILED: i64 = 12;
const SPAWN_FAILED: i64 = 13;
const LINK_FAILED: i64 = 14;

fn helper_path() -> PathBuf {
    std::fs::canonicalize(env!("CARGO_BIN_EXE_orcel-contain")).unwrap()
}

fn pin_of(path: &Path) -> HelperPin {
    let path = std::fs::canonicalize(path).unwrap();
    HelperPin::new(&path, &sha256_hex(&std::fs::read(&path).unwrap())).unwrap()
}

fn helper_pin() -> HelperPin {
    pin_of(&helper_path())
}

/// A private tree per test: the probe copied into its own directory (which is
/// not granted; only the probe file is), a working directory, a granted read
/// root, a granted write root and an outside directory nothing grants.
struct Fixture {
    _root: tempfile::TempDir,
    probe: PathBuf,
    work: PathBuf,
    readable: PathBuf,
    writable: PathBuf,
    outside: PathBuf,
}

/// Tests run in parallel, so a sibling test may fork while this copy's write
/// descriptor is open; that child holds the descriptor until it execs, and
/// executing the copy meanwhile fails with ETXTBSY. Wait until the copy runs.
fn is_text_file_busy(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    return error.raw_os_error() == Some(libc::ETXTBSY);
    #[cfg(not(unix))]
    return {
        let _ = error;
        false
    };
}

fn settle_copied_executable(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        // The probe exits 0 for `noop`; the helper refuses an empty stdin.
        // Either way it started, which is all this waits for.
        let started = Command::new(path)
            .arg("noop")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match started {
            Ok(_) => return,
            Err(error) if is_text_file_busy(&error) => {
                assert!(
                    Instant::now() < deadline,
                    "the copied executable stayed busy"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("the copied executable cannot start: {error}"),
        }
    }
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::Builder::new().prefix("xp13-").tempdir().unwrap();
        let base = std::fs::canonicalize(root.path()).unwrap();
        let dir = |name: &str| {
            let path = base.join(name);
            std::fs::create_dir(&path).unwrap();
            path
        };
        let bin = dir("bin");
        let work = dir("work");
        let readable = dir("readable");
        let writable = dir("writable");
        let outside = dir("outside");
        let probe = bin.join(if cfg!(windows) { "probe.exe" } else { "probe" });
        std::fs::copy(env!("CARGO_BIN_EXE_orcel-contain-probe"), &probe).unwrap();
        settle_copied_executable(&probe);
        std::fs::write(readable.join("granted.txt"), b"granted bytes").unwrap();
        std::fs::write(outside.join("secret.txt"), b"outside bytes").unwrap();
        Self {
            _root: root,
            probe,
            work,
            readable,
            writable,
            outside,
        }
    }

    fn spec(&self, args: &[&str]) -> ContainedSpec {
        ContainedSpec {
            executable: self.probe.clone(),
            argv: args.iter().map(|arg| (*arg).to_owned()).collect(),
            workdir: self.work.clone(),
            readable: vec![self.readable.clone()],
            writable: vec![self.writable.clone()],
            limits: ContainedLimits {
                timeout: Duration::from_secs(30),
                stdout_bytes: 64 * 1024,
                stderr_bytes: 16 * 1024,
                memory_bytes: 1 << 30,
                cpu_seconds: 30,
                open_files: 256,
            },
        }
    }

    fn contained(&self, args: &[&str]) -> ContainedRun {
        let spec = self.spec(args);
        match run_contained(&helper_pin(), &spec) {
            Ok(run) => run,
            Err(error) => panic!("contained run of {args:?} failed: {error:?}"),
        }
    }

    /// The same probe, same arguments, no containment.
    fn uncontained(&self, args: &[&str]) -> i64 {
        let status = Command::new(&self.probe)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        i64::from(status.code().unwrap_or(-1))
    }
}

fn exited(run: &ContainedRun) -> i64 {
    match run.outcome {
        ContainedOutcome::Exited(code) => code,
        ref other => panic!(
            "expected an exit, got {other:?}; stderr: {}",
            String::from_utf8_lossy(&run.stderr)
        ),
    }
}

fn path_arg(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn xp13_a_registered_executable_runs_and_its_output_is_relayed() {
    let fixture = Fixture::new();
    let run = fixture.contained(&["print", "100"]);
    assert_eq!(exited(&run), 0);
    assert_eq!(run.stdout, vec![b'o'; 100]);
    let run = fixture.contained(&["eprint", "40"]);
    assert_eq!(exited(&run), 0);
    assert_eq!(run.stderr, vec![b'e'; 40]);
    let run = fixture.contained(&["exit", "7"]);
    assert_eq!(exited(&run), 7);
}

#[test]
fn xp13_output_past_its_bound_kills_the_run_and_keeps_only_the_bound() {
    let fixture = Fixture::new();
    let mut spec = fixture.spec(&["print", "300000"]);
    spec.limits.stdout_bytes = 1000;
    let run = run_contained(&helper_pin(), &spec).unwrap();
    assert_eq!(
        run.outcome,
        ContainedOutcome::OutputLimit(ContainedStream::Stdout)
    );
    assert_eq!(run.stdout.len(), 1000);

    let mut spec = fixture.spec(&["eprint", "300000"]);
    spec.limits.stderr_bytes = 500;
    let run = run_contained(&helper_pin(), &spec).unwrap();
    assert_eq!(
        run.outcome,
        ContainedOutcome::OutputLimit(ContainedStream::Stderr)
    );
    assert_eq!(run.stderr.len(), 500);
}

#[test]
fn xp13_writes_land_only_inside_the_allowlist() {
    let fixture = Fixture::new();
    let inside_work = fixture.work.join("out.txt");
    let inside_root = fixture.writable.join("out.txt");
    assert_eq!(
        exited(&fixture.contained(&["write", path_arg(&inside_work)])),
        0
    );
    assert_eq!(
        exited(&fixture.contained(&["write", path_arg(&inside_root)])),
        0
    );
    assert!(inside_work.is_file() && inside_root.is_file());

    for denied in [
        fixture.outside.join("escape.txt"),
        fixture.readable.join("escape.txt"),
        fixture.probe.with_file_name("escape.txt"),
    ] {
        let run = fixture.contained(&["write", path_arg(&denied)]);
        assert_eq!(
            exited(&run),
            WRITE_FAILED,
            "{} was writable",
            denied.display()
        );
        assert!(!denied.exists(), "{} was created", denied.display());
        // Positive control: the same write works without containment.
        assert_eq!(fixture.uncontained(&["write", path_arg(&denied)]), 0);
        std::fs::remove_file(&denied).unwrap();
    }
}

#[test]
fn xp13_reads_see_only_the_allowlist() {
    let fixture = Fixture::new();
    let granted = fixture.readable.join("granted.txt");
    let run = fixture.contained(&["read", path_arg(&granted)]);
    assert_eq!(exited(&run), 0);
    assert_eq!(run.stdout, b"granted bytes");

    let secret = fixture.outside.join("secret.txt");
    let run = fixture.contained(&["read", path_arg(&secret)]);
    assert_eq!(exited(&run), READ_FAILED);
    assert!(run.stdout.is_empty());
    assert_eq!(fixture.uncontained(&["read", path_arg(&secret)]), 0);
}

#[test]
fn xp13_network_is_denied_even_to_loopback() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let run = fixture.contained(&["connect", &address]);
    assert_eq!(exited(&run), NETWORK_FAILED);
    assert_eq!(fixture.uncontained(&["connect", &address]), 0);
}

#[test]
fn xp13_the_contained_process_cannot_create_a_process() {
    let fixture = Fixture::new();
    let run = fixture.contained(&["spawn"]);
    assert_eq!(exited(&run), SPAWN_FAILED);
    assert_eq!(fixture.uncontained(&["spawn"]), 0);
}

#[test]
fn xp13_a_run_past_its_timeout_is_killed() {
    let fixture = Fixture::new();
    let mut spec = fixture.spec(&["sleep", "60000"]);
    spec.limits.timeout = Duration::from_secs(1);
    let started = Instant::now();
    let run = run_contained(&helper_pin(), &spec).unwrap();
    assert_eq!(run.outcome, ContainedOutcome::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(20));
}

#[test]
fn xp13_cpu_time_past_its_limit_ends_the_run() {
    let fixture = Fixture::new();
    let mut spec = fixture.spec(&["spin"]);
    spec.limits.cpu_seconds = 1;
    let run = run_contained(&helper_pin(), &spec).unwrap();
    // SIGXCPU on Unix; the Job Object's per-process time limit on Windows.
    assert_eq!(run.outcome, ContainedOutcome::ResourceLimit);
}

/// The donor's bypass and fixture variables, and ordinary ambient ones, are
/// set on the helper itself. None may widen the boundary, and none reaches the
/// child: the helper reads no environment variable and the child's
/// environment is built from nothing.
#[test]
fn xp13_donor_bypass_variables_are_not_honoured() {
    let fixture = Fixture::new();
    let secret = fixture.outside.join("secret.txt");
    let escape = fixture.outside.join("escape.txt");
    let bypass: Vec<(&str, String)> = vec![
        ("CUA_ENV_SKIP_SENSITIVE_AUTH", "1".into()),
        ("CUA_ENV_ALLOW_UNVERIFIED_SENSITIVE_EXPORT", "1".into()),
        ("CUA_TEST_PYTHON", fixture.probe.display().to_string()),
        (
            "CUA_TEST_PYTHON_READ_ROOTS",
            fixture.outside.display().to_string(),
        ),
        (
            "CUA_TEST_PYTHON_DYNAMIC_LINKER",
            fixture.probe.display().to_string(),
        ),
        ("CUA_DRIVER_ACL_RENAME_CHILD", "1".into()),
        ("ORCEL_CONTAIN_DISABLE", "1".into()),
        ("HTTP_PROXY", "http://127.0.0.1:9".into()),
    ];
    let run_with_env = |args: &[&str]| -> ContainedRun {
        let spec = fixture.spec(args);
        let encoded = encode_spec(&spec, std::process::id()).unwrap();
        let mut command = Command::new(helper_path());
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (name, value) in &bypass {
            command.env(name, value);
        }
        let mut child = command.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(&encoded).unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        drop(stdin);
        child.wait().unwrap();
        decode_result(&bytes, &spec.limits).unwrap()
    };

    assert_eq!(
        exited(&run_with_env(&["read", path_arg(&secret)])),
        READ_FAILED
    );
    assert_eq!(
        exited(&run_with_env(&["write", path_arg(&escape)])),
        WRITE_FAILED
    );
    assert!(!escape.exists());

    let run = run_with_env(&["env"]);
    assert_eq!(exited(&run), 0);
    let environment = String::from_utf8_lossy(&run.stdout).into_owned();
    for (name, _) in &bypass {
        assert!(
            !environment
                .lines()
                .any(|line| line.starts_with(&format!("{name}="))),
            "{name} reached the child:\n{environment}"
        );
    }
}

fn drive_helper(spec_bytes: &[u8]) -> (Vec<u8>, Option<i32>) {
    let mut child = Command::new(helper_path())
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let _ = stdin.write_all(spec_bytes);
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    drop(stdin);
    (bytes, child.wait().unwrap().code())
}

fn refusal(bytes: &[u8], limits: &ContainedLimits) -> RefusalKind {
    match decode_result(bytes, limits) {
        Err(ContainedError::Refused { kind, .. }) => kind,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn xp13_the_helper_refuses_an_oversize_or_malformed_spec() {
    let fixture = Fixture::new();
    let limits = fixture.spec(&["noop"]).limits;
    let marker = fixture.work.join("pid");
    let valid = encode_spec(
        &fixture.spec(&["hold", path_arg(&marker)]),
        std::process::id(),
    )
    .unwrap();

    // Oversize: a valid prefix that never ends within the bound.
    let mut oversize = valid[..valid.len() - b"end\n".len()].to_vec();
    while oversize.len() <= 70 * 1024 {
        oversize.extend_from_slice(format!("arg {}\n", "61".repeat(200)).as_bytes());
    }
    oversize.extend_from_slice(b"end\n");
    let (bytes, status) = drive_helper(&oversize);
    assert_eq!(refusal(&bytes, &limits), RefusalKind::SpecTooLarge);
    assert_eq!(status, Some(3));

    // Malformed: an unknown key.
    let text = String::from_utf8(valid.clone()).unwrap();
    let malformed = text.replace("files 256\n", "files 256\nnetwork 1\n");
    let (bytes, status) = drive_helper(malformed.as_bytes());
    assert_eq!(refusal(&bytes, &limits), RefusalKind::InvalidSpec);
    assert_eq!(status, Some(3));

    std::thread::sleep(Duration::from_millis(300));
    assert!(!marker.exists(), "a refused spec launched its child");
}

#[test]
fn xp13_a_tampered_or_unpinned_helper_is_refused() {
    let fixture = Fixture::new();
    let spec = fixture.spec(&["noop"]);
    let directory = tempfile::Builder::new()
        .prefix("xp13-helper-")
        .tempdir()
        .unwrap();
    let copy = directory.path().join(if cfg!(windows) {
        "orcel-contain.exe"
    } else {
        "orcel-contain"
    });
    std::fs::copy(helper_path(), &copy).unwrap();
    settle_copied_executable(&copy);

    // Positive control: the untouched copy, pinned, runs.
    let pin = pin_of(&copy);
    assert_eq!(exited(&run_contained(&pin, &spec).unwrap()), 0);

    // One flipped byte after the pin was taken.
    let mut bytes = std::fs::read(&copy).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    std::fs::write(&copy, &bytes).unwrap();
    assert_eq!(
        run_contained(&pin, &spec),
        Err(ContainedError::HelperTampered)
    );

    // Pinned to a digest the helper never had.
    let wrong = HelperPin::new(helper_path(), &sha256_hex(b"not the helper")).unwrap();
    assert_eq!(
        run_contained(&wrong, &spec),
        Err(ContainedError::HelperTampered)
    );

    // No PATH lookup: a bare name is not a pin.
    assert!(matches!(
        HelperPin::new("orcel-contain", &sha256_hex(b"x")),
        Err(ContainedError::HelperNotPinned(_))
    ));
}

/// Wait up to `limit` for a pid file the probe writes.
fn wait_for_pid(path: &Path, limit: Duration) -> u32 {
    let deadline = Instant::now() + limit;
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(pid) = text.trim().parse() {
                return pid;
            }
        }
        assert!(Instant::now() < deadline, "the probe never wrote its pid");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(target_os = "linux")]
fn process_gone(pid: u32) -> bool {
    // A zombie still answers kill(0); its /proc state says it is dead.
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        Ok(stat) => stat
            .rsplit_once(") ")
            .is_some_and(|(_, rest)| rest.starts_with('Z') || rest.starts_with('X')),
    }
}

#[cfg(target_os = "macos")]
fn process_gone(pid: u32) -> bool {
    // SAFETY: kill with signal 0 only probes.
    let alive = unsafe { libc::kill(pid as i32, 0) } == 0;
    !alive
}

#[cfg(windows)]
fn process_gone(pid: u32) -> bool {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }
    const SYNCHRONIZE: u32 = 0x0010_0000;
    // SAFETY: plain Win32 calls on a handle this function owns.
    unsafe {
        let handle = OpenProcess(SYNCHRONIZE, 0, pid);
        if handle.is_null() {
            return true;
        }
        let signaled = WaitForSingleObject(handle, 0) == 0;
        CloseHandle(handle);
        signaled
    }
}

fn assert_gone_within(pid: u32, limit: Duration) {
    let deadline = Instant::now() + limit;
    while !process_gone(pid) {
        assert!(
            Instant::now() < deadline,
            "contained process {pid} outlived its supervisor"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn start_holding(fixture: &Fixture) -> (std::process::Child, std::process::ChildStdin, u32) {
    let marker = fixture.work.join("pid");
    let spec = fixture.spec(&["hold", path_arg(&marker)]);
    let encoded = encode_spec(&spec, std::process::id()).unwrap();
    let mut child = Command::new(helper_path())
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&encoded).unwrap();
    let pid = wait_for_pid(&marker, Duration::from_secs(30));
    (child, stdin, pid)
}

/// orceld going away closes the helper's stdin; the helper kills the tree.
#[test]
fn xp13_supervisor_exit_kills_the_contained_process() {
    let fixture = Fixture::new();
    let (mut helper, stdin, pid) = start_holding(&fixture);
    assert!(!process_gone(pid));
    drop(stdin);
    let mut bytes = Vec::new();
    helper
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(helper.wait().unwrap().code(), Some(0));
    assert!(String::from_utf8_lossy(&bytes).starts_with("orcel-contain-result 1 parent_gone "));
    assert_gone_within(pid, Duration::from_secs(10));
}

/// The helper itself killed outright: the child still dies, through
/// PR_SET_PDEATHSIG (Linux), the sentinel pipe (macOS) or the kill-on-close
/// Job Object (Windows).
#[test]
fn xp13_killing_the_helper_kills_the_contained_process() {
    let fixture = Fixture::new();
    let (mut helper, _stdin, pid) = start_holding(&fixture);
    assert!(!process_gone(pid));
    helper.kill().unwrap();
    helper.wait().unwrap();
    assert_gone_within(pid, Duration::from_secs(10));
}

#[test]
fn xp13_the_helper_refuses_a_spec_from_a_different_supervisor() {
    let fixture = Fixture::new();
    let spec = fixture.spec(&["noop"]);
    let encoded = encode_spec(&spec, std::process::id().wrapping_add(1).max(2)).unwrap();
    let (bytes, status) = drive_helper(&encoded);
    // Unix: the pid the death signal is armed against. Windows: the parent
    // from a process snapshot, still running and started before the helper.
    assert_eq!(refusal(&bytes, &spec.limits), RefusalKind::InvalidSpec);
    assert_eq!(status, Some(3));
}

/// Linux without Landlock: the helper must refuse rather than run the child
/// with seccomp alone. A seccomp filter installed on the helper makes
/// `landlock_create_ruleset` return ENOSYS, exactly what a kernel without
/// Landlock answers.
#[cfg(target_os = "linux")]
#[test]
fn xp13_a_kernel_without_landlock_makes_the_helper_refuse() {
    use std::os::unix::process::CommandExt as _;

    #[repr(C)]
    struct Filter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }
    #[repr(C)]
    struct Program {
        len: u16,
        filter: *const Filter,
    }
    const LANDLOCK_CREATE_RULESET: u32 = 444;
    const RET_ERRNO_ENOSYS: u32 = 0x0005_0000 | 38;
    const RET_ALLOW: u32 = 0x7fff_0000;
    let filter = [
        // load syscall number; if landlock_create_ruleset return ENOSYS.
        Filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        Filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: LANDLOCK_CREATE_RULESET,
        },
        Filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: RET_ERRNO_ENOSYS,
        },
        Filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: RET_ALLOW,
        },
    ];
    let filter_address = filter.as_ptr() as usize;

    let fixture = Fixture::new();
    let marker = fixture.work.join("pid");
    let spec = fixture.spec(&["hold", path_arg(&marker)]);
    let encoded = encode_spec(&spec, std::process::id()).unwrap();
    let mut command = Command::new(helper_path());
    command
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // SAFETY: raw prctl/seccomp syscalls between fork and exec; the filter
    // array outlives the spawn.
    unsafe {
        command.pre_exec(move || {
            let program = Program {
                len: 4,
                filter: filter_address as *const Filter,
            };
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::syscall(libc::SYS_seccomp, 1_u64, 0_u64, &program as *const Program) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&encoded).unwrap();
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    drop(stdin);
    assert_eq!(child.wait().unwrap().code(), Some(3));
    assert_eq!(
        refusal(&bytes, &spec.limits),
        RefusalKind::UnsupportedPlatform
    );
    std::thread::sleep(Duration::from_millis(300));
    assert!(!marker.exists(), "the child ran without Landlock");
}

/// Spawn overhead: the median wall time of a trivial contained run against the
/// same probe uncontained. Recorded, not asserted; CI writes it to the job
/// summary.
#[test]
fn xp13_spawn_overhead_is_recorded() {
    let fixture = Fixture::new();
    let pin = helper_pin();
    let spec = fixture.spec(&["noop"]);
    let median = |mut samples: Vec<Duration>| {
        samples.sort();
        samples[samples.len() / 2]
    };
    let contained = median(
        (0..7)
            .map(|_| {
                let started = Instant::now();
                assert_eq!(exited(&run_contained(&pin, &spec).unwrap()), 0);
                started.elapsed()
            })
            .collect(),
    );
    let direct = median(
        (0..7)
            .map(|_| {
                let started = Instant::now();
                assert_eq!(fixture.uncontained(&["noop"]), 0);
                started.elapsed()
            })
            .collect(),
    );
    let line = format!(
        "- {}: contained run (pin check + helper + boundaries + child) median {:.1} ms; uncontained child median {:.1} ms; overhead {:.1} ms\n",
        std::env::consts::OS,
        contained.as_secs_f64() * 1000.0,
        direct.as_secs_f64() * 1000.0,
        (contained.saturating_sub(direct)).as_secs_f64() * 1000.0,
    );
    println!("{line}");
    if let Some(summary) = std::env::var_os("GITHUB_STEP_SUMMARY") {
        if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(summary) {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

fn plant_link(target: &Path, link: &Path) {
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(target, link);
    // A directory junction: a reparse point like a symbolic link, but one any
    // user may create, so the test needs no privilege.
    #[cfg(windows)]
    let made = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .stdout(Stdio::null())
        .status()
        .and_then(|status| {
            if status.success() {
                Ok(())
            } else {
                Err(std::io::Error::other(format!(
                    "mklink /J exited with {status}"
                )))
            }
        });
    if let Err(error) = made {
        panic!("cannot create the symbolic link this test needs: {error}");
    }
}

/// A root reached through a symbolic link is refused, by the kernel client
/// and by the helper itself, instead of granting the link's target.
#[test]
fn xp13_a_symlinked_root_is_refused() {
    let fixture = Fixture::new();
    let link = fixture.writable.join("out");
    plant_link(&fixture.outside, &link);

    let mut spec = fixture.spec(&["read", path_arg(&link.join("secret.txt"))]);
    spec.readable = vec![link.clone()];
    assert!(matches!(
        run_contained(&helper_pin(), &spec),
        Err(ContainedError::InvalidSpec(_))
    ));
    let (bytes, status) = drive_helper(&encode_spec(&spec, std::process::id()).unwrap());
    assert_eq!(refusal(&bytes, &spec.limits), RefusalKind::LaunchFailed);
    assert_eq!(status, Some(3));

    let mut spec = fixture.spec(&["noop"]);
    spec.workdir = link.clone();
    let (bytes, _) = drive_helper(&encode_spec(&spec, std::process::id()).unwrap());
    assert_eq!(refusal(&bytes, &spec.limits), RefusalKind::LaunchFailed);
}

/// A link an earlier run left inside its write root never widens a later
/// grant: reading through it reaches the target, which no rule grants (Unix),
/// or the grant itself refuses to walk a reparse point (Windows).
#[test]
fn xp13_a_link_planted_in_a_write_root_never_widens_a_later_grant() {
    let fixture = Fixture::new();
    let link = fixture.writable.join("out");
    plant_link(&fixture.outside, &link);
    let through = link.join("secret.txt");
    assert_eq!(fixture.uncontained(&["read", path_arg(&through)]), 0);
    let spec = fixture.spec(&["read", path_arg(&through)]);
    let result = run_contained(&helper_pin(), &spec);
    #[cfg(unix)]
    {
        let run = result.unwrap();
        assert_eq!(exited(&run), READ_FAILED);
        assert!(run.stdout.is_empty());
    }
    #[cfg(windows)]
    assert!(
        matches!(
            result,
            Err(ContainedError::Refused {
                kind: RefusalKind::LaunchFailed,
                ..
            })
        ),
        "{result:?}"
    );
}

/// XP-13b: the contained process cannot give a file it may only read, or
/// cannot reach at all, a second name inside its write root. Such a link
/// would outlive the run and widen a later grant of that root: on Unix the
/// path rules would then allow writes through it, and on Windows the grant
/// walk would refuse the root (see the next test). Landlock withholds
/// `REFER` from read-only roots, AppContainer has no write-attributes right
/// on them, and Seatbelt grants no `file-link` at all, so on macOS even a
/// file inside the write root cannot be linked.
#[test]
fn xp13_the_contained_process_cannot_create_a_hard_link() {
    let fixture = Fixture::new();
    for (source, name) in [
        (fixture.readable.join("granted.txt"), "from-readable"),
        (fixture.outside.join("secret.txt"), "from-outside"),
    ] {
        let link = fixture.writable.join(name);
        let run = fixture.contained(&["link", path_arg(&source), path_arg(&link)]);
        assert_eq!(
            exited(&run),
            LINK_FAILED,
            "{} was linked into the write root: {}",
            source.display(),
            String::from_utf8_lossy(&run.stderr)
        );
        assert!(!link.exists(), "{} was created", link.display());
        // Positive control: the same link works without containment.
        assert_eq!(
            fixture.uncontained(&["link", path_arg(&source), path_arg(&link)]),
            0
        );
        std::fs::remove_file(&link).unwrap();
    }

    #[cfg(target_os = "macos")]
    {
        let own = fixture.writable.join("own.txt");
        std::fs::write(&own, b"own").unwrap();
        let link = fixture.writable.join("own-link");
        let run = fixture.contained(&["link", path_arg(&own), path_arg(&link)]);
        assert_eq!(
            exited(&run),
            LINK_FAILED,
            "Seatbelt allowed a hard link inside the write root"
        );
        assert!(!link.exists());
        assert_eq!(
            fixture.uncontained(&["link", path_arg(&own), path_arg(&link)]),
            0
        );
    }
}

/// XP-13b: a hard link that already exists in a granted root. On Windows the
/// grant walk refuses it, because an ACE on the link would land on the
/// outside file it shares a security descriptor with. On Linux and macOS the
/// boundary is path based, so the contained process reads the linked file
/// through the granted path: this is the residual risk the README documents,
/// pinned here so a change in either direction is noticed.
#[test]
fn xp13_a_hard_link_already_in_a_granted_root() {
    let fixture = Fixture::new();
    let secret = fixture.outside.join("secret.txt");
    let link = fixture.writable.join("secret-link.txt");
    std::fs::hard_link(&secret, &link).unwrap();
    let spec = fixture.spec(&["read", path_arg(&link)]);
    let result = run_contained(&helper_pin(), &spec);
    #[cfg(windows)]
    assert!(
        matches!(
            result,
            Err(ContainedError::Refused {
                kind: RefusalKind::LaunchFailed,
                ..
            })
        ),
        "{result:?}"
    );
    #[cfg(unix)]
    {
        let run = result.unwrap();
        assert_eq!(exited(&run), 0);
        assert_eq!(run.stdout, b"outside bytes");
    }

    // Without the second name the same spec launches on every OS.
    std::fs::remove_file(&link).unwrap();
    let run = run_contained(&helper_pin(), &fixture.spec(&["noop"])).unwrap();
    assert_eq!(exited(&run), 0);
}
