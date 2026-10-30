//! SG-000115 slice A6, inert pre-activation engineering (category A6 in
//! `docs/orcel/implementation-readiness/prep/SG-000115.md`): the integration
//! fixture that composes A1 to A5 into one launch-and-teardown rehearsal
//! against a fake engine.
//!
//! The module is compiled only into Unix test builds
//! (`#[cfg(all(test, unix))]` in `lib.rs`), so no release build contains
//! it. No production path calls it, and macOS/Linux launch stays refused.
//! The "engine" is a `python3` fixture started through A2's fixture
//! constructor; it never starts a browser and opens no socket except to the
//! host's sink.
//!
//! The rehearsal pins the order activation will need:
//! - **Start:** managed policy (A1) → crash recovery of leftovers (A5) → a
//!   fresh 0700 profile and its hold (A3) → the sink → the exact Unix argv
//!   (A4) → the supervised engine (A2). Each stage runs only after the
//!   previous one succeeded. The tests exercise the policy and in-use
//!   refusals; a later refusal (create, hold, sink, argv, spawn) leaves the
//!   created profile for the next start's recovery.
//! - **Teardown:** sweep the engine's family (A2) → stop the sink → remove
//!   the profile through its hold (A5). Teardown stops the sink and removes
//!   the profile only when the sweep vouches for the whole family
//!   (`all_exited()`: nothing left and `Coverage::VerifiedComplete`). Every
//!   other outcome keeps both: the sink keeps its port and the profile stays
//!   held (the #501 contract: a stopped sink frees its port, and slice 1
//!   stops it only once every engine process is confirmed gone).
//!
//! What this rehearsal shows, and does not:
//! - A2 never produces `VerifiedComplete` (it is reserved for an
//!   activation-qualified mechanism), so every real teardown here is kept.
//!   The tests then release the scratch resources themselves, with that
//!   acceptance written in the test (`accept_unverified`); the rehearsal
//!   code has no such step, and activation must not gain one without
//!   verified coverage.
//! - One test pins why coverage is never claimed: a helper that leaves the
//!   group and is orphaned escapes the sweep (the open macOS/Linux item
//!   recorded in A2; category C, not accepted), and the sink is still
//!   running when the sweep returns. The `Incomplete` assertions elsewhere
//!   restate A2's contract; that test is the evidence.
//! - Nothing here is evidence about a real Chrome or Edge (category B).

use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::confinement::AdmittedDestination;
use crate::discovery::EngineKind;
use crate::error::HostError;
use crate::navigation::DnsResolver;
use crate::sink::NetworkSink;
use crate::unix_cleanup::{recover_stale_profile, sweep_held_profile, CleanupError, Recovery};
use crate::unix_confinement::{assert_unix_worker_argv_exact, build_unix_worker_argv};
use crate::unix_policy::{assert_no_unix_managed_policy, UnixPlatform};
use crate::unix_profile::{ProfileError, ProfileHold};
use crate::unix_supervise::{python_fixture, FamilyError, Supervised, SweepOutcome};

#[cfg(target_os = "linux")]
const PLATFORM: UnixPlatform = UnixPlatform::Linux;
#[cfg(target_os = "macos")]
const PLATFORM: UnixPlatform = UnixPlatform::MacOs;

/// How long a sweep may take to confirm the family's exit.
const DEADLINE: Duration = Duration::from_secs(10);
/// The file the fake engine writes into its profile once it is up.
const READY: &str = "orcel-rehearsal-ready";

/// The fake engine. It reads its profile and proxy from the host-built
/// argv, writes into the profile, makes one connection to the proxy (the
/// sink), and starts two helpers in its group. Modes add a helper that
/// leaves the group (`escape`, `orphan`) or crash the engine on a signal
/// file (`crash`, `orphan`).
const FAKE_ENGINE: &str = r#"
import os, socket, subprocess, sys, time
args = sys.argv[1:]
def flag(name):
    values = [arg.split('=', 1)[1] for arg in args if arg.startswith(name + '=')]
    if len(values) != 1:
        sys.exit(3)
    return values[0]
def wait_for(path):
    deadline = time.time() + 30
    while not os.path.exists(path):
        if time.time() > deadline:
            sys.exit(4)
        time.sleep(0.02)
profile = flag('--user-data-dir')
host, port = flag('--proxy-server')[len('http://'):].rsplit(':', 1)
mode = os.environ['ORCEL_REHEARSAL_MODE']
side = os.environ['ORCEL_REHEARSAL_SIDE']
os.makedirs(os.path.join(profile, 'Default'))
with open(os.path.join(profile, 'Default', 'Preferences'), 'w') as out:
    out.write('{}')
try:
    with socket.create_connection((host, int(port)), timeout=5) as egress:
        egress.sendall(b'CONNECT example.com:443 HTTP/1.1\r\n\r\n')
except OSError:
    pass
sleeper = 'import time; time.sleep(60)'
helpers = [subprocess.Popen([sys.executable, '-c', sleeper]) for _ in range(2)]
if mode in ('escape', 'orphan'):
    leaver = ('import os, sys, time; os.setsid(); '
              'open(sys.argv[1] + ".tmp", "w").write(str(os.getpid())); '
              'os.rename(sys.argv[1] + ".tmp", sys.argv[1]); time.sleep(float(sys.argv[2]))')
    life = '60' if mode == 'escape' else '8'
    subprocess.Popen([sys.executable, '-c', leaver, os.path.join(side, 'left.pid'), life])
    wait_for(os.path.join(side, 'left.pid'))
with open(os.path.join(profile, 'ready.tmp'), 'w') as out:
    out.write('ready')
os.rename(os.path.join(profile, 'ready.tmp'), os.path.join(profile, 'orcel-rehearsal-ready'))
if mode in ('crash', 'orphan'):
    wait_for(os.path.join(side, 'crash-now'))
    os._exit(1)
time.sleep(60)
"#;

/// What the fake engine does once it is up.
#[derive(Debug, Clone, Copy)]
enum Mode {
    /// Runs with two helpers in its group.
    Run,
    /// Adds a helper that leaves the group (setsid) while the engine lives.
    Escape,
    /// Exits abruptly once `crash-now` appears, leaving its helpers.
    Crash,
    /// Adds a short-lived helper that leaves the group, then exits
    /// abruptly once `crash-now` appears, orphaning that helper.
    Orphan,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Run => "run",
            Mode::Escape => "escape",
            Mode::Crash => "crash",
            Mode::Orphan => "orphan",
        }
    }
}

/// The stage that refused a start; no later stage ran.
// Payloads are for diagnostics (read through `Debug` in test failures).
#[allow(dead_code)]
#[derive(Debug)]
enum Refused {
    Policy(HostError),
    InUse,
    Recovery(CleanupError),
    Create(io::Error),
    Hold(ProfileError),
    Sink(io::Error),
    Argv(HostError),
    Spawn(io::Error),
}

/// A started rehearsal: the engine, the sink it may use, and the held
/// profile.
struct Running {
    engine: Supervised,
    sink: NetworkSink,
    hold: ProfileHold,
    profile: PathBuf,
}

/// A finished teardown.
#[derive(Debug)]
struct Released {
    outcome: SweepOutcome,
    /// Connections the sink took while the engine ran.
    accepted: u64,
}

/// Why teardown kept the sink and the profile instead of releasing them.
#[allow(dead_code)]
#[derive(Debug)]
enum Kept {
    /// The family could not be established.
    Family(FamilyError),
    /// Scanned members are still alive.
    Survivors(SweepOutcome),
    /// Every scanned member exited, but the sweep cannot vouch for the whole
    /// family (`Coverage::Incomplete`).
    Unverified(SweepOutcome),
}

/// What a refused release still holds: the sink keeps its port and the
/// profile stays held.
#[derive(Debug)]
struct Holding {
    why: Kept,
    sink: NetworkSink,
    hold: ProfileHold,
    profile: PathBuf,
}

#[allow(dead_code)]
#[derive(Debug)]
enum TeardownError {
    /// Fails closed (boxed: the holding is large).
    Kept(Box<Holding>),
    Cleanup(CleanupError),
}

/// Destinations are resolved by a fixed fake resolver: nothing is looked up.
struct FakeDns;

impl DnsResolver for FakeDns {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<std::net::IpAddr>, HostError> {
        Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            93, 184, 215, 14,
        ))])
    }
}

fn destinations() -> Vec<AdmittedDestination> {
    vec![AdmittedDestination::admit("https://example.com/", &FakeDns).unwrap()]
}

/// Start in the order activation needs; refuse at the first failing stage.
/// `side` is a scratch directory outside the profile for the fixture's
/// signal files.
fn start(policy_root: &Path, profile: &Path, mode: Mode, side: &Path) -> Result<Running, Refused> {
    assert_no_unix_managed_policy(PLATFORM, EngineKind::Chromium, policy_root)
        .map_err(Refused::Policy)?;
    match recover_stale_profile(profile) {
        Ok(Recovery::Absent | Recovery::Removed) => {}
        Ok(Recovery::InUse) => return Err(Refused::InUse),
        Err(error) => return Err(Refused::Recovery(error)),
    }
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(profile)
        .map_err(Refused::Create)?;
    // The umask may clear bits but never adds any; set the exact mode, and
    // the hold re-checks it on the descriptor.
    std::fs::set_permissions(profile, std::fs::Permissions::from_mode(0o700))
        .map_err(Refused::Create)?;
    let hold = ProfileHold::open(profile).map_err(Refused::Hold)?;
    let sink = NetworkSink::start().map_err(Refused::Sink)?;
    let destinations = destinations();
    let argv = build_unix_worker_argv(profile, &destinations, &sink).map_err(Refused::Argv)?;
    assert_unix_worker_argv_exact(&argv, profile, &destinations, &sink).map_err(Refused::Argv)?;
    let mut command = python_fixture(FAKE_ENGINE);
    command
        .args(&argv)
        .env("ORCEL_REHEARSAL_MODE", mode.name())
        .env("ORCEL_REHEARSAL_SIDE", side);
    let engine = Supervised::spawn(command).map_err(Refused::Spawn)?;
    Ok(Running {
        engine,
        sink,
        hold,
        profile: profile.to_path_buf(),
    })
}

/// Sweep the engine, then release the sink and the profile.
fn teardown(running: Running) -> Result<Released, TeardownError> {
    let Running {
        engine,
        sink,
        hold,
        profile,
    } = running;
    match engine.sweep(DEADLINE) {
        Ok(outcome) => release(outcome, sink, hold, profile),
        Err(error) => Err(TeardownError::Kept(Box::new(Holding {
            why: Kept::Family(error),
            sink,
            hold,
            profile,
        }))),
    }
}

/// Release only when the sweep vouches for the whole family; otherwise keep
/// the sink and the held profile.
fn release(
    outcome: SweepOutcome,
    sink: NetworkSink,
    hold: ProfileHold,
    profile: PathBuf,
) -> Result<Released, TeardownError> {
    let why = if !outcome.left.is_empty() {
        Kept::Survivors(outcome)
    } else if !outcome.all_exited() {
        Kept::Unverified(outcome)
    } else {
        return free(outcome, sink, hold, profile);
    };
    Err(TeardownError::Kept(Box::new(Holding {
        why,
        sink,
        hold,
        profile,
    })))
}

/// Stop the sink, then remove the profile through its hold. The release
/// step: reached from `release` only on verified coverage (the tests call it
/// directly, after accepting an unverified residual in test code).
fn free(
    outcome: SweepOutcome,
    sink: NetworkSink,
    hold: ProfileHold,
    profile: PathBuf,
) -> Result<Released, TeardownError> {
    let accepted = sink.accepted();
    drop(sink);
    sweep_held_profile(hold, &profile).map_err(TeardownError::Cleanup)?;
    Ok(Released { outcome, accepted })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unix_supervise::{is_alive, Coverage, Pinned};
    use std::time::Instant;

    struct Scratch {
        root: PathBuf,
    }

    impl Scratch {
        fn new(label: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let root = std::env::temp_dir().join(format!(
                "orcel-sg115-rehearsal-{label}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(root.join("policy")).unwrap();
            std::fs::create_dir_all(root.join("side")).unwrap();
            Self { root }
        }

        fn policy(&self) -> PathBuf {
            self.root.join("policy")
        }

        fn profile(&self) -> PathBuf {
            self.root.join("profile")
        }

        fn side(&self) -> PathBuf {
            self.root.join("side")
        }

        fn start(&self, mode: Mode) -> Result<Running, Refused> {
            start(&self.policy(), &self.profile(), mode, &self.side())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).ok();
        }
    }

    fn until(ready: impl Fn() -> bool) -> bool {
        let started = Instant::now();
        while !ready() {
            if started.elapsed() > DEADLINE {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        true
    }

    /// Up: the engine wrote its ready file into the profile it was given and
    /// the sink took its connection.
    fn wait_ready(running: &Running) {
        assert!(
            until(|| running.profile.join(READY).exists() && running.sink.accepted() >= 1),
            "the fake engine came up"
        );
    }

    fn refused(result: Result<Running, Refused>) -> Refused {
        result.err().expect("the start was expected to refuse")
    }

    /// The holding a teardown kept, and why.
    fn kept(result: Result<Released, TeardownError>) -> (Kept, NetworkSink, ProfileHold, PathBuf) {
        let holding = match result {
            Err(TeardownError::Kept(holding)) => Ok(holding),
            other => Err(format!("{other:?}")),
        }
        .expect("teardown keeps the sink and the profile");
        let Holding {
            why,
            sink,
            hold,
            profile,
        } = *holding;
        (why, sink, hold, profile)
    }

    /// Teardown kept everything because coverage is unverified, with no
    /// scanned survivor. The test, not the rehearsal, accepts that residual
    /// to clean up its scratch resources; the rehearsal has no such step.
    fn accept_unverified(result: Result<Released, TeardownError>) -> Released {
        let (why, sink, hold, profile) = kept(result);
        let outcome = match why {
            Kept::Unverified(outcome) => Ok(outcome),
            other => Err(format!("{other:?}")),
        }
        .expect("kept only because coverage is unverified");
        assert!(outcome.left.is_empty(), "{outcome:?}");
        assert_eq!(outcome.coverage, Coverage::Incomplete);
        assert!(still_sinks(&sink), "the kept sink still owns its port");
        free(outcome, sink, hold, profile).expect("the scratch is released")
    }

    /// The sink still accepts (and closes) connections on its port.
    fn still_sinks(sink: &NetworkSink) -> bool {
        let before = sink.accepted();
        std::net::TcpStream::connect(("127.0.0.1", sink.port())).is_ok()
            && until(|| sink.accepted() > before)
    }

    fn signal_crash(scratch: &Scratch) {
        std::fs::write(scratch.side().join("crash-now"), "").unwrap();
    }

    fn left_pid(scratch: &Scratch) -> i32 {
        let path = scratch.side().join("left.pid");
        assert!(until(|| path.exists()), "the leaving helper reported");
        std::fs::read_to_string(path)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    #[test]
    fn a_rehearsal_runs_every_slice_in_order_and_leaves_nothing() {
        let scratch = Scratch::new("full");
        let running = scratch.start(Mode::Run).unwrap();
        wait_ready(&running);
        // The engine used the host-built argv: its writes are in the held
        // profile, and its one connection reached the sink.
        assert!(scratch.profile().join("Default/Preferences").exists());
        let family = running.engine.family().unwrap();
        assert!(family.len() >= 3, "the engine and two helpers: {family:?}");

        let released = accept_unverified(teardown(running));
        assert!(released.accepted >= 1, "{released:?}");
        assert!(released.outcome.left.is_empty(), "{released:?}");
        // Every scanned member exited, yet the rehearsal never claims more.
        assert_eq!(released.outcome.coverage, Coverage::Incomplete);
        assert!(!released.outcome.all_exited());
        for member in family {
            assert!(!is_alive(member), "{member:?}");
        }
        assert!(!scratch.profile().exists(), "the profile was removed");
        let mut left: Vec<String> = std::fs::read_dir(&scratch.root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, ["policy", "side"], "nothing else is left behind");
    }

    #[test]
    fn a_helper_that_leaves_the_group_is_swept_with_the_engine() {
        let scratch = Scratch::new("escape");
        let running = scratch.start(Mode::Escape).unwrap();
        wait_ready(&running);
        let leaver = left_pid(&scratch);
        let family = running.engine.family().unwrap();
        assert!(
            family.iter().any(|member| member.pid == leaver),
            "the parent-link walk finds the helper outside the group: {family:?}"
        );
        let released = accept_unverified(teardown(running));
        assert!(released.outcome.left.is_empty(), "{released:?}");
        for member in family {
            assert!(!is_alive(member), "{member:?}");
        }
        assert!(!scratch.profile().exists());
    }

    #[test]
    fn an_engine_that_crashes_is_still_swept_with_its_helpers() {
        let scratch = Scratch::new("crash");
        let running = scratch.start(Mode::Crash).unwrap();
        wait_ready(&running);
        let family = running.engine.family().unwrap();
        assert!(family.len() >= 3, "{family:?}");
        let root = running.engine.root();
        signal_crash(&scratch);
        assert!(until(|| !is_alive(root)), "the engine crashed");
        let released = accept_unverified(teardown(running));
        assert!(released.outcome.left.is_empty(), "{released:?}");
        for member in family {
            assert!(!is_alive(member), "{member:?}");
        }
        assert!(!scratch.profile().exists());
    }

    /// The residual the sweep cannot close (A2's open item, category C): a
    /// helper that left the group and was orphaned before the scan is
    /// outside the parent-link walk. The sweep reports nothing left, yet the
    /// helper runs on; teardown therefore keeps the sink and the profile
    /// (coverage unverified), and nothing claims the family exited.
    #[test]
    fn an_orphan_outside_the_group_escapes_and_teardown_keeps_the_sink() {
        let scratch = Scratch::new("orphan");
        let running = scratch.start(Mode::Orphan).unwrap();
        wait_ready(&running);
        let leaver = left_pid(&scratch);
        // Pinned while it is still the engine's child: its start time guards
        // the later checks against pid reuse, and a zombie counts as gone.
        let orphan = running
            .engine
            .family()
            .unwrap()
            .into_iter()
            .find(|member| member.pid == leaver)
            .expect("the leaving helper is in the family before the crash");
        let root = running.engine.root();
        signal_crash(&scratch);
        assert!(until(|| !is_alive(root)), "the engine crashed");
        let (why, sink, hold, profile) = kept(teardown(running));
        let outcome = match why {
            Kept::Unverified(outcome) => Ok(outcome),
            other => Err(format!("{other:?}")),
        }
        .expect("kept because coverage is unverified");
        assert!(outcome.left.is_empty(), "the orphan was never scanned");
        assert!(!outcome.all_exited());
        assert!(is_alive(orphan), "the orphan escaped the sweep");
        assert!(still_sinks(&sink), "the sink outlives the escaped helper");
        assert!(profile.exists(), "the profile stays held");
        // The fixture orphan lives eight seconds; wait it out rather than
        // signal a process the sweep no longer vouches for.
        assert!(until(|| !is_alive(orphan)), "the orphan exited");
        free(outcome, sink, hold, profile).expect("the scratch is released");
    }

    #[test]
    fn a_managed_policy_refuses_before_any_other_stage() {
        let scratch = Scratch::new("policy");
        let populated = match PLATFORM {
            UnixPlatform::Linux => scratch.policy().join("etc/opt/chrome/policies/managed"),
            UnixPlatform::MacOs => scratch.policy().join("Library/Managed Preferences"),
        };
        std::fs::create_dir_all(&populated).unwrap();
        let file = match PLATFORM {
            UnixPlatform::Linux => "policy.json",
            UnixPlatform::MacOs => "com.google.Chrome.plist",
        };
        std::fs::write(populated.join(file), "{}").unwrap();
        // Leftovers from an earlier run stay untouched too: recovery comes
        // after the policy check.
        std::fs::create_dir(scratch.profile()).unwrap();
        std::fs::write(scratch.profile().join("leftover"), "x").unwrap();
        assert!(matches!(
            refused(scratch.start(Mode::Run)),
            Refused::Policy(_)
        ));
        assert!(scratch.profile().join("leftover").exists());
        assert!(!scratch
            .profile()
            .join(crate::unix_profile::LOCK_NAME)
            .exists());
    }

    #[test]
    fn a_profile_in_use_refuses_the_second_start() {
        let scratch = Scratch::new("in-use");
        let first = scratch.start(Mode::Run).unwrap();
        wait_ready(&first);
        assert!(matches!(refused(scratch.start(Mode::Run)), Refused::InUse));
        assert!(
            scratch.profile().join("Default/Preferences").exists(),
            "the first run's profile is untouched"
        );
        accept_unverified(teardown(first));
        assert!(!scratch.profile().exists());
    }

    #[test]
    fn a_crashed_host_leaves_leftovers_the_next_start_recovers() {
        let scratch = Scratch::new("recover");
        let running = scratch.start(Mode::Run).unwrap();
        wait_ready(&running);
        // The host "crashes" after the engine is gone but before cleanup:
        // its hold is released with it, and the profile stays behind.
        let Running {
            engine, sink, hold, ..
        } = running;
        assert!(engine.sweep(DEADLINE).unwrap().left.is_empty());
        drop(sink);
        drop(hold);
        std::fs::write(scratch.profile().join("leftover"), "x").unwrap();

        let next = scratch.start(Mode::Run).unwrap();
        assert!(
            !scratch.profile().join("leftover").exists(),
            "the next start removed the stale profile before its own"
        );
        wait_ready(&next);
        accept_unverified(teardown(next));
        assert!(!scratch.profile().exists());
    }

    fn held_profile(scratch: &Scratch) -> (ProfileHold, PathBuf) {
        let profile = scratch.profile();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&profile)
            .unwrap();
        std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o700)).unwrap();
        (ProfileHold::open(&profile).unwrap(), profile)
    }

    #[test]
    fn survivors_and_unverified_coverage_keep_the_sink_and_the_profile() {
        let survivor = Pinned {
            pid: i32::MAX,
            start: 1,
        };
        for (left, label) in [(vec![survivor], "survivors"), (Vec::new(), "unverified")] {
            let scratch = Scratch::new(label);
            let (hold, profile) = held_profile(&scratch);
            let sink = NetworkSink::start().unwrap();
            let outcome = SweepOutcome {
                left,
                coverage: Coverage::Incomplete,
            };
            let (why, sink, hold, profile) = kept(release(outcome, sink, hold, profile));
            match label {
                "survivors" => assert!(matches!(why, Kept::Survivors(_)), "{why:?}"),
                _ => assert!(matches!(why, Kept::Unverified(_)), "{why:?}"),
            }
            assert!(still_sinks(&sink), "{label}: the sink still owns its port");
            assert!(profile.exists());
            assert_eq!(ProfileHold::open(&profile).unwrap_err(), ProfileError::Busy);
            drop(hold);
            drop(sink);
            assert_eq!(recover_stale_profile(&profile), Ok(Recovery::Removed));
        }
    }

    /// The one releasing path: verified coverage (which only an
    /// activation-qualified mechanism may produce) with nothing left.
    #[test]
    fn only_verified_coverage_releases_the_sink_and_the_profile() {
        let scratch = Scratch::new("verified");
        let (hold, profile) = held_profile(&scratch);
        let sink = NetworkSink::start().unwrap();
        let outcome = SweepOutcome {
            left: Vec::new(),
            coverage: Coverage::VerifiedComplete,
        };
        let released = release(outcome, sink, hold, profile.clone()).expect("released");
        assert!(released.outcome.all_exited());
        assert!(
            !profile.exists(),
            "the profile was removed through its hold"
        );
    }

    /// Pre-activation boundary: only lib.rs (the test-only declaration) and
    /// the A1 to A5 modules (whose scans admit this module) name it, and
    /// each of those is itself declared test-only.
    #[test]
    fn the_rehearsal_is_unreachable_from_production() {
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for dir in ["src", "tests"] {
            let mut stack = vec![crate_dir.join(dir)];
            while let Some(next) = stack.pop() {
                for entry in std::fs::read_dir(&next).unwrap() {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if path.extension().is_some_and(|ext| ext == "rs") {
                        files.push(path);
                    }
                }
            }
        }
        assert!(files.len() > 10, "the scan found the crate's sources");
        let siblings = [
            ("unix_policy", "#[cfg(test)]"),
            ("unix_supervise", "#[cfg(all(test, unix))]"),
            ("unix_profile", "#[cfg(all(test, unix))]"),
            ("unix_confinement", "#[cfg(test)]"),
            ("unix_cleanup", "#[cfg(all(test, unix))]"),
        ];
        let admitted = |path: &Path| {
            *path == crate_dir.join("src").join("lib.rs")
                || *path == crate_dir.join("src").join("unix_rehearsal.rs")
                || siblings
                    .iter()
                    .any(|(module, _)| *path == crate_dir.join("src").join(format!("{module}.rs")))
        };
        let named: Vec<String> = files
            .iter()
            .filter(|path| !admitted(path))
            .filter(|path| {
                std::fs::read_to_string(path)
                    .unwrap_or_default()
                    .contains("unix_rehearsal")
            })
            .map(|path| path.display().to_string())
            .collect();
        assert!(named.is_empty(), "{named:?}");
        let lib = std::fs::read_to_string(crate_dir.join("src/lib.rs"))
            .unwrap()
            .replace("\r\n", "\n");
        for (module, cfg) in siblings
            .iter()
            .chain(&[("unix_rehearsal", "#[cfg(all(test, unix))]")])
        {
            assert_eq!(
                lib.matches(&format!("mod {module};")).count(),
                1,
                "{module}"
            );
            assert!(!lib.contains(&format!("pub mod {module}")), "{module}");
            assert!(lib.contains(&format!("{cfg}\nmod {module};\n")), "{module}");
        }
    }
}
