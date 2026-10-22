//! SG-000096 T03 native Windows qualification of interactive sessions. The
//! owners come from a MAC-verified disposable lease, as in the T02 tests.
use super::super::shell::tests::{
    disposable, fixture_at, fixture_mode, process_gone, protected_owner, serial,
};
use super::*;
use std::io::{BufRead, Write as _};

const PREFIX: &str = "windows_contained_launch::shell_session::tests::";

fn session_limits() -> SessionLimits {
    SessionLimits {
        stdin_frame_bytes: 4096,
        stdin_total_bytes: 1 << 20,
    }
}

fn far() -> Instant {
    Instant::now() + Duration::from_secs(600)
}

/// Polls until `done` holds or 15 s pass (condition-based, no fixed sleep).
fn wait_for(mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    done()
}

fn stdout_text(registry: &Registry, id: &str) -> String {
    let page = registry.read(id, Stream::Stdout, 0, 1 << 20).expect("read");
    String::from_utf8_lossy(&page.bytes).into_owned()
}

// ---- fixtures ----

#[test]
fn sg96_session_fixture_echo() {
    if fixture_mode() {
        let stdin = std::io::stdin();
        let mut out = std::io::stdout().lock();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            let _ = writeln!(out, "echo:{line}");
            let _ = out.flush();
        }
        let _ = writeln!(out, "eof");
        let _ = out.flush();
    }
}

#[test]
fn sg96_session_fixture_sleep() {
    if fixture_mode() {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[test]
fn sg96_session_fixture_flood_then_wait() {
    if fixture_mode() {
        // stderr: libtest writes its own lines to stdout.
        let mut out = std::io::stderr().lock();
        let _ = out.write_all(&vec![b'f'; 200_000]);
        let _ = out.write_all(b"TAIL");
        let _ = out.flush();
        std::thread::sleep(Duration::from_secs(60));
    }
}

// ---- qualification ----

#[test]
fn sg000096_t03_session_round_trips_stdin_and_denies_stale_generations() {
    let _serial = serial();
    let root = disposable("session-echo");
    let owner = protected_owner(&root.0);
    let registry = Registry::default();
    let command = fixture_at(PREFIX, "sg96_session_fixture_echo", &root.0);
    let started = registry
        .start(&command, &session_limits(), &owner, far())
        .expect("session starts");
    let id = started.session_id.clone();
    assert!(id.starts_with("sh_") && id.len() == 35);
    assert_eq!(started.generation, 1);
    assert_eq!(started.process.user_sid, owner.user_sid);

    let after_write = registry.write_stdin(&id, 1, b"hello\n").expect("write");
    assert_eq!(after_write.generation, 2);
    assert_eq!(after_write.stdin_accepted_bytes, 6);
    assert!(wait_for(
        || stdout_text(&registry, &id).contains("echo:hello")
    ));
    assert!(wait_for(|| registry
        .status(&id)
        .unwrap()
        .stdin_delivered_bytes
        == 6));

    // A mutation approved against generation 1 is now stale.
    assert_eq!(
        registry.write_stdin(&id, 1, b"replay\n"),
        Err(SessionFailure::StaleGeneration { current: 2 })
    );
    assert_eq!(
        registry.terminate(&id, 1),
        Err(SessionFailure::StaleGeneration { current: 2 })
    );
    assert!(!stdout_text(&registry, &id).contains("replay"));

    // Unicode and an empty frame.
    registry
        .write_stdin(&id, 2, "\u{e9}\u{2713}\n".as_bytes())
        .expect("write");
    assert!(wait_for(
        || stdout_text(&registry, &id).contains("echo:\u{e9}\u{2713}")
    ));
    assert_eq!(
        registry.write_stdin(&id, 3, b""),
        Err(SessionFailure::InputLimit)
    );

    // Closing stdin delivers end of input; the child exits on its own.
    registry.close_stdin(&id, 3).expect("close stdin");
    assert_eq!(
        registry.write_stdin(&id, 4, b"late\n"),
        Err(SessionFailure::InputClosed)
    );
    assert!(wait_for(|| !registry
        .status(&id)
        .unwrap()
        .state
        .is_running()));
    let ended = registry.status(&id).unwrap();
    assert_eq!(ended.state, SessionState::Exited { exit_code: 0 });
    // libtest adds its own summary after the fixture's last line.
    assert!(stdout_text(&registry, &id).contains("\neof\n"));
    assert!(ended.stdout.closed);
    let page = registry
        .read(&id, Stream::Stdout, ended.stdout.end_offset, 10)
        .unwrap();
    assert!(page.end_of_stream);
    assert!(process_gone(ended.process.pid));

    assert_eq!(
        registry.write_stdin(&id, ended.generation, b"x"),
        Err(SessionFailure::NotRunning {
            state: "exited".into()
        })
    );
    assert_eq!(
        registry.remove(&id, ended.generation - 1),
        Err(SessionFailure::StaleGeneration {
            current: ended.generation
        })
    );
    registry.remove(&id, ended.generation).expect("remove");
    assert_eq!(registry.status(&id), Err(SessionFailure::UnknownSession));
}

#[test]
fn sg000096_t03_terminate_revoke_and_expiry_end_the_whole_job() {
    let _serial = serial();
    let root = disposable("session-end");
    let owner = protected_owner(&root.0);
    let registry = Registry::default();
    let command = fixture_at(PREFIX, "sg96_session_fixture_sleep", &root.0);

    let one = registry
        .start(&command, &session_limits(), &owner, far())
        .unwrap();
    let ended = registry.terminate(&one.session_id, 1).expect("terminate");
    assert_eq!(ended.state, SessionState::Terminated);
    assert!(ended.descendants_terminated);
    assert!(process_gone(ended.process.pid));
    assert_eq!(
        registry.terminate(&one.session_id, ended.generation),
        Err(SessionFailure::NotRunning {
            state: "terminated".into()
        })
    );

    let two = registry
        .start(&command, &session_limits(), &owner, far())
        .unwrap();
    let three = registry
        .start(&command, &session_limits(), &owner, far())
        .unwrap();
    let revoked = registry.revoke_all("lease revoked in test");
    assert_eq!(revoked.len(), 2);
    for status in [&two, &three] {
        let now = registry.status(&status.session_id).unwrap();
        assert_eq!(
            now.state,
            SessionState::Revoked {
                reason: "lease revoked in test".into()
            }
        );
        assert!(process_gone(now.process.pid));
    }

    // The lease expiry bounds the session even under a longer timeout.
    let expiring = registry
        .start(
            &command,
            &session_limits(),
            &owner,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
    assert!(wait_for(|| !registry
        .status(&expiring.session_id)
        .unwrap()
        .state
        .is_running()));
    let status = registry.status(&expiring.session_id).unwrap();
    assert_eq!(status.state, SessionState::TimedOut);
    assert!(process_gone(status.process.pid));
}

#[test]
fn sg000096_t03_rings_evict_oldest_output_and_report_the_gap() {
    let _serial = serial();
    let root = disposable("session-ring");
    let owner = protected_owner(&root.0);
    let registry = Registry::default();
    let mut command = fixture_at(PREFIX, "sg96_session_fixture_flood_then_wait", &root.0);
    command.limits.stderr_bytes = 4096;
    let started = registry
        .start(&command, &session_limits(), &owner, far())
        .unwrap();
    let id = started.session_id;
    assert!(wait_for(
        || registry.status(&id).unwrap().stderr.end_offset == 200_004
    ));
    let status = registry.status(&id).unwrap();
    assert_eq!(status.stderr.start_offset, 200_004 - 4096);
    let page = registry.read(&id, Stream::Stderr, 0, 8192).unwrap();
    assert_eq!(page.evicted_before, 200_004 - 4096);
    assert_eq!(page.offset, 200_004 - 4096);
    assert!(page.bytes.ends_with(b"TAIL"));
    assert_eq!(page.bytes.len(), 4096);
    assert!(!page.end_of_stream);
    assert!(matches!(
        registry.read(&id, Stream::Stderr, 300_000, 10),
        Err(SessionFailure::OffsetBeyondEnd { end: 200_004 })
    ));
    registry.terminate(&id, status.generation).unwrap();
}

#[test]
fn sg000096_t03_stdin_is_bounded_and_never_reported_delivered_early() {
    let _serial = serial();
    let root = disposable("session-stdin");
    let owner = protected_owner(&root.0);
    let registry = Registry::default();
    // The sleeping child never reads stdin, so the pipe fills.
    let command = fixture_at(PREFIX, "sg96_session_fixture_sleep", &root.0);
    let limits = SessionLimits {
        stdin_frame_bytes: 4096,
        stdin_total_bytes: 64 * 1024,
    };
    let started = registry.start(&command, &limits, &owner, far()).unwrap();
    let id = started.session_id;
    assert_eq!(
        registry.write_stdin(&id, 1, &vec![b'x'; 4097]),
        Err(SessionFailure::InputLimit)
    );
    let mut generation = 1;
    let mut busy = false;
    for _ in 0..16 {
        match registry.write_stdin(&id, generation, &[b'y'; 4096]) {
            Ok(status) => generation = status.generation,
            Err(SessionFailure::InputBusy) => {
                busy = true;
                break;
            }
            Err(other) => panic!("unexpected {other:?}"),
        }
    }
    assert!(busy, "a full queue must refuse input, not drop it");
    let status = registry.status(&id).unwrap();
    assert!(status.stdin_delivered_bytes <= status.stdin_accepted_bytes);
    assert!(
        status.stdin_accepted_bytes - status.stdin_delivered_bytes
            <= (limits.stdin_frame_bytes * STDIN_PENDING_FRAMES) as u64
    );

    let ended = registry.terminate(&id, generation).unwrap();
    assert_eq!(ended.state, SessionState::Terminated);
    // Deliveries that never completed are reported, not invented.
    assert!(wait_for(|| {
        let now = registry.status(&id).unwrap();
        now.stdin_error.is_some() || now.stdin_delivered_bytes == now.stdin_accepted_bytes
    }));
    registry
        .remove(&id, ended.generation)
        .expect("remove joins the writer");
}

#[test]
fn sg000096_t03_registry_is_bounded_and_ids_are_not_guessable() {
    let _serial = serial();
    let root = disposable("session-registry");
    let owner = protected_owner(&root.0);
    let registry = Registry::default();
    let command = fixture_at(PREFIX, "sg96_session_fixture_sleep", &root.0);
    let mut ids = std::collections::BTreeSet::new();
    for _ in 0..MAX_LIVE_SESSIONS {
        let status = registry
            .start(&command, &session_limits(), &owner, far())
            .unwrap();
        assert!(ids.insert(status.session_id));
    }
    assert_eq!(
        registry.start(&command, &session_limits(), &owner, far()),
        Err(SessionFailure::RegistryFull)
    );
    assert_eq!(
        registry.status("sh_00000000000000000000000000000000"),
        Err(SessionFailure::UnknownSession)
    );
    let any = ids.iter().next().unwrap().clone();
    assert!(matches!(
        registry.remove(&any, 1),
        Err(SessionFailure::NotRunning { .. })
    ));
    assert_eq!(registry.revoke_all("test cleanup").len(), MAX_LIVE_SESSIONS);
    assert!(registry
        .list()
        .iter()
        .all(|status| !status.state.is_running()));
}

#[test]
fn sg000096_t03_dropping_the_registry_ends_every_session() {
    let _serial = serial();
    let root = disposable("session-drop");
    let owner = protected_owner(&root.0);
    let command = fixture_at(PREFIX, "sg96_session_fixture_sleep", &root.0);
    let pid = {
        let registry = Registry::default();
        registry
            .start(&command, &session_limits(), &owner, far())
            .unwrap()
            .process
            .pid
    };
    assert!(process_gone(pid));
}

#[test]
fn sg000096_t03_a_session_denied_before_resume_is_never_registered() {
    let _serial = serial();
    let root = disposable("session-denied");
    let owner = protected_owner(&root.0);
    let registry = Registry::default();
    let command = fixture_at(PREFIX, "sg96_session_fixture_sleep", &root.0);
    let result = registry.start_with(&command, &session_limits(), &owner, far(), Fault::WrongSid);
    assert!(matches!(
        result,
        Err(SessionFailure::Shell(ShellFailure::Denied(_)))
    ));
    assert!(registry.list().is_empty());
}

#[test]
fn sg000096_t03_losing_the_runtime_owner_revokes_the_session() {
    let _serial = serial();
    let root = disposable("session-owner");
    let lease_owner = protected_owner(&root.0);
    // A disposable owner process of the same user and logon session.
    let mut helper = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("{PREFIX}sg96_session_fixture_sleep"),
            "--nocapture",
            super::super::shell::tests::FIXTURE_CHILD_ARG,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("owner helper");
    // Bound exactly as the runtime record binds an owner: PID plus its
    // native creation generation.
    let helper_owner = ExpectedNativeOwner {
        owner_pid: helper.id(),
        owner_creation: super::super::shell::tests::creation_generation_of(helper.id()),
        ..lease_owner.clone()
    };
    let registry = Registry::default();
    let command = fixture_at(PREFIX, "sg96_session_fixture_sleep", &root.0);
    let started = registry
        .start(&command, &session_limits(), &helper_owner, far())
        .expect("session under the helper owner");
    let _ = helper.kill();
    let _ = helper.wait();
    assert!(wait_for(|| !registry
        .status(&started.session_id)
        .unwrap()
        .state
        .is_running()));
    let status = registry.status(&started.session_id).unwrap();
    assert!(
        matches!(&status.state, SessionState::Revoked { reason } if reason.contains("owner")),
        "{:?}",
        status.state
    );
    assert!(process_gone(status.process.pid));
}

#[test]
fn sg000096_t03_an_expired_authority_launches_nothing() {
    let _serial = serial();
    let root = disposable("session-expired");
    let owner = protected_owner(&root.0);
    let registry = Registry::default();
    let command = fixture_at(PREFIX, "sg96_session_fixture_sleep", &root.0);
    let before = super::super::shell::LAUNCHES.load(std::sync::atomic::Ordering::SeqCst);
    let result = registry.start(&command, &session_limits(), &owner, Instant::now());
    assert!(matches!(
        result,
        Err(SessionFailure::Shell(ShellFailure::Denied(_)))
    ));
    assert_eq!(
        super::super::shell::LAUNCHES.load(std::sync::atomic::Ordering::SeqCst),
        before
    );
    assert!(registry.list().is_empty());
}
