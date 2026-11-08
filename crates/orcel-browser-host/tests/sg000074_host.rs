//! SG-000074 live browser-host integration: supervised launch, private
//! channel handshake, second-launch refusal, deterministic shutdown, and
//! the typed unavailable path. When no engine is installed the test proves
//! typed unavailability instead of failing; both outcomes are real
//! assertions and neither falls back to a personal browser.

use orcel_browser_host::{HostError, SearchConfig, Supervisor, UnavailableReason};
use std::fs;
use std::path::PathBuf;

fn temp_root(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "orcel-host-it-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn host_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_orcel-browser-host"))
}

#[test]
fn isolated_search_without_engines_reports_typed_unavailable() {
    let scratch = temp_root("empty");
    let mut supervisor = Supervisor::new();
    let result = supervisor.launch(
        &host_binary(),
        &scratch,
        &SearchConfig::isolated(vec![scratch.join("no-engines-here")]),
    );
    match result {
        Err(HostError::Unavailable(
            UnavailableReason::NoEngine | UnavailableReason::UnsupportedEngine,
        )) if !cfg!(target_os = "macos") => {}
        // XP-14: macOS refuses before discovery until SG-000115.
        Err(HostError::Unavailable(UnavailableReason::UnsupportedRuntime))
            if cfg!(target_os = "macos") => {}
        other => panic!("expected typed unavailable, got {other:?}"),
    }
    assert!(!supervisor.is_live());
    let _ = fs::remove_dir_all(&scratch);
}

/// XP-14: on macOS nothing launches, even with the machine's own engines
/// in view (GitHub's macOS images have Chrome and Edge installed).
#[cfg(target_os = "macos")]
#[test]
fn macos_refuses_to_launch_before_discovery() {
    let scratch = temp_root("macos");
    let mut supervisor = Supervisor::new();
    let result = supervisor.launch(&host_binary(), &scratch, &SearchConfig::production());
    assert!(
        matches!(
            result,
            Err(HostError::Unavailable(
                UnavailableReason::UnsupportedRuntime
            ))
        ),
        "{result:?}"
    );
    assert!(!supervisor.is_live());
    let _ = fs::remove_dir_all(&scratch);
}

#[test]
fn live_host_or_typed_unavailable_with_lifecycle() {
    let scratch = temp_root("live");
    let mut supervisor = Supervisor::new();
    let launched = supervisor.launch(&host_binary(), &scratch, &SearchConfig::production());
    let identity = match launched {
        Err(HostError::Unavailable(_)) => {
            // No engine on this machine: unavailability is the qualified
            // outcome, and nothing launched.
            assert!(!supervisor.is_live());
            let _ = fs::remove_dir_all(&scratch);
            return;
        }
        Err(other) => panic!("launch must fail only as typed unavailable: {other:?}"),
        Ok(identity) => identity,
    };
    assert!(!identity.host_id.is_empty());
    assert!(!identity.engine_fingerprint.is_empty());
    assert!(!identity.profile_identity.is_empty());
    assert!(supervisor.is_live());
    // A second concurrent host is refused: the bound is one.
    assert!(supervisor
        .launch(&host_binary(), &scratch, &SearchConfig::production())
        .is_err());
    // Profile directory exists while live.
    let profile_dirs: Vec<PathBuf> = fs::read_dir(&scratch)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(profile_dirs.len(), 1);
    // Round-trip through the private channel.
    supervisor.ping("sg-000074-live").expect("ping");
    // Shutdown is deterministic and removes the ephemeral profile.
    let confirmed = supervisor.shutdown().expect("shutdown");
    assert!(confirmed);
    assert!(!supervisor.is_live());
    assert!(fs::read_dir(&scratch).unwrap().next().is_none());
    assert!(supervisor.shutdown().expect("second shutdown"));
    let _ = fs::remove_dir_all(&scratch);
}

/// SG-000108 product caller: without the test-only `live-browser-test`
/// feature, the host binary has no worker mode at all: `--worker` is an
/// unknown argument, refused before any discovery or launch.
#[cfg(not(feature = "live-browser-test"))]
#[test]
fn worker_mode_does_not_exist_without_the_test_feature() {
    let output = std::process::Command::new(host_binary())
        .args(["--worker", "--host-id", "h"])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run the host binary");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown argument: --worker"), "{stderr}");
}
