//! MAC-M1-08 on the hosted macOS runner: `orcel emergency-revoke` through
//! the real `orcel` CLI and the real `orceld` beside it (the pinned
//! next-to-`orcel` binary, XP-17), with nobody at the runner to answer.
//!
//! The CLI must name LocalAuthentication in its prompt; orceld's STRONG
//! check (summary dialog then LocalAuthentication) must fail closed headless;
//! nothing is revoked; and the refusal is in orceld's audit log. The donor's
//! two bypass variables are set and must change nothing (S-24). The test
//! uses its own `HOME`, so the runner user's state is never touched.
//!
//! The founder's approve-and-cancel run on a real Mac is UNVERIFIED here.
//! With `ORCEL_REQUIRE_MACOS_REVOKE=1` (CI), a missing `orceld` beside
//! `orcel` fails instead of skipping.
#![cfg(target_os = "macos")]

use orcel_lifecycle::config::{Config, WorkspaceEntry};
use orcel_lifecycle::layout::Layout;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn unique(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("orcel-mac-m1-08-{label}-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

#[test]
fn emergency_revoke_fails_closed_headless_revokes_nothing_and_is_audited() {
    let orcel = Path::new(env!("CARGO_BIN_EXE_orcel"));
    let orceld = orcel.with_file_name("orceld");
    if !orceld.is_file() {
        assert!(
            std::env::var_os("ORCEL_REQUIRE_MACOS_REVOKE").is_none(),
            "build orceld beside orcel first ({})",
            orceld.display()
        );
        eprintln!("MAC-M1-08 skipped: no orceld beside orcel");
        return;
    }
    let home = unique("home");
    let root = home
        .join("Library")
        .join("Application Support")
        .join("Orcel");
    let workspace = home.join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    Config {
        workspaces: vec![WorkspaceEntry {
            id: "ci".into(),
            root: workspace,
        }],
        ..Config::default()
    }
    .save(&Layout::new(&root))
    .unwrap();
    // orceld holds its state root to XP-01's private-directory rule (0700)
    // and repairs nothing, while `Config::save` creates the root with the
    // umask. An installed Orcel gets 0700 from the installer (MAC-M1-03);
    // here the root is made private as that install would leave it.
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

    let started = std::time::Instant::now();
    let output = std::process::Command::new(orcel)
        .arg("emergency-revoke")
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("CUA_ENV_SKIP_SENSITIVE_AUTH", "1")
        .env("CUA_ENV_ALLOW_UNVERIFIED_SENSITIVE_EXPORT", "1")
        .output()
        .expect("run orcel emergency-revoke");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "emergency revoke succeeded headless:\n{stdout}\n{stderr}"
    );
    assert!(
        stderr.contains(
            "Confirm with Touch ID or your password (LocalAuthentication) when prompted. Every pending approval will be invalidated."
        ),
        "{stderr}"
    );
    assert!(!stderr.contains("Windows Hello"), "{stderr}");
    assert!(!stdout.contains("Emergency revoke recorded"), "{stdout}");

    let audit = fs::read_to_string(root.join("audit.jsonl")).unwrap_or_else(|error| {
        panic!("orceld wrote no audit log ({error}); orcel said:\n{stdout}\n{stderr}")
    });
    let lines: Vec<&str> = audit
        .lines()
        .filter(|line| line.contains("trust.revoke_emergency"))
        .collect();
    assert!(!lines.is_empty(), "no revoke attempt was audited:\n{audit}");
    assert!(
        lines.iter().all(|line| !line.contains("\"SUCCESS\"")),
        "a revoke was recorded as done:\n{audit}"
    );
    let outcome = lines
        .iter()
        .find_map(|line| {
            [
                "APPROVAL_UNAVAILABLE",
                "APPROVAL_DENIED",
                "FAILED",
                "DENIED",
            ]
            .into_iter()
            .find(|outcome| line.contains(&format!("\"{outcome}\"")))
        })
        .unwrap_or("unknown");
    assert_ne!(outcome, "unknown", "{audit}");
    let reason = stderr
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    println!(
        "MAC-M1-08-EVIDENCE emergency_revoke exit={} audited_outcome={outcome} revoked=false bypass_env_ignored=true seconds={} reason={reason:?}",
        output.status.code().unwrap_or(-1),
        started.elapsed().as_secs()
    );
}
