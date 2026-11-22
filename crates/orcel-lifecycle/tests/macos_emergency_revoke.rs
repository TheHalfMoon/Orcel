//! MAC-M1-08 on the hosted macOS runner, before the macOS M1 activation.
//!
//! `orcel emergency-revoke` on macOS runs only the `orceld` of the verified
//! per-user install (activation checklist): never a binary found beside
//! `orcel`. While `host_platform()` still refuses the install on macOS, the
//! command must therefore refuse with the not-activated message, even though
//! a real `orceld` sits beside `orcel` (the CI step builds it there): no
//! prompt, no `orceld`, nothing audited. The STRONG path itself, through the
//! installed `orceld`, is exercised in `macos_install.rs`
//! (`the_installed_orceld_refuses_emergency_revoke_headless`).
//!
//! `Config::save` (the first write of `orcel workspace add`) creates the
//! state folder 0700 on macOS, as orceld requires (activation checklist).
//!
//! The test uses its own `HOME`. With `ORCEL_REQUIRE_MACOS_REVOKE=1` (CI), a
//! missing `orceld` beside `orcel` fails instead of skipping.
#![cfg(target_os = "macos")]

use orcel_lifecycle::config::{Config, WorkspaceEntry};
use orcel_lifecycle::layout::Layout;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

fn unique(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("orcel-mac-m1-08-{label}-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

#[test]
fn emergency_revoke_never_runs_a_sibling_orceld_before_activation() {
    let orcel = Path::new(env!("CARGO_BIN_EXE_orcel"));
    let sibling = orcel.with_file_name("orceld");
    if !sibling.is_file() {
        assert!(
            std::env::var_os("ORCEL_REQUIRE_MACOS_REVOKE").is_none(),
            "build orceld beside orcel first ({})",
            sibling.display()
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
    let root_mode = fs::metadata(&root).unwrap().mode() & 0o777;
    assert_eq!(
        root_mode, 0o700,
        "Config::save made the state folder private"
    );

    let output = std::process::Command::new(orcel)
        .arg("emergency-revoke")
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("run orcel emergency-revoke");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stdout}\n{stderr}");
    assert!(
        stderr.contains("not activated on macOS"),
        "the not-activated refusal:\n{stderr}"
    );
    assert!(
        !stderr.contains("Confirm with"),
        "nothing was asked before the refusal:\n{stderr}"
    );
    assert!(
        !root.join("audit.jsonl").exists(),
        "no orceld ran, so nothing was audited"
    );
    println!(
        "MAC-M1-08-EVIDENCE preactivation sibling_orceld_present=true refused=true orceld_launched=false state_root_mode={root_mode:o} exit={}",
        output.status.code().unwrap_or(-1)
    );
}
