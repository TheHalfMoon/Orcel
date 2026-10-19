// SPDX-License-Identifier: MIT
// Portions copyright (c) 2025 Cua AI, Inc.; modifications copyright Orcel.

//! Unit tests for `containment.rs`: the donor's contract and root tests
//! (blob 6179d5eac250382b76ad951a9abfc1c950193be8), adapted to the exact
//! boundary, plus Orcel's fail-closed and source tests.

use super::*;

fn limits() -> ContainmentLimits {
    ContainmentLimits {
        max_memory_bytes: 1 << 30,
        max_cpu_time: Duration::from_secs(10),
        max_open_files: 64,
        additional_writable_paths: Vec::new(),
        additional_readable_paths: Vec::new(),
    }
}

#[test]
fn every_supported_target_meets_the_containment_contract() {
    // A target that cannot install one of these boundaries must reach the
    // fail-closed branch in `spawn` instead of launching a child.
    let reported = capabilities();
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    assert!(
        reported.meets_contract(),
        "a supported target reported an incomplete boundary set: {reported:?}"
    );
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    assert!(!reported.meets_contract());
}

#[test]
fn macos_reports_its_memory_ceiling_as_sampled_rather_than_kernel_enforced() {
    #[cfg(target_os = "macos")]
    assert_eq!(
        capabilities().memory_limit,
        MemoryLimitEnforcement::SupervisorSampling
    );
    #[cfg(any(target_os = "linux", windows))]
    assert_eq!(capabilities().memory_limit, MemoryLimitEnforcement::Kernel);
}

#[test]
fn removing_any_single_boundary_breaks_the_contract() {
    let full = capabilities();
    if !full.meets_contract() {
        return;
    }
    let mut variants = Vec::new();
    for index in 0..11 {
        let mut weaker = full;
        let field = match index {
            0 => &mut weaker.process_tree_cleanup,
            1 => &mut weaker.parent_death,
            2 => &mut weaker.parent_eof,
            3 => &mut weaker.inherited_handle_closure,
            4 => &mut weaker.cpu_limit,
            5 => &mut weaker.process_creation_denial,
            6 => &mut weaker.filesystem_read_isolation,
            7 => &mut weaker.filesystem_write_isolation,
            8 => &mut weaker.network_isolation,
            9 => &mut weaker.process_memory_isolation,
            _ => &mut weaker.desktop_input_isolation,
        };
        *field = false;
        variants.push(weaker);
    }
    let mut no_memory = full;
    no_memory.memory_limit = MemoryLimitEnforcement::None;
    variants.push(no_memory);
    for weaker in variants {
        assert!(!weaker.meets_contract(), "{weaker:?} met the contract");
    }
}

/// The capability check runs before anything else: a platform that reports
/// one missing boundary launches nothing, whatever the spec says.
#[test]
fn an_incomplete_capability_report_refuses_to_spawn() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    let mut weaker = capabilities();
    weaker.network_isolation = false;
    let executable = std::env::current_exe().unwrap();
    let refused = runtime.block_on(spawn_checked(
        weaker,
        &executable,
        &[],
        root.path(),
        &limits(),
    ));
    assert_eq!(
        refused.err().map(|refusal| refusal.code),
        Some(ErrorCode::UnsupportedPlatform)
    );
}

#[test]
fn broad_directories_are_refused_as_roots() {
    for candidate in [
        "/",
        "/usr",
        "/tmp",
        "/etc",
        "/usr/lib",
        "/usr/local",
        "/Users/someone",
        "/home/someone",
        "/private/var",
        "/System/Library",
        r"C:\",
        r"C:\Users\someone",
        r"C:\Windows",
    ] {
        assert!(
            reject_broad_read_root(Path::new(candidate)).is_err(),
            "{candidate} was accepted as a root"
        );
    }
    for candidate in [
        "/opt/orcel/parsers/pdf",
        "/Users/someone/.orcel/work/0001",
        "/tmp/.tmpA1b2c3",
    ] {
        assert!(
            reject_broad_read_root(Path::new(candidate)).is_ok(),
            "{candidate} was refused as a root"
        );
    }
}

#[test]
fn collapsed_roots_drop_paths_an_ancestor_already_covers() {
    let collapsed = collapse_roots(vec![
        PathBuf::from("/opt/orcel/models"),
        PathBuf::from("/opt/orcel"),
        PathBuf::from("/opt/orcel"),
        PathBuf::from("/opt/orcelity"),
    ]);
    assert_eq!(
        collapsed,
        vec![PathBuf::from("/opt/orcel"), PathBuf::from("/opt/orcelity")]
    );
}

/// Unlike the donor, nothing is derived: neither the executable's directory
/// nor a path that appears in an argument becomes readable.
#[test]
fn the_boundary_is_exactly_the_spec() {
    let bundle = tempfile::tempdir().unwrap();
    let working = tempfile::tempdir().unwrap();
    let extra = tempfile::tempdir().unwrap();
    // Spec paths must be canonical (macOS temp dirs sit behind `/var`).
    let executable = std::fs::canonicalize(bundle.path()).unwrap().join("parser");
    std::fs::write(&executable, b"#!/bin/sh\n").unwrap();
    let mut limits = limits();
    limits.additional_readable_paths = vec![std::fs::canonicalize(extra.path()).unwrap()];
    let working_path = std::fs::canonicalize(working.path()).unwrap();

    let boundary = filesystem_boundary(&executable, &working_path, &limits).unwrap();

    let canonical_working = std::fs::canonicalize(working.path()).unwrap();
    let canonical_extra = std::fs::canonicalize(extra.path()).unwrap();
    let canonical_bundle = std::fs::canonicalize(bundle.path()).unwrap();
    let mut expected = vec![canonical_working.clone(), canonical_extra];
    expected.sort();
    assert_eq!(boundary.readable, expected);
    assert_eq!(boundary.writable, vec![canonical_working]);
    assert_eq!(
        boundary.executables,
        vec![std::fs::canonicalize(&executable).unwrap()]
    );
    assert!(!boundary.readable.contains(&canonical_bundle));
}

/// The helper reads no environment variable, so no variable (the donor's
/// `CUA_ENV_SKIP_*`/`CUA_TEST_PYTHON*` included) can widen or skip a
/// boundary. `tests/contain.rs` proves the same at run time.
#[test]
fn shipped_helper_source_reads_no_environment_variable() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut checked = 0;
    for entry in std::fs::read_dir(&source).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".rs") || name.ends_with("_tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        for forbidden in [
            "env::var",
            "env::vars",
            "var_os(",
            "getenv",
            "CUA_ENV_",
            "CUA_TEST_",
            "CUA_DRIVER_",
        ] {
            assert!(!text.contains(forbidden), "{name} contains {forbidden}");
        }
        checked += 1;
    }
    assert!(checked >= 6, "only {checked} source files were checked");
}

/// Roots and the executable must be named canonically; a link is refused,
/// not followed.
#[cfg(unix)]
#[test]
fn a_root_or_executable_reached_through_a_link_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(root.path()).unwrap();
    let real = root.join("real");
    std::fs::create_dir(&real).unwrap();
    let link = root.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(canonical_directory(&real).is_ok());
    assert!(canonical_directory(&link).is_err());
    assert!(canonical_directory(&real.join("..").join("real")).is_err());
    let file = real.join("tool");
    std::fs::write(&file, b"x").unwrap();
    let file_link = root.join("tool");
    std::os::unix::fs::symlink(&file, &file_link).unwrap();
    assert!(canonical_file(&file).is_ok());
    assert!(canonical_file(&file_link).is_err());
}
