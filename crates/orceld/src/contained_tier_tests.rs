//! XP-13b unit tests for the contained-tier wiring. The end-to-end run
//! through the real helper is `legacy::tests::xp13b_a_registered_contained_executable_runs_under_the_helper`
//! in `main.rs`.

use super::*;
use std::time::Duration;

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "orceld-xp13b-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(dir).unwrap()
}

const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn xp13b_the_pin_file_holds_exactly_one_lowercase_sha256() {
    assert_eq!(
        parse_pin_named(DIGEST.as_bytes(), PIN_NAME).unwrap(),
        DIGEST
    );
    assert_eq!(
        parse_pin_named(format!("{DIGEST}\n").as_bytes(), PIN_NAME).unwrap(),
        DIGEST
    );
    assert_eq!(
        parse_pin_named(format!("{DIGEST}\r\n").as_bytes(), PIN_NAME).unwrap(),
        DIGEST
    );
    for bad in [
        String::new(),
        DIGEST.to_uppercase(),
        DIGEST[..63].to_owned(),
        format!("{DIGEST}  orcel-contain\n"),
        format!("{DIGEST}\n\n"),
        format!(" {DIGEST}"),
    ] {
        let error = parse_pin_named(bad.as_bytes(), PIN_NAME).unwrap_err();
        assert_eq!(error.code, FailureCode::ProviderUnavailable, "{bad:?}");
    }
}

#[test]
fn xp13b_the_helper_is_pinned_only_from_its_own_directory() {
    let dir = temp_dir("pin");
    // No pin file: the contained tier is not installed.
    let error = helper_pin_in(&dir).unwrap_err();
    assert_eq!(error.code, FailureCode::ProviderUnavailable);
    assert!(error.message.contains(PIN_NAME), "{}", error.message);
    std::fs::write(dir.join(PIN_NAME), "not a digest\n").unwrap();
    assert_eq!(
        helper_pin_in(&dir).unwrap_err().code,
        FailureCode::ProviderUnavailable
    );
    std::fs::write(dir.join(PIN_NAME), format!("{DIGEST}\n")).unwrap();
    let pin = helper_pin_in(&dir).unwrap();
    assert_eq!(pin.path(), dir.join(HELPER_NAME));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn xp13b_the_spec_grants_the_cwd_read_only_and_nothing_writable() {
    let workspace = temp_dir("spec-workspace");
    let scratch = temp_dir("spec-scratch");
    let plan = orcel_provider_process::build_execution_plan(
        &workspace,
        std::env::current_exe().unwrap(),
        &["--version".to_owned()],
        ".",
        &Default::default(),
        orcel_provider_process::ExecutionLimits {
            timeout: Duration::from_secs(7),
            stdout_bytes: 100,
            stderr_bytes: 50,
        },
    )
    .unwrap();
    // #384 item 2: no registered digest, no contained run.
    assert_eq!(
        spec_for(&plan, scratch.clone()).unwrap_err().code,
        FailureCode::TargetStale
    );
    let mut plan = plan;
    plan.registered_sha256 = Some(DIGEST.to_owned());
    let spec = spec_for(&plan, scratch.clone()).unwrap();
    assert_eq!(spec.executable, plan.executable);
    assert_eq!(spec.executable_sha256, DIGEST);
    assert_eq!(spec.argv, plan.argv);
    assert_eq!(spec.workdir, scratch);
    assert_eq!(spec.readable, vec![workspace.clone()]);
    assert!(spec.writable.is_empty());
    assert_eq!(spec.limits.timeout, Duration::from_secs(7));
    assert_eq!(spec.limits.stdout_bytes, 100);
    assert_eq!(spec.limits.stderr_bytes, 50);
    assert_eq!(spec.limits.cpu_seconds, 7);
    let _ = std::fs::remove_dir_all(workspace);
    let _ = std::fs::remove_dir_all(scratch);
}

/// Judge nit on #380: the pin is only as good as its directory, so a pin or
/// helper that another user could replace makes the tier unavailable.
#[cfg(unix)]
#[test]
fn xp13b_a_replaceable_pin_or_helper_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("pin-shared");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(dir.join(PIN_NAME), format!("{DIGEST}\n")).unwrap();
    std::fs::write(dir.join(HELPER_NAME), b"helper").unwrap();
    for file in [PIN_NAME, HELPER_NAME] {
        std::fs::set_permissions(dir.join(file), std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    assert!(helper_pin_in(&dir).is_ok());
    for file in [PIN_NAME, HELPER_NAME] {
        std::fs::set_permissions(dir.join(file), std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            helper_pin_in(&dir).unwrap_err().code,
            FailureCode::ProviderUnavailable,
            "{file}"
        );
        std::fs::set_permissions(dir.join(file), std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        helper_pin_in(&dir).unwrap_err().code,
        FailureCode::ProviderUnavailable
    );
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

/// #384 item 2: the helper's digest refusal reaches the caller as a stale
/// target, like a tampered helper, not as an unavailable tier.
#[test]
fn xp13b_a_digest_mismatch_in_the_helper_is_a_stale_target() {
    let error = map_contained_error(ContainedError::Refused {
        kind: RefusalKind::ExecutableChanged,
        message: "digest mismatch".into(),
    });
    assert_eq!(error.code, FailureCode::TargetStale);
    let error = map_contained_error(ContainedError::Refused {
        kind: RefusalKind::LaunchFailed,
        message: "no".into(),
    });
    assert_eq!(error.code, FailureCode::ProviderUnavailable);
}
