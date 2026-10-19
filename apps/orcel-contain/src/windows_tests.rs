// SPDX-License-Identifier: MIT
// Portions copyright (c) 2025 Cua AI, Inc.; modifications copyright Orcel.

//! Unit tests for `windows.rs`, from the donor
//! (blob ac9b94724a3a9b0e5f042145446ed021102a6986). The journal and ACL-lease
//! tests are gone with the code they tested, and so is the cross-process
//! rename proof, which re-ran the test binary under `CUA_DRIVER_ACL_RENAME_*`
//! marker variables; Orcel's refusal test is at the end.

use super::*;

// Windows may map generic rights to their file-specific equivalents.
const FILE_READ_EXECUTE: u32 = 0x0012_00A9;
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
const DELETE: u32 = 0x0001_0000;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const INHERIT_ONLY_ACE: u8 = 0x08;
const INHERITED_ACE: u8 = 0x10;

fn test_profile_name() -> String {
    format!("{APP_CONTAINER_NAME_PREFIX}.{}", random_token().unwrap())
}

fn canonical_test_root(root: &tempfile::TempDir) -> PathBuf {
    std::fs::canonicalize(root.path()).unwrap()
}

fn open_delete_shared(path: &Path) -> OwnedHandle {
    let name = wide(path.as_os_str());
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle as isize == -1 {
        panic!(
            "failed to pre-open {} with DELETE access: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    OwnedHandle(handle)
}

fn is_equivalent_file_grant(mask: u32, requested: u32) -> bool {
    mask == requested
        || match requested {
            requested if requested == (GENERIC_READ | GENERIC_EXECUTE) => mask == FILE_READ_EXECUTE,
            GENERIC_ALL => mask == FILE_ALL_ACCESS,
            _ => false,
        }
}

#[test]
fn generated_profile_names_fit_the_windows_limit() {
    let first = test_profile_name();
    let second = test_profile_name();
    assert_ne!(first, second);
    assert!(first.encode_utf16().count() <= 64);
    validate_profile_name(&first).unwrap();
}

#[repr(C)]
struct AceHeader {
    ace_type: u8,
    ace_flags: u8,
    ace_size: u16,
}

#[repr(C)]
struct AccessAllowedAce {
    header: AceHeader,
    mask: u32,
    sid_start: u32,
}

fn matching_grants(path: &Path, sid: *mut c_void) -> Result<(bool, Vec<(u32, u8)>), ContainError> {
    #[link(name = "advapi32")]
    extern "system" {
        fn EqualSid(left: *mut c_void, right: *mut c_void) -> Bool;
        fn GetAce(acl: *const c_void, index: u32, ace: *mut *mut c_void) -> Bool;
        fn GetSecurityDescriptorControl(
            descriptor: *mut c_void,
            control: *mut u16,
            revision: *mut u32,
        ) -> Bool;
    }

    let target = AclTarget::open(path)?;
    let mut dacl: *mut c_void = std::ptr::null_mut();
    let mut descriptor: *mut c_void = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            target.handle.get(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || dacl.is_null() || descriptor.is_null() {
        return Err(containment_error(
            "failed to inspect a contained process ACL in a test",
            Some(format!("os error {status}")),
        ));
    }
    let descriptor = LocalAcl(descriptor);
    let mut control = 0_u16;
    let mut revision = 0_u32;
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == FALSE {
        return Err(last_error(
            "failed to inspect contained process ACL control flags in a test",
        ));
    }

    #[repr(C)]
    struct AclHeader {
        revision: u8,
        sbz1: u8,
        size: u16,
        ace_count: u16,
        sbz2: u16,
    }

    let ace_count = unsafe { (*(dacl.cast::<AclHeader>())).ace_count };
    let mut grants = Vec::new();
    for index in 0..u32::from(ace_count) {
        let mut raw: *mut c_void = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut raw) } == FALSE || raw.is_null() {
            return Err(last_error(
                "failed to inspect a contained process ACL entry in a test",
            ));
        }
        let ace = unsafe { &*raw.cast::<AccessAllowedAce>() };
        if ace.header.ace_type != 0 {
            continue;
        }
        let ace_sid = std::ptr::addr_of!(ace.sid_start).cast_mut().cast();
        if unsafe { EqualSid(ace_sid, sid) } != FALSE {
            grants.push((ace.mask, ace.header.ace_flags));
        }
    }
    Ok((control & 0x1000 != 0, grants))
}

fn protect_tree(path: &Path, grants: &[(*mut c_void, u32)]) {
    walk_acl_tree(path, &mut |target| {
        let acl = build_acl(grants, target.inheritance(true), std::ptr::null_mut())?;
        apply_dacl(
            target.handle.get(),
            acl.0,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            "failed to protect a contained process test path",
        )
    })
    .unwrap();
}

#[test]
fn every_job_ui_restriction_is_applied() {
    for restriction in [
        JOB_OBJECT_UILIMIT_HANDLES,
        JOB_OBJECT_UILIMIT_READCLIPBOARD,
        JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
        JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
        JOB_OBJECT_UILIMIT_GLOBALATOMS,
        JOB_OBJECT_UILIMIT_DESKTOP,
        JOB_OBJECT_UILIMIT_EXITWINDOWS,
    ] {
        assert_eq!(JOB_OBJECT_UILIMIT_ALL & restriction, restriction);
    }
}

#[test]
fn wait_status_requires_a_signaled_process() {
    assert!(classify_wait_status(WAIT_OBJECT_0, || {
        panic!("a successful wait must not inspect the last error")
    })
    .is_ok());

    let failed =
        classify_wait_status(WAIT_FAILED, || std::io::Error::from_raw_os_error(6)).unwrap_err();
    assert_eq!(failed.raw_os_error(), Some(6));

    let timeout = classify_wait_status(WAIT_TIMEOUT, || {
        panic!("an unexpected wait status must not inspect the last error")
    })
    .unwrap_err();
    assert!(timeout
        .to_string()
        .contains("unexpected WaitForSingleObject status"));
}

#[test]
fn app_container_delete_classifies_idempotent_results() {
    assert_eq!(classify_app_container_delete(0), Ok(()));
    assert_eq!(classify_app_container_delete(1), Ok(()));
    assert_eq!(classify_app_container_delete(-2_147_024_894), Ok(()));
    assert_eq!(classify_app_container_delete(-2_147_023_728), Ok(()));
    assert_eq!(classify_app_container_delete(-1), Err(-1));
}

#[test]
fn repeated_wait_failures_reach_the_process_fatal_boundary() {
    assert!(!cleanup_wait_is_fatal(CLEANUP_WAIT_FAILURE_ATTEMPTS - 1));
    assert!(cleanup_wait_is_fatal(CLEANUP_WAIT_FAILURE_ATTEMPTS));
}

#[test]
fn repeated_authority_cleanup_failures_reach_the_process_fatal_boundary() {
    assert!(!cleanup_authority_failure_is_fatal(
        CLEANUP_AUTHORITY_FAILURE_ATTEMPTS - 1
    ));
    assert!(cleanup_authority_failure_is_fatal(
        CLEANUP_AUTHORITY_FAILURE_ATTEMPTS
    ));
}

#[test]
fn the_desktop_grant_withholds_hooks_and_desktop_switching() {
    const DESKTOP_HOOKCONTROL: u32 = 0x0008;
    const DESKTOP_JOURNALRECORD: u32 = 0x0010;
    const DESKTOP_JOURNALPLAYBACK: u32 = 0x0020;
    const DESKTOP_SWITCHDESKTOP: u32 = 0x0100;
    for withheld in [
        DESKTOP_HOOKCONTROL,
        DESKTOP_JOURNALRECORD,
        DESKTOP_JOURNALPLAYBACK,
        DESKTOP_SWITCHDESKTOP,
    ] {
        assert_eq!(DESKTOP_CHILD_ACCESS & withheld, 0);
    }
}

#[test]
fn the_command_line_quotes_arguments_that_could_otherwise_split() {
    let rendered = command_line(
        Path::new(r"C:\Program Files\orcel\child.exe"),
        &["--manifest".to_owned(), r"C:\a b\m.json".to_owned()],
    );
    let rendered = String::from_utf16(&rendered[..rendered.len() - 1]).unwrap();
    assert_eq!(
        rendered,
        "\"C:\\Program Files\\orcel\\child.exe\" --manifest \"C:\\a b\\m.json\""
    );
}

#[test]
fn the_environment_block_carries_only_loader_and_private_child_paths() {
    let child_root = tempfile::tempdir().unwrap();
    let block = environment_block(child_root.path()).unwrap();
    let rendered = String::from_utf16(&block).unwrap();
    let entries = rendered
        .split('\0')
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.split_once('=').unwrap())
        .collect::<std::collections::HashMap<_, _>>();

    let expected_profile = child_root.path().join("profile");
    let expected_roaming = expected_profile.join("AppData").join("Roaming");
    let expected_local = expected_profile.join("AppData").join("Local");
    assert_eq!(entries["TEMP"], child_root.path().display().to_string());
    assert_eq!(entries["TMP"], child_root.path().display().to_string());
    assert_eq!(
        entries["USERPROFILE"],
        expected_profile.display().to_string()
    );
    assert_eq!(entries["APPDATA"], expected_roaming.display().to_string());
    assert_eq!(
        entries["LOCALAPPDATA"],
        expected_local.display().to_string()
    );
    assert!(entries.contains_key("SystemRoot"));
    assert!(entries.contains_key("windir"));
    assert!(entries.contains_key("PATH"));
    for unrelated in ["HTTP_PROXY", "PATHEXT", "USERNAME", "HOMEDRIVE"] {
        assert!(
            !entries.contains_key(unrelated),
            "{unrelated} reached the child"
        );
    }
    for path in [&expected_profile, &expected_roaming, &expected_local] {
        assert!(path.is_dir(), "{} was not created", path.display());
        assert!(path.starts_with(child_root.path()));
    }
    for name in ["USERPROFILE", "APPDATA", "LOCALAPPDATA"] {
        assert!(Path::new(entries[name]).starts_with(child_root.path()));
        if let Some(host) = std::env::var_os(name) {
            assert_ne!(
                normalize_windows_path(Path::new(entries[name])),
                normalize_windows_path(Path::new(&host)),
                "{name} reused the host profile path"
            );
        }
    }
    assert!(rendered.ends_with("\0\0"));
}

#[test]
fn final_handle_paths_compare_without_win32_namespace_prefixes() {
    assert_eq!(
        normalize_windows_path(Path::new(r"\\?\C:\Orcel\Child")),
        normalize_windows_path(Path::new(r"c:\orcel\child\"))
    );
    assert_eq!(
        normalize_windows_path(Path::new(r"\\?\UNC\server\share\child")),
        normalize_windows_path(Path::new(r"\\server\share\child"))
    );
}

#[test]
fn protected_descendants_receive_direct_least_privilege_grants() {
    let root = tempfile::tempdir().unwrap();
    let bundle = root.path().join("bundle");
    let models = bundle.join("models");
    let model = models.join("detector.onnx");
    let working = root.path().join("working");
    let scratch = working.join("capture.png");
    std::fs::create_dir_all(&models).unwrap();
    std::fs::create_dir(&working).unwrap();
    std::fs::write(&model, b"model").unwrap();
    std::fs::write(&scratch, b"capture").unwrap();

    // Production boundaries are canonicalized before ACL admission. Match
    // that contract so Windows short-path aliases cannot affect this test.
    let root = canonical_test_root(&root);
    let bundle = root.join("bundle");
    let models = bundle.join("models");
    let model = models.join("detector.onnx");
    let working = root.join("working");
    let scratch = working.join("capture.png");

    let user = current_user_sid().unwrap();
    protect_tree(&bundle, &[(user.sid(), GENERIC_ALL)]);
    let container = AppContainerSid::create_unique().unwrap();
    let boundary = FilesystemBoundary {
        readable: vec![bundle.clone(), working.clone()],
        writable: vec![working.clone()],
        executables: Vec::new(),
    };
    let mut ledger = grant_child_paths(&working, &boundary, user.sid(), container.sid()).unwrap();

    for directory in [&bundle, &models] {
        let (protected, grants) = matching_grants(directory, container.sid()).unwrap();
        assert!(protected, "{} lost DACL protection", directory.display());
        assert!(grants.iter().any(|(mask, flags)| {
            is_equivalent_file_grant(*mask, GENERIC_READ | GENERIC_EXECUTE)
                && u32::from(*flags) & SUB_CONTAINERS_AND_OBJECTS_INHERIT == NO_INHERITANCE
        }));
    }
    let (protected, grants) = matching_grants(&model, container.sid()).unwrap();
    assert!(protected, "{} lost DACL protection", model.display());
    assert!(grants.iter().any(|(mask, flags)| {
        is_equivalent_file_grant(*mask, GENERIC_READ | GENERIC_EXECUTE)
            && u32::from(*flags) & SUB_CONTAINERS_AND_OBJECTS_INHERIT == NO_INHERITANCE
    }));

    let (_, grants) = matching_grants(&working, container.sid()).unwrap();
    assert!(grants.iter().any(|(mask, flags)| {
        is_equivalent_file_grant(*mask, GENERIC_ALL)
            && u32::from(*flags) & SUB_CONTAINERS_AND_OBJECTS_INHERIT
                == SUB_CONTAINERS_AND_OBJECTS_INHERIT
    }));
    let (_, grants) = matching_grants(&scratch, container.sid()).unwrap();
    assert!(grants.iter().any(|(mask, flags)| {
        is_equivalent_file_grant(*mask, GENERIC_ALL)
            && u32::from(*flags) & SUB_CONTAINERS_AND_OBJECTS_INHERIT == NO_INHERITANCE
    }));

    ledger.revoke().unwrap();
    for path in [&bundle, &models, &model, &working, &scratch] {
        let (_, grants) = matching_grants(path, container.sid()).unwrap();
        assert!(
            grants.is_empty(),
            "{} retained a temporary AppContainer grant",
            path.display()
        );
    }
    assert!(matching_grants(&bundle, container.sid()).unwrap().0);
    assert!(!matching_grants(&working, container.sid()).unwrap().0);
}

#[test]
fn recursive_grants_do_not_escape_the_boundary_root() {
    let root = tempfile::tempdir().unwrap();
    let bundle = root.path().join("bundle");
    let working = root.path().join("working");
    let outside = root.path().join("outside.bin");
    std::fs::create_dir(&bundle).unwrap();
    std::fs::create_dir(&working).unwrap();
    std::fs::write(bundle.join("inside.bin"), b"inside").unwrap();
    std::fs::write(&outside, b"outside").unwrap();

    let root = canonical_test_root(&root);
    let bundle = root.join("bundle");
    let working = root.join("working");
    let outside = root.join("outside.bin");

    let user = current_user_sid().unwrap();
    let container = AppContainerSid::create_unique().unwrap();
    let boundary = FilesystemBoundary {
        readable: vec![bundle, working.clone()],
        writable: vec![working.clone()],
        executables: Vec::new(),
    };
    let _ledger = grant_child_paths(&working, &boundary, user.sid(), container.sid()).unwrap();

    let (_, grants) = matching_grants(&outside, container.sid()).unwrap();
    assert!(
        grants.is_empty(),
        "a sibling outside the boundary was granted"
    );
}

#[test]
fn a_partial_recursive_grant_is_rolled_back() {
    let root = tempfile::tempdir().unwrap();
    let bundle = root.path().join("bundle");
    let model = bundle.join("detector.onnx");
    let working = root.path().join("working");
    std::fs::create_dir(&bundle).unwrap();
    std::fs::create_dir(&working).unwrap();
    std::fs::write(&model, b"model").unwrap();

    let root = canonical_test_root(&root);
    let bundle = root.join("bundle");
    let model = bundle.join("detector.onnx");
    let missing = root.join("missing");
    let working = root.join("working");

    let user = current_user_sid().unwrap();
    let container = AppContainerSid::create_unique().unwrap();
    let boundary = FilesystemBoundary {
        readable: vec![bundle.clone(), missing],
        writable: vec![working.clone()],
        executables: Vec::new(),
    };
    assert!(grant_child_paths(&working, &boundary, user.sid(), container.sid()).is_err());

    for path in [&bundle, &model, &working] {
        let (_, grants) = matching_grants(path, container.sid()).unwrap();
        assert!(
            grants.is_empty(),
            "{} retained a grant after rollback",
            path.display()
        );
    }
}

#[test]
fn overlapping_roots_keep_the_stronger_single_grant() {
    let root = tempfile::tempdir().unwrap();
    let bundle = root.path().join("bundle");
    let writable = bundle.join("cache");
    let artifact = writable.join("compiled.bin");
    let working = root.path().join("working");
    std::fs::create_dir_all(&writable).unwrap();
    std::fs::create_dir(&working).unwrap();
    std::fs::write(&artifact, b"cache").unwrap();

    let root = canonical_test_root(&root);
    let bundle = root.join("bundle");
    let writable = bundle.join("cache");
    let artifact = writable.join("compiled.bin");
    let working = root.join("working");

    let user = current_user_sid().unwrap();
    let container = AppContainerSid::create_unique().unwrap();
    let boundary = FilesystemBoundary {
        readable: vec![bundle],
        writable: vec![working.clone(), writable.clone()],
        executables: Vec::new(),
    };
    let _ledger = grant_child_paths(&working, &boundary, user.sid(), container.sid()).unwrap();

    for path in [&writable, &artifact] {
        let (_, grants) = matching_grants(path, container.sid()).unwrap();
        assert_eq!(
            grants
                .iter()
                .filter(|(_, flags)| flags & (INHERITED_ACE | INHERIT_ONLY_ACE) == 0)
                .count(),
            1,
            "{} received duplicate direct grants",
            path.display()
        );
        assert!(grants
            .iter()
            .all(|(mask, _)| is_equivalent_file_grant(*mask, GENERIC_ALL)));
    }
}

#[test]
fn only_writable_directories_grant_new_descendants() {
    let root = tempfile::tempdir().unwrap();
    let readable = root.path().join("models");
    let writable = root.path().join("cache");
    let working = root.path().join("working");
    std::fs::create_dir(&readable).unwrap();
    std::fs::create_dir(&writable).unwrap();
    std::fs::create_dir(&working).unwrap();

    let root = canonical_test_root(&root);
    let readable = root.join("models");
    let writable = root.join("cache");
    let working = root.join("working");

    let user = current_user_sid().unwrap();
    let container = AppContainerSid::create_unique().unwrap();
    let boundary = FilesystemBoundary {
        readable: vec![readable.clone(), writable.clone(), working.clone()],
        writable: vec![working.clone(), writable.clone()],
        executables: Vec::new(),
    };
    let _ledger = grant_child_paths(&working, &boundary, user.sid(), container.sid()).unwrap();

    let new_model = readable.join("late-model.onnx");
    let new_cache = writable.join("late-cache.bin");
    std::fs::write(&new_model, b"model").unwrap();
    std::fs::write(&new_cache, b"cache").unwrap();
    assert!(matching_grants(&new_model, container.sid())
        .unwrap()
        .1
        .is_empty());
    let (_, grants) = matching_grants(&new_cache, container.sid()).unwrap();
    assert!(grants
        .iter()
        .any(|(mask, _)| is_equivalent_file_grant(*mask, GENERIC_ALL)));
}

#[test]
fn acl_target_open_conflicts_with_existing_delete_handles() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("model.bin"), b"model").unwrap();
    std::fs::create_dir(root.path().join("models")).unwrap();

    let root = canonical_test_root(&root);
    for path in [root.join("model.bin"), root.join("models")] {
        let delete_handle = open_delete_shared(&path);
        let error = match AclTarget::open(&path) {
            Ok(_) => panic!(
                "opened {} without delete sharing while a DELETE handle was live",
                path.display()
            ),
            Err(error) => error,
        };
        assert_eq!(
            error.detail.as_deref(),
            Some("os error 32"),
            "opening {} failed with an unexpected error: {error:?}",
            path.display()
        );

        drop(delete_handle);
        AclTarget::open(&path).unwrap_or_else(|error| {
            panic!(
                "failed to open {} after releasing the DELETE handle: {error:?}",
                path.display()
            )
        });
    }
}

#[test]
fn failed_revocation_is_retained_for_retry() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("model.bin");
    std::fs::write(&target, b"model").unwrap();

    let root = canonical_test_root(&root);
    let target = root.join("model.bin");

    let container = AppContainerSid::create_unique().unwrap();
    let mut ledger = AclGrantLedger::default();
    ledger
        .merge_grant_tree(&target, container.sid(), GENERIC_READ, false)
        .unwrap();
    assert_eq!(ledger.entries.len(), 1);

    let handle = ledger.entries[0].target.handle.get();
    assert_ne!(unsafe { CloseHandle(handle) }, FALSE);
    ledger.entries[0].target.handle.0 = std::ptr::null_mut();

    let mut cleanup = PendingCleanup {
        process: 0,
        process_reaped: true,
        grants: Some(ledger),
        container: None,
    };
    assert!(cleanup.cleanup_reaped_once().is_err());
    assert_eq!(cleanup.grants.as_ref().unwrap().entries.len(), 1);
}

#[test]
fn an_app_container_profile_that_cannot_be_created_is_a_refusal() {
    // 65 UTF-16 units: over the Windows limit, so no profile can exist and
    // nothing may launch.
    let name = format!("{APP_CONTAINER_NAME_PREFIX}.{}", "0".repeat(48));
    assert!(name.encode_utf16().count() > 64);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    let executable = std::env::current_exe().unwrap();
    let boundary = FilesystemBoundary {
        readable: vec![canonical_test_root(&root)],
        writable: vec![canonical_test_root(&root)],
        executables: vec![executable.clone()],
    };
    let limits = ContainmentLimits {
        max_memory_bytes: 1 << 30,
        max_cpu_time: Duration::from_secs(5),
        max_open_files: 64,
        additional_writable_paths: Vec::new(),
        additional_readable_paths: Vec::new(),
    };
    let refused = runtime.block_on(spawn_named(
        &name,
        &executable,
        &[],
        root.path(),
        &boundary,
        &limits,
    ));
    assert_eq!(
        refused.err().map(|refusal| refusal.code),
        Some(crate::containment::ErrorCode::LaunchFailed)
    );
}
