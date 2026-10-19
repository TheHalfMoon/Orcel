// SPDX-License-Identifier: MIT
// Portions copyright (c) 2025 Cua AI, Inc.; modifications copyright Orcel.

//! Unit tests for `macos.rs`: the donor's profile and sentinel tests
//! (blob 28f9d8120057001db53dd40f80b591e290234469) plus Orcel's refusal test.

use super::*;

fn profile_for(readable: &[&str], writable: &[&str]) -> String {
    build_profile(&FilesystemBoundary {
        readable: readable.iter().map(PathBuf::from).collect(),
        writable: writable.iter().map(PathBuf::from).collect(),
        executables: readable.iter().map(PathBuf::from).collect(),
    })
    .unwrap()
}

#[test]
fn the_profile_denies_capture_input_and_credential_authority() {
    let profile = profile_for(&["/opt/orcel/parser"], &["/tmp/.tmpcontained"]);
    assert!(profile.starts_with("(version 1)\n(deny default)\n"));
    // The broad grants that previously re-granted the helper's own TCC
    // authority to the child must not reappear.
    for forbidden in [
        "(allow mach-lookup)",
        "(allow iokit-open)",
        "(allow file-read*)\n",
        "(allow process-exec*)\n",
        "com.apple.windowserver",
        "com.apple.tccd",
        "com.apple.pasteboard",
        "com.apple.SecurityServer",
    ] {
        assert!(
            !profile.contains(forbidden),
            "the profile still contains {forbidden}:\n{profile}"
        );
    }
    assert!(profile.contains("(subpath \"/opt/orcel/parser\")"));
    assert!(profile.contains("(deny process-fork)"));
}

#[test]
fn writable_paths_never_widen_beyond_the_requested_roots() {
    let profile = profile_for(&["/opt/orcel/parser"], &["/tmp/.tmpcontained"]);
    let writes = profile
        .split("(allow file-write*\n")
        .nth(1)
        .expect("the profile grants writes");
    assert!(writes.starts_with("  (subpath \"/tmp/.tmpcontained\")\n)\n"));
}

#[test]
fn a_crafted_path_cannot_inject_profile_syntax() {
    let profile = profile_for(&["/opt/\") (allow default) (subpath \"/"], &["/tmp/w"]);
    assert!(profile.contains("(subpath \"/opt/\\\") (allow default) (subpath \\\"/\")"));
    assert!(!profile.contains("(allow default)\n"));
}

#[test]
fn the_sentinel_script_kills_the_group_and_hides_its_descriptor() {
    assert!(PARENT_DEATH_SENTINEL.contains("read -r orcel_parent_gone <&3"));
    assert!(PARENT_DEATH_SENTINEL.contains("kill -9 -$$"));
    assert!(PARENT_DEATH_SENTINEL.contains("exec 3<&-"));
    assert!(PARENT_DEATH_SENTINEL.trim_end().ends_with("exec \"$@\""));
}

/// Darwin has no `PR_SET_PDEATHSIG`, so the parent-death claim rests
/// entirely on this sentinel. Closing the helper's end of the pipe stands in
/// for the helper dying; a child that ignores termination signals must
/// still be gone afterwards.
#[test]
fn closing_the_sentinel_pipe_kills_a_child_that_ignores_signals() {
    use std::os::unix::process::CommandExt as _;

    let (read, write) = sentinel_pipe().unwrap();
    let source = read.as_raw_fd();
    let mut command = std::process::Command::new(SHELL);
    command
        .arg("-c")
        .arg(PARENT_DEATH_SENTINEL)
        .arg("orcel-contain-supervisor")
        .arg(SHELL)
        .arg("-c")
        .arg("trap '' TERM INT HUP; while :; do sleep 1; done")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0);
    // SAFETY: `pre_exec` runs in the forked child before exec; the closure only calls dup2,
    // close and fcntl on the descriptor number it captured, which are async-signal-safe, and
    // allocates nothing.
    unsafe {
        command.pre_exec(move || {
            if source != SENTINEL_DESCRIPTOR && libc::dup2(source, SENTINEL_DESCRIPTOR) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            close_inherited_descriptors(Some(SENTINEL_DESCRIPTOR))
        });
    }
    let mut child = command.spawn().unwrap();
    drop(read);

    // The child is alive and unreachable by an ordinary termination
    // signal before the helper's end of the sentinel pipe closes.
    std::thread::sleep(Duration::from_millis(250));
    assert!(child.try_wait().unwrap().is_none());

    drop(write);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success(), "the sentinel did not kill the child");
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the child outlived its helper"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn the_executable_is_readable_as_an_exact_file_not_through_its_directory() {
    let profile = build_profile(&FilesystemBoundary {
        readable: vec![PathBuf::from("/tmp/.tmpcontained")],
        writable: vec![PathBuf::from("/tmp/.tmpcontained")],
        executables: vec![PathBuf::from("/opt/orcel/parser/bin/parse")],
    })
    .unwrap();
    assert!(profile.contains("(literal \"/opt/orcel/parser/bin/parse\")"));
    assert!(!profile.contains("(subpath \"/opt/orcel/parser"));
}

#[test]
fn a_missing_sandbox_exec_is_a_refusal_not_an_unsandboxed_launch() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let boundary = FilesystemBoundary {
        readable: Vec::new(),
        writable: Vec::new(),
        executables: Vec::new(),
    };
    let limits = ContainmentLimits {
        max_memory_bytes: 1 << 30,
        max_cpu_time: Duration::from_secs(5),
        max_open_files: 64,
        additional_writable_paths: Vec::new(),
        additional_readable_paths: Vec::new(),
    };
    let refused = runtime.block_on(spawn_with_tools(
        Path::new(SHELL),
        Path::new("/usr/bin/orcel-no-such-sandbox-exec"),
        Path::new("/bin/echo"),
        &[],
        Path::new("/tmp"),
        &boundary,
        &limits,
    ));
    assert_eq!(
        refused.err().map(|refusal| refusal.code),
        Some(crate::containment::ErrorCode::UnsupportedPlatform)
    );
}

#[test]
fn sysctl_reads_are_limited_to_named_startup_facts() {
    let profile = profile_for(&["/opt/orcel/parser"], &["/tmp/.tmpcontained"]);
    assert!(!profile.contains("(allow sysctl-read)"));
    assert!(profile.contains("(sysctl-name \"hw.ncpu\")"));
    for denied in ["kern.proc", "kern.hostname", "net."] {
        assert!(!profile.contains(denied), "{denied} is readable");
    }
}

/// XP-13b: no rule grants `file-link` (nor `file*`, which would include it),
/// so the child cannot give any file a second name, even inside its write
/// root. The end-to-end proof is `xp13_the_contained_process_cannot_create_a_hard_link`.
#[test]
fn the_profile_grants_no_hard_link_creation() {
    let profile = profile_for(&["/opt/orcel/parser"], &["/tmp/.tmpcontained"]);
    for forbidden in ["file-link", "(allow file*", "(allow file\n"] {
        assert!(
            !profile.contains(forbidden),
            "the profile grants {forbidden}:\n{profile}"
        );
    }
}
