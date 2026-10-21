//! #373 item 1: the built helper makes itself non-dumpable before it reads
//! the request. While it waits on stdin, its `/proc/<pid>` files belong to
//! root and this user can no longer read its memory map. No display is
//! needed: the helper is still reading stdin when this is checked.

#[cfg(target_os = "linux")]
#[test]
fn xp10_helper_is_not_dumpable_while_it_reads_the_request() {
    use std::os::unix::fs::MetadataExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let our_uid = std::fs::metadata("/proc/self").expect("own proc").uid();
    if our_uid == 0 {
        eprintln!("skipped: root can trace any process, so ownership proves nothing");
        return;
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_orcel-approval-helper-linux"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the helper");
    let proc_dir = format!("/proc/{}", child.id());
    let deadline = Instant::now() + Duration::from_secs(10);
    let owner = loop {
        let owner = std::fs::metadata(format!("{proc_dir}/maps"))
            .expect("helper proc entry")
            .uid();
        if owner != our_uid || Instant::now() > deadline {
            break owner;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let maps = std::fs::read(format!("{proc_dir}/maps"));
    // Closing stdin ends the helper: an empty request is refused unanswered.
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait");
    assert_eq!(
        owner, 0,
        "the helper's /proc entries still belong to uid {our_uid}"
    );
    assert!(
        maps.is_err(),
        "this user could still read the helper's memory map"
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}
