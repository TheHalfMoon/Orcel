//! The process-tree walk `native_qualify` uses to prove the shell starts no
//! process beyond WebView2's own (`support/qualify.rs`): it follows only real
//! parent links, so an orphan whose dead parent's PID was reused inside the
//! tree (CI run 44271489652: the MSVC linker's `vctip.exe`, left behind by
//! the build) is not taken for the shell's child, while every real child,
//! and every process that cannot be dated, still is.
//!
//! Read-only: a process snapshot and query-only handles. No window, input
//! or child process.

#![cfg(windows)]

#[path = "support/qualify.rs"]
mod qualify;

use qualify::{descendants, is_child_of, Proc};

fn proc(pid: u32, parent: u32, exe: &str, created: Option<u64>) -> Proc {
    Proc {
        pid,
        parent,
        exe: exe.into(),
        created,
    }
}

fn pids(tree: &[Proc]) -> Vec<u32> {
    let mut pids: Vec<u32> = tree.iter().map(|proc| proc.pid).collect();
    pids.sort_unstable();
    pids
}

#[test]
fn a_child_created_after_its_parent_is_a_child() {
    let shell = proc(100, 4, "orcel-control-room-shell.exe", Some(1_000));
    let webview = proc(200, 100, "msedgewebview2.exe", Some(1_001));
    assert!(is_child_of(&webview, &shell));
}

#[test]
fn an_orphan_older_than_the_reused_parent_pid_is_not_a_child() {
    // link.exe was PID 100 and started vctip.exe; link.exe exited and the
    // shell was later given PID 100.
    let shell = proc(100, 4, "orcel-control-room-shell.exe", Some(5_000));
    let vctip = proc(300, 100, "vctip.exe", Some(1_000));
    assert!(!is_child_of(&vctip, &shell));
}

#[test]
fn a_process_that_cannot_be_dated_is_kept() {
    let shell = proc(100, 4, "orcel-control-room-shell.exe", Some(5_000));
    let undated = proc(300, 100, "unknown.exe", None);
    assert!(is_child_of(&undated, &shell));
    let undated_parent = proc(100, 4, "orcel-control-room-shell.exe", None);
    let older = proc(301, 100, "older.exe", Some(1_000));
    assert!(is_child_of(&older, &undated_parent));
}

#[test]
fn only_the_recorded_parent_counts() {
    let shell = proc(100, 4, "orcel-control-room-shell.exe", Some(1_000));
    let other = proc(200, 101, "other.exe", Some(2_000));
    assert!(!is_child_of(&other, &shell));
    let idle = proc(0, 100, "[System Process]", Some(2_000));
    assert!(!is_child_of(&idle, &shell));
    assert!(!is_child_of(&shell, &shell));
}

#[test]
fn the_tree_skips_orphans_at_any_depth_and_keeps_real_grandchildren() {
    let all = vec![
        proc(4, 0, "System", None),
        proc(100, 4, "orcel-control-room-shell.exe", Some(5_000)),
        proc(200, 100, "msedgewebview2.exe", Some(5_100)),
        proc(210, 200, "msedgewebview2.exe", Some(5_200)),
        // A real grandchild that is not WebView2: still reported.
        proc(220, 210, "unexpected.exe", Some(5_300)),
        // Orphans of dead processes whose PIDs the shell and its browser
        // now hold, and an orphan's own child.
        proc(300, 100, "vctip.exe", Some(1_000)),
        proc(310, 200, "vctip.exe", Some(1_100)),
        proc(320, 300, "conhost.exe", Some(1_200)),
        // Unrelated.
        proc(400, 4, "explorer.exe", Some(10)),
    ];
    let tree = descendants(100, all);
    assert_eq!(pids(&tree), vec![100, 200, 210, 220]);
}

#[test]
fn this_process_is_found_dated_in_a_live_snapshot() {
    let me = std::process::id();
    let all = qualify::processes();
    let this = all
        .iter()
        .find(|proc| proc.pid == me)
        .expect("this process is in the snapshot");
    assert!(
        this.created.is_some(),
        "this process can be dated: {this:?}"
    );
    let tree = qualify::tree(me);
    assert!(tree.iter().any(|proc| proc.pid == me));
    // Whatever else is under this test process was created after it.
    let created = this.created.unwrap_or_default();
    for proc in tree.iter().filter(|proc| proc.pid != me) {
        assert!(
            proc.created.is_none_or(|child| child >= created),
            "{proc:?}"
        );
    }
}
