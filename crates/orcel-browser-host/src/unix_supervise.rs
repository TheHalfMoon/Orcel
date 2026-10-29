//! SG-000115 slice A2, inert pre-activation engineering (category A2 in
//! `docs/orcel/implementation-readiness/prep/SG-000115.md`): Unix process
//! supervision and bounded descendant tracking, the counterpart of the
//! Windows Job Object sweep (`terminate_and_confirm`).
//!
//! Compiled only into Unix test builds (`#[cfg(all(test, unix))]` in
//! `lib.rs`); `libc` is a Unix dev-dependency only. No release build
//! contains it and no production path calls it: `supervise.rs`'s Unix
//! platform module is unchanged, and macOS/Linux launch stays refused.
//! Tests spawn only fixture processes (`sh`, `sleep`, `python3`), never a
//! browser.
//!
//! The shape:
//! - The child starts in a new process group.
//! - Its family is the group plus every descendant reachable by parent
//!   links, enumerated with a bound ([`MAX_SCAN`] processes scanned,
//!   [`MAX_FAMILY`] members) and pinned by start time, so a reused pid is
//!   never signalled.
//! - The sweep kills the group and every pinned member, then confirms each
//!   one exited before the deadline.
//!
//! Open, not accepted (category C): a helper that leaves the group and is
//! orphaned (its parent exits) before a scan reparents to init on macOS,
//! which has no subreaper, and is then outside the parent-link walk. On
//! Linux, `PR_SET_CHILD_SUBREAPER` closes that gap only when the
//! supervisor process sets it, which activation must decide and qualify;
//! this slice does not set it on the shared test process.
//!
//! Also open for activation (not solved here):
//! - **Forks after the scan.** The sweep is one snapshot, so a member outside
//!   the group can fork between the scan and the kills, and its new child is
//!   never pinned. Activation needs stop-then-rescan (`SIGSTOP`, rescan until
//!   stable, `SIGKILL`) or a kill-and-rescan loop.
//! - **Check-to-kill window.** The start-time check and the kill are two
//!   calls; on Linux a pidfd closes the window; on macOS it stays a residual.
//! - **Family bound.** `MAX_FAMILY` must be qualified against a real Chrome
//!   or Edge tree; exceeding it fails closed.

use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// At most this many processes are scanned per enumeration; more fails
/// closed (the sweep still kills the group).
pub(crate) const MAX_SCAN: usize = 65_536;
/// At most this many members in one supervised family, the Unix
/// counterpart of the Windows job's active-process limit.
pub(crate) const MAX_FAMILY: usize = 32;

/// A process identity that survives pid reuse: the pid and its start time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Pinned {
    pub(crate) pid: i32,
    pub(crate) start: u64,
}

/// One row of the process table: identity, parent and group.
#[derive(Debug, Clone, Copy)]
struct Row {
    pinned: Pinned,
    ppid: i32,
    pgid: i32,
}

/// Why a family could not be established; every case fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FamilyError {
    /// The process table could not be read.
    Unreadable,
    /// More processes than the scan bound.
    ScanBound,
    /// More family members than the family bound.
    FamilyBound,
}

/// A supervised fixture: the child in its own process group.
pub(crate) struct Supervised {
    child: Child,
    root: Pinned,
    /// While armed, dropping kills the family: a failing test never leaves
    /// fixture processes behind. Disarmed once the root is reaped, because
    /// its pgid may then belong to someone else.
    armed: bool,
}

impl Drop for Supervised {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(table) = process_table() {
            for member in family_of(self.root, &table).0 {
                kill_pinned(member);
            }
        }
        // SAFETY: the root is unreaped while armed, so this pgid is ours.
        unsafe { libc::killpg(self.root.pid, libc::SIGKILL) };
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Supervised {
    /// Spawn `command` as the leader of a new process group.
    pub(crate) fn spawn(mut command: Command) -> std::io::Result<Self> {
        command.process_group(0);
        let mut child = command.spawn()?;
        let start = i32::try_from(child.id())
            .ok()
            .and_then(|pid| match start_time(pid) {
                Ok(Some(start)) => Some((pid, start)),
                _ => None,
            });
        let Some((pid, start)) = start else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::other(
                "the fixture's identity cannot be pinned",
            ));
        };
        Ok(Self {
            child,
            root: Pinned { pid, start },
            armed: true,
        })
    }

    pub(crate) fn root(&self) -> Pinned {
        self.root
    }

    /// The family: the root's group and every descendant by parent links,
    /// each pinned by its start time.
    pub(crate) fn family(&self) -> Result<Vec<Pinned>, FamilyError> {
        let table = process_table()?;
        match family_of(self.root, &table) {
            (_, Some(error)) => Err(error),
            (members, None) => Ok(members),
        }
    }

    /// Kill the group and every pinned member, reap the root, and confirm
    /// that every member is gone before `deadline`. Returns the members
    /// still alive (empty on success).
    pub(crate) fn sweep(mut self, deadline: Duration) -> Result<Vec<Pinned>, FamilyError> {
        let (family, error) = match process_table() {
            Ok(table) => family_of(self.root, &table),
            Err(error) => (Vec::new(), Some(error)),
        };
        // Kill the group and every member found, even when the scan or the
        // family bound failed: a partial set is still killed.
        // SAFETY: the root is unreaped here, so this pgid is ours.
        unsafe { libc::killpg(self.root.pid, libc::SIGKILL) };
        for member in &family {
            kill_pinned(*member);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.armed = false;
        if let Some(error) = error {
            return Err(error);
        }
        let started = Instant::now();
        loop {
            let alive: Vec<Pinned> = family
                .iter()
                .copied()
                .filter(|member| is_alive(*member))
                .collect();
            if alive.is_empty() || started.elapsed() >= deadline {
                return Ok(alive);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Signal a member only while its start time still matches (no reused pid).
fn kill_pinned(member: Pinned) {
    if start_time(member.pid) == Ok(Some(member.start)) {
        // SAFETY: plain signal to a pid whose identity was just re-checked.
        unsafe { libc::kill(member.pid, libc::SIGKILL) };
    }
}

/// Alive means the same process (pid and start time) still exists and is
/// not a zombie awaiting its reaper. A process that cannot be read counts
/// as alive: its exit cannot be confirmed.
pub(crate) fn is_alive(member: Pinned) -> bool {
    match row_of(member.pid) {
        Ok(Some((row, dead))) => row.pinned.start == member.start && !dead,
        Ok(None) => false,
        Err(_) => true,
    }
}

/// The family of `root` within `table`: its process group plus every
/// descendant by parent links, bounded.
fn family_of(root: Pinned, table: &[Row]) -> (Vec<Pinned>, Option<FamilyError>) {
    let mut children: BTreeMap<i32, Vec<Row>> = BTreeMap::new();
    for row in table {
        children.entry(row.ppid).or_default().push(*row);
    }
    let mut family: BTreeMap<i32, Pinned> = BTreeMap::new();
    for row in table.iter().filter(|row| row.pgid == root.pid) {
        family.insert(row.pinned.pid, row.pinned);
    }
    // The root is a member only while it is the same process.
    if table.iter().any(|row| row.pinned == root) {
        family.insert(root.pid, root);
    }
    let mut queue: Vec<i32> = family.keys().copied().collect();
    while let Some(pid) = queue.pop() {
        for child in children.get(&pid).into_iter().flatten() {
            if family.insert(child.pinned.pid, child.pinned).is_none() {
                queue.push(child.pinned.pid);
            }
            if family.len() > MAX_FAMILY {
                return (
                    family.into_values().collect(),
                    Some(FamilyError::FamilyBound),
                );
            }
        }
    }
    if family.len() > MAX_FAMILY {
        return (
            family.into_values().collect(),
            Some(FamilyError::FamilyBound),
        );
    }
    (family.into_values().collect(), None)
}

#[cfg(target_os = "linux")]
mod table {
    use super::{FamilyError, Pinned, Row, MAX_SCAN};

    /// Parse `/proc/<pid>/stat`: (ppid, pgid, start time, zombie). The
    /// command name may contain spaces and parentheses, so fields are read
    /// after the last `)`.
    pub(super) fn parse_stat(text: &str) -> Option<(i32, i32, u64, bool)> {
        let rest = &text[text.rfind(')')? + 1..];
        let fields: Vec<&str> = rest.split_whitespace().collect();
        // After the name: state(0) ppid(1) pgrp(2) ... starttime(19).
        let state = fields.first()?;
        let ppid = fields.get(1)?.parse().ok()?;
        let pgid = fields.get(2)?.parse().ok()?;
        let start = fields.get(19)?.parse().ok()?;
        Some((ppid, pgid, start, *state == "Z" || *state == "X"))
    }

    /// `Ok(None)` only when the process is gone (ENOENT, ESRCH); any other
    /// failure fails closed.
    pub(super) fn row_of(pid: i32) -> Result<Option<(Row, bool)>, FamilyError> {
        let text = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(text) => text,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ESRCH) =>
            {
                return Ok(None)
            }
            Err(_) => return Err(FamilyError::Unreadable),
        };
        let (ppid, pgid, start, dead) = parse_stat(&text).ok_or(FamilyError::Unreadable)?;
        Ok(Some((
            Row {
                pinned: Pinned { pid, start },
                ppid,
                pgid,
            },
            dead,
        )))
    }

    pub(super) fn process_table() -> Result<Vec<Row>, FamilyError> {
        let mut rows = Vec::new();
        let entries = std::fs::read_dir("/proc").map_err(|_| FamilyError::Unreadable)?;
        for (scanned, entry) in entries.enumerate() {
            if scanned >= MAX_SCAN {
                return Err(FamilyError::ScanBound);
            }
            let Ok(entry) = entry else {
                return Err(FamilyError::Unreadable);
            };
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
            else {
                continue;
            };
            // A process that exited between the listing and the read is
            // gone; any other read failure fails closed.
            if let Some((row, _)) = row_of(pid)? {
                rows.push(row);
            }
        }
        Ok(rows)
    }
}

#[cfg(target_os = "macos")]
mod table {
    use super::{FamilyError, Pinned, Row, MAX_SCAN};

    /// `Ok(None)` only when the process is gone (ESRCH); any other failure
    /// fails closed.
    pub(super) fn row_of(pid: i32) -> Result<Option<(Row, bool)>, FamilyError> {
        // SAFETY: proc_bsdinfo is plain data; zeroed is a valid value.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: the buffer is exactly one proc_bsdinfo of `size` bytes.
        let read = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        if read != size {
            let errno = std::io::Error::last_os_error().raw_os_error();
            return if errno == Some(libc::ESRCH) {
                Ok(None)
            } else {
                Err(FamilyError::Unreadable)
            };
        }
        let start = info
            .pbi_start_tvsec
            .wrapping_mul(1_000_000)
            .wrapping_add(info.pbi_start_tvusec);
        // SZOMB is 5 in <sys/proc.h>.
        let zombie = info.pbi_status == 5;
        Ok(Some((
            Row {
                pinned: Pinned { pid, start },
                ppid: info.pbi_ppid as i32,
                pgid: info.pbi_pgid as i32,
            },
            zombie,
        )))
    }

    pub(super) fn process_table() -> Result<Vec<Row>, FamilyError> {
        let mut pids = vec![0i32; MAX_SCAN];
        let bytes = (pids.len() * std::mem::size_of::<i32>()) as libc::c_int;
        // SAFETY: the buffer holds MAX_SCAN pids of `bytes` bytes.
        let count = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        if count <= 0 {
            return Err(FamilyError::Unreadable);
        }
        let count = count as usize;
        if count >= MAX_SCAN {
            return Err(FamilyError::ScanBound);
        }
        let mut rows = Vec::new();
        for pid in pids[..count].iter().filter(|pid| **pid > 0) {
            if let Some((row, _)) = row_of(*pid)? {
                rows.push(row);
            }
        }
        Ok(rows)
    }
}

use table::{process_table, row_of};

/// The start time of a process, `Ok(None)` when it is gone.
fn start_time(pid: i32) -> Result<Option<u64>, FamilyError> {
    Ok(row_of(pid)?.map(|(row, _)| row.pinned.start))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEADLINE: Duration = Duration::from_secs(10);

    fn sh(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(script);
        command
    }

    /// Wait until the family satisfies `ready`, bounded by `DEADLINE`.
    fn family_until(supervised: &Supervised, ready: impl Fn(&[Pinned]) -> bool) -> Vec<Pinned> {
        let started = Instant::now();
        loop {
            let family = supervised.family().unwrap();
            if ready(&family) || started.elapsed() > DEADLINE {
                return family;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn outside_group(family: &[Pinned], group: i32) -> Vec<Pinned> {
        family
            .iter()
            .copied()
            .filter(|member| matches!(row_of(member.pid), Ok(Some((row, _))) if row.pgid != group))
            .collect()
    }

    #[test]
    fn the_family_is_the_group_and_the_sweep_confirms_every_exit() {
        let supervised = Supervised::spawn(sh("sleep 60 & sleep 60 & wait")).unwrap();
        let family = family_until(&supervised, |family| family.len() >= 3);
        assert!(family.len() >= 3, "{family:?}");
        assert!(family.contains(&supervised.root()));
        let left = supervised.sweep(DEADLINE).unwrap();
        assert!(left.is_empty(), "{left:?}");
        for member in family {
            assert!(!is_alive(member), "{member:?}");
        }
    }

    /// A helper that leaves the group (setsid) while its parent lives is
    /// still found by the parent-link walk and swept.
    #[test]
    fn a_descendant_that_leaves_the_group_is_still_swept() {
        let script = "python3 -c 'import os,time; os.setsid(); time.sleep(60)' & wait";
        let supervised = Supervised::spawn(sh(script)).unwrap();
        let root = supervised.root();
        // Wait for the helper to have called setsid, not merely to exist.
        let family = family_until(&supervised, |family| {
            !outside_group(family, root.pid).is_empty()
        });
        let escaped = outside_group(&family, root.pid);
        assert!(
            !escaped.is_empty(),
            "the setsid helper is in the family: {family:?}"
        );
        let left = supervised.sweep(DEADLINE).unwrap();
        assert!(left.is_empty(), "{left:?}");
        for member in escaped {
            assert!(!is_alive(member), "the escaped helper is gone: {member:?}");
        }
    }

    /// A test that fails before its sweep leaves no fixture behind: the
    /// armed guard kills the family on drop.
    #[test]
    fn dropping_an_armed_fixture_kills_its_family() {
        let supervised = Supervised::spawn(sh("sleep 60 & sleep 60 & wait")).unwrap();
        let family = family_until(&supervised, |family| family.len() >= 3);
        assert!(family.len() >= 3, "{family:?}");
        drop(supervised);
        let started = Instant::now();
        while family.iter().any(|member| is_alive(*member)) && started.elapsed() < DEADLINE {
            std::thread::sleep(Duration::from_millis(20));
        }
        for member in family {
            assert!(!is_alive(member), "{member:?}");
        }
    }

    #[test]
    fn a_family_beyond_the_bound_fails_closed() {
        let root = Pinned { pid: 100, start: 1 };
        let mut table = vec![Row {
            pinned: root,
            ppid: 1,
            pgid: 100,
        }];
        for index in 0..=MAX_FAMILY as i32 {
            table.push(Row {
                pinned: Pinned {
                    pid: 1000 + index,
                    start: 1,
                },
                ppid: 100,
                pgid: 100,
            });
        }
        let (members, error) = family_of(root, &table);
        assert_eq!(error, Some(FamilyError::FamilyBound));
        // The partial set is still returned, so the sweep can kill it.
        assert!(members.len() > MAX_FAMILY, "{}", members.len());
    }

    #[test]
    fn a_reused_pid_is_not_a_family_member() {
        // The root's pid now belongs to a different process (other start
        // time): it is not the root, and its children are not followed
        // through it unless they are in the root's group.
        let root = Pinned { pid: 100, start: 1 };
        let table = vec![
            Row {
                pinned: Pinned { pid: 100, start: 2 },
                ppid: 1,
                pgid: 7,
            },
            Row {
                pinned: Pinned { pid: 101, start: 3 },
                ppid: 100,
                pgid: 7,
            },
        ];
        assert_eq!(family_of(root, &table), (Vec::new(), None));
    }

    #[test]
    fn a_pinned_identity_with_another_start_time_is_not_alive() {
        let me = std::process::id() as i32;
        let start = start_time(me).unwrap().unwrap();
        assert!(is_alive(Pinned { pid: me, start }));
        assert!(!is_alive(Pinned {
            pid: me,
            start: start.wrapping_add(1)
        }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stat_lines_with_hostile_names_parse_after_the_last_parenthesis() {
        let line = "42 (a) b) (c) S 7 42 42 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0";
        assert_eq!(table::parse_stat(line), Some((7, 42, 12345, false)));
        assert_eq!(
            table::parse_stat("42 (z) Z 7 42 42 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 9 0"),
            Some((7, 42, 9, true))
        );
        assert_eq!(table::parse_stat("garbage"), None);
    }

    /// Pre-activation boundary: only lib.rs (the test-only declaration)
    /// names this module; production supervision is unchanged.
    #[test]
    fn the_unix_supervisor_is_unreachable_from_production() {
        let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let src = crate_dir.join("src");
        let mut named = Vec::new();
        for entry in std::fs::read_dir(&src).unwrap() {
            let path = entry.unwrap().path();
            if path == src.join("unix_supervise.rs") || path == src.join("lib.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            if text.contains("unix_supervise") {
                named.push(path.display().to_string());
            }
        }
        assert!(named.is_empty(), "{named:?}");
        let lib = std::fs::read_to_string(src.join("lib.rs"))
            .unwrap()
            .replace("\r\n", "\n");
        assert!(lib.contains("#[cfg(all(test, unix))]\nmod unix_supervise;\n"));
        assert_eq!(
            lib.matches("unix_supervise").count(),
            2,
            "one comment and one declaration"
        );
        let manifest = std::fs::read_to_string(crate_dir.join("Cargo.toml"))
            .unwrap()
            .replace("\r\n", "\n");
        let (_, unix_dev) = manifest
            .split_once("[target.'cfg(unix)'.dev-dependencies]\n")
            .expect("libc is a Unix dev-dependency");
        assert!(unix_dev.trim_start().starts_with("libc = "));
        assert_eq!(
            manifest.matches("libc").count(),
            1,
            "libc is declared once, as a Unix dev-dependency"
        );
    }
}
