//! SG-000115 slice A2, inert pre-activation engineering (category A2 in
//! `docs/orcel/implementation-readiness/prep/SG-000115.md`): Unix process
//! supervision and bounded descendant tracking, the counterpart of the
//! Windows Job Object sweep (`terminate_and_confirm`).
//!
//! Compiled only into Unix test builds (`#[cfg(all(test, unix))]` in
//! `lib.rs`); `libc` is a Unix dev-dependency only. No release build
//! contains it and no production path calls it: `supervise.rs`'s Unix
//! platform module is unchanged, and macOS/Linux launch stays refused.
//! Tests spawn only fixture processes (`python3`, `sleep`), never a
//! browser and never a shell.
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
//! `sweep` is that snapshot sweep and always reports `Incomplete` coverage.
//!
//! **Verified termination (A2b, `verified_sweep`).** The only path that can
//! report `VerifiedComplete`:
//! - **Linux, a dedicated supervisor process that is a subreaper**
//!   (`PR_SET_CHILD_SUBREAPER`, set before the fixture starts). Every
//!   orphaned descendant, including one that called `setsid` or `setpgid`
//!   and whose parent exited, is reparented to the supervisor (or to a
//!   subreaper that is itself a descendant). The sweep kills every
//!   descendant it finds, reaps, and repeats until `waitpid(-1)` reports
//!   `ECHILD`: a process with no children has no descendants, so that is
//!   the proof. Forks after a scan are caught by the next round. A
//!   descendant it cannot kill (another user's, after a setuid exec) keeps
//!   it from reaching `ECHILD`, so the deadline returns `Incomplete`.
//!   Precondition: the supervisor's only children are the supervised
//!   family (a dedicated process; the tests re-execute this test binary for
//!   it, never the shared test process).
//! - **macOS, parent unique-id lineage.** macOS has no subreaper, and
//!   kqueue `NOTE_TRACK` is unsupported (pinned by a test). Each process
//!   carries a 64-bit unique id that is never reused and the unique id of
//!   the parent that created it, which is kept when the process is
//!   reparented (pinned by a test). A tracker records the family's unique
//!   ids while it runs; the sweep closes the set over parent unique ids,
//!   re-stops every known member (`SIGSTOP`) each round until one scan
//!   shows them all stopped, kills them, and confirms with a fresh,
//!   re-attributed scan, repeating until that scan accounts for everything.
//!   Any process (of any user) whose creating parent was born after the root
//!   and is neither a known member nor alive cannot be attributed: it might
//!   be an escaped descendant whose intermediate parent exited unseen, so
//!   coverage is `Incomplete`. That rule turns an escape into a detected,
//!   fail-closed result; it can also flag an unrelated orphan of a process
//!   started after the root (a false positive, which only keeps resources
//!   held). What launchd or any older process creates is never flagged.
//!   A scan lists pids and then reads them, so a process could fork after
//!   the listing and exit before its read, hiding its child: such a listed
//!   pid is "torn", and the confirm scan is repeated until none is. A pid
//!   reused within one scan is torn too (B1): the scan marks the wall clock
//!   before listing, and a listed pid whose process started at or after the
//!   mark is a newer process under a listed pid; the node is still kept.
//!   Recorded residuals (not accepted): a backward clock step during a
//!   scan can hide a reuse, and after one, processes whose start lies in
//!   the future tear every scan, so the sweep fails closed (`Incomplete`).
//!
//! Still open for activation:
//! - **Check-to-kill window.** The identity check and the kill are two
//!   calls; on Linux a pidfd closes the window; on macOS (unique id checked
//!   just before the signal) it stays a narrow residual.
//! - **Another user on macOS.** A descendant that changed user (setuid
//!   exec) is followed when its unique ids can be read (it then cannot be
//!   stopped or killed, so the sweep ends `Incomplete`); where they cannot
//!   be read, the lineage neither follows nor flags it. Not accepted:
//!   activation must refuse an engine that can reach a setuid executable,
//!   or close this differently.
//! - **Work started through another process** (a daemon asked to spawn on
//!   the engine's behalf) is not a descendant on either OS.
//! - **SIGCHLD.** The root's pgid stays reserved until `sweep` reaps it,
//!   unless something in the same process sets `SIGCHLD` to `SIG_IGN`
//!   (automatic reaping); nothing in this crate does.
//! - **Family bound.** `MAX_FAMILY` must be qualified against a real Chrome
//!   or Edge tree; exceeding it fails closed.
//! - **Fixture constructor.** `python_fixture` evaluates a fixed Python
//!   string; it is `#[cfg(test)]` on its own and must never reach a
//!   production build.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// At most this many processes are scanned per enumeration; more fails
/// closed (the sweep still kills the group).
pub(crate) const MAX_SCAN: usize = 65_536;
/// At most this many members in one supervised family: the Windows job's
/// active-process limit, shared rather than duplicated.
pub(crate) const MAX_FAMILY: usize = crate::supervise::JOB_ACTIVE_PROCESS_LIMIT as usize;

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

/// How much of the family a sweep can vouch for. Adapted from #528's
/// descendant-accounting model: observing every scanned member exit is not
/// proof that no descendant escaped the scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Coverage {
    /// The scan is one snapshot, so forks after it and (on macOS) orphans
    /// reparented before it are unaccounted for. Every sweep in this slice
    /// reports this.
    Incomplete,
    /// Produced only by `verified_sweep`: a Linux subreaper supervisor
    /// reached `ECHILD`, or the macOS lineage accounted for every process
    /// that could be a descendant and confirmed each member's exit.
    VerifiedComplete,
}

/// The result of a sweep: the scanned members still alive, and what the
/// sweep can vouch for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SweepOutcome {
    pub(crate) left: Vec<Pinned>,
    pub(crate) coverage: Coverage,
}

impl SweepOutcome {
    /// True only when every scanned member exited and coverage is verified
    /// complete. With `Incomplete` coverage this is never true, however
    /// clean the scan looked.
    pub(crate) fn all_exited(&self) -> bool {
        self.left.is_empty() && self.coverage == Coverage::VerifiedComplete
    }
}

/// A supervised fixture: the child in its own process group.
pub(crate) struct Supervised {
    child: Child,
    root: Pinned,
    /// While armed, dropping kills the family: a failing test never leaves
    /// fixture processes behind. Disarmed once the root is reaped, because
    /// its pgid may then belong to someone else.
    armed: bool,
    /// macOS: the lineage tracker started with the fixture
    /// (`spawn_verifiable`); `verified_sweep` needs it.
    #[cfg(target_os = "macos")]
    lineage: Option<lineage::Tracker>,
    /// Linux: the process was already a subreaper with no other child when
    /// the fixture started (`spawn_verifiable`); `verified_sweep` needs it.
    #[cfg(target_os = "linux")]
    verifiable: bool,
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
            #[cfg(target_os = "macos")]
            lineage: None,
            #[cfg(target_os = "linux")]
            verifiable: false,
        })
    }

    /// Spawn for `verified_sweep`. On macOS this also starts the lineage
    /// tracker. On Linux the precondition is checked here, before the
    /// fixture starts: this process is already a subreaper and has no child
    /// at all (checked without reaping). If it does not hold, the fixture
    /// still starts, but `verified_sweep` falls back to the snapshot sweep
    /// (`Incomplete`); becoming a subreaper later does not help, because an
    /// orphan may already have escaped to init.
    pub(crate) fn spawn_verifiable(command: Command) -> std::io::Result<Self> {
        #[cfg(target_os = "linux")]
        let ready = reaper::is_subreaper() && reaper::childless();
        #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(unused_mut))]
        let mut supervised = Self::spawn(command)?;
        #[cfg(target_os = "linux")]
        {
            supervised.verifiable = ready;
        }
        #[cfg(target_os = "macos")]
        {
            supervised.lineage = Some(
                lineage::Tracker::start(supervised.root)
                    .map_err(|_| std::io::Error::other("the lineage tracker cannot start"))?,
            );
        }
        Ok(supervised)
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
    /// that every scanned member is gone before `deadline`. The outcome
    /// lists the members still alive, with `Incomplete` coverage.
    pub(crate) fn sweep(mut self, deadline: Duration) -> Result<SweepOutcome, FamilyError> {
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
                return Ok(SweepOutcome {
                    left: alive,
                    coverage: Coverage::Incomplete,
                });
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Supervised {
    /// The verified sweep (A2b, see the module comment). Falls back to the
    /// snapshot sweep, and so to `Incomplete`, whenever its precondition
    /// does not hold: not set up by `spawn_verifiable` as a subreaper with
    /// no other child (Linux), no lineage tracker (macOS).
    pub(crate) fn verified_sweep(self, deadline: Duration) -> Result<SweepOutcome, FamilyError> {
        #[cfg(target_os = "linux")]
        {
            self.verified_sweep_linux(deadline)
        }
        #[cfg(target_os = "macos")]
        {
            self.verified_sweep_macos(deadline)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            self.sweep(deadline)
        }
    }

    #[cfg(target_os = "linux")]
    fn verified_sweep_linux(mut self, deadline: Duration) -> Result<SweepOutcome, FamilyError> {
        if !(self.verifiable && reaper::is_subreaper()) {
            return self.sweep(deadline);
        }
        let me = std::process::id() as i32;
        // From here this sweep reaps (waitpid(-1)), so the drop guard must
        // never signal the root's pgid after it is reaped.
        self.armed = false;
        // SAFETY: the root is unreaped here (only this sweep reaps), so the
        // pgid is ours.
        unsafe { libc::killpg(self.root.pid, libc::SIGKILL) };
        let outcome = self.reap_until_childless(me, deadline);
        if outcome.is_err() {
            // An error leaves nothing running: kill every descendant still
            // visible before returning it.
            if let Ok(table) = process_table() {
                for member in descendants_of(me, &table) {
                    kill_pinned(member);
                }
            }
        }
        outcome
    }

    #[cfg(target_os = "linux")]
    fn reap_until_childless(
        &mut self,
        me: i32,
        deadline: Duration,
    ) -> Result<SweepOutcome, FamilyError> {
        let started = Instant::now();
        loop {
            let table = process_table()?;
            let members = descendants_of(me, &table);
            for member in &members {
                kill_pinned(*member);
            }
            if members.len() > MAX_FAMILY {
                return Err(FamilyError::FamilyBound);
            }
            if reaper::reap_all()? {
                // No child at all: with this process a subreaper since before
                // the fixture started, no descendant is left anywhere.
                let _ = self.child.wait();
                return Ok(SweepOutcome {
                    left: Vec::new(),
                    coverage: Coverage::VerifiedComplete,
                });
            }
            if started.elapsed() >= deadline {
                let left = members.into_iter().filter(|m| is_alive(*m)).collect();
                return Ok(SweepOutcome {
                    left,
                    coverage: Coverage::Incomplete,
                });
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[cfg(target_os = "macos")]
    fn verified_sweep_macos(mut self, deadline: Duration) -> Result<SweepOutcome, FamilyError> {
        let Some(tracker) = self.lineage.take() else {
            return self.sweep(deadline);
        };
        let lineage::Stopped {
            mut known,
            root_unique,
        } = tracker.stop();
        // Every process this sweep ever stopped, so an error path can kill
        // them instead of leaving them stopped.
        let mut signalled: BTreeMap<u64, Node> = BTreeMap::new();
        let outcome = self.freeze_kill_confirm(&mut known, root_unique, deadline, &mut signalled);
        if outcome.is_err() {
            for node in signalled.values() {
                lineage::signal(*node, libc::SIGKILL);
            }
            self.reap_root();
        }
        outcome
    }

    #[cfg(target_os = "macos")]
    fn reap_root(&mut self) {
        if self.armed {
            // SAFETY: the root is unreaped while armed, so this pgid is ours.
            unsafe { libc::killpg(self.root.pid, libc::SIGKILL) };
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.armed = false;
        }
    }

    /// Freeze, kill, confirm, repeated until a scan after the kills accounts
    /// for everything:
    /// 1. **Freeze.** Every known living member is sent `SIGSTOP` on every
    ///    round (a member not yet stopped may `SIGCONT` another), until one
    ///    scan shows every known living member stopped (`SSTOP`). Stopped
    ///    processes neither fork nor signal.
    /// 2. **Kill** every member in that scan, then wait until each one has
    ///    exited: a process cannot finish exiting while a fork it started is
    ///    still in progress, so any child it made exists before step 3 lists.
    /// 3. **Confirm** with a fresh scan, rescanned until no listed pid is
    ///    gone at its read ("torn"), attributed again. Verified only when
    ///    the freeze converged, every killed member was seen to exit, the
    ///    confirm scan is untorn, no known member is alive, and no scan of
    ///    this sweep ever found an unattributable process.
    ///
    /// A pid reused within one scan (listed, exited, taken by a new process
    /// before its read) is torn as well ([`born_after_listing`]).
    #[cfg(target_os = "macos")]
    fn freeze_kill_confirm(
        &mut self,
        known: &mut BTreeSet<u64>,
        root_unique: u64,
        deadline: Duration,
        signalled: &mut BTreeMap<u64, Node>,
    ) -> Result<SweepOutcome, FamilyError> {
        let started = Instant::now();
        // Every unattributable process any scan of this sweep found.
        let mut unattributable: BTreeMap<u64, Node> = BTreeMap::new();
        loop {
            let (members, converged) = loop {
                let nodes = lineage::nodes()?;
                for node in attribute(&nodes, known, root_unique) {
                    unattributable.insert(node.unique, node);
                }
                let members: Vec<Node> = nodes
                    .into_iter()
                    .filter(|n| known.contains(&n.unique) && !n.zombie)
                    .collect();
                if members.len() > MAX_FAMILY {
                    // Kill this scan's members too, not only those already
                    // signalled: none is left running past the error.
                    for node in &members {
                        signalled.insert(node.unique, *node);
                        lineage::signal(*node, libc::SIGKILL);
                    }
                    return Err(FamilyError::FamilyBound);
                }
                let running: Vec<Node> = members.iter().copied().filter(|n| !n.stopped).collect();
                if running.is_empty() {
                    break (members, true);
                }
                if started.elapsed() >= deadline {
                    break (members, false);
                }
                for node in running {
                    signalled.insert(node.unique, node);
                    lineage::signal(node, libc::SIGSTOP);
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            for node in &members {
                signalled.insert(node.unique, *node);
                lineage::signal(*node, libc::SIGKILL);
            }
            self.reap_root();
            while !members.iter().all(|n| lineage::exited(*n)) && started.elapsed() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            let all_exited = members.iter().all(|n| lineage::exited(*n));
            // The confirm scan: rescanned until no pid is torn, so a process
            // that forked after a listing and exited before its read cannot
            // hide its child (it would be torn, and the next scan reads the
            // child).
            let (nodes, torn) = loop {
                let (nodes, torn) = lineage::scan()?;
                if torn == 0 || started.elapsed() >= deadline {
                    break (nodes, torn);
                }
                for node in attribute(&nodes, known, root_unique) {
                    unattributable.insert(node.unique, node);
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            for node in attribute(&nodes, known, root_unique) {
                unattributable.insert(node.unique, node);
            }
            let alive: Vec<Pinned> = nodes
                .iter()
                .filter(|n| known.contains(&n.unique) && !n.zombie)
                .map(|n| n.pinned)
                .collect();
            // Verified only on a converged freeze, every killed member seen to
            // exit, and an untorn confirm scan that accounts for everything.
            if converged && all_exited && torn == 0 && alive.is_empty() && unattributable.is_empty()
            {
                return Ok(SweepOutcome {
                    left: Vec::new(),
                    coverage: Coverage::VerifiedComplete,
                });
            }
            // Something unattributable was seen: never verified. Once every
            // known member is gone there is nothing left to kill.
            if (alive.is_empty() && !unattributable.is_empty()) || started.elapsed() >= deadline {
                let mut left = alive;
                left.extend(unattributable.values().map(|n| n.pinned));
                return Ok(SweepOutcome {
                    left,
                    coverage: Coverage::Incomplete,
                });
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// Whether a process read under a listed pid started at or after the
/// scan's clock mark (taken just before the listing), in microseconds since
/// the epoch: then it is not the process that was listed, whose pid was
/// reused, so the scan is torn (B1). The node itself is kept. One born
/// between the mark and the listing is counted too, which only costs a
/// retry.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn born_after_listing(start_us: u64, mark_us: u64) -> bool {
    start_us >= mark_us
}

/// The wall clock in microseconds since the epoch, the clock `pbi_start`
/// uses.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn clock_mark() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_micros() as u64)
        .unwrap_or(0)
}

/// Every descendant of `ancestor` in `table` by parent links (excluding
/// `ancestor` itself).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn descendants_of(ancestor: i32, table: &[Row]) -> Vec<Pinned> {
    let mut children: BTreeMap<i32, Vec<Row>> = BTreeMap::new();
    for row in table.iter().filter(|row| row.pinned.pid > 0) {
        children.entry(row.ppid).or_default().push(*row);
    }
    let mut found: BTreeMap<i32, Pinned> = BTreeMap::new();
    let mut queue = vec![ancestor];
    while let Some(pid) = queue.pop() {
        for child in children.get(&pid).into_iter().flatten() {
            if child.pinned.pid != ancestor
                && found.insert(child.pinned.pid, child.pinned).is_none()
            {
                queue.push(child.pinned.pid);
            }
        }
    }
    found.into_values().collect()
}

/// One process as the macOS lineage sees it: identity, user, its unique id
/// and its creating parent's unique id. Built synthetically by the tests on
/// every Unix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Node {
    pub(crate) pinned: Pinned,
    pub(crate) unique: u64,
    pub(crate) parent_unique: u64,
    pub(crate) zombie: bool,
    /// Stopped (`SSTOP`): it neither forks nor signals until continued.
    pub(crate) stopped: bool,
}

/// Grow `known` (unique ids) to its closure over `nodes` through parent
/// unique ids, and return the processes that cannot be attributed: not
/// known, whose creating parent was born after the root (a descendant's
/// creating parent is the root or another descendant, and unique ids only
/// grow) and is neither known nor alive. Such a process may be an escaped
/// descendant whose intermediate parent exited unseen, so it defeats
/// verified coverage, whatever its user (a setuid step must not hide a
/// descendant). Anything launchd or another older process creates is never
/// flagged. (A zombie is dead: its children were reparented when it
/// exited.)
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn attribute(nodes: &[Node], known: &mut BTreeSet<u64>, root_unique: u64) -> Vec<Node> {
    loop {
        let before = known.len();
        for node in nodes {
            if known.contains(&node.parent_unique) {
                known.insert(node.unique);
            }
        }
        if known.len() == before {
            break;
        }
    }
    let living: BTreeSet<u64> = nodes
        .iter()
        .filter(|n| !n.zombie)
        .map(|n| n.unique)
        .collect();
    nodes
        .iter()
        .copied()
        .filter(|n| {
            !n.zombie
                && n.parent_unique > root_unique
                && !known.contains(&n.unique)
                && !known.contains(&n.parent_unique)
                && !living.contains(&n.parent_unique)
        })
        .collect()
}

#[cfg(target_os = "linux")]
pub(crate) mod reaper {
    use super::FamilyError;

    /// Make this process a subreaper. Only a dedicated supervisor process
    /// may call this (the tests re-execute the test binary for it).
    pub(crate) fn become_subreaper() -> std::io::Result<()> {
        // SAFETY: prctl with an integer argument; no memory is passed.
        let status = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1 as libc::c_ulong) };
        if status == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    pub(crate) fn is_subreaper() -> bool {
        let mut value: libc::c_int = 0;
        // SAFETY: PR_GET_CHILD_SUBREAPER writes one int to the pointer.
        let status =
            unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut value as *mut libc::c_int) };
        status == 0 && value == 1
    }

    /// Whether this process has no child at all, checked without reaping
    /// (`WNOWAIT`).
    pub(crate) fn childless() -> bool {
        // SAFETY: plain data; zeroed is a valid value.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: waitid with a valid siginfo pointer; WNOWAIT leaves any
        // child waitable.
        let status = unsafe {
            libc::waitid(
                libc::P_ALL,
                0,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
            )
        };
        status == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
    }

    /// Reap every exited child without blocking. `Ok(true)` when this
    /// process has no child left at all (`ECHILD`).
    pub(crate) fn reap_all() -> Result<bool, FamilyError> {
        loop {
            let mut status: libc::c_int = 0;
            // SAFETY: waitpid with a valid status pointer.
            // __WALL: every child, whatever its exit signal.
            let reaped = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG | libc::__WALL) };
            if reaped > 0 {
                continue;
            }
            if reaped == 0 {
                return Ok(false);
            }
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ECHILD) => return Ok(true),
                Some(libc::EINTR) => continue,
                _ => return Err(FamilyError::Unreadable),
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) mod lineage {
    use super::{attribute, born_after_listing, clock_mark, FamilyError, Node, Pinned, MAX_SCAN};
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::Duration;

    /// `PROC_PIDUNIQIDENTIFIERINFO` in `<sys/proc_info.h>`.
    const PROC_PIDUNIQIDENTIFIERINFO: libc::c_int = 17;

    /// `struct proc_uniqidentifierinfo` in `<sys/proc_info.h>`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct UniqueIdentifierInfo {
        uuid: [u8; 16],
        unique: u64,
        parent_unique: u64,
        id_version: i32,
        reserved2: u32,
        reserved3: u64,
        reserved4: u64,
    }

    /// `Ok(None)` when the process is gone; `Err` (EPERM included) when it
    /// cannot be read.
    fn unique_ids(pid: i32) -> Result<Option<(u64, u64)>, i32> {
        // SAFETY: plain data; zeroed is a valid value.
        let mut info: UniqueIdentifierInfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<UniqueIdentifierInfo>() as libc::c_int;
        // SAFETY: the buffer is exactly one UniqueIdentifierInfo of `size` bytes.
        let read = unsafe {
            libc::proc_pidinfo(
                pid,
                PROC_PIDUNIQIDENTIFIERINFO,
                0,
                (&mut info as *mut UniqueIdentifierInfo).cast(),
                size,
            )
        };
        if read == size {
            return Ok(Some((info.unique, info.parent_unique)));
        }
        if read > 0 {
            return Err(0);
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => Ok(None),
            other => Err(other.unwrap_or(0)),
        }
    }

    /// The start time `pid`'s BSD info reports (microseconds), for the tests.
    #[cfg(test)]
    pub(crate) fn start_of(pid: i32) -> Option<u64> {
        let info = bsd(pid).ok().flatten()?;
        Some(
            info.pbi_start_tvsec
                .wrapping_mul(1_000_000)
                .wrapping_add(info.pbi_start_tvusec),
        )
    }

    /// The unique id and parent unique id of `pid`, for the tests.
    #[cfg(test)]
    pub(crate) fn ids_of(pid: i32) -> Option<(u64, u64)> {
        unique_ids(pid).ok().flatten()
    }

    fn bsd(pid: i32) -> Result<Option<libc::proc_bsdinfo>, i32> {
        // SAFETY: plain data; zeroed is a valid value.
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
        if read == size {
            return Ok(Some(info));
        }
        if read > 0 {
            return Err(0);
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => Ok(None),
            other => Err(other.unwrap_or(0)),
        }
    }

    /// Every process whose unique ids can be read, as lineage nodes.
    /// Another user's process whose BSD info cannot be read (EPERM) is kept
    /// too: it counts as a living parent, it is flagged like any other when
    /// unattributable, and as a known member (a descendant that changed
    /// user) it can be neither stopped nor killed, so the sweep ends
    /// `Incomplete`. One whose unique ids cannot be read either is skipped
    /// (the open "another user" item).
    pub(crate) fn nodes() -> Result<Vec<Node>, FamilyError> {
        scan().map(|(nodes, _)| nodes)
    }

    /// One scan and how many pids it listed that were gone by the time
    /// they were read ("torn"). A torn pid may have been a process that
    /// forked after the listing and exited before its read, so its child
    /// is in neither the list nor the nodes: a scan with any torn pid
    /// cannot confirm anything. So is a listed pid now carrying a process
    /// born after the listing (B1): the listed one exited and its pid was
    /// reused.
    pub(crate) fn scan() -> Result<(Vec<Node>, usize), FamilyError> {
        let mut pids = vec![0i32; MAX_SCAN];
        let mark = clock_mark();
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
        let mut nodes = Vec::new();
        let mut torn = 0usize;
        for pid in pids[..count].iter().copied().filter(|pid| *pid > 0) {
            let (unique, parent_unique) = match unique_ids(pid) {
                Ok(Some(ids)) => ids,
                Ok(None) => {
                    torn += 1;
                    continue;
                }
                Err(libc::EPERM) => continue,
                Err(_) => return Err(FamilyError::Unreadable),
            };
            let node = match bsd(pid) {
                Ok(Some(info)) => Node {
                    pinned: Pinned {
                        pid,
                        start: info
                            .pbi_start_tvsec
                            .wrapping_mul(1_000_000)
                            .wrapping_add(info.pbi_start_tvusec),
                    },
                    unique,
                    parent_unique,
                    // SZOMB is 5 and SSTOP is 4 in <sys/proc.h>.
                    zombie: info.pbi_status == 5,
                    stopped: info.pbi_status == 4,
                },
                Ok(None) => {
                    torn += 1;
                    continue;
                }
                // No start time can be read: not checked against the mark
                // (the open "another user" item).
                Err(libc::EPERM) => Node {
                    pinned: Pinned { pid, start: 0 },
                    unique,
                    parent_unique,
                    zombie: false,
                    stopped: false,
                },
                Err(_) => return Err(FamilyError::Unreadable),
            };
            // Kept, not dropped: it is a real process, attributed by its real
            // ids, frozen and killed like any member. Only the scan is torn.
            if node.pinned.start != 0 && born_after_listing(node.pinned.start, mark) {
                torn += 1;
            }
            nodes.push(node);
        }
        Ok((nodes, torn))
    }

    /// Whether a node has finished exiting: its pid is gone, carries another
    /// unique id, or is a zombie. Unknown counts as not exited.
    pub(crate) fn exited(node: Node) -> bool {
        match unique_ids(node.pinned.pid) {
            Ok(None) => true,
            Ok(Some((unique, _))) if unique != node.unique => true,
            Ok(Some(_)) => matches!(bsd(node.pinned.pid), Ok(Some(info)) if info.pbi_status == 5),
            Err(_) => false,
        }
    }

    /// Signal a node only while its pid still carries the same unique id
    /// (unique ids are never reused).
    pub(crate) fn signal(node: Node, signal: libc::c_int) {
        if matches!(unique_ids(node.pinned.pid), Ok(Some((unique, _))) if unique == node.unique) {
            // SAFETY: plain signal to a pid whose unique id was just re-checked.
            unsafe { libc::kill(node.pinned.pid, signal) };
        }
    }

    /// What the tracker learned, handed to the sweep.
    pub(crate) struct Stopped {
        pub(crate) known: BTreeSet<u64>,
        pub(crate) root_unique: u64,
    }

    /// Records the family's unique ids while it runs, so an intermediate
    /// parent that exits later is still known.
    pub(crate) struct Tracker {
        known: Arc<Mutex<BTreeSet<u64>>>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
        root_unique: u64,
    }

    impl Tracker {
        pub(crate) fn start(root: Pinned) -> Result<Self, FamilyError> {
            let (root_unique, _) = unique_ids(root.pid)
                .ok()
                .flatten()
                .ok_or(FamilyError::Unreadable)?;
            let known = Arc::new(Mutex::new(BTreeSet::from([root_unique])));
            let stop = Arc::new(AtomicBool::new(false));
            let thread = {
                let (known, stop) = (Arc::clone(&known), Arc::clone(&stop));
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        if let Ok(nodes) = nodes() {
                            if let Ok(mut known) = known.lock() {
                                let _ = attribute(&nodes, &mut known, root_unique);
                            }
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                })
            };
            Ok(Self {
                known,
                stop,
                thread: Some(thread),
                root_unique,
            })
        }

        pub(crate) fn stop(mut self) -> Stopped {
            self.halt();
            let known = self.known.lock().map(|k| k.clone()).unwrap_or_default();
            Stopped {
                known,
                root_unique: self.root_unique,
            }
        }

        fn halt(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    impl Drop for Tracker {
        fn drop(&mut self) {
            self.halt();
        }
    }
}

/// The only tests `spawn_test` may run: the dedicated supervisor entries
/// (recorded in prep/SG-000115.md).
#[cfg(all(test, target_os = "linux"))]
pub(crate) const SUPERVISOR_ENTRIES: [&str; 2] = [
    "unix_supervise::tests::supervisor_entry",
    "unix_rehearsal::tests::sink_supervisor_entry",
];

/// Tests only (Linux): run one of `SUPERVISOR_ENTRIES` in a fresh process
/// of this test binary (`--exact <test>`), with `env`, its stdout piped. The
/// A6 rehearsal uses it for its dedicated subreaper supervisor, so that
/// module needs no spawn of its own. Any other test name is refused.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn spawn_test(test: &str, env: &[(&str, String)]) -> std::io::Result<Child> {
    if !SUPERVISOR_ENTRIES.contains(&test) {
        return Err(std::io::Error::other("not a supervisor entry"));
    }
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .stdout(std::process::Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }
    command.spawn()
}

/// A `python3` fixture running `code` (no shell: SG-000085 bans shell tokens
/// in this crate's sources, tests included). The single fixture constructor
/// for this module's tests and the A6 rehearsal (`unix_rehearsal.rs`), so
/// that module needs no spawn of its own. Explicitly `cfg(test)`, so it
/// stays test-only if activation ever lifts this module's cfg.
#[cfg(test)]
pub(crate) fn python_fixture(code: &str) -> Command {
    let mut command = Command::new("python3");
    command.arg("-c").arg(code);
    command
}

/// Tests only (Linux, the rehearsal's crash test): pin a pid to its current
/// start time, `None` if it is gone.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn pin_pid(pid: i32) -> Option<Pinned> {
    match start_time(pid) {
        Ok(Some(start)) => Some(Pinned { pid, start }),
        _ => None,
    }
}

/// Signal a member only while its start time still matches (no reused pid).
pub(crate) fn kill_pinned(member: Pinned) {
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
    // A non-positive pid is never a real identity: such rows are ignored.
    let table: Vec<Row> = table
        .iter()
        .copied()
        .filter(|row| row.pinned.pid > 0)
        .collect();
    let table = table.as_slice();
    // An invalid root fails closed: `killpg(0, ...)` would signal the
    // caller's own group, so no family is built for it.
    if root.pid <= 0 {
        return (Vec::new(), Some(FamilyError::Unreadable));
    }
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
    /// fails closed. Used for pinned members (alive checks and kills).
    pub(super) fn row_of(pid: i32) -> Result<Option<(Row, bool)>, FamilyError> {
        read(pid, false)
    }

    /// One row. During the table scan (`scanning`), a process this user
    /// may not inspect (EPERM, for example a root-owned daemon) is skipped:
    /// it cannot be the fixture's descendant unless it changed user, which
    /// stays an open item. A pinned member is always read fail-closed.
    fn read(pid: i32, scanning: bool) -> Result<Option<(Row, bool)>, FamilyError> {
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
        if read > 0 && read != size {
            // A short read sets no errno: never consult a stale one.
            return Err(FamilyError::Unreadable);
        }
        if read != size {
            let errno = std::io::Error::last_os_error().raw_os_error();
            return if errno == Some(libc::ESRCH) || (scanning && errno == Some(libc::EPERM)) {
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
            if let Some((row, _)) = read(*pid, true)? {
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

    fn python(code: &str) -> Command {
        python_fixture(code)
    }

    /// The root and two `sleep` children, all in the root's group.
    const TWO_SLEEPERS: &str = "import subprocess; \
        ps = [subprocess.Popen(['sleep', '60']) for _ in range(2)]; \
        [p.wait() for p in ps]";

    /// A child that leaves the group (setsid) and sleeps; the root waits.
    const ESCAPER: &str = "import subprocess, sys; \
        code = 'import os, time; os.setsid(); time.sleep(60)'; \
        subprocess.Popen([sys.executable, '-c', code]).wait()";

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
        let supervised = Supervised::spawn(python(TWO_SLEEPERS)).unwrap();
        let family = family_until(&supervised, |family| family.len() >= 3);
        assert!(family.len() >= 3, "{family:?}");
        assert!(family.contains(&supervised.root()));
        let outcome = supervised.sweep(DEADLINE).unwrap();
        assert!(outcome.left.is_empty(), "{outcome:?}");
        // Every scanned member exited, yet the sweep never claims more.
        assert_eq!(outcome.coverage, Coverage::Incomplete);
        assert!(!outcome.all_exited());
        for member in family {
            assert!(!is_alive(member), "{member:?}");
        }
    }

    /// A helper that leaves the group (setsid) while its parent lives is
    /// still found by the parent-link walk and swept.
    #[test]
    fn a_descendant_that_leaves_the_group_is_still_swept() {
        let supervised = Supervised::spawn(python(ESCAPER)).unwrap();
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
        let outcome = supervised.sweep(DEADLINE).unwrap();
        assert!(outcome.left.is_empty(), "{outcome:?}");
        // Every scanned member exited, yet the sweep never claims more.
        assert_eq!(outcome.coverage, Coverage::Incomplete);
        assert!(!outcome.all_exited());
        for member in escaped {
            assert!(!is_alive(member), "the escaped helper is gone: {member:?}");
        }
    }

    /// A test that fails before its sweep leaves no fixture behind: the
    /// armed guard kills the family on drop.
    #[test]
    fn dropping_an_armed_fixture_kills_its_family() {
        let supervised = Supervised::spawn(python(TWO_SLEEPERS)).unwrap();
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

    /// From #528: no coverage proof, no success, even when every observed
    /// member exited; and a leftover member defeats even verified coverage.
    #[test]
    fn success_needs_verified_coverage_and_no_survivor() {
        let gone = SweepOutcome {
            left: Vec::new(),
            coverage: Coverage::Incomplete,
        };
        assert!(!gone.all_exited());
        let verified = SweepOutcome {
            left: Vec::new(),
            coverage: Coverage::VerifiedComplete,
        };
        assert!(verified.all_exited());
        let survivor = SweepOutcome {
            left: vec![Pinned { pid: 7, start: 1 }],
            coverage: Coverage::VerifiedComplete,
        };
        assert!(!survivor.all_exited());
    }

    /// From #528: zero or negative identities are never family members,
    /// and an invalid root has no family.
    #[test]
    fn invalid_identities_are_never_members() {
        let root = Pinned { pid: 100, start: 1 };
        let table = vec![
            Row {
                pinned: root,
                ppid: 1,
                pgid: 100,
            },
            Row {
                pinned: Pinned { pid: 0, start: 1 },
                ppid: 100,
                pgid: 100,
            },
            Row {
                pinned: Pinned { pid: -1, start: 1 },
                ppid: 100,
                pgid: 100,
            },
        ];
        assert_eq!(family_of(root, &table), (vec![root], None));
        let invalid = Pinned { pid: 0, start: 1 };
        assert_eq!(
            family_of(invalid, &table),
            (Vec::new(), Some(FamilyError::Unreadable))
        );
    }

    /// From #528: the root's exit alone proves nothing about descendants;
    /// the walk reaches a member that left the group while its parent
    /// lives. (An orphan whose parent is gone has ppid 1 and is outside the
    /// walk: the open macOS residual, not covered here.)
    #[test]
    fn a_descendant_outside_the_group_stays_a_member() {
        let root = Pinned { pid: 100, start: 1 };
        let table = vec![
            Row {
                pinned: root,
                ppid: 1,
                pgid: 100,
            },
            Row {
                pinned: Pinned { pid: 101, start: 2 },
                ppid: 100,
                pgid: 100,
            },
            // Left the group with setsid, still a child of 101.
            Row {
                pinned: Pinned { pid: 102, start: 3 },
                ppid: 101,
                pgid: 102,
            },
        ];
        let (members, error) = family_of(root, &table);
        assert_eq!(error, None);
        assert!(
            members.contains(&Pinned { pid: 102, start: 3 }),
            "{members:?}"
        );
    }

    #[test]
    fn the_family_bound_is_the_job_limit() {
        assert_eq!(
            MAX_FAMILY,
            crate::supervise::JOB_ACTIVE_PROCESS_LIMIT as usize
        );
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

    // ---- A2b: verified termination ------------------------------------

    /// Escape shapes. Every fixture process appends its pid to the file named
    /// by `ORCEL_SG115_PIDS`, so a test can check independently of the sweep
    /// whether any of them survived.
    const NOTE: &str = "import os, sys, time\n\
        def note():\n    \
            with open(os.environ['ORCEL_SG115_PIDS'], 'a') as f: f.write(str(os.getpid()) + chr(10))\n";

    /// A child calls setsid (leaves the group and the session).
    const SETSID: &str = "note()\n\
        if os.fork() == 0:\n    os.setsid(); note(); time.sleep(60)\n\
        time.sleep(60)\n";
    /// A child calls setpgid (leaves the group only).
    const SETPGID: &str = "note()\n\
        if os.fork() == 0:\n    os.setpgid(0, 0); note(); time.sleep(60)\n\
        time.sleep(60)\n";
    /// Double fork: the grandchild calls setsid; the intermediate lingers
    /// 0.5 s, then exits, orphaning it.
    const DOUBLE_FORK_LINGER: &str = "note()\n\
        if os.fork() == 0:\n    note()\n    \
            if os.fork() == 0:\n        os.setsid(); note(); time.sleep(60)\n    \
            time.sleep(0.5); os._exit(0)\n\
        time.sleep(60)\n";
    /// Double fork with an intermediate that exits at once.
    const DOUBLE_FORK_FAST: &str = "note()\n\
        if os.fork() == 0:\n    \
            if os.fork() == 0:\n        os.setsid(); note(); time.sleep(60)\n    \
            os._exit(0)\n\
        time.sleep(60)\n";
    /// Keeps forking setsid children while the sweep runs.
    const FORK_STORM: &str = "note()\n\
        for _ in range(60):\n    \
            if os.fork() == 0:\n        os.setsid(); note(); time.sleep(60)\n    \
            time.sleep(0.02)\n\
        time.sleep(60)\n";

    const CASES: [(&str, &str, usize); 5] = [
        ("setsid", SETSID, 2),
        ("setpgid", SETPGID, 2),
        ("double_fork_linger", DOUBLE_FORK_LINGER, 3),
        ("double_fork_fast", DOUBLE_FORK_FAST, 2),
        ("fork_storm", FORK_STORM, 10),
    ];

    fn escape_fixture(body: &str, pids: &std::path::Path) -> Command {
        let mut command = python(&format!("{NOTE}{body}"));
        command.env("ORCEL_SG115_PIDS", pids);
        command
    }

    fn noted(pids: &std::path::Path) -> Vec<i32> {
        std::fs::read_to_string(pids)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.trim().parse().ok())
            .collect()
    }

    fn wait_noted(pids: &std::path::Path, at_least: usize) -> Vec<i32> {
        let started = Instant::now();
        loop {
            let found = noted(pids);
            if found.len() >= at_least || started.elapsed() > DEADLINE {
                return found;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Pin noted pids to their start times as soon as they are seen, so a
    /// later check or cleanup never touches a reused pid.
    fn pin(pids: &[i32], pinned: &mut BTreeMap<i32, Pinned>) {
        for pid in pids {
            if !pinned.contains_key(pid) {
                if let Ok(Some(start)) = start_time(*pid) {
                    pinned.insert(*pid, Pinned { pid: *pid, start });
                }
            }
        }
    }

    /// Fixture processes still running (not zombies), checked by pinned
    /// identity, independently of the sweep's own accounting; then killed,
    /// so a failing test leaves nothing behind. The scratch directory is
    /// removed.
    fn survivors(file: &std::path::Path, pinned: &mut BTreeMap<i32, Pinned>) -> Vec<Pinned> {
        pin(&noted(file), pinned);
        let alive: Vec<Pinned> = pinned.values().copied().filter(|m| is_alive(*m)).collect();
        for member in &alive {
            kill_pinned(*member);
        }
        if let Some(dir) = file.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
        alive
    }

    fn scratch_file(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("orcel-sg115-a2b-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("pids")
    }

    /// B6b (investigation, Linux): containment by PID namespace, option (a)
    /// of the crash residual. Every fixture process notes its host pid
    /// (through the host's `/proc/self`, since `getpid` answers inside the
    /// namespace). The fixture enters a new user and PID namespace
    /// (`unshare`, unprivileged), its first child is the namespace's init,
    /// and that init's child leaves the session (`setsid`). Killing the init
    /// must take the whole family with it: no orphaned helper is left to use
    /// a freed sink port. Where the host refuses unprivileged user
    /// namespaces, the refusal is recorded as evidence instead.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_pid_namespace_init_takes_its_whole_family_with_it() {
        const BODY: &str = "import os, time\n\
            def note():\n    \
                with open(os.environ['ORCEL_SG115_PIDS'], 'a') as f: f.write(os.readlink('/proc/self') + chr(10))\n\
            note()\n\
            if os.fork() == 0:\n    \
                note()\n    \
                if os.fork() == 0:\n        os.setsid(); note(); time.sleep(60)\n    \
                time.sleep(60)\n\
            time.sleep(60)\n";
        let pids = scratch_file("pidns");
        let mut command = python(BODY);
        command.env("ORCEL_SG115_PIDS", &pids);
        // SAFETY: only an async-signal-safe system call runs between fork
        // and exec.
        unsafe {
            command.pre_exec(|| {
                if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWPID) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        // Only the errors `unshare` gives for a refused namespace count as
        // the host's refusal (recorded as evidence, never as a pass of the
        // containment claim); any other spawn failure (no python3, out of
        // memory) fails the test.
        let spawned = command.spawn();
        if let Err(error) = &spawned {
            if matches!(
                error.raw_os_error(),
                Some(libc::EPERM | libc::EACCES | libc::ENOSPC | libc::EINVAL)
            ) {
                println!("SG115-EVIDENCE unprivileged PID namespace refused: {error}");
                let _ = std::fs::remove_dir_all(pids.parent().unwrap());
                return;
            }
        }
        let mut outer = spawned.expect("the fixture did not start");
        let noted_pids = wait_noted(&pids, 3);
        let mut pinned = BTreeMap::new();
        pin(&noted_pids, &mut pinned);
        assert_eq!(noted_pids.len(), 3, "{noted_pids:?}");
        let (init, helper) = (pinned[&noted_pids[1]], pinned[&noted_pids[2]]);
        assert!(is_alive(helper), "the helper runs before the init dies");
        kill_pinned(init);
        let started = Instant::now();
        while is_alive(helper) && started.elapsed() < DEADLINE {
            std::thread::sleep(Duration::from_millis(20));
        }
        let taken = !is_alive(helper);
        println!("SG115-RESULT PID namespace: the init's death took its setsid helper: {taken}");
        let _ = outer.kill();
        let _ = outer.wait();
        let left = survivors(&pids, &mut pinned);
        assert!(taken, "the helper outlived the namespace init");
        assert!(left.is_empty(), "survivors {left:?}");
    }

    /// B9a: one thread that spawns every engine and lives as long as the
    /// host. Callers hand it a prepared command and get the child back.
    #[cfg(target_os = "linux")]
    struct LifetimeSpawner {
        requests:
            std::sync::mpsc::Sender<(Command, std::sync::mpsc::Sender<std::io::Result<Child>>)>,
    }

    #[cfg(target_os = "linux")]
    impl LifetimeSpawner {
        fn start() -> Self {
            let (requests, incoming) = std::sync::mpsc::channel::<(
                Command,
                std::sync::mpsc::Sender<std::io::Result<Child>>,
            )>();
            std::thread::Builder::new()
                .name("engine-spawner".to_owned())
                .spawn(move || {
                    for (mut command, reply) in incoming {
                        let _ = reply.send(command.spawn());
                    }
                })
                .expect("the spawner thread starts");
            Self { requests }
        }

        fn spawn(&self, command: Command) -> std::io::Result<Child> {
            let (reply, answer) = std::sync::mpsc::channel();
            self.requests
                .send((command, reply))
                .map_err(|_| std::io::Error::other("the spawner thread is gone"))?;
            answer
                .recv()
                .map_err(|_| std::io::Error::other("the spawner thread is gone"))?
        }
    }

    /// B9a: a fixture that dies with its spawning thread: a parent-death
    /// signal set in `pre_exec`, then a check that the parent is still the
    /// host (it could have died between the fork and the `prctl`).
    #[cfg(target_os = "linux")]
    fn tied_to_its_spawner() -> Command {
        let mut command = python("import time; time.sleep(60)");
        let host = libc::pid_t::try_from(std::process::id()).expect("a pid fits pid_t");
        // SAFETY: only async-signal-safe system calls (prctl, getppid,
        // _exit) run between fork and exec, on a value captured by copy.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != host {
                    libc::_exit(1);
                }
                Ok(())
            });
        }
        command
    }

    /// B9a: Linux sends a parent-death signal when the *thread* that forked
    /// the child exits, not only the process. A child spawned straight from
    /// a short-lived thread dies when that thread ends; one spawned through
    /// the lifetime spawner, at the request of another short-lived thread,
    /// outlives its requester. Host death is B8b's evidence.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_parent_death_signal_follows_the_spawning_thread() {
        use std::os::unix::process::ExitStatusExt;
        let mut direct = std::thread::spawn(|| tied_to_its_spawner().spawn())
            .join()
            .expect("the spawning thread did not panic")
            .expect("the fixture did not start");
        let started = Instant::now();
        let mut status = None;
        while status.is_none() && started.elapsed() < DEADLINE {
            status = direct
                .try_wait()
                .expect("the direct child can be waited on");
            std::thread::sleep(Duration::from_millis(20));
        }
        let direct_killed = status.and_then(|status| status.signal()) == Some(libc::SIGKILL);
        // Already reaped when it was killed; otherwise end it here.
        let _ = direct.kill();
        let _ = direct.wait();

        let spawner = LifetimeSpawner::start();
        let mut through = std::thread::scope(|scope| {
            scope
                .spawn(|| spawner.spawn(tied_to_its_spawner()))
                .join()
                .expect("the requesting thread did not panic")
        })
        .expect("the fixture did not start");
        // The requester has ended; give a misdirected signal time to land.
        std::thread::sleep(Duration::from_millis(500));
        let spawner_child_alive = through
            .try_wait()
            .expect("the spawner's child can be waited on")
            .is_none();
        let _ = through.kill();
        let _ = through.wait();
        println!(
            "SG115-EVIDENCE B9a spawning-thread exit killed the direct child={direct_killed}, spawner child alive={spawner_child_alive}"
        );
        assert!(
            direct_killed,
            "the direct child outlived its spawning thread: {status:?}"
        );
        assert!(
            spawner_child_alive,
            "the spawner's child died with its requester"
        );
    }

    /// B9b: the fake host and a `setsid` helper; each notes its pid.
    #[cfg(target_os = "linux")]
    const FAMILY: &str = "import os, sys, time\n\
        def note():\n    \
            with open(sys.argv[1], 'a') as f: f.write(str(os.getpid()) + chr(10))\n\
        note()\n\
        if os.fork() == 0:\n    \
            os.setsid(); note(); time.sleep(60); os._exit(0)\n\
        time.sleep(60)\n";

    /// B9b (investigation, Linux): containment by a systemd **user**
    /// service's control group, for hosts that refuse user namespaces
    /// entirely. The fake host runs as the unit's main process
    /// (`KillMode=control-group`, `KillSignal=SIGKILL`); when it is killed,
    /// systemd kills what is left in the unit's cgroup, the `setsid` helper
    /// included. A control runs the same family without the unit and shows
    /// the helper outliving the host. Where no user manager answers, the
    /// refusal is recorded as evidence instead.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_user_service_cgroup_takes_a_crashed_hosts_family_with_it() {
        let mut pinned = BTreeMap::new();
        // Control: the same family, no unit. The helper survives the host.
        let control_pids = scratch_file("b9b-control");
        let mut control = python(FAMILY);
        control.arg(&control_pids);
        let mut host = control.spawn().expect("the control fixture did not start");
        let noted_pids = wait_noted(&control_pids, 2);
        pin(&noted_pids, &mut pinned);
        assert_eq!(noted_pids.len(), 2, "{noted_pids:?}");
        let control_helper = pinned[&noted_pids[1]];
        let _ = host.kill();
        let _ = host.wait();
        std::thread::sleep(Duration::from_millis(500));
        let control_survived = is_alive(control_helper);
        let left = survivors(&control_pids, &mut pinned);
        assert!(left.iter().all(|m| m.pid == control_helper.pid), "{left:?}");

        // The unit.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let unit = format!("orcel-sg115-b9b-{}-{nanos}", std::process::id());
        let pids = scratch_file("b9b-unit");
        let started = Command::new("systemd-run")
            .args([
                "--user",
                "--quiet",
                "--collect",
                "--service-type=exec",
                "--property=KillMode=control-group",
                "--property=KillSignal=SIGKILL",
            ])
            .arg(format!("--unit={unit}"))
            .args(["python3", "-c", FAMILY])
            .arg(&pids)
            .output();
        let refused = match &started {
            Err(error) => Some(error.to_string()),
            Ok(output) if !output.status.success() => {
                Some(String::from_utf8_lossy(&output.stderr).trim().to_owned())
            }
            Ok(_) => None,
        };
        if let Some(reason) = refused {
            println!("SG115-EVIDENCE B9b user service refused: {reason}");
            let _ = std::fs::remove_dir_all(pids.parent().unwrap());
            assert!(control_survived, "the control helper died with its host");
            return;
        }
        // Stops the unit however the test ends, a panic included.
        struct StopUnit(String);
        impl Drop for StopUnit {
            fn drop(&mut self) {
                let _ = Command::new("systemctl")
                    .args(["--user", "stop"])
                    .arg(&self.0)
                    .output();
            }
        }
        let _stop = StopUnit(unit.clone());
        let mut pinned = BTreeMap::new();
        let noted_pids = wait_noted(&pids, 2);
        pin(&noted_pids, &mut pinned);
        assert_eq!(noted_pids.len(), 2, "{noted_pids:?}");
        let (unit_host, helper) = (pinned[&noted_pids[0]], pinned[&noted_pids[1]]);
        assert!(is_alive(helper), "the helper runs before the host dies");
        kill_pinned(unit_host);
        let started = Instant::now();
        while is_alive(helper) && started.elapsed() < DEADLINE {
            std::thread::sleep(Duration::from_millis(20));
        }
        let gone = !is_alive(helper);
        println!(
            "SG115-EVIDENCE B9b user service: helper gone={gone}, control helper survived={control_survived}"
        );
        let left = survivors(&pids, &mut pinned);
        assert!(
            control_survived,
            "the control helper died with its host: the result would be vacuous"
        );
        assert!(gone, "the helper outlived the unit's host");
        assert!(left.is_empty(), "survivors {left:?}");
    }

    /// B9c: from inside a unit, a child moves itself to a new sibling cgroup, before
    /// and after a restricted child tries each way out it can reach. The answer goes
    /// to argv[1], written whole by a rename, whatever went wrong.
    #[cfg(target_os = "linux")]
    const LANDLOCK_CGROUP: &str = r#"
import ctypes, errno, json, os, socket, struct, sys

def own_cgroup():
    with open('/proc/self/cgroup') as f:
        return next(line.split('::', 1)[1].strip() for line in f if line.startswith('0::'))

def restrict():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        return False
    attr = struct.pack('=Q', 1 << 1)
    ruleset = libc.syscall(444, ctypes.c_char_p(attr), ctypes.c_size_t(len(attr)), ctypes.c_uint32(0))
    if ruleset < 0:
        return False
    return libc.syscall(446, ctypes.c_int(ruleset), ctypes.c_uint32(0)) == 0

def in_child(work):
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_end)
        try:
            answer = work()
        except BaseException as error:
            answer = {'error': type(error).__name__}
        os.write(write_end, json.dumps(answer).encode())
        os._exit(0)
    os.close(write_end)
    data = b''
    while True:
        chunk = os.read(read_end, 4096)
        if not chunk:
            break
        data += chunk
    os.waitpid(pid, 0)
    return json.loads(data) if data else {'error': 'no answer'}

def clone_into(target, here):
    """A child made directly in the sibling cgroup, by a directory opened read-only."""
    libc = ctypes.CDLL(None, use_errno=True)
    folder = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    read_end, write_end = os.pipe()
    flags = 0x200000000
    args = struct.pack('=11Q', flags, 0, 0, 0, 17, 0, 0, 0, 0, 0, folder)
    buffer = ctypes.create_string_buffer(args)
    pid = libc.syscall(435, buffer, ctypes.c_size_t(len(args)))
    if pid == 0:
        moved = own_cgroup() != here
        os.write(write_end, b'1' if moved else b'0')
        os._exit(0)
    if pid < 0:
        return False
    os.close(write_end)
    landed = os.read(read_end, 1) == b'1'
    os.waitpid(pid, 0)
    return landed

here = own_cgroup()
parent = '/sys/fs/cgroup' + os.path.dirname(here)
target = os.path.join(parent, 'orcel-sg115-b9c-' + str(os.getpid()))
procs = os.path.join(target, 'cgroup.procs')
answer = {'made': False}

def control():
    with open(procs, 'w') as f:
        f.write(str(os.getpid()))
    return {'moved': own_cgroup() != here}

def restricted():
    inherited = os.open(procs, os.O_WRONLY)
    if not restrict():
        return {'restricted': False}
    result = {'restricted': True, 'open_errno': None}
    try:
        os.close(os.open(procs, os.O_WRONLY))
    except OSError as error:
        result['open_errno'] = error.errno
    result['stayed'] = own_cgroup() == here
    bus = socket.socket(socket.AF_UNIX)
    try:
        bus.connect(os.path.join(os.environ.get('XDG_RUNTIME_DIR', '/nonexistent'), 'bus'))
        result['bus'] = True
    except OSError:
        result['bus'] = False
    try:
        result['clone3'] = clone_into(target, here)
    except OSError:
        result['clone3'] = False
    try:
        os.write(inherited, str(os.getpid()).encode())
    except OSError:
        pass
    result['inherited_fd'] = own_cgroup() != here
    return result

try:
    os.mkdir(target)
    answer['made'] = True
    answer['control'] = in_child(control)
    answer['landlock'] = in_child(restricted)
    answer['control_after'] = in_child(control)
except BaseException as error:
    answer['error'] = type(error).__name__
finally:
    if answer['made']:
        try:
            os.rmdir(target)
        except OSError as error:
            answer['rmdir_errno'] = error.errno
    with open(sys.argv[1] + '.tmp', 'w') as f:
        json.dump(answer, f)
    os.rename(sys.argv[1] + '.tmp', sys.argv[1])
"#;

    /// B9c (investigation, Linux): what Landlock does and doesn't do about leaving a
    /// unit's cgroup. It refuses a fresh open of `cgroup.procs`, shown against a control
    /// before and after. It doesn't stop an inherited descriptor, `clone3` with
    /// `CLONE_INTO_CGROUP` or the user bus: those are measured and recorded, not
    /// asserted, so this is evidence that Landlock alone isn't a cgroup the engine
    /// can't leave.
    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_refuses_a_fresh_open_of_cgroup_procs_and_leaves_other_routes_out() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let unit = format!("orcel-sg115-b9c-{}-{nanos}", std::process::id());
        let answer_path = scratch_file("b9c-answer");
        let started = Command::new("systemd-run")
            .args(["--user", "--quiet", "--collect", "--service-type=exec"])
            .arg(format!("--unit={unit}"))
            .args(["python3", "-c", LANDLOCK_CGROUP])
            .arg(&answer_path)
            .output();
        let refused = match &started {
            Err(error) => Some(error.to_string()),
            Ok(output) if !output.status.success() => {
                Some(String::from_utf8_lossy(&output.stderr).trim().to_owned())
            }
            Ok(_) => None,
        };
        if let Some(reason) = refused {
            println!("SG115-EVIDENCE B9c refused: {reason}");
            let _ = std::fs::remove_dir_all(answer_path.parent().unwrap());
            return;
        }
        // Stops the unit and removes the scratch folder however the test ends.
        struct Cleanup(String, std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = Command::new("systemctl")
                    .args(["--user", "stop"])
                    .arg(&self.0)
                    .output();
                let _ = std::fs::remove_dir_all(&self.1);
            }
        }
        let _cleanup = Cleanup(unit, answer_path.parent().unwrap().to_owned());
        let begun = Instant::now();
        let answer = loop {
            if let Ok(text) = std::fs::read_to_string(&answer_path) {
                break serde_json::from_str::<serde_json::Value>(&text)
                    .expect("the fixture's answer");
            }
            assert!(begun.elapsed() < DEADLINE, "the fixture never answered");
            std::thread::sleep(Duration::from_millis(20));
        };
        if answer["made"] != true {
            println!("SG115-EVIDENCE B9c refused: no sibling cgroup could be made: {answer}");
            return;
        }
        if answer["landlock"]["restricted"] != true {
            println!("SG115-EVIDENCE B9c refused: Landlock is unavailable: {answer}");
            return;
        }
        const EACCES: i64 = 13;
        let controls =
            answer["control"]["moved"] == true && answer["control_after"]["moved"] == true;
        let open_refused = answer["landlock"]["open_errno"].as_i64() == Some(EACCES);
        let stayed = answer["landlock"]["stayed"] == true;
        let inherited = answer["landlock"]["inherited_fd"] == true;
        let clone3 = answer["landlock"]["clone3"] == true;
        let bus = answer["landlock"]["bus"] == true;
        println!(
            "SG115-EVIDENCE B9c landlock: controls moved={controls}, fresh open refused={open_refused}, stayed={stayed}; still open: inherited fd={inherited}, clone3={clone3}, bus={bus}"
        );
        assert!(
            controls,
            "a control couldn't move, so the refusal may not be Landlock's: {answer}"
        );
        assert!(
            open_refused && stayed,
            "a fresh open wasn't refused: {answer}"
        );
        assert!(
            answer.get("rmdir_errno").is_none(),
            "a stray cgroup was left: {answer}"
        );
    }

    /// The sweep never claims verified coverage while any descendant lives:
    /// the property the verified sweep exists for.
    #[test]
    fn verified_coverage_never_coexists_with_a_survivor_by_construction() {
        let outcome = SweepOutcome {
            left: vec![Pinned { pid: 9, start: 1 }],
            coverage: Coverage::VerifiedComplete,
        };
        assert!(!outcome.all_exited());
    }

    // -- Linux: the subreaper supervisor ---------------------------------

    #[cfg(target_os = "linux")]
    const SUPERVISOR_CASE: &str = "ORCEL_SG115_SUPERVISOR_CASE";
    #[cfg(target_os = "linux")]
    const SUPERVISOR_SUBREAPER: &str = "ORCEL_SG115_SUPERVISOR_SUBREAPER";

    /// Runs only inside a re-executed test binary (`run_supervisor`), never
    /// in the shared test process: it makes its process a subreaper.
    #[cfg(target_os = "linux")]
    #[test]
    fn supervisor_entry() {
        let Ok(case) = std::env::var(SUPERVISOR_CASE) else {
            return;
        };
        // "1": a subreaper before the fixture; "0": never; "late": only
        // after the fixture started (too late: the precondition fails).
        let mode = std::env::var(SUPERVISOR_SUBREAPER).unwrap_or_default();
        if mode == "1" {
            reaper::become_subreaper().unwrap();
            assert!(reaper::is_subreaper());
        }
        assert!(reaper::childless(), "the supervisor starts childless");
        let (_, body, expected) = CASES.iter().find(|(name, _, _)| *name == case).unwrap();
        let pids = scratch_file(&case);
        let supervised = Supervised::spawn_verifiable(escape_fixture(body, &pids)).unwrap();
        let mut pinned = BTreeMap::new();
        let seen = wait_noted(&pids, *expected);
        pin(&seen, &mut pinned);
        // Let the fast intermediate exit, so its grandchild is an orphan.
        std::thread::sleep(Duration::from_millis(300));
        if mode == "late" {
            reaper::become_subreaper().unwrap();
        }
        let outcome = supervised.verified_sweep(DEADLINE).unwrap();
        let all = noted(&pids);
        let left = survivors(&pids, &mut pinned);
        println!(
            "SG115-RESULT case={case} coverage={:?} left={} noted={} seen_before_sweep={} survivors={}",
            outcome.coverage,
            outcome.left.len(),
            all.len(),
            seen.len(),
            left.len()
        );
    }

    #[cfg(target_os = "linux")]
    fn run_supervisor(case: &str, mode: &str) -> String {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "unix_supervise::tests::supervisor_entry",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(SUPERVISOR_CASE, case)
            .env(SUPERVISOR_SUBREAPER, mode)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "{case}: {stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        // The harness prints "test ... " on the same line first.
        let result = stdout
            .lines()
            .find_map(|line| line.find("SG115-RESULT ").map(|at| line[at..].to_string()));
        assert!(result.is_some(), "{case}: no result in {stdout}");
        result.unwrap_or_default()
    }

    #[cfg(target_os = "linux")]
    fn field<'a>(result: &'a str, name: &str) -> &'a str {
        let value = result
            .split_whitespace()
            .find_map(|part| part.strip_prefix(&format!("{name}=")));
        assert!(value.is_some(), "no {name} in {result}");
        value.unwrap_or_default()
    }

    /// Every escape shape, including an orphan whose parent exited at once
    /// and a family that keeps forking during the sweep, ends verified and
    /// with no fixture process left, checked independently by pid.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_subreaper_supervisor_verifies_every_escape_shape() {
        for (case, _, expected) in CASES {
            let result = run_supervisor(case, "1");
            assert_eq!(field(&result, "coverage"), "VerifiedComplete", "{result}");
            assert_eq!(field(&result, "survivors"), "0", "{result}");
            assert!(
                field(&result, "noted").parse::<usize>().unwrap() >= expected,
                "{result}"
            );
        }
    }

    /// Without the subreaper the same sweep never verifies, and the orphan
    /// really does escape the snapshot walk: the gap the subreaper closes.
    #[cfg(target_os = "linux")]
    #[test]
    fn without_a_subreaper_an_orphan_escapes_and_nothing_is_verified() {
        let result = run_supervisor("double_fork_fast", "0");
        assert_eq!(field(&result, "coverage"), "Incomplete", "{result}");
        assert_ne!(
            field(&result, "survivors"),
            "0",
            "the escape is real: {result}"
        );
    }

    /// Becoming a subreaper only after the fixture started is too late (an
    /// orphan may already be init's): the precondition is checked at spawn,
    /// so the sweep never verifies.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_subreaper_set_after_the_fixture_started_never_verifies() {
        let result = run_supervisor("double_fork_fast", "late");
        assert_eq!(field(&result, "coverage"), "Incomplete", "{result}");
    }

    // -- macOS: parent unique-id lineage ---------------------------------

    /// The claim the lineage rests on: a process's creating-parent unique id
    /// is kept when it is reparented after its parent exits.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_parent_unique_id_survives_reparenting() {
        let pids = scratch_file("reparent");
        // The intermediate notes itself, forks a setsid grandchild, and
        // exits after 0.5 s; the root waits.
        let supervised = Supervised::spawn(escape_fixture(DOUBLE_FORK_LINGER, &pids)).unwrap();
        let noted_pids = wait_noted(&pids, 3);
        assert_eq!(noted_pids.len(), 3, "{noted_pids:?}");
        let (intermediate, grandchild) = (noted_pids[1], noted_pids[2]);
        let (intermediate_unique, _) =
            lineage::ids_of(intermediate).expect("the intermediate is alive");
        let started = Instant::now();
        while matches!(row_of(grandchild), Ok(Some((row, _))) if row.ppid != 1)
            && started.elapsed() < DEADLINE
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        let (row, _) = row_of(grandchild)
            .unwrap()
            .expect("the grandchild is alive");
        assert_eq!(row.ppid, 1, "reparented to launchd");
        let (_, parent_unique) = lineage::ids_of(grandchild).unwrap();
        assert_eq!(
            parent_unique, intermediate_unique,
            "the creating parent's unique id is kept"
        );
        let mut pinned = BTreeMap::new();
        pin(&noted_pids, &mut pinned);
        drop(supervised);
        survivors(&pids, &mut pinned);
        println!(
            "SG115-EVIDENCE launchd unique ids readable by this user: {}",
            lineage::ids_of(1).is_some()
        );
    }

    /// Evidence for the packet's open question: kqueue `NOTE_TRACK` is not
    /// supported, so macOS descendant tracking cannot rely on it.
    #[cfg(target_os = "macos")]
    #[test]
    fn kqueue_note_track_is_unsupported() {
        const NOTE_TRACK: u32 = 0x0000_0001;
        let mut supervised = Supervised::spawn(python("import time; time.sleep(30)")).unwrap();
        // SAFETY: kqueue has no arguments; the descriptor is closed below.
        let queue = unsafe { libc::kqueue() };
        assert!(queue >= 0);
        let change = libc::kevent {
            ident: supervised.root().pid as libc::uintptr_t,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_RECEIPT,
            fflags: libc::NOTE_EXIT | NOTE_TRACK,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: plain data; zeroed is a valid value.
        let mut event: libc::kevent = unsafe { std::mem::zeroed() };
        // SAFETY: one change and room for one receipt.
        let count = unsafe { libc::kevent(queue, &change, 1, &mut event, 1, std::ptr::null()) };
        // SAFETY: the descriptor came from kqueue above.
        unsafe { libc::close(queue) };
        // `kevent` is packed on Apple: copy its fields before using them.
        let (flags, data) = (event.flags, event.data);
        let refused = if count < 0 {
            std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOTSUP)
        } else {
            count == 1 && flags & libc::EV_ERROR != 0 && data == libc::ENOTSUP as libc::intptr_t
        };
        let _ = supervised.child.kill();
        drop(supervised);
        assert!(
            refused,
            "NOTE_TRACK answered count={count} flags={flags:#x} data={data}"
        );
    }

    /// The lineage cases run only alone (`ORCEL_SG115_LINEAGE_ALONE=1`, one
    /// thread; the CI step): the unattributable rule is system-wide, so an
    /// orphan left by a concurrent test would be a false positive. In the
    /// shared suite they return at once.
    #[cfg(target_os = "macos")]
    fn lineage_alone() -> bool {
        std::env::var("ORCEL_SG115_LINEAGE_ALONE").as_deref() == Ok("1")
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_lineage_verifies_attributable_escapes() {
        if !lineage_alone() {
            return;
        }
        println!(
            "SG115-EVIDENCE launchd unique ids readable by this user: {}",
            lineage::ids_of(1).is_some()
        );
        for (case, body, expected) in CASES {
            if case == "double_fork_fast" {
                continue;
            }
            let pids = scratch_file(case);
            let supervised = Supervised::spawn_verifiable(escape_fixture(body, &pids)).unwrap();
            let mut pinned = BTreeMap::new();
            pin(&wait_noted(&pids, expected), &mut pinned);
            std::thread::sleep(Duration::from_millis(800));
            let outcome = supervised.verified_sweep(DEADLINE).unwrap();
            let left = survivors(&pids, &mut pinned);
            assert_eq!(
                outcome.coverage,
                Coverage::VerifiedComplete,
                "{case}: {outcome:?}"
            );
            assert!(left.is_empty(), "{case}: survivors {left:?}");
        }
    }

    /// An orphan whose parent exited at once may not be attributable; then
    /// it must never hide behind verified coverage.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_lineage_fast_orphan_is_never_hidden() {
        if !lineage_alone() {
            return;
        }
        let (mut verified, mut detected) = (0, 0);
        for round in 0..5 {
            let pids = scratch_file(&format!("fast-{round}"));
            let supervised =
                Supervised::spawn_verifiable(escape_fixture(DOUBLE_FORK_FAST, &pids)).unwrap();
            let mut pinned = BTreeMap::new();
            pin(&wait_noted(&pids, 2), &mut pinned);
            std::thread::sleep(Duration::from_millis(300));
            let outcome = supervised.verified_sweep(Duration::from_secs(2)).unwrap();
            let left = survivors(&pids, &mut pinned);
            if !left.is_empty() {
                assert_eq!(
                    outcome.coverage,
                    Coverage::Incomplete,
                    "a survivor behind verified coverage: {left:?}"
                );
                detected += 1;
            } else if outcome.coverage == Coverage::VerifiedComplete {
                verified += 1;
            }
        }
        println!(
            "SG115-RESULT fast orphan rounds: verified={verified} detected_incomplete={detected}"
        );
        // The escape must actually have been exercised at least once.
        assert!(detected >= 1, "no round produced a survivor to detect");
    }

    /// B1's premise, checked for consistency: a process started after a mark
    /// has a `pbi_start` at or after it, and the test process (started
    /// before) does not, consistent with `pbi_start` and `clock_mark` reading
    /// the same clock.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_process_started_after_the_clock_mark_is_born_after_it() {
        let mark = clock_mark();
        std::thread::sleep(Duration::from_millis(20));
        let mut supervised = Supervised::spawn(python("import time; time.sleep(30)")).unwrap();
        let start = lineage::start_of(supervised.root().pid).expect("the child is alive");
        let own = lineage::start_of(std::process::id() as i32).expect("this process is alive");
        let _ = supervised.child.kill();
        drop(supervised);
        assert!(born_after_listing(start, mark), "start {start} mark {mark}");
        assert!(
            !born_after_listing(own, mark),
            "own start {own} mark {mark}"
        );
        // Same clock: the child started within a minute of the mark.
        assert!(start - mark < 60_000_000, "start {start} mark {mark}");
    }

    // -- The attribution rule, on synthetic tables (every Unix) ------------

    #[test]
    fn a_read_born_after_the_listing_marks_the_scan_torn() {
        // B1: listed at mark 1_000; a read whose process started at or after
        // it is a reused pid (torn); one started before it is the listed one.
        assert!(born_after_listing(1_000, 1_000));
        assert!(born_after_listing(1_001, 1_000));
        assert!(!born_after_listing(999, 1_000));
        let now = clock_mark();
        assert!(
            now > 1_600_000_000_000_000,
            "microseconds since the epoch: {now}"
        );
    }

    fn node(pid: i32, unique: u64, parent_unique: u64) -> Node {
        Node {
            pinned: Pinned { pid, start: unique },
            unique,
            parent_unique,
            zombie: false,
            stopped: false,
        }
    }

    #[test]
    fn the_lineage_follows_parent_unique_ids_through_an_orphan() {
        // root 100 (u10) -> intermediate (u11, exited, but recorded) ->
        // orphan 102 (u12, reparented to launchd: ppid 1, parent unique 11).
        let mut known = BTreeSet::from([10, 11]);
        let nodes = [node(1, 1, 0), node(100, 10, 5), node(102, 12, 11)];
        let unattributable = attribute(&nodes, &mut known, 10);
        assert!(known.contains(&12), "{known:?}");
        assert!(unattributable.is_empty(), "{unattributable:?}");
    }

    #[test]
    fn an_orphan_of_an_unseen_parent_is_unattributable() {
        // The intermediate (u11) exited before it was ever recorded.
        let mut known = BTreeSet::from([10]);
        let nodes = [node(1, 1, 0), node(100, 10, 5), node(102, 12, 11)];
        let unattributable = attribute(&nodes, &mut known, 10);
        assert_eq!(unattributable, vec![node(102, 12, 11)]);
    }

    #[test]
    fn the_attribution_rule_leaves_out_what_cannot_be_ours() {
        let mut known = BTreeSet::from([10]);
        let zombie_parent_child = node(105, 15, 14);
        let mut zombie = node(104, 14, 3);
        zombie.zombie = true;
        let nodes = [
            node(1, 1, 0),
            node(100, 10, 5),
            // Born before the root: not a descendant.
            node(50, 4, 2),
            // Created by a process older than the root (dead, unknown, as
            // launchd's children look to a reader that cannot see launchd):
            // never a descendant, never flagged.
            node(108, 18, 5),
            // Its parent (u1, launchd) is alive: not an orphan of ours.
            node(106, 16, 1),
            zombie,
            zombie_parent_child,
        ];
        let unattributable = attribute(&nodes, &mut known, 10);
        // Only the child of a dead (zombie) unknown parent born after the
        // root is flagged.
        assert_eq!(unattributable, vec![zombie_parent_child]);
    }

    /// A setuid step must not hide a descendant: whatever its user, an
    /// unknown process whose creating parent was born after the root and is
    /// dead is flagged, and its own child is then not hidden behind it.
    #[test]
    fn another_users_orphan_of_a_young_dead_parent_is_flagged() {
        let mut known = BTreeSet::from([10]);
        // A1 (u11) exited unseen; A2 (u12) ran a setuid program; A3 (u13) is
        // A2's child, back under this user.
        let nodes = [node(100, 10, 5), node(102, 12, 11), node(103, 13, 12)];
        let unattributable = attribute(&nodes, &mut known, 10);
        assert_eq!(
            unattributable,
            vec![node(102, 12, 11)],
            "the setuid step is flagged"
        );
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
            if path == src.join("unix_supervise.rs")
                || path == src.join("unix_rehearsal.rs")
                || path == src.join("lib.rs")
            {
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
        // A6's rehearsal (recorded rule change, prep/SG-000115.md) composes
        // this module; it is admitted only while declared once, private,
        // under the Unix test cfg.
        assert_eq!(lib.matches("mod unix_rehearsal;").count(), 1);
        assert!(!lib.contains("pub mod unix_rehearsal"));
        assert!(lib.contains("#[cfg(all(test, unix))]\nmod unix_rehearsal;\n"));
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
