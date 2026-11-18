//! SG-000135 OB-06: where a person's input comes from in a Visible session
//! (open choice 2 of the grain), given that page script stays forbidden.
//!
//! A Visible session's engine has a headed window of its own. When a person
//! types or clicks while that window is in front, the session's pages go to
//! `HUMAN_OVERRIDE` in the takeover gate, and the agent may act on them
//! again only 3000 ms after the last such input (then it must observe the
//! page again). This module tells the gate when that input happened.
//!
//! The source reads two facts the operating system already keeps, and
//! changes nothing:
//!
//! - When the last keyboard or mouse input of this Windows session
//!   happened (`GetLastInputInfo`, with `GetTickCount` to turn it into an
//!   age). It says nothing about which key or where: no contents.
//! - Which window is in front (`GetForegroundWindow`), and whether its
//!   process is the session's engine: a descendant of the browser host this
//!   session launched (`GetWindowThreadProcessId`, then the parent chain
//!   from a process snapshot, each parent created no later than its child,
//!   ending at the host's own pid and creation time).
//!
//! A new last-input instant seen while the session's window is in front is
//! a person's input. Orcel's own page input is dispatched over the engine's
//! debugging pipe (CDP `Input.*`), straight into the renderer; it never
//! passes through the operating system's input queue, so it does not move
//! the last-input instant. If that ever did not hold, the error would be a
//! pause the agent did not need, never an action under a person's hand.
//!
//! No hook, no message loop, no page script, no OS input injection, no
//! focus or clipboard call: the session's window is only looked at. The
//! source polls every [`POLL_MS`] on a thread of its own and again right
//! before every gate decision.
//!
//! Orcel's own approval prompt is a window too: the click or key that
//! answers it can reach the browser window once the prompt closes and the
//! browser comes back to the front. Input within [`PROMPT_EDGE_BEFORE_MS`]
//! before and [`PROMPT_EDGE_AFTER_MS`] after a prompt closed is therefore
//! not counted (input during the prompt with the browser in front still
//! is).
//!
//! A Shadow session has no window and never starts this source. On other
//! operating systems no source exists yet ([`for_host`] answers `None`):
//! macOS needs its own (later packet); the live browser is Windows-only
//! today, so nothing on those systems can reach a Visible session.

use orcel_browser_session::Millis;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

/// How often the source's thread reads the operating system.
pub(crate) const POLL_MS: u64 = 25;

/// Input this long before an Orcel approval prompt closed is taken as the
/// answer to the prompt, not as a person on the browser.
pub(crate) const PROMPT_EDGE_BEFORE_MS: u64 = 500;

/// Input this long after an Orcel approval prompt closed is taken as the
/// rest of the answer (a key's release reaching the browser window), not
/// as a person on the browser.
pub(crate) const PROMPT_EDGE_AFTER_MS: u64 = 1_000;

/// The most inputs held while a prompt is up. Past it the newest are
/// dropped (the oldest, which a prompt's end cannot excuse, are kept).
const MAX_HELD: usize = 1_024;

/// One reading of the operating system's input state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sample {
    /// The operating system's mark of the last input (its tick count); a
    /// different value means new input.
    pub last_input: u32,
    /// How long ago that input happened, in milliseconds.
    pub idle_ms: u64,
    /// Whether the window in front belongs to the session's engine.
    pub session_in_front: bool,
}

/// A source of [`Sample`]s.
pub(crate) trait InputProbe: Send {
    /// The current reading; `None` when the operating system would not say,
    /// which counts as a person's input now (fail closed: the agent waits).
    fn sample(&mut self) -> Option<Sample>;
}

/// The pure part: readings in, the latest instant of a person's input out.
#[derive(Debug, Default)]
pub(crate) struct InputFeed {
    last_input: Option<u32>,
    latest: Option<Millis>,
    prompt_open: bool,
    held: Vec<Millis>,
    last_prompt_end: Option<Millis>,
}

impl InputFeed {
    /// A reading taken at `now`.
    pub(crate) fn sample(&mut self, now: Millis, sample: Option<Sample>) {
        let Some(sample) = sample else {
            self.record(now);
            return;
        };
        // The first reading is the baseline: input from before the session
        // watched is not a person on this session's window.
        let Some(previous) = self.last_input.replace(sample.last_input) else {
            return;
        };
        if previous == sample.last_input || !sample.session_in_front {
            return;
        }
        self.record(Millis(now.0.saturating_sub(sample.idle_ms)));
    }

    fn near_prompt_end(&self, at: Millis) -> bool {
        self.last_prompt_end.is_some_and(|end| {
            at.0.saturating_add(PROMPT_EDGE_BEFORE_MS) >= end.0
                && at.0 <= end.0.saturating_add(PROMPT_EDGE_AFTER_MS)
        })
    }

    fn record(&mut self, at: Millis) {
        if self.prompt_open {
            if self.held.len() < MAX_HELD {
                self.held.push(at);
            }
            return;
        }
        if !self.near_prompt_end(at) {
            self.latest = self.latest.max(Some(at));
        }
    }

    /// An Orcel approval prompt is up: input seen from now on is held until
    /// it closes.
    pub(crate) fn prompt_started(&mut self) {
        self.prompt_open = true;
    }

    /// The prompt closed at `end`: held input near its end was the answer;
    /// the rest was a person on the browser.
    pub(crate) fn prompt_ended(&mut self, end: Millis) {
        self.prompt_open = false;
        self.last_prompt_end = Some(end);
        for at in std::mem::take(&mut self.held) {
            if !self.near_prompt_end(at) {
                self.latest = self.latest.max(Some(at));
            }
        }
    }

    /// The latest person's input since the last call, if any.
    pub(crate) fn take(&mut self) -> Option<Millis> {
        self.latest.take()
    }
}

/// The time source the feed's instants are on (the takeover gate's clock).
pub(crate) type Now = Box<dyn Fn() -> Millis + Send>;

struct Inner {
    probe: Box<dyn InputProbe>,
    now: Now,
    feed: InputFeed,
}

impl Inner {
    fn poll(&mut self) {
        let sample = self.probe.sample();
        let now = (self.now)();
        self.feed.sample(now, sample);
    }
}

struct Shared {
    stop: AtomicBool,
    inner: Mutex<Inner>,
}

impl Shared {
    fn with<T>(&self, action: impl FnOnce(&mut Inner) -> T) -> T {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        action(&mut inner)
    }
}

/// A Visible session's input source: a probe, polled on its own thread and
/// before every gate decision. Dropping it stops the thread.
pub(crate) struct HumanInputMonitor {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for HumanInputMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HumanInputMonitor")
            .field("polling", &self.thread.is_some())
            .finish()
    }
}

impl HumanInputMonitor {
    /// A monitor that reads `probe` only when asked (tests drive it).
    pub(crate) fn manual(probe: Box<dyn InputProbe>, now: Now) -> Self {
        let monitor = Self {
            shared: Arc::new(Shared {
                stop: AtomicBool::new(false),
                inner: Mutex::new(Inner {
                    probe,
                    now,
                    feed: InputFeed::default(),
                }),
            }),
            thread: None,
        };
        // The baseline reading.
        monitor.poll();
        monitor
    }

    /// A monitor that also reads `probe` every [`POLL_MS`] on its own
    /// thread. If the thread cannot be started, it still reads before every
    /// gate decision.
    pub(crate) fn polling(probe: Box<dyn InputProbe>, now: Now) -> Self {
        let mut monitor = Self::manual(probe, now);
        let shared = Arc::clone(&monitor.shared);
        monitor.thread = std::thread::Builder::new()
            .name("orceld-ob06-input".into())
            .spawn(move || {
                while !shared.stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(POLL_MS));
                    shared.with(Inner::poll);
                }
            })
            .ok();
        monitor
    }

    /// Read the probe now.
    pub(crate) fn poll(&self) {
        self.shared.with(Inner::poll);
    }

    /// Read the probe now, then hand over the latest person's input since
    /// the last call.
    pub(crate) fn take(&self) -> Option<Millis> {
        self.shared.with(|inner| {
            inner.poll();
            inner.feed.take()
        })
    }

    /// An Orcel approval prompt is about to show.
    pub(crate) fn prompt_started(&self) {
        self.shared.with(|inner| {
            inner.poll();
            inner.feed.prompt_started();
        });
    }

    /// The prompt closed (it was answered, denied or failed).
    pub(crate) fn prompt_ended(&self) {
        self.shared.with(|inner| {
            let end = (inner.now)();
            inner.feed.prompt_ended(end);
            inner.poll();
        });
    }
}

impl Drop for HumanInputMonitor {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The input source for a Visible session whose browser host is `host_pid`,
/// created at `host_created` (a FILETIME), on this operating system.
#[cfg(windows)]
pub(crate) fn for_host(host_pid: u32, host_created: u64) -> Option<Box<dyn InputProbe>> {
    Some(Box::new(windows::WindowsProbe::new(host_pid, host_created)))
}

/// No input source exists here yet (macOS needs its own; the live browser
/// is Windows-only today, so no Visible session runs here).
#[cfg(not(windows))]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn for_host(_host_pid: u32, _host_created: u64) -> Option<Box<dyn InputProbe>> {
    None
}

#[cfg(windows)]
mod windows {
    use super::{InputProbe, Sample};
    use std::collections::HashMap;
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::SystemInformation::GetTickCount;
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowThreadProcessId,
    };

    /// The longest parent chain walked from a window's process to the host
    /// (host, worker runtime, engine, engine child: a few hops).
    const MAX_DEPTH: usize = 8;

    /// Read-only Win32 readings for one session's browser host.
    pub(crate) struct WindowsProbe {
        host_pid: u32,
        host_created: u64,
        /// The window last judged, its process and the verdict.
        cache: Option<(isize, u32, bool)>,
    }

    impl WindowsProbe {
        pub(crate) fn new(host_pid: u32, host_created: u64) -> Self {
            Self {
                host_pid,
                host_created,
                cache: None,
            }
        }

        fn in_front(&mut self) -> bool {
            // SAFETY: no arguments; returns a window handle or 0.
            let window = unsafe { GetForegroundWindow() };
            if window == 0 {
                return false;
            }
            let mut pid: u32 = 0;
            // SAFETY: a window handle and an out-pointer to a local.
            unsafe { GetWindowThreadProcessId(window, &mut pid) };
            if let Some((cached_window, cached_pid, verdict)) = self.cache {
                if cached_window == window && cached_pid == pid {
                    return verdict;
                }
            }
            let verdict = descends_from(pid, self.host_pid, self.host_created);
            self.cache = Some((window, pid, verdict));
            verdict
        }
    }

    impl InputProbe for WindowsProbe {
        fn sample(&mut self) -> Option<Sample> {
            let mut info = LASTINPUTINFO {
                cbSize: u32::try_from(std::mem::size_of::<LASTINPUTINFO>()).ok()?,
                dwTime: 0,
            };
            // SAFETY: an initialised struct with its size set.
            if unsafe { GetLastInputInfo(&mut info) } == 0 {
                return None;
            }
            // SAFETY: no arguments.
            let tick = unsafe { GetTickCount() };
            Some(Sample {
                last_input: info.dwTime,
                idle_ms: u64::from(tick.wrapping_sub(info.dwTime)),
                session_in_front: self.in_front(),
            })
        }
    }

    /// A process's creation time (FILETIME as one number), or `None`.
    pub(crate) fn created(pid: u32) -> Option<u64> {
        // SAFETY: a plain query-only open of a pid; closed below.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process == 0 {
            return None;
        }
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        // SAFETY: a valid handle and out-pointers to locals.
        let ok =
            unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) };
        // SAFETY: closing the handle opened above, once.
        unsafe { CloseHandle(process) };
        (ok != 0)
            .then(|| (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }

    /// Every process's parent, from one snapshot.
    fn parents() -> Option<HashMap<u32, u32>> {
        // SAFETY: a process snapshot; closed below.
        let snapshot: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE || snapshot == 0 {
            return None;
        }
        let mut map = HashMap::new();
        // SAFETY: PROCESSENTRY32W is plain data; all zero is a valid value.
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).unwrap_or(0);
        // SAFETY: a valid snapshot and an entry with its size set.
        let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
        while more {
            map.insert(entry.th32ProcessID, entry.th32ParentProcessID);
            // SAFETY: as above.
            more = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
        }
        // SAFETY: closing the snapshot opened above, once.
        unsafe { CloseHandle(snapshot) };
        Some(map)
    }

    /// Whether `pid` is `host_pid` (created at `host_created`) or one of
    /// its descendants. Each parent must have been created no later than
    /// its child, so a reused pid never makes a stranger a parent; any
    /// unanswerable step answers no.
    pub(crate) fn descends_from(pid: u32, host_pid: u32, host_created: u64) -> bool {
        if pid == 0 || host_pid == 0 {
            return false;
        }
        let Some(parents) = parents() else {
            return false;
        };
        let mut current = pid;
        let Some(mut current_created) = created(current) else {
            return false;
        };
        for _ in 0..MAX_DEPTH {
            if current == host_pid {
                return current_created == host_created;
            }
            let Some(&parent) = parents.get(&current) else {
                return false;
            };
            if parent == 0 || parent == current {
                return false;
            }
            let Some(parent_created) = created(parent) else {
                return false;
            };
            if parent_created > current_created {
                return false;
            }
            current = parent;
            current_created = parent_created;
        }
        false
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn own() -> (u32, u64) {
            let pid = std::process::id();
            (pid, created(pid).unwrap_or(0))
        }

        #[test]
        fn ob06_a_child_process_descends_from_its_parent_and_not_the_other_way() {
            let (pid, started) = own();
            assert!(started != 0);
            assert!(
                descends_from(pid, pid, started),
                "a process is its own tree"
            );
            assert!(
                !descends_from(pid, pid, started + 1),
                "another creation time is another process"
            );
            let mut child = std::process::Command::new("cmd")
                .args(["/C", "ping -n 4 127.0.0.1 >NUL"])
                .spawn()
                .expect("spawn a child");
            let child_pid = child.id();
            let child_started = created(child_pid).unwrap_or(0);
            assert!(
                descends_from(child_pid, pid, started),
                "the child is in our tree"
            );
            assert!(
                !descends_from(pid, child_pid, child_started),
                "we are not in the child's tree"
            );
            let _ = child.kill();
            let _ = child.wait();
            assert!(!descends_from(0, pid, started));
        }

        #[test]
        fn ob06_the_probe_reads_the_last_input_without_touching_anything() {
            // Read-only: GetLastInputInfo, GetTickCount, GetForegroundWindow.
            let (pid, started) = own();
            let mut probe = WindowsProbe::new(pid, started);
            let first = probe.sample().expect("the OS reports the last input");
            let second = probe.sample().expect("again");
            assert!(second.idle_ms < 50 * 24 * 3_600_000);
            assert_eq!(first.session_in_front, second.session_in_front);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicU64;

    fn sample(last_input: u32, idle_ms: u64, session_in_front: bool) -> Option<Sample> {
        Some(Sample {
            last_input,
            idle_ms,
            session_in_front,
        })
    }

    #[test]
    fn ob06_the_first_reading_is_a_baseline_and_only_new_input_in_front_counts() {
        let mut feed = InputFeed::default();
        feed.sample(Millis(1_000), sample(7, 10, true));
        assert_eq!(feed.take(), None, "input from before the session watched");
        feed.sample(Millis(1_100), sample(7, 110, true));
        assert_eq!(feed.take(), None, "the same input again");
        feed.sample(Millis(1_200), sample(8, 30, false));
        assert_eq!(feed.take(), None, "input with another window in front");
        feed.sample(Millis(1_300), sample(9, 20, true));
        assert_eq!(feed.take(), Some(Millis(1_280)), "dated when it happened");
        assert_eq!(feed.take(), None, "taken once");
        feed.sample(Millis(1_400), sample(10, 50, true));
        feed.sample(Millis(1_500), sample(11, 10, true));
        assert_eq!(feed.take(), Some(Millis(1_490)), "the latest wins");
    }

    #[test]
    fn ob06_an_unreadable_os_counts_as_input_now() {
        let mut feed = InputFeed::default();
        feed.sample(Millis(5_000), None);
        assert_eq!(feed.take(), Some(Millis(5_000)));
    }

    #[test]
    fn ob06_the_answer_to_an_orcel_prompt_is_not_a_person_on_the_browser() {
        let mut feed = InputFeed::default();
        feed.sample(Millis(0), sample(1, 0, false));
        feed.prompt_started();
        // A person used the browser while the prompt was up: kept.
        feed.sample(Millis(2_000), sample(2, 0, true));
        // The answering click, seen with the browser back in front: dropped.
        feed.sample(Millis(4_900), sample(3, 0, true));
        feed.prompt_ended(Millis(5_000));
        assert_eq!(feed.take(), Some(Millis(2_000)));
        // The key's release reaching the browser after the prompt closed.
        feed.sample(Millis(5_300), sample(4, 0, true));
        assert_eq!(feed.take(), None);
        // Input after the prompt's edge counts again.
        feed.sample(Millis(6_100), sample(5, 0, true));
        assert_eq!(feed.take(), Some(Millis(6_100)));
    }

    struct Scripted(Arc<Mutex<VecDeque<Option<Sample>>>>);

    impl InputProbe for Scripted {
        fn sample(&mut self) -> Option<Sample> {
            let mut queue = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            match queue.len() {
                0 => sample(0, 0, false),
                1 => queue.front().copied().flatten(),
                _ => queue.pop_front().flatten(),
            }
        }
    }

    #[test]
    fn ob06_the_monitor_polls_before_handing_input_over_and_brackets_prompts() {
        let script = Arc::new(Mutex::new(VecDeque::from([
            sample(1, 0, true),
            sample(2, 5, true),
        ])));
        let clock = Arc::new(AtomicU64::new(100));
        let now_clock = Arc::clone(&clock);
        let monitor = HumanInputMonitor::manual(
            Box::new(Scripted(Arc::clone(&script))),
            Box::new(move || Millis(now_clock.load(Ordering::SeqCst))),
        );
        clock.store(200, Ordering::SeqCst);
        assert_eq!(monitor.take(), Some(Millis(195)));
        // A prompt: the answering input near its end is dropped.
        script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend([sample(2, 0, true), sample(3, 0, true), sample(3, 0, true)]);
        monitor.prompt_started();
        clock.store(900, Ordering::SeqCst);
        monitor.poll();
        clock.store(1_000, Ordering::SeqCst);
        monitor.prompt_ended();
        assert_eq!(monitor.take(), None);
    }

    #[test]
    fn ob06_a_polling_monitor_stops_its_thread_when_dropped() {
        let script = Arc::new(Mutex::new(VecDeque::from([sample(1, 0, false)])));
        let monitor =
            HumanInputMonitor::polling(Box::new(Scripted(script)), Box::new(|| Millis(0)));
        assert!(monitor.thread.is_some());
        std::thread::sleep(Duration::from_millis(POLL_MS * 3));
        drop(monitor);
    }

    #[test]
    fn ob06_other_systems_have_no_source_yet() {
        assert_eq!(for_host(1, 1).is_some(), cfg!(windows));
    }
}
