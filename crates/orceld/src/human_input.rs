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
//!   process belongs to the session's browser family: the kill-on-close job
//!   orceld put the session's browser host in, which every descendant (the
//!   worker runtime, the engine and its children) stays in, since the job
//!   allows no breakaway (`GetWindowThreadProcessId`, then
//!   `IsProcessInJob`).
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
//! browser comes back to the front. When a person answered a prompt
//! (approved or denied it), input within [`PROMPT_EDGE_BEFORE_MS`] before
//! and [`PROMPT_EDGE_AFTER_MS`] after it closed is not counted. A prompt
//! that failed without an answer (refused before any dialog, unavailable)
//! excuses nothing, so a prompt that fails fast and often cannot mask a
//! person's input.
//!
//! A Shadow session has no window and never starts this source. Only
//! Windows has one ([`for_job`]); the live browser is Windows-only today,
//! so no Visible session runs elsewhere (macOS needs its own, later).

use orcel_browser_session::Millis;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

/// How often the source's thread reads the operating system.
pub(crate) const POLL_MS: u64 = 25;

/// Input this long before an answered Orcel approval prompt closed is taken
/// as the answer (the click or key that closed it, then the dialog closing
/// and orceld resuming), not as a person on the browser.
pub(crate) const PROMPT_EDGE_BEFORE_MS: u64 = 500;

/// Input this long after an answered Orcel approval prompt closed is taken
/// as the rest of the answer, not as a person on the browser. A dialog
/// answers on the key's press or the button's release; what can follow is
/// the key's release, which comes 50 to 150 ms after its press for ordinary
/// typing and so lands within a few tens of milliseconds after the prompt
/// closed. 250 ms covers it with margin and leaves a person who goes on to
/// use the browser counted from their very next input.
pub(crate) const PROMPT_EDGE_AFTER_MS: u64 = 250;

/// `GetTickCount` (and the last-input tick) advance in steps of the system
/// timer, 10 to 16 ms. An input's age read from them can be up to one step
/// too large, so an input is dated this much later than its age says (never
/// later than now): the quiet period then never ends before 3000 ms.
pub(crate) const TICK_MARGIN_MS: u64 = 16;

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
    /// Whether the window in front could not be checked (its process could
    /// not be opened or asked). New input then counts as a person's on the
    /// session (fail closed: the agent waits).
    pub front_unknown: bool,
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
        if previous == sample.last_input || !(sample.session_in_front || sample.front_unknown) {
            return;
        }
        let at = now
            .0
            .saturating_sub(sample.idle_ms)
            .saturating_add(TICK_MARGIN_MS)
            .min(now.0);
        self.record(Millis(at));
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

    /// The prompt closed at `end`. If a person `answered` it (approved or
    /// denied), held input near its end was the answer and the rest was a
    /// person on the browser; if not, all of it was.
    pub(crate) fn prompt_ended(&mut self, end: Millis, answered: bool) {
        self.prompt_open = false;
        if answered {
            self.last_prompt_end = Some(end);
        }
        for at in std::mem::take(&mut self.held) {
            self.record(at);
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

    /// The prompt closed; `answered` when a person approved or denied it.
    pub(crate) fn prompt_ended(&self, answered: bool) {
        self.shared.with(|inner| {
            let end = (inner.now)();
            inner.feed.prompt_ended(end, answered);
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

/// Whether the window in front belongs to the session, remembered per
/// window and process. Only a definite answer is remembered: a check that
/// could not be made answers "unknown" this time (the caller then counts
/// new input as a person's) and is made again at the next reading, so a
/// passing failure never blinds the source for the rest of the session.
#[derive(Debug, Default)]
pub(crate) struct Membership {
    known: Option<(isize, u32, bool)>,
}

impl Membership {
    /// The verdict for `window` of process `pid`; `None` when `judge`
    /// could not tell.
    pub(crate) fn verdict(
        &mut self,
        window: isize,
        pid: u32,
        judge: impl FnOnce(u32) -> Option<bool>,
    ) -> Option<bool> {
        if let Some((known_window, known_pid, verdict)) = self.known {
            if known_window == window && known_pid == pid {
                return Some(verdict);
            }
        }
        match judge(pid) {
            Some(verdict) => {
                self.known = Some((window, pid, verdict));
                Some(verdict)
            }
            None => {
                self.known = None;
                None
            }
        }
    }
}

/// The input source for a Visible session whose browser family is in
/// `job` (an owned handle of the host's job).
#[cfg(windows)]
pub(crate) fn for_job(job: std::os::windows::io::OwnedHandle) -> Box<dyn InputProbe> {
    Box::new(windows::WindowsProbe::new(job))
}

#[cfg(windows)]
mod windows {
    use super::{InputProbe, Membership, Sample};
    use std::os::windows::io::{AsRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
    use windows_sys::Win32::System::JobObjects::IsProcessInJob;
    use windows_sys::Win32::System::SystemInformation::GetTickCount;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowThreadProcessId,
    };

    /// Read-only Win32 readings for one session's browser family.
    pub(crate) struct WindowsProbe {
        job: OwnedHandle,
        membership: Membership,
    }

    impl WindowsProbe {
        pub(crate) fn new(job: OwnedHandle) -> Self {
            Self {
                job,
                membership: Membership::default(),
            }
        }

        /// Whether the session's window is in front; `None` when the
        /// window's process could not be checked.
        fn in_front(&mut self) -> Option<bool> {
            // SAFETY: no arguments; returns a window handle or 0.
            let window = unsafe { GetForegroundWindow() };
            if window == 0 {
                return Some(false);
            }
            let mut pid: u32 = 0;
            // SAFETY: a window handle and an out-pointer to a local.
            unsafe { GetWindowThreadProcessId(window, &mut pid) };
            if pid == 0 {
                return None;
            }
            let job = self.job.as_raw_handle() as HANDLE;
            self.membership.verdict(window, pid, |pid| in_job(pid, job))
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
            let front = self.in_front();
            Some(Sample {
                last_input: info.dwTime,
                idle_ms: u64::from(tick.wrapping_sub(info.dwTime)),
                session_in_front: front == Some(true),
                front_unknown: front.is_none(),
            })
        }
    }

    /// Whether process `pid` is in `job`; `None` when it could not be asked
    /// (the process could not be opened, or the query failed).
    pub(crate) fn in_job(pid: u32, job: HANDLE) -> Option<bool> {
        // SAFETY: a plain query-only open of a pid; closed below.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process == 0 {
            return None;
        }
        let mut result: BOOL = 0;
        // SAFETY: valid process and job handles, and an out-pointer to a local.
        let ok = unsafe { IsProcessInJob(process, job, &mut result) };
        // SAFETY: closing the handle opened above, once.
        unsafe { CloseHandle(process) };
        (ok != 0).then_some(result != 0)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW};

        fn new_job() -> OwnedHandle {
            // SAFETY: null attributes and name are permitted.
            let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            assert!(raw != 0, "a job");
            // SAFETY: a fresh handle owned by nobody else.
            unsafe { OwnedHandle::from_raw_handle(raw as _) }
        }

        #[test]
        fn ob06_a_process_in_the_job_belongs_and_one_outside_does_not() {
            let job = new_job();
            let mut child = std::process::Command::new("cmd")
                .args(["/C", "ping -n 4 127.0.0.1 >NUL"])
                .spawn()
                .expect("spawn a child");
            let child_pid = child.id();
            let raw_job = job.as_raw_handle() as HANDLE;
            assert_eq!(in_job(child_pid, raw_job), Some(false));
            // SAFETY: valid job and process handles.
            let assigned =
                unsafe { AssignProcessToJobObject(raw_job, child.as_raw_handle() as HANDLE) };
            assert!(assigned != 0, "the child joins the job");
            assert_eq!(in_job(child_pid, raw_job), Some(true));
            assert_eq!(in_job(std::process::id(), raw_job), Some(false));
            let _ = child.kill();
            let _ = child.wait();
            assert_eq!(in_job(0, raw_job), None, "no such process");
        }

        #[test]
        fn ob06_the_probe_reads_the_last_input_without_touching_anything() {
            // Read-only: GetLastInputInfo, GetTickCount, GetForegroundWindow.
            let mut probe = WindowsProbe::new(new_job());
            let first = probe.sample().expect("the OS reports the last input");
            let second = probe.sample().expect("again");
            assert!(second.idle_ms < 50 * 24 * 3_600_000);
            assert!(
                !first.session_in_front && !second.session_in_front,
                "an empty job owns no window"
            );
            assert_eq!(first.front_unknown, second.front_unknown);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicU64;

    fn sample(last_input: u32, idle_ms: u64, session_in_front: bool) -> Option<Sample> {
        Some(Sample {
            last_input,
            idle_ms,
            session_in_front,
            front_unknown: false,
        })
    }

    #[test]
    fn ob06_new_input_with_an_unchecked_window_in_front_counts() {
        let mut feed = InputFeed::default();
        let unknown = |last_input| {
            Some(Sample {
                last_input,
                idle_ms: 0,
                session_in_front: false,
                front_unknown: true,
            })
        };
        feed.sample(Millis(0), unknown(1));
        assert_eq!(feed.take(), None, "the baseline");
        feed.sample(Millis(100), unknown(1));
        assert_eq!(feed.take(), None, "no new input, nothing to count");
        feed.sample(Millis(200), unknown(2));
        assert_eq!(feed.take(), Some(Millis(200)), "fail closed");
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
        feed.sample(Millis(1_300), sample(9, 40, true));
        assert_eq!(
            feed.take(),
            Some(Millis(1_300 - 40 + TICK_MARGIN_MS)),
            "dated by its age, one timer step late"
        );
        assert_eq!(feed.take(), None, "taken once");
        feed.sample(Millis(1_400), sample(10, 50, true));
        feed.sample(Millis(1_500), sample(11, 30, true));
        assert_eq!(
            feed.take(),
            Some(Millis(1_500 - 30 + TICK_MARGIN_MS)),
            "the latest wins"
        );
    }

    #[test]
    fn ob06_the_timer_step_margin_never_dates_input_after_now() {
        let mut feed = InputFeed::default();
        feed.sample(Millis(0), sample(1, 0, true));
        feed.sample(Millis(2_000), sample(2, 0, true));
        assert_eq!(feed.take(), Some(Millis(2_000)));
        feed.sample(Millis(3_000), sample(3, 5, true));
        assert_eq!(feed.take(), Some(Millis(3_000)));
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
        feed.prompt_ended(Millis(5_000), true);
        assert_eq!(feed.take(), Some(Millis(2_000)));
        // The key's release reaching the browser after the prompt closed.
        feed.sample(Millis(5_200), sample(4, 0, true));
        assert_eq!(feed.take(), None);
        // Input after the prompt's edge counts again.
        feed.sample(Millis(5_300), sample(5, 0, true));
        assert_eq!(feed.take(), Some(Millis(5_300)));
    }

    #[test]
    fn ob06_a_prompt_that_failed_unanswered_excuses_no_input() {
        let mut feed = InputFeed::default();
        feed.sample(Millis(0), sample(1, 0, false));
        // An agent repeats a prompt that fails at once, about once a second,
        // while the person types in the browser.
        for second in 1..=5u32 {
            let at = u64::from(second) * 1_000;
            feed.prompt_started();
            feed.sample(Millis(at), sample(second + 1, 0, true));
            feed.prompt_ended(Millis(at + 2), false);
            feed.sample(Millis(at + 100), sample(second + 100, 0, true));
            assert_eq!(feed.take(), Some(Millis(at + 100)), "second {second}");
        }
    }

    #[test]
    fn ob06_only_a_definite_membership_answer_is_remembered() {
        let mut membership = Membership::default();
        let asked = Cell::new(0);
        let failing = |_: u32| {
            asked.set(asked.get() + 1);
            None
        };
        assert_eq!(membership.verdict(10, 20, failing), None, "unknown");
        // A passing failure is asked again, and then a yes is remembered.
        let yes = membership.verdict(10, 20, |_| {
            asked.set(asked.get() + 1);
            Some(true)
        });
        assert_eq!(yes, Some(true));
        let cached = membership.verdict(10, 20, |_| {
            asked.set(asked.get() + 1);
            Some(false)
        });
        assert_eq!(cached, Some(true));
        assert_eq!(asked.get(), 2, "the yes was remembered");
        // Another window is asked afresh.
        assert_eq!(membership.verdict(11, 20, |_| Some(false)), Some(false));
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
            sample(2, 20, true),
        ])));
        let clock = Arc::new(AtomicU64::new(100));
        let now_clock = Arc::clone(&clock);
        let monitor = HumanInputMonitor::manual(
            Box::new(Scripted(Arc::clone(&script))),
            Box::new(move || Millis(now_clock.load(Ordering::SeqCst))),
        );
        clock.store(200, Ordering::SeqCst);
        assert_eq!(monitor.take(), Some(Millis(200 - 20 + TICK_MARGIN_MS)));
        // An answered prompt: the answering input near its end is dropped.
        script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend([sample(2, 0, true), sample(3, 0, true), sample(3, 0, true)]);
        monitor.prompt_started();
        clock.store(900, Ordering::SeqCst);
        monitor.poll();
        clock.store(1_000, Ordering::SeqCst);
        monitor.prompt_ended(true);
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
}
