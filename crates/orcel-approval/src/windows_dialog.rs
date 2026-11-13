//! The Windows Yes/No approval dialog, bounded in time.
//!
//! `MessageBoxW` waits for an answer indefinitely, so an unanswered prompt would hold its
//! request open for as long as nobody is at the desk. A watcher thread closes the dialog
//! after [`DIALOG_TIMEOUT`] by answering No on the dialog's behalf, and records that it did,
//! so the answer reads as a timeout. A timeout denies, as Cancel or a timeout does on macOS
//! (`soft_macos`) and Linux (`linux`), which use the same 120 seconds.

use std::time::Duration;

/// How long a Windows approval dialog waits for an answer.
pub(crate) const DIALOG_TIMEOUT: Duration = Duration::from_secs(120);

pub(crate) const IDYES: i32 = 6;
pub(crate) const IDNO: i32 = 7;

/// What a bounded Yes/No dialog came back with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialogAnswer {
    Yes,
    No,
    /// The dialog was closed for its timeout. This wins over a Yes that arrived in the same
    /// moment, so an answer given after the deadline never approves.
    TimedOut,
    /// Anything else, including a dialog that couldn't be shown (0).
    Unexpected(i32),
}

/// The answer, from `MessageBoxW`'s result and whether the watcher closed the dialog.
pub(crate) fn answer(result: i32, timed_out: bool) -> DialogAnswer {
    if timed_out {
        return DialogAnswer::TimedOut;
    }
    match result {
        IDYES => DialogAnswer::Yes,
        IDNO => DialogAnswer::No,
        other => DialogAnswer::Unexpected(other),
    }
}

/// The caption with how long the dialog stays open.
pub(crate) fn caption(title: &str, limit: Duration) -> String {
    format!("{title} (closes in {} seconds)", limit.as_secs())
}

/// Shows a system-modal Yes/No dialog whose default is No, closed as a timeout after `limit`.
#[cfg(windows)]
pub(crate) fn ask_yes_no(body: &str, title: &str, limit: Duration) -> DialogAnswer {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::sync::Arc;

    type Hwnd = *mut c_void;
    const MB_YESNO: u32 = 0x0000_0004;
    const MB_ICONWARNING: u32 = 0x0000_0030;
    const MB_DEFBUTTON2: u32 = 0x0000_0100;
    const MB_SYSTEMMODAL: u32 = 0x0000_1000;
    const WM_COMMAND: u32 = 0x0111;

    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(hwnd: Hwnd, text: *const u16, caption: *const u16, kind: u32) -> i32;
        fn EnumThreadWindows(
            thread: u32,
            callback: extern "system" fn(Hwnd, isize) -> i32,
            lparam: isize,
        ) -> i32;
        fn GetClassNameW(hwnd: Hwnd, name: *mut u16, capacity: i32) -> i32;
        fn PostMessageW(hwnd: Hwnd, message: u32, wparam: usize, lparam: isize) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentThreadId() -> u32;
    }

    /// Answers No for every message box (class `#32770`) this thread owns. The dialog then
    /// returns IDNO, which [`answer`] reads as a timeout.
    extern "system" fn close_dialog(hwnd: Hwnd, _: isize) -> i32 {
        let mut name = [0u16; 16];
        // SAFETY: `name` is a writable buffer of the stated capacity; `hwnd` came from
        // EnumThreadWindows for this call.
        let length = unsafe { GetClassNameW(hwnd, name.as_mut_ptr(), name.len() as i32) };
        let dialog: Vec<u16> = "#32770".encode_utf16().collect();
        if usize::try_from(length).ok() == Some(dialog.len()) && name[..dialog.len()] == dialog[..]
        {
            // SAFETY: posting a message to a window handle is safe even if it closes meanwhile;
            // the call then fails and is ignored.
            unsafe { PostMessageW(hwnd, WM_COMMAND, IDNO as usize, 0) };
        }
        1
    }

    let wide =
        |value: &str| -> Vec<u16> { value.encode_utf16().chain(std::iter::once(0)).collect() };
    let body = wide(body);
    let caption = wide(&caption(title, limit));
    // SAFETY: GetCurrentThreadId has no preconditions.
    let thread = unsafe { GetCurrentThreadId() };
    let timed_out = Arc::new(AtomicBool::new(false));
    let (done, finished) = mpsc::channel::<()>();
    let watcher = {
        let timed_out = Arc::clone(&timed_out);
        std::thread::Builder::new()
            .name("orcel-approval-dialog-timeout".into())
            .spawn(move || {
                if finished.recv_timeout(limit) != Err(RecvTimeoutError::Timeout) {
                    return;
                }
                // Recorded before the dialog is answered, so its No reads as a timeout.
                timed_out.store(true, Ordering::SeqCst);
                // Repeated until the dialog returns, in case it wasn't up yet.
                loop {
                    // SAFETY: the callback only reads class names and posts messages.
                    unsafe { EnumThreadWindows(thread, close_dialog, 0) };
                    if finished.recv_timeout(Duration::from_millis(100))
                        != Err(RecvTimeoutError::Timeout)
                    {
                        return;
                    }
                }
            })
    };
    // Without a watcher the dialog would wait indefinitely, so no dialog is shown: unavailable.
    let Ok(watcher) = watcher else {
        return DialogAnswer::Unexpected(0);
    };
    // SAFETY: both strings are NUL-terminated UTF-16 that outlive the call; no owner window.
    let result = unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            body.as_ptr(),
            caption.as_ptr(),
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SYSTEMMODAL,
        )
    };
    drop(done);
    // The flag alone decides: the watcher sets it before it closes the dialog.
    let _ = watcher.join();
    answer(result, timed_out.load(Ordering::SeqCst))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timeout_denies_even_when_yes_arrived_with_it() {
        assert_eq!(answer(IDYES, false), DialogAnswer::Yes);
        assert_eq!(answer(IDNO, false), DialogAnswer::No);
        assert_eq!(answer(IDNO, true), DialogAnswer::TimedOut);
        assert_eq!(answer(IDYES, true), DialogAnswer::TimedOut);
        assert_eq!(answer(0, false), DialogAnswer::Unexpected(0));
        assert_eq!(
            caption("Orcel approval SOFT", DIALOG_TIMEOUT),
            "Orcel approval SOFT (closes in 120 seconds)"
        );
    }

    /// The real dialog on a Windows desktop session: nobody answers, so it closes itself as
    /// a timeout. It shows a dialog, so it runs only where `ORCEL_TEST_REAL_DIALOG` is set
    /// (CI's Windows runner), never on a person's desktop by default.
    #[cfg(windows)]
    #[test]
    fn an_unanswered_dialog_closes_itself_as_a_timeout() {
        if std::env::var_os("ORCEL_TEST_REAL_DIALOG").is_none() {
            return;
        }
        let started = std::time::Instant::now();
        let outcome = ask_yes_no(
            "Orcel test dialog. Nothing is approved by it.",
            "Orcel test",
            Duration::from_secs(2),
        );
        assert_eq!(outcome, DialogAnswer::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "{:?}",
            started.elapsed()
        );
    }
}
