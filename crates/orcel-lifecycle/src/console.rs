//! Reading secret input from an interactive console without echo.

use crate::LifecycleError;

/// Prompts on stderr and reads one line from the console with echo disabled.
/// Fails when stdin is not an interactive console or echo cannot be
/// disabled, so a secret is never read while it could be echoed or captured
/// from a pipe; use `--key-file` instead. The original console mode is
/// restored on return, on error, and on Ctrl+C or Ctrl+Break. Prompts are
/// serialized: the saved (handle, mode) pair is process-global, so only one
/// hidden prompt can be active at a time.
#[cfg(windows)]
pub fn read_secret_line(prompt: &str) -> Result<String, LifecycleError> {
    use std::sync::Mutex;
    use windows_sys::Win32::Foundation::BOOL;
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleCtrlHandler, SetConsoleMode, ENABLE_ECHO_INPUT,
        STD_INPUT_HANDLE,
    };

    /// The console input handle and mode this prompt changed, restored by the
    /// signal handler and by `Restore`.
    static SAVED: Mutex<Option<(isize, u32)>> = Mutex::new(None);
    /// Serializes prompts so `SAVED` always describes the active prompt.
    static PROMPT: Mutex<()> = Mutex::new(());

    unsafe extern "system" fn restore_on_signal(_signal: u32) -> BOOL {
        if let Ok(saved) = SAVED.try_lock() {
            if let Some((handle, mode)) = *saved {
                // SAFETY: restores the exact handle and mode saved by this prompt.
                unsafe { SetConsoleMode(handle, mode) };
            }
        }
        // Not handled: the default handler still terminates the process.
        0
    }

    struct Restore {
        handle: isize,
        mode: u32,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: restores the saved mode and removes the signal handler.
            unsafe {
                SetConsoleMode(self.handle, self.mode);
                SetConsoleCtrlHandler(Some(restore_on_signal), 0);
            }
            if let Ok(mut saved) = SAVED.lock() {
                *saved = None;
            }
        }
    }

    let _prompt = PROMPT
        .lock()
        .map_err(|_| LifecycleError::internal("hidden prompt lock poisoned"))?;
    // SAFETY: GetStdHandle has no preconditions.
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode = 0u32;
    // SAFETY: valid out-pointer; failure means stdin is not a console.
    if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
        return Err(LifecycleError::usage(
            "no interactive console for the hidden key prompt; pass --key-file <path>",
        ));
    }
    *SAVED
        .lock()
        .map_err(|_| LifecycleError::internal("console state lock poisoned"))? =
        Some((handle, mode));
    // SAFETY: registers a handler with the documented signature.
    if unsafe { SetConsoleCtrlHandler(Some(restore_on_signal), 1) } == 0 {
        if let Ok(mut saved) = SAVED.lock() {
            *saved = None;
        }
        return Err(LifecycleError::platform(
            "the console signal handler could not be installed; pass --key-file <path>",
        ));
    }
    let restore = Restore { handle, mode };
    // SAFETY: the handle is the console input handle queried above.
    if unsafe { SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) } == 0 {
        return Err(LifecycleError::platform(
            "console echo could not be disabled, so the key was not read; pass --key-file <path>",
        ));
    }
    eprint!("{prompt}");
    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);
    drop(restore);
    eprintln!();
    read.map_err(|error| LifecycleError::io("read key", error))?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Unix: the same contract through termios. Echo is turned off on the
/// terminal behind stdin and restored on return, on error, and on SIGINT,
/// SIGTERM or SIGHUP (the handler restores the saved mode, then re-raises
/// the signal with its default action). Stdin that is not a terminal is
/// refused, so a key is never read from a pipe; use `--key-file` instead.
#[cfg(unix)]
pub fn read_secret_line(prompt: &str) -> Result<String, LifecycleError> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    /// The terminal mode to restore, readable from the signal handler.
    /// Written only while `PROMPT` is held and before `ARMED` is set.
    static mut SAVED: Option<libc::termios> = None;
    static ARMED: AtomicBool = AtomicBool::new(false);
    static PROMPT: Mutex<()> = Mutex::new(());
    const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

    extern "C" fn restore_on_signal(signal: libc::c_int) {
        if ARMED.swap(false, Ordering::SeqCst) {
            // SAFETY: `SAVED` was written before `ARMED` was set and is not
            // written again while armed; tcsetattr, signal and raise are
            // async-signal-safe.
            unsafe {
                if let Some(saved) = (*std::ptr::addr_of!(SAVED)).as_ref() {
                    libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, saved);
                }
            }
        }
        // SAFETY: restores the default action and re-raises the signal.
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
            libc::raise(signal);
        }
    }

    struct Restore {
        previous: [libc::sighandler_t; 3],
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            if ARMED.swap(false, Ordering::SeqCst) {
                // SAFETY: restores the mode saved below on the same fd.
                unsafe {
                    if let Some(saved) = (*std::ptr::addr_of!(SAVED)).as_ref() {
                        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, saved);
                    }
                }
            }
            for (signal, previous) in SIGNALS.iter().zip(self.previous) {
                // SAFETY: reinstalls the handler that was active before.
                unsafe {
                    libc::signal(*signal, previous);
                }
            }
        }
    }

    let _prompt = PROMPT
        .lock()
        .map_err(|_| LifecycleError::internal("hidden prompt lock poisoned"))?;
    // SAFETY: an all-zero termios is a valid out buffer for tcgetattr.
    let mut mode: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd and out-pointer; failure means stdin is not a tty.
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1
        || unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut mode) } != 0
    {
        return Err(LifecycleError::usage(
            "no interactive terminal for the hidden key prompt; pass --key-file <path>",
        ));
    }
    // SAFETY: `PROMPT` is held and `ARMED` is false, so no handler reads
    // `SAVED` while it is written.
    unsafe {
        *std::ptr::addr_of_mut!(SAVED) = Some(mode);
    }
    ARMED.store(true, Ordering::SeqCst);
    let handler = restore_on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: installs a handler with the signature signal(2) expects.
    let previous = SIGNALS.map(|signal| unsafe { libc::signal(signal, handler) });
    let restore = Restore { previous };
    let mut hidden = mode;
    hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
    hidden.c_lflag |= libc::ICANON;
    // SAFETY: valid fd and a termios derived from the one just read.
    if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &hidden) } != 0 {
        return Err(LifecycleError::platform(
            "terminal echo could not be disabled, so the key was not read; pass --key-file <path>",
        ));
    }
    eprint!("{prompt}");
    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);
    drop(restore);
    eprintln!();
    read.map_err(|error| LifecycleError::io("read key", error))?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

#[cfg(not(any(windows, unix)))]
pub fn read_secret_line(_prompt: &str) -> Result<String, LifecycleError> {
    Err(LifecycleError::usage(
        "the hidden key prompt is unavailable on this platform; pass --key-file <path>",
    ))
}
