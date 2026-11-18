//! Event Log anchoring (spec 4.8 and 4.13): 4100 audit anchors, 4101
//! granted scopes, 4102 intents and confirmation results, written to the
//! Application log under the `Orcel` source the install script registers.
//! Each event carries the service account's SID as its user SID, so an
//! entry written by a user process under the same source name (any process
//! can open an unregistered source) is told apart by its user field.
//!
//! Console mode writes the same lines to `events.jsonl` in its temporary
//! state directory instead, so tests never touch the machine's Event Log.

use super::{os_error, wide};
use crate::core::EventSink;
use crate::error::AuthorityError;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
    EVENTLOG_INFORMATION_TYPE,
};

/// The registered `Orcel` source.
pub struct EventLogSink {
    handle: HANDLE,
    user_sid: Vec<u64>,
}

// SAFETY: an event source handle may be used from any thread.
unsafe impl Send for EventLogSink {}

impl EventLogSink {
    pub fn open() -> Result<Self, AuthorityError> {
        let source = wide(crate::EVENT_SOURCE);
        // SAFETY: `source` is NUL-terminated.
        let handle = unsafe { RegisterEventSourceW(std::ptr::null(), source.as_ptr()) };
        if handle == 0 {
            return Err(os_error("RegisterEventSourceW"));
        }
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        let token = super::identity::open_process_token(
            // SAFETY: the pseudo handle needs no closing.
            unsafe { GetCurrentProcess() },
        )?;
        let user_sid =
            super::identity::token_info(&token, windows_sys::Win32::Security::TokenUser)?;
        Ok(Self { handle, user_sid })
    }
}

impl Drop for EventLogSink {
    fn drop(&mut self) {
        // SAFETY: registered above, deregistered once.
        unsafe { DeregisterEventSource(self.handle) };
    }
}

impl EventSink for EventLogSink {
    fn record(&self, event_id: u32, error: bool, text: &str) -> Result<(), AuthorityError> {
        let text = wide(text);
        let strings = [text.as_ptr()];
        // SAFETY: the buffer holds a TOKEN_USER; its SID lives in `self`.
        let sid = unsafe {
            (*(self.user_sid.as_ptr() as *const windows_sys::Win32::Security::TOKEN_USER))
                .User
                .Sid
        };
        let kind = if error {
            EVENTLOG_ERROR_TYPE
        } else {
            EVENTLOG_INFORMATION_TYPE
        };
        // SAFETY: one NUL-terminated insertion string; no raw data.
        if unsafe {
            ReportEventW(
                self.handle,
                kind,
                0,
                event_id,
                sid,
                1,
                0,
                strings.as_ptr(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(os_error("ReportEventW"));
        }
        Ok(())
    }
}

/// Console mode: the same events as JSON lines in a file.
pub struct FileEventSink {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FileEventSink {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }
}

impl EventSink for FileEventSink {
    fn record(&self, event_id: u32, error: bool, text: &str) -> Result<(), AuthorityError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| AuthorityError::internal("the event file lock is poisoned"))?;
        let line = serde_json::json!({
            "event_id": event_id,
            "type": if error { "error" } else { "information" },
            "source": crate::EVENT_SOURCE,
            "text": text,
            "at_ms": crate::now_ms(),
        });
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut file| writeln!(file, "{line}"))
            .map_err(|error| AuthorityError::internal(format!("write the event file: {error}")))
    }
}
