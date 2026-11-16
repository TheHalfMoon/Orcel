//! Windows: the fixed pipe, the identification-only open, and the server
//! identity read before the first write.
//!
//! Written for this crate from the Win32 documentation and the WPF preview's
//! checks (`apps/orcel-desktop-preview/src/Program.cs`, `ServerIsThisUser`
//! and `ProcessRunsAsThisUser`); orceld's `describe_holder` performs the
//! same identification-only open on the server side of the protocol.

use crate::error::{ClientError, Unavailable};
use crate::identity::{self, IdentityRefusal, ServerFacts};
use crate::transport::{Canceller, Conn};
use std::ffi::c_void;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE,
    ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING, ERROR_PIPE_BUSY, ERROR_PIPE_NOT_CONNECTED,
    GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    EqualSid, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    TokenIntegrityLevel, TokenUser, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken, SetEvent,
    WaitForMultipleObjects, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

/// How long one write may take before the connection is given up.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// The most a token information answer may be.
const MAX_TOKEN_INFO: u32 = 4096;

/// A handle closed exactly once.
pub(crate) struct Owned(pub(crate) HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        if self.0 != 0 && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: the handle was opened by this module and is closed once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

// SAFETY: a kernel handle may be used and closed from any thread.
unsafe impl Send for Owned {}
// SAFETY: the only shared use is SetEvent on an event handle, which is
// thread-safe.
unsafe impl Sync for Owned {}

pub(crate) fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// One token information class, in memory aligned for its struct.
struct TokenInfo(Vec<u64>);

fn token_info(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<TokenInfo, u32> {
    let mut len = 0u32;
    // SAFETY: the first call only asks how much room the answer needs.
    unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut len) };
    if len == 0 || len > MAX_TOKEN_INFO {
        // SAFETY: plain read of this thread's last error.
        return Err(unsafe { GetLastError() });
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` holds at least `len` bytes, aligned for any token struct.
    if unsafe { GetTokenInformation(token, class, buf.as_mut_ptr().cast(), len, &mut len) } == 0 {
        // SAFETY: plain read of this thread's last error.
        return Err(unsafe { GetLastError() });
    }
    Ok(TokenInfo(buf))
}

impl TokenInfo {
    /// The user SID of a `TokenUser` answer; valid while `self` is.
    fn user_sid(&self) -> *mut c_void {
        // SAFETY: filled by GetTokenInformation(TokenUser), aligned.
        unsafe { (*(self.0.as_ptr() as *const TOKEN_USER)).User.Sid }
    }

    /// The last sub-authority of a `TokenIntegrityLevel` answer's label.
    fn integrity(&self) -> Option<u32> {
        // SAFETY: filled by GetTokenInformation(TokenIntegrityLevel), aligned;
        // the label SID lives inside the buffer.
        unsafe {
            let sid = (*(self.0.as_ptr() as *const TOKEN_MANDATORY_LABEL))
                .Label
                .Sid;
            if sid.is_null() {
                return None;
            }
            let count = *GetSidSubAuthorityCount(sid);
            if count == 0 {
                return None;
            }
            Some(*GetSidSubAuthority(sid, u32::from(count) - 1))
        }
    }
}

/// Opens `process`'s token for a query.
fn process_token(process: HANDLE) -> Result<Owned, u32> {
    let mut token: HANDLE = 0;
    // SAFETY: `process` is a live process handle; `token` receives a handle
    // that `Owned` closes.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        // SAFETY: plain read of this thread's last error.
        return Err(unsafe { GetLastError() });
    }
    Ok(Owned(token))
}

fn own_user() -> Result<TokenInfo, u32> {
    // SAFETY: the pseudo handle of this process needs no closing.
    let token = process_token(unsafe { GetCurrentProcess() })?;
    token_info(token.0, TokenUser)
}

/// This account's SID as `S-1-5-...`, from this process's token.
pub(crate) fn current_user_sid() -> io::Result<String> {
    let user = own_user().map_err(|code| io::Error::from_raw_os_error(code as i32))?;
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: the SID is valid while `user` is; `text` receives a LocalAlloc'd
    // string freed below.
    if unsafe { ConvertSidToStringSidW(user.user_sid(), &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `text` is a NUL-terminated UTF-16 string freed once.
    let sid = unsafe {
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        sid
    };
    Ok(sid)
}

/// `\\.\pipe\orcel-<sid>-app<suffix>`. The shell passes an empty suffix;
/// only this crate's tests pass another.
pub(crate) fn pipe_name(suffix: &str) -> Result<String, ClientError> {
    let sid = current_user_sid().map_err(|error| {
        ClientError::Unavailable(Unavailable::ConnectionLost(error.raw_os_error()))
    })?;
    Ok(format!(r"\\.\pipe\orcel-{sid}-app{suffix}"))
}

/// What the server of `pipe` is: its pid, its token user against ours, and
/// its integrity level.
pub(crate) fn server_facts(pipe: HANDLE) -> ServerFacts {
    let mut pid = 0u32;
    // SAFETY: `pid` receives the id; a failure leaves it 0.
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut pid) } == 0 || pid == 0 {
        return ServerFacts::NoServerPid;
    }
    process_facts(pid)
}

/// The identity facts of process `pid`.
pub(crate) fn process_facts(pid: u32) -> ServerFacts {
    // SAFETY: plain call; `Owned` closes the handle.
    let process = Owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
    if process.0 == 0 {
        // SAFETY: plain read of this thread's last error.
        return ServerFacts::ProcessNotOpened(unsafe { GetLastError() });
    }
    let token = match process_token(process.0) {
        Ok(token) => token,
        Err(code) => return ServerFacts::TokenUnreadable(code),
    };
    let (theirs, label, ours) = match (
        token_info(token.0, TokenUser),
        token_info(token.0, TokenIntegrityLevel),
        own_user(),
    ) {
        (Ok(theirs), Ok(label), Ok(ours)) => (theirs, label, ours),
        (Err(code), _, _) | (_, Err(code), _) | (_, _, Err(code)) => {
            return ServerFacts::TokenUnreadable(code)
        }
    };
    // SAFETY: both SIDs live in their buffers through the call.
    let same_user = unsafe { EqualSid(theirs.user_sid(), ours.user_sid()) } != 0;
    ServerFacts::Token {
        same_user,
        integrity: label.integrity(),
    }
}

/// A manual-reset event.
fn event() -> io::Result<Owned> {
    // SAFETY: an unnamed manual-reset event with default security.
    let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if handle == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Owned(handle))
}

/// The client end of the pipe, overlapped so every read can time out or be
/// cancelled from another thread.
pub(crate) struct Pipe {
    handle: Owned,
    io: Owned,
    cancel: Arc<Owned>,
    read_timeout: Option<Duration>,
}

fn millis(timeout: Option<Duration>) -> u32 {
    timeout
        .map(|timeout| u32::try_from(timeout.as_millis()).unwrap_or(INFINITE - 1))
        .unwrap_or(INFINITE)
}

/// Opens `name` as an identification-only client and confirms its server
/// before returning; nothing is written here.
pub(crate) fn connect(name: &str, timeout: Duration) -> Result<Pipe, ClientError> {
    let deadline = Instant::now() + timeout;
    let wide_name = wide(name);
    let handle = loop {
        // SAFETY: `wide_name` is NUL-terminated; the returned handle goes into
        // `Owned` below or is invalid.
        let handle = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                0,
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            break Owned(handle);
        }
        // SAFETY: plain read of this thread's last error.
        let code = unsafe { GetLastError() };
        match code {
            ERROR_FILE_NOT_FOUND => return Err(ClientError::Unavailable(Unavailable::NotRunning)),
            ERROR_ACCESS_DENIED => {
                // The pipe's security refuses this account: another account
                // created the name first.
                let refused = identity::decide(&ServerFacts::PipeRefusesThisAccount);
                return Err(ClientError::NotYours(
                    refused.err().unwrap_or(IdentityRefusal::OtherAccount),
                ));
            }
            ERROR_PIPE_BUSY => {
                let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                    return Err(ClientError::Unavailable(Unavailable::NoFreeInstance));
                };
                // SAFETY: `wide_name` is NUL-terminated.
                unsafe { WaitNamedPipeW(wide_name.as_ptr(), millis(Some(left)).max(1)) };
            }
            code => {
                return Err(ClientError::Unavailable(Unavailable::ConnectionLost(Some(
                    code as i32,
                ))))
            }
        }
    };
    identity::decide(&server_facts(handle.0)).map_err(ClientError::NotYours)?;
    let io = event().map_err(|error| ClientError::io(&error))?;
    let cancel = event().map_err(|error| ClientError::io(&error))?;
    Ok(Pipe {
        handle,
        io,
        cancel: Arc::new(cancel),
        read_timeout: None,
    })
}

impl Pipe {
    fn overlapped(&self) -> OVERLAPPED {
        // SAFETY: an all-zero OVERLAPPED is the documented initial value.
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = self.io.0;
        ov
    }

    fn transfer(&self, buf: *mut u8, len: usize, write: bool) -> io::Result<usize> {
        let len = u32::try_from(len).unwrap_or(u32::MAX);
        let mut ov = self.overlapped();
        // SAFETY: `buf` holds `len` bytes and, like `ov`, outlives the
        // operation: every path below waits for it to finish, even after a
        // cancel.
        let started = unsafe {
            if write {
                WriteFile(self.handle.0, buf, len, std::ptr::null_mut(), &mut ov)
            } else {
                ReadFile(self.handle.0, buf, len, std::ptr::null_mut(), &mut ov)
            }
        };
        if started == 0 {
            // SAFETY: plain read of this thread's last error.
            let code = unsafe { GetLastError() };
            if code != ERROR_IO_PENDING {
                if !write && (code == ERROR_BROKEN_PIPE || code == ERROR_PIPE_NOT_CONNECTED) {
                    return Ok(0);
                }
                return Err(io::Error::from_raw_os_error(code as i32));
            }
        }
        let timeout = if write {
            Some(WRITE_TIMEOUT)
        } else {
            self.read_timeout
        };
        let handles = [self.io.0, self.cancel.0];
        // SAFETY: both handles are live events.
        let waited = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, millis(timeout)) };
        let mut transferred = 0u32;
        if waited != WAIT_OBJECT_0 {
            let error = if waited == WAIT_TIMEOUT {
                io::Error::new(io::ErrorKind::TimedOut, "pipe operation timed out")
            } else if waited == WAIT_OBJECT_0 + 1 {
                io::Error::new(io::ErrorKind::Interrupted, "cancelled")
            } else {
                io::Error::last_os_error()
            };
            // SAFETY: `ov` is the pending operation on this handle; after the
            // cancel, wait for it so `ov` and the buffer outlive it.
            unsafe {
                CancelIoEx(self.handle.0, &ov);
                GetOverlappedResult(self.handle.0, &ov, &mut transferred, 1);
            }
            return Err(if error.kind() == io::ErrorKind::Interrupted {
                io::Error::new(io::ErrorKind::ConnectionAborted, "cancelled")
            } else {
                error
            });
        }
        // SAFETY: the operation has completed; `ov` is still live.
        if unsafe { GetOverlappedResult(self.handle.0, &ov, &mut transferred, 0) } == 0 {
            // SAFETY: plain read of this thread's last error.
            let code = unsafe { GetLastError() };
            if !write && (code == ERROR_BROKEN_PIPE || code == ERROR_PIPE_NOT_CONNECTED) {
                return Ok(0);
            }
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        Ok(transferred as usize)
    }
}

impl io::Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.transfer(buf.as_mut_ptr(), buf.len(), false)
    }
}

impl io::Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // WriteFile only reads from the buffer.
        self.transfer(buf.as_ptr().cast_mut(), buf.len(), true)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Conn for Pipe {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.read_timeout = timeout;
        Ok(())
    }

    fn canceller(&self) -> io::Result<Canceller> {
        let cancel = Arc::clone(&self.cancel);
        Ok(Canceller::new(move || {
            // SAFETY: a live event handle shared through the Arc.
            unsafe { SetEvent(cancel.0) };
        }))
    }
}
