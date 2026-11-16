// SPDX-License-Identifier: FSL-1.1-MIT
// Portions copyright (c) 2026 Cua AI, Inc.; modifications copyright Orcel.

//! Windows: the fixed pipe, the identification-only open, and the server
//! identity read before the first write.
//!
//! Provenance (transplant rows T-CUA-25 and T-CUA-26): the handle guard, the
//! wide-string helper, the token-user buffer, the SID string, the pipe name,
//! the identification-only `CreateFileW` and the `OpenProcess`/`EqualSid`
//! account comparison adapt orceld's FSL-1.1-MIT identity helpers
//! (`Owned`, `wide`, `TokenUserBuf`, `token_user`, `current_user_sid`,
//! `pipe_name`, `describe_holder` and `same_account` in
//! `crates/orceld/src/app_api.rs`), which adapt cua@a802eaf26ca9's
//! `cua-keyvault` `winpipe.rs` and `winpeer.rs`; notice in
//! `docs/orcel/notices/cua-FSL-1.1-MIT.txt`. Modifications: a client rather
//! than a server; the integrity half (the token's mandatory label at Medium
//! or above) is ported from the WPF preview's `ProcessRunsAsThisUser`
//! (`apps/orcel-desktop-preview/src/Program.cs`); the pipe object's owner and
//! label are read with `GetSecurityInfo`; reads and the connect wait can be
//! cancelled from another thread.

use crate::error::{ClientError, Unavailable};
use crate::identity::{self, IdentityRefusal, ObjectFacts, ServerFacts};
use crate::transport::{Cancel, Conn};
use std::ffi::c_void;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE,
    ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING, ERROR_PIPE_BUSY, ERROR_PIPE_NOT_CONNECTED,
    GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    EqualSid, GetAce, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    TokenIntegrityLevel, TokenOwner, TokenUser, ACE_HEADER, ACL, LABEL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SYSTEM_MANDATORY_LABEL_ACE,
    TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};
use windows_sys::Win32::System::SystemServices::SYSTEM_MANDATORY_LABEL_ACE_TYPE;
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken, SetEvent,
    WaitForMultipleObjects, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION,
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

    /// The owner SID of a `TokenOwner` answer; valid while `self` is.
    fn owner_sid(&self) -> *mut c_void {
        // SAFETY: filled by GetTokenInformation(TokenOwner), aligned.
        unsafe { (*(self.0.as_ptr() as *const TOKEN_OWNER)).Owner }
    }

    /// The last sub-authority of a `TokenIntegrityLevel` answer's label.
    fn integrity(&self) -> Option<u32> {
        // SAFETY: filled by GetTokenInformation(TokenIntegrityLevel), aligned;
        // the label SID lives inside the buffer.
        unsafe {
            last_sub_authority(
                (*(self.0.as_ptr() as *const TOKEN_MANDATORY_LABEL))
                    .Label
                    .Sid,
            )
        }
    }
}

/// The last sub-authority of `sid` (a mandatory label's level).
///
/// # Safety
/// `sid` is null or a valid SID.
unsafe fn last_sub_authority(sid: *mut c_void) -> Option<u32> {
    if sid.is_null() {
        return None;
    }
    let count = *GetSidSubAuthorityCount(sid);
    if count == 0 {
        return None;
    }
    Some(*GetSidSubAuthority(sid, u32::from(count) - 1))
}

/// A security descriptor `GetSecurityInfo` allocated, freed once.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Drop for Descriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocated by GetSecurityInfo and freed once.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// The pipe object's owner (against this user and this process's default
/// owner) and its mandatory label.
pub(crate) fn object_facts(pipe: HANDLE) -> ObjectFacts {
    let mut owner: *mut c_void = std::ptr::null_mut();
    let mut sacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: every out pointer is writable; the descriptor holding `owner`
    // and `sacl` is freed by `Descriptor` after their last use.
    let read = unsafe {
        GetSecurityInfo(
            pipe,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sacl,
            &mut descriptor,
        )
    };
    let descriptor = Descriptor(descriptor);
    if read != 0 {
        return ObjectFacts::Unreadable(read);
    }
    // SAFETY: the pseudo handle of this process needs no closing.
    let ours = match process_token(unsafe { GetCurrentProcess() }) {
        Ok(token) => match (
            token_info(token.0, TokenUser),
            token_info(token.0, TokenOwner),
        ) {
            (Ok(user), Ok(default_owner)) => (user, default_owner),
            (Err(code), _) | (_, Err(code)) => return ObjectFacts::Unreadable(code),
        },
        Err(code) => return ObjectFacts::Unreadable(code),
    };
    // SAFETY: `owner` lives in `descriptor`; the SIDs live in their buffers.
    let owner_ours = !owner.is_null()
        && unsafe {
            EqualSid(owner, ours.0.user_sid()) != 0 || EqualSid(owner, ours.1.owner_sid()) != 0
        };
    // SAFETY: `sacl` is null or the ACL inside `descriptor`; each ACE GetAce
    // returns lives inside it.
    let label = unsafe { label_of(sacl) };
    drop(descriptor);
    ObjectFacts::Read { owner_ours, label }
}

/// The level of the first mandatory label ACE in `sacl`, if any.
///
/// # Safety
/// `sacl` is null or a valid ACL.
unsafe fn label_of(sacl: *mut ACL) -> Option<u32> {
    if sacl.is_null() {
        return None;
    }
    for index in 0..u32::from((*sacl).AceCount) {
        let mut ace: *mut c_void = std::ptr::null_mut();
        if GetAce(sacl, index, &mut ace) == 0 || ace.is_null() {
            return None;
        }
        if u32::from((*(ace as *const ACE_HEADER)).AceType) == SYSTEM_MANDATORY_LABEL_ACE_TYPE {
            let sid = std::ptr::addr_of_mut!((*(ace as *mut SYSTEM_MANDATORY_LABEL_ACE)).SidStart);
            return last_sub_authority(sid.cast());
        }
    }
    None
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

/// Opens `name` identification-only, reads its server's process and pipe
/// object facts, and closes it without writing. This crate's tests only.
#[cfg(test)]
pub(crate) fn probe(name: &str) -> Option<(ServerFacts, ObjectFacts)> {
    let wide_name = wide(name);
    // SAFETY: `wide_name` is NUL-terminated; `Owned` closes the handle.
    let handle = Owned(unsafe {
        CreateFileW(
            wide_name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            0,
        )
    });
    if handle.0 == INVALID_HANDLE_VALUE {
        return None;
    }
    Some((server_facts(handle.0), object_facts(handle.0)))
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

/// A cancel event: set once, it ends every wait on it.
pub(crate) struct CancelEvent(Owned);

impl CancelEvent {
    pub(crate) fn new() -> io::Result<Self> {
        event().map(Self)
    }

    pub(crate) fn set(&self) {
        // SAFETY: a live event handle.
        unsafe { SetEvent((self.0).0) };
    }

    /// Waits up to `millis`; true when the event is set.
    fn wait(&self, millis: u32) -> bool {
        // SAFETY: a live event handle.
        unsafe { WaitForSingleObject((self.0).0, millis) == WAIT_OBJECT_0 }
    }
}

/// The client end of the pipe, overlapped so every read can time out or be
/// cancelled from another thread.
pub(crate) struct Pipe {
    handle: Owned,
    io: Owned,
    cancel: Arc<Cancel>,
    read_timeout: Option<Duration>,
}

fn millis(timeout: Option<Duration>) -> u32 {
    timeout
        .map(|timeout| u32::try_from(timeout.as_millis()).unwrap_or(INFINITE - 1))
        .unwrap_or(INFINITE)
}

/// How long one wait for a free pipe instance lasts before the cancel event
/// and the deadline are looked at again.
const BUSY_POLL: u32 = 50;

/// Opens `name` as an identification-only client and confirms its server
/// (process and pipe object) before returning; nothing is written here.
/// `cancel` ends the wait for a free instance and every later read.
pub(crate) fn connect(
    name: &str,
    timeout: Duration,
    cancel: Arc<Cancel>,
) -> Result<Pipe, ClientError> {
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
                if cancel.event().wait(0) {
                    return Err(ClientError::Unavailable(Unavailable::ConnectionLost(None)));
                }
                // SAFETY: `wide_name` is NUL-terminated.
                unsafe {
                    WaitNamedPipeW(wide_name.as_ptr(), millis(Some(left)).clamp(1, BUSY_POLL))
                };
            }
            code => {
                return Err(ClientError::Unavailable(Unavailable::ConnectionLost(Some(
                    code as i32,
                ))))
            }
        }
    };
    identity::decide(&server_facts(handle.0)).map_err(ClientError::NotYours)?;
    identity::decide_object(&object_facts(handle.0)).map_err(ClientError::NotYours)?;
    let io = event().map_err(|error| ClientError::io(&error))?;
    Ok(Pipe {
        handle,
        io,
        cancel,
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
        let handles = [self.io.0, (self.cancel.event().0).0];
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
}
