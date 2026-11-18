//! The authority named pipe: server instances with the spec 4.13
//! anti-squatting rules, the client open with the exact access mask, and
//! the client's server verification (PID and owner SID) before anything is
//! sent.
//!
//! The overlapped-I/O transport (every connect, read and write can time
//! out) follows orceld's app API pipe (`crates/orceld/src/app_api.rs`,
//! module `win`), the repository's own code.

use super::{os_error, sid_to_string, wide, Owned};
use crate::error::AuthorityError;
use crate::pipe_sddl::{pipe_sddl, CLIENT_ACCESS};
use crate::protocol::MAX_FRAME_BYTES;
use std::ffi::c_void;
use std::io;
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND,
    ERROR_IO_PENDING, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX, SECURITY_IMPERSONATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeServerProcessId, WaitNamedPipeW,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

const PIPE_BUFFER: u32 = MAX_FRAME_BYTES as u32;

/// One end of a pipe opened for overlapped I/O.
pub struct Pipe {
    handle: Owned,
    event: Owned,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

// SAFETY: the handles are kernel handles usable from any thread; one
// thread owns a Pipe at a time.
unsafe impl Send for Pipe {}

fn millis(timeout: Option<Duration>) -> u32 {
    timeout
        .map(|timeout| u32::try_from(timeout.as_millis()).unwrap_or(INFINITE - 1))
        .unwrap_or(INFINITE)
}

impl Pipe {
    fn from_handle(handle: HANDLE) -> io::Result<Self> {
        let handle = Owned(handle);
        // SAFETY: a manual-reset, unnamed event with default security.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            handle,
            event: Owned(event),
            read_timeout: None,
            write_timeout: None,
        })
    }

    pub fn raw(&self) -> HANDLE {
        self.handle.0
    }

    pub fn set_timeouts(&mut self, read: Option<Duration>, write: Option<Duration>) {
        self.read_timeout = read;
        self.write_timeout = write;
    }

    fn complete(&self, ov: &OVERLAPPED, timeout: Option<Duration>) -> io::Result<u32> {
        // SAFETY: `self.event` is the live event `ov` signals.
        let waited = unsafe { WaitForSingleObject(self.event.0, millis(timeout)) };
        let mut transferred = 0u32;
        if waited != WAIT_OBJECT_0 {
            let error = if waited == WAIT_TIMEOUT {
                io::Error::new(io::ErrorKind::TimedOut, "pipe operation timed out")
            } else {
                io::Error::last_os_error()
            };
            // SAFETY: cancel the pending operation and wait for it so `ov`
            // and its buffer outlive it.
            unsafe {
                CancelIoEx(self.raw(), ov);
                GetOverlappedResult(self.raw(), ov, &mut transferred, 1);
            }
            return Err(error);
        }
        // SAFETY: the operation completed; `ov` is live.
        if unsafe { GetOverlappedResult(self.raw(), ov, &mut transferred, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(transferred)
    }

    fn overlapped(&self) -> OVERLAPPED {
        // SAFETY: an all-zero OVERLAPPED is the documented initial value.
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = self.event.0;
        ov
    }

    /// Waits for a client of this server instance.
    pub fn connect(&self) -> io::Result<()> {
        let mut ov = self.overlapped();
        // SAFETY: `ov` lives until `complete` returns.
        if unsafe { ConnectNamedPipe(self.raw(), &mut ov) } != 0 {
            return Ok(());
        }
        // SAFETY: plain read of this thread's last error.
        match unsafe { GetLastError() } {
            ERROR_PIPE_CONNECTED => Ok(()),
            ERROR_IO_PENDING => self.complete(&ov, None).map(|_| ()),
            error => Err(io::Error::from_raw_os_error(error as i32)),
        }
    }

    fn transfer(&self, buf: *mut u8, len: usize, write: bool) -> io::Result<usize> {
        let len = u32::try_from(len).unwrap_or(u32::MAX);
        let mut ov = self.overlapped();
        // SAFETY: `buf` holds `len` bytes and outlives the operation.
        let started = unsafe {
            if write {
                WriteFile(self.raw(), buf, len, std::ptr::null_mut(), &mut ov)
            } else {
                ReadFile(self.raw(), buf, len, std::ptr::null_mut(), &mut ov)
            }
        };
        if started == 0 {
            // SAFETY: plain read of this thread's last error.
            let error = unsafe { GetLastError() };
            if !write && error == ERROR_BROKEN_PIPE {
                return Ok(0);
            }
            if error != ERROR_IO_PENDING {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
        }
        let timeout = if write {
            self.write_timeout
        } else {
            self.read_timeout
        };
        match self.complete(&ov, timeout) {
            Ok(transferred) => Ok(transferred as usize),
            Err(error) if !write && error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) => Ok(0),
            Err(error) => Err(error),
        }
    }
}

impl io::Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.transfer(buf.as_mut_ptr(), buf.len(), false)
    }
}

impl io::Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.transfer(buf.as_ptr().cast_mut(), buf.len(), true)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Why the first instance could not be created.
#[derive(Debug)]
pub enum CreateError {
    /// The name already exists (squatted or a second server): the service
    /// refuses to run.
    NameTaken(String),
    Failed(AuthorityError),
}

/// Creates one server instance of `name` owned by `owner_sid`.
pub fn create_instance(name: &str, owner_sid: &str, first: bool) -> Result<Pipe, CreateError> {
    let sddl = pipe_sddl(owner_sid).map_err(CreateError::Failed)?;
    let sddl = wide(&sddl);
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated; `descriptor` is freed below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(CreateError::Failed(os_error(
            "the pipe security descriptor",
        )));
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    let wide_name = wide(name);
    // SAFETY: `wide_name` is NUL-terminated; the descriptor lives through
    // the call, which copies it.
    let handle = unsafe {
        CreateNamedPipeW(
            wide_name.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER,
            PIPE_BUFFER,
            0,
            &attributes,
        )
    };
    let created = if handle == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        let code = error.raw_os_error().map(|code| code as u32);
        if first && (code == Some(ERROR_ACCESS_DENIED) || code == Some(ERROR_PIPE_BUSY)) {
            Err(CreateError::NameTaken(format!(
                "the pipe name {name} already exists ({error}); the authority refuses to run rather than share or follow it"
            )))
        } else {
            Err(CreateError::Failed(AuthorityError::internal(format!(
                "create the pipe {name}: {error}"
            ))))
        }
    } else {
        Pipe::from_handle(handle)
            .map_err(|error| CreateError::Failed(AuthorityError::internal(error.to_string())))
    };
    // SAFETY: freed once after the system copied it.
    unsafe { LocalFree(descriptor.cast()) };
    created
}

/// Who the client expects on the other end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerExpectation {
    pub pipe_name: String,
    /// The server's process id (installed: from `QueryServiceStatusEx`).
    pub pid: u32,
    /// The pipe owner SID (installed: the virtual service SID).
    pub owner_sid: String,
}

/// The pipe's owner SID and the DACL's ACEs as (SID, mask) of allow ACEs.
pub fn pipe_security(handle: HANDLE) -> Result<(String, Vec<(String, u32)>), AuthorityError> {
    let mut owner: *mut c_void = std::ptr::null_mut();
    let mut dacl: *mut windows_sys::Win32::Security::ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the out pointers point into `descriptor`, freed below.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(AuthorityError::unavailable(format!(
            "read the pipe's security (Win32 error {status})"
        )));
    }
    // SAFETY: `owner` and `dacl` point into the live descriptor.
    let result = unsafe {
        let owner = if owner.is_null() {
            Err(AuthorityError::unavailable("the pipe has no owner"))
        } else {
            sid_to_string(owner)
        };
        owner.and_then(|owner| Ok((owner, super::acl::allow_aces(dacl)?)))
    };
    // SAFETY: allocated by GetSecurityInfo; freed once.
    unsafe { LocalFree(descriptor) };
    result
}

/// Opens the pipe as a client and verifies the server before returning.
/// Nothing is written to a pipe that fails the check.
pub fn connect_verified(
    expectation: &ServerExpectation,
    timeout: Duration,
) -> Result<Pipe, AuthorityError> {
    let name = wide(&expectation.pipe_name);
    let mut attempts = 0;
    let handle = loop {
        // SAFETY: `name` is NUL-terminated. The access mask is exactly what
        // the pipe grants INTERACTIVE; identification is allowed up to
        // impersonation so the service can read our image as us.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                CLIENT_ACCESS,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
                0,
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            break handle;
        }
        // SAFETY: plain read of this thread's last error.
        let error = unsafe { GetLastError() };
        attempts += 1;
        if error == ERROR_PIPE_BUSY && attempts < 5 {
            // SAFETY: `name` is NUL-terminated.
            unsafe { WaitNamedPipeW(name.as_ptr(), 2_000) };
            continue;
        }
        return Err(AuthorityError::unavailable(
            if error == ERROR_FILE_NOT_FOUND {
                format!(
                "the Orcel authority service is not running (no pipe {}); Full Control is unavailable",
                expectation.pipe_name
            )
            } else {
                format!(
                    "the authority pipe {} could not be opened ({})",
                    expectation.pipe_name,
                    io::Error::from_raw_os_error(error as i32)
                )
            },
        ));
    };
    let mut pipe = Pipe::from_handle(handle)
        .map_err(|error| AuthorityError::unavailable(format!("the pipe event: {error}")))?;
    let mut server_pid = 0u32;
    // SAFETY: `server_pid` receives the id.
    if unsafe { GetNamedPipeServerProcessId(pipe.raw(), &mut server_pid) } == 0 {
        return Err(AuthorityError::unavailable(
            "the authority server's process id could not be read",
        ));
    }
    if server_pid != expectation.pid {
        return Err(AuthorityError::unavailable(format!(
            "the authority pipe is served by process {server_pid}, not the service's process {}; refusing to send anything",
            expectation.pid
        )));
    }
    let (owner, _) = pipe_security(pipe.raw())?;
    if !owner.eq_ignore_ascii_case(&expectation.owner_sid) {
        return Err(AuthorityError::unavailable(format!(
            "the authority pipe is owned by {owner}, not the service account {}; refusing to send anything",
            expectation.owner_sid
        )));
    }
    pipe.set_timeouts(Some(timeout), Some(timeout));
    Ok(pipe)
}
