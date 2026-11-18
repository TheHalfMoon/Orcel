//! Windows pieces of the authority service.

pub mod acl;
pub mod confirm;
pub mod crypto;
pub mod eventlog;
pub mod identity;
pub mod pipe;
pub mod roots;
pub mod runtime;
pub mod service;
pub mod uac;

use crate::error::AuthorityError;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

/// A kernel handle closed exactly once.
pub struct Owned(pub HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        if self.0 != 0 && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: the handle was opened by this crate and is closed once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// NUL-terminated UTF-16.
pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The last OS error with `context`, as an internal error.
pub fn os_error(context: &str) -> AuthorityError {
    AuthorityError::internal(format!("{context}: {}", std::io::Error::last_os_error()))
}

/// Reads a NUL-terminated UTF-16 string.
///
/// # Safety
/// `ptr` points to a NUL-terminated UTF-16 string.
pub unsafe fn from_wide_ptr(ptr: *const u16) -> String {
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

/// A SID as `S-1-...`.
///
/// # Safety
/// `sid` is a valid SID pointer for the duration of the call.
pub unsafe fn sid_to_string(sid: *mut c_void) -> Result<String, AuthorityError> {
    let mut text: *mut u16 = std::ptr::null_mut();
    if ConvertSidToStringSidW(sid, &mut text) == 0 {
        return Err(os_error("ConvertSidToStringSidW"));
    }
    let out = from_wide_ptr(text);
    LocalFree(text.cast());
    Ok(out)
}

/// The SID of an account name (for example `NT SERVICE\OrcelAuthority`).
pub fn account_sid(name: &str) -> Result<String, AuthorityError> {
    use windows_sys::Win32::Security::LookupAccountNameW;
    let wide_name = wide(name);
    let mut sid = vec![0u8; 256];
    let mut sid_len = sid.len() as u32;
    let mut domain = vec![0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut use_ = 0i32;
    // SAFETY: every buffer is as long as its length argument says.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            wide_name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut use_,
        )
    };
    if ok == 0 {
        return Err(AuthorityError::unavailable(format!(
            "the account {name} does not exist ({})",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: LookupAccountNameW filled `sid` with a valid SID.
    unsafe { sid_to_string(sid.as_mut_ptr().cast()) }
}

/// The SID this process runs as.
pub fn current_process_sid() -> Result<String, AuthorityError> {
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    let token = identity::open_process_token(
        // SAFETY: the pseudo handle needs no closing.
        unsafe { GetCurrentProcess() },
    )?;
    let user = identity::token_info(&token, windows_sys::Win32::Security::TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER and is aligned for it.
    let sid = unsafe {
        (*(user.as_ptr() as *const windows_sys::Win32::Security::TOKEN_USER))
            .User
            .Sid
    };
    // SAFETY: the SID lives in `user`.
    unsafe { sid_to_string(sid) }
}
