//! Who is on the other end of an authority pipe (spec 4.13: "for every
//! request the service records the caller's token user SID and logon
//! session (`ImpersonateNamedPipeClient`, `GetTokenInformation`), process id
//! (`GetNamedPipeClientProcessId`) and image path").
//!
//! The service impersonates the client only on the handling thread and only
//! for these reads; a guard reverts on every path, and a failed revert ends
//! the process rather than continue as the client. The image path is read
//! while impersonating, so the process is opened with the client's own
//! rights (the service account has none on user processes). Clients connect
//! with `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` for that reason,
//! after they have verified the server's PID and owner SID.

use super::{os_error, sid_to_string, Owned};
use crate::caller::CallerFacts;
use crate::error::AuthorityError;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, RevertToSelf, TokenGroups, TokenSessionId, TokenStatistics,
    TokenUser, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient};
use windows_sys::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenProcessToken, OpenThreadToken};

/// The `INTERACTIVE` well-known SID.
const INTERACTIVE_SID: &str = "S-1-5-4";

/// `SE_GROUP_ENABLED`.
const SE_GROUP_ENABLED: u32 = 0x0000_0004;

pub fn open_process_token(process: HANDLE) -> Result<Owned, AuthorityError> {
    let mut token: HANDLE = 0;
    // SAFETY: `process` is a live handle; `token` is closed by Owned.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(os_error("OpenProcessToken"));
    }
    Ok(Owned(token))
}

/// `GetTokenInformation` into a buffer aligned for any token struct.
pub fn token_info(token: &Owned, class: i32) -> Result<Vec<u64>, AuthorityError> {
    let mut needed = 0u32;
    // SAFETY: the first call asks for the size only.
    unsafe { GetTokenInformation(token.0, class, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(os_error("GetTokenInformation size"));
    }
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buffer` holds at least `needed` bytes.
    if unsafe {
        GetTokenInformation(
            token.0,
            class,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(os_error("GetTokenInformation"));
    }
    Ok(buffer)
}

struct Impersonation;

impl Drop for Impersonation {
    fn drop(&mut self) {
        // SAFETY: plain call on this thread.
        if unsafe { RevertToSelf() } == 0 {
            // Continuing as the client would be worse than stopping.
            std::process::abort();
        }
    }
}

struct LocalSid(*mut c_void);

impl Drop for LocalSid {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSidToSidW; freed once.
        unsafe { LocalFree(self.0) };
    }
}

fn well_known(sid: &str) -> Result<LocalSid, AuthorityError> {
    let wide = super::wide(sid);
    let mut out: *mut c_void = std::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated; `out` is freed by LocalSid.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut out) } == 0 {
        return Err(os_error("ConvertStringSidToSidW"));
    }
    Ok(LocalSid(out))
}

/// The facts of `token`: user SID, logon LUID, session id, INTERACTIVE.
pub fn token_facts(token: &Owned) -> Result<(String, u64, u32, bool), AuthorityError> {
    let user = token_info(token, TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER.
    let sid = unsafe { sid_to_string((*(user.as_ptr() as *const TOKEN_USER)).User.Sid)? };
    let stats = token_info(token, TokenStatistics)?;
    // SAFETY: the buffer holds a TOKEN_STATISTICS.
    let luid = unsafe { (*(stats.as_ptr() as *const TOKEN_STATISTICS)).AuthenticationId };
    let logon = ((luid.HighPart as u32 as u64) << 32) | luid.LowPart as u64;
    let session = token_info(token, TokenSessionId)?;
    let ts_session = session.first().map(|word| *word as u32).unwrap_or(u32::MAX);
    let groups = token_info(token, TokenGroups)?;
    let interactive = well_known(INTERACTIVE_SID)?;
    // SAFETY: the buffer holds a TOKEN_GROUPS with GroupCount entries.
    let is_interactive = unsafe {
        let header = &*(groups.as_ptr() as *const TOKEN_GROUPS);
        let entries =
            std::slice::from_raw_parts(header.Groups.as_ptr(), header.GroupCount as usize);
        entries.iter().any(|entry| {
            entry.Attributes & SE_GROUP_ENABLED != 0 && EqualSid(entry.Sid, interactive.0) != 0
        })
    };
    Ok((sid, logon, ts_session, is_interactive))
}

/// Everything the service observes about the client of `pipe`.
pub fn client_facts(pipe: HANDLE) -> Result<CallerFacts, AuthorityError> {
    let mut pid = 0u32;
    // SAFETY: `pid` receives the id.
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 || pid == 0 {
        return Err(os_error("GetNamedPipeClientProcessId"));
    }
    // SAFETY: `pipe` is a connected server end.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(os_error("ImpersonateNamedPipeClient"));
    }
    let guard = Impersonation;
    let mut token: HANDLE = 0;
    // SAFETY: open this thread's impersonation token as the client (the
    // token's DACL is the client's, which need not grant the service).
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut token) } == 0 {
        return Err(os_error("OpenThreadToken"));
    }
    let token = Owned(token);
    let (user_sid, logon_session_id, ts_session_id, interactive) = token_facts(&token)?;
    // Read the image as the client: the service account cannot open user
    // processes itself. Empty when it cannot be read; the role then falls
    // back to interactive or other, never orceld.
    let image = orcel_platform::process::image_path_and_generation(pid)
        .map(|(image, _)| image)
        .unwrap_or_default();
    drop(token);
    drop(guard);
    // SAFETY: plain call.
    let console = unsafe { WTSGetActiveConsoleSessionId() };
    Ok(CallerFacts {
        pid,
        image,
        user_sid,
        logon_session_id,
        ts_session_id,
        interactive,
        console_session: console != u32::MAX && console == ts_session_id,
    })
}
