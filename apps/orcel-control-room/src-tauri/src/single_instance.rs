//! One shell per user: the named mutex `Local\orcel-control-room-<user SID>`.
//!
//! The shell's own code creates it (no single-instance plugin), with a
//! protected DACL that grants this user's SID alone. Two refusals:
//!
//! - `ERROR_ALREADY_EXISTS`: another instance of this user holds it, so this
//!   process exits with "Orcel Control Room is already open".
//! - `ERROR_ACCESS_DENIED`: the name exists under a DACL that refuses this
//!   user, so another account (or another program) created it first. The
//!   process exits without opening a window.
//!
//! The name is predictable, so squatting it is a recorded residual beside
//! pipe squatting: another account's mutex is refused and reported; a
//! same-user holder only keeps a viewer from opening.

use std::fmt;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, HANDLE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::System::Threading::CreateMutexW;

/// Why this process may not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Another instance of this user holds the mutex.
    AlreadyOpen,
    /// The name exists under a DACL that refuses this user.
    NameHeldByAnother,
    /// The SID, the descriptor or the mutex could not be made.
    Os(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::AlreadyOpen => f.write_str("Orcel Control Room is already open"),
            Refusal::NameHeldByAnother => f.write_str(
                "another program holds the Control Room's name; it may be another account",
            ),
            Refusal::Os(detail) => write!(f, "the single-instance check failed: {detail}"),
        }
    }
}

/// Holds the mutex for as long as it lives.
#[derive(Debug)]
pub struct Instance(HANDLE);

impl Drop for Instance {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// The mutex name for `sid`.
pub fn mutex_name(sid: &str) -> String {
    format!(r"Local\orcel-control-room-{sid}")
}

/// The protected DACL granting `sid` alone (generic all, which maps to every
/// mutex right).
pub fn user_only_sddl(sid: &str) -> String {
    format!("D:P(A;;GA;;;{sid})")
}

/// Takes this user's single-instance mutex.
pub fn acquire() -> Result<Instance, Refusal> {
    let sid = orcel_app_api_client::this_user_sid()
        .map_err(|error| Refusal::Os(format!("this user's SID could not be read: {error}")))?;
    create(&mutex_name(&sid), &user_only_sddl(&sid))
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Creates (or meets) the mutex `name` with the descriptor `sddl`.
fn create(name: &str, sddl: &str) -> Result<Instance, Refusal> {
    let sddl = wide(sddl);
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `descriptor` receives a LocalAlloc'd descriptor freed below.
    let made = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if made == 0 {
        // SAFETY: plain read of this thread's last error.
        let code = unsafe { GetLastError() };
        return Err(Refusal::Os(format!(
            "the mutex descriptor could not be made (error {code})"
        )));
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let name = wide(name);
    // SAFETY: the attributes and name outlive the call; the last error is
    // read before anything else can change it.
    let (handle, code) = unsafe {
        let handle = CreateMutexW(&attributes, 0, name.as_ptr());
        (handle, GetLastError())
    };
    // SAFETY: the descriptor was allocated above and is freed once.
    unsafe { LocalFree(descriptor) };
    if handle == 0 {
        return Err(if code == ERROR_ACCESS_DENIED {
            Refusal::NameHeldByAnother
        } else {
            Refusal::Os(format!("the mutex could not be created (error {code})"))
        });
    }
    let instance = Instance(handle);
    if code == ERROR_ALREADY_EXISTS {
        return Err(Refusal::AlreadyOpen);
    }
    Ok(instance)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_and_dacl_follow_the_packet() {
        assert_eq!(
            mutex_name("S-1-5-21-1-2-3-1001"),
            r"Local\orcel-control-room-S-1-5-21-1-2-3-1001"
        );
        assert_eq!(
            user_only_sddl("S-1-5-21-1-2-3-1001"),
            "D:P(A;;GA;;;S-1-5-21-1-2-3-1001)"
        );
    }

    /// The two refusals, on a private name (the live cases on the real name
    /// run in the native test against the real binary).
    #[test]
    fn already_open_and_name_held_by_another() {
        let sid = orcel_app_api_client::this_user_sid().unwrap();
        let name = format!(
            r"Local\orcel-control-room-unit-test-{}-{}",
            std::process::id(),
            sid
        );
        let first = create(&name, &user_only_sddl(&sid)).unwrap();
        assert_eq!(
            create(&name, &user_only_sddl(&sid)).unwrap_err(),
            Refusal::AlreadyOpen
        );
        drop(first);
        // A protected, empty DACL grants nobody: what another account's
        // mutex looks like to this user.
        let squatted = format!("{name}-squatted");
        let squatter = create(&squatted, "D:P").unwrap();
        assert_eq!(
            create(&squatted, &user_only_sddl(&sid)).unwrap_err(),
            Refusal::NameHeldByAnother
        );
        drop(squatter);
    }
}
