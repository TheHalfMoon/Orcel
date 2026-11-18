//! The authority pipe's security descriptor (spec 4.13, anti-squatting).
//!
//! - Owner and group: the server's account. Installed, that is the virtual
//!   service SID of `NT SERVICE\OrcelAuthority`, which every client checks
//!   before it sends anything. In console mode it is the current user.
//! - DACL, protected (no inheritance): the server's account full control,
//!   and `NT AUTHORITY\INTERACTIVE` (`IU`) exactly [`CLIENT_ACCESS`] =
//!   `FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE |
//!   READ_CONTROL`. `READ_CONTROL` lets a client read the owner for its check.
//!   `FILE_READ_ATTRIBUTES` is required: `CreateFileW` always adds it (and
//!   `SYNCHRONIZE`) to the access it asks for, so a client that is not the
//!   owner is refused without it (the CI install E2E found every client of
//!   the installed service refused, 2026-11-18). Nothing
//!   grants `FILE_APPEND_DATA`, whose bit on a pipe is
//!   `FILE_CREATE_PIPE_INSTANCE`, or `GENERIC_WRITE` / `GENERIC_ALL`, which
//!   map to it, so no user process can add a rogue server instance while
//!   the service holds the name.
//! - The pipe is created with `FILE_FLAG_FIRST_PIPE_INSTANCE` and
//!   `PIPE_REJECT_REMOTE_CLIENTS` (see `win::pipe`): if the name already
//!   exists the service refuses to run (a denial of service, never a
//!   spoof).
//!
//! Console mode caveat: there the owner ACE names the current user, so any
//! process of that user may create instances of the console pipe; the
//! anti-squatting guarantee holds only for the installed service, whose
//! account no user process runs as.

use crate::error::AuthorityError;

pub const FILE_READ_DATA: u32 = 0x0000_0001;
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
/// On a named pipe this bit is `FILE_CREATE_PIPE_INSTANCE`.
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
/// Added by `CreateFileW` to every open; reads attributes only.
pub const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
pub const FILE_CREATE_PIPE_INSTANCE: u32 = FILE_APPEND_DATA;
pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;

/// Exactly what `INTERACTIVE` is granted, and exactly what a client asks
/// for in `CreateFileW`.
pub const CLIENT_ACCESS: u32 =
    FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE | READ_CONTROL;

/// Whether a client mask stays clear of every right that could create a
/// pipe instance or change the pipe's security.
pub fn client_mask_is_safe(mask: u32) -> bool {
    mask & (FILE_CREATE_PIPE_INSTANCE
        | GENERIC_WRITE
        | GENERIC_ALL
        | WRITE_DAC
        | WRITE_OWNER
        | DELETE)
        == 0
}

/// A SID in string form: `S-1-` and dash-separated decimal parts.
pub fn is_sid_string(text: &str) -> bool {
    text.len() <= 184
        && text.strip_prefix("S-1-").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .split('-')
                    .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// The SDDL of the pipe for a server running as `owner_sid`.
pub fn pipe_sddl(owner_sid: &str) -> Result<String, AuthorityError> {
    if !is_sid_string(owner_sid) {
        return Err(AuthorityError::internal(
            "the pipe owner is not a SID string",
        ));
    }
    if !client_mask_is_safe(CLIENT_ACCESS) {
        return Err(AuthorityError::internal("the client access mask is unsafe"));
    }
    Ok(format!(
        "O:{owner_sid}G:{owner_sid}D:P(A;;FA;;;{owner_sid})(A;;0x{CLIENT_ACCESS:08x};;;IU)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_ace_is_exactly_read_write_synchronize_read_control() {
        assert_eq!(CLIENT_ACCESS, 0x0012_0083);
        assert!(client_mask_is_safe(CLIENT_ACCESS));
        assert_eq!(CLIENT_ACCESS & FILE_CREATE_PIPE_INSTANCE, 0);
        for unsafe_mask in [
            GENERIC_WRITE,
            GENERIC_ALL,
            FILE_APPEND_DATA,
            WRITE_DAC,
            WRITE_OWNER,
        ] {
            assert!(!client_mask_is_safe(CLIENT_ACCESS | unsafe_mask));
        }
    }

    #[test]
    fn the_descriptor_is_protected_owned_by_the_server_and_grants_iu_the_exact_mask(
    ) -> Result<(), String> {
        let sid = "S-1-5-80-1111111111-2222222222-3333333333-4444444444-5555555555";
        let sddl = pipe_sddl(sid).map_err(|e| e.to_string())?;
        assert_eq!(
            sddl,
            format!("O:{sid}G:{sid}D:P(A;;FA;;;{sid})(A;;0x00120083;;;IU)")
        );
        assert!(sddl.contains("D:P("), "the DACL is protected");
        assert!(!sddl.contains(";GW;") && !sddl.contains(";GA;;;IU"));
        assert!(!sddl.contains("WD") && !sddl.contains(";;;BU") && !sddl.contains(";;;AU"));
        assert!(pipe_sddl("not-a-sid").is_err());
        assert!(pipe_sddl("S-1-5-;(A;;GA;;;WD)").is_err());
        Ok(())
    }
}
