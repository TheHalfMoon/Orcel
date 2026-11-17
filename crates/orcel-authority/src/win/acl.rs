//! The protected state directory check (spec 4.13 "State").
//!
//! The install script creates `%ProgramData%\Orcel\authority` with a
//! protected DACL: `NT SERVICE\OrcelAuthority`, `SYSTEM` and
//! `BUILTIN\Administrators` full control, nobody else. The service refuses
//! to start unless the directory's DACL is protected (no inherited ACEs)
//! and every allow ACE names one of those three SIDs. This module never
//! changes an ACL; it only reads one.

use super::{sid_to_string, wide};
use crate::error::AuthorityError;
use std::path::Path;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
};

/// `SYSTEM`.
pub const SYSTEM_SID: &str = "S-1-5-18";
/// `BUILTIN\Administrators`.
pub const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

/// The allow ACEs of `dacl` as (SID, mask). A null DACL (everyone, full
/// access) is an error.
///
/// # Safety
/// `dacl` is null or points to a valid ACL for the duration of the call.
pub unsafe fn allow_aces(dacl: *mut ACL) -> Result<Vec<(String, u32)>, AuthorityError> {
    if dacl.is_null() {
        return Err(AuthorityError::unavailable(
            "a null DACL grants everyone full access",
        ));
    }
    let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
    if GetAclInformation(
        dacl,
        (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
        std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
        AclSizeInformation,
    ) == 0
    {
        return Err(super::os_error("GetAclInformation"));
    }
    let mut out = Vec::new();
    for index in 0..info.AceCount {
        let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
        if GetAce(dacl, index, &mut ace) == 0 || ace.is_null() {
            return Err(super::os_error("GetAce"));
        }
        let header = &*(ace as *const ACE_HEADER);
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
            continue;
        }
        let allowed = ace as *mut ACCESS_ALLOWED_ACE;
        let sid = std::ptr::addr_of_mut!((*allowed).SidStart).cast();
        out.push((sid_to_string(sid)?, (*allowed).Mask));
    }
    Ok(out)
}

/// Rights on a directory that let a holder add, remove or rename entries or
/// change its security: `FILE_ADD_FILE`, `FILE_ADD_SUBDIRECTORY`,
/// `FILE_DELETE_CHILD`, `DELETE`, `WRITE_DAC`, `WRITE_OWNER`,
/// `GENERIC_WRITE`, `GENERIC_ALL`.
pub const DIRECTORY_CHANGE_RIGHTS: u32 = 0x0000_0002
    | 0x0000_0004
    | 0x0000_0040
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x4000_0000
    | 0x1000_0000;

fn is_one_of(sid: &str, allowed: &[&str]) -> bool {
    allowed.iter().any(|ok| ok.eq_ignore_ascii_case(sid))
}

/// The state directory rule: owned by one of `allowed`, protected (no
/// inherited ACEs), and every allow ACE names one of `allowed`.
pub fn evaluate(
    owner: &str,
    protected: bool,
    aces: &[(String, u32)],
    allowed: &[&str],
) -> Result<(), AuthorityError> {
    if !is_one_of(owner, allowed) {
        return Err(AuthorityError::unavailable(format!(
            "the authority state directory is owned by {owner}; the owner must be the service, SYSTEM or Administrators (a user who owns it can change its DACL)"
        )));
    }
    if !protected {
        return Err(AuthorityError::unavailable(
            "the authority state directory inherits ACEs; run the install script to protect it",
        ));
    }
    if let Some((sid, mask)) = aces
        .iter()
        .find(|(sid, mask)| *mask != 0 && !is_one_of(sid, allowed))
    {
        return Err(AuthorityError::unavailable(format!(
            "the authority state directory grants {sid} access 0x{mask:08x}; only the service, SYSTEM and Administrators may have access"
        )));
    }
    Ok(())
}

/// The parent rule: owned by SYSTEM or Administrators, and nobody else may
/// add, delete or rename entries in it or change its security (otherwise
/// the state directory could be swapped for one a user owns).
pub fn evaluate_parent(
    owner: &str,
    aces: &[(String, u32)],
    privileged: &[&str],
) -> Result<(), AuthorityError> {
    if !is_one_of(owner, &[SYSTEM_SID, ADMINISTRATORS_SID]) {
        return Err(AuthorityError::unavailable(format!(
            "the parent of the authority state directory is owned by {owner}, not SYSTEM or Administrators"
        )));
    }
    if let Some((sid, mask)) = aces
        .iter()
        .find(|(sid, mask)| mask & DIRECTORY_CHANGE_RIGHTS != 0 && !is_one_of(sid, privileged))
    {
        return Err(AuthorityError::unavailable(format!(
            "the parent of the authority state directory lets {sid} change its entries (0x{mask:08x})"
        )));
    }
    Ok(())
}

/// Owner SID, protected flag and allow ACEs of a file system object.
/// Owner SID, whether the DACL is protected, and the allow ACEs.
type Security = (String, bool, Vec<(String, u32)>);

fn read_security(path: &Path) -> Result<Security, AuthorityError> {
    let wide_path = wide(&path.to_string_lossy());
    let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `wide_path` is NUL-terminated; `owner` and `dacl` point into
    // `descriptor`, freed below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
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
            "read the security of {} (Win32 error {status})",
            path.display()
        )));
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `descriptor` is live; `owner` and `dacl` point into it.
    let result = unsafe {
        let protected = GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) != 0
            && control & SE_DACL_PROTECTED != 0;
        let owner = if owner.is_null() {
            Err(AuthorityError::unavailable("the directory has no owner"))
        } else {
            sid_to_string(owner)
        };
        owner.and_then(|owner| Ok((owner, protected, allow_aces(dacl)?)))
    };
    // SAFETY: freed once.
    unsafe { LocalFree(descriptor) };
    result
}

/// Refuses `dir` unless it is owned by and grants access only to
/// `service_sid`, SYSTEM and Administrators with a protected DACL, and its
/// parent lets nobody else change its entries.
pub fn check_protected_dir(dir: &Path, service_sid: &str) -> Result<(), AuthorityError> {
    let allowed = [service_sid, SYSTEM_SID, ADMINISTRATORS_SID];
    let (owner, protected, aces) = read_security(dir)?;
    evaluate(&owner, protected, &aces, &allowed)?;
    if let Some(parent) = dir.parent() {
        let (owner, _, aces) = read_security(parent)?;
        evaluate_parent(&owner, &aces, &allowed)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_service_system_and_administrators_pass() {
        let service = "S-1-5-80-1-2-3-4-5";
        let allowed = [service, SYSTEM_SID, ADMINISTRATORS_SID];
        let good = vec![
            (service.to_owned(), 0x1f01ff),
            (SYSTEM_SID.to_owned(), 0x1f01ff),
            (ADMINISTRATORS_SID.to_owned(), 0x1f01ff),
        ];
        assert_eq!(evaluate(ADMINISTRATORS_SID, true, &good, &allowed), Ok(()));
        assert!(
            evaluate("S-1-5-21-1-2-3-1001", true, &good, &allowed).is_err(),
            "a user owner is refused"
        );
        assert!(
            evaluate(ADMINISTRATORS_SID, false, &good, &allowed).is_err(),
            "inheritance refused"
        );
        for intruder in [
            "S-1-5-32-545",
            "S-1-5-11",
            "S-1-5-4",
            "S-1-1-0",
            "S-1-5-21-1-2-3-1001",
        ] {
            let mut bad = good.clone();
            bad.push((intruder.to_owned(), 0x1200a9));
            assert!(
                evaluate(ADMINISTRATORS_SID, true, &bad, &allowed).is_err(),
                "{intruder}"
            );
        }
    }

    #[test]
    fn the_parent_must_not_let_users_swap_the_state_directory() {
        let privileged = ["S-1-5-80-1-2-3-4-5", SYSTEM_SID, ADMINISTRATORS_SID];
        let read_only_users = vec![
            (SYSTEM_SID.to_owned(), 0x1f01ff),
            (ADMINISTRATORS_SID.to_owned(), 0x1f01ff),
            ("S-1-5-32-545".to_owned(), 0x1200a9),
        ];
        assert_eq!(
            evaluate_parent(ADMINISTRATORS_SID, &read_only_users, &privileged),
            Ok(())
        );
        assert!(evaluate_parent("S-1-5-21-1-2-3-1001", &read_only_users, &privileged).is_err());
        // ProgramData's default lets Users create folders.
        let mut creatable = read_only_users.clone();
        creatable.push(("S-1-5-32-545".to_owned(), 0x000116));
        assert!(evaluate_parent(SYSTEM_SID, &creatable, &privileged).is_err());
    }

    #[test]
    fn an_ordinary_temp_directory_is_refused() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!("orcel-authority-acl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let result = check_protected_dir(&dir, "S-1-5-80-1-2-3-4-5");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(result.is_err(), "a user-readable directory must not pass");
        Ok(())
    }
}
