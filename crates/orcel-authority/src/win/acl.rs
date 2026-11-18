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

/// `NT SERVICE\TrustedInstaller`.
pub const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const INHERIT_ONLY_ACE: u8 = 0x08;

/// The allow ACEs of `dacl` as (SID, mask), inherit-only ones included. A
/// null DACL (everyone, full access) is an error, and so is any ACE type
/// other than plain allow and deny (object, callback and conditional ACEs
/// are not evaluated here, so they are treated as unsafe).
///
/// # Safety
/// `dacl` is null or points to a valid ACL for the duration of the call.
pub unsafe fn allow_aces(dacl: *mut ACL) -> Result<Vec<(String, u32)>, AuthorityError> {
    aces(dacl, true)
}

/// As [`allow_aces`], without inherit-only ACEs (those that do not apply to
/// the object itself).
///
/// # Safety
/// As [`allow_aces`].
pub unsafe fn effective_allow_aces(dacl: *mut ACL) -> Result<Vec<(String, u32)>, AuthorityError> {
    aces(dacl, false)
}

unsafe fn aces(dacl: *mut ACL, inherit_only: bool) -> Result<Vec<(String, u32)>, AuthorityError> {
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
        match header.AceType {
            ACCESS_ALLOWED_ACE_TYPE => {}
            ACCESS_DENIED_ACE_TYPE => continue,
            other => {
                return Err(AuthorityError::unavailable(format!(
                    "the DACL holds an ACE of type {other}, which this check does not evaluate; treated as unsafe"
                )))
            }
        }
        if !inherit_only && header.AceFlags & INHERIT_ONLY_ACE != 0 {
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

fn read_security(path: &Path, effective: bool) -> Result<Security, AuthorityError> {
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
        owner.and_then(|owner| {
            let aces = if effective {
                effective_allow_aces(dacl)?
            } else {
                allow_aces(dacl)?
            };
            Ok((owner, protected, aces))
        })
    };
    // SAFETY: freed once.
    unsafe { LocalFree(descriptor) };
    result
}

/// `FILE_ATTRIBUTE_REPARSE_POINT`.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Refuses a path element that is a reparse point (junction, symbolic link,
/// mount point): a checked path must be the object it names.
pub fn refuse_reparse_point(path: &Path) -> Result<(), AuthorityError> {
    use std::os::windows::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        AuthorityError::unavailable(format!(
            "read the attributes of {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(AuthorityError::unavailable(format!(
            "{} is a reparse point (junction, link or mount point); refused",
            path.display()
        )));
    }
    Ok(())
}

/// Refuses `dir` unless it is owned by and grants access only to
/// `service_sid`, SYSTEM and Administrators with a protected DACL, and its
/// parent lets nobody else change its entries.
pub fn check_protected_dir(dir: &Path, service_sid: &str) -> Result<(), AuthorityError> {
    let allowed = [service_sid, SYSTEM_SID, ADMINISTRATORS_SID];
    refuse_reparse_point(dir)?;
    let (owner, protected, aces) = read_security(dir, false)?;
    evaluate(&owner, protected, &aces, &allowed)?;
    if let Some(parent) = dir.parent() {
        refuse_reparse_point(parent)?;
        let (owner, _, aces) = read_security(parent, false)?;
        evaluate_parent(&owner, &aces, &allowed)?;
    }
    Ok(())
}

/// One element of an image path: (path, owner SID, effective allow ACEs).
pub type PathSecurity = (String, String, Vec<(String, u32)>);

/// Rights on an image file that let a holder change or replace it.
pub const FILE_REPLACE_RIGHTS: u32 = 0x0000_0002 // FILE_WRITE_DATA
    | 0x0000_0004 // FILE_APPEND_DATA
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x4000_0000 // GENERIC_WRITE
    | 0x1000_0000; // GENERIC_ALL

/// Rights on a directory on an image's path that let a holder rename or
/// remove what is in it, or take the directory over.
pub const ANCESTOR_REPLACE_RIGHTS: u32 = 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000; // GENERIC_ALL

/// The trusted-image rule: the file and every directory above it are owned
/// by a privileged SID, no one else may write, replace or re-permission the
/// file, and no one else may rename or delete entries in, or take over, any
/// directory on its path. `chain[0]` is the file, then its parents up to
/// the root; each is (path, owner, effective allow ACEs).
pub fn evaluate_image_chain(
    chain: &[PathSecurity],
    privileged: &[&str],
) -> Result<(), AuthorityError> {
    for (index, (path, owner, aces)) in chain.iter().enumerate() {
        if !is_one_of(owner, privileged) {
            return Err(AuthorityError::unavailable(format!(
                "the trusted orceld path is user-writable: {path} is owned by {owner}"
            )));
        }
        let rights = if index == 0 {
            FILE_REPLACE_RIGHTS
        } else {
            ANCESTOR_REPLACE_RIGHTS
        };
        if let Some((sid, mask)) = aces
            .iter()
            .find(|(sid, mask)| mask & rights != 0 && !is_one_of(sid, privileged))
        {
            return Err(AuthorityError::unavailable(format!(
                "the trusted orceld path is user-writable: {path} grants {sid} 0x{mask:08x}"
            )));
        }
    }
    Ok(())
}

/// Refuses a trusted orceld image that a non-administrator could replace:
/// reads the file's and every parent directory's owner and DACL.
pub fn check_trusted_image(path: &Path, service_sid: &str) -> Result<(), AuthorityError> {
    if !path.is_absolute() || !path.is_file() {
        return Err(AuthorityError::unavailable(format!(
            "the trusted orceld image {} is not an existing absolute file",
            path.display()
        )));
    }
    let privileged = [
        SYSTEM_SID,
        ADMINISTRATORS_SID,
        TRUSTED_INSTALLER_SID,
        service_sid,
    ];
    let mut chain = Vec::new();
    let mut current = Some(path);
    while let Some(item) = current {
        refuse_reparse_point(item)?;
        let (owner, _, aces) = read_security(item, true)?;
        chain.push((item.display().to_string(), owner, aces));
        current = item.parent();
    }
    evaluate_image_chain(&chain, &privileged)
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
    fn a_user_writable_image_or_path_is_refused() {
        let privileged = [SYSTEM_SID, ADMINISTRATORS_SID, TRUSTED_INSTALLER_SID];
        let users_rx = ("S-1-5-32-545".to_owned(), 0x1200a9);
        let good = vec![
            (
                r"C:\Program Files\Orcel\orceld.exe".to_owned(),
                ADMINISTRATORS_SID.to_owned(),
                vec![users_rx.clone()],
            ),
            (
                r"C:\Program Files\Orcel".to_owned(),
                ADMINISTRATORS_SID.to_owned(),
                vec![users_rx.clone()],
            ),
            // The drive root lets users create folders (append data), which
            // does not let them replace anything below.
            (
                r"C:\".to_owned(),
                SYSTEM_SID.to_owned(),
                vec![("S-1-5-11".to_owned(), 0x0000_0004)],
            ),
        ];
        assert_eq!(evaluate_image_chain(&good, &privileged), Ok(()));
        let mut writable_file = good.clone();
        writable_file[0]
            .2
            .push(("S-1-5-21-1-2-3-1001".to_owned(), 0x0012_019f));
        assert!(evaluate_image_chain(&writable_file, &privileged).is_err());
        let mut user_owned_dir = good.clone();
        user_owned_dir[1].1 = "S-1-5-21-1-2-3-1001".to_owned();
        assert!(evaluate_image_chain(&user_owned_dir, &privileged).is_err());
        let mut delete_child = good.clone();
        delete_child[1]
            .2
            .push(("S-1-5-32-545".to_owned(), 0x0000_0040));
        assert!(evaluate_image_chain(&delete_child, &privileged).is_err());
    }

    #[test]
    fn the_live_image_check_passes_system32_and_refuses_a_temp_file() -> Result<(), String> {
        let windir = std::env::var_os("SystemRoot").ok_or("SystemRoot")?;
        let notepad = std::path::Path::new(&windir)
            .join("System32")
            .join("notepad.exe");
        assert_eq!(check_trusted_image(&notepad, "S-1-5-80-1-2-3-4-5"), Ok(()));
        let file =
            std::env::temp_dir().join(format!("orcel-authority-image-{}.exe", std::process::id()));
        std::fs::write(&file, b"MZ").map_err(|e| e.to_string())?;
        let result = check_trusted_image(&file, "S-1-5-80-1-2-3-4-5");
        let _ = std::fs::remove_file(&file);
        assert!(
            result.is_err(),
            "a file in the user's temp directory must be refused"
        );
        Ok(())
    }

    #[test]
    fn a_junction_on_the_path_is_refused() -> Result<(), String> {
        let base =
            std::env::temp_dir().join(format!("orcel-authority-junction-{}", std::process::id()));
        let target = base.join("target");
        let link = base.join("link");
        std::fs::create_dir_all(&target).map_err(|e| e.to_string())?;
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .map_err(|e| e.to_string())?;
        assert!(made.status.success(), "mklink /J failed");
        assert_eq!(refuse_reparse_point(&target), Ok(()));
        assert!(refuse_reparse_point(&link).is_err());
        let file = link.join("orceld.exe");
        std::fs::write(&file, b"MZ").map_err(|e| e.to_string())?;
        let error = check_trusted_image(&file, "S-1-5-80-1-2-3-4-5").err();
        let _ = std::fs::remove_dir(&link);
        let _ = std::fs::remove_dir_all(&base);
        let message = error.map(|e| e.message).unwrap_or_default();
        assert!(message.contains("reparse point"), "{message}");
        Ok(())
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
