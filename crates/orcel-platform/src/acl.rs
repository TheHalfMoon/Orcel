//! Windows owner and DACL rules (#358 item 2, #384 item 4): the Windows
//! counterpart of the Unix owner and mode checks in `paths`.
//!
//! Trusted principals are the current user, `SYSTEM`, `BUILTIN\Administrators`
//! and `NT SERVICE\TrustedInstaller`, which play the part of "the user or
//! root" on Unix. A DACL that is absent (a NULL DACL grants everyone
//! everything) is refused. Deny entries only take access away, so they are
//! ignored; inherit-only entries do not apply to the object itself (each
//! child's own DACL is checked when it is reached). Any other allow-type entry
//! (object or callback) is refused, because its grant cannot be judged here.
//!
//! What another principal may hold depends on the object's role:
//!
//! - a private state directory (the `0700` counterpart): nothing beyond
//!   `SYNCHRONIZE`;
//! - an executable file (or a pin file beside it): no right that changes
//!   its content, attributes, DACL or owner, or deletes or renames it;
//! - an ancestor directory: no right that deletes, renames or re-points an
//!   entry (`DELETE`, `FILE_DELETE_CHILD`, `WRITE_DAC`, `WRITE_OWNER`,
//!   `GENERIC_ALL`). Adding new entries is allowed, like a sticky `/tmp`:
//!   nobody else can remove or replace the user's own entries there, and a
//!   name another user pre-created is refused by its owner.
//!
//! The judging is a pure function, so its rules are tested on every OS. Only
//! the reader is Windows-only.

/// `SYNCHRONIZE`: waiting on the object, which grants nothing.
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_APPEND_DATA: u32 = 0x0004;
const FILE_WRITE_EA: u32 = 0x0010;
const FILE_DELETE_CHILD: u32 = 0x0040;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

/// Rights that let a holder replace, rename or re-point an entry below a
/// directory, or the directory itself.
const REPLACE_RIGHTS: u32 = DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
/// Rights that change a file in place, on top of [`REPLACE_RIGHTS`].
const FILE_WRITE_RIGHTS: u32 = REPLACE_RIGHTS
    | FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | GENERIC_WRITE;

pub(crate) const LOCAL_SYSTEM: &str = "S-1-5-18";
pub(crate) const ADMINISTRATORS: &str = "S-1-5-32-544";
pub(crate) const TRUSTED_INSTALLER: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
/// `OWNER RIGHTS`: whatever the (separately checked) owner holds.
const OWNER_RIGHTS: &str = "S-1-3-4";

/// What a checked object is for, which decides what others may hold on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    PrivateDir,
    Ancestor,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AceKind {
    Allow,
    Deny,
    /// Any other entry type, by its `AceType` byte.
    Other(u8),
}

/// One DACL entry as the judge needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ace {
    pub kind: AceKind,
    pub inherit_only: bool,
    pub mask: u32,
    /// The trustee in string form (`S-1-...`); empty for entry types whose
    /// trustee is not read.
    pub sid: String,
}

fn trusted(sid: &str, user: &str) -> bool {
    sid.eq_ignore_ascii_case(user)
        || [LOCAL_SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER].contains(&sid)
}

/// `Ok` when only trusted principals can do more than `role` allows others.
/// `dacl` is `None` for a NULL DACL.
pub(crate) fn judge(
    owner: &str,
    dacl: Option<&[Ace]>,
    user: &str,
    role: Role,
) -> Result<(), String> {
    if !trusted(owner, user) {
        return Err(format!("is owned by {owner}, not the current user"));
    }
    let Some(dacl) = dacl else {
        return Err("has no DACL, which grants everyone full access".into());
    };
    let forbidden = match role {
        Role::PrivateDir => !SYNCHRONIZE,
        Role::Ancestor => REPLACE_RIGHTS,
        Role::File => FILE_WRITE_RIGHTS,
    };
    for ace in dacl.iter().filter(|ace| !ace.inherit_only) {
        match ace.kind {
            AceKind::Deny => {}
            AceKind::Other(kind) => {
                return Err(format!(
                    "has an access entry of type {kind:#x} that cannot be judged"
                ))
            }
            AceKind::Allow => {
                if trusted(&ace.sid, user) || ace.sid == OWNER_RIGHTS {
                    continue;
                }
                if ace.mask & forbidden != 0 {
                    return Err(format!(
                        "grants {} access {:#x}",
                        ace.sid,
                        ace.mask & forbidden
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) use reader::{create_private_dir, current_user_sid, security_of};

#[cfg(windows)]
mod reader {
    use super::{Ace, AceKind};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE, HLOCAL,
    };
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetAce, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::Storage::FileSystem::CreateDirectoryW;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;
    const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 6;
    const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 0xA;
    const ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0xC;

    /// Memory the system allocated with `LocalAlloc`, freed on drop.
    struct Local(*mut core::ffi::c_void);

    impl Drop for Local {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from a Win32 call documented to
                // allocate it with LocalAlloc, and is freed exactly once here.
                unsafe {
                    LocalFree(HLOCAL(self.0));
                }
            }
        }
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// The string form of a SID the caller keeps alive for the call.
    fn sid_string(sid: PSID) -> Result<String, String> {
        let mut text = PWSTR::null();
        // SAFETY: `sid` points at a valid SID owned by the caller for this
        // call; `text` receives a LocalAlloc'd string, freed by `Local`.
        unsafe { ConvertSidToStringSidW(sid, &mut text) }
            .map_err(|error| format!("ConvertSidToStringSidW: {error}"))?;
        let _owned = Local(text.0.cast());
        // SAFETY: on success `text` is a NUL-terminated UTF-16 string that
        // stays allocated until `_owned` drops at the end of this function.
        unsafe { text.to_string() }.map_err(|error| format!("SID text: {error}"))
    }

    /// The owner and the DACL entries of `path` (following a final link,
    /// which callers refuse beforehand). `None` is a NULL DACL.
    pub(crate) fn security_of(path: &Path) -> Result<(String, Option<Vec<Ace>>), String> {
        let name = wide(path);
        let mut owner = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `name` is NUL-terminated and outlives the call; the out
        // pointers are valid locals. On success the owner and DACL point into
        // `descriptor`, which `_descriptor` frees after their last use.
        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(name.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                Some(&mut dacl),
                None,
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("GetNamedSecurityInfoW failed with {}", status.0));
        }
        let _descriptor = Local(descriptor.0);
        if owner.0.is_null() {
            return Err("has no owner".into());
        }
        let owner = sid_string(owner)?;
        if dacl.is_null() {
            return Ok((owner, None));
        }
        // SAFETY: a non-null DACL from GetNamedSecurityInfoW points at a valid
        // ACL header inside `descriptor`.
        let count = unsafe { (*dacl).AceCount };
        let mut entries = Vec::with_capacity(usize::from(count));
        for index in 0..u32::from(count) {
            let mut entry: *mut core::ffi::c_void = std::ptr::null_mut();
            // SAFETY: `index` is below the ACL's own entry count and `entry`
            // is a valid out pointer; the result points into `descriptor`.
            unsafe { GetAce(dacl, index, &mut entry) }
                .map_err(|error| format!("GetAce: {error}"))?;
            // SAFETY: every ACE starts with an ACE_HEADER; read unaligned so
            // no alignment is assumed.
            let header = unsafe { std::ptr::read_unaligned(entry.cast::<ACE_HEADER>()) };
            let inherit_only = u32::from(header.AceFlags) & INHERIT_ONLY_ACE.0 != 0;
            let kind = match header.AceType {
                ACCESS_ALLOWED_ACE_TYPE => AceKind::Allow,
                ACCESS_DENIED_ACE_TYPE
                | ACCESS_DENIED_OBJECT_ACE_TYPE
                | ACCESS_DENIED_CALLBACK_ACE_TYPE
                | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => AceKind::Deny,
                other => AceKind::Other(other),
            };
            let (mask, sid) = if kind == AceKind::Allow {
                if usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>() {
                    return Err("has a truncated access entry".into());
                }
                let allowed = entry.cast::<ACCESS_ALLOWED_ACE>();
                // SAFETY: the entry is an ACCESS_ALLOWED_ACE of at least that
                // size (checked above); its SID starts at `SidStart`, inside
                // the same entry, and lives as long as `descriptor`.
                let (mask, sid) = unsafe {
                    (
                        std::ptr::read_unaligned(std::ptr::addr_of!((*allowed).Mask)),
                        PSID(std::ptr::addr_of_mut!((*allowed).SidStart).cast()),
                    )
                };
                (mask, sid_string(sid)?)
            } else {
                (0, String::new())
            };
            entries.push(Ace {
                kind,
                inherit_only,
                mask,
                sid,
            });
        }
        Ok((owner, Some(entries)))
    }

    /// The string SID of the user this process runs as.
    pub(crate) fn current_user_sid() -> Result<String, String> {
        let mut token = HANDLE::default();
        // SAFETY: GetCurrentProcess returns a pseudo handle that needs no
        // closing; `token` is a valid out pointer.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .map_err(|error| format!("OpenProcessToken: {error}"))?;
        struct Token(HANDLE);
        impl Drop for Token {
            fn drop(&mut self) {
                // SAFETY: the handle came from OpenProcessToken and is closed
                // exactly once.
                let _ = unsafe { CloseHandle(self.0) };
            }
        }
        let token = Token(token);
        let mut needed = 0_u32;
        // SAFETY: a size query with no buffer; it fails with
        // ERROR_INSUFFICIENT_BUFFER and writes the size into `needed`.
        let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut needed) };
        if (needed as usize) < std::mem::size_of::<TOKEN_USER>() {
            return Err("the process token has no user".into());
        }
        // u64 elements keep the TOKEN_USER (pointer-aligned) aligned.
        let mut buffer = vec![0_u64; (needed as usize).div_ceil(8)];
        // SAFETY: `buffer` holds at least `needed` writable bytes.
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                needed,
                &mut needed,
            )
        }
        .map_err(|error| format!("GetTokenInformation: {error}"))?;
        // SAFETY: on success the buffer starts with a TOKEN_USER whose SID
        // points into the same buffer, which outlives `sid_string`.
        let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        sid_string(sid)
    }

    /// Creates one directory whose protected DACL admits only `user`,
    /// `SYSTEM` and Administrators (the `mkdir -m 0700` counterpart).
    pub(crate) fn create_private_dir(path: &Path, user: &str) -> std::io::Result<()> {
        let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `sddl` is NUL-terminated and outlives the call; the
        // descriptor is LocalAlloc'd and freed by `_descriptor`.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }?;
        let _descriptor = Local(descriptor.0);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        let name = wide(path);
        // SAFETY: `name` is NUL-terminated; `attributes` and the descriptor it
        // points at stay alive for the call.
        unsafe { CreateDirectoryW(PCWSTR(name.as_ptr()), Some(&attributes)) }.map_err(|error| {
            // The windows crate's conversion loses the kind of this error;
            // callers tell "already there" from a failure by `ErrorKind`.
            if error.code() == ERROR_ALREADY_EXISTS.to_hresult() {
                std::io::Error::from_raw_os_error(ERROR_ALREADY_EXISTS.0 as i32)
            } else {
                error.into()
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "S-1-5-21-1-2-3-1001";
    const OTHER: &str = "S-1-5-21-1-2-3-1004";
    const EVERYONE: &str = "S-1-1-0";
    const MODIFY: u32 = 0x0013_01bf;
    const READ_EXECUTE: u32 = 0x0012_00a9;
    const ADD_SUBDIRECTORY: u32 = FILE_APPEND_DATA;

    fn allow(sid: &str, mask: u32) -> Ace {
        Ace {
            kind: AceKind::Allow,
            inherit_only: false,
            mask,
            sid: sid.into(),
        }
    }

    fn private() -> Vec<Ace> {
        vec![
            allow(LOCAL_SYSTEM, 0x001f_01ff),
            allow(ADMINISTRATORS, 0x001f_01ff),
            allow(USER, 0x001f_01ff),
        ]
    }

    #[test]
    fn a_private_dacl_passes_every_role() {
        for role in [Role::PrivateDir, Role::Ancestor, Role::File] {
            assert_eq!(judge(USER, Some(&private()), USER, role), Ok(()));
            assert_eq!(judge(ADMINISTRATORS, Some(&private()), USER, role), Ok(()));
            assert_eq!(
                judge(TRUSTED_INSTALLER, Some(&private()), USER, role),
                Ok(())
            );
        }
    }

    #[test]
    fn a_foreign_owner_or_a_null_dacl_is_refused() {
        for role in [Role::PrivateDir, Role::Ancestor, Role::File] {
            assert!(judge(OTHER, Some(&private()), USER, role).is_err());
            assert!(judge(USER, None, USER, role).is_err());
        }
    }

    #[test]
    fn a_private_dir_refuses_any_access_by_others() {
        let mut dacl = private();
        dacl.push(allow(EVERYONE, READ_EXECUTE));
        assert!(judge(USER, Some(&dacl), USER, Role::PrivateDir).is_err());
        // Reading is not a write: an ancestor or executable may be readable.
        assert_eq!(judge(USER, Some(&dacl), USER, Role::Ancestor), Ok(()));
        assert_eq!(judge(USER, Some(&dacl), USER, Role::File), Ok(()));
        let mut dacl = private();
        dacl.push(allow(EVERYONE, SYNCHRONIZE));
        assert_eq!(judge(USER, Some(&dacl), USER, Role::PrivateDir), Ok(()));
    }

    /// The case on the machine that found it: another local account holds
    /// Modify on `%LOCALAPPDATA%`.
    #[test]
    fn modify_for_another_account_is_refused_everywhere() {
        let mut dacl = private();
        dacl.push(allow(OTHER, MODIFY));
        for role in [Role::PrivateDir, Role::Ancestor, Role::File] {
            assert!(judge(USER, Some(&dacl), USER, role).is_err(), "{role:?}");
        }
    }

    /// `C:\` lets Authenticated Users create folders: like a sticky `/tmp`,
    /// that is fine above Orcel's directories but not on them.
    #[test]
    fn add_only_rights_are_allowed_on_an_ancestor_only() {
        let mut dacl = private();
        dacl.push(allow("S-1-5-11", ADD_SUBDIRECTORY));
        assert_eq!(
            judge(TRUSTED_INSTALLER, Some(&dacl), USER, Role::Ancestor),
            Ok(())
        );
        assert!(judge(USER, Some(&dacl), USER, Role::File).is_err());
        assert!(judge(USER, Some(&dacl), USER, Role::PrivateDir).is_err());
        for right in [
            DELETE,
            FILE_DELETE_CHILD,
            WRITE_DAC,
            WRITE_OWNER,
            GENERIC_ALL,
        ] {
            let mut dacl = private();
            dacl.push(allow(EVERYONE, right));
            assert!(
                judge(USER, Some(&dacl), USER, Role::Ancestor).is_err(),
                "{right:#x}"
            );
        }
    }

    #[test]
    fn every_write_right_on_a_file_is_refused() {
        for right in [
            FILE_WRITE_DATA,
            FILE_APPEND_DATA,
            FILE_WRITE_EA,
            FILE_WRITE_ATTRIBUTES,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
            GENERIC_ALL,
            GENERIC_WRITE,
        ] {
            let mut dacl = private();
            dacl.push(allow(EVERYONE, right));
            assert!(
                judge(USER, Some(&dacl), USER, Role::File).is_err(),
                "{right:#x}"
            );
        }
    }

    #[test]
    fn deny_and_inherit_only_entries_do_not_grant() {
        let mut dacl = private();
        dacl.push(Ace {
            kind: AceKind::Deny,
            inherit_only: false,
            mask: MODIFY,
            sid: String::new(),
        });
        dacl.push(Ace {
            kind: AceKind::Allow,
            inherit_only: true,
            mask: GENERIC_ALL,
            sid: "S-1-3-0".into(),
        });
        for role in [Role::PrivateDir, Role::Ancestor, Role::File] {
            assert_eq!(judge(USER, Some(&dacl), USER, role), Ok(()), "{role:?}");
        }
    }

    #[test]
    fn an_entry_type_that_cannot_be_judged_is_refused() {
        let mut dacl = private();
        dacl.push(Ace {
            kind: AceKind::Other(0x9),
            inherit_only: false,
            mask: 0,
            sid: String::new(),
        });
        assert!(judge(USER, Some(&dacl), USER, Role::Ancestor).is_err());
    }
}
