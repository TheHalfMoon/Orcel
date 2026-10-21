//! macOS extended ACLs (#384 item 1). The mode bits do not show an entry
//! added with `chmod +a`, so the owner and mode checks in `paths` also refuse
//! an `allow` entry that grants what the mode check guards against.
//!
//! On Linux a POSIX ACL entry for a named user or group raises the group
//! class bits (the ACL mask) in the mode, so the mode check already sees it.
//! Deny entries only take access away and are ignored.

use std::ffi::{c_char, c_int, c_void, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

type Acl = *mut c_void;
type AclEntry = *mut c_void;
type AclPermset = *mut c_void;

/// `ACL_TYPE_EXTENDED` from `<sys/acl.h>`.
const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
const ACL_FIRST_ENTRY: c_int = 0;
const ACL_NEXT_ENTRY: c_int = -1;
/// `ACL_EXTENDED_ALLOW` (an `acl_tag_t`).
const ACL_EXTENDED_ALLOW: c_int = 1;

/// The `acl_perm_t` values (`__DARWIN_ACL_*`) that change an object or the
/// entries below it.
const WRITE_PERMS: [(c_int, &str); 8] = [
    (1 << 2, "write_data/add_file"),
    (1 << 4, "delete"),
    (1 << 5, "append_data/add_subdirectory"),
    (1 << 6, "delete_child"),
    (1 << 8, "write_attributes"),
    (1 << 10, "write_extattributes"),
    (1 << 12, "write_security"),
    (1 << 13, "change_owner"),
];

extern "C" {
    fn acl_get_file(path: *const c_char, kind: c_int) -> Acl;
    fn acl_get_link_np(path: *const c_char, kind: c_int) -> Acl;
    fn acl_get_entry(acl: Acl, entry_id: c_int, entry: *mut AclEntry) -> c_int;
    fn acl_get_tag_type(entry: AclEntry, tag: *mut c_int) -> c_int;
    fn acl_get_permset(entry: AclEntry, permset: *mut AclPermset) -> c_int;
    fn acl_get_perm_np(permset: AclPermset, perm: c_int) -> c_int;
    fn acl_free(object: *mut c_void) -> c_int;
}

/// What an `allow` entry may grant before the object is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refuse {
    /// Any allow entry (a private directory, the `0700` counterpart).
    AnyAllow,
    /// An allow entry with a right in [`WRITE_PERMS`].
    Write,
}

/// `Err` naming the grant when `path` has an extended ACL entry that
/// `refuse` forbids. `follow` reads the target of a final symlink instead of
/// the link itself. A file system that stores no ACLs has none to grant.
pub(crate) fn check(path: &Path, follow: bool, refuse: Refuse) -> Result<(), String> {
    let name = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("{} contains NUL", path.display()))?;
    // SAFETY: `name` is NUL-terminated and outlives the call; the result is
    // an ACL owned by this function and freed by `Owned`.
    let acl = unsafe {
        if follow {
            acl_get_file(name.as_ptr(), ACL_TYPE_EXTENDED)
        } else {
            acl_get_link_np(name.as_ptr(), ACL_TYPE_EXTENDED)
        }
    };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            // No extended ACL, or a file system that cannot hold one.
            Some(libc::ENOENT) | Some(libc::ENOTSUP) | Some(libc::EOPNOTSUPP) => Ok(()),
            _ => Err(format!(
                "the ACL of {} cannot be read: {error}",
                path.display()
            )),
        };
    }
    struct Owned(Acl);
    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: the ACL came from acl_get_file/acl_get_link_np and is
            // freed exactly once.
            unsafe {
                acl_free(self.0);
            }
        }
    }
    let acl = Owned(acl);
    let mut entry_id = ACL_FIRST_ENTRY;
    loop {
        let mut entry: AclEntry = std::ptr::null_mut();
        // SAFETY: `acl.0` is a valid ACL and `entry` a valid out pointer; the
        // entry stays owned by the ACL.
        if unsafe { acl_get_entry(acl.0, entry_id, &mut entry) } != 0 {
            // -1 with EINVAL past the last entry.
            return Ok(());
        }
        entry_id = ACL_NEXT_ENTRY;
        let mut tag: c_int = 0;
        // SAFETY: `entry` came from acl_get_entry on a live ACL.
        if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
            return Err(format!("an ACL entry of {} is unreadable", path.display()));
        }
        if tag != ACL_EXTENDED_ALLOW {
            continue;
        }
        if refuse == Refuse::AnyAllow {
            return Err(format!(
                "{} has an ACL entry that grants access",
                path.display()
            ));
        }
        let mut permset: AclPermset = std::ptr::null_mut();
        // SAFETY: as above; the permset is owned by the entry.
        if unsafe { acl_get_permset(entry, &mut permset) } != 0 {
            return Err(format!("an ACL entry of {} is unreadable", path.display()));
        }
        for (perm, name) in WRITE_PERMS {
            // SAFETY: `permset` came from acl_get_permset on a live entry.
            match unsafe { acl_get_perm_np(permset, perm) } {
                0 => {}
                1 => {
                    return Err(format!(
                        "{} has an ACL entry that grants {name}",
                        path.display()
                    ))
                }
                _ => return Err(format!("an ACL entry of {} is unreadable", path.display())),
            }
        }
    }
}
