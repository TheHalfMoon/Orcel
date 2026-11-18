//! SG-000132 install hardening: the operating-system pieces of
//! `orcel-authority install|uninstall` (see `install.rs`). Native only: no
//! PowerShell, no .NET, no helper programs, no environment variables for
//! folders, no DLL loaded from anywhere but System32 after start.

use super::acl::{self, ADMINISTRATORS_SID, SYSTEM_SID, TRUSTED_INSTALLER_SID};
use super::{from_wide_ptr, wide};
use std::ffi::c_void;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, ACL, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, GetFileInformationByHandle, GetFinalPathNameByHandleW,
    BY_HANDLE_FILE_INFORMATION, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
};

/// `OWNER RIGHTS`: an ACE for it applies to the owner, which must be privileged anyway.
const OWNER_RIGHTS_SID: &str = "S-1-3-4";
/// The SIDs that may own and change what an elevated step consumes.
pub const PRIVILEGED: [&str; 3] = [SYSTEM_SID, ADMINISTRATORS_SID, TRUSTED_INSTALLER_SID];

/// On a parent folder: delete or rename an entry, delete or rename the
/// folder, change its permissions or owner (creating NEW entries in a parent
/// cannot change an existing path; `C:\` lets Authenticated Users create
/// folders).
pub const ENTRY_CHANGE_RIGHTS: u32 = 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE
/// On the consumed file or folder itself: every right that changes it or what it holds.
pub const CONTENT_CHANGE_RIGHTS: u32 = ENTRY_CHANGE_RIGHTS
    | 0x0000_0002 // FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x0000_0004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x0000_0010 // FILE_WRITE_EA
    | 0x0000_0100; // FILE_WRITE_ATTRIBUTES
/// Registry rights that change a key: KEY_SET_VALUE, KEY_CREATE_SUB_KEY,
/// KEY_CREATE_LINK, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE.
pub const KEY_CHANGE_RIGHTS: u32 = 0x0000_0002
    | 0x0000_0004
    | 0x0000_0020
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x1000_0000
    | 0x4000_0000;

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

fn is_privileged(sid: &str) -> bool {
    PRIVILEGED.iter().any(|ok| ok.eq_ignore_ascii_case(sid))
}

/// The problems that let someone other than SYSTEM, Administrators or
/// TrustedInstaller change one object: its owner, and every effective allow
/// ACE granting any of `forbidden` to another SID.
pub fn rights_problems(
    path: &str,
    owner: &str,
    effective_aces: &[(String, u32)],
    forbidden: u32,
) -> Vec<String> {
    let mut out = Vec::new();
    if !is_privileged(owner) {
        out.push(format!(
            "{path} is owned by {owner}, not SYSTEM, Administrators or TrustedInstaller (an owner can always change the permissions)"
        ));
    }
    for (sid, mask) in effective_aces {
        if is_privileged(sid) || sid.eq_ignore_ascii_case(OWNER_RIGHTS_SID) {
            continue;
        }
        if mask & forbidden != 0 {
            out.push(format!(
                "{path} lets {sid} change it (access mask 0x{mask:08x})"
            ));
        }
    }
    out
}

fn is_reparse_point(path: &Path) -> Result<bool, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("read the attributes of {}: {error}", path.display()))?;
    Ok(metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

/// One object: not a reparse point, privileged owner, no forbidden right
/// for anyone else (ACE types the check cannot judge are refused).
pub fn object_problems(path: &Path, forbidden: u32) -> Vec<String> {
    let mut out = Vec::new();
    match is_reparse_point(path) {
        Ok(true) => out.push(format!(
            "{} is a reparse point (junction, symbolic link or mount point)",
            path.display()
        )),
        Ok(false) => {}
        Err(error) => return vec![error],
    }
    match acl::read_security(path, true) {
        Ok((owner, _, aces)) => out.extend(rights_problems(
            &path.display().to_string(),
            &owner,
            &aces,
            forbidden,
        )),
        Err(error) => out.push(format!("{}: {}", path.display(), error.message)),
    }
    out
}

/// `path` (a consumed file or folder, checked with every content right) and
/// each parent up to the volume root (checked with the entry rights).
pub fn location_problems(path: &Path) -> Vec<String> {
    let text = path.to_string_lossy();
    let bytes = text.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || &bytes[1..3] != b":\\" {
        return vec![format!(
            "{text} is not an absolute path on a local drive letter"
        )];
    }
    if text.contains("\\..\\") || text.ends_with("\\..") {
        return vec![format!("{text} has a parent reference")];
    }
    let mut out = object_problems(path, CONTENT_CHANGE_RIGHTS);
    let mut current = path.parent();
    while let Some(parent) = current {
        out.extend(object_problems(parent, ENTRY_CHANGE_RIGHTS));
        current = parent.parent();
    }
    out
}

/// A known folder (for example Program Files), resolved by the shell from
/// the machine's settings, never from this process's environment. shell32
/// and ole32 are loaded from System32 only.
pub fn known_folder(id: &windows_sys::core::GUID) -> Result<PathBuf, String> {
    type GetPath = unsafe extern "system" fn(
        *const windows_sys::core::GUID,
        u32,
        HANDLE,
        *mut *mut u16,
    ) -> i32;
    type Free = unsafe extern "system" fn(*const c_void);
    let get: GetPath = system_proc("shell32.dll", "SHGetKnownFolderPath")?;
    let free: Free = system_proc("ole32.dll", "CoTaskMemFree")?;
    let mut raw: *mut u16 = std::ptr::null_mut();
    // SAFETY: `raw` receives a CoTaskMem string freed below; a null token is the current user.
    let hr = unsafe { get(id, 0, 0, &mut raw) };
    if hr < 0 || raw.is_null() {
        return Err(format!("SHGetKnownFolderPath failed (0x{hr:08x})"));
    }
    // SAFETY: a NUL-terminated string from the shell.
    let path = unsafe { from_wide_ptr(raw) };
    // SAFETY: allocated by SHGetKnownFolderPath; freed once.
    unsafe { free(raw.cast()) };
    Ok(PathBuf::from(path))
}

/// `GetSystemWindowsDirectoryW` (for example `C:\Windows`).
pub fn windows_directory() -> Result<PathBuf, String> {
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    let mut buffer = vec![0u16; 520];
    // SAFETY: the buffer is as long as its length argument.
    let len = unsafe { GetSystemWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if len == 0 || len as usize >= buffer.len() {
        return Err(format!(
            "GetSystemWindowsDirectoryW: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(PathBuf::from(String::from_utf16_lossy(
        &buffer[..len as usize],
    )))
}

/// A function from a DLL in System32 (never the application folder or the
/// current directory).
fn system_proc<T: Copy>(dll: &str, name: &str) -> Result<T, String> {
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };
    assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<usize>());
    let wide_dll = wide(dll);
    // SAFETY: `wide_dll` is NUL-terminated; the module stays loaded for the process.
    let module = unsafe { LoadLibraryExW(wide_dll.as_ptr(), 0, LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if module == 0 {
        return Err(format!(
            "load {dll} from System32: {}",
            std::io::Error::last_os_error()
        ));
    }
    let cname = std::ffi::CString::new(name).map_err(|error| error.to_string())?;
    // SAFETY: `module` is loaded; `cname` is NUL-terminated.
    let proc = unsafe { GetProcAddress(module, cname.as_ptr().cast()) }
        .ok_or_else(|| format!("{dll} has no {name}"))?;
    // SAFETY: the caller names the exact signature of `name`; both are pointer sized.
    Ok(unsafe { std::mem::transmute_copy::<_, T>(&proc) })
}

/// From here on, DLLs load only from System32, and the current directory is
/// not searched. (DLLs this program imports were loaded before `main` from
/// its own folder, which the install refuses unless it is admin-only and
/// holds nothing but the three staged binaries.)
pub fn harden_dll_search() -> Result<(), String> {
    use windows_sys::Win32::System::LibraryLoader::{
        SetDefaultDllDirectories, SetDllDirectoryW, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };
    let empty = [0u16];
    // SAFETY: plain flag and an empty NUL-terminated string.
    let ok = unsafe {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) != 0
            && SetDllDirectoryW(empty.as_ptr()) != 0
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "restrict the DLL search to System32: {}",
            std::io::Error::last_os_error()
        ))
    }
}

/// Whether this process's token is elevated.
pub fn process_is_elevated() -> bool {
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    // SAFETY: the pseudo handle needs no closing.
    match super::identity::open_process_token(unsafe { GetCurrentProcess() }) {
        Ok(token) => super::identity::token_elevated(&token),
        Err(_) => false,
    }
}

/// The final, normalized DOS path of an open file (`\\?\` removed).
pub fn final_path(file: &std::fs::File) -> Result<PathBuf, String> {
    let mut buffer = vec![0u16; 1024];
    // SAFETY: the buffer is as long as its length argument.
    let len = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle() as HANDLE,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if len == 0 || len as usize >= buffer.len() {
        return Err(format!(
            "GetFinalPathNameByHandleW: {}",
            std::io::Error::last_os_error()
        ));
    }
    let text = String::from_utf16_lossy(&buffer[..len as usize]);
    Ok(PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text)))
}

/// The number of hard links to an open file.
pub fn link_count(file: &std::fs::File) -> Result<u32, String> {
    // SAFETY: zeroed plain data, filled by the call.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: a live handle and a valid out pointer.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return Err(format!(
            "GetFileInformationByHandle: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(info.nNumberOfLinks)
}

/// Opens `path` for reading with read sharing only: while the handle is
/// open no process can write, delete or rename the file. A reparse point is
/// opened as itself, never followed.
pub fn open_held(path: &Path) -> Result<std::fs::File, String> {
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            format!(
                "open {} without write or delete sharing: {error}",
                path.display()
            )
        })
}

/// SHA-256 (hex) of everything readable from `file`, from its start.
pub fn sha256_of(file: &mut std::fs::File) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(crate::hex(&hasher.finalize()))
}

/// A parsed security descriptor (freed on drop).
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { LocalFree(self.0) };
    }
}

fn descriptor(sddl: &str) -> Result<Descriptor, String> {
    let wide_sddl = wide(sddl);
    let mut raw: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: NUL-terminated input; `raw` is freed by Descriptor.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut raw,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(format!(
            "the security descriptor {sddl}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(Descriptor(raw))
}

/// Creates `path` with its owner and protected DACL in the same call (it
/// never exists with other access), then reads them back: owner
/// Administrators, protected, and exactly `expected` (SID, mask) allow ACEs.
/// An existing path is an error (nothing is taken over).
pub fn create_protected_dir(
    path: &Path,
    sddl: &str,
    expected: &[(&str, u32)],
) -> Result<(), String> {
    let security = descriptor(sddl)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.0,
        bInheritHandle: 0,
    };
    let wide_path = wide(&path.to_string_lossy());
    // SAFETY: NUL-terminated path; the descriptor outlives the call.
    if unsafe { CreateDirectoryW(wide_path.as_ptr(), &attributes) } == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(format!("{} already exists", path.display()));
        }
        return Err(format!("create {}: {error}", path.display()));
    }
    let (owner, protected, aces) =
        acl::read_security(path, false).map_err(|error| error.message)?;
    let mut have: Vec<(String, u32)> = aces
        .into_iter()
        .map(|(sid, mask)| (sid.to_uppercase(), mask))
        .collect();
    have.sort();
    let mut want: Vec<(String, u32)> = expected
        .iter()
        .map(|(sid, mask)| (sid.to_uppercase(), *mask))
        .collect();
    want.sort();
    if owner != ADMINISTRATORS_SID || !protected || have != want {
        return Err(format!(
            "the security of {} is not what was asked for (owner {owner}, protected {protected}, wanted {want:?}, found {have:?})",
            path.display()
        ));
    }
    println!(
        "Created {} (owner Administrators, protected): {have:?}",
        path.display()
    );
    Ok(())
}

/// Copies from the held, already hashed `source` into a new file (never one
/// that exists), then hashes the copy through its own handle.
pub fn copy_held(
    source: &mut std::fs::File,
    destination: &Path,
    expected: &str,
) -> Result<(), String> {
    use std::io::{Seek, SeekFrom};
    source
        .seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let mut out = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(destination)
        .map_err(|error| format!("create {}: {error}", destination.display()))?;
    std::io::copy(source, &mut out).map_err(|error| error.to_string())?;
    out.sync_all().map_err(|error| error.to_string())?;
    let actual = sha256_of(&mut out)?;
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(format!(
            "SHA-256 mismatch for the copy {}: expected {expected}, found {actual}",
            destination.display()
        ));
    }
    Ok(())
}

/// Deletes a folder tree. The whole tree is scanned first and any reparse
/// point refuses the delete before anything is deleted: a junction is never
/// followed out of the tree.
pub fn remove_tree(path: &Path) -> Result<(), String> {
    refuse_reparse_in_tree(path)?;
    delete_tree(path)
}

fn refuse_reparse_in_tree(path: &Path) -> Result<(), String> {
    if is_reparse_point(path)? {
        return Err(format!(
            "{} is a reparse point; refusing to delete through it",
            path.display()
        ));
    }
    if !std::fs::symlink_metadata(path)
        .map_err(|error| error.to_string())?
        .is_dir()
    {
        return Ok(());
    }
    let entries =
        std::fs::read_dir(path).map_err(|error| format!("list {}: {error}", path.display()))?;
    for entry in entries {
        refuse_reparse_in_tree(&entry.map_err(|error| error.to_string())?.path())?;
    }
    Ok(())
}

fn delete_tree(path: &Path) -> Result<(), String> {
    if is_reparse_point(path)? {
        return Err(format!(
            "{} is a reparse point; refusing to delete through it",
            path.display()
        ));
    }
    let entries =
        std::fs::read_dir(path).map_err(|error| format!("list {}: {error}", path.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let child = entry.path();
        if is_reparse_point(&child)? {
            return Err(format!(
                "{} is a reparse point; refusing to delete through it",
                child.display()
            ));
        }
        if std::fs::symlink_metadata(&child)
            .map_err(|error| error.to_string())?
            .is_dir()
        {
            delete_tree(&child)?;
        } else {
            std::fs::remove_file(&child)
                .map_err(|error| format!("delete {}: {error}", child.display()))?;
        }
    }
    std::fs::remove_dir(path).map_err(|error| format!("delete {}: {error}", path.display()))
}

// ---- Registry -------------------------------------------------------------------------------------------------

use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegGetKeySecurity, RegOpenKeyExW,
    RegQueryValueExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ,
    KEY_WOW64_64KEY, REG_CREATED_NEW_KEY, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE,
    REG_SZ,
};

/// An open registry key (closed on drop).
pub struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: opened by this module; closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

/// Opens `HKLM\<path>` for reading (64-bit view); `None` if it does not exist.
pub fn open_key(path: &str) -> Option<Key> {
    let wide_path = wide(path);
    let mut key: HKEY = 0;
    // SAFETY: NUL-terminated path; `key` is closed by Key.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide_path.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    (status == ERROR_SUCCESS).then_some(Key(key))
}

/// Creates `HKLM\<path>` only if it does not exist (atomically): `Ok(None)`
/// when it already existed (it is then left as it is).
pub fn create_new_key(path: &str) -> Result<Option<Key>, String> {
    let wide_path = wide(path);
    let mut key: HKEY = 0;
    let mut disposition = 0u32;
    // SAFETY: NUL-terminated path; default security (inherited from the parent key).
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            wide_path.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS | KEY_WOW64_64KEY,
            std::ptr::null(),
            &mut key,
            &mut disposition,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!("create HKLM\\{path}: Win32 error {status}"));
    }
    let key = Key(key);
    Ok((disposition == REG_CREATED_NEW_KEY).then_some(key))
}

fn set_value(key: &Key, name: &str, kind: u32, data: &[u8]) -> Result<(), String> {
    let wide_name = wide(name);
    // SAFETY: `data` is valid for its length.
    let status = unsafe {
        RegSetValueExW(
            key.0,
            wide_name.as_ptr(),
            0,
            kind,
            data.as_ptr(),
            data.len() as u32,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!(
            "set the registry value {name}: Win32 error {status}"
        ))
    }
}

fn utf16_bytes(text: &str) -> Vec<u8> {
    wide(text)
        .iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
}

/// A REG_SZ value.
pub fn set_string(key: &Key, name: &str, value: &str) -> Result<(), String> {
    set_value(key, name, REG_SZ, &utf16_bytes(value))
}

/// A REG_EXPAND_SZ value (written as an absolute path, nothing to expand).
pub fn set_expand_string(key: &Key, name: &str, value: &str) -> Result<(), String> {
    set_value(key, name, REG_EXPAND_SZ, &utf16_bytes(value))
}

/// A REG_DWORD value.
pub fn set_dword(key: &Key, name: &str, value: u32) -> Result<(), String> {
    set_value(key, name, REG_DWORD, &value.to_le_bytes())
}

/// A REG_SZ value, if present.
pub fn query_string(key: &Key, name: &str) -> Option<String> {
    let wide_name = wide(name);
    let mut buffer = vec![0u16; 512];
    let mut size = (buffer.len() * 2) as u32;
    let mut kind = 0u32;
    // SAFETY: the buffer holds `size` bytes.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            wide_name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status != ERROR_SUCCESS || kind != REG_SZ {
        return None;
    }
    let units = (size as usize / 2).min(buffer.len());
    Some(
        String::from_utf16_lossy(&buffer[..units])
            .trim_end_matches('\0')
            .to_owned(),
    )
}

/// Owner and effective allow ACEs of a key.
pub fn key_security(key: &Key, label: &str) -> Result<(String, Vec<(String, u32)>), String> {
    let mut size = 0u32;
    // SAFETY: the first call asks for the size.
    unsafe {
        RegGetKeySecurity(
            key.0,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if size == 0 {
        return Err(format!("read the security of {label}"));
    }
    let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
    // SAFETY: the buffer holds `size` bytes and is aligned.
    let status = unsafe {
        RegGetKeySecurity(
            key.0,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "read the security of {label}: Win32 error {status}"
        ));
    }
    let descriptor: PSECURITY_DESCRIPTOR = buffer.as_mut_ptr().cast();
    let mut owner: *mut c_void = std::ptr::null_mut();
    let mut defaulted = 0i32;
    let mut present = 0i32;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: a self-relative descriptor in `buffer`; the pointers point into it.
    unsafe {
        if GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) == 0
            || owner.is_null()
        {
            return Err(format!("{label} has no owner"));
        }
        if GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) == 0 {
            return Err(format!("read the DACL of {label}"));
        }
        let owner = super::sid_to_string(owner).map_err(|error| error.message)?;
        if present == 0 {
            return Err(format!("{label} has no DACL, so everyone has full access"));
        }
        let aces = acl::effective_allow_aces(dacl).map_err(|error| error.message)?;
        Ok((owner, aces))
    }
}

/// Deletes `HKLM\<path>` and everything under it.
pub fn delete_key_tree(path: &str) -> Result<(), String> {
    let wide_path = wide(path);
    // SAFETY: NUL-terminated path.
    let status = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, wide_path.as_ptr()) };
    if status != ERROR_SUCCESS {
        return Err(format!("delete HKLM\\{path}: Win32 error {status}"));
    }
    // RegDeleteTreeW leaves the key itself.
    let wide_parent_path = wide(path);
    // SAFETY: NUL-terminated path.
    let status = unsafe {
        windows_sys::Win32::System::Registry::RegDeleteKeyExW(
            HKEY_LOCAL_MACHINE,
            wide_parent_path.as_ptr(),
            KEY_WOW64_64KEY,
            0,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!("delete HKLM\\{path}: Win32 error {status}"))
    }
}

// ---- Profiles -------------------------------------------------------------------------------------------------

/// Whether Windows has a user profile for `sid`.
pub fn profile_exists(sid: &str) -> bool {
    open_key(&format!(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"
    ))
    .is_some()
}

/// `DeleteProfileW` (userenv.dll from System32).
pub fn delete_profile(sid: &str) -> Result<(), String> {
    type Delete = unsafe extern "system" fn(*const u16, *const u16, *const u16) -> i32;
    let delete: Delete = system_proc("userenv.dll", "DeleteProfileW")?;
    let wide_sid = wide(sid);
    // SAFETY: NUL-terminated SID string; null path and computer mean this machine's profile.
    if unsafe { delete(wide_sid.as_ptr(), std::ptr::null(), std::ptr::null()) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

// ---- Service Control Manager ----------------------------------------------------------------------------------

use windows_sys::Win32::Security::SC_HANDLE;
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, StartServiceW, SC_ACTION,
    SC_ACTION_RESTART, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SC_STATUS_PROCESS_INFO,
    SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
    SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONW,
    SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONSW, SERVICE_REQUIRED_PRIVILEGES_INFOW,
    SERVICE_RUNNING, SERVICE_SID_INFO, SERVICE_SID_TYPE_UNRESTRICTED, SERVICE_STATUS,
    SERVICE_STATUS_PROCESS, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
};

/// A service or SCM handle (closed on drop).
pub struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: opened by this module; closed once.
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn scm(create: bool) -> Result<ScHandle, String> {
    let access = if create {
        SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE
    } else {
        SC_MANAGER_CONNECT
    };
    // SAFETY: local SCM, active database.
    let handle = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), access) };
    if handle == 0 {
        return Err(format!(
            "open the service control manager: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(ScHandle(handle))
}

/// The service, if it exists.
pub fn open_service(name: &str) -> Result<Option<ScHandle>, String> {
    let manager = scm(false)?;
    let wide_name = wide(name);
    // SAFETY: NUL-terminated name.
    let handle = unsafe { OpenServiceW(manager.0, wide_name.as_ptr(), SERVICE_ALL_ACCESS) };
    if handle == 0 {
        let error = std::io::Error::last_os_error();
        // ERROR_SERVICE_DOES_NOT_EXIST
        if error.raw_os_error() == Some(1060) {
            return Ok(None);
        }
        return Err(format!("open the service {name}: {error}"));
    }
    Ok(Some(ScHandle(handle)))
}

/// What the service is registered as.
pub struct ServiceSpec<'a> {
    pub name: &'a str,
    pub display_name: &'a str,
    pub description: &'a str,
    pub binary: &'a Path,
    pub account: &'a str,
    pub privileges: &'a [&'a str],
}

/// Registers the service: own process, automatic start, the virtual
/// account (no password), SID type unrestricted, only `privileges`, restart
/// twice on failure within a day.
pub fn create_service(spec: &ServiceSpec<'_>) -> Result<ScHandle, String> {
    let manager = scm(true)?;
    let name = wide(spec.name);
    let display = wide(spec.display_name);
    let binary = wide(&format!("\"{}\"", spec.binary.display()));
    let account = wide(spec.account);
    // SAFETY: every string is NUL-terminated; no dependencies, no password.
    let handle = unsafe {
        CreateServiceW(
            manager.0,
            name.as_ptr(),
            display.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            binary.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            account.as_ptr(),
            std::ptr::null(),
        )
    };
    if handle == 0 {
        return Err(format!(
            "create the service {}: {}",
            spec.name,
            std::io::Error::last_os_error()
        ));
    }
    let service = ScHandle(handle);
    let mut description = wide(spec.description);
    let info = SERVICE_DESCRIPTIONW {
        lpDescription: description.as_mut_ptr(),
    };
    change_config(&service, SERVICE_CONFIG_DESCRIPTION, &info, "description")?;
    let sid = SERVICE_SID_INFO {
        dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
    };
    change_config(&service, SERVICE_CONFIG_SERVICE_SID_INFO, &sid, "SID type")?;
    let mut multi: Vec<u16> = Vec::new();
    for privilege in spec.privileges {
        multi.extend(privilege.encode_utf16());
        multi.push(0);
    }
    multi.push(0);
    let privileges = SERVICE_REQUIRED_PRIVILEGES_INFOW {
        pmszRequiredPrivileges: multi.as_mut_ptr(),
    };
    change_config(
        &service,
        SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
        &privileges,
        "required privileges",
    )?;
    let mut actions = [
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5000,
        },
    ];
    let failure = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 86_400,
        lpRebootMsg: std::ptr::null_mut(),
        lpCommand: std::ptr::null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    change_config(
        &service,
        SERVICE_CONFIG_FAILURE_ACTIONS,
        &failure,
        "failure actions",
    )?;
    Ok(service)
}

fn change_config<T>(service: &ScHandle, level: u32, info: &T, what: &str) -> Result<(), String> {
    // SAFETY: `info` is the structure `level` names and lives through the call.
    if unsafe { ChangeServiceConfig2W(service.0, level, (info as *const T).cast()) } == 0 {
        return Err(format!(
            "set the service's {what}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// The service's current state (`SERVICE_RUNNING`, `SERVICE_STOPPED`, ...).
pub fn service_state(service: &ScHandle) -> Result<u32, String> {
    // SAFETY: zeroed plain data, filled by the call.
    let mut status: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut needed = 0u32;
    // SAFETY: the buffer is a SERVICE_STATUS_PROCESS of the stated size.
    if unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(format!(
            "query the service: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(status.dwCurrentState)
}

/// Starts the service and waits until it runs and `ready` holds, stably.
pub fn start_and_wait(
    service: &ScHandle,
    seconds: u64,
    ready: &dyn Fn() -> bool,
) -> Result<(), String> {
    // SAFETY: no arguments.
    if unsafe { StartServiceW(service.0, 0, std::ptr::null()) } == 0 {
        return Err(format!(
            "start the service: {}",
            std::io::Error::last_os_error()
        ));
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    while std::time::Instant::now() < deadline {
        let state = service_state(service)?;
        if state == SERVICE_STOPPED {
            return Err(
                "the service stopped during its start (read event 4103 in the Application log)"
                    .to_owned(),
            );
        }
        if state == SERVICE_RUNNING && ready() {
            std::thread::sleep(std::time::Duration::from_secs(2));
            if service_state(service)? == SERVICE_RUNNING {
                return Ok(());
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(format!(
        "the service did not reach Running with its public key published within {seconds} seconds"
    ))
}

/// Stops the service (if running) and waits until it has stopped.
pub fn stop_and_wait(service: &ScHandle, seconds: u64) -> Result<(), String> {
    if service_state(service)? != SERVICE_STOPPED {
        // SAFETY: zeroed plain data, filled by the call.
        let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        // SAFETY: a live service handle.
        unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) };
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    while std::time::Instant::now() < deadline {
        if service_state(service)? == SERVICE_STOPPED {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(format!(
        "the service did not stop within {seconds} seconds; nothing was deleted"
    ))
}

/// Marks the service for deletion and waits until the SCM has removed it.
pub fn delete_and_wait(service: ScHandle, name: &str, seconds: u64) -> Result<(), String> {
    // SAFETY: a live service handle.
    if unsafe { DeleteService(service.0) } == 0 {
        return Err(format!(
            "delete the service: {}",
            std::io::Error::last_os_error()
        ));
    }
    drop(service);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    while std::time::Instant::now() < deadline {
        if open_service(name)?.is_none() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(format!(
        "the service {name} still exists after {seconds} seconds"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_are_judged_per_sid_and_owner() {
        let admin_only = [
            (SYSTEM_SID.to_owned(), 0x001f_01ff),
            (ADMINISTRATORS_SID.to_owned(), 0x001f_01ff),
            ("S-1-5-32-545".to_owned(), 0x0012_00a9),
            (OWNER_RIGHTS_SID.to_owned(), 0x001f_01ff),
        ];
        assert!(
            rights_problems("x", ADMINISTRATORS_SID, &admin_only, CONTENT_CHANGE_RIGHTS).is_empty()
        );
        // Authenticated Users with modify (what C:\ hands down to new folders).
        let modify = [("S-1-5-11".to_owned(), 0x0013_01bf)];
        assert_eq!(
            rights_problems("x", ADMINISTRATORS_SID, &modify, CONTENT_CHANGE_RIGHTS).len(),
            1
        );
        // Creating new entries in a parent is allowed there; deleting them is not.
        let add_only = [("S-1-5-11".to_owned(), 0x0000_0004)];
        assert!(
            rights_problems("x", ADMINISTRATORS_SID, &add_only, ENTRY_CHANGE_RIGHTS).is_empty()
        );
        assert_eq!(
            rights_problems("x", ADMINISTRATORS_SID, &add_only, CONTENT_CHANGE_RIGHTS).len(),
            1
        );
        let delete_child = [("S-1-1-0".to_owned(), 0x0000_0040)];
        assert_eq!(
            rights_problems("x", ADMINISTRATORS_SID, &delete_child, ENTRY_CHANGE_RIGHTS).len(),
            1
        );
        // A user owner is refused whatever the DACL says.
        assert_eq!(
            rights_problems(
                "x",
                "S-1-5-21-1-2-3-1001",
                &admin_only,
                CONTENT_CHANGE_RIGHTS
            )
            .len(),
            1
        );
        // Generic rights count.
        let generic = [("S-1-5-4".to_owned(), 0x4000_0000)];
        assert_eq!(
            rights_problems("x", SYSTEM_SID, &generic, ENTRY_CHANGE_RIGHTS).len(),
            1
        );
    }

    #[test]
    fn system32_is_an_admin_only_location_and_temp_is_not() {
        let windows = windows_directory().expect("windows dir");
        let cmd = windows.join("System32").join("cmd.exe");
        assert!(
            location_problems(&cmd).is_empty(),
            "{:?}",
            location_problems(&cmd)
        );
        let temp = std::env::temp_dir().join(format!("orcel-install-os-{}", std::process::id()));
        std::fs::create_dir_all(&temp).expect("temp");
        assert!(!location_problems(&temp).is_empty());
        let _ = std::fs::remove_dir_all(&temp);
        assert!(!location_problems(Path::new(r"\\server\share\x")).is_empty());
    }

    #[test]
    fn known_folders_come_from_the_shell() {
        use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, FOLDERID_ProgramFiles};
        let program_files = known_folder(&FOLDERID_ProgramFiles).expect("the program files folder");
        let program_data = known_folder(&FOLDERID_ProgramData).expect("the program data folder");
        assert!(program_files.is_dir() && program_data.is_dir());
        assert!(
            location_problems(&program_files).is_empty(),
            "{:?}",
            location_problems(&program_files)
        );
    }

    #[test]
    fn a_held_file_cannot_be_written_or_deleted_and_the_running_image_can_be_held() {
        let path = std::env::temp_dir().join(format!("orcel-held-{}.bin", std::process::id()));
        std::fs::write(&path, b"held bytes").expect("write");
        {
            let mut held = open_held(&path).expect("held");
            assert_eq!(link_count(&held).expect("links"), 1);
            assert_eq!(
                sha256_of(&mut held).expect("hash"),
                crate::sha256_hex(b"held bytes")
            );
            assert!(
                std::fs::OpenOptions::new().write(true).open(&path).is_err(),
                "no write while held"
            );
            assert!(std::fs::remove_file(&path).is_err(), "no delete while held");
        }
        std::fs::remove_file(&path).expect("deleted once released");
        // The installer holds its own running image the same way.
        let me = std::env::current_exe().expect("exe");
        let held = open_held(&me).expect("the running image can be held");
        let final_path = final_path(&held).expect("final path");
        assert!(
            final_path
                .to_string_lossy()
                .eq_ignore_ascii_case(&me.to_string_lossy()),
            "{final_path:?} vs {me:?}"
        );
    }
    #[test]
    fn remove_tree_refuses_a_junction_and_deletes_nothing_behind_it() {
        let root = std::env::temp_dir().join(format!("orcel-remove-tree-{}", std::process::id()));
        let outside = root.join("outside");
        let tree = root.join("tree");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::create_dir_all(tree.join("sub")).expect("tree");
        std::fs::write(outside.join("keep.txt"), b"keep").expect("keep");
        std::fs::write(tree.join("sub").join("gone.txt"), b"x").expect("gone");
        let made = std::process::Command::new(
            windows_directory()
                .expect("windows")
                .join(r"System32\cmd.exe"),
        )
        .args(["/d", "/c", "mklink", "/J"])
        .arg(tree.join("link"))
        .arg(&outside)
        .output()
        .expect("mklink");
        assert!(made.status.success());
        assert!(remove_tree(&tree).unwrap_err().contains("reparse point"));
        assert!(
            outside.join("keep.txt").exists(),
            "nothing behind the junction is deleted"
        );
        std::fs::remove_dir(tree.join("link")).expect("unlink");
        remove_tree(&tree).expect("a plain tree is deleted");
        assert!(!tree.exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
