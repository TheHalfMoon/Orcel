//! The code signature of an executable image file, for display on approval prompts.
//!
//! Display only: nothing grants or refuses anything because of it. On Windows the file is
//! opened once and checked through that handle with `WinVerifyTrust` (Authenticode, then the
//! system catalogs, since many inbox binaries are catalog-signed only, hashing the same
//! handle), offline: no revocation check and no network retrieval. Other systems report
//! [`SignatureState::Unknown`].
//!
//! The signature describes a file on disk, not the code in memory. [`image_signature_for`]
//! also says whether the file it checked is the file a running process's image is mapped
//! from ([`RunningImage`]): a file renamed away and replaced after launch leaves another
//! file at the path. On Windows it opens the process (`PROCESS_QUERY_INFORMATION` and
//! `PROCESS_VM_READ`), confirms its creation time is the recorded start generation, takes the
//! first module `K32EnumProcessModules` lists (the executable), asks `K32GetMappedFileNameW`
//! for the current name of the file mapped at that base, opens that name, asks again and
//! requires the same name, then compares the volume serial number and file id
//! (`FILE_ID_INFO`) of that file and of the checked handle. Where any step fails (another
//! user's or an elevated process, which deny that access; an exited process; a reused pid;
//! a file system without file ids) the answer is [`RunningImage::Unconfirmed`], never a
//! match. The two name queries narrow, but cannot close, the window in which the image could
//! be renamed away and back while another file holds its name.

use std::path::Path;

/// The longest signer subject kept, in characters. A certificate subject is text the signer
/// chose, so prompts escape and cut it again to their own bound.
pub const MAX_SUBJECT_CHARS: usize = 256;

/// What a signature check of an image file found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureState {
    /// The file carries, or a system catalog holds, a signature that chains to a root this
    /// machine trusts. `subject` is the signing certificate's display name, cut to
    /// [`MAX_SUBJECT_CHARS`]; it may be empty when the certificate names nobody.
    Verified { subject: String },
    /// Neither the file nor any system catalog has a signature for it.
    Unsigned,
    /// A signature is present but does not verify or does not chain to a trusted root.
    Untrusted,
    /// Not checked: another system, an unreadable file, or a failed check.
    Unknown,
}

/// The signature state of the image file at `path`. Never fails: whatever cannot be checked
/// is [`SignatureState::Unknown`].
pub fn image_signature(path: &Path) -> SignatureState {
    #[cfg(windows)]
    {
        imp::image_signature(path).0
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        SignatureState::Unknown
    }
}

/// Whether the file a signature check read is the file a running process's image is mapped
/// from. Display only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunningImage {
    /// The checked file is the file the process's image is mapped from.
    Same,
    /// The checked file is another file than the one the process's image is mapped from.
    Different,
    /// Not established: another system, an unreadable file, a process that denies the
    /// access the comparison needs, an exited process or reused pid, or a failed query.
    Unconfirmed,
}

/// The signature of the file at a process's image path, and whether that file is the one the
/// process runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSignature {
    pub state: SignatureState,
    pub running_image: RunningImage,
}

impl ImageSignature {
    /// A state known without reading any file, whose file nothing compared with a process.
    pub fn unconfirmed(state: SignatureState) -> Self {
        Self {
            state,
            running_image: RunningImage::Unconfirmed,
        }
    }
}

/// The signature state of the image file at `path`, checked through one open handle, and
/// whether that same file is the image of the process `pid` whose start generation (on
/// Windows its creation time, as [`crate::process::start_generation`] reads it) is
/// `generation`. Never fails: what cannot be checked is [`SignatureState::Unknown`] and what
/// cannot be compared is [`RunningImage::Unconfirmed`].
pub fn image_signature_for(path: &Path, pid: u32, generation: u64) -> ImageSignature {
    #[cfg(windows)]
    {
        imp::image_signature_for(path, pid, generation)
    }
    #[cfg(not(windows))]
    {
        let _ = (path, pid, generation);
        ImageSignature::unconfirmed(SignatureState::Unknown)
    }
}

#[cfg(windows)]
mod imp {
    use super::{ImageSignature, RunningImage, SignatureState, MAX_SUBJECT_CHARS};
    use std::ffi::c_void;
    use std::fs::File;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use windows::core::{GUID, HRESULT, PCWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, BOOL, CRYPT_E_FILE_ERROR, FILETIME, HANDLE, HMODULE, HWND,
        TRUST_E_ACTION_UNKNOWN, TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN,
        TRUST_E_SUBJECT_FORM_UNKNOWN,
    };
    use windows::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
        CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
        CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
    };
    use windows::Win32::Security::Cryptography::{
        CertGetNameStringW, BCRYPT_SHA256_ALGORITHM, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    };
    use windows::Win32::Security::WinTrust::{
        WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0,
        WINTRUST_DATA_UNION_CHOICE, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
        WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };
    use windows::Win32::Storage::FileSystem::{
        FileIdInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
        BY_HANDLE_FILE_INFORMATION, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    use windows::Win32::System::ProcessStatus::{K32EnumProcessModules, K32GetMappedFileNameW};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    /// One `WinVerifyTrust` outcome: its status, and the signer's name when it succeeded.
    struct Outcome {
        status: HRESULT,
        subject: Option<String>,
    }

    /// Which check produced a result: the file's own signature, or a system catalog.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Checked {
        Embedded,
        Catalog,
    }

    pub(super) fn image_signature(path: &Path) -> (SignatureState, Checked) {
        let Ok(file) = File::open(path) else {
            return (SignatureState::Unknown, Checked::Embedded);
        };
        signature_of_open(&file, path)
    }

    pub(super) fn image_signature_for(path: &Path, pid: u32, generation: u64) -> ImageSignature {
        let Ok(file) = File::open(path) else {
            return ImageSignature::unconfirmed(SignatureState::Unknown);
        };
        // One open file: the signature is checked, and the identity read, through this handle.
        let (state, _) = signature_of_open(&file, path);
        let running_image = match (file_id(&file), image_file_id(pid, generation)) {
            (Some(checked), Some(running)) if checked == running => RunningImage::Same,
            (Some(_), Some(_)) => RunningImage::Different,
            _ => RunningImage::Unconfirmed,
        };
        ImageSignature {
            state,
            running_image,
        }
    }

    /// A process handle, closed on drop.
    struct ProcessHandle(HANDLE);

    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful OpenProcess and is closed once here.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    /// The longest NT path `K32GetMappedFileNameW` is given room for, in UTF-16 units.
    const MAPPED_NAME_UNITS: usize = 32_768;

    /// The current NT name (`\Device\...`) of the file mapped at `address` in the process,
    /// or `None` when the query fails or the name might not fit.
    fn mapped_name(process: &ProcessHandle, address: *const c_void) -> Option<Vec<u16>> {
        let mut name = vec![0u16; MAPPED_NAME_UNITS];
        // SAFETY: the handle is open with PROCESS_QUERY_INFORMATION; `address` is only read
        // as a number in the other process; the call writes at most `name.len()` units.
        let len = unsafe { K32GetMappedFileNameW(process.0, address, &mut name) } as usize;
        if len == 0 || len >= name.len() - 1 {
            return None;
        }
        name.truncate(len);
        Some(name)
    }

    /// The identity of the file the image of process `pid` is mapped from, when the process
    /// still is the instance started at `generation` and every query succeeds.
    fn image_file_id(pid: u32, generation: u64) -> Option<(u64, u128)> {
        // SAFETY: plain values in; the returned handle is owned by ProcessHandle.
        let process = ProcessHandle(
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }.ok()?,
        );
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: the handle is open with PROCESS_QUERY_INFORMATION and all four pointers are
        // live FILETIME values the call writes.
        unsafe { GetProcessTimes(process.0, &mut creation, &mut exit, &mut kernel, &mut user) }
            .ok()?;
        let created =
            (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        if created != generation {
            return None;
        }
        // The first module listed is the executable.
        let mut module = HMODULE::default();
        let mut needed = 0u32;
        // SAFETY: room for exactly one HMODULE, as the call is told; `needed` is written.
        let listed = unsafe {
            K32EnumProcessModules(
                process.0,
                &mut module,
                std::mem::size_of::<HMODULE>() as u32,
                &mut needed,
            )
        };
        if !listed.as_bool() || needed == 0 || module.is_invalid() {
            return None;
        }
        let base = module.0 as *const c_void;
        let name = mapped_name(&process, base)?;
        let mut global: Vec<u16> = r"\\?\GLOBALROOT".encode_utf16().collect();
        global.extend_from_slice(&name);
        let image = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES.0)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
            .open(std::ffi::OsString::from_wide(&global))
            .ok()?;
        // The image still has the name just opened, so the open reached the image's file
        // unless it was renamed away and back in between.
        if mapped_name(&process, base)? != name {
            return None;
        }
        file_id(&image)
    }

    /// The volume serial number and 128-bit file id of an open file (`FILE_ID_INFO`); a file
    /// system without that class gets the 32-bit serial and 64-bit index, as
    /// orcel-provider-fs does. One volume always answers the same way.
    fn file_id(file: &File) -> Option<(u64, u128)> {
        let handle = HANDLE(file.as_raw_handle());
        let mut info = FILE_ID_INFO::default();
        // SAFETY: the handle is open for this call and `info` is a writable FILE_ID_INFO of
        // the size the call is told.
        let read = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                (&mut info as *mut FILE_ID_INFO).cast::<c_void>(),
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        };
        if read.is_ok() {
            return Some((
                info.VolumeSerialNumber,
                u128::from_le_bytes(info.FileId.Identifier),
            ));
        }
        let mut basic = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle is open for this call and `basic` is a writable structure.
        unsafe { GetFileInformationByHandle(handle, &mut basic) }.ok()?;
        Some((
            u64::from(basic.dwVolumeSerialNumber),
            (u128::from(basic.nFileIndexHigh) << 32) | u128::from(basic.nFileIndexLow),
        ))
    }

    fn signature_of_open(file: &File, path: &Path) -> (SignatureState, Checked) {
        let handle = HANDLE(file.as_raw_handle());
        let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide_path.as_ptr()),
            hFile: handle,
            pgKnownSubject: std::ptr::null_mut(),
        };
        let embedded = verify(
            WTD_CHOICE_FILE,
            WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
        );
        let (outcome, checked) = if embedded.status == TRUST_E_NOSIGNATURE {
            match verify_catalog(handle, &wide_path) {
                Some(outcome) => (outcome, Checked::Catalog),
                None => return (SignatureState::Unknown, Checked::Catalog),
            }
        } else {
            (embedded, Checked::Embedded)
        };
        (state_of(outcome), checked)
    }

    fn state_of(outcome: Outcome) -> SignatureState {
        let status = outcome.status;
        if status.is_ok() {
            let subject = outcome.subject.unwrap_or_default();
            SignatureState::Verified {
                subject: subject.chars().take(MAX_SUBJECT_CHARS).collect(),
            }
        } else if status == TRUST_E_NOSIGNATURE {
            SignatureState::Unsigned
        } else if status == TRUST_E_SUBJECT_FORM_UNKNOWN
            || status == TRUST_E_PROVIDER_UNKNOWN
            || status == TRUST_E_ACTION_UNKNOWN
            || status == CRYPT_E_FILE_ERROR
            // FACILITY_WIN32: an I/O or API error, not a verdict on the signature.
            || ((status.0 as u32) >> 16) & 0x1fff == 7
        {
            SignatureState::Unknown
        } else {
            SignatureState::Untrusted
        }
    }

    /// Verify one subject offline with no UI, read the signer while the state is open, and
    /// always close the state again.
    fn verify(choice: WINTRUST_DATA_UNION_CHOICE, subject: WINTRUST_DATA_0) -> Outcome {
        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: choice,
            Anonymous: subject,
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        };
        let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: `data` is a fully initialized WINTRUST_DATA whose subject pointer, and the
        // strings and handles it points to, outlive both calls; WTD_UI_NONE shows no window.
        let status = HRESULT(unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action,
                &mut data as *mut WINTRUST_DATA as *mut c_void,
            )
        });
        let subject = if status.is_ok() {
            signer_subject(data.hWVTStateData)
        } else {
            None
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: the same live structure, now asking WinVerifyTrust to free the state data
        // the verify call allocated (a no-op when it allocated none).
        let _ = unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action,
                &mut data as *mut WINTRUST_DATA as *mut c_void,
            )
        };
        Outcome { status, subject }
    }

    /// The display name of the leaf certificate of the first signer, from open state data.
    fn signer_subject(state: HANDLE) -> Option<String> {
        // SAFETY: `state` is the open state of a successful verify, not yet closed; every
        // pointer read below is checked for null and belongs to that state.
        unsafe {
            let provider = WTHelperProvDataFromStateData(state);
            if provider.is_null() {
                return None;
            }
            let signer = WTHelperGetProvSignerFromChain(provider, 0, BOOL::from(false), 0);
            if signer.is_null() || (*signer).csCertChain == 0 || (*signer).pasCertChain.is_null() {
                return None;
            }
            let leaf = (*(*signer).pasCertChain).pCert;
            if leaf.is_null() {
                return None;
            }
            let needed = CertGetNameStringW(leaf, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None);
            if needed <= 1 {
                return None;
            }
            let mut name = vec![0u16; needed as usize];
            let written = CertGetNameStringW(
                leaf,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                Some(&mut name),
            );
            // `written` counts the terminating NUL.
            let len = (written as usize).saturating_sub(1).min(name.len());
            Some(String::from_utf16_lossy(&name[..len]))
        }
    }

    /// A catalog admin context, released on drop.
    struct CatAdmin(isize);

    impl Drop for CatAdmin {
        fn drop(&mut self) {
            // SAFETY: the context came from a successful acquire and is released once.
            let _ = unsafe { CryptCATAdminReleaseContext(self.0, 0) };
        }
    }

    /// A catalog context, released on drop before its admin context.
    struct CatInfo<'a>(&'a CatAdmin, isize);

    impl Drop for CatInfo<'_> {
        fn drop(&mut self) {
            // SAFETY: the context came from a successful enumeration under this admin
            // context and is released once.
            let _ = unsafe { CryptCATAdminReleaseCatalogContext((self.0).0, self.1, 0) };
        }
    }

    /// Verify the file against the system catalog that lists its hash. A file no catalog
    /// lists is unsigned; `None` when the catalog machinery itself fails.
    fn verify_catalog(file: HANDLE, wide_path: &[u16]) -> Option<Outcome> {
        let mut raw_admin = 0isize;
        // SAFETY: plain out-parameter; SHA256 is the hash Windows 8+ catalogs list.
        unsafe {
            CryptCATAdminAcquireContext2(&mut raw_admin, None, BCRYPT_SHA256_ALGORITHM, None, 0)
        }
        .ok()?;
        let admin = CatAdmin(raw_admin);
        // One hash of the file: 64 bytes holds any hash a catalog admin context computes, and
        // the call writes the real length back.
        let mut hash = vec![0u8; 64];
        let mut hash_len = hash.len() as u32;
        // SAFETY: `hash` holds `hash_len` bytes, as the call is told.
        unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                admin.0,
                file,
                &mut hash_len,
                Some(hash.as_mut_ptr()),
                0,
            )
        }
        .ok()?;
        if hash_len == 0 || hash_len as usize > hash.len() {
            return None;
        }
        hash.truncate(hash_len as usize);
        // SAFETY: `hash` is a live slice; no previous catalog context is passed.
        let raw_catalog = unsafe { CryptCATAdminEnumCatalogFromHash(admin.0, &hash, 0, None) };
        if raw_catalog == 0 {
            return Some(Outcome {
                status: TRUST_E_NOSIGNATURE,
                subject: None,
            });
        }
        let catalog = CatInfo(&admin, raw_catalog);
        let mut info = CATALOG_INFO {
            cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
            ..Default::default()
        };
        // SAFETY: `info` is a live CATALOG_INFO with its size set.
        unsafe { CryptCATCatalogInfoFromContext(catalog.1, &mut info, 0) }.ok()?;
        // Catalog members are tagged with the hash in upper-case hex.
        let mut tag: Vec<u16> = hash
            .iter()
            .flat_map(|byte| format!("{byte:02X}").encode_utf16().collect::<Vec<_>>())
            .collect();
        tag.push(0);
        let mut catalog_info = WINTRUST_CATALOG_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
            dwCatalogVersion: 0,
            pcwszCatalogFilePath: PCWSTR(info.wszCatalogFile.as_ptr()),
            pcwszMemberTag: PCWSTR(tag.as_ptr()),
            pcwszMemberFilePath: PCWSTR(wide_path.as_ptr()),
            hMemberFile: file,
            pbCalculatedFileHash: hash.as_mut_ptr(),
            cbCalculatedFileHash: hash.len() as u32,
            pcCatalogContext: std::ptr::null_mut(),
            hCatAdmin: admin.0,
        };
        let outcome = verify(
            WTD_CHOICE_CATALOG,
            WINTRUST_DATA_0 {
                pCatalog: &mut catalog_info,
            },
        );
        // The catalog context is released before the admin context it belongs to.
        drop(catalog);
        Some(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every result names Microsoft. `kernel32.dll` carries its own signature on current
    /// Windows; inbox tools such as `cmd.exe` and `notepad.exe` are signed only through a
    /// system catalog, so at least one of them proves the catalog fallback.
    #[cfg(windows)]
    #[test]
    fn signature_of_system_binaries_is_verified_through_both_paths() {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let mut through_catalog = Vec::new();
        for name in ["kernel32.dll", "cmd.exe", "notepad.exe", "where.exe"] {
            let path = Path::new(&root).join("System32").join(name);
            let (state, checked) = imp::image_signature(&path);
            assert!(
                matches!(state, SignatureState::Verified { .. }),
                "{name}: {state:?}"
            );
            if let SignatureState::Verified { subject } = state {
                assert!(subject.contains("Microsoft"), "{name}: {subject}");
                assert!(subject.chars().count() <= MAX_SUBJECT_CHARS);
                if checked == imp::Checked::Catalog {
                    through_catalog.push(name);
                }
            }
        }
        assert!(
            !through_catalog.is_empty(),
            "no system binary was verified through a catalog"
        );
    }

    #[test]
    fn signature_of_random_bytes_is_never_verified() {
        let path = std::env::temp_dir().join(format!(
            "orcel-signature-random-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        let mut seed = 0x9e37_79b9_7f4a_7c15u64 ^ u64::from(std::process::id());
        let bytes: Vec<u8> = (0..4096)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect();
        std::fs::write(&path, bytes).unwrap();
        let state = image_signature(&path);
        let _ = std::fs::remove_file(&path);
        if cfg!(windows) {
            assert!(
                matches!(state, SignatureState::Unsigned | SignatureState::Unknown),
                "{state:?}"
            );
        } else {
            assert_eq!(state, SignatureState::Unknown);
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn signature_is_not_checked_off_windows() {
        let exe = std::env::current_exe().unwrap();
        assert_eq!(image_signature(&exe), SignatureState::Unknown);
    }

    #[test]
    fn signature_of_a_missing_file_is_unknown() {
        let path = std::env::temp_dir().join("orcel-signature-no-such-file-7f3a.exe");
        assert_eq!(image_signature(&path), SignatureState::Unknown);
        assert_eq!(
            image_signature_for(&path, std::process::id(), 0),
            ImageSignature::unconfirmed(SignatureState::Unknown)
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn running_image_is_not_compared_off_windows() {
        let exe = std::env::current_exe().unwrap();
        assert_eq!(
            image_signature_for(&exe, std::process::id(), 0),
            ImageSignature::unconfirmed(SignatureState::Unknown)
        );
    }

    /// A fresh directory under the temp dir for one test.
    #[cfg(windows)]
    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "orcel-signature-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The test's own executable is its running image; a byte-for-byte copy of it is not,
    /// and neither is anything checked against a start generation this process never had.
    #[cfg(windows)]
    #[test]
    fn running_image_of_this_process_is_its_own_file_and_not_a_copy() {
        let exe = std::env::current_exe().unwrap();
        let pid = std::process::id();
        let generation = crate::process::current_instance().unwrap().generation;
        let own = image_signature_for(&exe, pid, generation);
        assert_eq!(own.running_image, RunningImage::Same, "{own:?}");
        assert_eq!(own.state, image_signature(&exe));

        let dir = scratch_dir("copy");
        let copy = dir.join("copy-of-test.exe");
        std::fs::copy(&exe, &copy).unwrap();
        let copied = image_signature_for(&copy, pid, generation);
        let stale = image_signature_for(&exe, pid, generation.wrapping_add(1));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(copied.running_image, RunningImage::Different, "{copied:?}");
        assert_eq!(stale.running_image, RunningImage::Unconfirmed, "{stale:?}");
    }

    /// The case the comparison exists for: a running program's file is renamed away and
    /// another file put at its path. The path then names a different file, and the renamed
    /// file is still the running image.
    #[cfg(windows)]
    #[test]
    fn running_image_follows_a_rename_and_replace() {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let cmd = Path::new(&root).join("System32").join("cmd.exe");
        let dir = scratch_dir("rename");
        let launched = dir.join("launched.exe");
        let renamed = dir.join("renamed.exe");
        std::fs::copy(&cmd, &launched).unwrap();
        let mut child = std::process::Command::new(&launched)
            .args(["/d", "/q", "/k"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let generation = crate::process::start_generation(pid).map(|g| g.generation);
        // A process just created may not list its modules yet; give it a few seconds.
        let before = generation.as_ref().map(|generation| {
            let mut seen = image_signature_for(&launched, pid, *generation);
            for _ in 0..50 {
                if seen.running_image != RunningImage::Unconfirmed {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
                seen = image_signature_for(&launched, pid, *generation);
            }
            seen
        });
        let moved = std::fs::rename(&launched, &renamed);
        let replaced = moved
            .as_ref()
            .map_err(|error| error.to_string())
            .and_then(|()| {
                std::fs::copy(std::env::current_exe().unwrap(), &launched)
                    .map_err(|error| error.to_string())
            });
        let after = generation.as_ref().map(|generation| {
            (
                image_signature_for(&launched, pid, *generation),
                image_signature_for(&renamed, pid, *generation),
            )
        });
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(replaced.is_ok(), "{moved:?} {replaced:?}");
        let before = before.unwrap();
        assert_eq!(before.running_image, RunningImage::Same, "{before:?}");
        let (at_path, at_new_name) = after.unwrap();
        assert_eq!(
            at_path.running_image,
            RunningImage::Different,
            "{at_path:?}"
        );
        assert_eq!(
            at_new_name.running_image,
            RunningImage::Same,
            "{at_new_name:?}"
        );
    }
}
