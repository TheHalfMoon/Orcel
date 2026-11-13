//! The code signature of an executable image file, for display on approval prompts.
//!
//! Display only: nothing grants or refuses anything because of it. On Windows the file is
//! opened once and checked through that handle with `WinVerifyTrust` (Authenticode, then the
//! system catalogs, since many inbox binaries are catalog-signed only, hashing the same
//! handle), offline: no revocation check and no network retrieval. Other systems report
//! [`SignatureState::Unknown`].
//!
//! The signature describes a file on disk, not the code in memory. [`image_signature_for`]
//! also compares the file it checked with the file the process's image appears to be mapped
//! from ([`RunningImage`]), mainly to warn when a file renamed away and replaced after launch
//! leaves another file at the path. That comparison is Orcel's, not Windows's. On Windows it
//! opens the process (`PROCESS_QUERY_INFORMATION` and `PROCESS_VM_READ`), confirms its
//! creation time is the recorded start generation, takes the first module
//! `K32EnumProcessModules` lists, asks `K32GetMappedFileNameW` (which answers from the
//! kernel's view of the mapping) for the current name of the file mapped at that base, opens
//! that name, asks again and requires the same name, then compares the volume serial number
//! and file id of that file and of the checked handle, and their volume device names.
//!
//! What it cannot show, and so why [`RunningImage::Same`] is worded as a hedged finding and
//! never as an assurance:
//! - The module list comes from the target process's own loader data (its PEB), which a
//!   process can rewrite to point at another mapped image. As a cross-check, `Same` also
//!   requires the mapped name to equal the image name the kernel reports for the process
//!   (`QueryFullProcessImageNameW`, `PROCESS_NAME_NATIVE`, the name the process was started
//!   under, which a later rename does not change; so a renamed image reads `Unconfirmed`). A
//!   process that controls both its loader data and the files at its own image path can
//!   still defeat it.
//! - The same file id does not mean the same contents: a file can be written through a handle
//!   opened before the image was mapped ("process herpaderping"), and code can be injected or
//!   changed in memory after launch. Nothing here reads the code that is running.
//! - The two name queries narrow, but cannot close, the window in which the image could be
//!   renamed away and back while another file holds its name.
//!
//! Every failure is [`RunningImage::Unconfirmed`], never `Same`: another user's, an elevated
//! or a protected process (which deny that access), an exited process or reused pid, a
//! failed query, a zero or all-ones volume serial or file id, volume device names that differ
//! or cannot be read, volume serial numbers that differ (one device such as `\Device\Mup`
//! holds many volumes, and a DFS failover moves a path to a replica). Only another file id on
//! the same device and serial is [`RunningImage::Different`], which an update that replaced
//! the file after launch also produces. A file system without `FILE_ID_INFO` falls back to the
//! 32-bit serial and 64-bit index, which can show `Different` but never `Same`.

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

/// Orcel's comparison of the file a signature check read with the file a running process's
/// image appears to be mapped from. Display only; see the module documentation for what it
/// cannot show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunningImage {
    /// The checked file has the same volume and 128-bit file id as the file the process's
    /// image appears to be mapped from, under the name the kernel reports for the process.
    /// It says nothing about the code now running, and a process that controls its own
    /// loader data and image path can produce it falsely.
    Same,
    /// The checked file has another file id than the file the process's image appears to be
    /// mapped from, on the same volume device and volume serial number. An update that
    /// replaced the file after launch reads this way too.
    Different,
    /// Not established: another system, an unreadable file, a process that denies the
    /// access the comparison needs, an exited process or reused pid, a failed query, an
    /// unusable file id, or volume device names or serial numbers that do not match.
    Unconfirmed,
}

/// The identity of one open file as Windows reports it.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    volume_serial: u64,
    file_id: u128,
    /// `FILE_ID_INFO` (64-bit serial, 128-bit id) rather than the 32-bit serial and 64-bit
    /// index fallback.
    full: bool,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl FileIdentity {
    /// Zero and all-ones serials and ids are what a file system without real ids reports.
    fn usable(&self) -> bool {
        let (serial_max, id_max) = if self.full {
            (u64::MAX, u128::MAX)
        } else {
            (u64::from(u32::MAX), u128::from(u64::MAX))
        };
        self.volume_serial != 0
            && self.volume_serial != serial_max
            && self.file_id != 0
            && self.file_id != id_max
    }
}

/// What was read about the process's image: the identity of the file opened by its mapped
/// name, that NT name, and the image name the kernel reports for the process.
#[cfg_attr(not(windows), allow(dead_code))]
struct ImageFacts {
    identity: FileIdentity,
    mapped_name: Vec<u16>,
    kernel_name: Vec<u16>,
}

/// The `\Device\<name>` prefix of an NT path, or `None` when it has no file part.
#[cfg_attr(not(windows), allow(dead_code))]
fn device_of(nt_path: &[u16]) -> Option<&[u16]> {
    let prefix: Vec<u16> = r"\Device\".encode_utf16().collect();
    let rest = nt_path.strip_prefix(prefix.as_slice())?;
    let end = rest.iter().position(|&unit| unit == u16::from(b'\\'))?;
    if end == 0 || end + 1 >= rest.len() {
        return None;
    }
    Some(&nt_path[..prefix.len() + end])
}

/// Two names compared without case; a name that is not valid UTF-16 equals nothing.
#[cfg_attr(not(windows), allow(dead_code))]
fn same_name(left: &[u16], right: &[u16]) -> bool {
    match (String::from_utf16(left), String::from_utf16(right)) {
        (Ok(left), Ok(right)) => left.to_lowercase() == right.to_lowercase(),
        _ => false,
    }
}

/// Orcel's comparison, from what was read. Only matching full ids, on one volume device, of
/// a file the kernel names the same way as the mapping, read `Same`; another usable id on the
/// same device and volume serial reads `Different`; everything else is `Unconfirmed`.
#[cfg_attr(not(windows), allow(dead_code))]
fn compare_identity(
    checked: Option<FileIdentity>,
    checked_nt_path: Option<&[u16]>,
    image: Option<&ImageFacts>,
) -> RunningImage {
    let (Some(checked), Some(checked_nt_path), Some(image)) = (checked, checked_nt_path, image)
    else {
        return RunningImage::Unconfirmed;
    };
    if !checked.usable() || !image.identity.usable() || checked.full != image.identity.full {
        return RunningImage::Unconfirmed;
    }
    match (device_of(checked_nt_path), device_of(&image.mapped_name)) {
        (Some(left), Some(right)) if same_name(left, right) => {}
        _ => return RunningImage::Unconfirmed,
    }
    // One device name can hold many volumes (`\Device\Mup` holds every network share, and a
    // DFS failover moves a path to a replica), so only another id on the same volume serial
    // is a different file; another serial is not known to be one.
    if checked.volume_serial != image.identity.volume_serial {
        return RunningImage::Unconfirmed;
    }
    if checked.file_id != image.identity.file_id {
        return RunningImage::Different;
    }
    if checked.full && same_name(&image.mapped_name, &image.kernel_name) {
        RunningImage::Same
    } else {
        RunningImage::Unconfirmed
    }
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
    use super::{
        compare_identity, FileIdentity, ImageFacts, ImageSignature, SignatureState,
        MAX_SUBJECT_CHARS,
    };
    use std::ffi::c_void;
    use std::fs::File;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use windows::core::{GUID, HRESULT, PCWSTR, PWSTR};
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
        GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, VOLUME_NAME_NT,
    };
    use windows::Win32::System::ProcessStatus::{K32EnumProcessModules, K32GetMappedFileNameW};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_NATIVE,
        PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
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
        let checked_nt_path = nt_path_of(&file);
        let image = image_facts(pid, generation);
        let running_image =
            compare_identity(file_id(&file), checked_nt_path.as_deref(), image.as_ref());
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

    /// What can be read about the file the image of process `pid` appears to be mapped from,
    /// when the process still is the instance started at `generation` and every query
    /// succeeds.
    fn image_facts(pid: u32, generation: u64) -> Option<ImageFacts> {
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
        // The image name the kernel reports for the process, read from the process object
        // rather than from the process's own memory.
        let mut kernel_name = vec![0u16; MAPPED_NAME_UNITS];
        let mut kernel_len = kernel_name.len() as u32;
        // SAFETY: `kernel_name` holds `kernel_len` units, as the call is told; it writes the
        // length back.
        unsafe {
            QueryFullProcessImageNameW(
                process.0,
                PROCESS_NAME_NATIVE,
                PWSTR(kernel_name.as_mut_ptr()),
                &mut kernel_len,
            )
        }
        .ok()?;
        if kernel_len == 0 || kernel_len as usize >= kernel_name.len() {
            return None;
        }
        kernel_name.truncate(kernel_len as usize);
        // The first module listed is the executable, by the process's own loader data, which
        // the process can rewrite: the kernel name above is the cross-check.
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
        Some(ImageFacts {
            identity: file_id(&image)?,
            mapped_name: name,
            kernel_name,
        })
    }

    /// The volume serial number and 128-bit file id of an open file (`FILE_ID_INFO`); a file
    /// system without that class gets the 32-bit serial and 64-bit index, as
    /// orcel-provider-fs does, marked so it can never read as the same file.
    fn file_id(file: &File) -> Option<FileIdentity> {
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
            return Some(FileIdentity {
                volume_serial: info.VolumeSerialNumber,
                file_id: u128::from_le_bytes(info.FileId.Identifier),
                full: true,
            });
        }
        let mut basic = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle is open for this call and `basic` is a writable structure.
        unsafe { GetFileInformationByHandle(handle, &mut basic) }.ok()?;
        Some(FileIdentity {
            volume_serial: u64::from(basic.dwVolumeSerialNumber),
            file_id: (u128::from(basic.nFileIndexHigh) << 32) | u128::from(basic.nFileIndexLow),
            full: false,
        })
    }

    /// The NT path (`\Device\...`) of an open file, for its volume device name.
    fn nt_path_of(file: &File) -> Option<Vec<u16>> {
        let mut name = vec![0u16; MAPPED_NAME_UNITS];
        // SAFETY: the handle is open for this call; the call writes at most `name.len()`
        // units and returns the length written, or the length needed when it did not fit.
        let len = unsafe {
            GetFinalPathNameByHandleW(HANDLE(file.as_raw_handle()), &mut name, VOLUME_NAME_NT)
        } as usize;
        if len == 0 || len >= name.len() {
            return None;
        }
        name.truncate(len);
        Some(name)
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
    /// another file put at its path. The path then names a different file; the renamed file
    /// is still the mapped image, but under another name than the kernel reports, so it is
    /// not confirmed.
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
        // The renamed file is still the mapped image, but the kernel keeps reporting the name
        // the process was started under, so the new name is not claimed as the same file.
        assert_eq!(
            at_new_name.running_image,
            RunningImage::Unconfirmed,
            "{at_new_name:?}"
        );
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    const IMAGE: &str = r"\Device\HarddiskVolume3\Apps\App.exe";

    fn full(volume_serial: u64, file_id: u128) -> FileIdentity {
        FileIdentity {
            volume_serial,
            file_id,
            full: true,
        }
    }

    fn facts(identity: FileIdentity, mapped: &str, kernel: &str) -> ImageFacts {
        ImageFacts {
            identity,
            mapped_name: wide(mapped),
            kernel_name: wide(kernel),
        }
    }

    fn compared(checked: FileIdentity, checked_path: &str, image: &ImageFacts) -> RunningImage {
        compare_identity(Some(checked), Some(&wide(checked_path)), Some(image))
    }

    #[test]
    fn identity_compare_reads_same_only_for_matching_full_ids_under_the_kernel_name() {
        let id = full(0x1234, 0xabcd);
        let image = facts(id, IMAGE, &IMAGE.to_uppercase());
        // Another name for the same file (a hard link) on the same device.
        assert_eq!(
            compared(id, r"\Device\HarddiskVolume3\Other\Link.exe", &image),
            RunningImage::Same
        );
        assert_eq!(
            compared(full(0x1234, 0xabce), IMAGE, &image),
            RunningImage::Different
        );
        // The mapping's name is not the one the kernel reports for the process: the loader
        // data may point elsewhere, so a matching id is not enough.
        let elsewhere = facts(id, IMAGE, r"\Device\HarddiskVolume3\Apps\Launched.exe");
        assert_eq!(compared(id, IMAGE, &elsewhere), RunningImage::Unconfirmed);
        // Missing facts.
        assert_eq!(
            compare_identity(None, Some(&wide(IMAGE)), Some(&image)),
            RunningImage::Unconfirmed
        );
        assert_eq!(
            compare_identity(Some(id), None, Some(&image)),
            RunningImage::Unconfirmed
        );
        assert_eq!(
            compare_identity(Some(id), Some(&wide(IMAGE)), None),
            RunningImage::Unconfirmed
        );
    }

    #[test]
    fn identity_compare_treats_zero_and_all_ones_ids_as_unconfirmed() {
        for unusable in [
            full(0, 0xabcd),
            full(u64::MAX, 0xabcd),
            full(0x1234, 0),
            full(0x1234, u128::MAX),
        ] {
            let image = facts(unusable, IMAGE, IMAGE);
            assert_eq!(
                compared(unusable, IMAGE, &image),
                RunningImage::Unconfirmed,
                "{unusable:?}"
            );
            let good = full(0x1234, 0xabcd);
            assert_eq!(
                compared(good, IMAGE, &image),
                RunningImage::Unconfirmed,
                "{unusable:?}"
            );
            assert_eq!(
                compared(unusable, IMAGE, &facts(good, IMAGE, IMAGE)),
                RunningImage::Unconfirmed,
                "{unusable:?}"
            );
        }
        let fallback = |volume_serial: u64, file_id: u128| FileIdentity {
            volume_serial,
            file_id,
            full: false,
        };
        for unusable in [
            fallback(u64::from(u32::MAX), 7),
            fallback(9, u128::from(u64::MAX)),
        ] {
            assert_eq!(
                compared(unusable, IMAGE, &facts(unusable, IMAGE, IMAGE)),
                RunningImage::Unconfirmed,
                "{unusable:?}"
            );
        }
    }

    #[test]
    fn identity_compare_needs_one_volume_device_and_never_matches_on_the_fallback() {
        let id = full(0x1234, 0xabcd);
        let image = facts(id, IMAGE, IMAGE);
        assert_eq!(
            compared(id, r"\Device\HarddiskVolume4\Apps\App.exe", &image),
            RunningImage::Unconfirmed
        );
        assert_eq!(
            compared(id, r"C:\Apps\App.exe", &image),
            RunningImage::Unconfirmed
        );
        assert_eq!(
            compared(id, r"\Device\HarddiskVolume3", &image),
            RunningImage::Unconfirmed
        );
        let fallback = FileIdentity {
            volume_serial: 0x1234,
            file_id: 0xabcd,
            full: false,
        };
        assert_eq!(
            compared(fallback, IMAGE, &facts(fallback, IMAGE, IMAGE)),
            RunningImage::Unconfirmed
        );
        let other = FileIdentity {
            file_id: 0xabce,
            ..fallback
        };
        assert_eq!(
            compared(other, IMAGE, &facts(fallback, IMAGE, IMAGE)),
            RunningImage::Different
        );
        // One full id and one fallback id are not compared.
        assert_eq!(
            compared(id, IMAGE, &facts(fallback, IMAGE, IMAGE)),
            RunningImage::Unconfirmed
        );
    }

    /// `\Device\Mup` holds every network share, so the same device name with another volume
    /// serial (a DFS failover to a replica, say) is not known to be another file: no warning.
    /// Another id on the same serial is.
    #[test]
    fn identity_compare_reads_different_only_on_the_same_volume_serial() {
        let share = r"\Device\Mup\server\share\App.exe";
        let replica = r"\Device\Mup\replica\share\App.exe";
        let running = full(0x1234, 0xabcd);
        let image = facts(running, share, share);
        assert_eq!(
            compared(full(0x5678, 0xabce), replica, &image),
            RunningImage::Unconfirmed
        );
        assert_eq!(
            compared(full(0x5678, 0xabcd), share, &image),
            RunningImage::Unconfirmed
        );
        assert_eq!(
            compared(full(0x1234, 0xabce), replica, &image),
            RunningImage::Different
        );
        let fallback = |volume_serial: u64, file_id: u128| FileIdentity {
            volume_serial,
            file_id,
            full: false,
        };
        assert_eq!(
            compared(
                fallback(0x5678, 0xabce),
                share,
                &facts(fallback(0x1234, 0xabcd), share, share)
            ),
            RunningImage::Unconfirmed
        );
    }
}
