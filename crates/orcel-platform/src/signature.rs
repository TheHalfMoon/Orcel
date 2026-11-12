//! The code signature of an executable image file, for display on approval prompts.
//!
//! Display only: the result describes the file on disk when it was checked, not the code
//! running in memory, and nothing grants or refuses anything because of it. On Windows the
//! file is checked with `WinVerifyTrust` (Authenticode, then the system catalogs, since many
//! inbox binaries are catalog-signed only), offline: no revocation check and no network
//! retrieval. Other systems report [`SignatureState::Unknown`].

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
        imp::image_signature(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        SignatureState::Unknown
    }
}

#[cfg(windows)]
mod imp {
    use super::{SignatureState, MAX_SUBJECT_CHARS};
    use std::ffi::c_void;
    use std::fs::File;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use windows::core::{GUID, HRESULT, PCWSTR};
    use windows::Win32::Foundation::{
        BOOL, CRYPT_E_FILE_ERROR, HANDLE, HWND, TRUST_E_ACTION_UNKNOWN, TRUST_E_NOSIGNATURE,
        TRUST_E_PROVIDER_UNKNOWN, TRUST_E_SUBJECT_FORM_UNKNOWN,
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

    /// One `WinVerifyTrust` outcome: its status, and the signer's name when it succeeded.
    struct Outcome {
        status: HRESULT,
        subject: Option<String>,
    }

    pub(super) fn image_signature(path: &Path) -> SignatureState {
        let Ok(file) = File::open(path) else {
            return SignatureState::Unknown;
        };
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
        let outcome = if embedded.status == TRUST_E_NOSIGNATURE {
            match verify_catalog(handle, &wide_path) {
                Some(outcome) => outcome,
                None => return SignatureState::Unknown,
            }
        } else {
            embedded
        };
        drop(file);
        state_of(outcome)
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
        let mut hash_len = 0u32;
        // SAFETY: a size query (no buffer); it fails with "insufficient buffer" and sets the
        // size, so only the size is read.
        let _ =
            unsafe { CryptCATAdminCalcHashFromFileHandle2(admin.0, file, &mut hash_len, None, 0) };
        if hash_len == 0 || hash_len > 64 {
            return None;
        }
        let mut hash = vec![0u8; hash_len as usize];
        // SAFETY: `hash` holds `hash_len` bytes, as the call was just told.
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

    #[cfg(windows)]
    #[test]
    fn signature_of_a_system_binary_is_verified_and_names_microsoft() {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        for name in ["kernel32.dll", "notepad.exe"] {
            let path = Path::new(&root).join("System32").join(name);
            match image_signature(&path) {
                SignatureState::Verified { subject } => {
                    assert!(subject.contains("Microsoft"), "{name}: {subject}");
                    assert!(subject.chars().count() <= MAX_SUBJECT_CHARS);
                }
                other => panic!("{name}: {other:?}"),
            }
        }
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
    }
}
