//! CNG cryptography: the ECDSA P-256 lease-signing key (wrapped at rest by
//! DPAPI under the account the authority runs as), its public-key verifier,
//! the RSA PKCS#1 v1.5 SHA-256 check of Windows Hello key-credential
//! signatures, and system randomness.
//!
//! Slice 1 keeps the signing key as a CNG software key whose private blob is
//! DPAPI-protected (user scope of `NT SERVICE\OrcelAuthority`) in the
//! protected state directory, so a standard user can neither read the file
//! (ACL) nor unwrap it (DPAPI is bound to the service account). The spec's
//! non-exportable key in the Microsoft Platform Crypto Provider (TPM) is a
//! later slice; it changes the [`EcdsaP256Signer`] constructor only.

use crate::attestation::{Hash, RsaVerifier};
use crate::core::{Entropy, LeaseSigner, PresenceVerifier};
use crate::error::AuthorityError;
use crate::lease::{key_id_of, SignatureVerifier};
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::path::Path;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptDestroyKey, BCryptExportKey, BCryptFinalizeKeyPair,
    BCryptGenRandom, BCryptGenerateKeyPair, BCryptGetProperty, BCryptImportKeyPair,
    BCryptOpenAlgorithmProvider, BCryptSignHash, BCryptVerifySignature, CryptDecodeObjectEx,
    CryptImportPublicKeyInfoEx2, CryptProtectData, CryptUnprotectData, BCRYPT_ALG_HANDLE,
    BCRYPT_ECCPRIVATE_BLOB, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM,
    BCRYPT_ECDSA_PUBLIC_P256_MAGIC, BCRYPT_KEY_HANDLE, BCRYPT_KEY_LENGTH, BCRYPT_PAD_PKCS1,
    BCRYPT_PKCS1_PADDING_INFO, BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA384_ALGORITHM,
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, CERT_PUBLIC_KEY_INFO, CRYPTPROTECT_UI_FORBIDDEN,
    CRYPT_DECODE_ALLOC_FLAG, CRYPT_INTEGER_BLOB, X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
};

/// DPAPI entropy binding the wrapped blob to its purpose.
const DPAPI_ENTROPY: &[u8] = b"orcel-authority-lease-signing-key/1";

/// The smallest RSA modulus accepted for a presence key.
pub const MIN_PRESENCE_RSA_BITS: u32 = 2048;

fn nt(status: i32, context: &str) -> Result<(), AuthorityError> {
    if status >= 0 {
        Ok(())
    } else {
        Err(AuthorityError::internal(format!(
            "{context} failed with NTSTATUS 0x{:08x}",
            status as u32
        )))
    }
}

struct Algorithm(BCRYPT_ALG_HANDLE);

impl Algorithm {
    fn open(id: *const u16) -> Result<Self, AuthorityError> {
        let mut handle: BCRYPT_ALG_HANDLE = std::ptr::null_mut();
        // SAFETY: `handle` receives a provider handle closed in Drop.
        nt(
            unsafe { BCryptOpenAlgorithmProvider(&mut handle, id, std::ptr::null(), 0) },
            "BCryptOpenAlgorithmProvider",
        )?;
        Ok(Self(handle))
    }
}

impl Drop for Algorithm {
    fn drop(&mut self) {
        // SAFETY: opened above, closed once.
        unsafe { BCryptCloseAlgorithmProvider(self.0, 0) };
    }
}

struct Key(BCRYPT_KEY_HANDLE);

// SAFETY: a CNG key handle may be used from any thread; the signer is
// only used under the authority core's lock.
unsafe impl Send for Key {}

impl Drop for Key {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: created by this module, destroyed once.
            unsafe { BCryptDestroyKey(self.0) };
        }
    }
}

fn export(key: &Key, blob: *const u16) -> Result<Vec<u8>, AuthorityError> {
    let mut size = 0u32;
    // SAFETY: the first call asks for the size only.
    nt(
        unsafe {
            BCryptExportKey(
                key.0,
                std::ptr::null_mut(),
                blob,
                std::ptr::null_mut(),
                0,
                &mut size,
                0,
            )
        },
        "BCryptExportKey size",
    )?;
    let mut out = vec![0u8; size as usize];
    // SAFETY: `out` holds `size` bytes.
    nt(
        unsafe {
            BCryptExportKey(
                key.0,
                std::ptr::null_mut(),
                blob,
                out.as_mut_ptr(),
                size,
                &mut size,
                0,
            )
        },
        "BCryptExportKey",
    )?;
    out.truncate(size as usize);
    Ok(out)
}

fn import(
    algorithm: &Algorithm,
    blob_type: *const u16,
    blob: &[u8],
) -> Result<Key, AuthorityError> {
    let mut key: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
    let len =
        u32::try_from(blob.len()).map_err(|_| AuthorityError::invalid("a key blob is too long"))?;
    // SAFETY: `blob` holds `len` bytes; `key` receives a handle destroyed by Key.
    nt(
        unsafe {
            BCryptImportKeyPair(
                algorithm.0,
                std::ptr::null_mut(),
                blob_type,
                &mut key,
                blob.as_ptr(),
                len,
                0,
            )
        },
        "BCryptImportKeyPair",
    )?;
    Ok(Key(key))
}

fn dpapi(data: &[u8], protect: bool) -> Result<Vec<u8>, AuthorityError> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len())
            .map_err(|_| AuthorityError::internal("DPAPI input too long"))?,
        pbData: data.as_ptr().cast_mut(),
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: DPAPI_ENTROPY.len() as u32,
        pbData: DPAPI_ENTROPY.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: the input blobs point at live slices; DPAPI only reads them and
    // allocates `output`, freed below with LocalFree.
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if ok == 0 {
        return Err(super::os_error(if protect {
            "CryptProtectData"
        } else {
            "CryptUnprotectData (the key belongs to another account?)"
        }));
    }
    // SAFETY: DPAPI returned `cbData` bytes at `pbData`.
    let out = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    // SAFETY: allocated by DPAPI with LocalAlloc; freed once.
    unsafe {
        std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        LocalFree(output.pbData.cast());
    }
    Ok(out)
}

/// The lease-signing key.
pub struct EcdsaP256Signer {
    _algorithm: Algorithm,
    key: Key,
    public: Vec<u8>,
}

// SAFETY: see `Key`; the provider handle is likewise thread-agnostic.
unsafe impl Send for EcdsaP256Signer {}
unsafe impl Send for Algorithm {}

impl EcdsaP256Signer {
    /// Loads the DPAPI-wrapped key at `path`, or creates and stores a new
    /// one when the file does not exist.
    pub fn load_or_create(path: &Path) -> Result<Self, AuthorityError> {
        let algorithm = Algorithm::open(BCRYPT_ECDSA_P256_ALGORITHM)?;
        let key = if path.exists() {
            let wrapped = std::fs::read(path).map_err(|error| {
                AuthorityError::internal(format!("read the signing key: {error}"))
            })?;
            let mut private = dpapi(&wrapped, false)?;
            let key = import(&algorithm, BCRYPT_ECCPRIVATE_BLOB, &private);
            private.iter_mut().for_each(|b| *b = 0);
            key?
        } else {
            let mut handle: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
            // SAFETY: `handle` receives a key destroyed by Key.
            nt(
                unsafe { BCryptGenerateKeyPair(algorithm.0, &mut handle, 256, 0) },
                "BCryptGenerateKeyPair",
            )?;
            let key = Key(handle);
            // SAFETY: a generated, not yet finalized key.
            nt(
                unsafe { BCryptFinalizeKeyPair(key.0, 0) },
                "BCryptFinalizeKeyPair",
            )?;
            let mut private = export(&key, BCRYPT_ECCPRIVATE_BLOB)?;
            let wrapped = dpapi(&private, true);
            private.iter_mut().for_each(|b| *b = 0);
            crate::core::write_atomically(path, &wrapped?)?;
            key
        };
        let public = export(&key, BCRYPT_ECCPUBLIC_BLOB)?;
        check_p256_public_blob(&public)?;
        Ok(Self {
            _algorithm: algorithm,
            key,
            public,
        })
    }
}

impl LeaseSigner for EcdsaP256Signer {
    fn public_key(&self) -> Vec<u8> {
        self.public.clone()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AuthorityError> {
        let hash = Sha256::digest(message);
        let mut size = 0u32;
        // SAFETY: the first call asks for the size only.
        nt(
            unsafe {
                BCryptSignHash(
                    self.key.0,
                    std::ptr::null(),
                    hash.as_ptr(),
                    32,
                    std::ptr::null_mut(),
                    0,
                    &mut size,
                    0,
                )
            },
            "BCryptSignHash size",
        )?;
        let mut out = vec![0u8; size as usize];
        // SAFETY: `out` holds `size` bytes.
        nt(
            unsafe {
                BCryptSignHash(
                    self.key.0,
                    std::ptr::null(),
                    hash.as_ptr(),
                    32,
                    out.as_mut_ptr(),
                    size,
                    &mut size,
                    0,
                )
            },
            "BCryptSignHash",
        )?;
        out.truncate(size as usize);
        Ok(out)
    }
}

/// `BCRYPT_ECCKEY_BLOB` header (magic, 32-byte coordinates) plus X and Y.
pub fn check_p256_public_blob(blob: &[u8]) -> Result<(), AuthorityError> {
    if blob.len() != 8 + 64 {
        return Err(AuthorityError::invalid(
            "an ECDSA P-256 public key blob is 72 bytes",
        ));
    }
    let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    let length = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
    if magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || length != 32 {
        return Err(AuthorityError::invalid(
            "not an ECDSA P-256 public key blob",
        ));
    }
    Ok(())
}

/// Verifies lease signatures with the published public key only.
pub struct EcdsaP256Verifier {
    _algorithm: Algorithm,
    key: Key,
    key_id: String,
}

impl EcdsaP256Verifier {
    pub fn from_public_blob(blob: &[u8]) -> Result<Self, AuthorityError> {
        check_p256_public_blob(blob)?;
        let algorithm = Algorithm::open(BCRYPT_ECDSA_P256_ALGORITHM)?;
        let key = import(&algorithm, BCRYPT_ECCPUBLIC_BLOB, blob)?;
        Ok(Self {
            _algorithm: algorithm,
            key,
            key_id: key_id_of(blob),
        })
    }
}

impl SignatureVerifier for EcdsaP256Verifier {
    fn key_id(&self) -> String {
        self.key_id.clone()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), AuthorityError> {
        if signature.len() != 64 {
            return Err(AuthorityError::lease_invalid(
                "an ECDSA P-256 signature is 64 bytes",
            ));
        }
        let hash = Sha256::digest(message);
        // SAFETY: both buffers live through the call and match their lengths.
        let status = unsafe {
            BCryptVerifySignature(
                self.key.0,
                std::ptr::null(),
                hash.as_ptr(),
                32,
                signature.as_ptr(),
                64,
                0,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(AuthorityError::lease_invalid(
                "the lease signature does not verify with the authority's public key",
            ))
        }
    }
}

/// An RSA public key from X.509 SubjectPublicKeyInfo DER.
fn import_spki_rsa(spki: &[u8]) -> Result<Key, AuthorityError> {
    let len = u32::try_from(spki.len())
        .map_err(|_| AuthorityError::invalid("the public key is too long"))?;
    let mut info: *mut CERT_PUBLIC_KEY_INFO = std::ptr::null_mut();
    let mut info_len = 0u32;
    // SAFETY: `spki` holds `len` bytes; with CRYPT_DECODE_ALLOC_FLAG the
    // system allocates `info`, freed below with LocalFree.
    let ok = unsafe {
        CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            spki.as_ptr(),
            len,
            CRYPT_DECODE_ALLOC_FLAG,
            std::ptr::null(),
            (&mut info as *mut *mut CERT_PUBLIC_KEY_INFO).cast::<c_void>(),
            &mut info_len,
        )
    };
    if ok == 0 || info.is_null() {
        return Err(AuthorityError::invalid(
            "the presence public key is not X.509 SubjectPublicKeyInfo DER",
        ));
    }
    // SAFETY: `info` is a decoded CERT_PUBLIC_KEY_INFO until freed.
    let oid = unsafe {
        let oid = (*info).Algorithm.pszObjId;
        if oid.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(oid.cast())
                .to_string_lossy()
                .into_owned()
        }
    };
    let mut key: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
    let imported = if oid == "1.2.840.113549.1.1.1" {
        // SAFETY: `info` is valid; `key` receives a handle destroyed by Key.
        unsafe {
            CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, info, 0, std::ptr::null(), &mut key)
        }
    } else {
        0
    };
    // SAFETY: allocated by CryptDecodeObjectEx; freed once.
    unsafe { LocalFree(info.cast()) };
    if imported == 0 || key.is_null() {
        return Err(AuthorityError::invalid(
            "the presence public key is not an RSA key (Windows Hello key credentials are RSA)",
        ));
    }
    let key = Key(key);
    let mut bits = 0u32;
    let mut written = 0u32;
    // SAFETY: `bits` is a 4-byte output buffer.
    nt(
        unsafe {
            BCryptGetProperty(
                key.0,
                BCRYPT_KEY_LENGTH,
                (&mut bits as *mut u32).cast(),
                4,
                &mut written,
                0,
            )
        },
        "BCryptGetProperty(KeyLength)",
    )?;
    if bits < MIN_PRESENCE_RSA_BITS {
        return Err(AuthorityError::invalid(
            "the presence key is shorter than 2048 bits",
        ));
    }
    Ok(key)
}

/// Windows Hello `KeyCredential.RequestSignAsync` signatures: RSASSA-PKCS1
/// v1.5 over SHA-256 of the challenge, checked with the enrolled public key.
pub struct HelloKeyVerifier;

impl PresenceVerifier for HelloKeyVerifier {
    fn check_public_key(&self, spki_der: &[u8]) -> Result<(), AuthorityError> {
        import_spki_rsa(spki_der).map(|_| ())
    }

    fn verify(
        &self,
        spki_der: &[u8],
        challenge: &[u8],
        signature: &[u8],
    ) -> Result<(), AuthorityError> {
        if rsa_pkcs1_verify(spki_der, Hash::Sha256, challenge, signature)? {
            Ok(())
        } else {
            Err(AuthorityError::denied(
                "the Windows Hello signature does not verify with the enrolled key",
            ))
        }
    }
}

/// RSASSA-PKCS1 v1.5 over `hash` of `message` with an SPKI key (at least
/// 2048 bits). `Ok(false)` when the signature does not verify.
fn rsa_pkcs1_verify(
    spki_der: &[u8],
    hash: Hash,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, AuthorityError> {
    let key = import_spki_rsa(spki_der)?;
    let digest = hash.digest(message);
    let padding = BCRYPT_PKCS1_PADDING_INFO {
        pszAlgId: match hash {
            Hash::Sha256 => BCRYPT_SHA256_ALGORITHM,
            Hash::Sha384 => BCRYPT_SHA384_ALGORITHM,
        },
    };
    let len = u32::try_from(signature.len())
        .map_err(|_| AuthorityError::invalid("signature too long"))?;
    let digest_len =
        u32::try_from(digest.len()).map_err(|_| AuthorityError::internal("digest length"))?;
    // SAFETY: `padding`, `digest` and `signature` live through the call.
    let status = unsafe {
        BCryptVerifySignature(
            key.0,
            (&padding as *const BCRYPT_PKCS1_PADDING_INFO).cast(),
            digest.as_ptr(),
            digest_len,
            signature.as_ptr(),
            len,
            BCRYPT_PAD_PKCS1,
        )
    };
    Ok(status == 0)
}

/// CNG RSA PKCS#1 v1.5 verification for the attestation check (AIK
/// statement and certificate signatures).
pub struct CngRsaVerifier;

impl RsaVerifier for CngRsaVerifier {
    fn verify(
        &self,
        spki_der: &[u8],
        hash: Hash,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), AuthorityError> {
        if rsa_pkcs1_verify(spki_der, hash, message, signature)? {
            Ok(())
        } else {
            Err(AuthorityError::denied("an RSA signature does not verify"))
        }
    }
}

/// `BCryptGenRandom` with the system-preferred generator.
pub struct SystemEntropy;

impl Entropy for SystemEntropy {
    fn fill(&self, out: &mut [u8]) -> Result<(), AuthorityError> {
        let len = u32::try_from(out.len())
            .map_err(|_| AuthorityError::internal("random request too long"))?;
        // SAFETY: `out` holds `len` bytes.
        nt(
            unsafe {
                BCryptGenRandom(
                    std::ptr::null_mut(),
                    out.as_mut_ptr(),
                    len,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            },
            "BCryptGenRandom",
        )
    }
}

#[cfg(test)]
pub(crate) mod test_keys {
    //! A software RSA key standing in for a Windows Hello key credential in
    //! tests (the real one lives in the user's Hello container and signs
    //! only after the user's gesture).

    use super::{nt, Algorithm, Key};
    use crate::error::AuthorityError;
    use sha2::{Digest, Sha256};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        BCryptFinalizeKeyPair, BCryptGenerateKeyPair, BCryptSignHash, CryptEncodeObjectEx,
        CryptExportPublicKeyInfoFromBCryptKeyHandle, BCRYPT_KEY_HANDLE, BCRYPT_PAD_PKCS1,
        BCRYPT_PKCS1_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM,
        CERT_PUBLIC_KEY_INFO, CRYPT_ENCODE_ALLOC_FLAG, X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
    };

    pub(crate) struct SoftwareHelloKey {
        _algorithm: Algorithm,
        key: Key,
    }

    impl SoftwareHelloKey {
        pub(crate) fn generate(bits: u32) -> Result<Self, AuthorityError> {
            let algorithm = Algorithm::open(BCRYPT_RSA_ALGORITHM)?;
            let mut handle: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
            nt(
                unsafe { BCryptGenerateKeyPair(algorithm.0, &mut handle, bits, 0) },
                "generate",
            )?;
            let key = Key(handle);
            nt(unsafe { BCryptFinalizeKeyPair(key.0, 0) }, "finalize")?;
            Ok(Self {
                _algorithm: algorithm,
                key,
            })
        }

        pub(crate) fn spki(&self) -> Result<Vec<u8>, AuthorityError> {
            let mut size = 0u32;
            let ok = unsafe {
                CryptExportPublicKeyInfoFromBCryptKeyHandle(
                    self.key.0,
                    X509_ASN_ENCODING,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    &mut size,
                )
            };
            if ok == 0 {
                return Err(super::super::os_error("export size"));
            }
            let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
            let info = buffer.as_mut_ptr().cast::<CERT_PUBLIC_KEY_INFO>();
            let ok = unsafe {
                CryptExportPublicKeyInfoFromBCryptKeyHandle(
                    self.key.0,
                    X509_ASN_ENCODING,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    info,
                    &mut size,
                )
            };
            if ok == 0 {
                return Err(super::super::os_error("export"));
            }
            let mut encoded: *mut u8 = std::ptr::null_mut();
            let mut encoded_len = 0u32;
            let ok = unsafe {
                CryptEncodeObjectEx(
                    X509_ASN_ENCODING,
                    X509_PUBLIC_KEY_INFO,
                    info.cast(),
                    CRYPT_ENCODE_ALLOC_FLAG,
                    std::ptr::null(),
                    (&mut encoded as *mut *mut u8).cast(),
                    &mut encoded_len,
                )
            };
            if ok == 0 || encoded.is_null() {
                return Err(super::super::os_error("encode"));
            }
            let out = unsafe { std::slice::from_raw_parts(encoded, encoded_len as usize).to_vec() };
            unsafe { LocalFree(encoded.cast()) };
            Ok(out)
        }

        pub(crate) fn sign(&self, data: &[u8]) -> Result<Vec<u8>, AuthorityError> {
            let hash = Sha256::digest(data);
            let padding = BCRYPT_PKCS1_PADDING_INFO {
                pszAlgId: BCRYPT_SHA256_ALGORITHM,
            };
            let pad = (&padding as *const BCRYPT_PKCS1_PADDING_INFO).cast();
            let mut size = 0u32;
            nt(
                unsafe {
                    BCryptSignHash(
                        self.key.0,
                        pad,
                        hash.as_ptr(),
                        32,
                        std::ptr::null_mut(),
                        0,
                        &mut size,
                        BCRYPT_PAD_PKCS1,
                    )
                },
                "sign size",
            )?;
            let mut out = vec![0u8; size as usize];
            nt(
                unsafe {
                    BCryptSignHash(
                        self.key.0,
                        pad,
                        hash.as_ptr(),
                        32,
                        out.as_mut_ptr(),
                        size,
                        &mut size,
                        BCRYPT_PAD_PKCS1,
                    )
                },
                "sign",
            )?;
            out.truncate(size as usize);
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_keys::SoftwareHelloKey;
    use super::*;

    fn temp_dir(name: &str) -> Result<std::path::PathBuf, String> {
        let dir = std::env::temp_dir().join(format!(
            "orcel-authority-crypto-{name}-{}-{}",
            std::process::id(),
            crate::now_ms()
        ));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        Ok(dir)
    }

    #[test]
    fn the_signing_key_signs_verifies_and_persists_wrapped() -> Result<(), String> {
        let dir = temp_dir("sign")?;
        let path = dir.join("lease-signing.key");
        let signer = EcdsaP256Signer::load_or_create(&path).map_err(|e| e.to_string())?;
        let public = signer.public_key();
        let signature = signer.sign(b"lease body").map_err(|e| e.to_string())?;
        let verifier = EcdsaP256Verifier::from_public_blob(&public).map_err(|e| e.to_string())?;
        assert_eq!(verifier.verify(b"lease body", &signature), Ok(()));
        assert!(verifier.verify(b"lease bodY", &signature).is_err());
        let mut flipped = signature.clone();
        flipped[10] ^= 1;
        assert!(verifier.verify(b"lease body", &flipped).is_err());
        // The file is DPAPI-wrapped, not the raw private blob.
        let stored = std::fs::read(&path).map_err(|e| e.to_string())?;
        assert!(
            stored.len() > 8 && &stored[..4] != b"ECS2",
            "not a raw ECCPRIVATEBLOB"
        );
        drop(signer);
        let again = EcdsaP256Signer::load_or_create(&path).map_err(|e| e.to_string())?;
        assert_eq!(again.public_key(), public, "the same key comes back");
        let other =
            EcdsaP256Signer::load_or_create(&dir.join("other.key")).map_err(|e| e.to_string())?;
        let foreign = other.sign(b"lease body").map_err(|e| e.to_string())?;
        assert!(verifier.verify(b"lease body", &foreign).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn hello_signatures_verify_only_with_the_enrolled_key() -> Result<(), String> {
        let enrolled = SoftwareHelloKey::generate(2048).map_err(|e| e.to_string())?;
        let spki = enrolled.spki().map_err(|e| e.to_string())?;
        let verifier = HelloKeyVerifier;
        assert_eq!(verifier.check_public_key(&spki), Ok(()));
        let challenge = [7u8; 32];
        let signature = enrolled.sign(&challenge).map_err(|e| e.to_string())?;
        assert_eq!(verifier.verify(&spki, &challenge, &signature), Ok(()));
        assert!(verifier.verify(&spki, &[8u8; 32], &signature).is_err());
        let stranger = SoftwareHelloKey::generate(2048).map_err(|e| e.to_string())?;
        let forged = stranger.sign(&challenge).map_err(|e| e.to_string())?;
        assert!(verifier.verify(&spki, &challenge, &forged).is_err());
        let short = SoftwareHelloKey::generate(1024).map_err(|e| e.to_string())?;
        assert!(verifier
            .check_public_key(&short.spki().map_err(|e| e.to_string())?)
            .is_err());
        assert!(verifier.check_public_key(b"not der").is_err());
        Ok(())
    }

    #[test]
    fn the_system_random_source_fills() -> Result<(), String> {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        SystemEntropy.fill(&mut a).map_err(|e| e.to_string())?;
        SystemEntropy.fill(&mut b).map_err(|e| e.to_string())?;
        assert_ne!(a, b);
        Ok(())
    }
}
