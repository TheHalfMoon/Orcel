//! SG-000132 slice 2: the Windows Hello key credential the Orcel authority
//! service enrolls and later asks to sign (Windows only).
//!
//! `KeyCredentialManager` keeps the private key in the user's Windows Hello
//! container (TPM-backed where a TPM is present, never exportable) and signs
//! only after the user's Hello gesture. `orcel authority enroll` creates the
//! key and reads its public key and TPM attestation
//! (`KeyCredential.GetAttestationAsync`); `orcel full-control grant` and
//! `orcel browser grant` open it and sign the service's challenge.
//!
//! Every call that creates, deletes or signs shows a Windows Hello prompt, so
//! nothing here runs in automated tests; the service verifies whatever these
//! calls return (signature, attestation) and refuses anything else.

use windows::core::HSTRING;
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialAttestationStatus, KeyCredentialCreationOption,
    KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType;
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::IBuffer;

/// The key credential names in the user's Hello container: two slots, so
/// re-enrollment creates the new key beside the enrolled one and nothing is
/// replaced before the service's box is answered Yes (review F6), and the
/// slice 2 single name, still opened for a key enrolled under it.
pub const KEY_SLOTS: [&str; 2] = ["Orcel Authority A", "Orcel Authority B"];
pub const LEGACY_KEY_NAME: &str = "Orcel Authority";

/// A Windows Hello key credential.
pub struct HelloKey {
    credential: KeyCredential,
}

fn winrt(context: &str, error: windows::core::Error) -> String {
    format!("{context}: {error}")
}

fn status_text(status: KeyCredentialStatus) -> &'static str {
    match status {
        KeyCredentialStatus::Success => "success",
        KeyCredentialStatus::NotFound => "no Orcel Authority key credential exists",
        KeyCredentialStatus::UserCanceled => "the Windows Hello prompt was cancelled",
        KeyCredentialStatus::UserPrefersPassword => "the user chose a password over Windows Hello",
        KeyCredentialStatus::CredentialAlreadyExists => {
            "an Orcel Authority key credential already exists"
        }
        KeyCredentialStatus::SecurityDeviceLocked => "the security device (TPM) is locked",
        _ => "Windows Hello reported an unknown error",
    }
}

fn bytes(buffer: &IBuffer) -> Result<Vec<u8>, String> {
    let mut array = windows::core::Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(buffer, &mut array)
        .map_err(|e| winrt("read a Windows buffer", e))?;
    Ok(array.to_vec())
}

/// Whether this account can use Windows Hello key credentials (no prompt).
pub fn is_supported() -> Result<bool, String> {
    KeyCredentialManager::IsSupportedAsync()
        .and_then(|operation| operation.get())
        .map_err(|e| winrt("KeyCredentialManager.IsSupportedAsync", e))
}

/// Creates the key `name` (Hello prompt). `replace` replaces a key of that
/// name in the Hello container; otherwise an existing one is an error.
pub fn create(name: &str, replace: bool) -> Result<HelloKey, String> {
    let option = if replace {
        KeyCredentialCreationOption::ReplaceExisting
    } else {
        KeyCredentialCreationOption::FailIfExists
    };
    let result = KeyCredentialManager::RequestCreateAsync(&HSTRING::from(name), option)
        .and_then(|operation| operation.get())
        .map_err(|e| winrt("KeyCredentialManager.RequestCreateAsync", e))?;
    let status = result
        .Status()
        .map_err(|e| winrt("KeyCredentialRetrievalResult.Status", e))?;
    if status != KeyCredentialStatus::Success {
        return Err(status_text(status).to_owned());
    }
    Ok(HelloKey {
        credential: result
            .Credential()
            .map_err(|e| winrt("KeyCredentialRetrievalResult.Credential", e))?,
    })
}

/// Opens the existing key `name` (no prompt until it signs).
pub fn open(name: &str) -> Result<HelloKey, String> {
    let result = KeyCredentialManager::OpenAsync(&HSTRING::from(name))
        .and_then(|operation| operation.get())
        .map_err(|e| winrt("KeyCredentialManager.OpenAsync", e))?;
    let status = result
        .Status()
        .map_err(|e| winrt("KeyCredentialRetrievalResult.Status", e))?;
    if status != KeyCredentialStatus::Success {
        return Err(status_text(status).to_owned());
    }
    Ok(HelloKey {
        credential: result
            .Credential()
            .map_err(|e| winrt("KeyCredentialRetrievalResult.Credential", e))?,
    })
}

/// Deletes the key `name` from the Hello container.
pub fn delete(name: &str) -> Result<(), String> {
    KeyCredentialManager::DeleteAsync(&HSTRING::from(name))
        .and_then(|operation| operation.get())
        .map_err(|e| winrt("KeyCredentialManager.DeleteAsync", e))
}

impl HelloKey {
    /// The public key as X.509 SubjectPublicKeyInfo DER.
    pub fn public_key_spki(&self) -> Result<Vec<u8>, String> {
        let buffer = self
            .credential
            .RetrievePublicKeyWithBlobType(CryptographicPublicKeyBlobType::X509SubjectPublicKeyInfo)
            .map_err(|e| winrt("KeyCredential.RetrievePublicKey", e))?;
        bytes(&buffer)
    }

    /// The TPM attestation and its certificate chain. An error when the
    /// hardware or Windows cannot attest the key: enrollment then stays
    /// refused (fail closed).
    pub fn attestation(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        let result = self
            .credential
            .GetAttestationAsync()
            .and_then(|operation| operation.get())
            .map_err(|e| winrt("KeyCredential.GetAttestationAsync", e))?;
        let status = result
            .Status()
            .map_err(|e| winrt("KeyCredentialAttestationResult.Status", e))?;
        match status {
            KeyCredentialAttestationStatus::Success => {}
            KeyCredentialAttestationStatus::NotSupported => {
                return Err("this PC cannot attest the key (no TPM attestation support)".to_owned())
            }
            KeyCredentialAttestationStatus::TemporaryFailure => {
                return Err(
                    "the key attestation is temporarily unavailable (Windows may still be obtaining the TPM's AIK certificate); try again later".to_owned(),
                )
            }
            _ => return Err("the key attestation failed".to_owned()),
        }
        let attestation = bytes(
            &result
                .AttestationBuffer()
                .map_err(|e| winrt("KeyCredentialAttestationResult.AttestationBuffer", e))?,
        )?;
        let chain = bytes(
            &result
                .CertificateChainBuffer()
                .map_err(|e| winrt("KeyCredentialAttestationResult.CertificateChainBuffer", e))?,
        )?;
        Ok((attestation, chain))
    }

    /// Signs `data` (Windows Hello prompt): RSASSA-PKCS1 v1.5 over SHA-256.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let buffer = CryptographicBuffer::CreateFromByteArray(data)
            .map_err(|e| winrt("CryptographicBuffer.CreateFromByteArray", e))?;
        let result = self
            .credential
            .RequestSignAsync(&buffer)
            .and_then(|operation| operation.get())
            .map_err(|e| winrt("KeyCredential.RequestSignAsync", e))?;
        let status = result
            .Status()
            .map_err(|e| winrt("KeyCredentialOperationResult.Status", e))?;
        if status != KeyCredentialStatus::Success {
            return Err(status_text(status).to_owned());
        }
        bytes(
            &result
                .Result()
                .map_err(|e| winrt("KeyCredentialOperationResult.Result", e))?,
        )
    }
}
