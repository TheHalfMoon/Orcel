//! SG-000120 RJ-03: keyed fingerprints for the resume summary.
//!
//! A fingerprint is HMAC-SHA256 under a random 32-byte key kept beside the
//! report journal in orceld's private state root, over length-prefixed
//! identifying fields (paths, sizes, hashes, a session id). It lets a
//! client match a step to the request it sent without any value being
//! stored or derivable from the journal alone: without the key a guessed
//! input cannot be checked against a fingerprint.

use sha2::{Digest, Sha256};
use std::path::Path;

const KEY_BYTES: usize = 32;
const BLOCK_BYTES: usize = 64;

pub(crate) struct FingerprintKey([u8; KEY_BYTES]);

impl FingerprintKey {
    /// The key at `path`, created (owner-only, never replaced) when absent.
    /// Whoever loses a creation race adopts the winner's key.
    pub(crate) fn load_or_create(path: &Path) -> std::io::Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => Self::from_bytes(&bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let key = random_key()?;
                match orcel_platform::files::write_private_new(path, &key) {
                    Ok(()) => Ok(Self(key)),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        Self::from_bytes(&std::fs::read(path)?)
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }

    /// A key for this process only (a registry without a journal).
    pub(crate) fn ephemeral() -> std::io::Result<Self> {
        random_key().map(Self)
    }

    fn from_bytes(bytes: &[u8]) -> std::io::Result<Self> {
        let key: [u8; KEY_BYTES] = bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the resume fingerprint key has the wrong length",
            )
        })?;
        Ok(Self(key))
    }

    /// The keyed fingerprint of `fields` under `label`, as lowercase hex.
    pub(crate) fn fingerprint(&self, label: &str, fields: &[&str]) -> String {
        let mut message = Vec::new();
        for field in std::iter::once(label).chain(fields.iter().copied()) {
            message.extend_from_slice(&(field.len() as u64).to_be_bytes());
            message.extend_from_slice(field.as_bytes());
        }
        hmac_sha256(&self.0, &message)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

fn hmac_sha256(key: &[u8; KEY_BYTES], message: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; BLOCK_BYTES];
    padded[..KEY_BYTES].copy_from_slice(key);
    let mut inner = Sha256::new();
    inner.update(padded.map(|byte| byte ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(padded.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

#[cfg(windows)]
fn random_key() -> std::io::Result<[u8; KEY_BYTES]> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let mut key = [0u8; KEY_BYTES];
    // SAFETY: the buffer is a live, writable array of exactly the length
    // passed; a null algorithm handle is valid with the system-preferred
    // RNG flag.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            key.as_mut_ptr(),
            KEY_BYTES as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(std::io::Error::other(
            "the Windows CSPRNG could not create the resume fingerprint key",
        ));
    }
    Ok(key)
}

#[cfg(not(windows))]
fn random_key() -> std::io::Result<[u8; KEY_BYTES]> {
    use std::io::Read as _;
    let mut key = [0u8; KEY_BYTES];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut key)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rj03_hmac_matches_rfc_4231_case_2_shape_and_keys_differ() {
        // RFC 4231 test case 2 uses a 4-byte key; pad it into the fixed
        // 32-byte key (zero padding is what HMAC itself does).
        let mut key = [0u8; KEY_BYTES];
        key[..4].copy_from_slice(b"Jefe");
        let mac = hmac_sha256(&key, b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let one = FingerprintKey::ephemeral().unwrap();
        let two = FingerprintKey::ephemeral().unwrap();
        assert_ne!(
            one.fingerprint("session", &["s"]),
            two.fingerprint("session", &["s"])
        );
        assert_ne!(
            one.fingerprint("session", &["ab", "c"]),
            one.fingerprint("session", &["a", "bc"]),
            "fields are length-prefixed"
        );
    }

    #[test]
    fn rj03_a_stored_key_is_reused_and_never_replaced() {
        let dir = std::env::temp_dir().join(format!(
            "orceld-rj03-key-{}-{}",
            std::process::id(),
            orcel_approval::now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report-tasks.key");
        let first = FingerprintKey::load_or_create(&path).unwrap();
        let again = FingerprintKey::load_or_create(&path).unwrap();
        assert_eq!(
            first.fingerprint("x", &["y"]),
            again.fingerprint("x", &["y"])
        );
        std::fs::write(&path, b"short").unwrap();
        assert!(
            FingerprintKey::load_or_create(&path).is_err(),
            "fails closed"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
