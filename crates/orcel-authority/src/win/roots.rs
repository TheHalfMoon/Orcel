//! SG-000132 slice 2: the pinned TPM attestation roots present on this PC.
//!
//! The chain `GetAttestationAsync` returns may stop below the root. The
//! service then looks for the root in the local machine's `CA` and `ROOT`
//! certificate stores (opened read-only) and keeps only certificates whose
//! SHA-256 is pinned in [`crate::attestation::PINNED_ROOTS`]: a certificate
//! someone added to a store is never trusted for its name alone.

use crate::attestation::PINNED_ROOTS;
use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertOpenStore, CERT_CONTEXT,
    CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG,
    CERT_SYSTEM_STORE_LOCAL_MACHINE_ID, CERT_SYSTEM_STORE_LOCATION_SHIFT,
};

/// `CERT_SYSTEM_STORE_LOCAL_MACHINE`.
const LOCAL_MACHINE: u32 = CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT;

/// The DER of every pinned root found in `LocalMachine\CA` and
/// `LocalMachine\ROOT`. Empty when none is present (enrollment is then
/// refused unless the chain itself carries the pinned root).
pub fn pinned_roots_on_this_pc() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for store in ["CA", "ROOT"] {
        let name = super::wide(store);
        // SAFETY: a read-only system store opened by name; closed below.
        let handle = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                0,
                0,
                LOCAL_MACHINE | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG,
                name.as_ptr().cast(),
            )
        };
        if handle.is_null() {
            continue;
        }
        let mut context: *const CERT_CONTEXT = std::ptr::null();
        loop {
            // SAFETY: enumeration frees the previous context and returns the
            // next one (or null at the end).
            context = unsafe { CertEnumCertificatesInStore(handle, context) };
            if context.is_null() {
                break;
            }
            // SAFETY: a live context holds `cbCertEncoded` bytes.
            let der = unsafe {
                let cert = &*context;
                std::slice::from_raw_parts(cert.pbCertEncoded, cert.cbCertEncoded as usize)
            };
            let digest = crate::sha256_hex(der);
            if PINNED_ROOTS.contains(&digest.as_str()) && !out.iter().any(|seen| seen == der) {
                out.push(der.to_vec());
            }
        }
        // SAFETY: opened above; closed once.
        unsafe { CertCloseStore(handle, 0) };
    }
    out
}
