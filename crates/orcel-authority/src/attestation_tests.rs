//! SG-000132 slice 2: the TPM key attestation check against test vectors.
//!
//! No real TPM attestation was recorded on the development PC (creating a
//! Windows Hello key there would prompt, which this work may not do). The
//! vectors below are built from CNG software RSA keys in the documented TPM
//! 2.0 and PCP layouts: a root CA, an AIK certificate with the TCG AIK usage,
//! a `PCP_KEY_ATTESTATION_BLOB` over a `TPM2_Certify` statement, and the
//! certified key's public area. One recorded vector is real: the Microsoft
//! TPM Root Certificate Authority 2014 from this PC's `LocalMachine\CA`
//! store, which must match the pinned SHA-256 and verify as self-signed.

use crate::attestation::{
    self, check_root, verify_with_pins, FIXED_PARENT, FIXED_TPM, RESTRICTED, SENSITIVE_DATA_ORIGIN,
    SIGN,
};
use crate::der::oid;
use crate::error::AuthorityError;
use crate::win::crypto::test_keys::SoftwareHelloKey;
use crate::win::crypto::CngRsaVerifier;
use sha2::{Digest, Sha256};

const NOW: u64 = 1_800_000_000_000;
/// sha256WithRSAEncryption with NULL parameters.
fn sha256_rsa() -> Vec<u8> {
    seq(&[tlv(0x06, oid::SHA256_WITH_RSA), tlv(0x05, &[])])
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn name(common_name: &str) -> Vec<u8> {
    let attribute = seq(&[
        tlv(0x06, &[0x55, 0x04, 0x03]),
        tlv(0x0c, common_name.as_bytes()),
    ]);
    seq(&[tlv(0x31, &attribute)])
}

fn extension(id: &[u8], critical: bool, value: Vec<u8>) -> Vec<u8> {
    let mut parts = vec![tlv(0x06, id)];
    if critical {
        parts.push(tlv(0x01, &[0xff]));
    }
    parts.push(tlv(0x04, &value));
    seq(&parts)
}

fn basic_constraints(ca: bool) -> Vec<u8> {
    let value = if ca {
        seq(&[tlv(0x01, &[0xff])])
    } else {
        seq(&[])
    };
    extension(oid::BASIC_CONSTRAINTS, true, value)
}

fn aik_usage() -> Vec<u8> {
    extension(
        oid::EXT_KEY_USAGE,
        false,
        seq(&[tlv(0x06, oid::TCG_KP_AIK_CERTIFICATE)]),
    )
}

/// A certificate for `subject_key` named `subject`, signed by `issuer_key`
/// as `issuer`.
fn certificate(
    serial: u8,
    issuer: &str,
    issuer_key: &SoftwareHelloKey,
    subject: &str,
    subject_key: &SoftwareHelloKey,
    not_after: &str,
    extensions: Vec<Vec<u8>>,
) -> Result<Vec<u8>, AuthorityError> {
    let tbs = seq(&[
        tlv(0xa0, &tlv(0x02, &[2])),
        tlv(0x02, &[serial]),
        sha256_rsa(),
        name(issuer),
        seq(&[tlv(0x17, b"200101000000Z"), tlv(0x18, not_after.as_bytes())]),
        name(subject),
        subject_key.spki()?,
        tlv(0xa3, &seq(&extensions)),
    ]);
    let signature = issuer_key.sign(&tbs)?;
    let mut bits = vec![0u8];
    bits.extend_from_slice(&signature);
    Ok(seq(&[tbs, sha256_rsa(), tlv(0x03, &bits)]))
}

fn be16(value: usize) -> [u8; 2] {
    (value as u16).to_be_bytes()
}

fn tpm2b(bytes: &[u8]) -> Vec<u8> {
    let mut out = be16(bytes.len()).to_vec();
    out.extend_from_slice(bytes);
    out
}

/// A `TPMT_PUBLIC` for an RSA key with `attributes`.
fn public_area(key: &SoftwareHelloKey, attributes: u32) -> Result<Vec<u8>, AuthorityError> {
    let (modulus, _) = crate::der::rsa_public_key(&key.spki()?)?;
    let mut out = Vec::new();
    out.extend_from_slice(&0x0001u16.to_be_bytes()); // TPM_ALG_RSA
    out.extend_from_slice(&0x000bu16.to_be_bytes()); // nameAlg SHA-256
    out.extend_from_slice(&attributes.to_be_bytes());
    out.extend_from_slice(&tpm2b(&[])); // authPolicy
    out.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric NULL
    out.extend_from_slice(&0x0010u16.to_be_bytes()); // scheme NULL
    out.extend_from_slice(&((modulus.len() * 8) as u16).to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // exponent: default 65537
    out.extend_from_slice(&tpm2b(&modulus));
    Ok(out)
}

/// A `TPMS_ATTEST` certifying `area`.
fn certify_statement(area: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut name = 0x000bu16.to_be_bytes().to_vec();
    name.extend_from_slice(&Sha256::digest(area));
    let mut out = Vec::new();
    out.extend_from_slice(&0xff54_4347u32.to_be_bytes());
    out.extend_from_slice(&0x8017u16.to_be_bytes());
    out.extend_from_slice(&tpm2b(b"qualified-signer"));
    out.extend_from_slice(&tpm2b(extra));
    out.extend_from_slice(&42u64.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&2u32.to_be_bytes());
    out.push(1);
    out.extend_from_slice(&7u64.to_be_bytes());
    out.extend_from_slice(&tpm2b(&name));
    out.extend_from_slice(&tpm2b(b"qualified-name"));
    out
}

/// A PCP key blob ("MPCP") whose public part is `TPM2B_PUBLIC(area)`.
fn pcp_key_blob(area: &[u8]) -> Vec<u8> {
    let public = tpm2b(area);
    let mut out = Vec::new();
    for value in [0x5043_504du32, 52, 0, 0, public.len() as u32] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.resize(52, 0);
    out.extend_from_slice(&public);
    out
}

fn kads(attest: &[u8], signature: &[u8], key_blob: &[u8], platform: u32) -> Vec<u8> {
    let mut out = Vec::new();
    for value in [
        0x5344_414bu32,
        platform,
        24,
        attest.len() as u32,
        signature.len() as u32,
        key_blob.len() as u32,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(attest);
    out.extend_from_slice(signature);
    out.extend_from_slice(key_blob);
    out
}

fn tpm_signature(aik: &SoftwareHelloKey, attest: &[u8]) -> Result<Vec<u8>, AuthorityError> {
    let mut out = 0x0014u16.to_be_bytes().to_vec();
    out.extend_from_slice(&0x000bu16.to_be_bytes());
    out.extend_from_slice(&tpm2b(&aik.sign(attest)?));
    Ok(out)
}

const GOOD: u32 = FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | SIGN | 0x0000_0040;

/// One complete set of vectors.
struct Vectors {
    hello: SoftwareHelloKey,
    root_der: Vec<u8>,
    aik_der: Vec<u8>,
    attestation: Vec<u8>,
    root_key: SoftwareHelloKey,
    aik: SoftwareHelloKey,
}

impl Vectors {
    fn new() -> Result<Self, AuthorityError> {
        let root_key = SoftwareHelloKey::generate(2048)?;
        let aik = SoftwareHelloKey::generate(2048)?;
        let hello = SoftwareHelloKey::generate(2048)?;
        let root_der = certificate(
            1,
            "Test TPM Root",
            &root_key,
            "Test TPM Root",
            &root_key,
            "20500101000000Z",
            vec![basic_constraints(true)],
        )?;
        let aik_der = certificate(
            2,
            "Test TPM Root",
            &root_key,
            "Test AIK",
            &aik,
            "20500101000000Z",
            vec![basic_constraints(false), aik_usage()],
        )?;
        let area = public_area(&hello, GOOD)?;
        let attest = certify_statement(&area, b"windows-nonce");
        let attestation = kads(
            &attest,
            &tpm_signature(&aik, &attest)?,
            &pcp_key_blob(&area),
            2,
        );
        Ok(Self {
            hello,
            root_der,
            aik_der,
            attestation,
            root_key,
            aik,
        })
    }

    fn pin(&self) -> String {
        crate::sha256_hex(&self.root_der)
    }

    fn chain(&self) -> Vec<u8> {
        [self.aik_der.clone(), self.root_der.clone()].concat()
    }

    fn check(&self, attestation: &[u8], chain: &[u8], now: u64) -> Result<String, AuthorityError> {
        let pin = self.pin();
        verify_with_pins(
            &self.hello.spki()?,
            attestation,
            chain,
            &[],
            &[pin.as_str()],
            now,
            &CngRsaVerifier,
        )
        .map(|report| report.root_sha256)
    }
}

fn refused(result: Result<String, AuthorityError>, needle: &str) -> Result<(), String> {
    match result {
        Ok(root) => Err(format!(
            "accepted (root {root}), expected refusal: {needle}"
        )),
        Err(error) if error.message.contains(needle) => Ok(()),
        Err(error) => Err(format!(
            "refused for another reason: {} (wanted {needle})",
            error.message
        )),
    }
}

#[test]
fn a_tpm_certified_hello_key_with_a_pinned_chain_verifies() -> Result<(), String> {
    let v = Vectors::new().map_err(|e| e.to_string())?;
    let root = v
        .check(&v.attestation, &v.chain(), NOW)
        .map_err(|e| e.to_string())?;
    assert_eq!(root, v.pin());
    // The root may come from this PC's store instead of the chain.
    let pin = v.pin();
    let report = verify_with_pins(
        &v.hello.spki().map_err(|e| e.to_string())?,
        &v.attestation,
        &v.aik_der,
        std::slice::from_ref(&v.root_der),
        &[pin.as_str()],
        NOW,
        &CngRsaVerifier,
    )
    .map_err(|e| e.to_string())?;
    assert_eq!(report.chain_length, 1);
    assert!(report
        .not_verified
        .iter()
        .any(|item| item.contains("gesture")));
    // A bare TPM2B_PUBLIC key blob is accepted too.
    let area = public_area(&v.hello, GOOD).map_err(|e| e.to_string())?;
    let attest = certify_statement(&area, b"n");
    let bare = kads(
        &attest,
        &tpm_signature(&v.aik, &attest).map_err(|e| e.to_string())?,
        &tpm2b(&area),
        2,
    );
    v.check(&bare, &v.chain(), NOW).map_err(|e| e.to_string())?;
    Ok(())
}

#[test]
fn the_attestation_must_be_about_the_enrolled_tpm_key() -> Result<(), String> {
    let v = Vectors::new().map_err(|e| e.to_string())?;
    let pin = v.pin();
    // Another key enrolled with this attestation.
    let stranger = SoftwareHelloKey::generate(2048).map_err(|e| e.to_string())?;
    refused(
        verify_with_pins(
            &stranger.spki().map_err(|e| e.to_string())?,
            &v.attestation,
            &v.chain(),
            &[],
            &[pin.as_str()],
            NOW,
            &CngRsaVerifier,
        )
        .map(|r| r.root_sha256),
        "not the key being enrolled",
    )?;
    // The statement certifies another public area than the blob carries.
    let area = public_area(&v.hello, GOOD).map_err(|e| e.to_string())?;
    let other_area = public_area(&stranger, GOOD).map_err(|e| e.to_string())?;
    let attest = certify_statement(&other_area, b"n");
    let swapped = kads(
        &attest,
        &tpm_signature(&v.aik, &attest).map_err(|e| e.to_string())?,
        &pcp_key_blob(&area),
        2,
    );
    refused(v.check(&swapped, &v.chain(), NOW), "certifies another key")?;
    // Exportable, not TPM-generated, restricted: refused.
    for attributes in [
        GOOD & !FIXED_TPM,
        GOOD & !FIXED_PARENT,
        GOOD & !SENSITIVE_DATA_ORIGIN,
        GOOD & !SIGN,
        GOOD | RESTRICTED,
    ] {
        let area = public_area(&v.hello, attributes).map_err(|e| e.to_string())?;
        let attest = certify_statement(&area, b"n");
        let blob = kads(
            &attest,
            &tpm_signature(&v.aik, &attest).map_err(|e| e.to_string())?,
            &pcp_key_blob(&area),
            2,
        );
        refused(v.check(&blob, &v.chain(), NOW), "non-exportable")?;
    }
    Ok(())
}

#[test]
fn the_statement_must_be_signed_by_an_aik_chaining_to_a_pinned_root() -> Result<(), String> {
    let v = Vectors::new().map_err(|e| e.to_string())?;
    // A changed statement no longer verifies under the AIK.
    let mut tampered = v.attestation.clone();
    let at = 24 + 12;
    tampered[at] ^= 0x01;
    refused(v.check(&tampered, &v.chain(), NOW), "AIK did not sign")?;
    // Signed by a key that is not the AIK.
    let area = public_area(&v.hello, GOOD).map_err(|e| e.to_string())?;
    let attest = certify_statement(&area, b"n");
    let forged = kads(
        &attest,
        &tpm_signature(&v.hello, &attest).map_err(|e| e.to_string())?,
        &pcp_key_blob(&area),
        2,
    );
    refused(v.check(&forged, &v.chain(), NOW), "AIK did not sign")?;
    // A leaf without the TCG AIK usage.
    let plain = certificate(
        3,
        "Test TPM Root",
        &v.root_key,
        "Test AIK",
        &v.aik,
        "20500101000000Z",
        vec![basic_constraints(false)],
    )
    .map_err(|e| e.to_string())?;
    refused(
        v.check(&v.attestation, &[plain, v.root_der.clone()].concat(), NOW),
        "not an AIK certificate",
    )?;
    // An unknown critical extension.
    let odd = certificate(
        4,
        "Test TPM Root",
        &v.root_key,
        "Test AIK",
        &v.aik,
        "20500101000000Z",
        vec![
            aik_usage(),
            extension(&[0x2a, 0x03, 0x04], true, vec![0x05, 0x00]),
        ],
    )
    .map_err(|e| e.to_string())?;
    refused(
        v.check(&v.attestation, &[odd, v.root_der.clone()].concat(), NOW),
        "unknown critical extension",
    )?;
    // Expired.
    let expired = certificate(
        5,
        "Test TPM Root",
        &v.root_key,
        "Test AIK",
        &v.aik,
        "20250101000000Z",
        vec![basic_constraints(false), aik_usage()],
    )
    .map_err(|e| e.to_string())?;
    refused(
        v.check(&v.attestation, &[expired, v.root_der.clone()].concat(), NOW),
        "not valid now",
    )?;
    // A root that is not pinned, or no root at all.
    let other_root_key = SoftwareHelloKey::generate(2048).map_err(|e| e.to_string())?;
    let other_root = certificate(
        6,
        "Test TPM Root",
        &other_root_key,
        "Test TPM Root",
        &other_root_key,
        "20500101000000Z",
        vec![basic_constraints(true)],
    )
    .map_err(|e| e.to_string())?;
    refused(
        v.check(
            &v.attestation,
            &[v.aik_der.clone(), other_root].concat(),
            NOW,
        ),
        "signature does not verify",
    )?;
    refused(v.check(&v.attestation, &v.aik_der, NOW), "pinned TPM root")?;
    // The real pin list does not trust the test root.
    refused(
        attestation::verify(
            &v.hello.spki().map_err(|e| e.to_string())?,
            &v.attestation,
            &v.chain(),
            &[],
            NOW,
            &CngRsaVerifier,
        )
        .map(|r| r.root_sha256),
        "pinned TPM root",
    )?;
    Ok(())
}

#[test]
fn malformed_blobs_are_refused() -> Result<(), String> {
    let v = Vectors::new().map_err(|e| e.to_string())?;
    refused(v.check(b"", &v.chain(), NOW), "empty or too large")?;
    let mut not_kads = v.attestation.clone();
    not_kads[0] = b'X';
    refused(v.check(&not_kads, &v.chain(), NOW), "KADS")?;
    let mut tpm12 = v.attestation.clone();
    tpm12[4] = 1;
    refused(v.check(&tpm12, &v.chain(), NOW), "TPM 2.0")?;
    let mut short = v.attestation.clone();
    short.pop();
    refused(v.check(&short, &v.chain(), NOW), "sizes do not match")?;
    refused(v.check(&v.attestation, b"not der", NOW), "malformed DER")?;
    Ok(())
}

/// The recorded real vector: the Microsoft TPM root on this PC, when the
/// store has it (Windows keeps it in `LocalMachine\CA` once a TPM has been
/// provisioned; a runner without it has nothing to check here).
#[test]
fn the_pinned_microsoft_tpm_root_on_this_pc_is_self_signed_and_current() -> Result<(), String> {
    let roots = crate::win::roots::pinned_roots_on_this_pc();
    for der in &roots {
        assert_eq!(
            crate::sha256_hex(der),
            attestation::MICROSOFT_TPM_ROOT_2014_SHA256
        );
        check_root(der, crate::now_ms(), &CngRsaVerifier).map_err(|e| e.to_string())?;
        let cert = crate::der::Certificate::parse(der).map_err(|e| e.to_string())?;
        assert_eq!(cert.is_ca().map_err(|e| e.to_string())?, Some(true));
    }
    if roots.is_empty() {
        eprintln!("no pinned TPM root on this machine; the real-root vector was not checked");
    }
    Ok(())
}
