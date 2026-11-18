//! SG-000132 slice 2: the TPM key attestation check behind enrollment.
//!
//! `orcel authority enroll` sends the Windows Hello key credential's public
//! key (SubjectPublicKeyInfo DER, RSA) and what
//! `KeyCredential.GetAttestationAsync()` returned: the attestation buffer and
//! the certificate chain buffer. Enrollment is refused unless every check
//! below passes (fail closed).
//!
//! What is verified:
//!
//! 1. The attestation buffer is a `PCP_KEY_ATTESTATION_BLOB` ("KADS", TPM
//!    2.0): a `TPMS_ATTEST` of type `TPM_ST_ATTEST_CERTIFY` with the TPM's
//!    `TPM_GENERATED_VALUE`, its `TPMT_SIGNATURE` (RSASSA, SHA-256 or
//!    SHA-384) and the key's public area (inside a "MPCP" PCP key blob, or a
//!    bare `TPM2B_PUBLIC`).
//! 2. The certified key's TPM name (`nameAlg || H(TPMT_PUBLIC)`, SHA-256 or
//!    SHA-384) equals the name in the `TPMS_ATTEST`, so the attestation is
//!    about exactly that public area.
//! 3. That public area is an RSA key whose modulus and exponent equal the
//!    enrolled SubjectPublicKeyInfo, and whose attributes say `fixedTPM`,
//!    `fixedParent`, `sensitiveDataOrigin` and `sign`, not `restricted`: the
//!    private key was generated in the TPM and can never leave it.
//! 4. The `TPMS_ATTEST` is signed by the leaf certificate's RSA key (the
//!    AIK), whose certificate carries the TCG AIK extended key usage
//!    (2.23.133.8.3) and is not a CA.
//! 5. Each certificate is signed (RSA PKCS#1 v1.5, SHA-256 or SHA-384) by
//!    the next, every issuer is a CA, every certificate is valid now, no
//!    unknown extension is critical, and the chain ends at a pinned root
//!    (by SHA-256 of its DER): the root is in the chain, or the last
//!    certificate is issued by a pinned root found on this PC.
//!
//! What cannot be verified from the attestation (recorded in
//! SG132_SLICE2.md): that the key needs a Windows Hello gesture (a property
//! of KeyCredentialManager keys that the attestation does not state; the
//! service's challenge signature at enrollment is the evidence a gesture
//! signed once), and freshness (`GetAttestationAsync` takes no nonce, so the
//! `extraData` is not the service's). No real TPM output was recorded on the
//! development PC (a Hello prompt was not allowed there): the parser follows
//! the PCP structures documented for TPM 2.0 key attestation, and any
//! difference in a real buffer refuses enrollment rather than accepting it.

use crate::der::{self, oid, Certificate};
use crate::error::AuthorityError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};

/// SHA-256 of the DER of the Microsoft TPM Root Certificate Authority 2014
/// (the root of the AIK certificates Windows obtains for its TPM). Read from
/// this PC's `LocalMachine\CA` store on 2026-11-18 (SHA-1 thumbprint
/// D4FFDB19BA590FFFAA34DB5F4B568706A2978436); the founder checks it against
/// Microsoft's published root before the first enrollment.
pub const MICROSOFT_TPM_ROOT_2014_SHA256: &str =
    "870c7a35ceab3d59979f2c6a524042d404cb71518004350925fb2ced79a999da";

/// Every pinned root, by SHA-256 of its DER.
pub const PINNED_ROOTS: [&str; 1] = [MICROSOFT_TPM_ROOT_2014_SHA256];

/// Bounds on what an enrollment may carry.
pub const MAX_ATTESTATION_BYTES: usize = 8 * 1024;
pub const MAX_CHAIN_BYTES: usize = 24 * 1024;
pub const MAX_CHAIN_CERTIFICATES: usize = 5;

const KADS_MAGIC: u32 = 0x5344_414b;
const MPCP_MAGIC: u32 = 0x5043_504d;
const TPM_VERSION_20: u32 = 2;
const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
const TPM_ST_ATTEST_CERTIFY: u16 = 0x8017;
const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_SHA384: u16 = 0x000c;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_RSASSA: u16 = 0x0014;

/// `TPMA_OBJECT` bits.
pub const FIXED_TPM: u32 = 0x0000_0002;
pub const FIXED_PARENT: u32 = 0x0000_0010;
pub const SENSITIVE_DATA_ORIGIN: u32 = 0x0000_0020;
pub const RESTRICTED: u32 = 0x0001_0000;
pub const SIGN: u32 = 0x0004_0000;

/// A hash an RSA PKCS#1 v1.5 signature is made over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha384,
}

impl Hash {
    pub fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(message).to_vec(),
            Self::Sha384 => Sha384::digest(message).to_vec(),
        }
    }

    fn from_tpm(alg: u16) -> Option<Self> {
        match alg {
            TPM_ALG_SHA256 => Some(Self::Sha256),
            TPM_ALG_SHA384 => Some(Self::Sha384),
            _ => None,
        }
    }

    fn from_signature_oid(algorithm: &[u8]) -> Option<Self> {
        if algorithm == oid::SHA256_WITH_RSA {
            Some(Self::Sha256)
        } else if algorithm == oid::SHA384_WITH_RSA {
            Some(Self::Sha384)
        } else {
            None
        }
    }
}

/// Checks RSA PKCS#1 v1.5 signatures with a SubjectPublicKeyInfo key (CNG
/// on Windows; a software stand-in is never used outside tests).
pub trait RsaVerifier {
    fn verify(
        &self,
        spki_der: &[u8],
        hash: Hash,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), AuthorityError>;
}

/// What a passed check found, kept with the enrolled key and in the audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationReport {
    pub format: String,
    /// SHA-256 of the pinned root the chain ends at.
    pub root_sha256: String,
    /// SHA-256 of the AIK certificate.
    pub aik_certificate_sha256: String,
    pub chain_length: usize,
    pub name_alg: String,
    pub object_attributes: u32,
    pub verified: Vec<String>,
    pub not_verified: Vec<String>,
}

fn refused(message: impl Into<String>) -> AuthorityError {
    AuthorityError::denied(format!("key attestation refused: {}", message.into()))
}

/// A big-endian cursor over TPM structures.
struct Tpm<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Tpm<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], AuthorityError> {
        let end = self
            .pos
            .checked_add(count)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| refused("a TPM structure is truncated"))?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, AuthorityError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, AuthorityError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, AuthorityError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, AuthorityError> {
        let high = u64::from(self.u32()?);
        let low = u64::from(self.u32()?);
        Ok((high << 32) | low)
    }

    /// A `TPM2B_*`: a 16-bit size, then that many bytes.
    fn sized(&mut self) -> Result<&'a [u8], AuthorityError> {
        let size = usize::from(self.u16()?);
        self.take(size)
    }

    fn finish(&self) -> Result<(), AuthorityError> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(refused("a TPM structure has trailing bytes"))
        }
    }
}

fn le_u32(bytes: &[u8], at: usize) -> Result<u32, AuthorityError> {
    bytes
        .get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| refused("a blob header is truncated"))
}

/// The three parts of a `PCP_KEY_ATTESTATION_BLOB`.
struct KeyAttestation<'a> {
    attest: &'a [u8],
    signature: &'a [u8],
    key_blob: &'a [u8],
}

fn split_kads(buffer: &[u8]) -> Result<KeyAttestation<'_>, AuthorityError> {
    if le_u32(buffer, 0)? != KADS_MAGIC {
        return Err(refused(
            "the attestation is not a PCP key attestation blob (KADS)",
        ));
    }
    if le_u32(buffer, 4)? != TPM_VERSION_20 {
        return Err(refused("the attestation is not from a TPM 2.0"));
    }
    let header = le_u32(buffer, 8)? as usize;
    let attest_len = le_u32(buffer, 12)? as usize;
    let signature_len = le_u32(buffer, 16)? as usize;
    let key_len = le_u32(buffer, 20)? as usize;
    if header < 24 {
        return Err(refused("the attestation header is too short"));
    }
    let total = header
        .checked_add(attest_len)
        .and_then(|n| n.checked_add(signature_len))
        .and_then(|n| n.checked_add(key_len))
        .ok_or_else(|| refused("the attestation sizes overflow"))?;
    if total != buffer.len() || attest_len == 0 || signature_len == 0 || key_len == 0 {
        return Err(refused("the attestation sizes do not match the buffer"));
    }
    let attest_end = header + attest_len;
    let signature_end = attest_end + signature_len;
    Ok(KeyAttestation {
        attest: &buffer[header..attest_end],
        signature: &buffer[attest_end..signature_end],
        key_blob: &buffer[signature_end..],
    })
}

/// The `TPMT_PUBLIC` inside the key blob: a "MPCP" PCP key blob whose
/// public part is a `TPM2B_PUBLIC`, or a bare `TPM2B_PUBLIC`.
fn public_area(key_blob: &[u8]) -> Result<&[u8], AuthorityError> {
    let tpm2b = if le_u32(key_blob, 0)? == MPCP_MAGIC {
        let header = le_u32(key_blob, 4)? as usize;
        let public_len = le_u32(key_blob, 16)? as usize;
        key_blob
            .get(header..header.saturating_add(public_len))
            .ok_or_else(|| refused("the PCP key blob's public part is out of bounds"))?
    } else {
        key_blob
    };
    let mut reader = Tpm::new(tpm2b);
    let area = reader.sized()?;
    reader.finish()?;
    Ok(area)
}

/// The RSA key and attributes of a `TPMT_PUBLIC`.
struct RsaPublicArea {
    name_alg: u16,
    attributes: u32,
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

fn parse_public_area(area: &[u8]) -> Result<RsaPublicArea, AuthorityError> {
    let mut reader = Tpm::new(area);
    if reader.u16()? != TPM_ALG_RSA {
        return Err(refused("the attested key is not an RSA key"));
    }
    let name_alg = reader.u16()?;
    let attributes = reader.u32()?;
    reader.sized()?; // authPolicy
    let symmetric = reader.u16()?;
    if symmetric != TPM_ALG_NULL {
        reader.u16()?;
        reader.u16()?;
    }
    let scheme = reader.u16()?;
    if scheme != TPM_ALG_NULL {
        reader.u16()?;
    }
    let bits = reader.u16()?;
    let exponent = reader.u32()?;
    let modulus = reader.sized()?;
    reader.finish()?;
    if usize::from(bits) != modulus.len() * 8 || bits < 2048 {
        return Err(refused(
            "the attested RSA key is shorter than 2048 bits or inconsistent",
        ));
    }
    let exponent = if exponent == 0 { 65_537 } else { exponent };
    let exponent_bytes: Vec<u8> = exponent
        .to_be_bytes()
        .iter()
        .copied()
        .skip_while(|b| *b == 0)
        .collect();
    let first = modulus
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(modulus.len());
    Ok(RsaPublicArea {
        name_alg,
        attributes,
        modulus: modulus[first..].to_vec(),
        exponent: exponent_bytes,
    })
}

/// The certified name from a `TPMS_ATTEST` of type certify.
fn certified_name(attest: &[u8]) -> Result<&[u8], AuthorityError> {
    let mut reader = Tpm::new(attest);
    if reader.u32()? != TPM_GENERATED_VALUE {
        return Err(refused("the attestation was not generated by a TPM"));
    }
    if reader.u16()? != TPM_ST_ATTEST_CERTIFY {
        return Err(refused("the attestation is not a TPM2_Certify statement"));
    }
    reader.sized()?; // qualifiedSigner
    reader.sized()?; // extraData
    reader.u64()?; // clock
    reader.u32()?; // resetCount
    reader.u32()?; // restartCount
    reader.u8()?; // safe
    reader.u64()?; // firmwareVersion
    let name = reader.sized()?;
    reader.sized()?; // qualifiedName
    reader.finish()?;
    Ok(name)
}

/// The hash and bytes of a `TPMT_SIGNATURE` (RSASSA only).
fn tpm_signature(signature: &[u8]) -> Result<(Hash, &[u8]), AuthorityError> {
    let mut reader = Tpm::new(signature);
    if reader.u16()? != TPM_ALG_RSASSA {
        return Err(refused(
            "the attestation signature is not RSASSA-PKCS1-v1_5",
        ));
    }
    let hash = Hash::from_tpm(reader.u16()?)
        .ok_or_else(|| refused("the attestation signature hash is not SHA-256 or SHA-384"))?;
    let bytes = reader.sized()?;
    reader.finish()?;
    Ok((hash, bytes))
}

fn known_extension(oid: &[u8]) -> bool {
    [
        oid::SUBJECT_KEY_IDENTIFIER,
        oid::KEY_USAGE,
        oid::SUBJECT_ALT_NAME,
        oid::BASIC_CONSTRAINTS,
        oid::CRL_DISTRIBUTION_POINTS,
        oid::CERTIFICATE_POLICIES,
        oid::AUTHORITY_KEY_IDENTIFIER,
        oid::EXT_KEY_USAGE,
        oid::AUTHORITY_INFO_ACCESS,
    ]
    .contains(&oid)
}

fn check_certificate(
    cert: &Certificate<'_>,
    now_ms: u64,
    what: &str,
) -> Result<(), AuthorityError> {
    let now = i64::try_from(now_ms).unwrap_or(i64::MAX);
    if now < cert.not_before_ms || now > cert.not_after_ms {
        return Err(refused(format!("the {what} certificate is not valid now")));
    }
    if cert
        .extensions
        .iter()
        .any(|ext| ext.critical && !known_extension(ext.oid))
    {
        return Err(refused(format!(
            "the {what} certificate has an unknown critical extension"
        )));
    }
    Ok(())
}

/// `child` was signed by `issuer`, whose subject is the child's issuer and
/// which is a CA.
fn check_issued_by(
    child: &Certificate<'_>,
    issuer: &Certificate<'_>,
    rsa: &dyn RsaVerifier,
) -> Result<(), AuthorityError> {
    if child.issuer != issuer.subject {
        return Err(refused(
            "a certificate's issuer is not the next certificate's subject",
        ));
    }
    if issuer.is_ca()? != Some(true) {
        return Err(refused("an issuing certificate is not a CA"));
    }
    let hash = Hash::from_signature_oid(child.signature_algorithm)
        .ok_or_else(|| refused("a certificate is not signed with sha256RSA or sha384RSA"))?;
    rsa.verify(issuer.spki, hash, child.tbs, child.signature)
        .map_err(|_| refused("a certificate signature does not verify"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    crate::sha256_hex(bytes)
}

/// A pinned root on its own: parses, is valid now, and signed itself.
pub fn check_root(der: &[u8], now_ms: u64, rsa: &dyn RsaVerifier) -> Result<(), AuthorityError> {
    let root = Certificate::parse(der)?;
    check_certificate(&root, now_ms, "root")?;
    check_issued_by(&root, &root, rsa)
}

/// Verify an enrollment's attestation. `roots` holds the DER of pinned roots
/// found on this PC (each is checked against [`PINNED_ROOTS`] here too).
pub fn verify(
    spki: &[u8],
    attestation: &[u8],
    chain: &[u8],
    roots: &[Vec<u8>],
    now_ms: u64,
    rsa: &dyn RsaVerifier,
) -> Result<AttestationReport, AuthorityError> {
    verify_with_pins(spki, attestation, chain, roots, &PINNED_ROOTS, now_ms, rsa)
}

/// [`verify`] against an explicit pin list (tests pin their own root).
pub fn verify_with_pins(
    spki: &[u8],
    attestation: &[u8],
    chain: &[u8],
    roots: &[Vec<u8>],
    pins: &[&str],
    now_ms: u64,
    rsa: &dyn RsaVerifier,
) -> Result<AttestationReport, AuthorityError> {
    if attestation.is_empty() || attestation.len() > MAX_ATTESTATION_BYTES {
        return Err(refused("the attestation is empty or too large"));
    }
    if chain.is_empty() || chain.len() > MAX_CHAIN_BYTES {
        return Err(refused("the certificate chain is empty or too large"));
    }
    // 1. The blob and its parts.
    let parts = split_kads(attestation)?;
    let name = certified_name(parts.attest)?;
    let (attest_hash, attest_signature) = tpm_signature(parts.signature)?;
    let area_bytes = public_area(parts.key_blob)?;
    let area = parse_public_area(area_bytes)?;
    // 2. The certified name is this public area's.
    let name_hash = Hash::from_tpm(area.name_alg)
        .ok_or_else(|| refused("the key's name algorithm is not SHA-256 or SHA-384"))?;
    let mut expected_name = area.name_alg.to_be_bytes().to_vec();
    expected_name.extend_from_slice(&name_hash.digest(area_bytes));
    if name != expected_name.as_slice() {
        return Err(refused("the attestation certifies another key"));
    }
    // 3. It is the enrolled key, generated in and bound to the TPM.
    let (modulus, exponent) = der::rsa_public_key(spki)?;
    if modulus != area.modulus || exponent != area.exponent {
        return Err(refused("the attested key is not the key being enrolled"));
    }
    let required = FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | SIGN;
    if area.attributes & required != required || area.attributes & RESTRICTED != 0 {
        return Err(refused(
            "the attested key is not a non-exportable, TPM-generated signing key",
        ));
    }
    // 4. The AIK signed the statement.
    let ders = der::split_certificates(chain)?;
    if ders.is_empty() || ders.len() > MAX_CHAIN_CERTIFICATES {
        return Err(refused(
            "the certificate chain has no or too many certificates",
        ));
    }
    let certs = ders
        .iter()
        .map(|der| Certificate::parse(der))
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = &certs[0];
    check_certificate(leaf, now_ms, "AIK")?;
    if leaf.is_ca()? == Some(true) {
        return Err(refused("the AIK certificate is a CA"));
    }
    let usages = leaf.extended_key_usages()?.unwrap_or_default();
    if !usages.contains(&oid::TCG_KP_AIK_CERTIFICATE) {
        return Err(refused("the leaf certificate is not an AIK certificate"));
    }
    rsa.verify(leaf.spki, attest_hash, parts.attest, attest_signature)
        .map_err(|_| refused("the AIK did not sign this attestation"))?;
    // 5. The chain up to a pinned root.
    for pair in certs.windows(2) {
        check_certificate(&pair[1], now_ms, "intermediate")?;
        check_issued_by(&pair[0], &pair[1], rsa)?;
    }
    let last = &certs[certs.len() - 1];
    let pinned = |der: &[u8]| pins.contains(&sha256_hex(der).as_str());
    let root_der: Vec<u8> = if pinned(last.der) {
        last.der.to_vec()
    } else {
        let candidates: Vec<Certificate<'_>> = roots
            .iter()
            .filter(|der| pinned(der))
            .filter_map(|der| Certificate::parse(der).ok())
            .collect();
        let root = candidates
            .iter()
            .find(|root| root.subject == last.issuer)
            .ok_or_else(|| refused("the chain does not end at a pinned TPM root"))?;
        check_issued_by(last, root, rsa)?;
        root.der.to_vec()
    };
    check_root(&root_der, now_ms, rsa)?;
    Ok(AttestationReport {
        format: "pcp-key-attestation/tpm2".to_owned(),
        root_sha256: sha256_hex(&root_der),
        aik_certificate_sha256: sha256_hex(leaf.der),
        chain_length: certs.len(),
        name_alg: if name_hash == Hash::Sha256 {
            "sha256"
        } else {
            "sha384"
        }
        .to_owned(),
        object_attributes: area.attributes,
        verified: [
            "TPM2_Certify statement generated by a TPM",
            "certified name equals the key's public area",
            "public area equals the enrolled public key",
            "fixedTPM, fixedParent, sensitiveDataOrigin, sign; not restricted",
            "statement signed by the AIK certificate's key (TCG AIK usage)",
            "certificate chain signatures, CA flags and validity up to a pinned root",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect(),
        not_verified: [
            "that the key requires a Windows Hello gesture (not stated by the attestation)",
            "freshness: GetAttestationAsync takes no service nonce",
            "revocation of the AIK or intermediate certificates (no CRL or OCSP is fetched)",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect(),
    })
}
