//! A minimal, strict DER reader and the X.509 certificate fields the
//! attestation check needs (SG-000132 slice 2).
//!
//! Only definite lengths, single-byte tags and at most four length bytes are
//! accepted; anything else is refused. Nothing here trusts a certificate: it
//! only splits one into the parts [`crate::attestation`] checks.

use crate::error::AuthorityError;

pub const TAG_BOOLEAN: u8 = 0x01;
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OID: u8 = 0x06;
pub const TAG_UTC_TIME: u8 = 0x17;
pub const TAG_GENERALIZED_TIME: u8 = 0x18;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_SET: u8 = 0x31;
/// `[0]` constructed (the certificate version, explicit).
pub const TAG_CONTEXT_0: u8 = 0xa0;
/// `[1]` primitive (issuerUniqueID, implicit).
pub const TAG_CONTEXT_1_PRIMITIVE: u8 = 0x81;
/// `[2]` primitive (subjectUniqueID, implicit).
pub const TAG_CONTEXT_2_PRIMITIVE: u8 = 0x82;
/// `[3]` constructed (the extensions, explicit).
pub const TAG_CONTEXT_3: u8 = 0xa3;

/// Object identifiers, as the content bytes of their DER encoding.
pub mod oid {
    /// 1.2.840.113549.1.1.1 rsaEncryption.
    pub const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    /// 1.2.840.113549.1.1.11 sha256WithRSAEncryption.
    pub const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    /// 1.2.840.113549.1.1.12 sha384WithRSAEncryption.
    pub const SHA384_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
    /// 2.5.29.14 subjectKeyIdentifier.
    pub const SUBJECT_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x0e];
    /// 2.5.29.15 keyUsage.
    pub const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
    /// 2.5.29.17 subjectAltName.
    pub const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
    /// 2.5.29.19 basicConstraints.
    pub const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    /// 2.5.29.31 cRLDistributionPoints.
    pub const CRL_DISTRIBUTION_POINTS: &[u8] = &[0x55, 0x1d, 0x1f];
    /// 2.5.29.32 certificatePolicies.
    pub const CERTIFICATE_POLICIES: &[u8] = &[0x55, 0x1d, 0x20];
    /// 2.5.29.35 authorityKeyIdentifier.
    pub const AUTHORITY_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x23];
    /// 2.5.29.37 extKeyUsage.
    pub const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
    /// 1.3.6.1.5.5.7.1.1 authorityInfoAccess.
    pub const AUTHORITY_INFO_ACCESS: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
    /// 2.23.133.8.3 tcg-kp-AIKCertificate.
    pub const TCG_KP_AIK_CERTIFICATE: &[u8] = &[0x67, 0x81, 0x05, 0x08, 0x03];
}

fn malformed(what: &str) -> AuthorityError {
    AuthorityError::invalid(format!("malformed DER: {what}"))
}

/// One element: its tag, its content and its whole encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    pub raw: &'a [u8],
}

/// Reads consecutive elements from a byte slice.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// The next element, whatever its tag.
    pub fn read(&mut self) -> Result<Tlv<'a>, AuthorityError> {
        let start = self.pos;
        let tag = *self
            .data
            .get(start)
            .ok_or_else(|| malformed("missing tag"))?;
        if tag & 0x1f == 0x1f {
            return Err(malformed("multi-byte tags are not accepted"));
        }
        let first = *self
            .data
            .get(start + 1)
            .ok_or_else(|| malformed("missing length"))?;
        let (length, header) = if first < 0x80 {
            (usize::from(first), 2)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 {
                return Err(malformed("indefinite or oversized length"));
            }
            let bytes = self
                .data
                .get(start + 2..start + 2 + count)
                .ok_or_else(|| malformed("truncated length"))?;
            if bytes[0] == 0 {
                return Err(malformed("non-minimal length"));
            }
            let mut length = 0usize;
            for byte in bytes {
                length = (length << 8) | usize::from(*byte);
            }
            if length < 0x80 {
                return Err(malformed("non-minimal length"));
            }
            (length, 2 + count)
        };
        let end = start
            .checked_add(header)
            .and_then(|value_start| value_start.checked_add(length))
            .ok_or_else(|| malformed("length overflow"))?;
        if end > self.data.len() {
            return Err(malformed("truncated element"));
        }
        self.pos = end;
        Ok(Tlv {
            tag,
            value: &self.data[start + header..end],
            raw: &self.data[start..end],
        })
    }

    /// The next element, which must carry `tag`.
    pub fn expect(&mut self, tag: u8) -> Result<Tlv<'a>, AuthorityError> {
        let tlv = self.read()?;
        if tlv.tag != tag {
            return Err(malformed(&format!(
                "expected tag 0x{tag:02x}, found 0x{:02x}",
                tlv.tag
            )));
        }
        Ok(tlv)
    }

    /// The next element if it carries `tag`.
    pub fn optional(&mut self, tag: u8) -> Result<Option<Tlv<'a>>, AuthorityError> {
        if self.peek_tag() == Some(tag) {
            self.read().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Refuse trailing bytes.
    pub fn finish(&self) -> Result<(), AuthorityError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(malformed("trailing bytes"))
        }
    }
}

/// The unsigned magnitude of a DER INTEGER (leading zero bytes removed).
pub fn unsigned_integer(value: &[u8]) -> Result<&[u8], AuthorityError> {
    if value.is_empty() {
        return Err(malformed("empty integer"));
    }
    if value[0] & 0x80 != 0 {
        return Err(malformed("negative integer"));
    }
    let first = value.iter().position(|b| *b != 0).unwrap_or(value.len());
    Ok(&value[first..])
}

/// The content of a BIT STRING with no unused bits.
pub fn bit_string_bytes(value: &[u8]) -> Result<&[u8], AuthorityError> {
    match value.split_first() {
        Some((0, rest)) => Ok(rest),
        _ => Err(malformed("a bit string with unused bits")),
    }
}

/// Days from 1970-01-01 to a civil date (proleptic Gregorian).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn digits(text: &[u8]) -> Option<i64> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut value = 0i64;
    for byte in text {
        value = value * 10 + i64::from(byte - b'0');
    }
    Some(value)
}

/// A UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`) as
/// milliseconds since the Unix epoch. Fractions and offsets are refused.
pub fn time_ms(tlv: &Tlv<'_>) -> Result<i64, AuthorityError> {
    let text = tlv.value;
    let (year, rest) = match tlv.tag {
        TAG_UTC_TIME if text.len() == 13 => {
            let yy = digits(&text[..2]).ok_or_else(|| malformed("time"))?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &text[2..])
        }
        TAG_GENERALIZED_TIME if text.len() == 15 => (
            digits(&text[..4]).ok_or_else(|| malformed("time"))?,
            &text[4..],
        ),
        _ => return Err(malformed("time")),
    };
    if rest.last() != Some(&b'Z') {
        return Err(malformed("time without Z"));
    }
    let field =
        |range: std::ops::Range<usize>| digits(&rest[range]).ok_or_else(|| malformed("time"));
    let (month, day, hour, minute, second) = (
        field(0..2)?,
        field(2..4)?,
        field(4..6)?,
        field(6..8)?,
        field(8..10)?,
    );
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(malformed("time out of range"));
    }
    let days = days_from_civil(year, month, day);
    Ok(((days * 24 + hour) * 60 + minute) * 60_000 + second * 1_000)
}

/// One extension of a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extension<'a> {
    pub oid: &'a [u8],
    pub critical: bool,
    pub value: &'a [u8],
}

/// The parts of an X.509 certificate the attestation check uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate<'a> {
    pub der: &'a [u8],
    pub tbs: &'a [u8],
    pub signature_algorithm: &'a [u8],
    pub signature: &'a [u8],
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    pub not_before_ms: i64,
    pub not_after_ms: i64,
    /// The whole SubjectPublicKeyInfo element.
    pub spki: &'a [u8],
    pub extensions: Vec<Extension<'a>>,
}

fn algorithm_oid<'a>(tlv: &Tlv<'a>) -> Result<&'a [u8], AuthorityError> {
    let mut algorithm = Reader::new(tlv.value);
    let oid = algorithm.expect(TAG_OID)?.value;
    // Parameters: absent or NULL for the RSA algorithms accepted here.
    if let Some(params) = algorithm.optional(TAG_NULL)? {
        if !params.value.is_empty() {
            return Err(malformed("NULL parameters with content"));
        }
    }
    algorithm.finish()?;
    Ok(oid)
}

impl<'a> Certificate<'a> {
    /// Parse one certificate; `der` must be exactly one SEQUENCE.
    pub fn parse(der: &'a [u8]) -> Result<Self, AuthorityError> {
        let mut outer = Reader::new(der);
        let cert = outer.expect(TAG_SEQUENCE)?;
        outer.finish()?;
        let mut parts = Reader::new(cert.value);
        let tbs = parts.expect(TAG_SEQUENCE)?;
        let outer_algorithm = algorithm_oid(&parts.expect(TAG_SEQUENCE)?)?;
        let signature = bit_string_bytes(parts.expect(TAG_BIT_STRING)?.value)?;
        parts.finish()?;

        let mut fields = Reader::new(tbs.value);
        if let Some(version) = fields.optional(TAG_CONTEXT_0)? {
            let mut inner = Reader::new(version.value);
            let number = inner.expect(TAG_INTEGER)?;
            inner.finish()?;
            if number.value != [2] {
                return Err(AuthorityError::invalid(
                    "only X.509 version 3 certificates are accepted",
                ));
            }
        } else {
            return Err(AuthorityError::invalid(
                "only X.509 version 3 certificates are accepted",
            ));
        }
        fields.expect(TAG_INTEGER)?;
        let inner_algorithm = algorithm_oid(&fields.expect(TAG_SEQUENCE)?)?;
        if inner_algorithm != outer_algorithm {
            return Err(AuthorityError::invalid(
                "the certificate's two signature algorithms differ",
            ));
        }
        let issuer = fields.expect(TAG_SEQUENCE)?.raw;
        let validity = fields.expect(TAG_SEQUENCE)?;
        let mut times = Reader::new(validity.value);
        let not_before = times.read()?;
        let not_after = times.read()?;
        times.finish()?;
        let subject = fields.expect(TAG_SEQUENCE)?.raw;
        let spki = fields.expect(TAG_SEQUENCE)?.raw;
        fields.optional(TAG_CONTEXT_1_PRIMITIVE)?;
        fields.optional(TAG_CONTEXT_2_PRIMITIVE)?;
        let mut extensions = Vec::new();
        if let Some(explicit) = fields.optional(TAG_CONTEXT_3)? {
            let mut wrapper = Reader::new(explicit.value);
            let list = wrapper.expect(TAG_SEQUENCE)?;
            wrapper.finish()?;
            let mut items = Reader::new(list.value);
            while !items.is_empty() {
                let item = items.expect(TAG_SEQUENCE)?;
                let mut ext = Reader::new(item.value);
                let oid = ext.expect(TAG_OID)?.value;
                let critical = match ext.optional(TAG_BOOLEAN)? {
                    Some(flag) if flag.value == [0xff] => true,
                    Some(flag) if flag.value == [0x00] => false,
                    Some(_) => return Err(malformed("boolean")),
                    None => false,
                };
                let value = ext.expect(TAG_OCTET_STRING)?.value;
                ext.finish()?;
                if extensions.iter().any(|e: &Extension<'_>| e.oid == oid) {
                    return Err(AuthorityError::invalid("an extension appears twice"));
                }
                extensions.push(Extension {
                    oid,
                    critical,
                    value,
                });
            }
        }
        fields.finish()?;
        Ok(Self {
            der,
            tbs: tbs.raw,
            signature_algorithm: outer_algorithm,
            signature,
            issuer,
            subject,
            not_before_ms: time_ms(&not_before)?,
            not_after_ms: time_ms(&not_after)?,
            spki,
            extensions,
        })
    }

    pub fn extension(&self, oid: &[u8]) -> Option<&Extension<'a>> {
        self.extensions.iter().find(|ext| ext.oid == oid)
    }

    /// `basicConstraints` cA, or `None` when the extension is absent.
    pub fn is_ca(&self) -> Result<Option<bool>, AuthorityError> {
        let Some(ext) = self.extension(oid::BASIC_CONSTRAINTS) else {
            return Ok(None);
        };
        let mut outer = Reader::new(ext.value);
        let constraints = outer.expect(TAG_SEQUENCE)?;
        outer.finish()?;
        let mut fields = Reader::new(constraints.value);
        let ca = match fields.optional(TAG_BOOLEAN)? {
            Some(flag) if flag.value == [0xff] => true,
            Some(flag) if flag.value == [0x00] => false,
            Some(_) => return Err(malformed("boolean")),
            None => false,
        };
        fields.optional(TAG_INTEGER)?;
        fields.finish()?;
        Ok(Some(ca))
    }

    /// The extended key usage OIDs, or `None` when the extension is absent.
    pub fn extended_key_usages(&self) -> Result<Option<Vec<&'a [u8]>>, AuthorityError> {
        let Some(ext) = self.extension(oid::EXT_KEY_USAGE) else {
            return Ok(None);
        };
        let mut outer = Reader::new(ext.value);
        let list = outer.expect(TAG_SEQUENCE)?;
        outer.finish()?;
        let mut items = Reader::new(list.value);
        let mut out = Vec::new();
        while !items.is_empty() {
            out.push(items.expect(TAG_OID)?.value);
        }
        Ok(Some(out))
    }
}

/// An RSA public key from SubjectPublicKeyInfo DER: (modulus, exponent),
/// both unsigned big-endian without leading zeros.
pub fn rsa_public_key(spki: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AuthorityError> {
    let mut outer = Reader::new(spki);
    let info = outer.expect(TAG_SEQUENCE)?;
    outer.finish()?;
    let mut fields = Reader::new(info.value);
    let algorithm = algorithm_oid(&fields.expect(TAG_SEQUENCE)?)?;
    if algorithm != oid::RSA_ENCRYPTION {
        return Err(AuthorityError::invalid("the public key is not an RSA key"));
    }
    let key = bit_string_bytes(fields.expect(TAG_BIT_STRING)?.value)?;
    fields.finish()?;
    let mut key_reader = Reader::new(key);
    let sequence = key_reader.expect(TAG_SEQUENCE)?;
    key_reader.finish()?;
    let mut numbers = Reader::new(sequence.value);
    let modulus = unsigned_integer(numbers.expect(TAG_INTEGER)?.value)?.to_vec();
    let exponent = unsigned_integer(numbers.expect(TAG_INTEGER)?.value)?.to_vec();
    numbers.finish()?;
    if modulus.is_empty() || exponent.is_empty() {
        return Err(AuthorityError::invalid("an RSA key with a zero part"));
    }
    Ok((modulus, exponent))
}

/// Split a buffer of concatenated DER certificates.
pub fn split_certificates(buffer: &[u8]) -> Result<Vec<&[u8]>, AuthorityError> {
    let mut reader = Reader::new(buffer);
    let mut out = Vec::new();
    while !reader.is_empty() {
        let tlv = reader.expect(TAG_SEQUENCE)?;
        out.push(tlv.raw);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_are_definite_minimal_and_bounded() {
        assert_eq!(
            Reader::new(&[0x04, 0x02, 0xaa, 0xbb])
                .read()
                .map(|t| t.value.to_vec()),
            Ok(vec![0xaa, 0xbb])
        );
        // Indefinite, non-minimal, truncated and multi-byte tags.
        assert!(Reader::new(&[0x30, 0x80, 0x00, 0x00]).read().is_err());
        assert!(Reader::new(&[0x04, 0x81, 0x01, 0xaa]).read().is_err());
        assert!(Reader::new(&[0x04, 0x05, 0xaa]).read().is_err());
        assert!(Reader::new(&[0x1f, 0x01, 0x00]).read().is_err());
        assert!(Reader::new(&[0x04, 0x82, 0x00, 0x90]).read().is_err());
    }

    #[test]
    fn times_parse_in_both_forms() {
        let utc = Tlv {
            tag: TAG_UTC_TIME,
            value: b"141211003119Z",
            raw: &[],
        };
        // 2014-12-11T00:31:19Z.
        assert_eq!(time_ms(&utc), Ok(1_418_257_879_000));
        let generalized = Tlv {
            tag: TAG_GENERALIZED_TIME,
            value: b"20391211003928Z",
            raw: &[],
        };
        assert_eq!(time_ms(&generalized), Ok(2_207_176_768_000));
        let fraction = Tlv {
            tag: TAG_GENERALIZED_TIME,
            value: b"20391211003928.5Z",
            raw: &[],
        };
        assert!(time_ms(&fraction).is_err());
    }

    #[test]
    fn integers_are_unsigned_magnitudes() {
        assert_eq!(unsigned_integer(&[0x00, 0x80, 0x01]), Ok(&[0x80, 0x01][..]));
        assert!(unsigned_integer(&[0x80]).is_err());
        assert!(unsigned_integer(&[]).is_err());
    }
}
