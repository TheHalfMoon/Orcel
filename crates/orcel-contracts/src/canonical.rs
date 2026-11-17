//! Canonical JSON for contracts v1 digests (spec section 4.0).
//!
//! RFC 8785 (JCS) for the integer-only subset the contracts use: UTF-8
//! output, object keys sorted by their UTF-16 code units, no insignificant
//! whitespace, strings with minimal escaping, and integers written without
//! exponent. Integers are bounded to the IEEE 754 exact range
//! (`-(2^53 - 1)` to `2^53 - 1`), so every value has the same canonical form
//! in Rust, JavaScript and any other JCS implementation; anything else
//! (floats, larger integers) is refused rather than given an encoding that
//! another implementation would not reproduce. Only the new contracts' digests (`spec_digest`, `action_digest`,
//! the audit `digest`) use it. The SG-000093 lease identifiers and binding
//! digests, the SG-000018/SG-000019 approval digests and the SG-000040
//! approval digest keep their own domain-separated encodings and must never
//! be recomputed through this function.
//!
//! This crate holds no hash implementation: callers hash the returned bytes
//! with SHA-256 themselves.

use serde::Serialize;
use serde_json::Value;
use std::fmt;

/// Largest integer magnitude canonical JSON accepts: `2^53 - 1`.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalJsonError {
    /// A number that is not an integer. Contract digests cover integers
    /// only, so a float is refused rather than given an ambiguous encoding.
    NonIntegerNumber,
    /// An integer outside `-(2^53 - 1)..=2^53 - 1`, which JCS
    /// implementations based on IEEE 754 doubles cannot reproduce exactly.
    IntegerOutOfRange,
    /// The value could not be converted to JSON.
    Unserializable(String),
}

impl fmt::Display for CanonicalJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonIntegerNumber => f.write_str("canonical JSON refuses non-integer numbers"),
            Self::IntegerOutOfRange => {
                f.write_str("canonical JSON refuses integers beyond 2^53 - 1 in magnitude")
            }
            Self::Unserializable(message) => write!(f, "value is not serializable: {message}"),
        }
    }
}

impl std::error::Error for CanonicalJsonError {}

/// Canonical JSON text of any serializable value.
pub fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<String, CanonicalJsonError> {
    let value = serde_json::to_value(value)
        .map_err(|error| CanonicalJsonError::Unserializable(error.to_string()))?;
    canonical_json_value(&value)
}

/// Canonical JSON text of a JSON value.
pub fn canonical_json_value(value: &Value) -> Result<String, CanonicalJsonError> {
    let mut out = String::new();
    write_value(&mut out, value)?;
    Ok(out)
}

fn write_value(out: &mut String, value: &Value) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => {
            if let Some(unsigned) = number.as_u64() {
                if unsigned > MAX_SAFE_INTEGER {
                    return Err(CanonicalJsonError::IntegerOutOfRange);
                }
                out.push_str(&unsigned.to_string());
            } else if let Some(signed) = number.as_i64() {
                if signed.unsigned_abs() > MAX_SAFE_INTEGER {
                    return Err(CanonicalJsonError::IntegerOutOfRange);
                }
                out.push_str(&signed.to_string());
            } else {
                return Err(CanonicalJsonError::NonIntegerNumber);
            }
        }
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Sort explicitly by UTF-16 code units (RFC 8785 section
            // 3.2.3): serde_json's map order depends on a crate feature,
            // and Rust's byte order differs from UTF-16 order for keys
            // with characters above U+FFFF.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, &map[key])?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}
