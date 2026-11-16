//! Canonical JSON for contracts v1 digests (spec section 4.0).
//!
//! UTF-8, object keys sorted by code point, no insignificant whitespace,
//! integers without exponent and strings with minimal escaping (RFC 8785
//! style). Only the new contracts' digests (`spec_digest`, `action_digest`,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalJsonError {
    /// A number that is not an integer representable as `i64` or `u64`.
    /// Contract digests cover integers only, so a float is refused rather
    /// than given an ambiguous encoding.
    NonIntegerNumber,
    /// The value could not be converted to JSON.
    Unserializable(String),
}

impl fmt::Display for CanonicalJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonIntegerNumber => f.write_str("canonical JSON refuses non-integer numbers"),
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
                out.push_str(&unsigned.to_string());
            } else if let Some(signed) = number.as_i64() {
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
            // Sort explicitly: serde_json's map order depends on a crate
            // feature that another workspace member could enable. Rust
            // string order is byte order, which for UTF-8 is code point
            // order.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
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
