//! `capabilities.get`.

use super::rules::{self, charset};
use super::{count_unknown, str_field, Field, Incompatible, Withheld};
use serde::Serialize;
use serde_json::Value;

/// At most this many capability rows are kept.
pub const MAX_CAPABILITIES: usize = 64;
/// An unavailable reason is cut to this many characters.
pub const MAX_REASON_CHARS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    pub os: Field<String>,
    pub capabilities: Vec<Capability>,
    pub withheld: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Capability {
    pub id: String,
    pub state: CapabilityState,
    /// Text-ruled, at most [`MAX_REASON_CHARS`] characters.
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Available,
    Unavailable,
}

fn id_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
}

fn os_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
}

/// One row, or `None` (dropped and counted by the caller) when its id or
/// state fails or its reason is neither null nor a string.
fn row(value: &Value, withheld: &mut Withheld) -> Option<Capability> {
    let object = value.as_object()?;
    let id = charset(object.get("id")?.as_str()?, 64, id_byte)?;
    let state = match object.get("state")?.as_str()? {
        "available" => CapabilityState::Available,
        "unavailable" => CapabilityState::Unavailable,
        _ => return None,
    };
    let reason = match object.get("reason") {
        None | Some(Value::Null) => None,
        Some(Value::String(reason)) => Some(rules::text(reason, MAX_REASON_CHARS)),
        Some(_) => return None,
    };
    count_unknown(object, &["id", "state", "reason"], &[], withheld);
    Some(Capability { id, state, reason })
}

/// Sanitises a `capabilities.get` result. `read_only` other than `true` is
/// [`Incompatible`]. `methods` and `reserved_methods` are not forwarded.
pub fn sanitize(value: &Value) -> Result<Capabilities, Incompatible> {
    let object = value.as_object().ok_or(Incompatible)?;
    if object.get("read_only") != Some(&Value::Bool(true)) {
        return Err(Incompatible);
    }
    let mut withheld = Withheld::default();
    count_unknown(
        object,
        &["os", "read_only", "capabilities"],
        &["methods", "reserved_methods"],
        &mut withheld,
    );
    let os = str_field(object.get("os"), |v| charset(v, 16, os_byte), &mut withheld);
    let mut capabilities = Vec::new();
    match object.get("capabilities") {
        Some(Value::Array(rows)) => {
            for value in rows {
                if capabilities.len() >= MAX_CAPABILITIES {
                    withheld.one();
                    continue;
                }
                let mut inner = Withheld::default();
                match row(value, &mut inner) {
                    Some(row) => {
                        withheld.add(inner.0 as usize);
                        capabilities.push(row);
                    }
                    None => withheld.one(),
                }
            }
        }
        None | Some(Value::Null) => {}
        Some(_) => withheld.one(),
    }
    Ok(Capabilities {
        os,
        capabilities,
        withheld: withheld.0,
    })
}
