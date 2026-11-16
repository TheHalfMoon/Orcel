//! The closed sanitiser (SG-000119 packet, "The sanitiser: nothing reaches
//! the web view unshaped"). Every answer and event orceld sends is read field
//! by field into the types below and only those types are ever serialized for
//! the web view. A field that is not named here never reaches it.
//!
//! Counting. Each output carries `withheld`, the number of things the window
//! reports as "n fields withheld": a field orceld sent that this sanitiser
//! does not know (including one orceld adds later), a named field whose value
//! failed its rule, and a record, entry, event or event kind that was
//! dropped. Fields the packet drops by name (`pid`, `endpoint`, `peer`,
//! `endpoint_wait.reason`, the endpoint-in-use `reason`, `request_id`, the
//! task `title`, `methods`, `reserved_methods`, `max_tasks`, the check's
//! `reason`) are policy, not surprises: they are dropped without being
//! counted, so the count means "something unexpected was withheld".

pub mod capabilities;
pub mod events;
pub mod rules;
pub mod status;
pub mod tasks;

#[cfg(test)]
mod tests;

use serde::Serialize;
use serde_json::{Map, Value};

/// A retained field: shown with its value, withheld because the value
/// failed its rule ("path withheld"), or absent because orceld sent nothing
/// or `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
pub enum Field<T> {
    Shown(T),
    Withheld,
    Absent,
}

impl<T> Field<T> {
    pub fn shown(&self) -> Option<&T> {
        match self {
            Field::Shown(value) => Some(value),
            Field::Withheld | Field::Absent => None,
        }
    }

    pub fn is_withheld(&self) -> bool {
        matches!(self, Field::Withheld)
    }
}

/// orceld answered with `read_only` other than `true`: the window shows
/// "incompatible orceld" and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Incompatible;

/// The running count of withheld things for one output.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Withheld(pub u32);

impl Withheld {
    pub fn add(&mut self, n: usize) {
        self.0 = self.0.saturating_add(u32::try_from(n).unwrap_or(u32::MAX));
    }

    pub fn one(&mut self) {
        self.add(1);
    }
}

/// Counts every key of `object` that is in neither `kept` nor `dropped`.
pub(crate) fn count_unknown(
    object: &Map<String, Value>,
    kept: &[&str],
    dropped: &[&str],
    withheld: &mut Withheld,
) {
    let unknown = object
        .keys()
        .filter(|key| !kept.contains(&key.as_str()) && !dropped.contains(&key.as_str()))
        .count();
    withheld.add(unknown);
}

/// A field judged by `rule`. Absent and `null` are `Absent`; a value of the
/// wrong JSON type or one the rule refuses is `Withheld` and counted.
pub(crate) fn field<T>(
    value: Option<&Value>,
    rule: impl FnOnce(&Value) -> Option<T>,
    withheld: &mut Withheld,
) -> Field<T> {
    match value {
        None | Some(Value::Null) => Field::Absent,
        Some(value) => match rule(value) {
            Some(kept) => Field::Shown(kept),
            None => {
                withheld.one();
                Field::Withheld
            }
        },
    }
}

/// A string field judged by `rule`.
pub(crate) fn str_field(
    value: Option<&Value>,
    rule: impl FnOnce(&str) -> Option<String>,
    withheld: &mut Withheld,
) -> Field<String> {
    field(value, |value| value.as_str().and_then(rule), withheld)
}

/// A non-negative integer field.
pub(crate) fn u64_field(value: Option<&Value>, withheld: &mut Withheld) -> Field<u64> {
    field(value, Value::as_u64, withheld)
}

/// A boolean field.
pub(crate) fn bool_field(value: Option<&Value>, withheld: &mut Withheld) -> Field<bool> {
    field(value, Value::as_bool, withheld)
}
