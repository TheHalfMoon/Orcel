//! `status.get`, and the `status` inside a snapshot event.

use super::rules::{self, charset};
use super::{count_unknown, field, str_field, u64_field, Field, Incompatible, Withheld};
use serde::Serialize;
use serde_json::Value;

/// The protocol name orceld reports in `app_api`. Its `/` is outside the
/// version charset, so the field is a closed value rather than a charset.
pub const APP_API: &str = "orcel-app-api/1";

const KEPT: &[&str] = &[
    "name",
    "version",
    "app_api",
    "read_only",
    "internal_protocol_version",
    "os",
    "arch",
    "mode",
    "policy_revision",
    "started_at_ms",
    "uptime_ms",
    "events",
    "clients",
    "endpoint_wait",
];
/// `endpoint` carries the user's SID; `peer` names a pid.
const DROPPED: &[&str] = &["pid", "endpoint", "peer"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Status {
    pub name: Field<String>,
    pub version: Field<String>,
    pub app_api: Field<String>,
    pub internal_protocol_version: Field<String>,
    pub os: Field<String>,
    pub arch: Field<String>,
    pub mode: Field<String>,
    pub policy_revision: Field<String>,
    pub started_at_ms: Field<u64>,
    pub uptime_ms: Field<u64>,
    pub events: Field<EventsInfo>,
    pub clients: Field<ClientsInfo>,
    pub endpoint_wait: Field<EndpointWait>,
    /// Fields withheld from this status (see the module docs of `sanitize`).
    pub withheld: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventsInfo {
    pub epoch: String,
    pub head_seq: u64,
    pub oldest_seq: u64,
    pub ring_capacity: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClientsInfo {
    pub active: u64,
    pub max: u64,
}

/// When and how often orceld found its endpoint held; its free-text reason
/// is never kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EndpointWait {
    pub since_ms: u64,
    pub attempts: u64,
}

fn version_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-')
}

fn os_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
}

/// `mode`. orceld's real value is `SG-000039_CLIPBOARD_WRITE` (the
/// `DaemonFacts` in `crates/orceld/src/sg000039_main.rs`), so the charset is
/// `[A-Za-z0-9_-]`; see `mode_rule_keeps_orcelds_real_mode` in the tests.
pub(crate) fn mode(value: &str) -> Option<String> {
    charset(value, 32, rules::identifier_byte)
}

/// `policy_revision`: a number, or the identifier charset, at most 64.
fn policy_revision(value: &Value) -> Option<String> {
    match value {
        Value::Number(number) => number.as_u64().map(|n| n.to_string()),
        Value::String(text) => charset(text, 64, rules::identifier_byte),
        _ => None,
    }
}

fn events_info(value: &Value, withheld: &mut Withheld) -> Option<EventsInfo> {
    let object = value.as_object()?;
    count_unknown(
        object,
        &["epoch", "head_seq", "oldest_seq", "ring_capacity"],
        &[],
        withheld,
    );
    Some(EventsInfo {
        epoch: rules::epoch(object.get("epoch")?.as_str()?)?,
        head_seq: object.get("head_seq")?.as_u64()?,
        oldest_seq: object.get("oldest_seq")?.as_u64()?,
        ring_capacity: object.get("ring_capacity")?.as_u64()?,
    })
}

fn clients_info(value: &Value, withheld: &mut Withheld) -> Option<ClientsInfo> {
    let object = value.as_object()?;
    count_unknown(object, &["active", "max"], &[], withheld);
    Some(ClientsInfo {
        active: object.get("active")?.as_u64()?,
        max: object.get("max")?.as_u64()?,
    })
}

fn endpoint_wait(value: &Value, withheld: &mut Withheld) -> Option<EndpointWait> {
    let object = value.as_object()?;
    count_unknown(object, &["since_ms", "attempts"], &["reason"], withheld);
    Some(EndpointWait {
        since_ms: object.get("since_ms")?.as_u64()?,
        attempts: object.get("attempts")?.as_u64()?,
    })
}

/// A nested object: its reader counts its own unknown keys into a scratch
/// count that is added only when the nested object itself is kept (a
/// withheld object counts once).
pub(crate) fn nested<T>(
    value: Option<&Value>,
    withheld: &mut Withheld,
    read: impl FnOnce(&Value, &mut Withheld) -> Option<T>,
) -> Field<T> {
    let mut inner = Withheld::default();
    let kept = field(value, |value| read(value, &mut inner), withheld);
    if kept.shown().is_some() {
        withheld.add(inner.0 as usize);
    }
    kept
}

/// Sanitises one status object. `read_only` other than `true` (missing
/// included) is [`Incompatible`]: nothing else of the answer is shown.
pub fn sanitize(value: &Value) -> Result<Status, Incompatible> {
    let object = value.as_object().ok_or(Incompatible)?;
    if object.get("read_only") != Some(&Value::Bool(true)) {
        return Err(Incompatible);
    }
    let mut withheld = Withheld::default();
    let w = &mut withheld;
    count_unknown(object, KEPT, DROPPED, w);
    let name = str_field(object.get("name"), |v| charset(v, 32, version_byte), w);
    let version = str_field(object.get("version"), |v| charset(v, 32, version_byte), w);
    let app_api = str_field(
        object.get("app_api"),
        |v| (v == APP_API).then(|| v.to_owned()),
        w,
    );
    let internal_protocol_version = str_field(
        object.get("internal_protocol_version"),
        |v| charset(v, 32, version_byte),
        w,
    );
    let os = str_field(object.get("os"), |v| charset(v, 16, os_byte), w);
    let arch = str_field(object.get("arch"), |v| charset(v, 16, os_byte), w);
    let mode = str_field(object.get("mode"), mode, w);
    let policy_revision = field(object.get("policy_revision"), policy_revision, w);
    let started_at_ms = u64_field(object.get("started_at_ms"), w);
    let uptime_ms = u64_field(object.get("uptime_ms"), w);
    let events = nested(object.get("events"), w, events_info);
    let clients = nested(object.get("clients"), w, clients_info);
    let endpoint_wait = nested(object.get("endpoint_wait"), w, endpoint_wait);
    Ok(Status {
        name,
        version,
        app_api,
        internal_protocol_version,
        os,
        arch,
        mode,
        policy_revision,
        started_at_ms,
        uptime_ms,
        events,
        clients,
        endpoint_wait,
        withheld: withheld.0,
    })
}
