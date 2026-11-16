//! Events: a closed allowlist of kinds, with fields per kind. Every kept
//! event keeps `seq`, `epoch` and `at_ms`. Any other kind is dropped and
//! counted. Heartbeats are not events; the subscription consumes them.

use super::rules::{self, charset};
use super::status::{self, Status};
use super::tasks::{self, Known, StepKind, StepOutcome, TaskKind, TaskState};
use super::{bool_field, count_unknown, str_field, u64_field, Field, Incompatible, Withheld};
use serde::Serialize;
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Event {
    pub seq: u64,
    pub epoch: String,
    pub at_ms: u64,
    #[serde(flatten)]
    pub body: EventBody,
    /// Fields withheld from this event.
    pub withheld: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind")]
pub enum EventBody {
    #[serde(rename = "daemon.started")]
    DaemonStarted { mode: Field<String> },
    #[serde(rename = "request.completed")]
    RequestCompleted {
        capability: Field<String>,
        operation: Field<String>,
        ok: Field<bool>,
        failure_code: Field<String>,
    },
    /// Shown as "orceld waited for its endpoint"; the reason is never kept.
    #[serde(rename = "app_api.endpoint_in_use")]
    EndpointInUse,
    #[serde(rename = "task.updated")]
    TaskUpdated {
        run_id: String,
        step_id: String,
        task_kind: TaskKind,
        state: TaskState,
        step: Known<StepKind>,
        outcome: Known<StepOutcome>,
    },
    #[serde(rename = "snapshot")]
    Snapshot {
        reason: SnapshotReason,
        head_seq: u64,
        oldest_seq: u64,
        status: Field<Box<Status>>,
        resubscribe: Resubscribe,
    },
    /// orceld replaced the event's data with `{truncated: true, bytes}`:
    /// shown as "event too large, withheld".
    #[serde(rename = "withheld")]
    TooLarge {
        of_kind: &'static str,
        bytes: Field<u64>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotReason {
    Gap,
    Epoch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Resubscribe {
    pub after_seq: u64,
    pub epoch: String,
}

/// The kinds this sanitiser keeps.
pub const KINDS: &[&str] = &[
    "daemon.started",
    "request.completed",
    "app_api.endpoint_in_use",
    "task.updated",
    "snapshot",
];

const TOP: &[&str] = &["seq", "epoch", "at_ms", "kind", "data", "run_id", "step_id"];

/// `capability` and `operation`: `[a-z0-9_.:/-]`, at most 64.
fn shape(value: &str) -> Option<String> {
    charset(value, 64, |b| {
        b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || matches!(b, b'_' | b'.' | b':' | b'/' | b'-')
    })
}

/// `failure_code`: `[A-Z0-9_]`, at most 48.
fn failure_code(value: &str) -> Option<String> {
    charset(value, 48, |b| {
        b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'
    })
}

/// An event's position: `seq` and an epoch in orceld's format. `None` when
/// either fails; the event is then dropped and its position unknown.
pub fn position(value: &Value) -> Option<(u64, String)> {
    let object = value.as_object()?;
    let seq = object.get("seq")?.as_u64()?;
    let epoch = rules::epoch(object.get("epoch")?.as_str()?)?;
    Some((seq, epoch))
}

fn truncated(data: &Map<String, Value>) -> bool {
    data.get("truncated") == Some(&Value::Bool(true))
}

fn data_of(object: &Map<String, Value>) -> Option<&Map<String, Value>> {
    object.get("data")?.as_object()
}

/// Sanitises one event. `Ok(None)` means the event is dropped and the caller
/// counts it: an unknown kind, a malformed position, or a kind's required
/// field that failed its rule. A snapshot whose status is not read-only is
/// [`Incompatible`].
pub fn sanitize(value: &Value) -> Result<Option<Event>, Incompatible> {
    let Some(object) = value.as_object() else {
        return Ok(None);
    };
    let Some((seq, epoch)) = position(value) else {
        return Ok(None);
    };
    let Some(at_ms) = object.get("at_ms").and_then(Value::as_u64) else {
        return Ok(None);
    };
    let Some(kind) = object
        .get("kind")
        .and_then(Value::as_str)
        .and_then(|kind| KINDS.iter().copied().find(|known| *known == kind))
    else {
        return Ok(None);
    };
    let Some(data) = data_of(object) else {
        return Ok(None);
    };
    let mut withheld = Withheld::default();
    let w = &mut withheld;
    count_unknown(object, TOP, &[], w);
    if kind != "task.updated" {
        for key in ["run_id", "step_id"] {
            if !matches!(object.get(key), None | Some(Value::Null)) {
                w.one();
            }
        }
    }
    let body = if truncated(data) {
        count_unknown(data, &["truncated", "bytes"], &[], w);
        EventBody::TooLarge {
            of_kind: kind,
            bytes: u64_field(data.get("bytes"), w),
        }
    } else {
        match kind {
            "daemon.started" => {
                count_unknown(data, &["mode"], &["pid"], w);
                EventBody::DaemonStarted {
                    mode: str_field(data.get("mode"), status::mode, w),
                }
            }
            "request.completed" => {
                count_unknown(
                    data,
                    &["capability", "operation", "ok", "failure_code"],
                    &["request_id"],
                    w,
                );
                EventBody::RequestCompleted {
                    capability: str_field(data.get("capability"), shape, w),
                    operation: str_field(data.get("operation"), shape, w),
                    ok: bool_field(data.get("ok"), w),
                    failure_code: str_field(data.get("failure_code"), failure_code, w),
                }
            }
            "app_api.endpoint_in_use" => {
                count_unknown(data, &[], &["reason"], w);
                EventBody::EndpointInUse
            }
            "task.updated" => match task_updated(object, data, w) {
                Some(body) => body,
                None => return Ok(None),
            },
            "snapshot" => match snapshot(data, w)? {
                Some(body) => body,
                None => return Ok(None),
            },
            _ => return Ok(None),
        }
    };
    Ok(Some(Event {
        seq,
        epoch,
        at_ms,
        body,
        withheld: withheld.0,
    }))
}

fn task_updated(
    object: &Map<String, Value>,
    data: &Map<String, Value>,
    w: &mut Withheld,
) -> Option<EventBody> {
    let run_id = rules::identifier(object.get("run_id")?.as_str()?)?;
    let step_id = rules::step_id(object.get("step_id")?.as_str()?)?;
    let task_kind = data.get("task_kind")?.as_str().and_then(TaskKind::parse)?;
    let state = tasks::task_state(data.get("state"))?;
    count_unknown(data, &["task_kind", "state", "step", "outcome"], &[], w);
    Some(EventBody::TaskUpdated {
        run_id,
        step_id,
        task_kind,
        state,
        step: tasks::step_kind(data.get("step")),
        outcome: tasks::step_outcome(data.get("outcome")),
    })
}

fn snapshot(
    data: &Map<String, Value>,
    w: &mut Withheld,
) -> Result<Option<EventBody>, Incompatible> {
    let reason = match data.get("reason").and_then(Value::as_str) {
        Some("gap") => SnapshotReason::Gap,
        Some("epoch") => SnapshotReason::Epoch,
        _ => return Ok(None),
    };
    let (Some(head_seq), Some(oldest_seq)) = (
        data.get("head_seq").and_then(Value::as_u64),
        data.get("oldest_seq").and_then(Value::as_u64),
    ) else {
        return Ok(None);
    };
    let Some(resubscribe) = data.get("resubscribe").and_then(Value::as_object) else {
        return Ok(None);
    };
    let (Some(after_seq), Some(resubscribe_epoch)) = (
        resubscribe.get("after_seq").and_then(Value::as_u64),
        resubscribe
            .get("epoch")
            .and_then(Value::as_str)
            .and_then(rules::epoch),
    ) else {
        return Ok(None);
    };
    count_unknown(resubscribe, &["after_seq", "epoch"], &[], w);
    let status = match data.get("status") {
        None | Some(Value::Null) => Field::Absent,
        Some(value) => {
            let status = status::sanitize(value)?;
            Field::Shown(Box::new(status))
        }
    };
    count_unknown(
        data,
        &["reason", "head_seq", "oldest_seq", "status", "resubscribe"],
        &[],
        w,
    );
    Ok(Some(EventBody::Snapshot {
        reason,
        head_seq,
        oldest_seq,
        status,
        resubscribe: Resubscribe {
            after_seq,
            epoch: resubscribe_epoch,
        },
    }))
}
