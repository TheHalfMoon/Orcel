//! Sanitiser tests. Every fixture has the shape orceld really writes: the
//! `json!` bodies of `status`, `capabilities`, `snapshot_event` and
//! `Event::to_json` in `crates/orceld/src/app_api.rs`, `request_event` and
//! `app_api_capabilities` in `crates/orceld/src/sg000039_main.rs`, and
//! `summary`, `detail` and `update_if` in `crates/orceld/src/report_task.rs`.

use super::capabilities::{self, CapabilityState, MAX_CAPABILITIES, MAX_REASON_CHARS};
use super::events::{self, EventBody, SnapshotReason};
use super::rules::{self, REPLACEMENT};
use super::status;
use super::tasks::{self, Known, OtherValue, StepKind, StepOutcome, TaskState};
use super::{Field, Incompatible};
use serde_json::{json, Value};

/// orceld's `new_epoch`: `format!("{:x}-{:x}", pid, nanos)`.
fn epoch() -> String {
    format!("{:x}-{:x}", 13_572u32, 1_763_301_234_567_890_123u128)
}

const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const SID_PIPE: &str = r"\\.\pipe\orcel-S-1-5-21-1111111111-2222222222-3333333333-1001-app";

/// `status(shared, Some(peer))` of orceld, with the endpoint held once.
fn orceld_status() -> Value {
    json!({
        "name": "orceld",
        "version": "0.2.0",
        "app_api": "orcel-app-api/1",
        "read_only": true,
        "internal_protocol_version": "1",
        "os": "windows",
        "arch": "x86_64",
        "pid": 13572,
        "mode": "SG-000039_CLIPBOARD_WRITE",
        "policy_revision": "sg-000039-v1",
        "started_at_ms": 1_763_301_234_567u64,
        "uptime_ms": 4_200,
        "endpoint": SID_PIPE,
        "endpoint_wait": {
            "since_ms": 1_763_301_230_000u64,
            "reason": "the pipe name already exists (Access is denied.); it is held by process 999, which runs as another account (the name is squatted)",
            "attempts": 3,
        },
        "events": {
            "epoch": epoch(),
            "head_seq": 12,
            "oldest_seq": 1,
            "ring_capacity": 1024,
        },
        "clients": { "active": 1, "max": 8 },
        "peer": { "pid": 777, "source": "win32-named-pipe-client" },
    })
}

fn serialized(value: &impl serde::Serialize) -> String {
    serde_json::to_string(value).unwrap()
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

#[test]
fn text_rule_replaces_controls_format_characters_and_separators() {
    let hostile = "a\u{0}b\u{1b}[31mc\u{7f}d\u{85}e\u{9f}f\u{202e}g\u{2066}h\u{200b}i\u{feff}j\u{61c}k\u{2028}l\u{2029}m\u{ad}n\u{e0041}o";
    let cleaned = rules::text(hostile, 1000);
    assert!(cleaned
        .chars()
        .all(|c| !rules::is_replaced(c) || c == REPLACEMENT));
    assert_eq!(cleaned.matches(REPLACEMENT).count(), 14);
    assert_eq!(rules::text("plain words", 1000), "plain words");
    assert_eq!(rules::text("ééééé", 3), "ééé");
}

#[test]
fn format_table_covers_the_bidi_controls_and_zero_width_characters() {
    for c in [
        '\u{200e}',
        '\u{200f}',
        '\u{202a}',
        '\u{202b}',
        '\u{202c}',
        '\u{202d}',
        '\u{202e}',
        '\u{2066}',
        '\u{2067}',
        '\u{2068}',
        '\u{2069}',
        '\u{061c}',
        '\u{200b}',
        '\u{200c}',
        '\u{200d}',
        '\u{2060}',
        '\u{feff}',
        '\u{180e}',
        '\u{e0001}',
        '\u{e007f}',
    ] {
        assert!(rules::is_format(c), "U+{:04X}", c as u32);
    }
    for c in ['a', ' ', '\u{2070}', '\u{fffd}', '\u{e0080}', '\u{200a}'] {
        assert!(!rules::is_format(c), "U+{:04X}", c as u32);
    }
}

#[test]
fn identifier_rules() {
    let id = "r-0001-6a2f";
    assert_eq!(rules::identifier(id).as_deref(), Some(id));
    assert_eq!(
        rules::identifier(&"a".repeat(128)).map(|s| s.len()),
        Some(128)
    );
    for bad in ["", "a b", "a/b", "a.b", "é", "a\u{202e}", &"a".repeat(129)] {
        assert_eq!(rules::identifier(bad), None, "{bad:?}");
    }
    for good in ["s1", "s32", "s9999"] {
        assert!(rules::step_id(good).is_some(), "{good}");
    }
    for bad in ["", "s", "s10000", "S1", "t1", "s1a", "s-1", "1"] {
        assert_eq!(rules::step_id(bad), None, "{bad:?}");
    }
}

#[test]
fn epochs_in_orcelds_format_are_accepted_and_others_refused() {
    // Built exactly as `new_epoch` builds them.
    for (pid, nanos) in [
        (1u32, 0u128),
        (13_572, 1_763_301_234_567_890_123),
        (u32::MAX, u128::MAX),
        (0, 1),
    ] {
        let epoch = format!("{:x}-{:x}", pid, nanos);
        assert_eq!(rules::epoch(&epoch).as_deref(), Some(epoch.as_str()));
    }
    for bad in [
        "",
        "-",
        "1a2b",
        "1a2b-",
        "-17f",
        "1A2B-17f",
        "1a2b-17F",
        "123456789-1",
        &format!("1-{}", "f".repeat(33)),
        "1a2b-17f-3",
        "1a2b_17f",
        "g-1",
        " 1-1",
    ] {
        assert_eq!(rules::epoch(bad), None, "{bad:?}");
    }
}

#[test]
fn hash_rule() {
    assert_eq!(rules::sha256(SHA).as_deref(), Some(SHA));
    for bad in [
        "",
        &SHA[..63],
        &format!("{SHA}0"),
        &SHA.to_uppercase(),
        &format!("{}g", &SHA[..63]),
        &format!("{} ", &SHA[..63]),
    ] {
        assert_eq!(rules::sha256(bad), None, "{bad:?}");
    }
}

/// Values every path field must withhold.
fn hostile_paths() -> Vec<String> {
    let mut paths: Vec<String> = [
        "",
        "/etc/passwd",
        "\\Windows\\System32",
        "C:\\Users\\me\\secret.txt",
        "c:relative",
        "Z:/x",
        "\\\\server\\share\\x",
        "//server/share/x",
        "\\\\?\\C:\\x",
        "\\\\.\\pipe\\x",
        "..",
        "../outside",
        "reports/../../outside",
        "reports\\..\\outside",
        ".",
        "./reports",
        "reports/./q3.md",
        "reports\\.\\q3.md",
        "reports/q3\u{0}.md",
        "reports/q3\u{1b}.md",
        "reports/q3\u{85}.md",
        "reports/\u{202e}dm.3q",
        "reports/q3\u{200b}.md",
        "reports/q3\u{2028}.md",
        "reports/q3\u{2029}.md",
        "reports/q3\n.md",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    paths.push(format!("reports/{}", "a".repeat(1018)));
    paths
}

#[test]
fn path_rule_keeps_workspace_relative_paths_only() {
    for good in [
        "reports",
        "reports/",
        "reports/q3.md",
        "data\\q3.csv",
        "a/b/c/d.e",
        "Résumé/notes..md",
        "..hidden/x",
        "x.",
    ] {
        assert_eq!(
            rules::workspace_path(good).as_deref(),
            Some(good),
            "{good:?}"
        );
    }
    let longest = format!("reports/{}", "a".repeat(1016));
    assert_eq!(longest.len(), 1024);
    assert!(rules::workspace_path(&longest).is_some());
    for bad in hostile_paths() {
        assert_eq!(rules::workspace_path(&bad), None, "{bad:?}");
    }
}

#[test]
fn file_name_rule_withholds_separators_and_long_names() {
    assert_eq!(rules::file_name("q3.md").as_deref(), Some("q3.md"));
    assert!(rules::file_name(&"a".repeat(255)).is_some());
    for bad in [
        "reports/q3.md",
        "reports\\q3.md",
        "/q3.md",
        "..",
        ".",
        "",
        "q3\u{202e}.md",
        &"a".repeat(256),
    ] {
        assert_eq!(rules::file_name(bad), None, "{bad:?}");
    }
}

// ---------------------------------------------------------------------------
// Status and capabilities
// ---------------------------------------------------------------------------

#[test]
fn status_keeps_named_fields_and_drops_pid_endpoint_peer_and_reason() {
    let status = status::sanitize(&orceld_status()).unwrap();
    assert_eq!(status.name, Field::Shown("orceld".into()));
    assert_eq!(status.version, Field::Shown("0.2.0".into()));
    assert_eq!(status.app_api, Field::Shown("orcel-app-api/1".into()));
    assert_eq!(status.internal_protocol_version, Field::Shown("1".into()));
    assert_eq!(status.os, Field::Shown("windows".into()));
    assert_eq!(status.arch, Field::Shown("x86_64".into()));
    assert_eq!(status.policy_revision, Field::Shown("sg-000039-v1".into()));
    assert_eq!(status.started_at_ms, Field::Shown(1_763_301_234_567));
    assert_eq!(status.uptime_ms, Field::Shown(4_200));
    let events = status.events.shown().unwrap();
    assert_eq!(
        (
            events.epoch.as_str(),
            events.head_seq,
            events.oldest_seq,
            events.ring_capacity
        ),
        (epoch().as_str(), 12, 1, 1024)
    );
    let clients = status.clients.shown().unwrap();
    assert_eq!((clients.active, clients.max), (1, 8));
    let wait = status.endpoint_wait.shown().unwrap();
    assert_eq!((wait.since_ms, wait.attempts), (1_763_301_230_000, 3));
    // Named drops are not counted; nothing unexpected was withheld.
    assert_eq!(status.withheld, 0);
    let out = serialized(&status);
    for gone in [
        "13572", "777", "S-1-5-21", "pipe", "peer", "squatted", "reason", "\"pid\"",
    ] {
        assert!(!out.contains(gone), "{gone} leaked: {out}");
    }
}

#[test]
fn mode_rule_keeps_orcelds_real_mode() {
    let status = status::sanitize(&orceld_status()).unwrap();
    assert_eq!(
        status.mode,
        Field::Shown("SG-000039_CLIPBOARD_WRITE".into())
    );
    let mut odd = orceld_status();
    odd["mode"] = json!("clip board");
    assert_eq!(status::sanitize(&odd).unwrap().mode, Field::Withheld);
}

#[test]
fn status_read_only_other_than_true_is_incompatible() {
    for read_only in [json!(false), json!("true"), json!(1), Value::Null] {
        let mut value = orceld_status();
        value["read_only"] = read_only;
        assert_eq!(status::sanitize(&value), Err(Incompatible));
    }
    let mut missing = orceld_status();
    missing.as_object_mut().unwrap().remove("read_only");
    assert_eq!(status::sanitize(&missing), Err(Incompatible));
    assert_eq!(status::sanitize(&json!([])), Err(Incompatible));
}

#[test]
fn status_unknown_fields_and_failed_values_are_withheld_and_counted() {
    let mut value = orceld_status();
    value["new_field"] = json!("whatever orceld adds later");
    value["another"] = json!({"nested": true});
    value["version"] = json!("0.2.0 \u{202e}");
    value["os"] = json!("Windows");
    value["app_api"] = json!("orcel-app-api/2");
    value["events"]["extra"] = json!(1);
    value["endpoint_wait"] = Value::Null;
    let status = status::sanitize(&value).unwrap();
    assert_eq!(status.version, Field::Withheld);
    assert_eq!(status.os, Field::Withheld);
    assert_eq!(status.app_api, Field::Withheld);
    assert_eq!(status.endpoint_wait, Field::Absent);
    // two unknown top-level fields, three failed values, one unknown nested.
    assert_eq!(status.withheld, 6);
    assert!(!serialized(&status).contains("whatever"));

    let mut bad_epoch = orceld_status();
    bad_epoch["events"]["epoch"] = json!("not-an-epoch!");
    assert_eq!(
        status::sanitize(&bad_epoch).unwrap().events,
        Field::Withheld
    );
}

/// `capabilities(shared)` of orceld on Linux, where two rows carry reasons.
fn orceld_capabilities() -> Value {
    json!({
        "os": "linux",
        "read_only": true,
        "methods": ["status.get", "capabilities.get", "events.subscribe", "task.list", "task.get", "task.stop", "approval.history", "clients.list"],
        "reserved_methods": ["devices.list"],
        "capabilities": [
            { "id": "fs", "state": "available", "reason": null },
            { "id": "git", "state": "available", "reason": null },
            { "id": "clipboard", "state": "available", "reason": null },
            { "id": "report.task", "state": "available", "reason": null },
            { "id": "process.contained", "state": "unavailable", "reason": "contained process execution is Windows only in this build" },
            { "id": "desktop.uia", "state": "unavailable", "reason": "the UI Automation desktop provider is Windows only in this build" },
            { "id": "approval.presence", "state": "unavailable", "reason": "no platform presence surface is available to orceld" },
        ],
    })
}

#[test]
fn capabilities_keep_rows_with_reasons_and_drop_method_lists() {
    let caps = capabilities::sanitize(&orceld_capabilities()).unwrap();
    assert_eq!(caps.os, Field::Shown("linux".into()));
    assert_eq!(caps.capabilities.len(), 7);
    assert_eq!(caps.capabilities[4].id, "process.contained");
    assert_eq!(caps.capabilities[4].state, CapabilityState::Unavailable);
    assert_eq!(
        caps.capabilities[4].reason.as_deref(),
        Some("contained process execution is Windows only in this build")
    );
    assert_eq!(caps.capabilities[0].reason, None);
    assert_eq!(caps.withheld, 0);
    let out = serialized(&caps);
    assert!(!out.contains("task.stop") && !out.contains("devices.list"));
}

#[test]
fn capability_reasons_are_cleaned_and_capped_and_bad_rows_dropped() {
    let mut value = orceld_capabilities();
    let rows = value["capabilities"].as_array_mut().unwrap();
    rows.push(json!({ "id": "x", "state": "unavailable", "reason": format!("bad\u{202e}{}", "r".repeat(400)) }));
    rows.push(json!({ "id": "Upper", "state": "available", "reason": null }));
    rows.push(json!({ "id": "y", "state": "maybe", "reason": null }));
    rows.push(json!({ "id": "z", "state": "available", "reason": 5 }));
    rows.push(json!({ "id": "w", "state": "available", "reason": null, "extra": 1 }));
    let caps = capabilities::sanitize(&value).unwrap();
    let x = caps.capabilities.iter().find(|c| c.id == "x").unwrap();
    let reason = x.reason.as_deref().unwrap();
    assert_eq!(reason.chars().count(), MAX_REASON_CHARS);
    assert!(reason.starts_with("bad\u{fffd}r"));
    assert!(caps.capabilities.iter().any(|c| c.id == "w"));
    // Three rows dropped, one unknown field.
    assert_eq!(caps.withheld, 4);

    let mut many = orceld_capabilities();
    many["capabilities"] = Value::Array(
        (0..70)
            .map(|i| json!({ "id": format!("c{i}"), "state": "available", "reason": null }))
            .collect(),
    );
    let caps = capabilities::sanitize(&many).unwrap();
    assert_eq!(caps.capabilities.len(), MAX_CAPABILITIES);
    assert_eq!(caps.withheld, 6);

    let mut not_read_only = orceld_capabilities();
    not_read_only["read_only"] = json!(false);
    assert_eq!(capabilities::sanitize(&not_read_only), Err(Incompatible));
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// `Event::to_json` of orceld.
fn event(seq: u64, kind: &str, run_id: Value, step_id: Value, data: Value) -> Value {
    json!({
        "seq": seq,
        "epoch": epoch(),
        "run_id": run_id,
        "step_id": step_id,
        "kind": kind,
        "at_ms": 1_763_301_234_999u64,
        "data": data,
    })
}

#[test]
fn daemon_started_keeps_mode_and_drops_pid() {
    let value = event(
        1,
        "daemon.started",
        Value::Null,
        Value::Null,
        json!({ "pid": 13572, "mode": "SG-000039_CLIPBOARD_WRITE" }),
    );
    let kept = events::sanitize(&value).unwrap().unwrap();
    assert_eq!(
        (kept.seq, kept.epoch.as_str(), kept.at_ms),
        (1, epoch().as_str(), 1_763_301_234_999)
    );
    assert_eq!(
        kept.body,
        EventBody::DaemonStarted {
            mode: Field::Shown("SG-000039_CLIPBOARD_WRITE".into())
        }
    );
    assert_eq!(kept.withheld, 0);
    assert!(!serialized(&kept).contains("13572"));
}

#[test]
fn request_completed_drops_request_id_and_accepts_null_shape() {
    // `request_event` for a request that had no shape (invalid JSON).
    let value = event(
        2,
        "request.completed",
        Value::Null,
        Value::Null,
        json!({ "request_id": "unknown", "capability": null, "operation": null, "ok": false, "failure_code": "INVALID_REQUEST" }),
    );
    let kept = events::sanitize(&value).unwrap().unwrap();
    assert_eq!(
        kept.body,
        EventBody::RequestCompleted {
            capability: Field::Absent,
            operation: Field::Absent,
            ok: Field::Shown(false),
            failure_code: Field::Shown("INVALID_REQUEST".into()),
        }
    );
    assert_eq!(kept.withheld, 0);

    let value = event(
        3,
        "request.completed",
        Value::Null,
        Value::Null,
        json!({ "request_id": "secret-request-7", "capability": "report", "operation": "start", "ok": true, "failure_code": null }),
    );
    let kept = events::sanitize(&value).unwrap().unwrap();
    assert_eq!(
        kept.body,
        EventBody::RequestCompleted {
            capability: Field::Shown("report".into()),
            operation: Field::Shown("start".into()),
            ok: Field::Shown(true),
            failure_code: Field::Absent,
        }
    );
    assert!(!serialized(&kept).contains("secret-request-7"));

    let value = event(
        4,
        "request.completed",
        Value::Null,
        Value::Null,
        json!({ "request_id": "r", "capability": "Report\u{202e}", "operation": "x".repeat(65), "ok": "yes", "failure_code": "lower" }),
    );
    let kept = events::sanitize(&value).unwrap().unwrap();
    assert_eq!(
        kept.body,
        EventBody::RequestCompleted {
            capability: Field::Withheld,
            operation: Field::Withheld,
            ok: Field::Withheld,
            failure_code: Field::Withheld,
        }
    );
    assert_eq!(kept.withheld, 4);
}

#[test]
fn endpoint_in_use_keeps_only_the_fact() {
    let value = event(
        5,
        "app_api.endpoint_in_use",
        Value::Null,
        Value::Null,
        json!({ "reason": "it is held by process 4321, which runs as another account (the name is squatted)" }),
    );
    let kept = events::sanitize(&value).unwrap().unwrap();
    assert_eq!(kept.body, EventBody::EndpointInUse);
    let out = serialized(&kept);
    assert!(!out.contains("4321") && !out.contains("squatted") && !out.contains("reason"));
}

#[test]
fn task_updated_keeps_run_step_and_task_enums() {
    // `update_if` publishes this with the task id as run_id.
    let value = event(
        6,
        "task.updated",
        json!("r-0001-6a2f"),
        json!("s3"),
        json!({ "task_kind": "report", "state": "proposed", "step": "preview", "outcome": "ok" }),
    );
    let kept = events::sanitize(&value).unwrap().unwrap();
    assert_eq!(
        kept.body,
        EventBody::TaskUpdated {
            run_id: "r-0001-6a2f".into(),
            step_id: "s3".into(),
            task_kind: tasks::TaskKind::Report,
            state: TaskState::Proposed,
            step: Known::Known(StepKind::Preview),
            outcome: Known::Known(StepOutcome::Ok),
        }
    );

    let other = event(
        7,
        "task.updated",
        json!("r-0001-6a2f"),
        json!("s4"),
        json!({ "task_kind": "report", "state": "stale", "step": "teleport", "outcome": "beamed \u{202e}" }),
    );
    let kept = events::sanitize(&other).unwrap().unwrap();
    let out = serialized(&kept);
    assert!(
        out.contains("\"step\":\"other\"") && out.contains("\"outcome\":\"other\""),
        "{out}"
    );
    assert!(!out.contains("teleport") && !out.contains("beamed"));

    for (run_id, step_id, data) in [
        (
            json!("r/1"),
            json!("s1"),
            json!({ "task_kind": "report", "state": "proposed", "step": "preview", "outcome": "ok" }),
        ),
        (
            json!("r1"),
            json!("step1"),
            json!({ "task_kind": "report", "state": "proposed", "step": "preview", "outcome": "ok" }),
        ),
        (
            json!("r1"),
            json!("s1"),
            json!({ "task_kind": "deploy", "state": "proposed", "step": "preview", "outcome": "ok" }),
        ),
        (
            json!("r1"),
            json!("s1"),
            json!({ "task_kind": "report", "state": "exploded", "step": "preview", "outcome": "ok" }),
        ),
        (
            Value::Null,
            json!("s1"),
            json!({ "task_kind": "report", "state": "proposed", "step": "preview", "outcome": "ok" }),
        ),
    ] {
        let value = event(8, "task.updated", run_id, step_id, data);
        assert_eq!(events::sanitize(&value), Ok(None), "{value}");
    }
}

/// `snapshot_event` of orceld.
fn snapshot(reason: &str, status: Value) -> Value {
    json!({
        "seq": 40,
        "epoch": epoch(),
        "run_id": null,
        "step_id": null,
        "kind": "snapshot",
        "at_ms": 1_763_301_235_000u64,
        "data": {
            "reason": reason,
            "head_seq": 40,
            "oldest_seq": 3,
            "status": status,
            "resubscribe": { "after_seq": 40, "epoch": epoch() },
        },
    })
}

#[test]
fn snapshot_keeps_reason_cursor_and_sanitised_status() {
    let mut without_peer = orceld_status();
    without_peer.as_object_mut().unwrap().remove("peer");
    for (text, reason) in [
        ("gap", SnapshotReason::Gap),
        ("epoch", SnapshotReason::Epoch),
    ] {
        let kept = events::sanitize(&snapshot(text, without_peer.clone()))
            .unwrap()
            .unwrap();
        let EventBody::Snapshot {
            reason: kept_reason,
            head_seq,
            oldest_seq,
            status,
            resubscribe,
        } = &kept.body
        else {
            panic!("not a snapshot: {kept:?}");
        };
        assert_eq!(*kept_reason, reason);
        assert_eq!((*head_seq, *oldest_seq), (40, 3));
        assert_eq!(
            (resubscribe.after_seq, resubscribe.epoch.as_str()),
            (40, epoch().as_str())
        );
        assert!(status.shown().is_some());
        let out = serialized(&kept);
        assert!(!out.contains("S-1-5-21") && !out.contains("13572"), "{out}");
    }
    assert_eq!(
        events::sanitize(&snapshot("whim", without_peer.clone())),
        Ok(None)
    );
    let mut writable = without_peer;
    writable["read_only"] = json!(false);
    assert_eq!(
        events::sanitize(&snapshot("gap", writable)),
        Err(Incompatible)
    );
}

#[test]
fn truncated_data_is_shown_as_withheld() {
    let value = event(
        9,
        "request.completed",
        Value::Null,
        Value::Null,
        json!({ "truncated": true, "bytes": 20_000 }),
    );
    let kept = events::sanitize(&value).unwrap().unwrap();
    assert_eq!(
        kept.body,
        EventBody::TooLarge {
            of_kind: "request.completed",
            bytes: Field::Shown(20_000)
        }
    );
}

#[test]
fn unknown_event_kinds_and_bad_positions_are_dropped() {
    for kind in [
        "app_api.endpoint_lost",
        "approval.granted",
        "task.stopped",
        "",
        "SNAPSHOT",
    ] {
        let value = event(10, kind, Value::Null, Value::Null, json!({ "reason": "x" }));
        assert_eq!(events::sanitize(&value), Ok(None), "{kind}");
    }
    let mut bad_epoch = event(
        11,
        "daemon.started",
        Value::Null,
        Value::Null,
        json!({ "mode": "m" }),
    );
    bad_epoch["epoch"] = json!("1A-2B");
    assert_eq!(events::sanitize(&bad_epoch), Ok(None));
    let mut bad_seq = event(
        12,
        "daemon.started",
        Value::Null,
        Value::Null,
        json!({ "mode": "m" }),
    );
    bad_seq["seq"] = json!(-1);
    assert_eq!(events::sanitize(&bad_seq), Ok(None));
}

#[test]
fn unknown_event_fields_are_counted() {
    let mut value = event(
        13,
        "daemon.started",
        json!("r1"),
        Value::Null,
        json!({ "pid": 1, "mode": "m", "extra": 2 }),
    );
    value["new_top"] = json!(true);
    let kept = events::sanitize(&value).unwrap().unwrap();
    // run_id on a non-task event, a new top-level field, a new data field.
    assert_eq!(kept.withheld, 3);
}

// ---------------------------------------------------------------------------
// Report tasks
// ---------------------------------------------------------------------------

/// `summary(owner)` of orceld.
fn summary(task_id: &str, state: &str, owner: &str) -> Value {
    json!({
        "task_id": task_id,
        "kind": "report",
        "title": "Q3 revenue summary for the board \u{202e}secret",
        "state": state,
        "workspace_id": "default",
        "created_at_ms": 1_763_301_000_000u64,
        "updated_at_ms": 1_763_301_100_000u64,
        "owner": owner,
    })
}

/// `detail(owner)` of a verified task with a workbook source.
fn detail() -> Value {
    let mut value = summary("r-0001-6a2f", "verified", "this_session");
    let object = value.as_object_mut().unwrap();
    object.insert("folder".into(), json!("reports"));
    object.insert(
        "sources".into(),
        json!([
            { "path": "data/q3.csv", "sha256": SHA, "bytes": 61 },
            { "path": "data/q3.xlsx", "sha256": SHA, "bytes": 8_812 },
        ]),
    );
    object.insert(
        "proposal".into(),
        json!({ "name": "q3.md", "destination": "reports/q3.md", "sha256": SHA, "bytes": 120 }),
    );
    object.insert(
        "report".into(),
        json!({ "name": "q3.md", "destination": "reports/q3.md", "sha256": SHA, "bytes": 120 }),
    );
    object.insert(
        "check".into(),
        json!({
            "checker": "orcel-report-check/1",
            "passed": true,
            "destination": "reports/q3.md",
            "bytes": 120,
            "sha256": SHA,
            "sources_unchanged": 2,
            "checked_at_ms": 1_763_301_100_000u64,
            "figures_confirmed": 3,
        }),
    );
    object.insert(
        "steps".into(),
        json!([
            { "step_id": "s1", "kind": "observe", "outcome": "ok", "at_ms": 1 },
            { "step_id": "s2", "kind": "preview", "outcome": "ok", "at_ms": 2 },
            { "step_id": "s3", "kind": "approval", "outcome": "approved", "at_ms": 3 },
            { "step_id": "s4", "kind": "verify", "outcome": "passed", "at_ms": 4 },
        ]),
    );
    value
}

#[test]
fn task_list_keeps_summaries_without_titles() {
    let value = json!({
        "max_tasks": 64,
        "tasks": [
            summary("r-0002-6a30", "proposed", "this_session"),
            summary("r-0001-6a2f", "stopped", "earlier_run"),
            summary("x-9", "committing", "other_session"),
        ],
    });
    let list = tasks::list(&value);
    assert_eq!(list.tasks.len(), 3);
    assert_eq!(list.tasks[1].state, TaskState::Stopped);
    assert_eq!(list.tasks[2].owner, tasks::Owner::OtherSession);
    assert_eq!(list.withheld, 0);
    let out = serialized(&list);
    assert!(
        !out.contains("title") && !out.contains("board") && !out.contains("secret"),
        "{out}"
    );
}

#[test]
fn task_records_with_out_of_enum_values_or_bad_ids_are_refused() {
    let mut bad_kind = summary("r1", "proposed", "this_session");
    bad_kind["kind"] = json!("deploy");
    let mut bad_workspace = summary("r1", "proposed", "this_session");
    bad_workspace["workspace_id"] = json!("../other");
    let value = json!({
        "tasks": [
            summary("r1", "exploded", "this_session"),
            summary("r2", "proposed", "root"),
            summary("r/3", "proposed", "this_session"),
            bad_kind,
            bad_workspace,
            summary("ok-1", "failed", "earlier_run"),
        ],
    });
    let list = tasks::list(&value);
    assert_eq!(list.tasks.len(), 1);
    assert_eq!(list.tasks[0].task_id, "ok-1");
    assert_eq!(list.withheld, 5);
    for value in [
        summary("r1", "exploded", "this_session"),
        summary("r1", "proposed", "admin"),
        summary("", "proposed", "this_session"),
    ] {
        assert_eq!(tasks::detail(&value), Err(tasks::TaskWithheld));
    }
}

#[test]
fn task_list_is_capped_at_64() {
    let value = json!({
        "tasks": (0..70).map(|i| summary(&format!("r{i}"), "observed", "this_session")).collect::<Vec<_>>(),
    });
    let list = tasks::list(&value);
    assert_eq!(list.tasks.len(), tasks::MAX_TASKS);
    assert_eq!(list.withheld, 6);
}

#[test]
fn task_detail_keeps_named_metadata_only() {
    let task = tasks::detail(&detail()).unwrap();
    assert_eq!(task.summary.task_id, "r-0001-6a2f");
    assert_eq!(task.folder, Field::Shown("reports".into()));
    assert_eq!(task.sources.len(), 2);
    assert_eq!(task.sources[1].path, Field::Shown("data/q3.xlsx".into()));
    assert_eq!(task.sources[1].sha256, Field::Shown(SHA.into()));
    let report = task.report.shown().unwrap();
    assert_eq!(report.name, Field::Shown("q3.md".into()));
    assert_eq!(report.destination, Field::Shown("reports/q3.md".into()));
    let check = task.check.shown().unwrap();
    assert_eq!(check.passed, Field::Shown(true));
    assert_eq!(check.figures_confirmed, Field::Shown(3));
    assert_eq!(check.sources_unchanged, Field::Shown(2));
    assert_eq!(task.steps.len(), 4);
    assert_eq!(task.steps[2].outcome, Known::Known(StepOutcome::Approved));
    assert_eq!(task.withheld, 0);
    let out = serialized(&task);
    assert!(!out.contains("title") && !out.contains("board"), "{out}");
}

#[test]
fn every_path_field_withholds_hostile_values() {
    for hostile in hostile_paths() {
        let mut value = detail();
        value["folder"] = json!(hostile);
        value["sources"][0]["path"] = json!(hostile);
        value["proposal"]["destination"] = json!(hostile);
        value["report"]["destination"] = json!(hostile);
        value["check"]["destination"] = json!(hostile);
        let task = tasks::detail(&value).unwrap();
        assert_eq!(task.folder, Field::Withheld, "{hostile:?}");
        assert_eq!(task.sources[0].path, Field::Withheld, "{hostile:?}");
        assert_eq!(task.proposal.shown().unwrap().destination, Field::Withheld);
        assert_eq!(task.report.shown().unwrap().destination, Field::Withheld);
        assert_eq!(task.check.shown().unwrap().destination, Field::Withheld);
        assert_eq!(task.withheld, 5, "{hostile:?}");
        if !hostile.is_empty() {
            assert!(!serialized(&task).contains(&serde_json::to_string(&hostile).unwrap()));
        }
    }
}

#[test]
fn names_with_separators_and_malformed_hashes_are_withheld() {
    let mut value = detail();
    value["proposal"]["name"] = json!("reports/q3.md");
    value["report"]["name"] = json!("..\\q3.md");
    value["sources"][0]["sha256"] = json!(SHA.to_uppercase());
    value["sources"][1]["sha256"] = json!("abc");
    value["proposal"]["sha256"] = json!(format!("{SHA}00"));
    value["check"]["sha256"] = json!(null);
    let task = tasks::detail(&value).unwrap();
    assert_eq!(task.proposal.shown().unwrap().name, Field::Withheld);
    assert_eq!(task.report.shown().unwrap().name, Field::Withheld);
    assert_eq!(task.sources[0].sha256, Field::Withheld);
    assert_eq!(task.sources[1].sha256, Field::Withheld);
    assert_eq!(task.proposal.shown().unwrap().sha256, Field::Withheld);
    assert_eq!(task.check.shown().unwrap().sha256, Field::Absent);
    assert_eq!(task.withheld, 5);
}

#[test]
fn another_checker_drops_the_check_and_failure_reasons_never_pass() {
    let mut value = detail();
    value["check"]["checker"] = json!("someone-else/1");
    let task = tasks::detail(&value).unwrap();
    assert_eq!(task.check, Field::Withheld);
    assert_eq!(task.withheld, 1);

    let mut failed = detail();
    failed["check"] = json!({ "checker": "orcel-report-check/1", "passed": false, "reason": "C:\\Users\\me\\secret.txt changed" });
    let task = tasks::detail(&failed).unwrap();
    assert_eq!(task.check.shown().unwrap().passed, Field::Shown(false));
    assert!(!serialized(&task).contains("secret"));
}

#[test]
fn out_of_enum_step_values_become_other_and_bad_step_ids_drop_the_step() {
    let mut value = detail();
    value["steps"] = json!([
        { "step_id": "s1", "kind": "levitate", "outcome": "ok", "at_ms": 1 },
        { "step_id": "s2", "kind": "verify", "outcome": "rm -rf /", "at_ms": 2 },
        { "step_id": "x2", "kind": "verify", "outcome": "passed", "at_ms": 3 },
    ]);
    let task = tasks::detail(&value).unwrap();
    assert_eq!(task.steps.len(), 2);
    assert_eq!(task.steps[0].kind, Known::Other(OtherValue::Other));
    assert_eq!(task.steps[1].outcome, Known::Other(OtherValue::Other));
    assert_eq!(task.withheld, 1);
    let out = serialized(&task);
    assert!(!out.contains("levitate") && !out.contains("rm -rf"));
}

#[test]
fn sources_and_steps_are_capped() {
    let mut value = detail();
    value["sources"] = Value::Array(
        (0..70)
            .map(|i| json!({ "path": format!("data/{i}.csv"), "sha256": SHA, "bytes": i }))
            .collect(),
    );
    value["steps"] = Value::Array(
        (1..=40)
            .map(|i| json!({ "step_id": format!("s{i}"), "kind": "observe", "outcome": "ok", "at_ms": i }))
            .collect(),
    );
    let task = tasks::detail(&value).unwrap();
    assert_eq!(task.sources.len(), tasks::MAX_SOURCES);
    assert_eq!(task.steps.len(), tasks::MAX_STEPS);
    assert_eq!(task.withheld, 6 + 8);
}

#[test]
fn unknown_task_fields_are_dropped_and_counted() {
    let mut value = detail();
    value["content"] = json!("the whole report text");
    value["sources"][0]["text"] = json!("source file text");
    value["report"]["body"] = json!("report body");
    let task = tasks::detail(&value).unwrap();
    assert_eq!(task.withheld, 3);
    let out = serialized(&task);
    assert!(
        !out.contains("report text")
            && !out.contains("source file text")
            && !out.contains("report body")
    );
}

// ---------------------------------------------------------------------------
// The step enums against orceld's own sources
// ---------------------------------------------------------------------------

/// orceld's sources with LF line endings, whatever the checkout's.
fn source(text: &str) -> String {
    text.replace("\r\n", "\n")
}

const REPORT_TASK: &str = include_str!("../../../orceld/src/report_task.rs");
const REPORT_JOURNAL: &str = include_str!("../../../orceld/src/report_journal.rs");

/// The call's argument list after `open` (just past its `(`), split at
/// top-level commas.
fn arguments(source: &str, open: usize) -> Vec<String> {
    let mut depth = 0i32;
    let mut current = String::new();
    let mut args = Vec::new();
    let mut in_string = false;
    let mut chars = source[open..].chars();
    while let Some(c) = chars.next() {
        if in_string {
            current.push(c);
            if c == '\\' {
                if let Some(escaped) = chars.next() {
                    current.push(escaped);
                }
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                current.push(c);
            }
            '(' | '[' | '{' => {
                depth += 1;
                current.push(c);
            }
            ')' | ']' | '}' if depth == 0 => {
                args.push(current.trim().to_owned());
                return args;
            }
            ')' | ']' | '}' => {
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => {
                args.push(current.trim().to_owned());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    args
}

fn literal(arg: &str) -> Option<&str> {
    arg.strip_prefix('"')?.strip_suffix('"')
}

/// The step kinds and outcomes orceld records, read from its sources.
fn orceld_step_values() -> (Vec<String>, Vec<String>) {
    let task_rs = source(REPORT_TASK);
    let task_rs = task_rs.as_str();
    let journal_rs = source(REPORT_JOURNAL);
    let journal_rs = journal_rs.as_str();
    let mut kinds = Vec::new();
    let mut outcomes = Vec::new();
    // `tasks.update(task, kind, outcome, ..)`, `.update_if(task, kind,
    // outcome, ..)` and `blocked(tasks, task, kind, ..)`.
    for needle in [".update(", ".update_if(", "blocked(tasks, "] {
        for (at, _) in task_rs.match_indices(needle) {
            let open = if needle.ends_with(", ") {
                at + "blocked(".len()
            } else {
                at + needle.len()
            };
            let args = arguments(task_rs, open);
            if needle.starts_with("blocked") {
                if let Some(kind) = args.get(2).and_then(|a| literal(a)) {
                    kinds.push(kind.to_owned());
                }
                continue;
            }
            if let Some(kind) = args.get(1).and_then(|a| literal(a)) {
                kinds.push(kind.to_owned());
            }
            if let Some(outcome) = args.get(2).and_then(|a| literal(a)) {
                outcomes.push(outcome.to_owned());
            }
        }
    }
    // `kind: "run".to_owned(), outcome: "orceld_run_ended".to_owned()` and
    // `kind: "reconcile".to_owned()` in the journal.
    for (at, _) in journal_rs.match_indices("kind: \"") {
        let rest = &journal_rs[at + "kind: \"".len()..];
        kinds.push(rest[..rest.find('"').unwrap()].to_owned());
    }
    for (at, _) in journal_rs.match_indices("outcome: \"") {
        let rest = &journal_rs[at + "outcome: \"".len()..];
        outcomes.push(rest[..rest.find('"').unwrap()].to_owned());
    }
    // `Reconciled::outcome`, the reconcile step's outcomes.
    let start = journal_rs
        .find("fn outcome(&self) -> &'static str")
        .expect("Reconciled::outcome");
    let body = &journal_rs[start..start + journal_rs[start..].find("\n    }\n").unwrap()];
    for (at, _) in body.match_indices("=> \"") {
        let rest = &body[at + "=> \"".len()..];
        outcomes.push(rest[..rest.find('"').unwrap()].to_owned());
    }
    // `blocked` itself records these outcomes for its kind.
    let blocked = &task_rs[task_rs.find("fn blocked(").unwrap()..];
    let blocked = &blocked[..blocked.find("\n}\n").unwrap()];
    for (at, _) in blocked.match_indices("kind, \"") {
        let rest = &blocked[at + "kind, \"".len()..];
        outcomes.push(rest[..rest.find('"').unwrap()].to_owned());
    }
    kinds.sort();
    kinds.dedup();
    outcomes.sort();
    outcomes.dedup();
    (kinds, outcomes)
}

#[test]
fn step_enums_match_orceld_sources() {
    let (kinds, outcomes) = orceld_step_values();
    let mut ours_kinds: Vec<String> = StepKind::ALL
        .iter()
        .map(|k| k.as_str().to_owned())
        .collect();
    ours_kinds.sort();
    let mut ours_outcomes: Vec<String> = StepOutcome::ALL
        .iter()
        .map(|o| o.as_str().to_owned())
        .collect();
    ours_outcomes.sort();
    assert_eq!(
        kinds, ours_kinds,
        "step kinds in report_task.rs and report_journal.rs"
    );
    assert_eq!(
        outcomes, ours_outcomes,
        "step outcomes in report_task.rs and report_journal.rs"
    );
}

#[test]
fn task_states_match_orceld_sources() {
    let task_rs = source(REPORT_TASK);
    let task_rs = task_rs.as_str();
    for state in TaskState::ALL {
        assert!(
            task_rs.contains(&format!("=> \"{}\",", state.as_str())),
            "{} is not a TaskState::as_str value",
            state.as_str()
        );
    }
    let start = task_rs
        .find("pub(crate) fn as_str(self) -> &'static str {")
        .unwrap();
    let body = &task_rs[start..start + task_rs[start..].find("\n    }\n").unwrap()];
    assert_eq!(body.matches("=> \"").count(), TaskState::ALL.len());
    for owner in tasks::Owner::ALL {
        assert!(task_rs.contains(&format!("= \"{}\";", owner.as_str())));
    }
    assert!(
        include_str!("../../../orceld/src/report_check.rs").contains(&format!(
            "pub(crate) const CHECKER: &str = \"{}\";",
            tasks::CHECKER
        ))
    );
}

#[test]
fn no_output_type_has_a_title_field() {
    let task = tasks::detail(&detail()).unwrap();
    let list = tasks::list(&json!({ "tasks": [summary("r1", "observed", "this_session")] }));
    for out in [serialized(&task), serialized(&list)] {
        assert!(!out.contains("\"title\""), "{out}");
    }
}

#[test]
fn the_sanitiser_never_touches_the_file_system() {
    for (file, source) in [
        ("rules.rs", include_str!("rules.rs")),
        ("mod.rs", include_str!("mod.rs")),
        ("status.rs", include_str!("status.rs")),
        ("capabilities.rs", include_str!("capabilities.rs")),
        ("events.rs", include_str!("events.rs")),
        ("tasks.rs", include_str!("tasks.rs")),
    ] {
        for line in source.lines().filter(|l| !l.trim_start().starts_with("//")) {
            for call in [
                "std::fs",
                "fs::",
                "File",
                "Path",
                "canonicalize",
                "read_link",
                "metadata",
            ] {
                assert!(!line.contains(call), "{file} uses {call}: {line}");
            }
        }
    }
}
