//! Report tasks, `task.list` and `task.get` (founder decision 5): read-only
//! metadata. Paths, sizes, hashes, states and step outcomes; never a title,
//! report content or source content. Paths pass the path rule and are never
//! opened, joined to a workspace root or resolved.

use super::rules;
use super::status::nested;
use super::{bool_field, count_unknown, str_field, u64_field, Field, Withheld};
use serde::Serialize;
use serde_json::{Map, Value};

/// orceld's `MAX_TASKS`: at most this many tasks in a list.
pub const MAX_TASKS: usize = 64;
/// At most this many sources per task.
pub const MAX_SOURCES: usize = 64;
/// orceld's `MAX_STEPS`: at most this many steps per task.
pub const MAX_STEPS: usize = 32;
/// The only checker whose record is shown (`report_check::CHECKER`).
pub const CHECKER: &str = "orcel-report-check/1";

/// Defines a closed enum of the snake_case values orceld emits.
macro_rules! closed_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
        pub enum $name {
            $(#[serde(rename = $text)] $variant,)+
        }

        impl $name {
            /// Every value, in declaration order.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            pub fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $text,)+
                }
            }

            pub fn parse(text: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|value| value.as_str() == text)
            }
        }
    };
}

closed_enum!(
    /// `TaskState::as_str` in `crates/orceld/src/report_task.rs`.
    TaskState {
        Observed => "observed",
        Proposed => "proposed",
        ApprovalDenied => "approval_denied",
        Committing => "committing",
        Verified => "verified",
        VerificationFailed => "verification_failed",
        Stale => "stale",
        Failed => "failed",
        Stopped => "stopped",
    }
);

closed_enum!(
    /// `OWNER_*` in `crates/orceld/src/report_task.rs`.
    Owner {
        ThisSession => "this_session",
        OtherSession => "other_session",
        EarlierRun => "earlier_run",
    }
);

closed_enum!(
    /// The only task kind orceld serves.
    TaskKind {
        Report => "report",
    }
);

closed_enum!(
    /// Step kinds orceld records: `update` and `update_if` calls and
    /// `blocked` kinds in `crates/orceld/src/report_task.rs`, and the
    /// `run` and `reconcile` steps of `crates/orceld/src/report_journal.rs`.
    /// Pinned by `step_enums_match_orceld_sources`.
    StepKind {
        Observe => "observe",
        Preview => "preview",
        Commit => "commit",
        Approval => "approval",
        Write => "write",
        Verify => "verify",
        Stop => "stop",
        Reconcile => "reconcile",
        Run => "run",
    }
);

closed_enum!(
    /// Step outcomes orceld records, from the same places as [`StepKind`].
    StepOutcome {
        Ok => "ok",
        Stale => "stale",
        DestinationExists => "destination_exists",
        Error => "error",
        NotPreviewed => "not_previewed",
        Denied => "denied",
        Unavailable => "unavailable",
        Approved => "approved",
        ApprovedAfterStop => "approved_after_stop",
        ApprovedAfterChange => "approved_after_change",
        Reopened => "reopened",
        Failed => "failed",
        Passed => "passed",
        Stopped => "stopped",
        NothingWritten => "nothing_written",
        Verified => "verified",
        Unknown => "unknown",
        OrceldRunEnded => "orceld_run_ended",
    }
);

/// A step kind or outcome: a known value, or `other`, never the text orceld
/// sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Known<T> {
    Known(T),
    Other(OtherValue),
}

/// Serializes as the string `"other"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OtherValue {
    #[serde(rename = "other")]
    Other,
}

impl<T> Known<T> {
    fn of(value: Option<T>) -> Self {
        value.map_or(Known::Other(OtherValue::Other), Known::Known)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaskSummary {
    pub task_id: String,
    pub workspace_id: String,
    pub kind: TaskKind,
    pub state: TaskState,
    pub owner: Owner,
    pub created_at_ms: Field<u64>,
    pub updated_at_ms: Field<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaskList {
    pub tasks: Vec<TaskSummary>,
    pub withheld: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Source {
    pub path: Field<String>,
    pub sha256: Field<String>,
    pub bytes: Field<u64>,
}

/// A proposal or a written report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Document {
    pub name: Field<String>,
    pub destination: Field<String>,
    pub sha256: Field<String>,
    pub bytes: Field<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub checker: &'static str,
    pub passed: Field<bool>,
    pub destination: Field<String>,
    pub bytes: Field<u64>,
    pub sha256: Field<String>,
    pub sources_unchanged: Field<u64>,
    pub figures_confirmed: Field<u64>,
    pub checked_at_ms: Field<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Step {
    pub step_id: String,
    pub kind: Known<StepKind>,
    pub outcome: Known<StepOutcome>,
    pub at_ms: Field<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaskDetail {
    #[serde(flatten)]
    pub summary: TaskSummary,
    pub folder: Field<String>,
    pub sources: Vec<Source>,
    pub proposal: Field<Document>,
    pub report: Field<Document>,
    pub check: Field<Check>,
    pub steps: Vec<Step>,
    pub withheld: u32,
}

/// The task record was refused: an identifier, kind, state or owner failed
/// its rule, so nothing of it is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskWithheld;

const SUMMARY_KEPT: &[&str] = &[
    "task_id",
    "workspace_id",
    "kind",
    "state",
    "owner",
    "created_at_ms",
    "updated_at_ms",
];
const DETAIL_KEPT: &[&str] = &["folder", "sources", "proposal", "report", "check", "steps"];
/// The planner-written title is free text that decision 5 does not list.
const TITLE: &[&str] = &["title"];

fn enum_of<T>(object: &Map<String, Value>, key: &str, parse: fn(&str) -> Option<T>) -> Option<T> {
    object.get(key)?.as_str().and_then(parse)
}

/// The summary fields, or `None` when the record must be dropped.
fn summary(object: &Map<String, Value>, withheld: &mut Withheld) -> Option<TaskSummary> {
    let task_id = rules::identifier(object.get("task_id")?.as_str()?)?;
    let workspace_id = rules::identifier(object.get("workspace_id")?.as_str()?)?;
    let kind = enum_of(object, "kind", TaskKind::parse)?;
    let state = enum_of(object, "state", TaskState::parse)?;
    let owner = enum_of(object, "owner", Owner::parse)?;
    Some(TaskSummary {
        task_id,
        workspace_id,
        kind,
        state,
        owner,
        created_at_ms: u64_field(object.get("created_at_ms"), withheld),
        updated_at_ms: u64_field(object.get("updated_at_ms"), withheld),
    })
}

/// Sanitises a `task.list` result: at most [`MAX_TASKS`] summaries; a
/// refused record or an excess one is dropped and counted.
pub fn list(value: &Value) -> TaskList {
    let mut withheld = Withheld::default();
    let mut tasks = Vec::new();
    match value.as_object() {
        Some(object) => {
            count_unknown(object, &["tasks"], &["max_tasks"], &mut withheld);
            match object.get("tasks") {
                Some(Value::Array(entries)) => {
                    for entry in entries {
                        if tasks.len() >= MAX_TASKS {
                            withheld.one();
                            continue;
                        }
                        let mut inner = Withheld::default();
                        let kept = entry.as_object().and_then(|object| {
                            count_unknown(object, SUMMARY_KEPT, TITLE, &mut inner);
                            summary(object, &mut inner)
                        });
                        match kept {
                            Some(task) => {
                                withheld.add(inner.0 as usize);
                                tasks.push(task);
                            }
                            None => withheld.one(),
                        }
                    }
                }
                None | Some(Value::Null) => {}
                Some(_) => withheld.one(),
            }
        }
        None => withheld.one(),
    }
    TaskList {
        tasks,
        withheld: withheld.0,
    }
}

fn source(value: &Value, withheld: &mut Withheld) -> Option<Source> {
    let object = value.as_object()?;
    count_unknown(object, &["path", "sha256", "bytes"], &[], withheld);
    Some(Source {
        path: str_field(object.get("path"), rules::workspace_path, withheld),
        sha256: str_field(object.get("sha256"), rules::sha256, withheld),
        bytes: u64_field(object.get("bytes"), withheld),
    })
}

fn document(value: &Value, withheld: &mut Withheld) -> Option<Document> {
    let object = value.as_object()?;
    count_unknown(
        object,
        &["name", "destination", "sha256", "bytes"],
        &[],
        withheld,
    );
    Some(Document {
        name: str_field(object.get("name"), rules::file_name, withheld),
        destination: str_field(object.get("destination"), rules::workspace_path, withheld),
        sha256: str_field(object.get("sha256"), rules::sha256, withheld),
        bytes: u64_field(object.get("bytes"), withheld),
    })
}

/// The checker's record, only for [`CHECKER`]; any other checker drops it.
fn check(value: &Value, withheld: &mut Withheld) -> Option<Check> {
    let object = value.as_object()?;
    if object.get("checker")?.as_str()? != CHECKER {
        return None;
    }
    count_unknown(
        object,
        &[
            "checker",
            "passed",
            "destination",
            "bytes",
            "sha256",
            "sources_unchanged",
            "figures_confirmed",
            "checked_at_ms",
        ],
        &["reason"],
        withheld,
    );
    Some(Check {
        checker: CHECKER,
        passed: bool_field(object.get("passed"), withheld),
        destination: str_field(object.get("destination"), rules::workspace_path, withheld),
        bytes: u64_field(object.get("bytes"), withheld),
        sha256: str_field(object.get("sha256"), rules::sha256, withheld),
        sources_unchanged: u64_field(object.get("sources_unchanged"), withheld),
        figures_confirmed: u64_field(object.get("figures_confirmed"), withheld),
        checked_at_ms: u64_field(object.get("checked_at_ms"), withheld),
    })
}

fn step(value: &Value, withheld: &mut Withheld) -> Option<Step> {
    let object = value.as_object()?;
    let step_id = rules::step_id(object.get("step_id")?.as_str()?)?;
    count_unknown(
        object,
        &["step_id", "kind", "outcome", "at_ms"],
        &[],
        withheld,
    );
    Some(Step {
        step_id,
        kind: Known::of(enum_of(object, "kind", StepKind::parse)),
        outcome: Known::of(enum_of(object, "outcome", StepOutcome::parse)),
        at_ms: u64_field(object.get("at_ms"), withheld),
    })
}

/// Reads an array of at most `max` entries; a refused or excess entry is
/// dropped and counted.
fn bounded<T>(
    value: Option<&Value>,
    max: usize,
    withheld: &mut Withheld,
    read: impl Fn(&Value, &mut Withheld) -> Option<T>,
) -> Vec<T> {
    let mut kept = Vec::new();
    match value {
        Some(Value::Array(entries)) => {
            for entry in entries {
                if kept.len() >= max {
                    withheld.one();
                    continue;
                }
                let mut inner = Withheld::default();
                match read(entry, &mut inner) {
                    Some(entry) => {
                        withheld.add(inner.0 as usize);
                        kept.push(entry);
                    }
                    None => withheld.one(),
                }
            }
        }
        None | Some(Value::Null) => {}
        Some(_) => withheld.one(),
    }
    kept
}

/// Sanitises a `task.get` result.
pub fn detail(value: &Value) -> Result<TaskDetail, TaskWithheld> {
    let object = value.as_object().ok_or(TaskWithheld)?;
    let mut withheld = Withheld::default();
    let w = &mut withheld;
    let kept: Vec<&str> = SUMMARY_KEPT.iter().chain(DETAIL_KEPT).copied().collect();
    count_unknown(object, &kept, TITLE, w);
    let summary = summary(object, w).ok_or(TaskWithheld)?;
    let folder = str_field(object.get("folder"), rules::workspace_path, w);
    let sources = bounded(object.get("sources"), MAX_SOURCES, w, source);
    let proposal = nested(object.get("proposal"), w, document);
    let report = nested(object.get("report"), w, document);
    let check = nested(object.get("check"), w, check);
    let steps = bounded(object.get("steps"), MAX_STEPS, w, step);
    Ok(TaskDetail {
        summary,
        folder,
        sources,
        proposal,
        report,
        check,
        steps,
        withheld: withheld.0,
    })
}

/// The state of a `task.updated` event, `None` when outside the enum.
pub(crate) fn task_state(value: Option<&Value>) -> Option<TaskState> {
    value?.as_str().and_then(TaskState::parse)
}

/// The step kind and outcome of a `task.updated` event, `other` when
/// outside the enums.
pub(crate) fn step_kind(value: Option<&Value>) -> Known<StepKind> {
    Known::of(value.and_then(Value::as_str).and_then(StepKind::parse))
}

pub(crate) fn step_outcome(value: Option<&Value>) -> Known<StepOutcome> {
    Known::of(value.and_then(Value::as_str).and_then(StepOutcome::parse))
}
