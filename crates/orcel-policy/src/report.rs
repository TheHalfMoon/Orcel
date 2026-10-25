//! SG-000126 (roadmap F2): admission of the kernel `report` task shapes.
//!
//! Policy checks the shape of each request only: the operation, the
//! closed argument set and the bounds of every argument. Whether a source
//! is unchanged, a folder kept its identity or a destination is absent is
//! decided by orceld when it handles the task, never here and never by the
//! caller.

use crate::{validate_relative_target, PolicyError};
use orcel_contracts::{FailureCode, RequestEnvelope};
use serde_json::{Map, Value};

/// The capability name of the report task.
pub const REPORT_CAPABILITY: &str = "report";
/// Longest task title, in characters.
pub const MAX_REPORT_TITLE_CHARS: usize = 120;
/// Most source files one task observes.
pub const MAX_REPORT_SOURCES: usize = 8;
/// Largest report, in bytes of UTF-8.
pub const MAX_REPORT_BYTES: usize = 256 * 1024;
/// Longest report file name, in characters.
pub const MAX_REPORT_NAME_CHARS: usize = 96;
/// The report file name extensions a task may create.
pub const REPORT_EXTENSIONS: &[&str] = &["md", "txt", "csv"];
/// orceld's task ids: this prefix and 32 lowercase hex digits.
pub const REPORT_TASK_ID_PREFIX: &str = "rpt-";

/// The admitted shapes. `report/start` observes the sources and opens a
/// task (read-only); `report/preview` checks a proposal (no effect);
/// `report/commit` creates the report after one SOFT approval;
/// `report/resume_summary` (SG-000120 RJ-03) reads what a task did and
/// what is unknown (read-only, the caller's own task only). None is
/// remotely mappable.
pub const REPORT_SHAPES: &[(&str, &str)] = &[
    ("report", "start"),
    ("report", "preview"),
    ("report", "commit"),
    ("report", "resume_summary"),
];

pub fn is_report_shape(capability: &str, operation: &str) -> bool {
    REPORT_SHAPES.contains(&(capability, operation))
}

fn invalid(message: impl Into<String>) -> PolicyError {
    crate::policy_error(FailureCode::InvalidRequest, message)
}

fn only_fields(
    arguments: &Map<String, Value>,
    operation: &str,
    allowed: &[&str],
) -> Result<(), PolicyError> {
    match arguments
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
    {
        Some(key) => Err(invalid(format!(
            "report/{operation} does not accept argument field: {key}"
        ))),
        None => Ok(()),
    }
}

fn string_field<'a>(
    arguments: &'a Map<String, Value>,
    operation: &str,
    name: &str,
) -> Result<&'a str, PolicyError> {
    arguments.get(name).and_then(Value::as_str).ok_or_else(|| {
        invalid(format!(
            "report/{operation} requires string arguments.{name}"
        ))
    })
}

/// A workspace-relative path that names something below the root: not
/// empty, not the root itself, and no escape.
fn workspace_path(path: &str, what: &str) -> Result<(), PolicyError> {
    validate_relative_target(path)?;
    let trimmed = path.trim_matches(|c| c == '/' || c == '\\');
    if trimmed.is_empty()
        || trimmed
            .split(['/', '\\'])
            .all(|part| part.is_empty() || part == ".")
    {
        return Err(invalid(format!(
            "{what} must name a path below the workspace root"
        )));
    }
    if path.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{what} must not contain control characters"
        )));
    }
    Ok(())
}

/// orceld-generated task id: `rpt-` and 32 lowercase hex digits.
pub fn is_report_task_id(id: &str) -> bool {
    id.strip_prefix(REPORT_TASK_ID_PREFIX).is_some_and(|hex| {
        hex.len() == 32 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// One path component of letters, digits, '.', '_' or '-', not starting
/// with '.', at most [`MAX_REPORT_NAME_CHARS`], ending in an allowed
/// extension. Separators, `..`, drive and UNC forms cannot pass.
pub fn is_report_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_REPORT_NAME_CHARS || name.starts_with('.') {
        return false;
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return false;
    }
    let Some((stem, extension)) = name.rsplit_once('.') else {
        return false;
    };
    // Windows ignores trailing dots and treats these stems as devices; a
    // name that would not round-trip is refused on every OS.
    let device = stem.split('.').next().unwrap_or(stem).to_ascii_uppercase();
    let reserved = matches!(device.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((device.starts_with("COM") || device.starts_with("LPT"))
            && device.len() == 4
            && device.as_bytes()[3].is_ascii_digit());
    !stem.is_empty()
        && !stem.ends_with('.')
        && !reserved
        && REPORT_EXTENSIONS
            .iter()
            .any(|allowed| extension.eq_ignore_ascii_case(allowed))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn validate_proposal(arguments: &Map<String, Value>, operation: &str) -> Result<(), PolicyError> {
    let task_id = string_field(arguments, operation, "task_id")?;
    if !is_report_task_id(task_id) {
        return Err(invalid("report task_id must be an id orceld issued"));
    }
    let name = string_field(arguments, operation, "name")?;
    if !is_report_name(name) {
        return Err(crate::policy_error(
            FailureCode::PathEscape,
            format!(
                "report name must be one file name of letters, digits, '.', '_' or '-' (at most {MAX_REPORT_NAME_CHARS}, not starting with '.') ending in .md, .txt or .csv"
            ),
        ));
    }
    let content = string_field(arguments, operation, "content")?;
    if content.len() > MAX_REPORT_BYTES {
        return Err(crate::policy_error(
            FailureCode::OutputLimit,
            format!("report content exceeds {MAX_REPORT_BYTES} bytes"),
        ));
    }
    Ok(())
}

/// Validates one admitted `report/*` request's shape.
pub fn validate_report(request: &RequestEnvelope) -> Result<(), PolicyError> {
    if request.target.is_some() {
        return Err(invalid("report does not accept a target field"));
    }
    let arguments = request
        .arguments
        .as_object()
        .ok_or_else(|| invalid("report arguments must be an object"))?;
    let operation = request.operation.as_str();
    match operation {
        "start" => {
            only_fields(arguments, operation, &["title", "sources", "folder"])?;
            let title = string_field(arguments, operation, "title")?;
            if title.trim().is_empty()
                || title.chars().count() > MAX_REPORT_TITLE_CHARS
                || title.chars().any(char::is_control)
            {
                return Err(invalid(format!(
                    "report title must be 1..={MAX_REPORT_TITLE_CHARS} characters without control characters"
                )));
            }
            let sources = arguments
                .get("sources")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("report/start requires arguments.sources as an array"))?;
            if sources.is_empty() || sources.len() > MAX_REPORT_SOURCES {
                return Err(invalid(format!(
                    "report/start takes 1..={MAX_REPORT_SOURCES} sources"
                )));
            }
            let mut seen = Vec::with_capacity(sources.len());
            for source in sources {
                let source = source
                    .as_str()
                    .ok_or_else(|| invalid("report sources must be strings"))?;
                workspace_path(source, "a report source")?;
                if seen.contains(&source) {
                    return Err(invalid("report sources must be distinct"));
                }
                seen.push(source);
            }
            let folder = string_field(arguments, operation, "folder")?;
            workspace_path(folder, "the report folder")
        }
        "preview" => {
            only_fields(arguments, operation, &["task_id", "name", "content"])?;
            validate_proposal(arguments, operation)
        }
        "commit" => {
            only_fields(
                arguments,
                operation,
                &["task_id", "name", "content", "expected_sha256"],
            )?;
            validate_proposal(arguments, operation)?;
            let expected = string_field(arguments, operation, "expected_sha256")?;
            if !is_sha256_hex(expected) {
                return Err(invalid(
                    "report/commit expected_sha256 must be the preview's lowercase SHA-256",
                ));
            }
            Ok(())
        }
        "resume_summary" => {
            only_fields(arguments, operation, &["task_id"])?;
            let task = string_field(arguments, operation, "task_id")?;
            if !is_report_task_id(task) {
                return Err(invalid("report/resume_summary requires an orceld task id"));
            }
            Ok(())
        }
        other => Err(crate::policy_error(
            FailureCode::CapabilityDenied,
            format!("report accepts only start, preview, commit and resume_summary, not {other}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_contracts::INTERNAL_PROTOCOL_VERSION;
    use serde_json::json;

    fn request(operation: &str, arguments: Value) -> RequestEnvelope {
        RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "r".into(),
            client_session_id: "s".into(),
            workspace_id: "default".into(),
            capability: REPORT_CAPABILITY.into(),
            operation: operation.into(),
            target: None,
            arguments,
        }
    }

    const TASK: &str = "rpt-0123456789abcdef0123456789abcdef";

    fn code(request: &RequestEnvelope) -> FailureCode {
        validate_report(request).unwrap_err().code
    }

    #[test]
    fn sg126_admits_exactly_the_three_bounded_shapes() {
        assert!(is_report_shape("report", "start"));
        assert!(is_report_shape("report", "preview"));
        assert!(is_report_shape("report", "commit"));
        for operation in ["write", "overwrite", "get", "list", "approve", ""] {
            assert!(!is_report_shape("report", operation), "{operation}");
        }
        assert!(!is_report_shape("report.task", "start"));

        let start = request(
            "start",
            json!({"title": "Q3 totals", "sources": ["data/q3.csv", "data/q2.csv"], "folder": "reports"}),
        );
        validate_report(&start).expect("start");
        let preview = request(
            "preview",
            json!({"task_id": TASK, "name": "q3-summary.md", "content": "# Q3\n"}),
        );
        validate_report(&preview).expect("preview");
        let commit = request(
            "commit",
            json!({"task_id": TASK, "name": "q3-summary.md", "content": "# Q3\n", "expected_sha256": "a".repeat(64)}),
        );
        validate_report(&commit).expect("commit");
    }

    #[test]
    fn sg126_refuses_unknown_fields_targets_and_operations() {
        let mut start = request(
            "start",
            json!({"title": "t", "sources": ["a.csv"], "folder": "out", "overwrite": true}),
        );
        assert_eq!(code(&start), FailureCode::InvalidRequest);
        start.arguments = json!({"title": "t", "sources": ["a.csv"], "folder": "out"});
        start.target = Some("out".into());
        assert_eq!(code(&start), FailureCode::InvalidRequest);
        let commit = request(
            "commit",
            json!({"task_id": TASK, "name": "a.md", "content": "x", "expected_sha256": "a".repeat(64), "task_state": "verified"}),
        );
        assert_eq!(code(&commit), FailureCode::InvalidRequest);
        let other = request("write", json!({}));
        assert_eq!(code(&other), FailureCode::CapabilityDenied);
        let not_object = request("start", json!(["a.csv"]));
        assert_eq!(code(&not_object), FailureCode::InvalidRequest);
    }

    #[test]
    fn sg126_start_bounds_title_sources_and_folder() {
        let start = |title: Value, sources: Value, folder: Value| {
            request(
                "start",
                json!({"title": title, "sources": sources, "folder": folder}),
            )
        };
        let long = "x".repeat(MAX_REPORT_TITLE_CHARS + 1);
        for title in [json!(""), json!("  "), json!(long), json!("a\nb"), json!(7)] {
            assert_eq!(
                code(&start(title.clone(), json!(["a.csv"]), json!("out"))),
                FailureCode::InvalidRequest,
                "{title}"
            );
        }
        let nine: Vec<String> = (0..9).map(|i| format!("s{i}.csv")).collect();
        for sources in [
            json!([]),
            json!(nine),
            json!(["a.csv", "a.csv"]),
            json!([1]),
            json!("a.csv"),
        ] {
            assert_eq!(
                code(&start(json!("t"), sources.clone(), json!("out"))),
                FailureCode::InvalidRequest,
                "{sources}"
            );
        }
        for escape in [
            "../a.csv",
            "/etc/passwd",
            "C:\\x.csv",
            "\\\\server\\share\\a.csv",
            "a/../../b.csv",
        ] {
            assert_eq!(
                code(&start(json!("t"), json!([escape]), json!("out"))),
                FailureCode::PathEscape,
                "{escape}"
            );
            assert_eq!(
                code(&start(json!("t"), json!(["a.csv"]), json!(escape))),
                FailureCode::PathEscape,
                "{escape}"
            );
        }
        for root in [".", "", "./", "/"] {
            assert!(
                validate_report(&start(json!("t"), json!(["a.csv"]), json!(root))).is_err(),
                "{root:?}"
            );
        }
    }

    #[test]
    fn sg126_report_names_are_one_plain_file_name() {
        for good in ["q3.md", "Q3_summary-v2.txt", "totals.CSV", "a.b.md"] {
            assert!(is_report_name(good), "{good}");
        }
        let long = format!("{}.md", "a".repeat(MAX_REPORT_NAME_CHARS));
        for bad in [
            "",
            ".md",
            ".hidden.md",
            "a/b.md",
            "a\\b.md",
            "..",
            "../x.md",
            "C:x.md",
            "x.exe",
            "x.md.exe",
            "x",
            "x.",
            "x .md",
            "CON.md",
            "nul.txt",
            "com1.md",
            "lpt9.csv",
            "x..md",
            "x\u{0}.md",
            "r\u{e9}sum\u{e9}.md",
            &long,
        ] {
            assert!(!is_report_name(bad), "{bad:?}");
        }
        let preview = |name: &str| {
            request(
                "preview",
                json!({"task_id": TASK, "name": name, "content": "x"}),
            )
        };
        assert_eq!(code(&preview("../out.md")), FailureCode::PathEscape);
        assert_eq!(code(&preview("out.exe")), FailureCode::PathEscape);
    }

    #[test]
    fn sg126_proposals_bind_an_issued_task_id_bounded_content_and_a_hash() {
        for id in [
            "",
            "rpt-",
            "rpt-XYZ",
            "task-0123456789abcdef0123456789abcdef",
            &format!("{TASK}0"),
        ] {
            let preview = request(
                "preview",
                json!({"task_id": id, "name": "a.md", "content": "x"}),
            );
            assert_eq!(code(&preview), FailureCode::InvalidRequest, "{id}");
        }
        let big = "x".repeat(MAX_REPORT_BYTES + 1);
        let preview = request(
            "preview",
            json!({"task_id": TASK, "name": "a.md", "content": big}),
        );
        assert_eq!(code(&preview), FailureCode::OutputLimit);
        for hash in [
            json!("A".repeat(64)),
            json!("a".repeat(63)),
            json!(null),
            json!(5),
        ] {
            let commit = request(
                "commit",
                json!({"task_id": TASK, "name": "a.md", "content": "x", "expected_sha256": hash}),
            );
            assert_eq!(code(&commit), FailureCode::InvalidRequest);
        }
    }
}
