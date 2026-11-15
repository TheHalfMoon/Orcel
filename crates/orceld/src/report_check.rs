//! SG-000126 (roadmap F2): the independent checker of a created report.
//!
//! It shares no code with the writer: it does not use the workspace file
//! provider, the task registry or the approval path. It re-opens the
//! destination with plain `std::fs` reads and passes only when
//!
//! - the destination is a regular file, not a link or reparse point;
//! - the folder is not a link or reparse point and the destination's
//!   parent canonicalizes to the folder's path recorded at start;
//! - its size and SHA-256 are exactly the approved ones;
//! - every source still hashes to the value the task recorded, read again
//!   within its type's limit ([`source_limit`]);
//! - SG-000130: when the task has a workbook source, every figure the report
//!   states (`[source.xlsx]Sheet!Cell = value`) names one of the task's
//!   workbooks and is what that workbook last saved in the cell.
//!
//! A pass is the only way a report task becomes verified.
//!
//! # The checker's route for a workbook (SG-000130 W1)
//!
//! The checker re-reads each workbook source with its own plain read (a
//! regular file, not a link or reparse point, within the parser's input
//! bound), requires its SHA-256 to equal the recorded one, and hands exactly
//! those bytes to the pinned parser in a contained run of its own
//! ([`crate::document_parse::run_parser`], told to expect a workbook, so the
//! parser refuses anything else by sniffing before any parse). The pins come
//! in the [`Expectation`], from the report task, which loads them; the
//! checker shares only the pinned parser and that one function with the
//! writer. It uses neither the workspace provider, the task registry, the
//! writer's workbook module nor slice 2's workspace route. Its plain read
//! doesn't repeat the route's link, hard-link and handle checks: the SHA-256
//! equality binds the bytes, so a path swapped after the commit can only
//! yield the same bytes or a refusal, and what remains is a denial of
//! service bounded by the limit.
//!
//! **W1: compiled only into tests.** No build but a test has a workbook
//! source, so [`Pins`] is uninhabited elsewhere and the contained run is
//! compiled only for tests, until SG-000130 slice W2 admits this file as a
//! release caller of the parser.

use crate::report_task::{SourceKind, SourceRecord};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::Path;

#[cfg(test)]
use crate::document_parse::{run_parser, ParserPin};
#[cfg(test)]
use orcel_provider_process::contained::HelperPin;
#[cfg(test)]
use orcel_provider_process::document_parser::{DocumentFormat, MAX_INPUT_BYTES};

/// The checker's name and revision in its records.
pub(crate) const CHECKER: &str = "orcel-report-check/1";
/// The largest text source the checker re-reads; the provider's read limit.
const MAX_TEXT_SOURCE_BYTES: u64 = 1024 * 1024;
/// The largest workbook source the checker re-reads: the parser's input
/// bound.
#[cfg(test)]
const MAX_WORKBOOK_SOURCE_BYTES: u64 = MAX_INPUT_BYTES;
/// W1: no build but a test reads a workbook source.
#[cfg(not(test))]
const MAX_WORKBOOK_SOURCE_BYTES: u64 = 0;

/// The pinned helper and parser for the checker's own contained runs.
#[cfg(test)]
pub(crate) type Pins = (HelperPin, ParserPin);
/// W1: no build but a test has a workbook source, so there are no pins.
#[cfg(not(test))]
pub(crate) type Pins = std::convert::Infallible;

/// What the created report must be.
pub(crate) struct Expectation<'a> {
    pub root: &'a Path,
    /// The folder's path in the workspace (not resolved).
    pub folder_path: &'a Path,
    /// The folder's canonical path as the task recorded it at start. It is
    /// compared as recorded, never resolved again.
    pub folder: &'a Path,
    /// Workspace-relative destination.
    pub destination: &'a str,
    pub sha256: &'a str,
    pub bytes: u64,
    pub sources: &'a [SourceRecord],
    /// The pinned helper and parser for a workbook source's own contained
    /// run, as the report task loaded them; `None` refuses a workbook source.
    pub pins: Option<&'a Pins>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(windows)]
pub(crate) fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
pub(crate) fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

/// Reads at most `limit` bytes of a regular file that is not a link.
fn read_regular_file(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| format!("inspect: {error}"))?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err("is a link or reparse point".into());
    }
    if !metadata.is_file() {
        return Err("is not a regular file".into());
    }
    if metadata.len() > limit {
        return Err(format!("is larger than {limit} bytes"));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|error| format!("open: {error}"))?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read: {error}"))?;
    if bytes.len() as u64 > limit {
        return Err(format!("is larger than {limit} bytes"));
    }
    Ok(bytes)
}

/// Reads at most `limit` bytes of a regular file that is not a link and
/// returns its SHA-256 and size.
pub(crate) fn hash_regular_file(path: &Path, limit: u64) -> Result<(String, u64), String> {
    let bytes = read_regular_file(path, limit)?;
    Ok((hex(&Sha256::digest(&bytes)), bytes.len() as u64))
}

/// SG-000130: the most bytes the checker re-reads of a source, by its type:
/// the provider's read limit for text, the parser's input bound for a
/// workbook.
pub(crate) fn source_limit(source: &SourceRecord) -> u64 {
    match source.kind {
        SourceKind::Text => MAX_TEXT_SOURCE_BYTES,
        SourceKind::Workbook => MAX_WORKBOOK_SOURCE_BYTES,
    }
}

/// Whether the checker could re-read a source of this size: the report task
/// asks at start, so a source past its type's limit never starts a task.
pub(crate) fn within_limit(source: &SourceRecord) -> Result<(), String> {
    let limit = source_limit(source);
    if source.bytes > limit {
        return Err(format!(
            "source {} holds {} bytes; the independent checker re-reads at most {limit} of a {}",
            source.path,
            source.bytes,
            match source.kind {
                SourceKind::Text => "text source",
                SourceKind::Workbook => "workbook",
            }
        ));
    }
    Ok(())
}

/// One source read again by the checker's own plain read, within its type's
/// limit, only if it still hashes to the recorded value.
fn reread(root: &Path, source: &SourceRecord) -> Result<Vec<u8>, String> {
    let bytes = read_regular_file(&root.join(&source.path), source_limit(source))
        .map_err(|reason| format!("source {} {reason}", source.path))?;
    if hex(&Sha256::digest(&bytes)) != source.sha256 {
        return Err(format!(
            "source {} changed since the task observed it",
            source.path
        ));
    }
    Ok(bytes)
}

/// SG-000130: whether the checker can re-read every source as recorded. The
/// report task asks before every approval prompt, so a source the checker
/// could not re-read after the write never reaches a prompt.
pub(crate) fn sources_rereadable(root: &Path, sources: &[SourceRecord]) -> Result<(), String> {
    for source in sources {
        reread(root, source)?;
    }
    Ok(())
}

/// Checks the created report. `Ok` carries the check record; `Err` says
/// why the report does not verify.
pub(crate) fn check(expected: &Expectation<'_>) -> Result<serde_json::Value, String> {
    let path = expected.root.join(expected.destination);
    let report = read_regular_file(&path, expected.bytes)
        .map_err(|reason| format!("the destination {reason}"))?;
    let sha256 = hex(&Sha256::digest(&report));
    let bytes = report.len() as u64;
    let parent = path
        .parent()
        .and_then(|parent| fs::canonicalize(parent).ok())
        .ok_or("the destination's folder cannot be resolved")?;
    let folder = fs::symlink_metadata(expected.folder_path)
        .map_err(|error| format!("the task folder cannot be inspected: {error}"))?;
    if folder.file_type().is_symlink() || is_reparse_point(&folder) || !folder.is_dir() {
        return Err("the task folder is no longer a plain directory".into());
    }
    if parent != expected.folder {
        return Err("the destination is not in the task's folder".into());
    }
    if bytes != expected.bytes {
        return Err(format!(
            "the destination holds {bytes} bytes, {} were approved",
            expected.bytes
        ));
    }
    if sha256 != expected.sha256 {
        return Err("the destination's SHA-256 differs from the approved bytes".into());
    }
    // With a workbook source, every stated figure is part of the check.
    let has_workbook = expected
        .sources
        .iter()
        .any(|source| source.kind == SourceKind::Workbook);
    let figures = if has_workbook {
        let text = std::str::from_utf8(&report)
            .map_err(|_| "the report is not UTF-8, so its figures can't be read")?;
        let figures = figures_from(text, expected.sources)?;
        if figures.is_empty() {
            return Err("the report states no figure from its workbooks".into());
        }
        figures
    } else {
        Vec::new()
    };
    for source in expected.sources {
        let current = reread(expected.root, source)?;
        if source.kind == SourceKind::Workbook {
            check_figures(source, &current, &figures, expected.pins)?;
        }
    }
    let mut record = serde_json::json!({
        "checker": CHECKER,
        "passed": true,
        "destination": expected.destination,
        "bytes": bytes,
        "sha256": sha256,
        "sources_unchanged": expected.sources.len(),
        "checked_at_ms": orcel_approval::now_ms(),
    });
    if has_workbook {
        record["figures_confirmed"] = serde_json::json!(figures.len());
    }
    Ok(record)
}

/// Every figure that names `source`, against the workbook's saved cells in
/// the checker's own contained run over exactly the bytes it re-read.
fn check_figures(
    source: &SourceRecord,
    bytes: &[u8],
    figures: &[Figure<'_>],
    pins: Option<&Pins>,
) -> Result<(), String> {
    let mine: Vec<&Figure<'_>> = figures
        .iter()
        .filter(|figure| figure.source == source.path)
        .collect();
    if mine.is_empty() {
        return Ok(());
    }
    let markdown = parsed_workbook(bytes, &source.sha256, pins)
        .map_err(|reason| format!("source {}: {reason}", source.path))?;
    for figure in mine {
        let place = format!("[{}]{}!{}", figure.source, figure.sheet, figure.cell);
        match cell_value(&markdown, figure.sheet, figure.cell) {
            Some(saved) if saved == figure.value => {}
            Some(_) => return Err(format!("{place} doesn't match the workbook")),
            None => return Err(format!("{place} has no saved value in the workbook")),
        }
    }
    Ok(())
}

/// The workbook's Markdown from the checker's own contained run of the
/// pinned parser, which expects a workbook and refuses anything else by
/// sniffing before any parse. A cut text is refused: a figure must not rest
/// on part of a workbook.
#[cfg(test)]
fn parsed_workbook(bytes: &[u8], sha256: &str, pins: Option<&Pins>) -> Result<String, String> {
    let (helper, parser) = pins.ok_or("workbook sources are not available in this build")?;
    let document = run_parser(bytes, sha256, Some(DocumentFormat::Xlsx), helper, parser)
        .map_err(|error| error.message)?;
    if document.format != DocumentFormat::Xlsx {
        return Err("the file named as a workbook isn't one".into());
    }
    if document.truncated {
        return Err("the workbook is too large to read in full".into());
    }
    Ok(document.markdown)
}

/// W1: no build but a test has a workbook source or the pins to read one.
#[cfg(not(test))]
fn parsed_workbook(_bytes: &[u8], _sha256: &str, pins: Option<&Pins>) -> Result<String, String> {
    match pins {
        Some(never) => match *never {},
        None => Err("workbook sources are not available in this build".into()),
    }
}

/// One stated figure: `[source]Sheet!Cell = value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Figure<'a> {
    /// The workspace-relative path of the workbook it comes from.
    pub source: &'a str,
    /// The sheet's whole title as the parser shows it.
    pub sheet: &'a str,
    pub cell: &'a str,
    pub value: &'a str,
}

/// The figures of a report, each naming one of `sources`' workbooks: a
/// figure that names no source, a source the task didn't observe, or a
/// source that isn't a workbook, is an error.
pub(crate) fn figures_from<'a>(
    report: &'a str,
    sources: &[SourceRecord],
) -> Result<Vec<Figure<'a>>, String> {
    let figures = figures_in(report)?;
    for figure in &figures {
        match sources.iter().find(|source| source.path == figure.source) {
            Some(source) if source.kind == SourceKind::Workbook => {}
            Some(_) => {
                return Err(format!(
                    "a figure names {}, which isn't one of the task's workbooks",
                    figure.source
                ))
            }
            None => {
                return Err(format!(
                    "a figure names {}, which the task didn't observe",
                    figure.source
                ))
            }
        }
    }
    Ok(figures)
}

/// The `[source]Sheet!Cell = value` lines of a report. `source` is the
/// workspace-relative path of the workbook, as the task recorded it. A
/// sheet's title can't hold `[` or `]`, so the last `]` before the sheet ends
/// the source; it may hold `!`, so the last one divides it from the cell. A
/// hidden sheet's title says so: `[data/q3.xlsx]Audit (hidden)!B2`. A line
/// that looks like a figure but isn't exactly this form is an error rather
/// than prose, since a figure skipped would be a figure unchecked: one with
/// both `!` and `=`, or one naming a cell before `=` or `:`, such as
/// `B4 = 9` or `Sales!B4: 9`, and one naming no source, such as
/// `Sales!B4 = 9`. That also catches a label like `Q3: 9`, which is the
/// safer way to be wrong.
pub(crate) fn figures_in(report: &str) -> Result<Vec<Figure<'_>>, String> {
    let mut figures = Vec::new();
    for line in report.lines() {
        if !(line.contains('!') && line.contains('=')) && !names_a_cell_first(line) {
            continue;
        }
        let figure = line.split_once(" = ").and_then(|(place, value)| {
            let (named, cell) = place.rsplit_once('!')?;
            let (source, sheet) = named.strip_prefix('[')?.rsplit_once(']')?;
            let letters = cell.bytes().take_while(u8::is_ascii_uppercase).count();
            let digits = &cell[letters..];
            let is_cell =
                letters > 0 && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
            (is_cell && !source.is_empty() && !sheet.is_empty() && !value.is_empty()).then_some(
                Figure {
                    source,
                    sheet,
                    cell,
                    value,
                },
            )
        });
        figures.push(figure.ok_or_else(|| {
            format!("not a figure this can check (`[source.xlsx]Sheet!Cell = value`): {line}")
        })?);
    }
    Ok(figures)
}

/// Whether the text before a line's first `=` or `:` ends in something like a cell
/// reference, in any case and with or without `$`.
fn names_a_cell_first(line: &str) -> bool {
    let Some(end) = line.find(['=', ':']) else {
        return false;
    };
    let last = line[..end]
        .split_whitespace()
        .next_back()
        .unwrap_or("")
        .rsplit('!')
        .next()
        .unwrap_or("");
    let bare: String = last.chars().filter(|c| *c != '$').collect();
    let letters = bare.chars().take_while(char::is_ascii_alphabetic).count();
    let digits = &bare[letters..];
    letters > 0 && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// The saved value of a cell in the parser's Markdown, exactly as the table shows
/// it. `sheet` is the whole title, which the parser keeps unique. `None` if the sheet
/// or the cell isn't there, or the cell has no saved value: a missing result isn't
/// zero, and it can't confirm any figure. Nor can a value that may be stale: anything
/// in a workbook declaring an outside source, since a formula may reach one through a
/// defined name and a query table fills plain cells; a formula marked as reaching
/// outside; or any formula in a workbook that calculates manually. Refusing more
/// than strictly needed is the right way for a check to be wrong.
pub(crate) fn cell_value<'a>(markdown: &'a str, sheet: &str, cell: &str) -> Option<&'a str> {
    let mut in_sheet = false;
    // Before the first sheet: the reader's notices. A sheet's name is listed with a
    // leading "- ", so a name can't pass for a notice.
    let notice = |phrase: &str| {
        markdown
            .lines()
            .take_while(|line| !line.starts_with("## Sheet: "))
            .any(|line| !line.starts_with("- ") && line.contains(phrase))
    };
    if notice("Not used or refreshed") {
        return None;
    }
    let manual = notice("calculates manually");
    for line in markdown.lines() {
        if let Some(title) = line.strip_prefix("## Sheet: ") {
            in_sheet = title == sheet;
            continue;
        }
        if !in_sheet {
            continue;
        }
        let Some(rest) = line
            .strip_prefix("| ")
            .and_then(|rest| rest.strip_prefix(cell))
            .and_then(|rest| rest.strip_prefix(" | "))
        else {
            continue;
        };
        let (value, after) = split_cell(rest)?;
        let (kind, after) = split_cell(after)?;
        let (_format, after) = split_cell(after)?;
        let (formula, note) = split_cell(after)?;
        let stale = note.contains("external") || (manual && !formula.is_empty());
        return (kind != "empty" && !stale).then_some(value);
    }
    None
}

/// A table cell up to its unescaped ` | `, which the parser's escaping makes the
/// only way one can end.
fn split_cell(text: &str) -> Option<(&str, &str)> {
    let bytes = text.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'\\' => at += 2,
            b' ' if text[at..].starts_with(" | ") => return Some((&text[..at], &text[at + 3..])),
            _ => at += 1,
        }
    }
    None
}

#[cfg(test)]
#[path = "report_check_tests.rs"]
mod tests;
