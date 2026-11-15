//! F5 Journey 2: a workbook as a report source, the writer's side. Founder
//! decision 7 of 2026-11-14 chose this path, slice by slice
//! (`prep/F5_SPREADSHEET_JOURNEY.md`); SG-000130 is its grain. Since slice W2
//! the local-only `report_start` reaches it for a source ending in `.xlsx`;
//! the core and tunnel profiles never list that tool, and orceld refuses a
//! remote-context report request before policy or dispatch.
//!
//! A workbook source differs from a text source in three ways:
//!
//! - it's read only through slice 2's workspace route in
//!   [`crate::document_parse`]: [`observe_workspace_file`] at start (plain
//!   directories, a single-linked regular file, the open handle tied to the
//!   walked path, within the parser's input bound), and
//!   [`parse_workspace_file`] for every later read, which refuses bytes other
//!   than the observed ones and a real path other than the one the handle
//!   gave at observe. Never through the workspace provider. It's recorded by
//!   the **file's** SHA-256, so a changed workbook is stale at preview and at
//!   commit;
//! - the text shown to the client comes from the confined parser, never from
//!   this process: one private copy, no network, no process creation, the
//!   CPU, memory and time limits of the contained tier, and the parser told to
//!   expect a workbook, so it refuses anything else by sniffing before any
//!   parse;
//! - the reader's notices (with the targets of links and data connections),
//!   hidden sheet names and the figures the report takes from each workbook
//!   are carried to the commit prompt, labelled workbook-supplied and
//!   untrusted ([`crate::report_task::supplied_text`]); the commit approval
//!   binds each workbook's handle-derived canonical path, its SHA-256 and the
//!   parser's pinned digest ([`binding`]).
//!
//! The pins come from the report task, which holds them. The figures a report
//! states are checked by the independent checker's own route
//! ([`crate::report_check`]), which uses nothing of this module.
//!
//! The Markdown is untrusted document content. Nothing here calculates a formula
//! or follows a link: a figure is only what the file last saved.

use crate::document_parse::{observe_workspace_file, parse_workspace_file, WorkspaceFile};
use crate::report_check::{self, Pins};
use crate::report_task::{SourceKind, SourceRecord, SuppliedEntry};
use orcel_contracts::FailureCode;
use orcel_policy::Workspace;
use orcel_provider_fs::ProviderError;
use orcel_provider_process::document_parser::ParsedDocument;

/// What the route recorded for one workbook source at start, and what the
/// reader said about it.
#[derive(Debug, Clone)]
pub(crate) struct WorkbookSource {
    /// The path the caller named, as the task's source record holds it.
    path: String,
    observed: WorkspaceFile,
    /// The parser's pinned SHA-256 the workbook was read with at start.
    parser_sha256: String,
    /// Sheet titles the reader marked hidden, as it shows them.
    hidden_sheets: Vec<String>,
    /// The reader's notices: outside sources and their targets,
    /// recalculation, manual calculation.
    notices: Vec<String>,
}

pub(crate) fn is_workbook(path: &str) -> bool {
    path.to_ascii_lowercase().ends_with(".xlsx")
}

/// Spreadsheet formats a report task never reads: binary and legacy
/// workbooks, and macro-enabled workbooks, templates and add-ins. Each would
/// otherwise reach the text read; it's refused by name instead.
const OTHER_SPREADSHEETS: [&str; 7] = [".xls", ".xlsb", ".xlsm", ".xltx", ".xltm", ".xlam", ".xla"];

/// Whether `path` names a spreadsheet format other than `.xlsx` (ASCII case
/// aside), which a report source must not be.
pub(crate) fn is_other_spreadsheet(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    OTHER_SPREADSHEETS
        .iter()
        .any(|extension| lower.ends_with(extension))
}

fn unavailable() -> ProviderError {
    ProviderError::new(
        FailureCode::ProviderUnavailable,
        "workbook sources are not available in this build",
    )
}

/// The observed file through the route and the pinned parser. A refusal by the
/// parser fails the source, as does output it had to cut: a report must not
/// rest on part of a workbook.
fn parse(
    workspace: &Workspace,
    observed: &WorkspaceFile,
    pins: Option<&Pins>,
) -> Result<ParsedDocument, ProviderError> {
    let (helper, parser) = pins.ok_or_else(unavailable)?;
    let document = parse_workspace_file(workspace, observed, helper, parser)?;
    if document.truncated {
        return Err(ProviderError::new(
            FailureCode::OutputLimit,
            "the workbook is too large to read in full",
        ));
    }
    Ok(document)
}

/// The source's record, its text from the confined parser, and the route's
/// record for every later read. Without the pins nothing is read.
pub(crate) fn observe(
    workspace: &Workspace,
    source: &str,
    pins: Option<&Pins>,
) -> Result<(SourceRecord, String, WorkbookSource), ProviderError> {
    let pins = pins.ok_or_else(unavailable)?;
    let observed = observe_workspace_file(workspace, source)?;
    let document = parse(workspace, &observed, Some(pins))?;
    let (hidden_sheets, notices) = preamble(&document.markdown);
    Ok((
        SourceRecord {
            path: source.to_owned(),
            sha256: observed.sha256().to_owned(),
            bytes: observed.bytes(),
            kind: SourceKind::Workbook,
        },
        document.markdown,
        WorkbookSource {
            path: source.to_owned(),
            parser_sha256: report_check::parser_digest(pins).to_owned(),
            observed,
            hidden_sheets,
            notices,
        },
    ))
}

/// The route's record of `source`, or a stale refusal.
fn record_of<'a>(
    workbooks: &'a [WorkbookSource],
    source: &SourceRecord,
) -> Result<&'a WorkbookSource, ProviderError> {
    workbooks
        .iter()
        .find(|workbook| workbook.path == source.path)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::TargetStale,
                "the task holds no route record of this workbook",
            )
        })
}

/// A workbook source's SHA-256 now: read again through the route, which
/// refuses it unless its real path, size and SHA-256 still equal the observed
/// ones, and parsed again under the same rules.
pub(crate) fn current_digest(
    workspace: &Workspace,
    workbooks: &[WorkbookSource],
    source: &SourceRecord,
    pins: Option<&Pins>,
) -> Result<String, ProviderError> {
    let found = record_of(workbooks, source)?;
    parse(workspace, &found.observed, pins)?;
    Ok(found.observed.sha256().to_owned())
}

/// What the commit approval binds for each workbook source, in the task's
/// source order: its handle-derived canonical path, its SHA-256 and the
/// parser's pinned digest, never the string the caller sent. The parser must
/// be the one the workbook was read with at start.
pub(crate) fn binding(
    workbooks: &[WorkbookSource],
    sources: &[SourceRecord],
    pins: Option<&Pins>,
) -> Result<Vec<String>, ProviderError> {
    let mut fields = Vec::new();
    for source in sources
        .iter()
        .filter(|source| source.kind == SourceKind::Workbook)
    {
        let found = record_of(workbooks, source)?;
        let parser = report_check::parser_digest(pins.ok_or_else(unavailable)?);
        if parser != found.parser_sha256 {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "the document parser's pin changed since the task read its workbooks; start a new task",
            ));
        }
        fields.extend([
            "workbook".to_owned(),
            found.observed.canonical().to_string_lossy().into_owned(),
            found.observed.sha256().to_owned(),
            parser.to_owned(),
        ]);
    }
    Ok(fields)
}

/// What the reader says before the first sheet: the hidden sheets' titles from
/// its list of sheets, and its notices (each link or connection target is a
/// notice line of its own). Its fixed opening lines are no notice.
fn preamble(markdown: &str) -> (Vec<String>, Vec<String>) {
    let mut hidden = Vec::new();
    let mut notices = Vec::new();
    for line in markdown
        .lines()
        .take_while(|line| !line.starts_with("## Sheet: "))
    {
        if let Some(title) = line.strip_prefix("- ") {
            if title.ends_with(" (hidden)") {
                hidden.push(title.to_owned());
            }
        } else if !line.is_empty()
            && !line.starts_with("# ")
            && !line.starts_with("Sheets (")
            && !line.starts_with("Values are as last saved.")
        {
            notices.push(line.to_owned());
        }
    }
    (hidden, notices)
}

/// The commit prompt's entry for each workbook source: its path as the file
/// system spells it, hidden sheets and notices, all workbook-supplied, and
/// which of the report's figures name it (`Sheet!Cell`, each once, in the
/// report's order).
pub(crate) fn prompt_entries(
    workbooks: &[WorkbookSource],
    sources: &[SourceRecord],
    report: &str,
) -> Result<Vec<SuppliedEntry>, ProviderError> {
    let figures = report_check::figures_from(report, sources)
        .map_err(|reason| ProviderError::new(FailureCode::InvalidRequest, reason))?;
    Ok(workbooks
        .iter()
        .map(|workbook| {
            let mut cells: Vec<String> = Vec::new();
            for figure in figures
                .iter()
                .filter(|figure| figure.source == workbook.path)
            {
                let cell = format!("{}!{}", figure.sheet, figure.cell);
                if !cells.contains(&cell) {
                    cells.push(cell);
                }
            }
            SuppliedEntry {
                path: workbook.observed.opened().to_owned(),
                hidden_sheets: workbook.hidden_sheets.clone(),
                notices: workbook.notices.clone(),
                figures: cells,
            }
        })
        .collect())
}

#[cfg(test)]
#[path = "report_workbook_tests.rs"]
pub(crate) mod tests;
