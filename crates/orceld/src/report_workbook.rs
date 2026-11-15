//! F5 Journey 2: a workbook as a report source, the writer's side. **Inert:
//! compiled only for tests.** Founder decision 7 of 2026-11-14 chose this path,
//! slice by slice (`prep/F5_SPREADSHEET_JOURNEY.md`); SG-000130 is its grain. No
//! release build holds this module, and no client can reach it, until slice W2.
//!
//! A workbook source differs from a text source in three ways:
//!
//! - it's read only through slice 2's workspace route in
//!   [`crate::document_parse`]: [`observe_workspace_file`] at start (plain
//!   directories, a single-linked regular file, the open handle tied to the
//!   walked path, within the parser's input bound), and
//!   [`parse_workspace_file`] for every later read, which refuses bytes other
//!   than the observed ones. Never through the workspace provider. It's
//!   recorded by the **file's** SHA-256, so a changed workbook is stale at
//!   preview and at commit;
//! - the text shown to the client comes from the confined parser, never from
//!   this process: one private copy, no network, no process creation, the
//!   CPU, memory and time limits of the contained tier, and the parser told to
//!   expect a workbook, so it refuses anything else by sniffing before any
//!   parse;
//! - the reader's notices and hidden sheet names are carried to the commit
//!   prompt, labelled workbook-supplied and untrusted
//!   ([`crate::report_task::supplied_text`]).
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
    path: String,
    observed: WorkspaceFile,
    /// Sheet titles the reader marked hidden, as it shows them.
    hidden_sheets: Vec<String>,
    /// The reader's notices: outside sources, recalculation, manual
    /// calculation.
    notices: Vec<String>,
}

pub(crate) fn is_workbook(path: &str) -> bool {
    path.to_ascii_lowercase().ends_with(".xlsx")
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
/// record for every later read.
pub(crate) fn observe(
    workspace: &Workspace,
    source: &str,
    pins: Option<&Pins>,
) -> Result<(SourceRecord, String, WorkbookSource), ProviderError> {
    let observed = observe_workspace_file(workspace, source)?;
    let document = parse(workspace, &observed, pins)?;
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
            observed,
            hidden_sheets,
            notices,
        },
    ))
}

/// `observe`, for a source named as a workbook.
pub(crate) fn observed_if_workbook(
    workspace: &Workspace,
    source: &str,
    pins: Option<&Pins>,
) -> Option<Result<(SourceRecord, String, WorkbookSource), ProviderError>> {
    is_workbook(source).then(|| observe(workspace, source, pins))
}

/// A workbook source's SHA-256 now: read again through the route, which
/// refuses it unless its size and SHA-256 still equal the observed ones, and
/// parsed again under the same rules.
pub(crate) fn current_digest(
    workspace: &Workspace,
    workbooks: &[WorkbookSource],
    source: &SourceRecord,
    pins: Option<&Pins>,
) -> Result<String, ProviderError> {
    let found = workbooks
        .iter()
        .find(|workbook| workbook.path == source.path)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::TargetStale,
                "the task holds no route record of this workbook",
            )
        })?;
    parse(workspace, &found.observed, pins)?;
    Ok(found.observed.sha256().to_owned())
}

/// What the reader says before the first sheet: the hidden sheets' titles from
/// its list of sheets, and its notices. Its fixed opening lines are no notice.
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

/// The commit prompt's entry for each workbook source: its path, hidden sheets
/// and notices, all workbook-supplied, and how many of the report's figures
/// name it.
pub(crate) fn prompt_entries(
    workbooks: &[WorkbookSource],
    sources: &[SourceRecord],
    report: &str,
) -> Result<Vec<SuppliedEntry>, ProviderError> {
    let figures = report_check::figures_from(report, sources)
        .map_err(|reason| ProviderError::new(FailureCode::InvalidRequest, reason))?;
    Ok(workbooks
        .iter()
        .map(|workbook| SuppliedEntry {
            path: workbook.path.clone(),
            hidden_sheets: workbook.hidden_sheets.clone(),
            notices: workbook.notices.clone(),
            figures: figures
                .iter()
                .filter(|figure| figure.source == workbook.path)
                .count(),
        })
        .collect())
}

#[cfg(test)]
#[path = "report_workbook_tests.rs"]
pub(crate) mod tests;
