//! F5 Journey 2: a workbook as a report source. **Inert: compiled only for
//! tests.** No release build holds this module, and no client can reach it, until
//! founder decision 7 and its grain (`prep/F5_SPREADSHEET_JOURNEY.md`).
//!
//! A workbook source differs from a text source in three ways:
//!
//! - it's read through the workspace provider's verified open, as text is, but
//!   as bytes, and it's recorded by the **file's** SHA-256, so a changed workbook
//!   is stale at preview and at commit;
//! - the text shown to the client comes from the confined parser, never from
//!   this process: one private copy, no network, no process creation, and the
//!   CPU, memory and time limits of the contained tier;
//! - a report can state figures as `Sheet!Cell = value`, and [`check_figures`]
//!   parses the workbook again in a separate contained run and compares each.
//!
//! The Markdown is untrusted document content. Nothing here calculates a formula
//! or follows a link: a figure is only what the file last saved.

use crate::document_parse::{run_parser, ParserPin};
use crate::report_task::SourceRecord;
use orcel_contracts::FailureCode;
use orcel_policy::Workspace;
use orcel_provider_fs::{FsProvider, ProviderError};
use orcel_provider_process::contained::{sha256_hex, HelperPin};
use orcel_provider_process::document_parser::{ParsedDocument, MAX_INPUT_BYTES};
use std::sync::OnceLock;

type Pins = (HelperPin, ParserPin);

/// The pins this module's tests run with. Nothing else sets them, and with none
/// a workbook source is unavailable.
static PINS: OnceLock<Pins> = OnceLock::new();

pub(crate) fn set_pins(helper: HelperPin, parser: ParserPin) {
    let _ = PINS.set((helper, parser));
}

pub(crate) fn is_workbook(path: &str) -> bool {
    path.to_ascii_lowercase().ends_with(".xlsx")
}

fn read(workspace: &Workspace, source: &str) -> Result<Vec<u8>, ProviderError> {
    FsProvider::new(&workspace.root)?.read_bytes(source, MAX_INPUT_BYTES as usize)
}

fn parse(bytes: &[u8], pins: Option<&Pins>) -> Result<ParsedDocument, ProviderError> {
    let (helper, parser) = pins.ok_or_else(|| {
        ProviderError::new(
            FailureCode::ProviderUnavailable,
            "workbook sources are not available in this build",
        )
    })?;
    run_parser(bytes, &sha256_hex(bytes), helper, parser)
}

/// The source's record, and its text from the confined parser. A refusal by the
/// parser fails the source, as does output it had to cut: a report must not rest
/// on part of a workbook.
pub(crate) fn observe(
    workspace: &Workspace,
    source: &str,
) -> Result<(SourceRecord, String), ProviderError> {
    let bytes = read(workspace, source)?;
    let document = parse(&bytes, PINS.get())?;
    if document.truncated {
        return Err(ProviderError::new(
            FailureCode::OutputLimit,
            "the workbook is too large to read in full",
        ));
    }
    Ok((
        SourceRecord {
            path: source.to_owned(),
            sha256: sha256_hex(&bytes),
            bytes: bytes.len() as u64,
        },
        document.markdown,
    ))
}

/// `observe`, for a source that's a workbook.
pub(crate) fn observed_if_workbook(
    workspace: &Workspace,
    source: &str,
) -> Option<Result<(SourceRecord, String), ProviderError>> {
    is_workbook(source).then(|| observe(workspace, source))
}

/// For a workbook, the file's SHA-256 now, or `None` if the provider can't read it.
/// For any other source, what the report task already found.
pub(crate) fn digest_if_workbook(
    workspace: &Workspace,
    source: &str,
    text_digest: Option<String>,
) -> Option<String> {
    if is_workbook(source) {
        read(workspace, source).ok().map(|bytes| sha256_hex(&bytes))
    } else {
        text_digest
    }
}

/// `Sheet!Cell = value` lines of a report: `(sheet, cell, value)`. A sheet's name
/// may hold `!`, so the last one divides it from the cell.
pub(crate) fn figures_in(report: &str) -> Vec<(&str, &str, &str)> {
    report
        .lines()
        .filter_map(|line| {
            let (place, value) = line.split_once(" = ")?;
            let (sheet, cell) = place.rsplit_once('!')?;
            let letters = cell.bytes().take_while(u8::is_ascii_uppercase).count();
            let digits = &cell[letters..];
            let is_cell =
                letters > 0 && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
            is_cell.then_some((sheet, cell, value))
        })
        .collect()
}

/// The saved value of a cell in the parser's Markdown, exactly as the table shows
/// it. `None` if the sheet or the cell isn't there, or the cell has no saved value:
/// a missing result isn't zero, and it can't confirm any figure.
pub(crate) fn cell_value<'a>(markdown: &'a str, sheet: &str, cell: &str) -> Option<&'a str> {
    let mut in_sheet = false;
    for line in markdown.lines() {
        if let Some(title) = line.strip_prefix("## Sheet: ") {
            in_sheet = title.strip_suffix(" (hidden)").unwrap_or(title) == sheet;
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
        let (kind, _) = split_cell(after)?;
        return (kind != "empty").then_some(value);
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

/// Whether every figure a report states is what the workbook saved, read again in
/// a separate contained run. The file must still be the one the task recorded. A
/// report stating no figure fails: there's nothing to confirm. Returns how many
/// were confirmed.
pub(crate) fn check_figures(
    workspace: &Workspace,
    source: &SourceRecord,
    report: &str,
) -> Result<usize, String> {
    check_figures_with(workspace, source, report, PINS.get())
}

fn check_figures_with(
    workspace: &Workspace,
    source: &SourceRecord,
    report: &str,
    pins: Option<&Pins>,
) -> Result<usize, String> {
    let bytes = read(workspace, &source.path).map_err(|error| error.message)?;
    if sha256_hex(&bytes) != source.sha256 {
        return Err(format!(
            "source {} changed since the task observed it",
            source.path
        ));
    }
    let document = parse(&bytes, pins).map_err(|error| error.message)?;
    if document.truncated {
        return Err("the workbook is too large to read in full".into());
    }
    let figures = figures_in(report);
    if figures.is_empty() {
        return Err("the report states no figure".into());
    }
    for (sheet, cell, stated) in &figures {
        match cell_value(&document.markdown, sheet, cell) {
            Some(saved) if saved == *stated => {}
            Some(_) => return Err(format!("{sheet}!{cell} doesn't match the workbook")),
            None => return Err(format!("{sheet}!{cell} has no saved value in the workbook")),
        }
    }
    Ok(figures.len())
}

#[cfg(test)]
#[path = "report_workbook_tests.rs"]
mod tests;
