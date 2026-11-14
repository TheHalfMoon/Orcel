//! F5 Journey 2: a workbook as a report source. **Inert: compiled only for
//! tests.** Founder decision 7 of 2026-11-14 chose this path, slice by slice
//! (`prep/F5_SPREADSHEET_JOURNEY.md`). No release build holds this module, and no
//! client can reach it, until slice 3 and its grain.
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
use orcel_provider_process::document_parser::{DocumentFormat, ParsedDocument, MAX_INPUT_BYTES};
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
    if document.format != DocumentFormat::Xlsx {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "the file named as a workbook isn't one",
        ));
    }
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

/// The `Sheet!Cell = value` lines of a report: `(sheet title, cell, value)`. A
/// sheet's title may hold `!`, so the last one divides it from the cell. A hidden
/// sheet's title says so: `Audit (hidden)!B2`. A line that looks like a figure but
/// isn't exactly this form is an error rather than prose, since a figure skipped
/// would be a figure unchecked: one with both `!` and `=`, or one naming a cell
/// before `=` or `:`, such as `B4 = 9` or `Sales!B4: 9`. That also catches a label
/// like `Q3: 9`, which is the safer way to be wrong.
pub(crate) fn figures_in(report: &str) -> Result<Vec<(&str, &str, &str)>, String> {
    let mut figures = Vec::new();
    for line in report.lines() {
        if !(line.contains('!') && line.contains('=')) && !names_a_cell_first(line) {
            continue;
        }
        let figure = line.split_once(" = ").and_then(|(place, value)| {
            let (sheet, cell) = place.rsplit_once('!')?;
            let letters = cell.bytes().take_while(u8::is_ascii_uppercase).count();
            let digits = &cell[letters..];
            let is_cell =
                letters > 0 && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
            (is_cell && !sheet.is_empty() && !value.is_empty()).then_some((sheet, cell, value))
        });
        figures.push(figure.ok_or_else(|| format!("not a figure this can check: {line}"))?);
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

/// Whether every `Sheet!Cell = value` line in a report is what the workbook saved,
/// read again in a separate contained run. The file must still be the one the task
/// recorded. A figure stated any other way, such as in a sentence or a table, isn't
/// seen. A report stating none fails: there's nothing to confirm. Returns how many
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
    if document.format != DocumentFormat::Xlsx {
        return Err("the file named as a workbook isn't one".into());
    }
    if document.truncated {
        return Err("the workbook is too large to read in full".into());
    }
    let figures = figures_in(report)?;
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
