//! The independent checker's own rules, without a parser: figures, cells,
//! type-dependent re-read limits and its independence from the writer. The
//! contained runs are in `report_workbook_tests.rs` (`wi05_`).

use super::*;
use crate::report_task::tests::Scene;

const MARKDOWN: &str = "# Workbook\n\n## Sheet: Sales\n\n\
| Cell | Value | Type | Format | Formula | Note |\n|---|---|---|---|---|---|\n\
| B2 | 1250.5 | number | \"$\"#,##0.00 |  |  |\n\
| B4 |  | empty |  | =SUM(B2:B3) | no saved value |\n\
| C1 | a \\| b | text |  |  |  |\n\
| B20 | 7 | number |  |  |  |\n\n\
## Sheet: Audit (hidden)\n\n\
| Cell | Value | Type | Format | Formula | Note |\n|---|---|---|---|---|---|\n\
| B2 | other | text |  |  |  |\n";

fn sha(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn record(path: &str, bytes: &[u8], kind: SourceKind) -> SourceRecord {
    SourceRecord {
        path: path.into(),
        sha256: sha(bytes),
        bytes: bytes.len() as u64,
        kind,
    }
}

#[test]
fn a_cell_is_found_in_its_own_sheet_and_only_there() {
    assert_eq!(cell_value(MARKDOWN, "Sales", "B2"), Some("1250.5"));
    assert_eq!(cell_value(MARKDOWN, "Audit (hidden)", "B2"), Some("other"));
    assert_eq!(cell_value(MARKDOWN, "Audit", "B2"), None, "the whole title");
    assert_eq!(cell_value(MARKDOWN, "Sales", "B20"), Some("7"));
    assert_eq!(cell_value(MARKDOWN, "Sales", "C1"), Some("a \\| b"));
    assert_eq!(cell_value(MARKDOWN, "Sales", "Z9"), None);
    assert_eq!(cell_value(MARKDOWN, "Nope", "B2"), None);
    assert_eq!(cell_value("| B2 | 1 | number |", "Sales", "B2"), None);
}

#[test]
fn a_value_that_may_be_stale_confirms_nothing() {
    let markdown = "## Sheet: S\n\n| A1 | 41 | number |  | =[1]R!A1 | external, not refreshed |\n";
    assert_eq!(cell_value(markdown, "S", "A1"), None);
}

#[test]
fn a_workbook_with_an_outside_source_confirms_nothing() {
    let notice = "Defined names that may reach outside: 1. Not used or refreshed, so values depending on them may be stale.";
    let rows = "## Sheet: S\n\n| A1 | 41 | number |  | =Rate |  |\n| B1 | 7 | number |  |  |  |\n";
    let declared = format!("# Workbook\n\n{notice}\n\n{rows}");
    assert_eq!(
        cell_value(&declared, "S", "A1"),
        None,
        "a formula may use it"
    );
    assert_eq!(
        cell_value(&declared, "S", "B1"),
        None,
        "a query table fills plain cells"
    );

    let manual = format!(
        "# Workbook\n\nThis workbook calculates manually, so saved values may be stale.\n\n{rows}"
    );
    assert_eq!(
        cell_value(&manual, "S", "A1"),
        None,
        "a formula may not have run"
    );
    assert_eq!(
        cell_value(&manual, "S", "B1"),
        Some("7"),
        "a typed value is what it is"
    );

    let plain = format!("# Workbook\n\n{rows}");
    assert_eq!(cell_value(&plain, "S", "A1"), Some("41"));
    let recalculates = format!("# Workbook\n\nThis workbook asks to be recalculated when opened, so saved values may be stale.\n\n{rows}");
    assert_eq!(
        cell_value(&recalculates, "S", "A1"),
        Some("41"),
        "that isn't an outside source"
    );
    let named = format!("# Workbook\n\nSheets (1):\n- Not used or refreshed\n\n{rows}");
    assert_eq!(
        cell_value(&named, "S", "A1"),
        Some("41"),
        "a sheet's name is no notice"
    );
}

#[test]
fn a_missing_saved_value_confirms_nothing_not_even_zero() {
    assert_eq!(cell_value(MARKDOWN, "Sales", "B4"), None);
}

#[test]
fn figures_are_read_from_their_own_lines_with_their_workbook() {
    let figure = |source, sheet, cell, value| Figure {
        source,
        sheet,
        cell,
        value,
    };
    assert_eq!(
        figures_in(
            "Intro = no place\nJust wow!\nNote: see below\nQ3 revenue: fine\n\
             [data/q3.xlsx]Sales!B2 = 1.5\n[a]b].xlsx]A!B!C3 = x = y\n\
             [data/q3.xlsx]Audit (hidden)!B2 = other\n"
        ),
        Ok(vec![
            figure("data/q3.xlsx", "Sales", "B2", "1.5"),
            figure("a]b].xlsx", "A!B", "C3", "x = y"),
            figure("data/q3.xlsx", "Audit (hidden)", "B2", "other"),
        ])
    );
}

#[test]
fn a_line_shaped_like_a_figure_but_not_checkable_is_an_error() {
    for line in [
        "[a.xlsx]Sales!b4 = 99999",
        "[a.xlsx]Sales!B4=99999",
        "[a.xlsx]Sales!$B$4 = 99999",
        "P = [a.xlsx]Q!B2 = 123456",
        "[a.xlsx]Sales!B = 1",
        "[a.xlsx]Sales!2 = 1",
        "[a.xlsx]!B2 = 1",
        "[]Sales!B2 = 1",
        "[a.xlsx]Sales!B2 = ",
        // Naming no workbook.
        "Sales!B2 = 1250.5",
        "a.xlsx Sales!B2 = 1250.5",
        "B4 = 99999",
        "b4 = 99999",
        "$B$4 = 99999",
        "Sales!B4: 99999",
        "B4: 99999",
    ] {
        let report = format!("[a.xlsx]Sales!B2 = 1250.5\n{line}\n");
        assert!(figures_in(&report).is_err(), "{line}");
    }
}

#[test]
fn every_figure_names_an_observed_workbook() {
    let sources = [
        record("data/a.xlsx", b"a", SourceKind::Workbook),
        record("data/b.xlsx", b"b", SourceKind::Workbook),
        record("data/q3.csv", b"c", SourceKind::Text),
    ];
    let figures = figures_from("[data/a.xlsx]S!A1 = 1\n[data/b.xlsx]S!A1 = 2\n", &sources).unwrap();
    assert_eq!(figures.len(), 2);
    assert_eq!(figures[1].source, "data/b.xlsx");
    let unobserved = figures_from("[data/c.xlsx]S!A1 = 1\n", &sources).unwrap_err();
    assert!(unobserved.contains("didn't observe"), "{unobserved}");
    let text = figures_from("[data/q3.csv]S!A1 = 1\n", &sources).unwrap_err();
    assert!(text.contains("isn't one of the task's workbooks"), "{text}");
    // The path must be the one the task recorded, exactly.
    assert!(figures_from("[data\\a.xlsx]S!A1 = 1\n", &sources).is_err());
    assert!(figures_from("[DATA/A.XLSX]S!A1 = 1\n", &sources).is_err());
}

/// SG-000130 W1: the re-read limit follows the source's type.
#[test]
fn the_reread_limit_follows_the_source_type() {
    let sized = |bytes: u64, kind| SourceRecord {
        path: "data/x".into(),
        sha256: String::new(),
        bytes,
        kind,
    };
    assert_eq!(
        source_limit(&sized(0, SourceKind::Text)),
        MAX_TEXT_SOURCE_BYTES
    );
    assert_eq!(
        source_limit(&sized(0, SourceKind::Workbook)),
        MAX_INPUT_BYTES
    );
    assert!(within_limit(&sized(MAX_TEXT_SOURCE_BYTES, SourceKind::Text)).is_ok());
    assert!(within_limit(&sized(MAX_TEXT_SOURCE_BYTES + 1, SourceKind::Text)).is_err());
    assert!(within_limit(&sized(MAX_TEXT_SOURCE_BYTES + 1, SourceKind::Workbook)).is_ok());
    assert!(within_limit(&sized(MAX_INPUT_BYTES, SourceKind::Workbook)).is_ok());
    let past = within_limit(&sized(MAX_INPUT_BYTES + 1, SourceKind::Workbook)).unwrap_err();
    assert!(past.contains("workbook"), "{past}");
}

/// The checker's own read: a workbook over the text limit is re-read in full
/// and bound by its SHA-256; a text source over 1 MiB isn't. With no parser,
/// a workbook's figures confirm nothing, so a report resting on one fails.
#[test]
fn the_checker_rereads_a_workbook_past_the_text_limit_and_binds_its_bytes() {
    let scene = Scene::new("checker-limits");
    let root = scene.workspace.root.clone();
    let large: Vec<u8> = (0..(MAX_TEXT_SOURCE_BYTES + 4096))
        .map(|at| (at % 251) as u8)
        .collect();
    std::fs::write(root.join("data").join("big.xlsx"), &large).unwrap();
    let workbook = record("data/big.xlsx", &large, SourceKind::Workbook);
    assert!(sources_rereadable(&root, std::slice::from_ref(&workbook)).is_ok());
    let as_text = SourceRecord {
        kind: SourceKind::Text,
        ..workbook.clone()
    };
    let error = sources_rereadable(&root, &[as_text]).unwrap_err();
    assert!(error.contains("larger than"), "{error}");

    let check_with = |report: &str, sources: &[SourceRecord]| {
        std::fs::write(root.join("reports").join("r.md"), report).unwrap();
        let folder = fs::canonicalize(root.join("reports")).unwrap();
        check(&Expectation {
            root: &root,
            folder_path: &root.join("reports"),
            folder: &folder,
            destination: "reports/r.md",
            sha256: &sha(report.as_bytes()),
            bytes: report.len() as u64,
            sources,
            pins: None,
        })
    };
    let sources = [workbook.clone()];
    let error = check_with("[data/big.xlsx]S!A1 = 1\n", &sources).unwrap_err();
    assert!(error.contains("not available"), "{error}");
    let error = check_with("no figures\n", &sources).unwrap_err();
    assert!(error.contains("states no figure"), "{error}");
    let error = check_with("S!A1 = 1\n", &sources).unwrap_err();
    assert!(error.contains("not a figure"), "{error}");
    // Changed bytes fail before any parse.
    let mut changed = large.clone();
    changed[0] ^= 1;
    std::fs::write(root.join("data").join("big.xlsx"), &changed).unwrap();
    let error = check_with("[data/big.xlsx]S!A1 = 1\n", &sources).unwrap_err();
    assert!(
        error.contains("changed since the task observed it"),
        "{error}"
    );
    assert!(sources_rereadable(&root, &sources).is_err());
    // A text-only report keeps its rules: no figure is read from it.
    let csv = crate::report_task::tests::Q3_CSV.as_bytes();
    let text = [record("data/q3.csv", csv, SourceKind::Text)];
    let passed = check_with("Q3: 9\nSales!B4 = 1\n", &text).expect("a text report");
    assert!(passed.get("figures_confirmed").is_none());
}

/// SG-000130 W1 acceptance: the checker names neither the workspace
/// provider, the task registry, the writer's workbook module nor slice 2's
/// route, in any line, its tests' lines included.
#[test]
fn the_checker_names_nothing_of_the_writer() {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/report_check.rs"),
    )
    .unwrap();
    let code: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    for name in [
        "orcel_provider_fs",
        "FsProvider",
        "TaskRegistry",
        "report_workbook",
        "observe_workspace_file",
        "parse_workspace_file",
        "WorkspaceFile",
        "workbook_pins",
        "installed_pins",
    ] {
        let named = code.iter().any(|line| {
            line.match_indices(name).any(|(at, _)| {
                !line[..at].ends_with(ident) && !line[at + name.len()..].starts_with(ident)
            })
        });
        assert!(!named, "report_check.rs names {name}");
    }
    // And it does reach the parser by its own run, as the spec says.
    assert!(text.contains("use crate::document_parse::{run_parser, ParserPin};"));
    // Reconcile names no parser or route item: it gets the pins from the task.
    let journal = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/report_journal.rs"),
    )
    .unwrap();
    for name in [
        "document_parse",
        "document_parser",
        "report_workbook",
        "run_parser",
        "installed_pins",
        "WorkspaceFile",
    ] {
        assert!(!journal.contains(name), "report_journal.rs names {name}");
    }
}
