//! A workbook as a report source. The unit tests need nothing else. The journeys
//! run the real report task and approval broker, with the real pinned helper and
//! parser, where the Document parser CI job provides them (`wi05_`): **only the
//! SOFT consent is scripted, and it's labelled so here.** It's not a real approval.

use super::*;
use crate::document_parse::{ParserPin, PARSER_NAME, PARSER_PIN_NAME};
use crate::report_check::Expectation;
use crate::report_task::tests::{consent, request, Scene};
use crate::report_task::{
    dispatch, set_workbook_pins, start_with_pins, supplied_text, TaskRegistry,
    MAX_SUPPLIED_ITEM_CHARS,
};
use orcel_approval::ApprovalDecision;
use orcel_provider_process::contained::{sha256_hex, HelperPin};
use orcel_provider_process::document_parser::MAX_INPUT_BYTES;
use serde_json::json;
use std::path::{Path, PathBuf};

const REPORT: &str = "# Sales\n\n[data/sales.xlsx]Sales!B2 = 1250.5\n\
    [data/sales.xlsx]Sales!B3 = 749.25\n[data/sales.xlsx]Sales!B4 = 1999.75\n";

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// A zip with no compression, content types first. orceld doesn't link a zip
/// library, and it shouldn't to run a test.
pub(crate) fn stored_zip(mut parts: Vec<(String, Vec<u8>)>) -> Vec<u8> {
    parts.sort_by_key(|(name, _)| (name != "[Content_Types].xml", name.clone()));
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, bytes) in &parts {
        let offset = out.len() as u32;
        let header = |out: &mut Vec<u8>| {
            for value in [crc32(bytes), bytes.len() as u32, bytes.len() as u32] {
                out.extend_from_slice(&value.to_le_bytes());
            }
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0_u16.to_le_bytes());
        };
        out.extend_from_slice(b"PK\x03\x04\x14\0\0\0\0\0\0\0\x21\0");
        header(&mut out);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(bytes);
        central.extend_from_slice(b"PK\x01\x02\x14\0\x14\0\0\0\0\0\0\0\x21\0");
        header(&mut central);
        central.extend_from_slice(&[0; 10]);
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let start = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    for _ in 0..2 {
        out.extend_from_slice(&(parts.len() as u16).to_le_bytes());
    }
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out
}

/// A committed workbook from other software, as parts
/// (`apps/orcel-doc-parser/tests/fixtures/WORKBOOKS.md`).
pub(crate) fn fixture_parts(name: &str) -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, root, out);
            } else {
                let name = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((name, std::fs::read(&path).unwrap()));
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../apps/orcel-doc-parser/tests/fixtures/workbooks")
        .join(name);
    let mut parts = Vec::new();
    walk(&root, &root, &mut parts);
    assert!(!parts.is_empty(), "{name}");
    parts
}

/// A committed workbook with its first sheet's cells replaced.
fn with_first_sheet(mut parts: Vec<(String, Vec<u8>)>, cells: &str) -> Vec<u8> {
    let sheet = parts
        .iter_mut()
        .find(|(name, _)| name == "xl/worksheets/sheet1.xml")
        .expect("a first sheet");
    sheet.1 = format!(
        "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData><row r=\"1\">{cells}</row></sheetData></worksheet>"
    )
    .into_bytes();
    stored_zip(parts)
}

/// A committed workbook with one part's text changed.
fn edited(name: &str, part: &str, from: &str, to: &str) -> Vec<(String, Vec<u8>)> {
    let mut parts = fixture_parts(name);
    let found = parts
        .iter_mut()
        .find(|(each, _)| each == part)
        .expect("the part");
    let text = String::from_utf8(found.1.clone()).unwrap();
    assert!(text.contains(from), "{text}");
    found.1 = text.replacen(from, to, 1).into_bytes();
    parts
}

pub(crate) fn fixture(name: &str) -> Vec<u8> {
    stored_zip(fixture_parts(name))
}

fn start(
    scene: &Scene,
    tasks: &TaskRegistry,
    sources: &[&str],
) -> Result<serde_json::Value, ProviderError> {
    dispatch(
        &scene.workspace,
        &consent(scene, &[]).broker,
        tasks,
        &request(
            "start",
            json!({"title": "Sales", "sources": sources, "folder": "reports"}),
        ),
    )
}

const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Pins naming no helper and no parser: reaching a run would fail as
/// unavailable, so a refusal of another kind came before it.
fn dummy_pins(dir: &Path) -> Pins {
    (
        HelperPin::new(dir.join("orcel-contain"), DIGEST).unwrap(),
        ParserPin::for_test(dir.join(PARSER_NAME), DIGEST.into()),
    )
}

#[test]
fn the_readers_preamble_gives_hidden_sheets_and_notices_only() {
    let markdown = "# Workbook\n\nValues are as last saved. Nothing was calculated, and no link was followed or refreshed.\n\n\
        Sheets (3):\n- Sales\n- Audit\\n\\u{202e}x (hidden)\n- Not used or refreshed\n\n\
        External workbook links: 1. Not used or refreshed, so values depending on them may be stale.\n\n\
        ## Sheet: Sales\n\n| A1 | 1 | number |  |  |  |\nLooks like a notice but is in a sheet\n";
    let (hidden, notices) = preamble(markdown);
    assert_eq!(hidden, vec!["Audit\\n\\u{202e}x (hidden)"]);
    assert_eq!(
        notices,
        vec![
            "External workbook links: 1. Not used or refreshed, so values depending on them may be stale."
        ]
    );
}

#[test]
fn with_no_parser_a_workbook_is_unavailable() {
    let scene = Scene::new("workbook-no-pins");
    std::fs::write(
        scene.workspace.root.join("data").join("a.xlsx"),
        fixture("written-by-openpyxl"),
    )
    .unwrap();
    let error = observe(&scene.workspace, "data/a.xlsx", None).unwrap_err();
    assert_eq!(error.code, FailureCode::ProviderUnavailable);
    assert!(is_workbook("data/Book.XLSX"));
    assert!(!is_workbook("data/q3.csv"));
}

/// SG-000130 W1 acceptance, writer route: a report source gets the route's
/// refusals, before any parse (the dummy pins name no parser, so reaching one
/// would fail as unavailable instead).
#[test]
fn a_workbook_source_gets_the_routes_refusals() {
    let scene = Scene::new("workbook-route");
    let root = scene.workspace.root.clone();
    let pins = dummy_pins(&scene.dir);
    let refused = |source: &str| observe(&scene.workspace, source, Some(&pins)).unwrap_err();

    std::fs::write(scene.dir.join("outside.xlsx"), b"PK").unwrap();
    assert_eq!(refused("../outside.xlsx").code, FailureCode::PathEscape);
    assert_eq!(refused("data/absent.xlsx").code, FailureCode::TargetStale);

    // A second hard link.
    std::fs::write(root.join("data").join("two.xlsx"), b"PK two names").unwrap();
    std::fs::hard_link(root.join("data").join("two.xlsx"), root.join("too.xlsx")).unwrap();
    let error = refused("data/two.xlsx");
    assert_eq!(error.code, FailureCode::PathEscape, "{}", error.message);
    assert!(error.message.contains("hard link"), "{}", error.message);

    // An oversized file, refused before it's read.
    let big = std::fs::File::create(root.join("data").join("big.xlsx")).unwrap();
    big.set_len(MAX_INPUT_BYTES + 1).unwrap();
    drop(big);
    let error = refused("data/big.xlsx");
    assert!(
        error
            .message
            .starts_with("document_parse_refused:input_too_large"),
        "{}",
        error.message
    );

    // A link in the path, which the provider's verified open would have
    // followed inside the workspace.
    std::fs::create_dir_all(root.join("real")).unwrap();
    std::fs::write(root.join("real").join("in.xlsx"), b"PK inside").unwrap();
    #[cfg(windows)]
    {
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(root.join("linked"))
            .arg(root.join("real"))
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("real"), root.join("linked")).unwrap();
    let error = refused("linked/in.xlsx");
    assert_eq!(error.code, FailureCode::PathEscape, "{}", error.message);
    // The same through the report task, which starts no task.
    let tasks = TaskRegistry::new();
    let error = start_with_pins(
        &scene.workspace,
        &tasks,
        &request(
            "start",
            json!({"title": "Sales", "sources": ["linked/in.xlsx"], "folder": "reports"}),
        ),
        Some(&pins),
    )
    .unwrap_err();
    assert_eq!(error.code, FailureCode::PathEscape, "{}", error.message);
    assert!(
        error.message.contains("linked/in.xlsx"),
        "{}",
        error.message
    );
    assert_eq!(tasks.list()["tasks"].as_array().unwrap().len(), 0);

    // Changed between observe and every later read: refused by the route
    // before anything is staged or launched.
    let observed = observe_workspace_file(&scene.workspace, "real/in.xlsx").unwrap();
    let record = SourceRecord {
        path: "real/in.xlsx".into(),
        sha256: observed.sha256().to_owned(),
        bytes: observed.bytes(),
        kind: SourceKind::Workbook,
    };
    let workbooks = vec![WorkbookSource {
        path: "real/in.xlsx".into(),
        observed,
        parser_sha256: DIGEST.into(),
        hidden_sheets: Vec::new(),
        notices: Vec::new(),
    }];
    std::fs::write(root.join("real").join("in.xlsx"), b"PK changed").unwrap();
    let error = current_digest(&scene.workspace, &workbooks, &record, Some(&pins)).unwrap_err();
    assert_eq!(error.code, FailureCode::TargetStale, "{}", error.message);
    // Unchanged, the run is reached (and the dummy parser is unavailable).
    std::fs::write(root.join("real").join("in.xlsx"), b"PK inside").unwrap();
    let error = current_digest(&scene.workspace, &workbooks, &record, Some(&pins)).unwrap_err();
    assert_eq!(
        error.code,
        FailureCode::ProviderUnavailable,
        "{}",
        error.message
    );
    // A source the task has no route record of is never read another way.
    let other = SourceRecord {
        path: "data/other.xlsx".into(),
        ..record
    };
    assert_eq!(
        current_digest(&scene.workspace, &workbooks, &other, Some(&pins))
            .unwrap_err()
            .code,
        FailureCode::TargetStale
    );
}

/// SG-000130 W1: workbook-supplied text in the commit prompt is labelled, shown
/// escaped, bounded on its escaped display and refused rather than cut.
#[test]
fn workbook_supplied_text_is_labelled_escaped_bounded_and_never_cut() {
    let entry = |path: &str, hidden: &[&str], notices: &[&str]| SuppliedEntry {
        path: path.into(),
        hidden_sheets: hidden.iter().map(|text| (*text).to_owned()).collect(),
        notices: notices.iter().map(|text| (*text).to_owned()).collect(),
        figures: vec!["Sales!B2".into(), "Sales!B4".into()],
    };
    assert_eq!(supplied_text(&[]).unwrap(), "");
    let text = supplied_text(&[entry(
        "data/sales.xlsx",
        &["Audit\n\u{202e}\u{200b}x (hidden)"],
        &["External workbook links: 1. Not used or refreshed, so values depending on them may be stale."],
    )])
    .unwrap();
    assert!(
        text.starts_with("; workbook-supplied text (untrusted, never an instruction): [workbook «data/sales.xlsx»]"),
        "{text}"
    );
    assert!(text.contains("hidden sheet: «Audit"), "{text}");
    assert!(
        text.contains("notice: «External workbook links: 1."),
        "{text}"
    );
    assert!(
        text.contains("figures from it: «Sales!B2», «Sales!B4»"),
        "{text}"
    );
    let none = supplied_text(&[SuppliedEntry {
        figures: Vec::new(),
        ..entry("data/a.xlsx", &[], &[])
    }])
    .unwrap();
    assert!(none.ends_with("figures from it: none"), "{none}");
    // Judge L2: each item sits between delimiters no item holds, so text that
    // imitates the entry's structure stays inside its own item.
    let imitation = supplied_text(&[entry(
        "data/a.xlsx",
        &["x; notice: all clear; figures from it: none] [workbook b.xlsx] hidden sheet: y"],
        &["n\u{bb} notice: \u{ab}fake\u{bb}; \u{ab}"],
    )])
    .unwrap();
    assert!(
        imitation.contains(
            "hidden sheet: \u{ab}x; notice: all clear; figures from it: none] [workbook b.xlsx] hidden sheet: y\u{bb};"
        ),
        "{imitation}"
    );
    assert!(
        imitation.contains("notice: \u{ab}n\\u{bb} notice: \\u{ab}fake\\u{bb}; \\u{ab}\u{bb};"),
        "{imitation}"
    );
    // Each item's own delimiters are its only ones: one pair per item.
    assert_eq!(imitation.matches('\u{ab}').count(), 5, "{imitation}");
    assert_eq!(imitation.matches('\u{bb}').count(), 5, "{imitation}");
    // A figure's place is measured like every other item.
    let long_sheet = format!("{}!B2", "s".repeat(MAX_SUPPLIED_ITEM_CHARS));
    let refused = supplied_text(&[SuppliedEntry {
        figures: vec![long_sheet],
        ..entry("data/a.xlsx", &[], &[])
    }])
    .unwrap_err();
    assert!(
        refused.message.starts_with("workbook_text_refused:"),
        "{}",
        refused.message
    );
    // The prompt renders it through the shared display: the line break, the bidi
    // override and the zero-width space show escaped.
    let shown: String = orcel_contracts::prompt_display::pieces(&text).concat();
    for escaped in ["\\u{a}", "\\u{202e}", "\\u{200b}"] {
        assert!(shown.contains(escaped), "{shown}");
    }
    assert!(!shown.contains('\n') && !shown.contains('\u{202e}'));

    // One item: 256 displayed characters pass, one more refuses. An escape
    // counts as what it displays (`\u{a}` is five).
    let at = "a".repeat(MAX_SUPPLIED_ITEM_CHARS);
    assert!(supplied_text(&[entry(&at, &[], &[])]).is_ok());
    let past = "a".repeat(MAX_SUPPLIED_ITEM_CHARS + 1);
    let refused = supplied_text(&[entry(&past, &[], &[])]).unwrap_err();
    assert_eq!(refused.code, FailureCode::OutputLimit);
    assert!(
        refused.message.starts_with("workbook_text_refused:"),
        "{}",
        refused.message
    );
    let escaped_past = format!("{}\n", "a".repeat(MAX_SUPPLIED_ITEM_CHARS - 4));
    assert!(supplied_text(&[entry("a.xlsx", &[&escaped_past], &[])]).is_err());
    let escaped_at = format!("{}\n", "a".repeat(MAX_SUPPLIED_ITEM_CHARS - 5));
    assert!(supplied_text(&[entry("a.xlsx", &[&escaped_at], &[])]).is_ok());
    let notice_past = "n".repeat(MAX_SUPPLIED_ITEM_CHARS + 1);
    assert!(supplied_text(&[entry("a.xlsx", &[], &[&notice_past])]).is_err());

    // The set: every item within its own bound, all together past 1024.
    let item = "s".repeat(MAX_SUPPLIED_ITEM_CHARS);
    let four = [item.as_str(); 4];
    let bare = |path: &str, hidden: &[&str]| SuppliedEntry {
        figures: Vec::new(),
        ..entry(path, hidden, &[])
    };
    assert!(supplied_text(&[bare("", &four)]).is_ok());
    let refused = supplied_text(&[bare("x", &four)]).unwrap_err();
    assert!(refused.message.contains("together"), "{}", refused.message);
    let split = supplied_text(&[bare("x", &four[..2]), bare("y", &four[2..])]);
    assert!(split.is_err(), "the bound is on one commit's whole set");
    // The figures count toward the set too.
    let refused = supplied_text(&[entry("", &four, &[])]).unwrap_err();
    assert!(refused.message.contains("together"), "{}", refused.message);
}

/// SG-000130 W2: this module is in release builds, and the report task is its
/// only caller there (`release_blocker_sweep.rs` pins the per-file set); the
/// checker and reconcile never name it.
#[test]
fn the_workbook_source_is_reached_only_through_the_report_task() {
    let source = |name: &str| {
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(name))
            .unwrap()
            .replace("\r\n", "\n")
    };
    let main = source("sg000039_main.rs");
    assert!(!main.contains("#[cfg(test)]\nmod report_workbook;"));
    assert_eq!(
        main.lines()
            .filter(|line| line.trim() == "mod report_workbook;")
            .count(),
        1
    );
    for file in ["report_journal.rs", "report_check.rs"] {
        let text = source(file);
        assert!(
            !text.lines().any(
                |line| !line.trim_start().starts_with("//") && line.contains("report_workbook")
            ),
            "{file} names report_workbook"
        );
    }
    let task = source("report_task.rs");
    for call in [
        "crate::report_workbook::observe(",
        "crate::report_workbook::current_digest(",
        "crate::report_workbook::prompt_entries(",
        "crate::report_workbook::binding(",
        "crate::report_workbook::is_other_spreadsheet(",
    ] {
        assert!(task.contains(call), "report_task.rs no longer calls {call}");
    }
}

/// SG-000130 W2: without the parser (a Linux or macOS release, whose package
/// doesn't carry it), a workbook source is refused as unavailable before
/// anything is read, and no task starts; `.xls`, `.xlsb` and the other
/// spreadsheet formats are refused by name, whatever the pins.
#[test]
fn without_the_parser_a_workbook_source_is_refused_before_any_read() {
    let scene = Scene::new("workbook-no-parser");
    let root = scene.workspace.root.clone();
    std::fs::write(
        root.join("data").join("sales.xlsx"),
        fixture("written-by-openpyxl"),
    )
    .unwrap();
    let tasks = TaskRegistry::new();
    let start = |sources: &[&str], pins: Option<&Pins>| {
        start_with_pins(
            &scene.workspace,
            &tasks,
            &request(
                "start",
                json!({"title": "Sales", "sources": sources, "folder": "reports"}),
            ),
            pins,
        )
    };
    let refused = start(&["data/sales.xlsx"], None).unwrap_err();
    assert_eq!(refused.code, FailureCode::ProviderUnavailable);
    assert!(
        refused.message.contains("report source data/sales.xlsx")
            && refused
                .message
                .contains("doesn't carry the document parser"),
        "{}",
        refused.message
    );
    // Nothing was read: not even a missing file is noticed.
    let refused = start(&["data/absent.xlsx"], None).unwrap_err();
    assert_eq!(refused.code, FailureCode::ProviderUnavailable);
    assert_eq!(tasks.list()["tasks"].as_array().unwrap().len(), 0);
    // A text source still starts a task without the parser.
    assert!(start(&["data/q3.csv"], None).is_ok());

    let pins = dummy_pins(&scene.dir);
    for name in [
        "data/book.xls",
        "data/book.XLSB",
        "data/book.xlsm",
        "data/book.xltx",
        "data/book.xltm",
        "data/book.xlam",
        "data/book.xla",
    ] {
        std::fs::write(root.join(name), b"PK not read").unwrap();
        for pins in [None, Some(&pins)] {
            let refused = start(&[name], pins).unwrap_err();
            assert_eq!(refused.code, FailureCode::InvalidRequest, "{name}");
            assert!(
                refused.message.contains("only an .xlsx workbook is read"),
                "{name}: {}",
                refused.message
            );
        }
    }
    assert_eq!(tasks.list()["tasks"].as_array().unwrap().len(), 1);
    assert!(is_other_spreadsheet("a/b.XLS"));
    assert!(!is_other_spreadsheet("a/b.xlsx"));
    assert!(!is_other_spreadsheet("a/b.csv"));
}

/// SG-000130 W2: what the commit approval binds for each workbook: the real
/// path read from the open handle (not the caller's string), the SHA-256 and the
/// parser's pinned digest; a parser pin other than the one the workbook was read
/// with is refused.
#[test]
fn the_approval_binds_the_handle_path_the_sha256_and_the_parser() {
    let first = Scene::new("workbook-binding-a");
    let second = Scene::new("workbook-binding-b");
    let bytes = b"PK the same bytes".to_vec();
    let mut bound = Vec::new();
    for scene in [&first, &second] {
        std::fs::write(scene.workspace.root.join("data").join("Sales.xlsx"), &bytes).unwrap();
        // Where names ignore case, the caller may name it in another case;
        // the prompt shows the handle's real path.
        let named = if cfg!(any(windows, target_os = "macos")) {
            "data/sales.xlsx"
        } else {
            "data/Sales.xlsx"
        };
        let observed = observe_workspace_file(&scene.workspace, named).unwrap();
        assert_eq!(observed.opened(), "data/Sales.xlsx");
        let record = SourceRecord {
            path: "data/sales.xlsx".into(),
            sha256: observed.sha256().to_owned(),
            bytes: observed.bytes(),
            kind: SourceKind::Workbook,
        };
        let workbooks = vec![WorkbookSource {
            path: "data/sales.xlsx".into(),
            observed: observed.clone(),
            parser_sha256: DIGEST.into(),
            hidden_sheets: Vec::new(),
            notices: Vec::new(),
        }];
        let pins = dummy_pins(&scene.dir);
        let fields = binding(&workbooks, std::slice::from_ref(&record), Some(&pins)).unwrap();
        assert_eq!(
            fields,
            vec![
                "workbook".to_owned(),
                observed.canonical().to_string_lossy().into_owned(),
                sha256_hex(&bytes),
                DIGEST.to_owned(),
            ]
        );
        assert!(
            !fields[1].starts_with(r"\\?\") && fields[1].ends_with("Sales.xlsx"),
            "{fields:?}"
        );
        // Another parser pin than the one it was read with.
        let other = (
            HelperPin::new(scene.dir.join("orcel-contain"), DIGEST).unwrap(),
            ParserPin::for_test(scene.dir.join(PARSER_NAME), "f".repeat(64)),
        );
        let refused = binding(&workbooks, std::slice::from_ref(&record), Some(&other)).unwrap_err();
        assert_eq!(
            refused.code,
            FailureCode::TargetStale,
            "{}",
            refused.message
        );
        assert_eq!(
            binding(&workbooks, std::slice::from_ref(&record), None)
                .unwrap_err()
                .code,
            FailureCode::ProviderUnavailable
        );
        // A text source binds nothing more.
        let text = SourceRecord {
            kind: SourceKind::Text,
            ..record
        };
        assert!(binding(&workbooks, &[text], Some(&pins))
            .unwrap()
            .is_empty());
        bound.push(fields);
    }
    // The same relative path and bytes in another place bind another path.
    assert_eq!(bound[0][2], bound[1][2]);
    assert_ne!(bound[0][1], bound[1][1]);
}

/// The real helper and parser, from the CI job's directories.
pub(crate) fn real_pins() -> Option<(HelperPin, ParserPin)> {
    let (Some(contain), Some(parser_dir)) = (
        std::env::var_os("ORCEL_TEST_CONTAIN_DIR"),
        std::env::var_os("ORCEL_TEST_DOC_PARSER_DIR"),
    ) else {
        assert!(
            std::env::var_os("ORCEL_REQUIRE_CONTAINED_PARSER").is_none(),
            "ORCEL_TEST_CONTAIN_DIR and ORCEL_TEST_DOC_PARSER_DIR are required"
        );
        return None;
    };
    let helper_path = std::fs::canonicalize(contain)
        .unwrap()
        .join(crate::contained_tier::HELPER_NAME);
    let helper = HelperPin::new(
        &helper_path,
        &sha256_hex(&std::fs::read(&helper_path).expect("read the helper")),
    )
    .unwrap();
    // A granted file must have one link, and Cargo hard-links its outputs: the
    // parser runs from a plain copy, as an install would hold it. One copy per
    // test process, which every journey here shares.
    let bin: PathBuf =
        std::env::temp_dir().join(format!("orceld-f5-workbook-bin-{}", std::process::id()));
    std::fs::create_dir_all(&bin).unwrap();
    let bin = std::fs::canonicalize(bin).unwrap();
    let parser_path = bin.join(PARSER_NAME);
    static COPIED: std::sync::Once = std::sync::Once::new();
    COPIED.call_once(|| {
        std::fs::copy(Path::new(&parser_dir).join(PARSER_NAME), &parser_path).unwrap();
        let digest = sha256_hex(&std::fs::read(&parser_path).unwrap());
        std::fs::write(bin.join(PARSER_PIN_NAME), format!("{digest}\n")).unwrap();
    });
    let digest = sha256_hex(&std::fs::read(&parser_path).unwrap());
    let started = std::time::Instant::now();
    while std::process::Command::new(&parser_path)
        .stdout(std::process::Stdio::null())
        .status()
        .is_err()
    {
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let pins = (helper, ParserPin::for_test(parser_path, digest));
    // The report task holds the pins; the writer and the checker get them there.
    set_workbook_pins(pins.clone());
    Some(pins)
}

/// The independent check of `report` at `reports/<name>`, with these sources
/// and pins.
fn checked(
    scene: &Scene,
    name: &str,
    report: &str,
    sources: &[SourceRecord],
    pins: Option<&Pins>,
) -> Result<serde_json::Value, String> {
    let root = &scene.workspace.root;
    let destination = format!("reports/{name}");
    std::fs::write(root.join(&destination), report).unwrap();
    let folder = std::fs::canonicalize(root.join("reports")).unwrap();
    report_check::check(&Expectation {
        root,
        folder_path: &root.join("reports"),
        folder: &folder,
        destination: &destination,
        sha256: &sha256_hex(report.as_bytes()),
        bytes: report.len() as u64,
        sources,
        pins,
    })
}

/// The xlsxwriter fixture with an incompressible part that takes it past the
/// checker's text limit (1 MiB), well within the parser's input bound.
pub(crate) fn large_workbook() -> Vec<u8> {
    let mut parts = fixture_parts("written-by-xlsxwriter");
    let mut seed = 0x9e37_79b9_u32;
    let padding: Vec<u8> = (0..1_200_000)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        })
        .collect();
    parts.push(("docProps/padding.bin".into(), padding));
    let large = stored_zip(parts);
    assert!(large.len() > 1024 * 1024);
    large
}

pub(crate) fn workbook_record(path: &str, bytes: &[u8]) -> SourceRecord {
    SourceRecord {
        path: path.into(),
        sha256: sha256_hex(bytes),
        bytes: bytes.len() as u64,
        kind: SourceKind::Workbook,
    }
}

fn commit_request(task: &str, name: &str, content: &str) -> orcel_contracts::RequestEnvelope {
    request(
        "commit",
        json!({
            "task_id": task, "name": name, "content": content,
            "expected_sha256": sha256_hex(content.as_bytes()),
        }),
    )
}

fn preview(
    scene: &Scene,
    tasks: &TaskRegistry,
    task: &str,
    name: &str,
    content: &str,
) -> Result<serde_json::Value, ProviderError> {
    dispatch(
        &scene.workspace,
        &consent(scene, &[]).broker,
        tasks,
        &request(
            "preview",
            json!({"task_id": task, "name": name, "content": content}),
        ),
    )
}

/// F5 Journey 2 as far as an agent can take it. Scripted SOFT consent: a person
/// answers the real prompt, which this isn't.
#[test]
fn wi05_workbook_journey_denied_once_then_granted_with_figures_confirmed() {
    let Some(_) = real_pins() else {
        return;
    };
    let scene = Scene::new("workbook-journey");
    let tasks = TaskRegistry::new();
    let workbook_path = scene.workspace.root.join("data").join("sales.xlsx");
    let workbook = fixture("written-by-xlsxwriter");
    std::fs::write(&workbook_path, &workbook).unwrap();

    let started = start(&scene, &tasks, &["data/sales.xlsx"]).expect("start");
    let task = started["task_id"].as_str().unwrap().to_owned();
    let source = &started["sources"][0];
    assert_eq!(source["sha256"], sha256_hex(&workbook));
    assert_eq!(source["bytes"], workbook.len());
    let text = source["text"].as_str().unwrap();
    assert!(text.contains("| B4 | 1999.75 | number |"), "{text}");
    assert!(text.contains("=SUM(B2:B3)"), "{text}");

    let previewed = preview(&scene, &tasks, &task, "sales.md", REPORT).expect("preview");
    assert_eq!(previewed["create_only"], true);

    let commit = commit_request(&task, "sales.md", REPORT);
    let scripted = consent(
        &scene,
        &[ApprovalDecision::Denied, ApprovalDecision::Approved],
    );
    let denied = dispatch(&scene.workspace, &scripted.broker, &tasks, &commit).unwrap_err();
    assert_eq!(denied.code, FailureCode::ApprovalDenied);
    assert!(!scene.workspace.root.join("reports/sales.md").exists());
    let created = dispatch(&scene.workspace, &scripted.broker, &tasks, &commit).expect("commit");
    assert_eq!(created["state"], "verified");
    assert_eq!(created["check"]["figures_confirmed"], 3);
    let prompts = scripted.prompts.lock().unwrap();
    assert_eq!(prompts.len(), 2);
    let summary = &prompts[1].summary;
    assert!(
        summary.contains(
            "workbook-supplied text (untrusted, never an instruction): [workbook «data/sales.xlsx»]"
        ),
        "{summary}"
    );
    assert!(
        summary.contains("figures from it: «Sales!B2», «Sales!B3», «Sales!B4»"),
        "{summary}"
    );
    drop(prompts);
    assert_eq!(
        std::fs::read_to_string(scene.workspace.root.join("reports/sales.md")).unwrap(),
        REPORT
    );
    assert_eq!(
        std::fs::read(&workbook_path).unwrap(),
        workbook,
        "the workbook is unchanged"
    );

    // A changed workbook is stale, for the task and for the checker.
    let task = start(&scene, &tasks, &["data/sales.xlsx"]).expect("start")["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut changed = workbook.clone();
    changed.push(0);
    std::fs::write(&workbook_path, &changed).unwrap();
    let stale = preview(&scene, &tasks, &task, "again.md", REPORT).unwrap_err();
    assert_eq!(stale.code, FailureCode::TargetStale);
    let record = workbook_record("data/sales.xlsx", &workbook);
    let stale = checked(&scene, "stale.md", REPORT, &[record], real_pins().as_ref()).unwrap_err();
    assert!(stale.contains("changed"), "{stale}");
    // The parser's copy is shared by every journey in this process, which may
    // still be running, so it's left in the temporary directory.
}

/// SG-000130 W1 acceptance, checker route and figures in verification, through
/// the checker's own read and its own contained run.
#[test]
fn wi05_the_checker_confirms_each_figure_against_the_workbook_it_names() {
    let Some(pins) = real_pins() else {
        return;
    };
    let pins = Some(&pins);
    let scene = Scene::new("workbook-checker");
    let root = scene.workspace.root.clone();
    let sales = fixture("written-by-xlsxwriter");
    std::fs::write(root.join("data").join("sales.xlsx"), &sales).unwrap();
    let record = workbook_record("data/sales.xlsx", &sales);
    let sources = [record.clone()];

    let passed = checked(&scene, "ok.md", REPORT, &sources, pins).expect("verified");
    assert_eq!(passed["figures_confirmed"], 3);
    for (report, why) in [
        ("[data/sales.xlsx]Sales!B4 = 1999.76\n", "doesn't match"),
        ("[data/sales.xlsx]Sales!Z9 = 1\n", "no saved value"),
        ("no figures here\n", "states no figure"),
        ("Sales!B4 = 1999.75\n", "not a figure"),
        ("[data/other.xlsx]Sales!B4 = 1999.75\n", "didn't observe"),
    ] {
        let error = checked(&scene, "bad.md", report, &sources, pins).unwrap_err();
        assert!(error.contains(why), "{report}: {error}");
    }
    // A figure naming a text source is not a workbook figure.
    let with_text = [
        record.clone(),
        SourceRecord {
            path: "data/q3.csv".into(),
            sha256: sha256_hex(crate::report_task::tests::Q3_CSV.as_bytes()),
            bytes: crate::report_task::tests::Q3_CSV.len() as u64,
            kind: SourceKind::Text,
        },
    ];
    let error = checked(
        &scene,
        "text.md",
        "[data/q3.csv]Sales!B4 = 1999.75\n",
        &with_text,
        pins,
    )
    .unwrap_err();
    assert!(
        error.contains("isn't one of the task's workbooks"),
        "{error}"
    );

    // Two workbooks with the same sheet and cell: each figure is checked against
    // the workbook it names.
    let other = stored_zip(edited(
        "written-by-openpyxl",
        "xl/worksheets/sheet1.xml",
        "<v>1250.5</v>",
        "<v>42</v>",
    ));
    std::fs::write(root.join("data").join("other.xlsx"), &other).unwrap();
    let both = [record.clone(), workbook_record("data/other.xlsx", &other)];
    let named = "[data/sales.xlsx]Sales!B2 = 1250.5\n[data/other.xlsx]Sales!B2 = 42\n";
    let passed = checked(&scene, "both.md", named, &both, pins).expect("both verified");
    assert_eq!(passed["figures_confirmed"], 2);
    let swapped = "[data/sales.xlsx]Sales!B2 = 42\n[data/other.xlsx]Sales!B2 = 1250.5\n";
    assert!(checked(&scene, "swapped.md", swapped, &both, pins)
        .unwrap_err()
        .contains("doesn't match"));

    // Bytes that no longer match the recorded SHA-256 fail the check.
    let mut changed = sales.clone();
    changed.push(0);
    std::fs::write(root.join("data").join("sales.xlsx"), &changed).unwrap();
    assert!(checked(&scene, "changed.md", REPORT, &sources, pins)
        .unwrap_err()
        .contains("changed since the task observed it"));

    // Values that may be stale confirm nothing, even a report saying zero.
    let openpyxl = fixture("written-by-openpyxl");
    std::fs::write(root.join("data").join("sales.xlsx"), &openpyxl).unwrap();
    let sources = [workbook_record("data/sales.xlsx", &openpyxl)];
    assert!(checked(
        &scene,
        "zero.md",
        "[data/sales.xlsx]Sales!B4 = 0\n",
        &sources,
        pins
    )
    .is_err());
    assert!(checked(
        &scene,
        "plain.md",
        "[data/sales.xlsx]Sales!B3 = 749.25\n",
        &sources,
        pins
    )
    .is_ok());
    let external = with_first_sheet(
        fixture_parts("written-by-openpyxl"),
        "<c r=\"A1\"><f>[1]Rates!A1</f><v>41</v></c>",
    );
    std::fs::write(root.join("data").join("sales.xlsx"), &external).unwrap();
    let sources = [workbook_record("data/sales.xlsx", &external)];
    let error = checked(
        &scene,
        "ext.md",
        "[data/sales.xlsx]Sales!A1 = 41\n",
        &sources,
        pins,
    )
    .unwrap_err();
    assert!(error.contains("no saved value"), "{error}");

    // Without pins, a workbook confirms nothing.
    let sources = [record];
    std::fs::write(root.join("data").join("sales.xlsx"), &sales).unwrap();
    let error = checked(&scene, "none.md", REPORT, &sources, None).unwrap_err();
    assert!(error.contains("not available"), "{error}");
}

/// SG-000130 W1 acceptance, expected format: a PDF, a zip that isn't a
/// workbook, a macro-enabled workbook and an `.xls` renamed `.xlsx` are refused
/// by the parser's sniff, on the writer's run and on the checker's.
#[test]
fn wi05_a_non_workbook_is_refused_by_the_sniff_on_both_runs() {
    let Some(pins) = real_pins() else {
        return;
    };
    let scene = Scene::new("workbook-sniff");
    let root = scene.workspace.root.clone();
    let tasks = TaskRegistry::new();
    let pdf = b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"
        .to_vec();
    let document = stored_zip(vec![
        (
            "[Content_Types].xml".into(),
            b"<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
              <Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>"
                .to_vec(),
        ),
        ("word/document.xml".into(), b"<w:document/>".to_vec()),
    ]);
    let not_a_package = stored_zip(vec![("notes.txt".into(), b"[a.xlsx]S!A1 = 1".to_vec())]);
    let mut macros = fixture_parts("written-by-openpyxl");
    macros.push(("xl/vbaProject.bin".into(), b"not really".to_vec()));
    let macros = stored_zip(macros);
    let mut xls = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    xls.resize(1024, 0);
    for (name, bytes, code) in [
        ("pdf.xlsx", pdf, "unsupported_format"),
        ("document.xlsx", document, "unsupported_format"),
        ("zip.xlsx", not_a_package, "unsupported_format"),
        ("macros.xlsx", macros, "active_content"),
        ("legacy.xlsx", xls, "unsupported_format"),
    ] {
        let path = format!("data/{name}");
        std::fs::write(root.join(&path), &bytes).unwrap();
        let refused = start(&scene, &tasks, &[&path]).unwrap_err();
        assert!(
            refused
                .message
                .contains(&format!("document_parse_refused:{code}")),
            "{name}: {}",
            refused.message
        );
        let report = format!("[{path}]Sales!B2 = 1\n");
        let error = checked(
            &scene,
            "sniffed.md",
            &report,
            &[workbook_record(&path, &bytes)],
            Some(&pins),
        )
        .unwrap_err();
        assert!(
            error.contains(&format!("document_parse_refused:{code}")),
            "{name}: {error}"
        );
    }
    assert_eq!(tasks.list()["tasks"].as_array().unwrap().len(), 0);
}

/// SG-000130 W1 acceptance, checker limit, false figures and the prompt: a
/// workbook over 1 MiB is observed, previewed, committed and verified; a false
/// figure ends `verification_failed`; a figure naming no workbook is refused at
/// preview; the prompt shows a hidden sheet and a link notice escaped.
#[test]
fn wi05_a_large_workbook_verifies_and_a_false_figure_never_does() {
    let Some(_) = real_pins() else {
        return;
    };
    let scene = Scene::new("workbook-limits");
    let root = scene.workspace.root.clone();
    let tasks = TaskRegistry::new();

    // Over the text limit, within the parser's input bound.
    let large = large_workbook();
    std::fs::write(root.join("data").join("sales.xlsx"), &large).unwrap();
    let task = start(&scene, &tasks, &["data/sales.xlsx"]).expect("start")["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    preview(&scene, &tasks, &task, "large.md", REPORT).expect("preview");
    let scripted = consent(&scene, &[ApprovalDecision::Approved]);
    let created = dispatch(
        &scene.workspace,
        &scripted.broker,
        &tasks,
        &commit_request(&task, "large.md", REPORT),
    )
    .expect("commit");
    assert_eq!(created["state"], "verified");

    // A false figure: written, then the checker ends it verification_failed.
    let task = start(&scene, &tasks, &["data/sales.xlsx"]).expect("start")["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let false_figure = "[data/sales.xlsx]Sales!B2 = 1250.5\n[data/sales.xlsx]Sales!B4 = 2000\n";
    preview(&scene, &tasks, &task, "false.md", false_figure).expect("preview");
    let scripted = consent(&scene, &[ApprovalDecision::Approved]);
    let failed = dispatch(
        &scene.workspace,
        &scripted.broker,
        &tasks,
        &commit_request(&task, "false.md", false_figure),
    )
    .unwrap_err();
    assert_eq!(failed.code, FailureCode::PostconditionFailed);
    assert!(
        failed.message.contains("doesn't match"),
        "{}",
        failed.message
    );
    assert_eq!(tasks.get(&task).unwrap()["state"], "verification_failed");

    // A figure naming no source, or one the task didn't observe, never reaches
    // a prompt.
    let task = start(&scene, &tasks, &["data/sales.xlsx"]).expect("start")["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    for report in [
        "Sales!B2 = 1250.5\n",
        "[data/else.xlsx]Sales!B2 = 1250.5\n",
        "no figures\n",
    ] {
        let refused = preview(&scene, &tasks, &task, "named.md", report).unwrap_err();
        assert_eq!(refused.code, FailureCode::InvalidRequest, "{report}");
    }

    // A hidden sheet whose name holds a line break, a bidi override and a
    // zero-width space, and an external link: shown in the prompt, labelled and
    // escaped.
    // The openpyxl fixture's sheet "Audit" is hidden already.
    let mut hidden = edited(
        "written-by-openpyxl",
        "xl/workbook.xml",
        "name=\"Audit\"",
        "name=\"Audit&#10;&#x202E;&#x200B;x\"",
    );
    let rels = hidden
        .iter_mut()
        .find(|(name, _)| name == "xl/_rels/workbook.xml.rels")
        .expect("workbook relationships");
    let text = String::from_utf8(rels.1.clone()).unwrap();
    rels.1 = text
        .replacen(
            "</Relationships>",
            "<Relationship Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLink\" Target=\"externalLinks/externalLink1.xml\" Id=\"rIdLink\" /></Relationships>",
            1,
        )
        .into_bytes();
    // SG-000130 W2: the link's target, with a line break, a bidi override and a
    // zero-width space in it.
    hidden.push((
        "xl/externalLinks/externalLink1.xml".into(),
        b"<externalLink xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"/>"
            .to_vec(),
    ));
    hidden.push((
        "xl/externalLinks/_rels/externalLink1.xml.rels".into(),
        b"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
          <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLinkPath\" \
          Target=\"file:///C:/x&#10;&#x202E;&#x200B;y.xlsx\" TargetMode=\"External\"/></Relationships>"
            .to_vec(),
    ));
    let book = stored_zip(hidden);
    std::fs::write(root.join("data").join("hidden.xlsx"), &book).unwrap();
    let started = start(&scene, &tasks, &["data/hidden.xlsx"]).expect("start");
    let task = started["task_id"].as_str().unwrap().to_owned();
    let report = "[data/hidden.xlsx]Sales!B3 = 749.25\n";
    preview(&scene, &tasks, &task, "hidden.md", report).expect("preview");
    let scripted = consent(&scene, &[ApprovalDecision::Denied]);
    let denied = dispatch(
        &scene.workspace,
        &scripted.broker,
        &tasks,
        &commit_request(&task, "hidden.md", report),
    )
    .unwrap_err();
    assert_eq!(denied.code, FailureCode::ApprovalDenied);
    let prompts = scripted.prompts.lock().unwrap();
    let summary = &prompts[0].summary;
    assert!(
        summary.contains("[workbook «data/hidden.xlsx»]"),
        "{summary}"
    );
    assert!(summary.contains("hidden sheet: «Audit"), "{summary}");
    assert!(
        summary.contains("notice: «External workbook links: 1."),
        "{summary}"
    );
    assert!(
        summary.contains(
            "notice: «External link target (workbook-supplied, not followed): file:///C:/x"
        ),
        "{summary}"
    );
    assert!(summary.contains("figures from it: «Sales!B3»"), "{summary}");
    let shown: String = orcel_contracts::prompt_display::pieces(summary).concat();
    assert!(!shown.contains('\n') && !shown.contains('\u{202e}') && !shown.contains('\u{200b}'));
    // The target's line break and bidi override, escaped by the reader, and its
    // zero-width space, escaped by the prompt's display.
    assert!(
        shown.contains("file:///C:/x\\\\n\\\\u{202e}\\u{200b}y.xlsx"),
        "{shown}"
    );
}

/// SG-000130 W2 acceptance, exposure, as a client reaches it: the report
/// journey with an `.xlsx` source in the exact shape the MCP edge's report
/// tools send to orceld (`buildRequest` in `apps/orcel-mcp/src/kernel.ts`, as
/// JSON on orceld's stdio channel, with the local transport's profile), through
/// orceld's own entry (`handle_envelope`: profile gate, the local-only check,
/// policy, dispatch, audit), the real broker over its own ledger and the real
/// pinned helper and parser. **Only the SOFT consent is scripted** (denied
/// once, then granted); it's not a real approval.
#[test]
fn wi05_sg130_an_xlsx_report_journey_through_the_mcp_report_tools_shape() {
    let Some(_) = real_pins() else {
        return;
    };
    let scene = Scene::new("workbook-mcp");
    let root = scene.workspace.root.clone();
    let workbook = fixture("written-by-xlsxwriter");
    std::fs::write(root.join("data").join("sales.xlsx"), &workbook).unwrap();
    std::fs::write(root.join("data").join("old.xls"), b"not read").unwrap();
    let tasks = TaskRegistry::new();
    let policy = orcel_policy::PolicyEngine::new(vec![scene.workspace.clone()]).unwrap();
    let audit = orcel_audit::AuditLogger::new(scene.dir.join("audit.jsonl")).unwrap();
    // What the edge writes for one tool call.
    let wire = |operation: &str, arguments: serde_json::Value, remote: bool| {
        let mut line = json!({
            "version": 1,
            "request_id": format!("mcp-{operation}"),
            "client_session_id": "mcp-session",
            "workspace_id": "default",
            "capability": "report",
            "operation": operation,
            "arguments": arguments,
            "profile": "desktop_structured",
        });
        if remote {
            line["remote"] = json!({
                "principal": "p", "remoteConnectionId": "rc", "connectionId": "c",
                "deviceId": "d", "deviceEpoch": 1, "providerKind": "generic",
                "clientProfileId": "cp", "clientProfileRevision": 1,
                "toolSurfaceProfile": "core", "scopes": ["orcel.local.write"],
            });
            line.as_object_mut().unwrap().remove("profile");
        }
        serde_json::from_str::<orcel_contracts::RemoteRequestEnvelope>(&line.to_string())
            .expect("the edge's wire shape")
    };
    let scripted = consent(
        &scene,
        &[ApprovalDecision::Denied, ApprovalDecision::Approved],
    );
    let call = |envelope| {
        crate::report_task::handle_envelope(&policy, &audit, &scripted.broker, &tasks, envelope)
    };
    let start_arguments =
        json!({"title": "Sales", "sources": ["data/sales.xlsx"], "folder": "reports"});

    // A remote context never reaches policy or dispatch.
    let remote = call(wire("start", start_arguments.clone(), true));
    assert!(!remote.ok);
    assert_eq!(remote.error.unwrap().code, FailureCode::CapabilityDenied);
    // .xls is refused by name; nothing starts.
    let xls = call(wire(
        "start",
        json!({"title": "Old", "sources": ["data/old.xls"], "folder": "reports"}),
        false,
    ));
    assert_eq!(xls.error.unwrap().code, FailureCode::InvalidRequest);
    assert_eq!(tasks.list()["tasks"].as_array().unwrap().len(), 0);

    let started = call(wire("start", start_arguments, false));
    assert!(started.ok, "{:?}", started.error);
    let started = started.result.unwrap();
    let task = started["task_id"].as_str().unwrap().to_owned();
    assert_eq!(started["sources"][0]["sha256"], sha256_hex(&workbook));
    assert!(started["content_label"]
        .as_str()
        .unwrap()
        .starts_with("untrusted workspace data"));
    let text = started["sources"][0]["text"].as_str().unwrap();
    assert!(text.contains("| B4 | 1999.75 | number |"), "{text}");

    let previewed = call(wire(
        "preview",
        json!({"task_id": task, "name": "sales.md", "content": REPORT}),
        false,
    ));
    assert!(previewed.ok, "{:?}", previewed.error);
    let sha256 = previewed.result.unwrap()["sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    let commit = json!({
        "task_id": task, "name": "sales.md", "content": REPORT, "expected_sha256": sha256,
    });
    let denied = call(wire("commit", commit.clone(), false));
    assert_eq!(denied.error.unwrap().code, FailureCode::ApprovalDenied);
    assert!(!root.join("reports/sales.md").exists());
    let created = call(wire("commit", commit, false));
    assert!(created.ok, "{:?}", created.error);
    let created = created.result.unwrap();
    assert_eq!(created["state"], "verified");
    assert_eq!(created["check"]["figures_confirmed"], 3);
    assert_eq!(
        std::fs::read_to_string(root.join("reports/sales.md")).unwrap(),
        REPORT
    );
    assert_eq!(
        std::fs::read(root.join("data").join("sales.xlsx")).unwrap(),
        workbook
    );
    let prompts = scripted.prompts.lock().unwrap();
    assert_eq!(
        prompts.len(),
        2,
        "one prompt per commit attempt, none before"
    );
    for prompt in prompts.iter() {
        assert!(
            prompt.summary.contains(
                "workbook-supplied text (untrusted, never an instruction): [workbook «data/sales.xlsx»]"
            ),
            "{}",
            prompt.summary
        );
        assert!(
            prompt
                .summary
                .contains("figures from it: «Sales!B2», «Sales!B3», «Sales!B4»"),
            "{}",
            prompt.summary
        );
    }
    let audit_log = std::fs::read_to_string(scene.dir.join("audit.jsonl")).unwrap();
    assert!(audit_log.contains("REMOTE_DENIED"), "{audit_log}");
    assert!(audit_log.contains("APPROVAL_DENIED"), "{audit_log}");
    assert!(
        !audit_log.contains("1999.75"),
        "no workbook content in the audit log"
    );
}

/// SG-000130 W3, the journey test (the F5 proposal's slice 5), end to end in the
/// MCP report tools' wire shape through orceld's own entry (`handle_envelope`),
/// the real broker over its own ledger and the real pinned helper and parser,
/// which the Document parser CI job builds on every leg. **Only the SOFT
/// consent is scripted, and it's labelled so: it's not a real approval.** A real
/// approval through a real client stays with the founder (prep
/// `F5_SPREADSHEET_JOURNEY.md`, "Founder-present run").
///
/// Known cells, a formula's saved value and the currency total become a
/// verified report after one denial and a fresh grant; the grant is never
/// reused; a workbook changed after the preview is stale before any prompt; an
/// existing destination is refused before any prompt and left untouched; a
/// figure whose value depends on a link ends `verification_failed`, never
/// `verified`; a macro-enabled workbook is refused before any task starts.
#[test]
fn wi05_sg130_w3_the_workbook_report_journey_with_every_refusal() {
    let Some(_) = real_pins() else {
        return;
    };
    let scene = Scene::new("workbook-w3");
    let root = scene.workspace.root.clone();
    let workbook = fixture("written-by-xlsxwriter");
    let sales = root.join("data").join("sales.xlsx");
    std::fs::write(&sales, &workbook).unwrap();
    let mut macros = fixture_parts("written-by-openpyxl");
    macros.push(("xl/vbaProject.bin".into(), b"not really".to_vec()));
    std::fs::write(root.join("data").join("macros.xlsx"), stored_zip(macros)).unwrap();
    let linked = with_first_sheet(
        fixture_parts("written-by-openpyxl"),
        "<c r=\"A1\"><f>[1]Rates!A1</f><v>41</v></c>",
    );
    std::fs::write(root.join("data").join("linked.xlsx"), &linked).unwrap();
    let taken = b"A file the user already has. Orcel must never overwrite it.\n";
    std::fs::write(root.join("reports").join("taken.md"), taken).unwrap();

    let tasks = TaskRegistry::new();
    let policy = orcel_policy::PolicyEngine::new(vec![scene.workspace.clone()]).unwrap();
    let audit = orcel_audit::AuditLogger::new(scene.dir.join("audit.jsonl")).unwrap();
    // Scripted SOFT consent, in order: the first commit denied, then granted;
    // the linked workbook's commit granted. Any further prompt is denied.
    let scripted = consent(
        &scene,
        &[
            ApprovalDecision::Denied,
            ApprovalDecision::Approved,
            ApprovalDecision::Approved,
        ],
    );
    let shown = || scripted.prompts.lock().unwrap().len();
    let call = |operation: &str, arguments: serde_json::Value| {
        let line = json!({
            "version": 1,
            "request_id": format!("mcp-w3-{operation}"),
            "client_session_id": "mcp-session",
            "workspace_id": "default",
            "capability": "report",
            "operation": operation,
            "arguments": arguments,
            "profile": "desktop_structured",
        });
        let envelope =
            serde_json::from_str::<orcel_contracts::RemoteRequestEnvelope>(&line.to_string())
                .expect("the edge's wire shape");
        let response = crate::report_task::handle_envelope(
            &policy,
            &audit,
            &scripted.broker,
            &tasks,
            envelope,
        );
        match (response.ok, response.result, response.error) {
            (true, Some(result), _) => Ok(result),
            (_, _, Some(error)) => Err(error),
            _ => panic!("a response with neither a result nor an error"),
        }
    };
    let start_task = |source: &str| {
        call(
            "start",
            json!({"title": "Sales", "sources": [source], "folder": "reports"}),
        )
    };
    let preview_report = |task: &str, name: &str, content: &str| {
        call(
            "preview",
            json!({"task_id": task, "name": name, "content": content}),
        )
    };
    let commit_report = |task: &str, name: &str, content: &str| {
        call(
            "commit",
            json!({
                "task_id": task, "name": name, "content": content,
                "expected_sha256": sha256_hex(content.as_bytes()),
            }),
        )
    };
    let task_id = |started: &serde_json::Value| started["task_id"].as_str().unwrap().to_owned();

    // 1. Known cells, a formula's saved value and the currency total: denied
    // once, then a fresh grant, verified figure by figure.
    let report = "# Sales\n\n[data/sales.xlsx]Sales!B2 = 1250.5\n\
        [data/sales.xlsx]Sales!B3 = 749.25\n[data/sales.xlsx]Sales!B4 = 1999.75\n\
        [data/sales.xlsx]Sales!C2 = 0.625\n";
    let started = start_task("data/sales.xlsx").expect("start");
    let text = started["sources"][0]["text"].as_str().unwrap();
    assert!(text.contains("=SUM(B2:B3)"), "{text}");
    assert!(text.contains("=B2/B4"), "{text}");
    let task = task_id(&started);
    preview_report(&task, "sales.md", report).expect("preview");
    let denied = commit_report(&task, "sales.md", report).unwrap_err();
    assert_eq!(denied.code, FailureCode::ApprovalDenied);
    assert!(!root.join("reports/sales.md").exists());
    let created = commit_report(&task, "sales.md", report).expect("a fresh grant");
    assert_eq!(created["state"], "verified");
    assert_eq!(created["check"]["figures_confirmed"], 4);
    assert_eq!(
        std::fs::read_to_string(root.join("reports/sales.md")).unwrap(),
        report
    );
    assert_eq!(shown(), 2, "one prompt per commit attempt");
    {
        let prompts = scripted.prompts.lock().unwrap();
        let summary = &prompts[1].summary;
        assert!(
            summary.contains(
                "workbook-supplied text (untrusted, never an instruction): [workbook «data/sales.xlsx»]"
            ),
            "{summary}"
        );
        assert!(
            summary.contains("figures from it: «Sales!B2», «Sales!B3», «Sales!B4», «Sales!C2»"),
            "{summary}"
        );
        // The fixture's hidden sheet, which the founder-present runbook names.
        assert!(summary.contains("hidden sheet: «Audit"), "{summary}");
    }
    // The grant is used once: committing the verified task again asks nothing.
    assert!(commit_report(&task, "sales.md", report).is_err());
    assert_eq!(shown(), 2);

    // 2. A workbook changed after the preview: stale before any prompt.
    let task = task_id(&start_task("data/sales.xlsx").expect("start"));
    preview_report(&task, "again.md", report).expect("preview");
    let mut changed = workbook.clone();
    changed.push(0);
    std::fs::write(&sales, &changed).unwrap();
    let stale = commit_report(&task, "again.md", report).unwrap_err();
    assert_eq!(stale.code, FailureCode::TargetStale, "{}", stale.message);
    assert!(
        stale.message.contains("data/sales.xlsx"),
        "{}",
        stale.message
    );
    assert_eq!(tasks.get(&task).unwrap()["state"], "stale");
    // Restoring the bytes doesn't revive the stale task.
    std::fs::write(&sales, &workbook).unwrap();
    assert!(commit_report(&task, "again.md", report).is_err());
    assert!(!root.join("reports/again.md").exists());
    assert_eq!(shown(), 2);

    // 3. An existing destination: refused at preview, and at commit when it
    // appears after the preview, before any prompt; the file is untouched.
    let task = task_id(&start_task("data/sales.xlsx").expect("start"));
    let exists = preview_report(&task, "taken.md", report).unwrap_err();
    assert_eq!(exists.code, FailureCode::TargetStale);
    assert!(exists.message.contains("exists"), "{}", exists.message);
    assert_ne!(tasks.get(&task).unwrap()["state"], "stale");
    preview_report(&task, "late.md", report).expect("preview");
    std::fs::write(root.join("reports/late.md"), taken).unwrap();
    let exists = commit_report(&task, "late.md", report).unwrap_err();
    assert!(exists.message.contains("exists"), "{}", exists.message);
    assert_eq!(std::fs::read(root.join("reports/taken.md")).unwrap(), taken);
    assert_eq!(std::fs::read(root.join("reports/late.md")).unwrap(), taken);
    assert_eq!(shown(), 2);

    // 4. A figure whose saved value depends on an external link confirms
    // nothing: written after the grant, then verification_failed.
    let task = task_id(&start_task("data/linked.xlsx").expect("start"));
    let linked_report = "[data/linked.xlsx]Sales!A1 = 41\n";
    preview_report(&task, "linked.md", linked_report).expect("preview");
    let failed = commit_report(&task, "linked.md", linked_report).unwrap_err();
    assert_eq!(failed.code, FailureCode::PostconditionFailed);
    assert!(
        failed.message.contains("no saved value"),
        "{}",
        failed.message
    );
    assert_eq!(tasks.get(&task).unwrap()["state"], "verification_failed");
    // The report was written (create-only) before the checker refused it.
    assert_eq!(
        std::fs::read_to_string(root.join("reports/linked.md")).unwrap(),
        linked_report
    );
    assert_eq!(shown(), 3);

    // 5. A macro-enabled workbook: refused by the parser's sniff, no task.
    let before = tasks.list()["tasks"].as_array().unwrap().len();
    let refused = start_task("data/macros.xlsx").unwrap_err();
    assert!(
        refused
            .message
            .contains("document_parse_refused:active_content"),
        "{}",
        refused.message
    );
    assert_eq!(tasks.list()["tasks"].as_array().unwrap().len(), before);

    // The workbooks were only read.
    assert_eq!(std::fs::read(&sales).unwrap(), workbook);
    assert_eq!(
        std::fs::read(root.join("data").join("linked.xlsx")).unwrap(),
        linked
    );
    let audit_log = std::fs::read_to_string(scene.dir.join("audit.jsonl")).unwrap();
    assert!(audit_log.contains("APPROVAL_DENIED"), "{audit_log}");
    assert!(audit_log.contains("TARGET_STALE"), "{audit_log}");
    assert!(audit_log.contains("POSTCONDITION_FAILED"), "{audit_log}");
    assert!(
        !audit_log.contains("1999.75"),
        "no workbook content in the audit log"
    );
}
