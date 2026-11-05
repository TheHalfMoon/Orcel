//! A workbook as a report source. The unit tests need nothing else. The journey
//! runs the real report task and approval broker, with the real pinned helper and
//! parser, where the Document parser CI job provides them: **only the SOFT consent
//! is scripted, and it's labelled so here.** It's not a real approval.

use super::*;
use crate::document_parse::{PARSER_NAME, PARSER_PIN_NAME};
use crate::report_task::tests::{consent, request, Scene};
use crate::report_task::{dispatch, TaskRegistry};
use orcel_approval::ApprovalDecision;
use serde_json::json;
use std::path::{Path, PathBuf};

const REPORT: &str = "# Sales\n\nSales!B2 = 1250.5\nSales!B3 = 749.25\nSales!B4 = 1999.75\n";

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
fn stored_zip(mut parts: Vec<(String, Vec<u8>)>) -> Vec<u8> {
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
fn fixture_parts(name: &str) -> Vec<(String, Vec<u8>)> {
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

fn fixture(name: &str) -> Vec<u8> {
    stored_zip(fixture_parts(name))
}

fn start(
    scene: &Scene,
    tasks: &TaskRegistry,
    source: &str,
) -> Result<serde_json::Value, ProviderError> {
    dispatch(
        &scene.workspace,
        &consent(scene, &[]).broker,
        tasks,
        &request(
            "start",
            json!({"title": "Sales", "sources": [source], "folder": "reports"}),
        ),
    )
}

const MARKDOWN: &str = "# Workbook\n\n## Sheet: Sales\n\n\
| Cell | Value | Type | Format | Formula | Note |\n|---|---|---|---|---|---|\n\
| B2 | 1250.5 | number | \"$\"#,##0.00 |  |  |\n\
| B4 |  | empty |  | =SUM(B2:B3) | no saved value |\n\
| C1 | a \\| b | text |  |  |  |\n\
| B20 | 7 | number |  |  |  |\n\n\
## Sheet: Audit (hidden)\n\n\
| Cell | Value | Type | Format | Formula | Note |\n|---|---|---|---|---|---|\n\
| B2 | other | text |  |  |  |\n";

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
fn a_workbook_with_an_outside_source_confirms_no_formula() {
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
        Some("7"),
        "a typed value doesn't"
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
fn figures_are_read_from_their_own_lines() {
    assert_eq!(
        figures_in("Intro = no place\nJust wow!\nNote: see below\nQ3 revenue: fine\nSales!B2 = 1.5\nA!B!C3 = x = y\n"),
        Ok(vec![("Sales", "B2", "1.5"), ("A!B", "C3", "x = y")])
    );
}

#[test]
fn a_line_shaped_like_a_figure_but_not_checkable_is_an_error() {
    for line in [
        "Sales!b4 = 99999",
        "Sales!B4=99999",
        "Sales!$B$4 = 99999",
        "P = Q!B2 = 123456",
        "Sales!B = 1",
        "Sales!2 = 1",
        "!B2 = 1",
        "Sales!B2 = ",
        "B4 = 99999",
        "b4 = 99999",
        "$B$4 = 99999",
        "Sales!B4: 99999",
        "B4: 99999",
    ] {
        let report = format!("Sales!B2 = 1250.5\n{line}\n");
        assert!(figures_in(&report).is_err(), "{line}");
    }
}

#[test]
fn with_no_parser_a_workbook_is_unavailable_and_nothing_is_confirmed() {
    let scene = Scene::new("workbook-no-pins");
    let path = scene.workspace.root.join("data").join("a.xlsx");
    let bytes = fixture("written-by-openpyxl");
    std::fs::write(&path, &bytes).unwrap();
    let error = parse(&bytes, None).unwrap_err();
    assert_eq!(error.code, FailureCode::ProviderUnavailable);
    let record = SourceRecord {
        path: "data/a.xlsx".into(),
        sha256: sha256_hex(&bytes),
        bytes: bytes.len() as u64,
    };
    assert!(check_figures_with(&scene.workspace, &record, REPORT, None).is_err());
}

#[test]
fn a_workbook_path_gets_the_providers_refusals() {
    let scene = Scene::new("workbook-paths");
    let outside = scene.dir.join("outside.xlsx");
    std::fs::write(&outside, b"PK").unwrap();
    assert!(read(&scene.workspace, "../outside.xlsx").is_err());
    assert!(read(&scene.workspace, "data/absent.xlsx").is_err());
    assert!(read(&scene.workspace, "data").is_err());
    assert!(is_workbook("data/Book.XLSX"));
    assert!(!is_workbook("data/q3.csv"));
}

/// The gate: this module is compiled only for tests, and every use of it in the
/// report task is too. It's what keeps this behind founder decision 7.
#[test]
fn the_workbook_source_is_compiled_only_for_tests() {
    let source = |name: &str| {
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(name))
            .unwrap()
    };
    // A checkout may end lines with CRLF.
    let main = source("sg000039_main.rs").replace("\r\n", "\n");
    assert!(main.contains("#[cfg(test)]\nmod report_workbook;"));
    assert_eq!(main.matches("mod report_workbook").count(), 1);
    let task = source("report_task.rs");
    let lines: Vec<&str> = task.lines().collect();
    let uses: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.contains("report_workbook::"))
        .map(|(at, _)| at)
        .collect();
    assert_eq!(uses.len(), 2, "one use at start and one at the stale check");
    for at in uses {
        assert!(
            lines[..at]
                .iter()
                .rev()
                .take(2)
                .any(|line| line.trim() == "#[cfg(test)]"),
            "report_task.rs:{} isn't test-only",
            at + 1
        );
    }
}

/// The real helper and parser, from the CI job's directories.
fn real_pins() -> Option<(HelperPin, ParserPin)> {
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
    // parser runs from a plain copy, as an install would hold it.
    let bin: PathBuf =
        std::env::temp_dir().join(format!("orceld-f5-workbook-bin-{}", std::process::id()));
    std::fs::create_dir_all(&bin).unwrap();
    let bin = std::fs::canonicalize(bin).unwrap();
    let parser_path = bin.join(PARSER_NAME);
    std::fs::copy(Path::new(&parser_dir).join(PARSER_NAME), &parser_path).unwrap();
    let digest = sha256_hex(&std::fs::read(&parser_path).unwrap());
    std::fs::write(bin.join(PARSER_PIN_NAME), format!("{digest}\n")).unwrap();
    let started = std::time::Instant::now();
    while std::process::Command::new(&parser_path)
        .stdout(std::process::Stdio::null())
        .status()
        .is_err()
    {
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Some((helper, ParserPin::for_test(parser_path, digest)))
}

/// F5 Journey 2 as far as an agent can take it. Scripted SOFT consent: a person
/// answers the real prompt, which this isn't.
#[test]
fn wi05_workbook_journey_denied_once_then_granted_with_figures_confirmed() {
    let Some((helper, parser)) = real_pins() else {
        return;
    };
    set_pins(helper, parser);
    let scene = Scene::new("workbook-journey");
    let tasks = TaskRegistry::new();
    let workbook_path = scene.workspace.root.join("data").join("sales.xlsx");
    let workbook = fixture("written-by-xlsxwriter");
    std::fs::write(&workbook_path, &workbook).unwrap();

    let started = start(&scene, &tasks, "data/sales.xlsx").expect("start");
    let task = started["task_id"].as_str().unwrap().to_owned();
    let source = &started["sources"][0];
    assert_eq!(source["sha256"], sha256_hex(&workbook));
    assert_eq!(source["bytes"], workbook.len());
    let text = source["text"].as_str().unwrap();
    assert!(text.contains("| B4 | 1999.75 | number |"), "{text}");
    assert!(text.contains("=SUM(B2:B3)"), "{text}");
    let record = SourceRecord {
        path: "data/sales.xlsx".into(),
        sha256: sha256_hex(&workbook),
        bytes: workbook.len() as u64,
    };

    let quiet = consent(&scene, &[]);
    let previewed = dispatch(
        &scene.workspace,
        &quiet.broker,
        &tasks,
        &request(
            "preview",
            json!({"task_id": task, "name": "sales.md", "content": REPORT}),
        ),
    )
    .expect("preview");
    assert_eq!(previewed["create_only"], true);

    let commit = request(
        "commit",
        json!({
            "task_id": task, "name": "sales.md", "content": REPORT,
            "expected_sha256": sha256_hex(REPORT.as_bytes()),
        }),
    );
    let scripted = consent(
        &scene,
        &[ApprovalDecision::Denied, ApprovalDecision::Approved],
    );
    let denied = dispatch(&scene.workspace, &scripted.broker, &tasks, &commit).unwrap_err();
    assert_eq!(denied.code, FailureCode::ApprovalDenied);
    assert!(!scene.workspace.root.join("reports/sales.md").exists());
    let created = dispatch(&scene.workspace, &scripted.broker, &tasks, &commit).expect("commit");
    assert_eq!(created["state"], "verified");
    assert_eq!(scripted.prompts.lock().unwrap().len(), 2);
    assert_eq!(
        std::fs::read_to_string(scene.workspace.root.join("reports/sales.md")).unwrap(),
        REPORT
    );
    assert_eq!(
        std::fs::read(&workbook_path).unwrap(),
        workbook,
        "the workbook is unchanged"
    );

    // A second contained run confirms each figure, and only a true one.
    assert_eq!(check_figures(&scene.workspace, &record, REPORT), Ok(3));
    let wrong = check_figures(&scene.workspace, &record, "Sales!B4 = 1999.76\n").unwrap_err();
    assert!(wrong.contains("doesn't match"), "{wrong}");
    assert!(check_figures(&scene.workspace, &record, "Sales!Z9 = 1\n").is_err());
    assert!(check_figures(&scene.workspace, &record, "no figures here\n").is_err());

    // A changed workbook is stale, for the task and for the figures.
    let task = start(&scene, &tasks, "data/sales.xlsx").expect("start")["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut changed = workbook.clone();
    changed.push(0);
    std::fs::write(&workbook_path, &changed).unwrap();
    let stale = dispatch(
        &scene.workspace,
        &quiet.broker,
        &tasks,
        &request(
            "preview",
            json!({"task_id": task, "name": "again.md", "content": REPORT}),
        ),
    )
    .unwrap_err();
    assert_eq!(stale.code, FailureCode::TargetStale);
    let stale = check_figures(&scene.workspace, &record, REPORT).unwrap_err();
    assert!(stale.contains("changed"), "{stale}");

    // A formula with no saved value confirms nothing, even a report saying zero.
    let openpyxl = fixture("written-by-openpyxl");
    std::fs::write(&workbook_path, &openpyxl).unwrap();
    let record = SourceRecord {
        path: "data/sales.xlsx".into(),
        sha256: sha256_hex(&openpyxl),
        bytes: openpyxl.len() as u64,
    };
    assert!(check_figures(&scene.workspace, &record, "Sales!B4 = 0\n").is_err());
    assert_eq!(
        check_figures(&scene.workspace, &record, "Sales!B3 = 749.25\n"),
        Ok(1)
    );

    // A value from a formula that may reach outside confirms nothing.
    let external = with_first_sheet(
        fixture_parts("written-by-openpyxl"),
        "<c r=\"A1\"><f>[1]Rates!A1</f><v>41</v></c>",
    );
    std::fs::write(&workbook_path, &external).unwrap();
    let record = SourceRecord {
        path: "data/sales.xlsx".into(),
        sha256: sha256_hex(&external),
        bytes: external.len() as u64,
    };
    let stale = check_figures(&scene.workspace, &record, "Sales!A1 = 41\n").unwrap_err();
    assert!(stale.contains("no saved value"), "{stale}");

    // Nor does one reaching outside through a defined name, which the row can't show.
    let mut named = fixture_parts("written-by-openpyxl");
    let book = named
        .iter_mut()
        .find(|(name, _)| name == "xl/workbook.xml")
        .expect("a workbook part");
    let text = String::from_utf8(book.1.clone()).unwrap();
    assert!(text.contains("</workbook>"), "{text}");
    book.1 = text
        .replace(
            "</workbook>",
            "<definedNames><definedName name=\"Rate\">[1]Rates!$A$1</definedName></definedNames></workbook>",
        )
        .into_bytes();
    let through_name = with_first_sheet(named, "<c r=\"A1\"><f>Rate</f><v>41</v></c>");
    std::fs::write(&workbook_path, &through_name).unwrap();
    let record = SourceRecord {
        path: "data/sales.xlsx".into(),
        sha256: sha256_hex(&through_name),
        bytes: through_name.len() as u64,
    };
    assert!(check_figures(&scene.workspace, &record, "Sales!A1 = 41\n").is_err());

    // A workbook too large for the frame isn't read in part.
    let text = "y".repeat(1_000_100);
    let large = with_first_sheet(
        fixture_parts("written-by-openpyxl"),
        &format!("<c r=\"A1\" t=\"inlineStr\"><is><t>{text}</t></is></c>"),
    );
    std::fs::write(&workbook_path, large).unwrap();
    let cut = start(&scene, &tasks, "data/sales.xlsx").unwrap_err();
    assert_eq!(cut.code, FailureCode::OutputLimit, "{}", cut.message);

    // A document named as a workbook isn't one.
    let content_types = "<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
        <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
        <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
        <Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>";
    let rels = "<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
        <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>";
    let body = "<?xml version=\"1.0\"?><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>Sales!B4 = 1</w:t></w:r></w:p></w:body></w:document>";
    let document = stored_zip(vec![
        (
            "[Content_Types].xml".into(),
            content_types.as_bytes().to_vec(),
        ),
        ("_rels/.rels".into(), rels.as_bytes().to_vec()),
        ("word/document.xml".into(), body.as_bytes().to_vec()),
    ]);
    std::fs::write(&workbook_path, &document).unwrap();
    let not_one = start(&scene, &tasks, "data/sales.xlsx").unwrap_err();
    assert_eq!(
        not_one.code,
        FailureCode::InvalidRequest,
        "{}",
        not_one.message
    );
    assert!(not_one.message.contains("isn't one"), "{}", not_one.message);

    // A link is refused before anything reads it.
    #[cfg(unix)]
    {
        let linked = scene.workspace.root.join("data").join("linked.xlsx");
        std::os::unix::fs::symlink(&workbook_path, &linked).unwrap();
        let refused = start(&scene, &tasks, "data/linked.xlsx").unwrap_err();
        assert_eq!(
            refused.code,
            FailureCode::CapabilityDenied,
            "{}",
            refused.message
        );
    }

    // A macro workbook is refused at the start, with its type, and starts no task.
    let mut macros = fixture_parts("written-by-openpyxl");
    macros.push(("xl/vbaProject.bin".into(), b"not really".to_vec()));
    std::fs::write(&workbook_path, stored_zip(macros)).unwrap();
    let refused = start(&scene, &tasks, "data/sales.xlsx").unwrap_err();
    assert!(
        refused.message.contains("active_content"),
        "{}",
        refused.message
    );
    let _ = std::fs::remove_dir_all(
        std::env::temp_dir().join(format!("orceld-f5-workbook-bin-{}", std::process::id())),
    );
}
