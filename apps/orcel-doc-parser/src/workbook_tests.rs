use super::*;
use crate::convert as convert_document;
use crate::fixtures;
use orcel_provider_process::document_parser::DocumentFormat;

fn refusal(bytes: &[u8]) -> ParseRefusal {
    convert_document(bytes).expect_err("must fail closed")
}

fn rows_of(markdown: &str) -> Vec<&str> {
    markdown
        .lines()
        .filter(|line| line.starts_with("| ") && !line.starts_with("| Cell "))
        .collect()
}

#[test]
fn known_cells_formula_values_and_currency_totals_carry_their_references() {
    let document = convert_document(&fixtures::workbook()).expect("workbook");
    assert_eq!(document.format, DocumentFormat::Xlsx);
    assert_eq!(document.pages, 2);
    assert!(!document.truncated);
    let markdown = &document.markdown;
    for row in [
        "| A1 | Region | text |  |  |  |",
        "| B2 | 1250.50 | number | \"$\"#,##0.00 |  |  |",
        "| B3 | 749.25 | number | \"$\"#,##0.00 |  |  |",
        "| B4 | 1999.75 | number | \"$\"#,##0.00 | =SUM(B2:B3) |  |",
        "| C2 | 0.5 | number | builtin 9 | =B2/B4 |  |",
        "| C3 | 0.25 | number | builtin 9 | shared with C2 |  |",
        "| D2 | Bold words | text |  |  |  |",
        "| D3 | inline | text |  |  |  |",
        "| E2 | TRUE | boolean |  |  |  |",
        "| E3 | #DIV/0! | error |  | =1/0 |  |",
    ] {
        assert!(markdown.contains(row), "{row} not in\n{markdown}");
    }
    assert!(markdown.contains("## Sheet: Sales"), "{markdown}");
    assert!(markdown.contains("## Sheet: Audit (hidden)"), "{markdown}");
    assert!(
        markdown.contains("Sheets (2):\n- Sales\n- Audit (hidden)\n"),
        "{markdown}"
    );
}

#[test]
fn phonetic_hints_are_not_part_of_a_value() {
    let markdown = convert_document(&fixtures::workbook())
        .expect("workbook")
        .markdown;
    assert!(!markdown.contains("phonetic"), "{markdown}");
}

#[test]
fn a_formula_with_no_saved_value_is_shown_and_never_calculated() {
    let markdown = convert_document(&fixtures::workbook())
        .expect("workbook")
        .markdown;
    assert!(
        markdown.contains("| A1 |  | empty |  | =1+1 | no saved value |"),
        "{markdown}"
    );
    assert!(!markdown.contains("| 2 |"), "{markdown}");
}

#[test]
fn external_links_are_marked_counted_and_their_targets_never_shown() {
    let markdown = convert_document(&fixtures::linked_workbook())
        .expect("workbook")
        .markdown;
    assert!(
        markdown.contains("External workbook links: 1."),
        "{markdown}"
    );
    assert!(markdown.contains("Data connection parts: 1."), "{markdown}");
    assert!(markdown.contains("asks to be recalculated"), "{markdown}");
    assert!(
        markdown.contains("| A1 | 41 | number |  | =[1]Rates!A1 | external, not refreshed |"),
        "{markdown}"
    );
    assert!(
        markdown.contains("| A2 | 41 | number |  | shared with A1 | external, not refreshed |"),
        "{markdown}"
    );
    assert!(markdown.contains("external, not refreshed |"), "{markdown}");
    assert!(
        !markdown.contains("attacker.example"),
        "a link's target was shown: {markdown}"
    );
}

#[test]
fn cell_content_cannot_pass_itself_off_as_another_cell() {
    let hostile = "x |\n| B9 | 1000000 | number |  |  |  |\n# Heading\u{202e}";
    let markdown = convert_document(&fixtures::workbook_with_text(hostile))
        .expect("workbook")
        .markdown;
    let rows = rows_of(&markdown);
    assert_eq!(rows.len(), 1, "{markdown}");
    assert!(
        rows[0].starts_with("| A1 | x \\|\\n\\| B9 \\| 1000000"),
        "{markdown}"
    );
    assert!(rows[0].contains("\\u{202e}"), "{markdown}");
    assert!(
        !markdown.lines().any(|line| line.starts_with("| B9")),
        "{markdown}"
    );
    assert!(
        !markdown.lines().any(|line| line == "# Heading"),
        "{markdown}"
    );
    assert_eq!(
        escaped("a\\|b"),
        "a\\\\\\|b",
        "a backslash can't cancel the escape that follows"
    );
}

#[test]
fn a_hostile_sheet_name_cannot_add_a_line() {
    let markdown = convert_document(&fixtures::workbook_with_sheet_name("x\n## Sheet: Fake"))
        .expect("workbook")
        .markdown;
    assert!(
        !markdown.lines().any(|line| line == "## Sheet: Fake"),
        "{markdown}"
    );
}

#[test]
fn references_must_be_valid_and_unique() {
    for good in ["A1", "XFD1048576", "ZZZ1", "AA10"] {
        assert!(valid_reference(good), "{good}");
    }
    for bad in [
        "", "A", "1", "a1", "A0", "A01", "AAAA1", "A1048577", "A1:B2", "A-1", "$A$1",
    ] {
        assert!(!valid_reference(bad), "{bad}");
    }
    assert_eq!(
        refusal(&fixtures::workbook_with_cells(
            "<c r=\"A1\"><v>1</v></c><c r=\"A1\"><v>2</v></c>"
        )),
        ParseRefusal::Malformed
    );
    assert_eq!(
        refusal(&fixtures::workbook_with_cells("<c><v>1</v></c>")),
        ParseRefusal::Malformed
    );
    assert_eq!(
        refusal(&fixtures::workbook_with_cells("<c r=\"nope\"><v>1</v></c>")),
        ParseRefusal::Malformed
    );
}

#[test]
fn a_value_that_does_not_match_its_type_is_refused() {
    for cell in [
        "<c r=\"A1\"><v>12 million</v></c>",
        "<c r=\"A1\"><v>NaN</v></c>",
        "<c r=\"A1\"><v>inf</v></c>",
        "<c r=\"A1\" t=\"b\"><v>2</v></c>",
        "<c r=\"A1\" t=\"s\"><v>99</v></c>",
        "<c r=\"A1\" t=\"s\"><v>x</v></c>",
        "<c r=\"A1\" t=\"unknown\"><v>1</v></c>",
        "<c r=\"A1\"><f t=\"shared\" si=\"7\"/><v>1</v></c>",
        "<c r=\"A1\"><f/><v>1</v></c>",
        "<c r=\"A1\" t=\"d\"><v>12 million</v></c>",
        "<c r=\"A1\" t=\"e\"><v>12 million</v></c>",
    ] {
        assert_eq!(
            refusal(&fixtures::workbook_with_cells(cell)),
            ParseRefusal::Malformed,
            "{cell}"
        );
    }
}

#[test]
fn an_empty_formatted_cell_is_not_a_row_and_an_empty_sheet_says_so() {
    let markdown = convert_document(&fixtures::workbook_with_cells("<c r=\"A1\" s=\"1\"/>"))
        .expect("workbook")
        .markdown;
    assert!(markdown.contains("No cells with content."), "{markdown}");
}

#[test]
fn a_binary_workbook_is_refused() {
    // A real XLSB declares a macro-enabled main part, so the pre-flight stops it.
    assert_eq!(
        refusal(&fixtures::binary_workbook(
            "application/vnd.ms-excel.sheet.binary.macroEnabled.main"
        )),
        ParseRefusal::ActiveContent
    );
    assert_eq!(
        refusal(&fixtures::binary_workbook("application/octet-stream")),
        ParseRefusal::UnsupportedFormat
    );
}

#[test]
fn excel_4_macro_sheets_are_active_content_however_they_are_declared() {
    for bytes in [
        fixtures::macrosheet_workbook_by_part(),
        fixtures::macrosheet_workbook_by_type(),
        fixtures::macrosheet_workbook_by_relationship(),
    ] {
        assert_eq!(refusal(&bytes), ParseRefusal::ActiveContent);
    }
}

#[test]
fn a_part_with_too_many_nodes_is_an_archive_limit_not_a_memory_kill() {
    let cells = "<x/>".repeat(MAX_PART_NODES as usize + 1);
    assert_eq!(
        parse(&format!("<a>{cells}</a>")).map(|_| ()),
        Err(ParseRefusal::ArchiveLimit)
    );
}

#[test]
fn more_cells_than_the_frame_can_carry_are_cut_and_flagged() {
    // Text that doesn't compress, so the archive's inflation bound stays out of it.
    let mut seed = 0x9e37_79b9_u32;
    let mut letter = move || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        char::from(b'a' + (seed % 26) as u8)
    };
    let text: String = (0..MAX_CHARS + 1_000).map(|_| letter()).collect();
    let cells = format!("<c r=\"A1\" t=\"inlineStr\"><is><t>{text}</t></is></c>");
    let document = convert_document(&fixtures::workbook_with_cells(&cells)).expect("workbook");
    assert!(document.truncated);
    assert_eq!(document.chars, MAX_CHARS);
}

#[test]
fn the_formulas_that_may_reach_outside_are_recognised() {
    for formula in [
        "[1]Rates!A1",
        "'[12]My Rates'!A1",
        "[1]!Name",
        "[Book.xlsx]S!A1",
        "'a\"b'!A1+[1]Rates!A1",
        "INDIRECT(\"[1]R!A1\")",
        "\"[1]x!a|b\"&A1",
        "cmd|'/c calc'!A1",
        "WEBSERVICE(\"http://x\")",
        "WEBSERVICE (\"http://x\")",
        "rtd (\"a\",,\"b\")",
        "CUBEVALUE(\"c\")",
        "_xlfn.STOCKHISTORY(\"A\",1)",
    ] {
        assert!(is_external_formula(formula), "{formula}");
    }
    for formula in [
        "SUM(A1:A2)",
        "Table1[2020]",
        "Sheet2!Table1[x]",
        "Sheet2!A1",
    ] {
        assert!(!is_external_formula(formula), "{formula}");
    }
}

#[test]
fn a_comment_does_not_cut_a_value_a_string_or_a_formula_short() {
    let markdown = convert_document(&fixtures::workbook_with_cells(
        "<c r=\"A1\"><v>1<!-- -->000000</v></c>\
         <c r=\"B1\" t=\"inlineStr\"><is><t>Paid<!-- --> in full NOT</t></is></c>\
         <c r=\"C1\"><f>SUM(1)<!-- -->+[1]Rates!A1</f><v>1</v></c>",
    ))
    .expect("workbook")
    .markdown;
    assert!(markdown.contains("| A1 | 1000000 | number |"), "{markdown}");
    assert!(
        markdown.contains("| B1 | Paid in full NOT | text |"),
        "{markdown}"
    );
    assert!(
        markdown.contains("| C1 | 1 | number |  | =SUM(1)+[1]Rates!A1 | external, not refreshed |"),
        "{markdown}"
    );
}

#[test]
fn an_element_inside_a_value_is_refused() {
    assert_eq!(
        refusal(&fixtures::workbook_with_cells(
            "<c r=\"A1\"><v>1<v>2</v></v></c>"
        )),
        ParseRefusal::Malformed
    );
}

#[test]
fn elements_in_another_namespace_are_not_cells_or_values() {
    let ignorable = "xmlns:x=\"urn:x\" xmlns:mc=\"http://schemas.openxmlformats.org/markup-compatibility/2006\" mc:Ignorable=\"x\"";
    let foreign_value = fixtures::worksheet_xml(
        ignorable,
        "<sheetData><row r=\"1\"><c r=\"A1\"><x:v>999</x:v><v>1</v></c></row></sheetData>",
    );
    // Not a known child of a cell, so it can't be silently preferred or ignored.
    assert_eq!(
        refusal(&fixtures::workbook_with_sheet_xml(&foreign_value)),
        ParseRefusal::Malformed
    );
    let foreign_cell = fixtures::worksheet_xml(
        ignorable,
        "<sheetData><row r=\"1\"><x:c r=\"Z9\"><x:v>9</x:v></x:c></row></sheetData>",
    );
    assert_eq!(
        refusal(&fixtures::workbook_with_sheet_xml(&foreign_cell)),
        ParseRefusal::Malformed
    );
}

#[test]
fn a_sheet_id_under_a_foreign_prefix_does_not_choose_the_part() {
    let markdown = convert_document(&fixtures::workbook_with_foreign_sheet_id())
        .expect("workbook")
        .markdown;
    assert!(markdown.contains("| A1 | 111 | number |"), "{markdown}");
    assert!(!markdown.contains("999"), "{markdown}");
}

#[test]
fn cells_anywhere_but_their_place_are_refused_not_skipped() {
    for data in [
        "",
        "<sheetData/><sheetData/>",
        "<sheetData><c r=\"A1\"><v>1</v></c></sheetData>",
        "<sheetData><row r=\"1\"><mc:AlternateContent xmlns:mc=\"urn:mc\"><c r=\"A1\"><v>1</v></c></mc:AlternateContent></row></sheetData>",
        "<sheetData><mc:AlternateContent xmlns:mc=\"urn:mc\"/></sheetData>",
        "<sheetData><row r=\"1\"><c r=\"A1\"><v>1</v><v>2</v></c></row></sheetData>",
        "<sheetData><row r=\"1\"><c r=\"A1\"><f>1</f><f>2</f></c></row></sheetData>",
        "<sheetData><row r=\"1\"><c r=\"A1\"><is><t>x</t></is></c></row></sheetData>",
        "<sheetData><row r=\"1\"><c r=\"A1\" t=\"inlineStr\"><v>1</v></c></row></sheetData>",
        "<sheetData><row r=\"2\"><c r=\"A3\"><v>1</v></c></row></sheetData>",
    ] {
        let xml = fixtures::worksheet_xml("", data);
        assert_eq!(
            refusal(&fixtures::workbook_with_sheet_xml(&xml)),
            ParseRefusal::Malformed,
            "{data}"
        );
    }
    assert_eq!(
        refusal(&fixtures::workbook_with_sheet_xml("<notasheet/>")),
        ParseRefusal::Malformed
    );
}

#[test]
fn an_extension_list_holds_no_cells_and_is_allowed() {
    let xml = fixtures::worksheet_xml(
        "",
        "<sheetData><row r=\"1\"><c r=\"A1\"><v>1</v><extLst/></c></row></sheetData><extLst/>",
    );
    let markdown = convert_document(&fixtures::workbook_with_sheet_xml(&xml))
        .expect("workbook")
        .markdown;
    assert!(markdown.contains("| A1 | 1 | number |"), "{markdown}");
}

#[test]
fn a_reused_shared_index_belongs_to_the_latest_formula_before_it() {
    let xml = fixtures::worksheet_xml(
        "",
        "<sheetData>\
         <row r=\"1\"><c r=\"A1\"><f t=\"shared\" si=\"0\">B1</f><v>1</v></c></row>\
         <row r=\"2\"><c r=\"A2\"><f t=\"shared\" si=\"0\">[1]R!A1</f><v>2</v></c></row>\
         <row r=\"3\"><c r=\"A3\"><f t=\"shared\" si=\"0\"/><v>3</v></c></row>\
         </sheetData>",
    );
    let markdown = convert_document(&fixtures::workbook_with_sheet_xml(&xml))
        .expect("workbook")
        .markdown;
    assert!(
        markdown.contains("| A3 | 3 | number |  | shared with A2 | external, not refreshed |"),
        "{markdown}"
    );
}

#[test]
fn every_stale_source_is_declared() {
    let markdown = convert_document(&fixtures::workbook_with_stale_sources())
        .expect("workbook")
        .markdown;
    for notice in [
        "Defined names that may reach outside: 1.",
        "Pivot caches: 1.",
        "Query tables: 1.",
        "calculates manually",
    ] {
        assert!(markdown.contains(notice), "{notice} not in\n{markdown}");
    }
}

#[test]
fn valid_shapes_are_read_not_refused() {
    let document = convert_document(&fixtures::workbook_with_chart_sheet()).expect("chart sheet");
    assert_eq!(document.pages, 2);
    assert!(
        document.markdown.contains("- Chart (no cells)"),
        "{}",
        document.markdown
    );
    assert!(
        !document.markdown.contains("## Sheet: Chart"),
        "{}",
        document.markdown
    );

    let document = convert_document(&fixtures::workbook_with_cells(
        "<c r=\"A1\"><f t=\"dataTable\" ref=\"A1:A2\" r1=\"B1\"/><v>5</v></c>",
    ))
    .expect("data table");
    assert!(
        document
            .markdown
            .contains("| A1 | 5 | number |  | data table |"),
        "{}",
        document.markdown
    );

    let document = convert_document(&fixtures::workbook_with_many_sheets(300)).expect("300 sheets");
    assert_eq!(document.pages, 300);
    assert!(
        document.markdown.contains("## Sheet: S300"),
        "{}",
        document.markdown
    );
}

#[test]
fn a_sheet_name_can_be_ambiguous_with_no_other() {
    assert_eq!(
        refusal(&fixtures::workbook_with_duplicate_sheet_names()),
        ParseRefusal::Malformed
    );
    let markdown = convert_document(&fixtures::workbook_with_sheet_name("Real, Audit"))
        .expect("workbook")
        .markdown;
    assert!(markdown.contains("\n- Real, Audit\n"), "{markdown}");
}

#[test]
fn marks_that_reorder_text_are_shown_as_codes() {
    assert_eq!(escaped("a\u{200f}b\u{061c}"), "a\\u{200f}b\\u{61c}");
}

#[test]
fn a_workbook_with_no_usable_sheet_is_refused() {
    assert_eq!(
        refusal(&fixtures::workbook_without_sheets()),
        ParseRefusal::Malformed
    );
    assert_eq!(
        refusal(&fixtures::workbook_with_external_sheet()),
        ParseRefusal::Malformed
    );
    assert_eq!(
        refusal(&fixtures::workbook_missing_sheet_part()),
        ParseRefusal::Malformed
    );
    // The pre-flight stops a DTD first, so ask this reader directly.
    assert_eq!(
        convert(&fixtures::workbook_with_dtd_sheet()).map(|_| ()),
        Err(ParseRefusal::Malformed)
    );
}

#[test]
fn too_many_attributes_are_an_archive_limit_before_the_xml_parser() {
    let attributes: String = (0..=MAX_ELEMENT_ATTRIBUTES)
        .map(|n| format!(" a{n}=\"1\""))
        .collect();
    assert_eq!(
        check_attributes(&format!("<a{attributes}/>")),
        Err(ParseRefusal::ArchiveLimit)
    );
    let fine: String = (0..MAX_ELEMENT_ATTRIBUTES)
        .map(|n| format!(" a{n}=\"=>'\""))
        .collect();
    assert_eq!(check_attributes(&format!("<a{fine}/>")), Ok(()));
    assert_eq!(check_attributes("<a>====== text ======</a>"), Ok(()));
    let many = "<a x=\"1\" y=\"2\" z=\"3\" w=\"4\"/>".repeat(MAX_PART_ATTRIBUTES / 4 + 1);
    assert_eq!(check_attributes(&many), Err(ParseRefusal::ArchiveLimit));
}

/// Text that doesn't compress, so the archive's inflation bound stays out of it.
fn random_text(length: usize) -> String {
    let mut seed = 0x9e37_79b9_u32;
    (0..length)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            char::from(b'a' + (seed % 26) as u8)
        })
        .collect()
}

#[test]
fn a_full_frame_stops_reading_the_next_sheet() {
    let text = random_text(MAX_CHARS + 1_000);
    let cells = format!("<c r=\"A1\" t=\"inlineStr\"><is><t>{text}</t></is></c>");
    // The second sheet would be refused if it were read.
    let document = convert_document(&fixtures::workbook_with_two_sheets(&cells, "<notasheet/>"))
        .expect("workbook");
    assert!(document.truncated);
}

#[test]
fn a_row_past_what_the_frame_can_carry_stops_the_sheet() {
    let text = random_text(MAX_CHARS * 4 + 1_000);
    // The second cell would be refused if it were read.
    let cells =
        format!("<c r=\"A1\" t=\"inlineStr\"><is><t>{text}</t></is></c><c r=\"nope\"><v>1</v></c>");
    let document = convert_document(&fixtures::workbook_with_cells(&cells)).expect("workbook");
    assert!(document.truncated);
}

#[test]
fn a_quote_in_a_comment_does_not_hide_a_flood_of_attributes() {
    let attributes: String = (0..=MAX_ELEMENT_ATTRIBUTES)
        .map(|n| format!(" a{n}=\"1\""))
        .collect();
    for prefix in ["<!-- ' -->", "<![CDATA[ ' ]]>", "<? ' ?>"] {
        assert_eq!(
            check_attributes(&format!("{prefix}<a{attributes}/>")),
            Err(ParseRefusal::ArchiveLimit),
            "{prefix}"
        );
    }
    // An unterminated comment is left for the parser to refuse.
    assert_eq!(check_attributes("<a/><!-- '"), Ok(()));
    assert_eq!(
        parse("<a/><!-- '").map(|_| ()),
        Err(ParseRefusal::Malformed)
    );
}

const CONTENT: &str = "<sheets><sheet name=\"S\" sheetId=\"1\" r:id=\"rId1\"/></sheets>";

#[test]
fn a_string_in_alternate_content_is_refused() {
    let hidden =
        "<mc:AlternateContent><si><t>Paid</t></si></mc:AlternateContent><si><t>Unpaid</t></si>";
    assert_eq!(
        refusal(&fixtures::workbook_with_parts(CONTENT, hidden)),
        ParseRefusal::Malformed
    );
    let inside = "<si><mc:AlternateContent><t>Paid</t></mc:AlternateContent><t>Unpaid</t></si>";
    assert_eq!(
        refusal(&fixtures::workbook_with_parts(CONTENT, inside)),
        ParseRefusal::Malformed
    );
}

#[test]
fn workbook_structure_in_alternate_content_is_refused() {
    for body in [
        "<mc:AlternateContent><sheets><sheet name=\"H\" sheetId=\"2\" r:id=\"rId1\"/></sheets></mc:AlternateContent>",
        "<sheets><sheet name=\"S\" sheetId=\"1\" r:id=\"rId1\"/><mc:AlternateContent><sheet name=\"H\" sheetId=\"2\" r:id=\"rId1\"/></mc:AlternateContent></sheets>",
    ] {
        assert_eq!(
            refusal(&fixtures::workbook_with_parts(body, "<si><t>x</t></si>")),
            ParseRefusal::Malformed,
            "{body}"
        );
    }
    let calculation = format!(
        "{CONTENT}<mc:AlternateContent><calcPr calcMode=\"manual\"/></mc:AlternateContent>"
    );
    assert_eq!(
        refusal(&fixtures::workbook_with_parts(
            &calculation,
            "<si><t>x</t></si>"
        )),
        ParseRefusal::Malformed
    );
}

#[test]
fn cells_in_a_wrapper_outside_sheet_data_are_refused() {
    for data in [
        "<sheetData/><mc:AlternateContent xmlns:mc=\"urn:mc\"><sheetData><row r=\"1\"><c r=\"A1\"><v>1</v></c></row></sheetData></mc:AlternateContent>",
        "<sheetData/><mc:AlternateContent xmlns:mc=\"urn:mc\"><c r=\"A1\"><v>1</v></c></mc:AlternateContent>",
        "<sheetData/><wrap xmlns=\"urn:other\"><row xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"/></wrap>",
    ] {
        let xml = fixtures::worksheet_xml("", data);
        assert_eq!(
            refusal(&fixtures::workbook_with_sheet_xml(&xml)),
            ParseRefusal::Malformed,
            "{data}"
        );
    }
}

/// The wrappers Excel writes for its own features hold none of what's read here.
#[test]
fn alternate_content_for_other_features_stays_readable() {
    let xml = fixtures::worksheet_xml(
        "",
        "<sheetData><row r=\"1\" spans=\"1:1\"><c r=\"A1\"><v>1</v></c></row></sheetData>\
         <mc:AlternateContent xmlns:mc=\"urn:mc\"><mc:Choice Requires=\"x14\"><controls/></mc:Choice></mc:AlternateContent>",
    );
    let markdown = convert_document(&fixtures::workbook_with_sheet_xml(&xml))
        .expect("workbook")
        .markdown;
    assert!(markdown.contains("| A1 | 1 | number |"), "{markdown}");

    let body = format!(
        "<mc:AlternateContent><mc:Choice Requires=\"x15\"><absPath xmlns=\"urn:x15\" url=\"C:\\\\\"/></mc:Choice></mc:AlternateContent>{CONTENT}"
    );
    let markdown = convert_document(&fixtures::workbook_with_parts(
        &body,
        "<si><t>kept</t></si>",
    ))
    .expect("workbook")
    .markdown;
    assert!(markdown.contains("| A1 | kept | text |"), "{markdown}");
}

#[test]
fn the_formats_character_escapes_are_decoded() {
    assert_eq!(decoded_xstring("_x0031__x0030_00"), "1000");
    assert_eq!(decoded_xstring("a_x000D_b"), "a\rb");
    assert_eq!(decoded_xstring("_x005F_x0031_"), "_x0031_");
    for unchanged in [
        "_x", "_x12", "_x123_", "_xZZZZ_", "_x00412", "_xD800_", "plain",
    ] {
        assert_eq!(decoded_xstring(unchanged), unchanged);
    }
    let markdown = convert_document(&fixtures::workbook_with_cells(
        "<c r=\"A1\" t=\"inlineStr\"><is><t>line_x000D_two</t></is></c>\
         <c r=\"B1\" t=\"str\"><f>A1</f><v>_x0031__x0030_0</v></c>\
         <c r=\"C1\"><f>_x005B_1_x005D_Rates!A1</f><v>1</v></c>",
    ))
    .expect("workbook")
    .markdown;
    // Decoded, then escaped, so it can't break the row.
    assert!(
        markdown.contains("| A1 | line\\rtwo | text |"),
        "{markdown}"
    );
    assert!(markdown.contains("| B1 | 100 | text |"), "{markdown}");
    assert!(
        markdown.contains("=[1]Rates!A1 | external, not refreshed |"),
        "an escaped link must not dodge the check: {markdown}"
    );
}

#[test]
fn a_number_must_be_written_as_one() {
    assert_eq!(
        refusal(&fixtures::workbook_with_cells(
            "<c r=\"A1\"><v>_x0031_</v></c>"
        )),
        ParseRefusal::Malformed
    );
}

#[test]
fn an_escape_cannot_span_two_runs_or_make_a_second_sheet_name() {
    let markdown = convert_document(&fixtures::workbook_with_cells(
        "<c r=\"A1\" t=\"inlineStr\"><is><r><t>_x00</t></r><r><t>31_000</t></r></is></c>",
    ))
    .expect("workbook")
    .markdown;
    assert!(
        markdown.contains("| A1 | _x0031_000 | text |"),
        "{markdown}"
    );

    let body = "<sheets><sheet name=\"Sales\" sheetId=\"1\" r:id=\"rId1\"/>\
                <sheet name=\"_x0053_ales\" sheetId=\"2\" r:id=\"rId1\"/></sheets>";
    assert_eq!(
        refusal(&fixtures::workbook_with_parts(body, "<si><t>x</t></si>")),
        ParseRefusal::Malformed
    );
}

#[test]
fn a_file_from_xlsxwriter_reads_with_its_references_values_and_formulas() {
    let document =
        convert_document(&fixtures::unpacked("written-by-xlsxwriter")).expect("XlsxWriter's file");
    assert_eq!(document.format, DocumentFormat::Xlsx);
    assert_eq!(document.pages, 2);
    let markdown = &document.markdown;
    for row in [
        "| A1 | Region | text |",
        "| A2 | North | text |",
        "| B2 | 1250.5 | number | \"$\"#,##0.00 |  |  |",
        "| B3 | 749.25 | number | \"$\"#,##0.00 |  |  |",
        "| B4 | 1999.75 | number | \"$\"#,##0.00 | =SUM(B2:B3) |  |",
        "| C2 | 0.625 | number | 0% | =B2/B4 |  |",
        "| D2 | Bold words | text |",
        "| E2 | TRUE | boolean |",
        "| E3 | #DIV/0! | error |  | =1/0 |  |",
        "| F2 | line one\\nline two | text |",
    ] {
        assert!(markdown.contains(row), "{row} not in\n{markdown}");
    }
    assert!(markdown.contains("## Sheet: Audit (hidden)"), "{markdown}");
    assert!(markdown.contains("| A1 | Reviewed | text |"), "{markdown}");
    assert!(
        !markdown.contains("A comment"),
        "comments aren't cells: {markdown}"
    );
}

#[test]
fn a_file_from_openpyxl_reads_and_shows_a_formula_has_no_saved_value() {
    let document =
        convert_document(&fixtures::unpacked("written-by-openpyxl")).expect("openpyxl's file");
    assert_eq!(document.format, DocumentFormat::Xlsx);
    assert_eq!(document.pages, 2);
    let markdown = &document.markdown;
    for row in [
        "| A1 | Region | text |",
        "| B2 | 1250.5 | number | \"$\"#,##0.00 |",
        "| B3 | 749.25 | number |",
        "| B4 |  | empty |  | =SUM(B2:B3) | no saved value |",
        "| D2 | TRUE | boolean |",
    ] {
        assert!(markdown.contains(row), "{row} not in\n{markdown}");
    }
    assert!(markdown.contains("## Sheet: Audit (hidden)"), "{markdown}");
}

#[test]
fn an_empty_value_is_no_saved_value_except_for_a_formulas_text() {
    let markdown = convert_document(&fixtures::workbook_with_cells(
        "<c r=\"A1\"><f>SUM(1)</f><v /></c>\
         <c r=\"B1\" t=\"str\"><f>\"\"</f><v></v></c>\
         <c r=\"C1\"><v> </v></c>\
         <c r=\"D1\" t=\"b\"><f>TRUE</f><v/></c>",
    ))
    .expect("workbook")
    .markdown;
    assert!(
        markdown.contains("| A1 |  | empty |  | =SUM(1) | no saved value |"),
        "{markdown}"
    );
    assert!(
        markdown.contains("| B1 |  | text |  | =\"\" |  |"),
        "{markdown}"
    );
    assert!(
        !markdown.contains("| C1 "),
        "an empty cell isn't a row: {markdown}"
    );
    assert!(
        markdown.contains("| D1 |  | empty |  | =TRUE | no saved value |"),
        "{markdown}"
    );
}

/// Saved by Microsoft Excel 12.0, by these files' own metadata (`WORKBOOKS.md`).
#[test]
fn files_saved_by_excel_read_with_their_references_values_and_formulas() {
    let document = convert_document(&fixtures::unpacked("excel-12-sample")).expect("Excel's file");
    assert_eq!(document.format, DocumentFormat::Xlsx);
    assert_eq!(document.pages, 3);
    for row in [
        "| A1 | Test spreadsheet | text |",
        "| A1 | Start of 2nd sheet | text |",
        "| B7 | 10 | number |",
        "| D7 | 13 | number |  | =SUM(A7:C7) |  |",
    ] {
        assert!(
            document.markdown.contains(row),
            "{row} not in\n{}",
            document.markdown
        );
    }
    assert!(
        document.markdown.contains("## Sheet: Sheet Number 2"),
        "{}",
        document.markdown
    );

    let document =
        convert_document(&fixtures::unpacked("excel-12-with-various-data")).expect("Excel's file");
    for row in [
        "| A2 | 22.3 | number |",
        "| B2 | Foo | text |",
        "| C4 | Link to http://poi.apache.org/ | text |",
        "| A7 | 42.5 | number |",
    ] {
        assert!(
            document.markdown.contains(row),
            "{row} not in\n{}",
            document.markdown
        );
    }
    assert!(
        !document.markdown.contains("| 13 |"),
        "{}",
        document.markdown
    );
    // Its comments, its header and its footer are in parts that aren't cells.
    assert!(
        document
            .markdown
            .contains("| C9 | We have a header | text |"),
        "a cell that merely says so: {}",
        document.markdown
    );
}

#[test]
fn a_missing_saved_value_is_not_zero() {
    let markdown = convert_document(&fixtures::workbook_with_cells(
        "<c r=\"A1\"><f>1-1</f><v>0</v></c><c r=\"B1\"><f>1-1</f></c>",
    ))
    .expect("workbook")
    .markdown;
    assert!(
        markdown.contains("| A1 | 0 | number |  | =1-1 |  |"),
        "{markdown}"
    );
    assert!(
        markdown.contains("| B1 |  | empty |  | =1-1 | no saved value |"),
        "{markdown}"
    );
}

#[test]
fn too_many_rows_or_cells_are_an_archive_limit() {
    let sheet =
        |data: String| fixtures::worksheet_xml("", &format!("<sheetData>{data}</sheetData>"));
    let rows = "<row/>".repeat(MAX_SHEET_ROWS + 1);
    assert_eq!(
        refusal(&fixtures::workbook_with_sheet_xml(&sheet(rows))),
        ParseRefusal::ArchiveLimit
    );
    let cells = format!("<row>{}</row>", "<c/>".repeat(MAX_WORKBOOK_CELLS + 1));
    assert_eq!(
        refusal(&fixtures::workbook_with_sheet_xml(&sheet(cells))),
        ParseRefusal::ArchiveLimit
    );
    // The limit on cells is across the workbook, not per sheet: this second sheet
    // is exactly at it, and the first sheet's one cell takes it past.
    let second = sheet(format!("<row>{}</row>", "<c/>".repeat(MAX_WORKBOOK_CELLS)));
    assert_eq!(
        refusal(&fixtures::workbook_with_two_sheets(
            "<c r=\"A1\"><v>1</v></c>",
            &second
        )),
        ParseRefusal::ArchiveLimit
    );
}
