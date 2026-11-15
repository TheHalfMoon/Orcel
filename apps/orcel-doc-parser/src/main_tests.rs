//! The fixture corpus through `convert`, in process: the normal PDF and
//! DOCX convert, every hostile input fails closed with its typed refusal.
use super::*;
use crate::fixtures;
use orcel_provider_process::document_parser::MAX_PAGES;

fn refusal(bytes: &[u8]) -> ParseRefusal {
    convert(bytes).expect_err("must fail closed")
}

#[test]
fn the_normal_pdf_converts_to_markdown() {
    let document = convert(&fixtures::text_pdf()).expect("normal PDF");
    assert_eq!(document.format, DocumentFormat::Pdf);
    assert_eq!(document.pages, 1);
    assert!(!document.truncated);
    assert!(
        document.markdown.contains("Orcel WI-05 fixture"),
        "{}",
        document.markdown
    );
    assert!(
        document.markdown.contains("quick brown fox"),
        "{}",
        document.markdown
    );
    assert_eq!(document.chars, document.markdown.chars().count());
}

#[test]
fn the_normal_docx_converts_with_its_header() {
    let document = convert(&fixtures::docx()).expect("normal DOCX");
    assert_eq!(document.format, DocumentFormat::Docx);
    assert!(
        document.markdown.contains("Orcel WI-05 office fixture"),
        "{}",
        document.markdown
    );
    assert!(
        document.markdown.contains("Second paragraph"),
        "{}",
        document.markdown
    );
    assert!(
        document.markdown.contains("Running header text"),
        "{}",
        document.markdown
    );
    // The external hyperlink relationship is never resolved or fetched.
    assert!(
        !document.markdown.contains("never-fetched"),
        "{}",
        document.markdown
    );
}

#[test]
fn hostile_pdfs_fail_closed_with_their_type() {
    assert_eq!(refusal(&fixtures::malformed_pdf()), ParseRefusal::Malformed);
    assert_eq!(refusal(&fixtures::encrypted_pdf()), ParseRefusal::Encrypted);
    assert_eq!(
        refusal(&fixtures::javascript_pdf()),
        ParseRefusal::ActiveContent
    );
    assert_eq!(
        refusal(&fixtures::launch_pdf()),
        ParseRefusal::ActiveContent
    );
    assert_eq!(
        refusal(&fixtures::pages_pdf(MAX_PAGES + 1)),
        ParseRefusal::TooManyPages
    );
    assert_eq!(
        refusal(&fixtures::nested_pdf(40)),
        ParseRefusal::NestingTooDeep
    );
    assert_eq!(refusal(&fixtures::blank_pdf()), ParseRefusal::NoText);
    assert_eq!(
        refusal(&fixtures::flate_bomb_pdf()),
        ParseRefusal::ArchiveLimit
    );
    assert_eq!(
        refusal(&fixtures::struct_name_bomb_pdf()),
        ParseRefusal::ArchiveLimit
    );
    assert_eq!(
        refusal(&fixtures::shifted_header_pdf()),
        ParseRefusal::Malformed
    );
    assert_eq!(refusal(&fixtures::short_xref_pdf()), ParseRefusal::NoText);
}

#[test]
fn bounds_admit_what_is_just_inside_them() {
    assert!(convert(&fixtures::nested_pdf(20)).is_ok());
    // MAX_PAGES blank pages pass the page bound and then have no text.
    assert_eq!(
        refusal(&fixtures::pages_pdf(MAX_PAGES)),
        ParseRefusal::NoText
    );
}

#[test]
fn hostile_office_files_fail_closed_with_their_type() {
    assert_eq!(
        refusal(&fixtures::zip_bomb_docx()),
        ParseRefusal::ArchiveLimit
    );
    assert_eq!(
        refusal(&fixtures::spread_bomb_docx()),
        ParseRefusal::ArchiveLimit
    );
    assert_eq!(
        refusal(&fixtures::macro_docx()),
        ParseRefusal::ActiveContent
    );
    assert_eq!(
        refusal(&fixtures::renamed_macro_docx()),
        ParseRefusal::ActiveContent
    );
    assert_eq!(
        refusal(&fixtures::renamed_slides_pptx(MAX_PAGES + 1)),
        ParseRefusal::TooManyPages
    );
    assert_eq!(
        refusal(&fixtures::nested_docx(200)),
        ParseRefusal::NestingTooDeep
    );
    assert_eq!(refusal(&fixtures::dtd_docx()), ParseRefusal::Malformed);
    assert_eq!(
        refusal(&fixtures::pptx(MAX_PAGES + 1)),
        ParseRefusal::TooManyPages
    );
    assert_eq!(
        refusal(&fixtures::encrypted_office()),
        ParseRefusal::Encrypted
    );
    assert_eq!(
        refusal(&fixtures::legacy_office()),
        ParseRefusal::UnsupportedFormat
    );
    assert_eq!(
        refusal(b"PK\x03\x04 not really a zip"),
        ParseRefusal::Malformed
    );
}

#[test]
fn other_content_is_unsupported_whatever_its_name() {
    for bytes in [&b"plain text"[..], b"{\rtf1 hello}", b"\x7fELF", b""] {
        assert_eq!(refusal(bytes), ParseRefusal::UnsupportedFormat);
    }
}

#[test]
fn markdown_past_the_character_bound_is_cut_and_flagged() {
    let document = convert(&fixtures::long_docx(MAX_CHARS + 10_000)).expect("long DOCX");
    assert!(document.truncated);
    assert_eq!(document.chars, MAX_CHARS);
    assert_eq!(document.markdown.chars().count(), MAX_CHARS);
}

#[test]
fn bound_chars_cuts_on_a_character_boundary() {
    let (text, truncated) = bound_chars("é".repeat(MAX_CHARS + 1));
    assert!(truncated);
    assert_eq!(text.chars().count(), MAX_CHARS);
    let (text, truncated) = bound_chars("short".into());
    assert!(!truncated);
    assert_eq!(text, "short");
}

/// SG-000130 W1: with an expected format, anything else is refused by the sniff, before
/// any parse. Where the parse would have said something else, that shows the sniff
/// decided, not the converter.
#[test]
fn an_expected_workbook_refuses_any_other_format_before_any_parse() {
    let xlsx = DocumentFormat::Xlsx;
    let workbook = convert_expecting(&fixtures::workbook(), xlsx).expect("a workbook");
    assert_eq!(workbook.format, xlsx);
    for name in [
        "written-by-xlsxwriter",
        "written-by-openpyxl",
        "excel-12-sample",
        "excel-12-with-various-data",
    ] {
        assert_eq!(sniff(&fixtures::unpacked(name), xlsx), Ok(()), "{name}");
    }

    // A PDF, even one its parse would call malformed.
    assert_eq!(refusal(&fixtures::malformed_pdf()), ParseRefusal::Malformed);
    for pdf in [fixtures::text_pdf(), fixtures::malformed_pdf()] {
        assert_eq!(sniff(&pdf, xlsx), Err(ParseRefusal::UnsupportedFormat));
        assert_eq!(
            convert_expecting(&pdf, xlsx),
            Err(ParseRefusal::UnsupportedFormat)
        );
    }
    // A zip that isn't a workbook: a document (one the pre-flight would call malformed
    // too), a deck, and a zip that is no package at all.
    assert_eq!(refusal(&fixtures::dtd_docx()), ParseRefusal::Malformed);
    for other in [
        fixtures::docx(),
        fixtures::dtd_docx(),
        fixtures::pptx(1),
        fixtures::zip(&[("notes.txt", b"Sales!B2 = 1".to_vec())]),
    ] {
        assert_eq!(sniff(&other, xlsx), Err(ParseRefusal::UnsupportedFormat));
    }
    // A macro-enabled workbook: by its macro part, and by its main part's type.
    let mut with_macros = fixtures::unpacked_parts("written-by-openpyxl");
    with_macros.push(("xl/vbaProject.bin".into(), b"not really".to_vec()));
    let with_macros = fixtures::zip_parts(&with_macros);
    assert_eq!(sniff(&with_macros, xlsx), Err(ParseRefusal::ActiveContent));
    let xlsm = fixtures::binary_workbook("application/vnd.ms-excel.sheet.macroEnabled.main+xml");
    assert_eq!(sniff(&xlsm, xlsx), Err(ParseRefusal::ActiveContent));
    // A template isn't the workbook either.
    let template = fixtures::binary_workbook(
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml",
    );
    assert_eq!(sniff(&template, xlsx), Err(ParseRefusal::UnsupportedFormat));
    // An .xls renamed .xlsx (an OLE file), and an encrypted package.
    assert_eq!(
        sniff(&fixtures::legacy_office(), xlsx),
        Err(ParseRefusal::UnsupportedFormat)
    );
    assert_eq!(
        sniff(&fixtures::encrypted_office(), xlsx),
        Err(ParseRefusal::Encrypted)
    );
    // Nothing else, the test triggers included.
    for other in [
        &b"plain text"[..],
        b"",
        fixtures::ABORT_TRIGGER,
        fixtures::UNCHECKED_TRIGGER,
    ] {
        assert_eq!(sniff(other, xlsx), Err(ParseRefusal::UnsupportedFormat));
    }
    // Two main parts, one of them not the workbook's.
    let both = fixtures::binary_workbook(
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>\
         <Override PartName=\"/word/document.xml\" \
         ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    );
    assert_eq!(sniff(&both, xlsx), Err(ParseRefusal::UnsupportedFormat));

    // The other expectations sniff their own formats.
    assert_eq!(sniff(&fixtures::text_pdf(), DocumentFormat::Pdf), Ok(()));
    assert_eq!(
        sniff(&fixtures::workbook(), DocumentFormat::Pdf),
        Err(ParseRefusal::UnsupportedFormat)
    );
    assert_eq!(sniff(&fixtures::docx(), DocumentFormat::Docx), Ok(()));
    assert_eq!(
        sniff(&fixtures::workbook(), DocumentFormat::Docx),
        Err(ParseRefusal::UnsupportedFormat)
    );
}

#[test]
fn the_arguments_are_the_input_or_an_expected_format_and_the_input() {
    let args = |list: &[&str]| -> Vec<std::ffi::OsString> {
        list.iter().map(std::ffi::OsString::from).collect()
    };
    assert_eq!(arguments(args(&["in"])), Ok((None, "in".into())));
    assert_eq!(
        arguments(args(&["--expect", "xlsx", "in"])),
        Ok((Some(DocumentFormat::Xlsx), "in".into()))
    );
    for wrong in [
        &[][..],
        &["a", "b"],
        &["--expect", "xlsm", "in"],
        &["--expect", "XLSX", "in"],
        &["--expected", "xlsx", "in"],
        &["in", "--expect", "xlsx"],
        &["--expect", "xlsx", "in", "more"],
    ] {
        assert_eq!(
            arguments(args(wrong)),
            Err(ParseRefusal::Usage),
            "{wrong:?}"
        );
    }
}
