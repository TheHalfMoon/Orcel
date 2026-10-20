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
