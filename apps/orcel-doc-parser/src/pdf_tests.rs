use super::*;
use lopdf::decode_budget::Scope;

/// Direct lopdf calls in these tests run under an open but unlimited decode
/// budget. Without one an unbounded decode is refused (P-02), and a decode
/// made while another test's scope is open would be charged to it; scopes
/// are serialised, so this also keeps the tests apart.
fn unlimited<T>(call: impl FnOnce() -> T) -> T {
    let _scope = Scope::enter(usize::MAX, usize::MAX);
    call()
}

/// `inspect_with_parity` under the decode budget `convert` gives it.
fn parity_only(
    bytes: &[u8],
    pages: usize,
) -> Result<pdf_inspector::PdfProcessResult, ParseRefusal> {
    within_budget(|| inspect_with_parity(bytes, pages))
}

#[test]
fn active_names_are_found_in_keys_and_values_at_any_depth() {
    let action =
        Object::Dictionary(lopdf::dictionary! { "S" => Object::Name(b"JavaScript".to_vec()) });
    assert_eq!(inspect(&action, 0), Err(ParseRefusal::ActiveContent));
    let keyed = Object::Dictionary(lopdf::dictionary! { "JS" => Object::Null });
    assert_eq!(
        inspect(&Object::Array(vec![keyed]), 0),
        Err(ParseRefusal::ActiveContent)
    );
    let plain = Object::Dictionary(lopdf::dictionary! { "Type" => Object::Name(b"Page".to_vec()) });
    assert_eq!(inspect(&plain, 0), Ok(()));
}

#[test]
fn nesting_is_bounded() {
    let mut object = Object::Null;
    for _ in 0..=MAX_NESTING {
        object = Object::Array(vec![object]);
    }
    assert_eq!(inspect(&object, 0), Err(ParseRefusal::NestingTooDeep));
    let Object::Array(mut inner) = object else {
        return;
    };
    assert_eq!(inspect(&inner.remove(0), 0), Ok(()));
}

#[test]
fn a_non_pdf_is_malformed() {
    assert_eq!(convert(b"%PDX-").map(|_| ()), Err(ParseRefusal::Malformed));
}

#[test]
fn the_hand_written_zlib_fixture_is_valid() {
    let stream = lopdf::Stream::new(
        lopdf::dictionary! { "Filter" => Object::Name(b"FlateDecode".to_vec()) },
        crate::fixtures::zlib_zeros(1 + 258 * 4),
    );
    assert_eq!(
        unlimited(|| stream.decompressed_content_with_limit(1 << 20)).unwrap(),
        vec![0; 1 + 258 * 4]
    );
}

/// The bare-name fixture really exercises the divergence: lopdf alone drops
/// the bomb XObject, and only the bytes pdf-inspector parses contain it.
#[test]
fn the_bomb_hidden_behind_a_bare_struct_name_is_found_in_the_bytes_inspector_reads() {
    let raw = crate::fixtures::struct_name_bomb_pdf();
    assert!(
        within_budget(|| preflight(&raw)).is_ok(),
        "lopdf on the raw bytes must not see the bomb, or the fixture tests nothing"
    );
    let rewritten = as_inspector_reads(&raw).unwrap();
    assert_ne!(rewritten, raw);
    assert_eq!(
        within_budget(|| preflight(&rewritten)),
        Err(ParseRefusal::ArchiveLimit)
    );
}

fn document_with_streams(streams: Vec<lopdf::Stream>) -> Document {
    let mut document = Document::with_version("1.7");
    for stream in streams {
        document.add_object(Object::Stream(stream));
    }
    document
}

fn flate(zeros: usize) -> lopdf::Stream {
    lopdf::Stream::new(
        lopdf::dictionary! { "Filter" => Object::Name(b"FlateDecode".to_vec()) },
        crate::fixtures::zlib_zeros(zeros),
    )
}

#[test]
fn the_total_budget_spans_every_stream() {
    let mib = 1 + 258 * 4_064; // 1,048,513 bytes each, just under 1 MiB
    let document = document_with_streams((0..4).map(|_| flate(mib)).collect());
    // Each stream fits the per-stream bound; four of them do not fit three.
    assert_eq!(
        unlimited(|| bound_stream_inflation_within(&document, 2 << 20, 3 << 20)),
        Err(ParseRefusal::ArchiveLimit)
    );
    assert_eq!(
        unlimited(|| bound_stream_inflation_within(&document, 2 << 20, 5 << 20)),
        Ok(())
    );
    // Each stream past a per-stream bound just below its size.
    assert_eq!(
        unlimited(|| bound_stream_inflation_within(&document, 1_048_512, 64 << 20)),
        Err(ParseRefusal::ArchiveLimit)
    );
}

#[test]
fn a_stream_lopdf_cannot_decode_is_charged_its_raw_length() {
    let image = lopdf::Stream::new(
        lopdf::dictionary! { "Filter" => Object::Name(b"DCTDecode".to_vec()) },
        vec![0xFF; 3 << 20],
    );
    let document = document_with_streams(vec![image]);
    assert_eq!(
        unlimited(|| bound_stream_inflation_within(&document, 64 << 20, 2 << 20)),
        Err(ParseRefusal::ArchiveLimit)
    );
    assert_eq!(
        unlimited(|| bound_stream_inflation_within(&document, 64 << 20, 4 << 20)),
        Ok(())
    );
}

/// Each input-changing path of pdf-inspector is observed, so a file that
/// would make it parse something other than what the pre-flight checked is
/// refused even if the pre-flight's own guards were bypassed. The header
/// strip and the bare-name rewrite are triggered for real here.
#[test]
fn parity_breaks_are_observed() {
    let text = crate::fixtures::text_pdf();
    assert!(parity_only(&text, 1).is_ok(), "the normal PDF");
    for (name, bytes) in [
        ("shifted header", crate::fixtures::shifted_header_pdf()),
        (
            "bare structure name",
            crate::fixtures::bare_struct_name_pdf(),
        ),
    ] {
        assert_eq!(
            parity_only(&bytes, 1).map(|_| ()),
            Err(ParseRefusal::Malformed),
            "{name}"
        );
    }
    // The page count must agree with the pre-flight's.
    assert_eq!(
        parity_only(&text, 2).map(|_| ()),
        Err(ParseRefusal::Malformed)
    );
}

/// pdf-inspector's container repair runs only after its load fails, and
/// lopdf 0.45 reconstructs the cross-reference table itself for every
/// corruption that repair targets (19-byte entries, a wrong or missing
/// `startxref`, a missing `%%EOF`, a damaged `xref` keyword). So the load
/// pdf-inspector repeats on the pre-flight's bytes cannot fail and the
/// repair cannot run. This pins that: each repair-shaped input loads
/// directly, pdf-inspector reports no repair, and the parse still ends in a
/// typed result. If a lopdf upgrade ever makes one of them fail to load, the
/// pre-flight refuses it as malformed before pdf-inspector runs, and this
/// test fails so the reasoning is revisited.
#[test]
fn repair_shaped_inputs_load_directly_and_never_take_the_repair_path() {
    let short = crate::fixtures::short_xref_pdf();
    let text = crate::fixtures::text_pdf();
    let at = text
        .windows(10)
        .rposition(|window| window == b"startxref\n")
        .unwrap();
    let mut wrong_pointer = text[..at + 10].to_vec();
    wrong_pointer.extend_from_slice(b"99999999\n%%EOF\n");
    let mut no_eof = text.clone();
    no_eof.truncate(text.len() - 6);
    let mut bad_keyword = text.clone();
    let xref = bad_keyword
        .windows(5)
        .position(|window| window == b"xref\n")
        .unwrap();
    bad_keyword[xref] = b'X';
    for (name, bytes, expected) in [
        ("short entries", short, Err(ParseRefusal::NoText)),
        ("wrong startxref", wrong_pointer, Ok(())),
        ("no %%EOF", no_eof, Ok(())),
        ("damaged xref keyword", bad_keyword, Ok(())),
    ] {
        let options = LoadOptions {
            max_decompressed_size: Some(INSPECTOR_LOAD_BOUND),
            ..LoadOptions::default()
        };
        assert!(
            unlimited(|| Document::load_mem_with_options(&bytes, options)).is_ok(),
            "{name}: lopdf no longer loads it directly"
        );
        assert!(parity_only(&bytes, 1).is_ok(), "{name}: parity");
        assert_eq!(convert(&bytes).map(|_| ()), expected, "{name}");
    }
}

/// The repair message itself, as pdf-inspector 1.21.0 writes it (lib.rs,
/// `load_document_from_mem_with_password`), is caught.
#[test]
fn the_repair_message_is_observed() {
    assert!(parity::watch());
    assert!(!parity::broken());
    log::debug!(target: "pdf_inspector", "loaded PDF after repairing malformed container bytes");
    assert!(parity::broken());
    // Other crates' records and other messages are ignored.
    assert!(parity::watch());
    log::debug!(target: "lopdf::reader", "loaded PDF after repairing malformed container bytes");
    log::debug!(target: "pdf_inspector", "TextBased PDF has garbage text");
    assert!(!parity::broken());
}

#[test]
fn only_a_canonical_header_at_the_first_byte_is_admitted() {
    assert!(has_canonical_header_at_start(b"%PDF-1.7\n"));
    assert!(has_canonical_header_at_start(b"%PDF-2.0\r\n"));
    for bytes in [
        &b"%PDF-x\n%PDF-1.7\n"[..],
        b"%PDF-1.7 trailing\n",
        b"%PDF-17\n",
        b" %PDF-1.7\n",
        b"\xEF\xBB\xBF%PDF-1.7\n",
    ] {
        assert!(!has_canonical_header_at_start(bytes), "{bytes:?}");
    }
}

#[test]
fn the_inflation_bound_is_wired_to_the_contract() {
    assert_eq!(
        stream_budget(),
        Ok((MAX_ARCHIVE_BYTES as usize, MAX_PDF_INFLATED_BYTES as usize))
    );
    assert_eq!(MAX_PDF_INFLATED_BYTES, 256 * 1024 * 1024);
}

#[test]
fn an_unplaced_member_of_two_object_streams_is_refused() {
    let once = crate::fixtures::object_stream_member_pdf(1);
    let document = unlimited(|| Document::load_mem(&once)).unwrap();
    assert!(
        document.objects.contains_key(&(9, 0)),
        "lopdf loads the member, or the fixture tests nothing"
    );
    assert_eq!(
        unlimited(|| refuse_ambiguous_object_stream_members(&document)),
        Ok(())
    );
    assert!(convert(&once).is_ok());

    let twice = crate::fixtures::object_stream_member_pdf(2);
    let document = unlimited(|| Document::load_mem(&twice)).unwrap();
    assert_eq!(
        unlimited(|| refuse_ambiguous_object_stream_members(&document)),
        Err(ParseRefusal::Malformed)
    );
    assert_eq!(convert(&twice).map(|_| ()), Err(ParseRefusal::Malformed));
}

/// The parity logger proves itself on every parse: its self-test record is
/// seen and then cleared, so it never reads as a parity break.
#[test]
fn the_parity_logger_proves_itself_before_each_parse() {
    assert!(parity::watch(), "the self-test record was not observed");
    assert!(!parity::broken(), "the self-test must not count as a break");
    assert!(parity_only(&crate::fixtures::text_pdf(), 1).is_ok());
}

// #391: the decode budget (vendored lopdf P-02) holds on its own terms.

fn spaces(len: usize) -> lopdf::Stream {
    lopdf::Stream::new(lopdf::Dictionary::new(), vec![b' '; len])
}

#[test]
fn every_decode_of_a_stream_is_charged_until_the_budget_runs_out() {
    let stream = flate(1 + 258 * 4); // 1,033 bytes
    let scope = Scope::enter(2_500, 1_100);
    assert!(stream.decompressed_content().is_ok());
    assert!(stream.decompressed_content().is_ok());
    assert!(!scope.exhausted());
    assert_eq!(scope.charged(), 2 * 1_033);
    assert!(stream.decompressed_content().is_err(), "434 bytes left");
    assert!(scope.exhausted());
    // Once exhausted, every decode is refused, even a bounded one.
    assert!(flate(1).decompressed_content_with_limit(10).is_err());
}

#[test]
fn one_decode_past_the_per_decode_cap_exhausts_the_budget() {
    let scope = Scope::enter(1 << 20, 1_000);
    assert!(flate(1 + 258 * 4)
        .decompressed_content_with_limit(1 << 20)
        .is_err());
    assert!(scope.exhausted());
}

#[test]
fn a_callers_own_smaller_limit_does_not_exhaust_the_budget() {
    let scope = Scope::enter(1 << 20, 1 << 20);
    assert!(flate(1 + 258 * 4)
        .decompressed_content_with_limit(500)
        .is_err());
    assert!(!scope.exhausted());
    assert!(flate(1 + 258 * 4).decompressed_content().is_ok());
}

#[test]
fn unfiltered_and_undecodable_streams_are_charged_their_raw_length() {
    let scope = Scope::enter(1_000, 1_000);
    assert!(spaces(600).decompressed_content().is_ok());
    assert!(spaces(600).decompressed_content().is_err());
    assert!(scope.exhausted());
    drop(scope);
    let image = lopdf::Stream::new(
        lopdf::dictionary! { "Filter" => Object::Name(b"DCTDecode".to_vec()) },
        vec![0xFF; 700],
    );
    let scope = Scope::enter(1_000, 1_000);
    assert!(image.decompressed_content().is_err());
    assert!(!scope.exhausted(), "700 of 1,000 charged");
    assert!(image.decompressed_content().is_err());
    assert!(scope.exhausted(), "the raw fallback is charged too");
}

#[test]
fn the_exhaustion_handler_runs_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static RUNS: AtomicUsize = AtomicUsize::new(0);
    fn count() {
        RUNS.fetch_add(1, Ordering::SeqCst);
    }
    let scope = Scope::enter(100, 100).on_exhausted(count);
    assert!(spaces(200).decompressed_content().is_err());
    assert!(spaces(1).decompressed_content().is_err());
    assert!(scope.exhausted());
    assert_eq!(RUNS.load(Ordering::SeqCst), 1);
}

#[test]
fn with_no_budget_open_an_unbounded_decode_is_refused() {
    let _closed = lopdf::decode_budget::closed();
    assert!(spaces(10).decompressed_content().is_err());
    assert!(spaces(10).decompressed_content_with_limit(10).is_ok());
}

/// The parity checks are bypassed here altogether: pdf-inspector runs with
/// no pre-flight and no parity watch, on documents whose bomb the pre-flight
/// would never see (the bare-name XObject lopdf drops) or that sits in the
/// page content itself. The decode budget alone still refuses them, and a
/// page's content is a stream pdf-inspector bounds with its own, smaller
/// limit (`MAX_PAGE_CONTENT_BYTES`), so the form XObject case is the one its
/// own code leaves unbounded.
#[test]
fn a_stream_the_preflight_never_saw_still_fails_closed_with_archive_limit() {
    let hidden = crate::fixtures::struct_name_bomb_pdf();
    assert!(
        within_budget(|| preflight(&hidden)).is_ok(),
        "the pre-flight must not see the bomb, or the fixture tests nothing"
    );
    for (name, bytes) in [
        ("bare-name form XObject", hidden),
        ("page content", crate::fixtures::flate_bomb_pdf()),
    ] {
        let unchecked = within_budget(|| {
            let _ =
                pdf_inspector::process_pdf_mem_with_options(&bytes, PdfOptions::new().pages(1..=1));
            Ok(())
        });
        assert_eq!(unchecked, Err(ParseRefusal::ArchiveLimit), "{name}");
    }
}

/// A form of just under 64 MiB fits every pre-flight bound, but each page
/// that draws it decodes it again. Drawn on 64 pages it would inflate 4 GiB;
/// the budget refuses it after the fourth decode.
#[test]
fn a_large_form_drawn_on_many_pages_is_refused_as_archive_limit() {
    use crate::fixtures::{repeated_form_pdf, FORM_ZEROS};
    let bytes = repeated_form_pdf(64, FORM_ZEROS);
    assert!(
        within_budget(|| preflight(&bytes)).is_ok(),
        "one decode of each stream fits the pre-flight"
    );
    assert_eq!(convert(&bytes).map(|_| ()), Err(ParseRefusal::ArchiveLimit));
}

/// The budget does not refuse ordinary repetition: a 1 MiB form drawn on
/// every one of 16 pages converts.
#[test]
fn a_small_form_drawn_on_every_page_converts() {
    let bytes = crate::fixtures::repeated_form_pdf(16, 1 + 258 * 4_064);
    let text = convert(&bytes).expect("converts");
    assert_eq!(text.pages, 16);
    assert!(text.markdown.contains("Orcel WI-05 fixture"));
}
