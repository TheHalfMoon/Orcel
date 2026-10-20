use super::*;

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
        stream.decompressed_content_with_limit(1 << 20).unwrap(),
        vec![0; 1 + 258 * 4]
    );
}

/// The bare-name fixture really exercises the divergence: lopdf alone drops
/// the bomb XObject, and only the bytes pdf-inspector parses contain it.
#[test]
fn the_bomb_hidden_behind_a_bare_struct_name_is_found_in_the_bytes_inspector_reads() {
    let raw = crate::fixtures::struct_name_bomb_pdf();
    assert!(
        preflight(&raw).is_ok(),
        "lopdf on the raw bytes must not see the bomb, or the fixture tests nothing"
    );
    let rewritten = as_inspector_reads(&raw).unwrap();
    assert_ne!(rewritten, raw);
    assert_eq!(preflight(&rewritten), Err(ParseRefusal::ArchiveLimit));
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
        bound_stream_inflation_within(&document, 2 << 20, 3 << 20),
        Err(ParseRefusal::ArchiveLimit)
    );
    assert_eq!(
        bound_stream_inflation_within(&document, 2 << 20, 5 << 20),
        Ok(())
    );
    // Each stream past a per-stream bound just below its size.
    assert_eq!(
        bound_stream_inflation_within(&document, 1_048_512, 64 << 20),
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
        bound_stream_inflation_within(&document, 64 << 20, 2 << 20),
        Err(ParseRefusal::ArchiveLimit)
    );
    assert_eq!(
        bound_stream_inflation_within(&document, 64 << 20, 4 << 20),
        Ok(())
    );
}
