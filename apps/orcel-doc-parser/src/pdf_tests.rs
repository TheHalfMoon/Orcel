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
