use super::*;

#[test]
fn xml_depth_skips_comments_cdata_instructions_and_quoted_values() {
    let xml =
        b"<?xml version=\"1.0\"?><a x='>' y=\"<b>\"><!-- <c><d> --><![CDATA[<e><f>]]><g/></a>";
    assert_eq!(check_xml(xml), Ok(()));
}

#[test]
fn xml_depth_is_bounded_and_dtds_are_refused() {
    let deep = format!(
        "{}{}",
        "<a>".repeat(MAX_XML_NESTING + 1),
        "</a>".repeat(MAX_XML_NESTING + 1)
    );
    assert_eq!(
        check_xml(deep.as_bytes()),
        Err(ParseRefusal::NestingTooDeep)
    );
    let inside = format!(
        "{}{}",
        "<a>".repeat(MAX_XML_NESTING),
        "</a>".repeat(MAX_XML_NESTING)
    );
    assert_eq!(check_xml(inside.as_bytes()), Ok(()));
    assert_eq!(check_xml(b"<!DOCTYPE a><a/>"), Err(ParseRefusal::Malformed));
    assert_eq!(check_xml(b"</a>"), Err(ParseRefusal::Malformed));
    assert_eq!(check_xml(b"<a"), Err(ParseRefusal::Malformed));
}

#[test]
fn macro_and_activex_parts_are_active_content() {
    for name in [
        "word/vbaProject.bin",
        "xl/vbaProject.bin",
        "word/vbaData.xml",
        "word/activeX/activeX1.xml",
    ] {
        assert!(is_active_part(name), "{name}");
    }
    assert!(!is_active_part("word/document.xml"));
}

#[test]
fn only_numbered_slides_and_sheets_count_as_pages() {
    assert!(is_page_part("ppt/slides/slide12.xml"));
    assert!(is_page_part("xl/worksheets/sheet1.xml"));
    assert!(!is_page_part("ppt/slides/_rels/slide1.xml.rels"));
    assert!(!is_page_part("ppt/slides/slide.xml"));
    assert!(!is_page_part("ppt/slideLayouts/slideLayout1.xml"));
}

#[test]
fn donor_part_resolution_never_climbs_out_of_the_package() {
    assert_eq!(
        resolve_part("word/document.xml", "header1.xml").as_deref(),
        Some("word/header1.xml")
    );
    assert_eq!(resolve_part("word/document.xml", "../../../x.xml"), None);
    assert_eq!(
        normalize_part("/word/./a.xml").as_deref(),
        Some("word/a.xml")
    );
}
