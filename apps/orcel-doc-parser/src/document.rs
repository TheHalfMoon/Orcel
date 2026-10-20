//! Office (OOXML) to Markdown (WI-05).
//!
//! COPY_ADAPT of Firecrawl's `apps/api/native/src/document.rs`
//! (firecrawl/firecrawl@f84845c864b6e2af22791c18fcf89ac2a21f1434, blob
//! ee75ba34f7a6b45b5bdad7317f895cd029c3d95b, AGPL-3.0; used and relicensed
//! under the founder authorization recorded in
//! docs/orcel/grants/2026-10-13-founder-source-authorization.md and
//! docs/orcel/grants/2026-10-18-founder-attestation.md; transplant row
//! T-FC-07). The conversion is the donor's: `anydoc` to Markdown, then for a
//! DOCX the headers and footers its references name, read through the
//! donor's bounded zip reader (`ZipReadBudget`, `read_zip_text`) and joined
//! around the body exactly as the donor does.
//!
//! Orcel's changes:
//! - the N-API glue is removed, and so is the extension hint: the format is
//!   only ever detected from the content;
//! - only DOCX, PPTX and XLSX are admitted. Binary Office (OLE compound
//!   files), OpenDocument, RTF, EPUB, CSV and PDF-through-anydoc are refused
//!   as `unsupported_format`, so the parser surface is three OOXML readers;
//!   an OLE file that holds an `EncryptionInfo` stream (an encrypted OOXML
//!   package) is refused as `encrypted`;
//! - a pre-flight pass over the whole archive before anydoc sees it:
//!   at most [`MAX_ARCHIVE_ENTRIES`] entries; no encrypted entry; no macro
//!   project (`vbaProject.bin`, `vbaData.xml`) or ActiveX part; no entry
//!   above [`RATIO_FLOOR_BYTES`] that inflates more than [`MAX_ENTRY_RATIO`]
//!   times; every entry actually inflated through a counting reader, all of
//!   them together at most [`MAX_ARCHIVE_BYTES`] (declared sizes are not
//!   trusted); every XML part free of a DTD and nested at most
//!   [`MAX_XML_NESTING`] deep; at most [`MAX_PAGES`] slides or sheets;
//! - the donor's part budget (128 MiB) is replaced by [`MAX_ARCHIVE_BYTES`];
//! - every error is one closed [`ParseRefusal`] code.
//!
//! Nothing in the package is run or followed: macros are refused, external
//! relationships (`TargetMode="External"`, linked templates, hyperlinks) are
//! never resolved, and embedded objects are never opened.

use orcel_provider_process::document_parser::{
    DocumentFormat, ParseRefusal, MAX_ARCHIVE_BYTES, MAX_ARCHIVE_ENTRIES, MAX_ENTRY_RATIO,
    MAX_PAGES, MAX_XML_NESTING, RATIO_FLOOR_BYTES,
};
use roxmltree::Document;
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};

const MAX_OOXML_PART_BYTES: u64 = MAX_ARCHIVE_BYTES;
const MAX_OOXML_TOTAL_BYTES: u64 = MAX_ARCHIVE_BYTES;
const MAX_OOXML_PARTS: usize = 256;
const MAX_HEADER_FOOTER_REFERENCES: usize = 256;
const WORDPROCESSINGML_NAMESPACES: [&str; 2] = [
    "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "http://purl.oclc.org/ooxml/wordprocessingml/main",
];

const OLE_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const ZIP_MAGIC: &[u8] = b"PK\x03\x04";

/// Converted Office text, its format, and its slide or sheet count (0 for a
/// DOCX: Word documents have no fixed pages).
#[derive(Debug)]
pub struct OfficeText {
    pub format: DocumentFormat,
    pub markdown: String,
    pub pages: usize,
}

/// Whether the bytes look like an Office container this module decides on.
pub fn is_office_container(bytes: &[u8]) -> bool {
    bytes.starts_with(ZIP_MAGIC) || bytes.starts_with(OLE_MAGIC)
}

pub fn convert(bytes: &[u8]) -> Result<OfficeText, ParseRefusal> {
    if bytes.starts_with(OLE_MAGIC) {
        return Err(if contains_utf16(bytes, "EncryptionInfo") {
            ParseRefusal::Encrypted
        } else {
            ParseRefusal::UnsupportedFormat
        });
    }
    if !bytes.starts_with(ZIP_MAGIC) {
        return Err(ParseRefusal::UnsupportedFormat);
    }
    let pages = preflight_archive(bytes)?;
    let (format, anydoc_format) = match anydoc::Format::from_bytes(bytes) {
        Some(anydoc::Format::Docx) => (DocumentFormat::Docx, anydoc::Format::Docx),
        Some(anydoc::Format::Pptx) => (DocumentFormat::Pptx, anydoc::Format::Pptx),
        Some(anydoc::Format::Excel) => (DocumentFormat::Xlsx, anydoc::Format::Excel),
        _ => return Err(ParseRefusal::UnsupportedFormat),
    };
    let markdown = convert_document_to_markdown(bytes, anydoc_format)?;
    Ok(OfficeText {
        format,
        markdown,
        pages: if format == DocumentFormat::Docx {
            0
        } else {
            pages
        },
    })
}

/// The donor's `convert_document_to_markdown`, with the format already
/// decided from the content.
fn convert_document_to_markdown(
    data: &[u8],
    format: anydoc::Format,
) -> Result<String, ParseRefusal> {
    let markdown = anydoc::to_markdown_bytes(data, format).map_err(anydoc_refusal)?;

    if format != anydoc::Format::Docx {
        return Ok(markdown);
    }

    let (headers, footers) = extract_docx_headers_and_footers(data);
    if headers.is_empty() && footers.is_empty() {
        return Ok(markdown);
    }
    let sections = [headers, markdown.trim().to_string(), footers]
        .into_iter()
        .filter(|section| !section.is_empty())
        .collect::<Vec<_>>();

    Ok(format!("{}\n", sections.join("\n\n")))
}

fn anydoc_refusal(error: anydoc::ConvertError) -> ParseRefusal {
    match error {
        anydoc::ConvertError::Encrypted => ParseRefusal::Encrypted,
        anydoc::ConvertError::ResourceLimit { .. } => ParseRefusal::ArchiveLimit,
        anydoc::ConvertError::Unsupported(_) => ParseRefusal::UnsupportedFormat,
        _ => ParseRefusal::Malformed,
    }
}

/// Check the whole archive before any converter reads it, and count its
/// slides and sheets.
fn preflight_archive(bytes: &[u8]) -> Result<usize, ParseRefusal> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| ParseRefusal::Malformed)?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(ParseRefusal::ArchiveLimit);
    }
    let mut inflated_total: u64 = 0;
    let mut pages = 0_usize;
    for index in 0..archive.len() {
        let (name, declared, compressed, encrypted) = {
            let entry = archive
                .by_index_raw(index)
                .map_err(|_| ParseRefusal::Malformed)?;
            (
                entry.name().to_owned(),
                entry.size(),
                entry.compressed_size(),
                entry.encrypted(),
            )
        };
        if encrypted {
            return Err(ParseRefusal::Encrypted);
        }
        if is_active_part(&name) {
            return Err(ParseRefusal::ActiveContent);
        }
        if declared > RATIO_FLOOR_BYTES && declared / compressed.max(1) > MAX_ENTRY_RATIO {
            return Err(ParseRefusal::ArchiveLimit);
        }
        if is_page_part(&name) {
            pages += 1;
            if pages > MAX_PAGES {
                return Err(ParseRefusal::TooManyPages);
            }
        }
        let remaining = MAX_ARCHIVE_BYTES - inflated_total;
        let mut entry = archive
            .by_index(index)
            .map_err(|_| ParseRefusal::Malformed)?;
        let mut content = Vec::new();
        let read = (&mut entry)
            .take(remaining + 1)
            .read_to_end(&mut content)
            .map_err(|_| ParseRefusal::Malformed)? as u64;
        if read > remaining {
            return Err(ParseRefusal::ArchiveLimit);
        }
        if read > RATIO_FLOOR_BYTES && read / compressed.max(1) > MAX_ENTRY_RATIO {
            return Err(ParseRefusal::ArchiveLimit);
        }
        inflated_total += read;
        if is_xml_part(&name) {
            check_xml(&content)?;
        }
    }
    Ok(pages)
}

fn is_active_part(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with("vbaproject.bin")
        || lower.ends_with("vbadata.xml")
        || lower.contains("/activex/")
        || lower.starts_with("activex/")
}

fn is_page_part(name: &str) -> bool {
    let numbered = |prefix: &str| {
        name.strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(".xml"))
            .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
    };
    numbered("ppt/slides/slide") || numbered("xl/worksheets/sheet")
}

fn is_xml_part(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".xml") || lower.ends_with(".rels")
}

/// Element nesting of one XML part, without building a tree: refuses a DTD
/// (no entity can expand) and nesting past [`MAX_XML_NESTING`]. Comments,
/// CDATA sections, processing instructions and quoted attribute values are
/// skipped.
pub(crate) fn check_xml(xml: &[u8]) -> Result<(), ParseRefusal> {
    let mut depth = 0_usize;
    let mut index = 0;
    let find = |from: usize, needle: &[u8]| {
        xml.get(from..)
            .and_then(|rest| rest.windows(needle.len()).position(|w| w == needle))
            .map(|at| from + at + needle.len())
            .ok_or(ParseRefusal::Malformed)
    };
    while let Some(offset) = xml
        .get(index..)
        .and_then(|rest| rest.iter().position(|b| *b == b'<'))
    {
        let start = index + offset;
        let rest = &xml[start..];
        if rest.starts_with(b"<!--") {
            index = find(start + 4, b"-->")?;
        } else if rest.starts_with(b"<![CDATA[") {
            index = find(start + 9, b"]]>")?;
        } else if rest.starts_with(b"<?") {
            index = find(start + 2, b"?>")?;
        } else if rest.starts_with(b"<!") {
            // <!DOCTYPE and any other declaration: never in OOXML parts.
            return Err(ParseRefusal::Malformed);
        } else if rest.starts_with(b"</") {
            depth = depth.checked_sub(1).ok_or(ParseRefusal::Malformed)?;
            index = find(start + 2, b">")?;
        } else {
            let (end, self_closing) = tag_end(xml, start + 1)?;
            if !self_closing {
                depth += 1;
                if depth > MAX_XML_NESTING {
                    return Err(ParseRefusal::NestingTooDeep);
                }
            }
            index = end;
        }
    }
    Ok(())
}

/// The index after an opening tag's `>`, and whether it was `/>`.
fn tag_end(xml: &[u8], from: usize) -> Result<(usize, bool), ParseRefusal> {
    let mut quote = None;
    let mut previous = 0_u8;
    for (offset, byte) in xml[from..].iter().enumerate() {
        match (quote, *byte) {
            (Some(open), byte) if byte == open => quote = None,
            (Some(_), _) => {}
            (None, b'"' | b'\'') => quote = Some(*byte),
            (None, b'>') => return Ok((from + offset + 1, previous == b'/')),
            (None, _) => {}
        }
        previous = *byte;
    }
    Err(ParseRefusal::Malformed)
}

fn contains_utf16(bytes: &[u8], text: &str) -> bool {
    let needle: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    bytes.windows(needle.len()).any(|window| window == needle)
}

// ---------------------------------------------------------------------------
// The donor's DOCX header and footer pass, unchanged but for the budget
// constants above and a checked capacity conversion in `read_zip_text`. It
// only reads parts inside the package; external relationships are skipped
// (`TargetMode="External"`).
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum RepeatingPartKind {
    Header,
    Footer,
}

struct Relationship {
    target: String,
    kind: RepeatingPartKind,
}

struct ZipReadBudget {
    bytes_remaining: u64,
    parts_remaining: usize,
}

impl Default for ZipReadBudget {
    fn default() -> Self {
        Self {
            bytes_remaining: MAX_OOXML_TOTAL_BYTES,
            parts_remaining: MAX_OOXML_PARTS,
        }
    }
}

fn extract_docx_headers_and_footers(data: &[u8]) -> (String, String) {
    let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(data)) else {
        return (String::new(), String::new());
    };
    let mut budget = ZipReadBudget::default();

    let main_part = read_zip_text(&mut archive, "_rels/.rels", &mut budget)
        .and_then(|xml| office_document_target(&xml))
        .unwrap_or_else(|| "word/document.xml".to_string());
    let Some(document_xml) = read_zip_text(&mut archive, &main_part, &mut budget) else {
        return (String::new(), String::new());
    };
    let relationship_part = relationship_part_for(&main_part);
    let Some(relationships_xml) = read_zip_text(&mut archive, &relationship_part, &mut budget)
    else {
        return (String::new(), String::new());
    };
    let relationships = parse_repeating_relationships(&relationships_xml);
    let Ok(document) = Document::parse(&document_xml) else {
        return (String::new(), String::new());
    };

    let mut seen = HashSet::new();
    let mut headers = Vec::new();
    let mut footers = Vec::new();
    let mut reference_count = 0;

    for reference in document
        .descendants()
        .filter(|node| is_wordprocessing_node(*node))
    {
        let reference_kind = match reference.tag_name().name() {
            "headerReference" => RepeatingPartKind::Header,
            "footerReference" => RepeatingPartKind::Footer,
            _ => continue,
        };
        reference_count += 1;
        if reference_count > MAX_HEADER_FOOTER_REFERENCES {
            break;
        }
        let Some(id) = reference
            .attributes()
            .find(|attribute| attribute.name() == "id")
            .map(|attribute| attribute.value())
        else {
            continue;
        };
        let Some(relationship) = relationships.get(id) else {
            continue;
        };
        if relationship.kind != reference_kind {
            continue;
        }
        let Some(part) = resolve_part(&main_part, &relationship.target) else {
            continue;
        };
        if !seen.insert((reference_kind, part.clone())) {
            continue;
        }
        let Some(xml) = read_zip_text(&mut archive, &part, &mut budget) else {
            continue;
        };
        let Some(text) = extract_wordprocessing_text(&xml) else {
            continue;
        };

        match reference_kind {
            RepeatingPartKind::Header => headers.push(text),
            RepeatingPartKind::Footer => footers.push(text),
        }
    }

    (headers.join("\n\n"), footers.join("\n\n"))
}

fn read_zip_text<R: Read + std::io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    name: &str,
    budget: &mut ZipReadBudget,
) -> Option<String> {
    if budget.parts_remaining == 0 || budget.bytes_remaining == 0 {
        return None;
    }
    let mut file = archive.by_name(name.trim_start_matches('/')).ok()?;
    if file.size() > MAX_OOXML_PART_BYTES || file.size() > budget.bytes_remaining {
        return None;
    }
    budget.parts_remaining -= 1;
    let mut bytes = Vec::with_capacity(usize::try_from(file.size()).ok()?);
    let read_limit = MAX_OOXML_PART_BYTES.min(budget.bytes_remaining);
    let read_result = file.by_ref().take(read_limit + 1).read_to_end(&mut bytes);
    budget.bytes_remaining = budget.bytes_remaining.saturating_sub(bytes.len() as u64);
    if read_result.is_err() {
        return None;
    }
    if bytes.len() as u64 > read_limit {
        budget.bytes_remaining = 0;
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn office_document_target(xml: &str) -> Option<String> {
    let document = Document::parse(xml).ok()?;
    let relationship = document.descendants().find(|node| {
        node.is_element()
            && node.tag_name().name() == "Relationship"
            && node
                .attribute("Type")
                .is_some_and(|value| value.ends_with("/officeDocument"))
    })?;
    normalize_part(relationship.attribute("Target")?)
}

fn parse_repeating_relationships(xml: &str) -> HashMap<String, Relationship> {
    let Ok(document) = Document::parse(xml) else {
        return HashMap::new();
    };

    document
        .descendants()
        .filter_map(|node| {
            if !node.is_element()
                || node.tag_name().name() != "Relationship"
                || node
                    .attribute("TargetMode")
                    .is_some_and(|value| value.eq_ignore_ascii_case("external"))
            {
                return None;
            }
            let kind = match node.attribute("Type")? {
                value if value.ends_with("/header") => RepeatingPartKind::Header,
                value if value.ends_with("/footer") => RepeatingPartKind::Footer,
                _ => return None,
            };
            Some((
                node.attribute("Id")?.to_string(),
                Relationship {
                    target: node.attribute("Target")?.to_string(),
                    kind,
                },
            ))
        })
        .collect()
}

fn relationship_part_for(part: &str) -> String {
    match part.rsplit_once('/') {
        Some((parent, file_name)) => format!("{parent}/_rels/{file_name}.rels"),
        None => format!("_rels/{part}.rels"),
    }
}

fn resolve_part(base: &str, target: &str) -> Option<String> {
    if target.starts_with('/') {
        return normalize_part(target);
    }
    let parent = base
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or("");
    normalize_part(&format!("{parent}/{target}"))
}

fn normalize_part(part: &str) -> Option<String> {
    let mut normalized = Vec::new();
    for component in part.trim_start_matches('/').split('/') {
        match component {
            "" | "." => {}
            ".." => normalized.pop().map(|_| ())?,
            value => normalized.push(value),
        }
    }
    (!normalized.is_empty()).then(|| normalized.join("/"))
}

fn extract_wordprocessing_text(xml: &str) -> Option<String> {
    let document = Document::parse(xml).ok()?;
    let paragraphs = document
        .descendants()
        .filter(|node| {
            is_wordprocessing_node(*node)
                && node.tag_name().name() == "p"
                && !node.ancestors().skip(1).any(|ancestor| {
                    is_wordprocessing_node(ancestor) && ancestor.tag_name().name() == "p"
                })
        })
        .filter_map(|paragraph| {
            let mut text = String::new();
            for node in paragraph
                .descendants()
                .filter(|node| is_wordprocessing_node(*node))
            {
                match node.tag_name().name() {
                    "t" => {
                        if let Some(value) = node.text() {
                            text.push_str(value);
                        }
                    }
                    "tab" => text.push('\t'),
                    "br" | "cr" => text.push('\n'),
                    _ => {}
                }
            }
            let text = text.trim();
            (!text.is_empty()).then(|| text.to_string())
        })
        .collect::<Vec<_>>();

    (!paragraphs.is_empty()).then(|| paragraphs.join("\n\n"))
}

fn is_wordprocessing_node(node: roxmltree::Node<'_, '_>) -> bool {
    node.is_element()
        && node
            .tag_name()
            .namespace()
            .is_some_and(|namespace| WORDPROCESSINGML_NAMESPACES.contains(&namespace))
}

#[cfg(test)]
#[path = "document_tests.rs"]
mod tests;
