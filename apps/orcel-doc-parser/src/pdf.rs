//! PDF to Markdown (WI-05).
//!
//! COPY_ADAPT of Firecrawl's `apps/api/native/src/pdf.rs`
//! (firecrawl/firecrawl@f84845c864b6e2af22791c18fcf89ac2a21f1434, blob
//! a4f019f072b13729610a2241cd51db5e34eed0c6, AGPL-3.0; used and relicensed
//! under the founder authorization recorded in
//! docs/orcel/grants/2026-10-13-founder-source-authorization.md and
//! docs/orcel/grants/2026-10-18-founder-attestation.md; transplant row
//! T-FC-06). The conversion is the donor's: `pdf_inspector` with the page
//! range bounded, and the same `PdfType` handling.
//!
//! Orcel's changes:
//! - the N-API, tokio and tracing glue is removed: this runs once, in its own
//!   confined process, on bytes it was handed (no path, no `detect_pdf`);
//! - pre-flight checks with `lopdf` that fail closed before any extraction:
//!   an encrypted document (the donor, through pdf-inspector, falls back to
//!   the empty password; Orcel never decrypts), JavaScript or launch actions
//!   anywhere in the object graph, object nesting deeper than
//!   [`MAX_NESTING`], more than [`MAX_PAGES`] pages (refused, not cut), and a
//!   stream that inflates past [`MAX_ARCHIVE_BYTES`] while loading;
//! - every error is one closed [`ParseRefusal`] code; no text from the
//!   document reaches an error;
//! - a scanned PDF (no text layer) is refused as `no_text`: Orcel runs no OCR.
//!
//! Nothing in the document is followed or run: actions, links, embedded
//! files, forms and fonts' programs are never evaluated, only the text the
//! content streams draw is read.

use lopdf::{DecompressError, Document, LoadOptions, Object};
use orcel_provider_process::document_parser::{
    ParseRefusal, MAX_ARCHIVE_BYTES, MAX_NESTING, MAX_PAGES,
};
use pdf_inspector::{PdfError, PdfOptions, PdfType};

/// Keys and names that mark executable content: a JavaScript action
/// (`/S /JavaScript`, its `/JS` script, the document's `/JavaScript` name
/// tree) or a launch action (`/S /Launch`, which starts a program).
const ACTIVE_NAMES: [&[u8]; 3] = [b"JavaScript", b"JS", b"Launch"];

/// The text of a converted PDF and its page count.
#[derive(Debug)]
pub struct PdfText {
    pub markdown: String,
    pub pages: usize,
}

pub fn convert(bytes: &[u8]) -> Result<PdfText, ParseRefusal> {
    if !bytes.starts_with(b"%PDF-") {
        return Err(ParseRefusal::Malformed);
    }
    let pages = preflight(bytes)?;
    // The donor's `process_pdf` with `max_pages`: only the pages counted
    // above are extracted.
    let last = u32::try_from(pages).map_err(|_| ParseRefusal::TooManyPages)?;
    let result =
        pdf_inspector::process_pdf_mem_with_options(bytes, PdfOptions::new().pages(1..=last))
            .map_err(inspector_refusal)?;
    let markdown = match result.pdf_type {
        PdfType::TextBased | PdfType::Mixed => result.markdown.unwrap_or_default(),
        PdfType::Scanned | PdfType::ImageBased => String::new(),
    };
    if markdown.trim().is_empty() {
        return Err(ParseRefusal::NoText);
    }
    Ok(PdfText { markdown, pages })
}

/// Load the document once with a bounded inflater, refuse what Orcel never
/// parses, and return the page count.
fn preflight(bytes: &[u8]) -> Result<usize, ParseRefusal> {
    let options = LoadOptions {
        max_decompressed_size: usize::try_from(MAX_ARCHIVE_BYTES).ok(),
        ..LoadOptions::default()
    };
    let document = Document::load_mem_with_options(bytes, options).map_err(load_refusal)?;
    if document.trailer.has(b"Encrypt") || document.was_encrypted() {
        return Err(ParseRefusal::Encrypted);
    }
    inspect(&Object::Dictionary(document.trailer.clone()), 0)?;
    for object in document.objects.values() {
        inspect(object, 0)?;
    }
    let pages = document.page_iter().take(MAX_PAGES + 1).count();
    match pages {
        0 => Err(ParseRefusal::Malformed),
        count if count > MAX_PAGES => Err(ParseRefusal::TooManyPages),
        count => Ok(count),
    }
}

/// Walk one object (references are not followed: every object is visited
/// once from the object table), refusing active content and deep nesting.
fn inspect(object: &Object, depth: usize) -> Result<(), ParseRefusal> {
    if depth > MAX_NESTING {
        return Err(ParseRefusal::NestingTooDeep);
    }
    match object {
        Object::Name(name) if is_active(name) => Err(ParseRefusal::ActiveContent),
        Object::Array(items) => items.iter().try_for_each(|item| inspect(item, depth + 1)),
        Object::Dictionary(dictionary) => inspect_dictionary(dictionary, depth),
        Object::Stream(stream) => inspect_dictionary(&stream.dict, depth),
        _ => Ok(()),
    }
}

fn inspect_dictionary(dictionary: &lopdf::Dictionary, depth: usize) -> Result<(), ParseRefusal> {
    for (key, value) in dictionary.iter() {
        if is_active(key) {
            return Err(ParseRefusal::ActiveContent);
        }
        inspect(value, depth + 1)?;
    }
    Ok(())
}

fn is_active(name: &[u8]) -> bool {
    ACTIVE_NAMES.contains(&name)
}

fn load_refusal(error: lopdf::Error) -> ParseRefusal {
    match error {
        lopdf::Error::Decryption(_)
        | lopdf::Error::InvalidPassword
        | lopdf::Error::AlreadyEncrypted
        | lopdf::Error::UnsupportedSecurityHandler(_) => ParseRefusal::Encrypted,
        lopdf::Error::Decompress(DecompressError::MemoryLimitExceeded { .. }) => {
            ParseRefusal::ArchiveLimit
        }
        _ => ParseRefusal::Malformed,
    }
}

fn inspector_refusal(error: PdfError) -> ParseRefusal {
    match error {
        PdfError::Encrypted => ParseRefusal::Encrypted,
        PdfError::Io(_)
        | PdfError::Parse(_)
        | PdfError::InvalidStructure
        | PdfError::NotAPdf(_) => ParseRefusal::Malformed,
    }
}

#[cfg(test)]
#[path = "pdf_tests.rs"]
mod tests;
