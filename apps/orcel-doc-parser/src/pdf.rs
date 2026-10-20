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
//! - pre-flight checks with `lopdf`, on exactly the bytes pdf-inspector
//!   parses (after its bare-name rewrite) loaded with exactly its options
//!   (`as_inspector_reads`), that fail closed before any extraction:
//!   an encrypted document (the donor, through pdf-inspector, falls back to
//!   the empty password; Orcel never decrypts), JavaScript or launch actions
//!   anywhere in the object graph, object nesting deeper than
//!   [`MAX_NESTING`], more than [`MAX_PAGES`] pages (refused, not cut), and
//!   any stream that inflates past [`MAX_ARCHIVE_BYTES`] (or all of them past
//!   [`MAX_PDF_INFLATED_BYTES`]) in one decode of each, which is what
//!   pdf-inspector later decodes without a bound (`bound_stream_inflation`);
//! - parity between the pre-flight and pdf-inspector is required and
//!   checked, not assumed: only a canonical `%PDF-d.d` header at byte 0 is
//!   admitted, and pdf-inspector's three input-changing paths (header strip,
//!   bare-name rewrite, container repair) are observed through its own log
//!   records while it runs; any of them, or a page count that differs from
//!   the pre-flight's, refuses the file (`inspect_with_parity`);
//! - every error is one closed [`ParseRefusal`] code; no text from the
//!   document reaches an error;
//! - a scanned PDF (no text layer) is refused as `no_text`: Orcel runs no OCR.
//!
//! Nothing in the document is followed or run: actions, links, embedded
//! files, forms and fonts' programs are never evaluated, only the text the
//! content streams draw is read.

use lopdf::{DecompressError, Document, LoadOptions, Object};
use orcel_provider_process::document_parser::{
    ParseRefusal, MAX_ARCHIVE_BYTES, MAX_NESTING, MAX_PAGES, MAX_PDF_INFLATED_BYTES,
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
    if !has_canonical_header_at_start(bytes) {
        return Err(ParseRefusal::Malformed);
    }
    let bytes = &as_inspector_reads(bytes)?;
    let pages = preflight(bytes)?;
    // The donor's `process_pdf` with `max_pages`: only the pages counted
    // above are extracted.
    let result = inspect_with_parity(bytes, pages)?;
    let markdown = match result.pdf_type {
        PdfType::TextBased | PdfType::Mixed => result.markdown.unwrap_or_default(),
        PdfType::Scanned | PdfType::ImageBased => String::new(),
    };
    if markdown.trim().is_empty() {
        return Err(ParseRefusal::NoText);
    }
    Ok(PdfText { markdown, pages })
}

/// The bounds above hold for what pdf-inspector decodes only if it parses
/// the very document the pre-flight checked. pdf-inspector 1.21.0 changes its
/// input on three paths before it loads, each of which logs (`log::debug!`):
/// - it drops bytes before the header it prefers ("dropping N leading
///   bytes"); [`has_canonical_header_at_start`] makes that a no-op;
/// - it rewrites bare structure names ("fix_bare_struct_names: patched");
///   [`as_inspector_reads`] applies that rewrite first, so a second pass
///   changes nothing;
/// - if the load fails, it retries on repaired copies of the container
///   ("loaded PDF after repairing"). The pre-flight already loaded the same
///   bytes with the same options and succeeded, so the load cannot fail.
///
/// Parity is checked here as well as argued: a logger records those three
/// messages, and if any of them is emitted while pdf-inspector runs, or its
/// page count differs from the pre-flight's, the file is refused. The
/// messages are pinned with pdf-inspector (=1.21.0), and
/// `pdf_tests::parity_breaks_are_observed` proves each one is still caught.
fn inspect_with_parity(
    bytes: &[u8],
    pages: usize,
) -> Result<pdf_inspector::PdfProcessResult, ParseRefusal> {
    let last = u32::try_from(pages).map_err(|_| ParseRefusal::TooManyPages)?;
    // Without the logger the check cannot run, so nothing is parsed.
    if !parity::watch() {
        return Err(ParseRefusal::Malformed);
    }
    let result =
        pdf_inspector::process_pdf_mem_with_options(bytes, PdfOptions::new().pages(1..=last));
    if parity::broken() {
        return Err(ParseRefusal::Malformed);
    }
    let result = result.map_err(inspector_refusal)?;
    if result.page_count as usize != pages {
        return Err(ParseRefusal::Malformed);
    }
    Ok(result)
}

/// pdf-inspector picks its own header: a canonical `%PDF-d.d` at a line
/// start within the first KiB wins over an earlier one (its
/// `pdf_header_offset`), while lopdf starts at the first `%PDF-`. Only a file
/// whose first bytes are a canonical header, which both agree on, is
/// admitted.
fn has_canonical_header_at_start(bytes: &[u8]) -> bool {
    matches!(bytes, [b'%', b'P', b'D', b'F', b'-', major, b'.', minor, rest @ ..]
        if major.is_ascii_digit()
            && minor.is_ascii_digit()
            && rest.first().is_none_or(|b| matches!(b, b'\r' | b'\n')))
}

/// Records, per thread, whether pdf-inspector logged one of the
/// input-changing paths [`inspect_with_parity`] names. pdf-inspector loads
/// on the calling thread, so a per-thread flag cannot see another parse.
mod parity {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Once;

    const MESSAGES: [&str; 3] = [
        "dropping ",
        "fix_bare_struct_names: patched",
        "loaded PDF after repairing",
    ];

    thread_local! {
        static BROKEN: Cell<bool> = const { Cell::new(false) };
    }

    struct ParityLog;

    impl log::Log for ParityLog {
        fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
            metadata.target().starts_with("pdf_inspector")
        }

        fn log(&self, record: &log::Record<'_>) {
            if !self.enabled(record.metadata()) {
                return;
            }
            let message = record.args().to_string();
            if MESSAGES.iter().any(|prefix| message.starts_with(prefix)) {
                BROKEN.with(|broken| broken.set(true));
            }
        }

        fn flush(&self) {}
    }

    static LOGGER: ParityLog = ParityLog;
    static INSTALL: Once = Once::new();
    static INSTALLED: AtomicBool = AtomicBool::new(false);

    /// Install the logger (once per process) and clear this thread's flag.
    /// False if another logger holds the slot, so nothing would be observed.
    pub(super) fn watch() -> bool {
        INSTALL.call_once(|| {
            if log::set_logger(&LOGGER).is_ok() {
                log::set_max_level(log::LevelFilter::Debug);
                INSTALLED.store(true, Ordering::SeqCst);
            }
        });
        BROKEN.with(|broken| broken.set(false));
        INSTALLED.load(Ordering::SeqCst)
    }

    pub(super) fn broken() -> bool {
        BROKEN.with(Cell::get)
    }
}

/// pdf-inspector's own load bound (`MAX_STREAM_DECOMPRESSED_BYTES` in
/// pdf-inspector 1.21.0, pinned exactly in Cargo.toml): the pre-flight loads
/// with the same options, so both loads keep and drop the same objects.
const INSPECTOR_LOAD_BOUND: usize = 8 * 1024 * 1024;

/// The bytes pdf-inspector actually parses. Before loading, it rewrites bare
/// structure names (`/S Code` to `/S /Code`, `fix_bare_struct_names`, when a
/// `/StructTreeRoot` is present), because lopdf drops objects written the
/// bare way. A pre-flight over the original bytes would miss every object
/// the rewrite brings back, so the pre-flight and pdf-inspector both get the
/// rewritten bytes. pdf-inspector rewrites them again; that second pass must
/// change nothing, or the file is refused.
fn as_inspector_reads(bytes: &[u8]) -> Result<Vec<u8>, ParseRefusal> {
    let fixed = pdf_inspector::structure_tree::fix_bare_struct_names(bytes).into_owned();
    if matches!(
        pdf_inspector::structure_tree::fix_bare_struct_names(&fixed),
        std::borrow::Cow::Owned(_)
    ) {
        return Err(ParseRefusal::Malformed);
    }
    Ok(fixed)
}

/// Load the document exactly as pdf-inspector will, refuse what Orcel never
/// parses, and return the page count.
fn preflight(bytes: &[u8]) -> Result<usize, ParseRefusal> {
    let options = LoadOptions {
        max_decompressed_size: Some(INSPECTOR_LOAD_BOUND),
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
    bound_stream_inflation(&document)?;
    let pages = document.page_iter().take(MAX_PAGES + 1).count();
    match pages {
        0 => Err(ParseRefusal::Malformed),
        count if count > MAX_PAGES => Err(ParseRefusal::TooManyPages),
        count => Ok(count),
    }
}

/// pdf-inspector decodes content, form XObject, font and ToUnicode streams
/// with lopdf's unbounded `decompressed_content`, on the same document this
/// pass loaded (`as_inspector_reads`). So every stream is decoded here first
/// under a bound: no one decode of a stream may inflate past
/// [`MAX_ARCHIVE_BYTES`] (each filter layer is capped while it decodes, never
/// after), and one decode of every stream together not past
/// [`MAX_PDF_INFLATED_BYTES`]. The bound is per decode: pdf-inspector may
/// decode one stream more than once (a form XObject drawn on many pages),
/// and those repeats are bounded by the memory, CPU and time ceilings of the
/// contained run, not by this budget.
///
/// A stream lopdf cannot decode (images: DCT, JPX, JBIG2, CCITT; or a corrupt
/// stream) is charged its raw length, which is what pdf-inspector falls back
/// to reading.
fn bound_stream_inflation(document: &Document) -> Result<(), ParseRefusal> {
    let (per_stream, total) = stream_budget()?;
    bound_stream_inflation_within(document, per_stream, total)
}

/// The per-stream and per-document inflation bounds, in bytes.
fn stream_budget() -> Result<(usize, usize), ParseRefusal> {
    Ok((
        usize::try_from(MAX_ARCHIVE_BYTES).map_err(|_| ParseRefusal::ArchiveLimit)?,
        usize::try_from(MAX_PDF_INFLATED_BYTES).map_err(|_| ParseRefusal::ArchiveLimit)?,
    ))
}

fn bound_stream_inflation_within(
    document: &Document,
    per_stream: usize,
    total: usize,
) -> Result<(), ParseRefusal> {
    let mut remaining = total;
    for object in document.objects.values() {
        let Object::Stream(stream) = object else {
            continue;
        };
        let charged = match stream.decompressed_content_with_limit(per_stream.min(remaining)) {
            Ok(content) => content.len(),
            Err(lopdf::Error::Decompress(DecompressError::MemoryLimitExceeded { .. })) => {
                return Err(ParseRefusal::ArchiveLimit)
            }
            Err(_) => stream.content.len(),
        };
        remaining = remaining
            .checked_sub(charged)
            .ok_or(ParseRefusal::ArchiveLimit)?;
    }
    Ok(())
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
