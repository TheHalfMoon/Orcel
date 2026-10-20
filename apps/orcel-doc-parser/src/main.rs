//! orcel-doc-parser: converts one approved, already-downloaded PDF or Office
//! file to Markdown (WI-05).
//!
//! orceld never runs this in its own process or in the browser worker. It
//! stages a private copy of a committed download, asks for approval, and
//! starts this binary through the contained tier (`orcel-contain`) with the
//! spec in `crates/orcel-provider-process/src/document_parser.rs`: one
//! read-only input directory holding only that copy, no writable root, no
//! network, no process creation, CPU, memory and output limits and a 30 s
//! timeout. A parser bug is therefore contained to a process that can read
//! one file and write one bounded frame to stdout.
//!
//! Usage: `orcel-doc-parser <input>`. The binary reads no environment
//! variable and no other file. It writes exactly one `orcel-doc-parser/1`
//! frame on stdout and exits 0 (`ok`) or 2 (`error`, a closed refusal code).
//! The format is detected from the content only, never from a name:
//! - `%PDF-` goes to [`pdf`] (Firecrawl's `pdf.rs`, adapted);
//! - a zip or OLE container goes to [`document`] (Firecrawl's `document.rs`,
//!   adapted), which admits DOCX, PPTX and XLSX;
//! - anything else is `unsupported_format`.
//!
//! Every bound fails closed except the Markdown length: past
//! [`MAX_CHARS`] the text is cut at a character boundary and flagged
//! `truncated`. The output is untrusted document content: orceld labels it
//! as such and it never carries authority.

mod document;
mod pdf;

use orcel_provider_process::document_parser::{
    encode_ok, encode_refusal, DocumentFormat, ParseRefusal, ParsedDocument, EXIT_REFUSED,
    MAX_CHARS, MAX_INPUT_BYTES,
};
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    // pdf-inspector and lopdf parallelise with rayon. One worker keeps the
    // memory ceiling meaningful and the run deterministic. An error only
    // means a pool already exists, which cannot happen this early.
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build_global();
    let (frame, status) = match run() {
        Ok(document) => (encode_ok(&document), 0),
        Err(refusal) => (encode_refusal(refusal), EXIT_REFUSED),
    };
    let mut stdout = std::io::stdout().lock();
    if stdout
        .write_all(&frame)
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return ExitCode::FAILURE;
    }
    ExitCode::from(u8::try_from(status).unwrap_or(1))
}

fn run() -> Result<ParsedDocument, ParseRefusal> {
    let mut args = std::env::args_os().skip(1);
    let (Some(path), None) = (args.next(), args.next()) else {
        return Err(ParseRefusal::Usage);
    };
    let bytes = read_bounded(Path::new(&path))?;
    convert(&bytes)
}

/// Read the input, refusing anything past [`MAX_INPUT_BYTES`] without
/// reading more than one byte beyond it.
fn read_bounded(path: &Path) -> Result<Vec<u8>, ParseRefusal> {
    let file = std::fs::File::open(path).map_err(|_| ParseRefusal::Usage)?;
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ParseRefusal::Usage)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(ParseRefusal::InputTooLarge);
    }
    Ok(bytes)
}

/// Convert one input held in memory.
pub(crate) fn convert(bytes: &[u8]) -> Result<ParsedDocument, ParseRefusal> {
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(ParseRefusal::InputTooLarge);
    }
    let (format, markdown, pages) = if bytes.starts_with(b"%PDF-") {
        let text = pdf::convert(bytes)?;
        (DocumentFormat::Pdf, text.markdown, text.pages)
    } else if document::is_office_container(bytes) {
        let text = document::convert(bytes)?;
        (text.format, text.markdown, text.pages)
    } else {
        return Err(ParseRefusal::UnsupportedFormat);
    };
    let (markdown, truncated) = bound_chars(markdown);
    Ok(ParsedDocument {
        format,
        pages,
        chars: markdown.chars().count(),
        truncated,
        markdown,
    })
}

/// Cut the Markdown to at most [`MAX_CHARS`] characters.
fn bound_chars(mut markdown: String) -> (String, bool) {
    match markdown.char_indices().nth(MAX_CHARS) {
        Some((cut, _)) => {
            markdown.truncate(cut);
            (markdown, true)
        }
        None => (markdown, false),
    }
}

#[cfg(test)]
#[path = "../tests/fixtures/mod.rs"]
mod fixtures;

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
