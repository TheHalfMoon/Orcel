//! WI-05: the contract between orceld and the confined document parser,
//! `apps/orcel-doc-parser` (std only, like [`crate::contained`]).
//!
//! The parser converts one approved, already-downloaded PDF or Office file to
//! Markdown. It only ever runs under the contained tier: [`spec`] is the one
//! spec orceld and the parser's own end-to-end tests use, so the boundary the
//! tests prove is the boundary orceld asks for. The parser
//!
//! - reads exactly one file, `input`, inside a private directory that holds
//!   nothing else and is the only extra root (read-only);
//! - has no writable root: its output is one frame on stdout, bounded here.
//!   Like every contained run it has a private working directory, which
//!   orceld creates empty and removes afterwards;
//! - has no network, cannot create processes, and runs under the CPU, memory,
//!   open-file and wall-clock limits in [`limits`].
//!
//! # Frame (`orcel-doc-parser/1`)
//!
//! One header line, then exactly the bytes it names:
//!
//! ```text
//! orcel-doc-parser/1 ok <format> <pages> <chars> <truncated> <bytes>\n<markdown>
//! orcel-doc-parser/1 error <code>\n
//! ```
//!
//! `format` is one of [`DocumentFormat`], `truncated` is `0` or `1`, and a
//! refusal carries only a closed [`ParseRefusal`] code, never text taken from
//! the document. The parser exits 0 after `ok` and [`EXIT_REFUSED`] after
//! `error`; any other exit, or a frame that does not decode, is a crash and
//! fails closed. The Markdown is untrusted document content: data to show or
//! summarise, never an instruction, and it carries no authority.

use crate::contained::{ContainedLimits, ContainedSpec};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const FRAME_MAGIC: &str = "orcel-doc-parser/1";
/// The parser's exit status after an `error` frame.
pub const EXIT_REFUSED: i64 = 2;
/// The only file in the input directory.
pub const INPUT_NAME: &str = "input";

/// Largest input the parser reads.
pub const MAX_INPUT_BYTES: u64 = 50 * 1024 * 1024;
/// A PDF with more pages, or a deck or workbook with more slides or sheets,
/// is refused rather than cut.
pub const MAX_PAGES: usize = 500;
/// Markdown longer than this is cut at a character boundary and flagged.
pub const MAX_CHARS: usize = 1_000_000;
/// Deepest PDF object nesting the parser accepts (arrays and dictionaries).
pub const MAX_NESTING: usize = 32;
/// Deepest element nesting of one Office XML part (drawings and nested
/// tables legitimately go deeper than PDF objects).
pub const MAX_XML_NESTING: usize = 128;
/// Office archives: entry count, total inflated bytes, and the largest
/// inflation ratio of one entry above [`RATIO_FLOOR_BYTES`].
pub const MAX_ARCHIVE_ENTRIES: usize = 1_000;
pub const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_ENTRY_RATIO: u64 = 100;
pub const RATIO_FLOOR_BYTES: u64 = 1024 * 1024;
/// PDFs: no one stream may inflate past [`MAX_ARCHIVE_BYTES`], and all of a
/// document's streams together not past this.
pub const MAX_PDF_INFLATED_BYTES: u64 = 256 * 1024 * 1024;

const MAX_HEADER_BYTES: usize = 256;

/// The contained-tier limits of one parse.
pub fn limits() -> ContainedLimits {
    ContainedLimits {
        timeout: Duration::from_secs(30),
        stdout_bytes: MAX_HEADER_BYTES + MAX_CHARS * 4,
        stderr_bytes: 64 * 1024,
        memory_bytes: 1024 * 1024 * 1024,
        cpu_seconds: 30,
        open_files: 64,
    }
}

/// The spec for one parse: `parser` reads `input_dir/input` and nothing
/// else. Every path must be canonical (the helper refuses links).
pub fn spec(parser: PathBuf, input_dir: &Path, workdir: PathBuf) -> ContainedSpec {
    ContainedSpec {
        executable: parser,
        argv: vec![input_dir.join(INPUT_NAME).to_string_lossy().into_owned()],
        workdir,
        readable: vec![input_dir.to_path_buf()],
        writable: Vec::new(),
        limits: limits(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentFormat {
    Pdf,
    Docx,
    Pptx,
    Xlsx,
}

impl DocumentFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pdf => "pdf",
            Self::Docx => "docx",
            Self::Pptx => "pptx",
            Self::Xlsx => "xlsx",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [Self::Pdf, Self::Docx, Self::Pptx, Self::Xlsx]
            .into_iter()
            .find(|format| format.as_str() == text)
    }
}

/// Why the parser refused an input. Every refusal fails closed: no Markdown
/// is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseRefusal {
    /// Not exactly one input argument, or the input cannot be read.
    Usage,
    InputTooLarge,
    /// Not a PDF or an OOXML document (DOCX, PPTX, XLSX).
    UnsupportedFormat,
    Malformed,
    /// A password-protected or encrypted PDF or Office file.
    Encrypted,
    /// PDF JavaScript or launch actions, or Office macros.
    ActiveContent,
    /// An archive past its entry, size or inflation-ratio bound.
    ArchiveLimit,
    TooManyPages,
    NestingTooDeep,
    /// A PDF with no text layer (scanned); Orcel runs no OCR.
    NoText,
}

impl ParseRefusal {
    pub const ALL: [Self; 10] = [
        Self::Usage,
        Self::InputTooLarge,
        Self::UnsupportedFormat,
        Self::Malformed,
        Self::Encrypted,
        Self::ActiveContent,
        Self::ArchiveLimit,
        Self::TooManyPages,
        Self::NestingTooDeep,
        Self::NoText,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::InputTooLarge => "input_too_large",
            Self::UnsupportedFormat => "unsupported_format",
            Self::Malformed => "malformed",
            Self::Encrypted => "encrypted",
            Self::ActiveContent => "active_content",
            Self::ArchiveLimit => "archive_limit",
            Self::TooManyPages => "too_many_pages",
            Self::NestingTooDeep => "nesting_too_deep",
            Self::NoText => "no_text",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.as_str() == text)
    }
}

/// A converted document. `markdown` is untrusted document content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDocument {
    pub format: DocumentFormat,
    pub pages: usize,
    pub chars: usize,
    pub truncated: bool,
    pub markdown: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The parser refused the input with a closed code.
    Refused(ParseRefusal),
    /// The output is not a well-formed frame within its bounds.
    Broken(&'static str),
}

pub fn encode_ok(document: &ParsedDocument) -> Vec<u8> {
    let mut out = format!(
        "{FRAME_MAGIC} ok {} {} {} {} {}\n",
        document.format.as_str(),
        document.pages,
        document.chars,
        u8::from(document.truncated),
        document.markdown.len()
    )
    .into_bytes();
    out.extend_from_slice(document.markdown.as_bytes());
    out
}

pub fn encode_refusal(refusal: ParseRefusal) -> Vec<u8> {
    format!("{FRAME_MAGIC} error {}\n", refusal.as_str()).into_bytes()
}

/// Decode the parser's stdout. Everything is checked against this module's
/// bounds: the character count must match the Markdown and stay within
/// [`MAX_CHARS`], and nothing may follow the bytes the header names.
pub fn decode_frame(bytes: &[u8]) -> Result<ParsedDocument, FrameError> {
    let broken = FrameError::Broken;
    let newline = bytes
        .iter()
        .take(MAX_HEADER_BYTES)
        .position(|byte| *byte == b'\n')
        .ok_or(broken("no header line"))?;
    let header =
        std::str::from_utf8(&bytes[..newline]).map_err(|_| broken("header is not UTF-8"))?;
    let body = &bytes[newline + 1..];
    let rest = header
        .strip_prefix(FRAME_MAGIC)
        .and_then(|rest| rest.strip_prefix(' '))
        .ok_or(broken("wrong magic"))?;
    let fields: Vec<&str> = rest.split(' ').collect();
    match fields[..] {
        ["error", code] => {
            if !body.is_empty() {
                return Err(broken("a refusal carries content"));
            }
            Err(FrameError::Refused(
                ParseRefusal::parse(code).ok_or(broken("unknown refusal code"))?,
            ))
        }
        ["ok", format, pages, chars, truncated, length] => {
            let number = |text: &str| {
                if text.is_empty() || (text.len() > 1 && text.starts_with('0')) {
                    return Err(broken("bad number"));
                }
                text.parse::<usize>().map_err(|_| broken("bad number"))
            };
            let format = DocumentFormat::parse(format).ok_or(broken("unknown format"))?;
            let pages = number(pages)?;
            let chars = number(chars)?;
            let length = number(length)?;
            let truncated = match truncated {
                "0" => false,
                "1" => true,
                _ => return Err(broken("bad truncation flag")),
            };
            if pages > MAX_PAGES {
                return Err(broken("page count exceeds the bound"));
            }
            if body.len() != length {
                return Err(broken("content length does not match the header"));
            }
            let markdown =
                String::from_utf8(body.to_vec()).map_err(|_| broken("content is not UTF-8"))?;
            if markdown.chars().count() != chars || chars > MAX_CHARS {
                return Err(broken(
                    "character count does not match or exceeds the bound",
                ));
            }
            Ok(ParsedDocument {
                format,
                pages,
                chars,
                truncated,
                markdown,
            })
        }
        _ => Err(broken("wrong field count")),
    }
}

#[cfg(test)]
#[path = "document_parser_tests.rs"]
mod tests;
