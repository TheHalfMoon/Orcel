//! The WI-05 fixture corpus, generated from source on every run so each
//! input is small and reviewable here rather than a committed binary.
//! Shared by the parser's unit tests (`src/main.rs`) and the contained
//! end-to-end tests (`tests/contained.rs`).
#![allow(dead_code)]

use std::io::{Cursor, Write as _};

/// A PDF from object bodies numbered 1.. (object 1 is the catalog), with a
/// correct cross-reference table.
pub fn pdf(objects: &[String], trailer_extra: &str) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::new();
    for (index, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", index + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for offset in offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R {trailer_extra}>>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

fn stream(content: &str) -> String {
    format!(
        "<< /Length {} >>\nstream\n{content}\nendstream",
        content.len()
    )
}

/// One page drawing `lines` in Helvetica; `catalog_extra` and `page_extra`
/// are spliced into those dictionaries.
pub fn text_pdf_with(lines: &[&str], catalog_extra: &str, page_extra: &str) -> Vec<u8> {
    let mut content = String::from("BT /F1 12 Tf 14 TL 72 720 Td");
    for line in lines {
        content.push_str(&format!(" ({line}) Tj T*"));
    }
    content.push_str(" ET");
    pdf(
        &[
            format!("<< /Type /Catalog /Pages 2 0 R {catalog_extra}>>"),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".into(),
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
                 /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R {page_extra}>>"
            ),
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".into(),
            stream(&content),
        ],
        "",
    )
}

/// The normal PDF of the corpus.
pub fn text_pdf() -> Vec<u8> {
    text_pdf_with(
        &[
            "Orcel WI-05 fixture",
            "The quick brown fox jumps over the lazy dog.",
        ],
        "",
        "",
    )
}

/// A document-level JavaScript action that runs on open.
pub fn javascript_pdf() -> Vec<u8> {
    text_pdf_with(
        &["Orcel WI-05 fixture"],
        "/OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> ",
        "",
    )
}

/// A launch action (starts a program) on the page.
pub fn launch_pdf() -> Vec<u8> {
    text_pdf_with(
        &["Orcel WI-05 fixture"],
        "",
        "/AA << /O << /S /Launch /F (calc.exe) >> >> ",
    )
}

/// The standard security handler (RC4, revision 2) in the trailer: a
/// password-protected document. Its keys are arbitrary, so no password
/// opens it; the parser must refuse it before trying.
pub fn encrypted_pdf() -> Vec<u8> {
    let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let mut objects = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".into(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>".into(),
    ];
    objects.push(format!(
        "<< /Filter /Standard /V 1 /R 2 /O <{key}> /U <{key}> /P -4 >>"
    ));
    pdf(
        &objects,
        "/Encrypt 4 0 R /ID [<00112233445566778899aabbccddeeff> <00112233445566778899aabbccddeeff>] ",
    )
}

/// `pages` blank pages under one page tree node.
pub fn pages_pdf(pages: usize) -> Vec<u8> {
    let kids: Vec<String> = (0..pages)
        .map(|index| format!("{} 0 R", index + 3))
        .collect();
    let mut objects = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        format!(
            "<< /Type /Pages /Kids [{}] /Count {pages} >>",
            kids.join(" ")
        ),
    ];
    for _ in 0..pages {
        objects.push("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>".into());
    }
    pdf(&objects, "")
}

/// An array nested `depth` deep in the page dictionary.
pub fn nested_pdf(depth: usize) -> Vec<u8> {
    let nested = format!("/OrcelNested {}{} ", "[".repeat(depth), "]".repeat(depth));
    text_pdf_with(&["Orcel WI-05 fixture"], "", &nested)
}

/// A PDF header followed by a cut-off object and no cross-reference table.
pub fn malformed_pdf() -> Vec<u8> {
    b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R\n".to_vec()
}

/// A page with no text: a scanned document as far as text goes.
pub fn blank_pdf() -> Vec<u8> {
    pages_pdf(1)
}

/// A deflated zip from (name, bytes) entries.
pub fn zip(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, bytes) in entries {
        writer.start_file(*name, options).expect("zip entry");
        writer.write_all(bytes).expect("zip write");
    }
    writer.finish().expect("zip finish").into_inner()
}

const W_NS: &str = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const R_NS: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

fn content_types(extra: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
         <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
         <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
         <Override PartName=\"/word/document.xml\" \
         ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>\
         {extra}</Types>"
    )
    .into_bytes()
}

fn root_rels() -> Vec<u8> {
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
     <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
     <Relationship Id=\"rId1\" \
     Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" \
     Target=\"word/document.xml\"/></Relationships>"
        .as_bytes()
        .to_vec()
}

fn document_xml(body: &str, section: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
         <w:document xmlns:w=\"{W_NS}\" xmlns:r=\"{R_NS}\"><w:body>{body}\
         <w:sectPr>{section}</w:sectPr></w:body></w:document>"
    )
    .into_bytes()
}

fn paragraph(text: &str) -> String {
    format!("<w:p><w:r><w:t>{text}</w:t></w:r></w:p>")
}

/// A DOCX whose body is `paragraphs`, plus `extra` entries.
pub fn docx_with(paragraphs: &[&str], extra: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let body: String = paragraphs.iter().map(|text| paragraph(text)).collect();
    let mut entries = vec![
        ("[Content_Types].xml", content_types("")),
        ("_rels/.rels", root_rels()),
        ("word/document.xml", document_xml(&body, "")),
    ];
    entries.extend(extra);
    zip(&entries)
}

/// The normal Office document of the corpus: a body, a header (the donor's
/// header pass) and an external hyperlink relationship that is never
/// followed.
pub fn docx() -> Vec<u8> {
    let body = format!(
        "{}{}",
        paragraph("Orcel WI-05 office fixture"),
        paragraph("Second paragraph of the body.")
    );
    let section = "<w:headerReference w:type=\"default\" r:id=\"rIdHeader\"/>";
    let rels = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
        <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
        <Relationship Id=\"rIdHeader\" \
        Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/header\" \
        Target=\"header1.xml\"/>\
        <Relationship Id=\"rIdLink\" \
        Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\" \
        Target=\"http://127.0.0.1:9/never-fetched\" TargetMode=\"External\"/>\
        </Relationships>";
    let header = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><w:hdr xmlns:w=\"{W_NS}\">{}</w:hdr>",
        paragraph("Running header text")
    );
    zip(&[
        ("[Content_Types].xml", content_types("")),
        ("_rels/.rels", root_rels()),
        ("word/document.xml", document_xml(&body, section)),
        ("word/_rels/document.xml.rels", rels.as_bytes().to_vec()),
        ("word/header1.xml", header.into_bytes()),
    ])
}

/// A macro-enabled document: a VBA project part.
pub fn macro_docx() -> Vec<u8> {
    docx_with(
        &["Orcel WI-05 office fixture"],
        vec![(
            "word/vbaProject.bin",
            b"Attribute VB_Name = \"Module1\"".to_vec(),
        )],
    )
}

/// A zip bomb: one part that inflates from about 20 KiB to 20 MiB.
pub fn zip_bomb_docx() -> Vec<u8> {
    let padding = " ".repeat(20 * 1024 * 1024);
    let body = format!("{}{padding}", paragraph("Orcel WI-05 office fixture"));
    zip(&[
        ("[Content_Types].xml", content_types("")),
        ("_rels/.rels", root_rels()),
        ("word/document.xml", document_xml(&body, "")),
    ])
}

/// Many parts each just under the ratio floor that together inflate past
/// the archive budget: the declared sizes pass, the total does not.
pub fn spread_bomb_docx() -> Vec<u8> {
    let part = vec![b' '; 1024 * 1024];
    let names: Vec<String> = (0..65)
        .map(|index| format!("word/media/pad{index}.xml"))
        .collect();
    let mut entries = vec![
        ("[Content_Types].xml", content_types("")),
        ("_rels/.rels", root_rels()),
        ("word/document.xml", document_xml(&paragraph("x"), "")),
    ];
    for name in &names {
        entries.push((name.as_str(), part.clone()));
    }
    zip(&entries)
}

/// Body elements nested `depth` deep.
pub fn nested_docx(depth: usize) -> Vec<u8> {
    let body = format!(
        "{}{}{}",
        "<w:sdt><w:sdtContent>".repeat(depth / 2),
        paragraph("deep"),
        "</w:sdtContent></w:sdt>".repeat(depth / 2)
    );
    zip(&[
        ("[Content_Types].xml", content_types("")),
        ("_rels/.rels", root_rels()),
        ("word/document.xml", document_xml(&body, "")),
    ])
}

/// A part with a DTD (entity expansion is never allowed).
pub fn dtd_docx() -> Vec<u8> {
    let xml = format!(
        "<?xml version=\"1.0\"?><!DOCTYPE w:document [<!ENTITY a \"aaaaaaaa\">]>\
         <w:document xmlns:w=\"{W_NS}\"><w:body>{}</w:body></w:document>",
        paragraph("&a;")
    );
    zip(&[
        ("[Content_Types].xml", content_types("")),
        ("_rels/.rels", root_rels()),
        ("word/document.xml", xml.into_bytes()),
    ])
}

/// A deck with `slides` slide parts.
pub fn pptx(slides: usize) -> Vec<u8> {
    let names: Vec<String> = (1..=slides)
        .map(|index| format!("ppt/slides/slide{index}.xml"))
        .collect();
    let mut entries = vec![("[Content_Types].xml", content_types(""))];
    for name in &names {
        entries.push((name.as_str(), b"<p:sld/>".to_vec()));
    }
    zip(&entries)
}

/// An encrypted OOXML package: an OLE compound file carrying the
/// `EncryptionInfo` stream name.
pub fn encrypted_office() -> Vec<u8> {
    let mut bytes = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    bytes.resize(512, 0);
    bytes.extend("EncryptionInfo".encode_utf16().flat_map(u16::to_le_bytes));
    bytes.resize(1024, 0);
    bytes
}

/// A legacy binary Office file (OLE without encryption).
pub fn legacy_office() -> Vec<u8> {
    let mut bytes = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    bytes.resize(1024, 0);
    bytes
}

/// A DOCX whose text is longer than the character bound, made of varied
/// words so it compresses like prose (well under the ratio bound).
pub fn long_docx(chars: usize) -> Vec<u8> {
    let mut seed = 0x2545_f491_u32;
    let mut paragraphs = Vec::new();
    let mut total = 0;
    while total < chars {
        let mut text = String::new();
        while text.len() < 2_000 {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let length = 2 + (seed % 9) as usize;
            for step in 0..length {
                text.push(char::from(b'a' + ((seed >> (step % 24)) % 26) as u8));
            }
            text.push(' ');
        }
        total += text.len();
        paragraphs.push(text);
    }
    let refs: Vec<&str> = paragraphs.iter().map(String::as_str).collect();
    docx_with(&refs, Vec::new())
}

/// A zlib stream that inflates to `zeros` zero bytes, written by hand so the
/// test never inflates it itself: one fixed-Huffman deflate block holding a
/// literal 0 and then length-258, distance-1 copies (13 bits per 258 bytes).
pub fn zlib_zeros(zeros: usize) -> Vec<u8> {
    struct Bits {
        out: Vec<u8>,
        bit: u32,
    }
    impl Bits {
        // Huffman codes go most significant bit first.
        fn code(&mut self, code: u32, length: u32) {
            for index in (0..length).rev() {
                self.push((code >> index) & 1);
            }
        }
        fn push(&mut self, bit: u32) {
            if self.bit == 0 {
                self.out.push(0);
            }
            if bit == 1 {
                *self.out.last_mut().expect("a byte") |= 1 << self.bit;
            }
            self.bit = (self.bit + 1) % 8;
        }
    }
    assert!(
        zeros >= 1 && (zeros - 1).is_multiple_of(258),
        "1 + 258 * n zeros"
    );
    let mut bits = Bits {
        out: Vec::new(),
        bit: 0,
    };
    bits.push(1); // BFINAL
    bits.push(1); // BTYPE = 01 (fixed Huffman), low bit first
    bits.push(0);
    bits.code(0b0011_0000, 8); // literal 0
    for _ in 0..(zeros - 1) / 258 {
        bits.code(0b1100_0101, 8); // length symbol 285 = 258
        bits.code(0, 5); // distance symbol 0 = 1
    }
    bits.code(0, 7); // end of block (256)
    let mut stream = vec![0x78, 0x01];
    stream.extend_from_slice(&bits.out);
    // Adler-32 of `zeros` zero bytes: a stays 1, b grows by 1 per byte.
    let b = (zeros % 65_521) as u32;
    stream.extend_from_slice(&((b << 16) | 1).to_be_bytes());
    stream
}

/// A PDF from binary object bodies numbered 1.. (object 1 is the catalog).
pub fn binary_pdf(objects: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (index, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", offsets.len() + 1).as_bytes(),
    );
    for offset in &offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            offsets.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// A FlateDecode stream object of about 66 MiB of zeros (past the
/// per-stream bound) from about 450 KiB, with `dict_extra` in its dictionary.
fn bomb_stream(dict_extra: &str) -> Vec<u8> {
    let data = zlib_zeros(1 + 258 * 270_000);
    let mut stream = format!(
        "<< {dict_extra}/Length {} /Filter /FlateDecode >>\nstream\n",
        data.len()
    )
    .into_bytes();
    stream.extend_from_slice(&data);
    stream.extend_from_slice(b"\nendstream");
    stream
}

/// A page whose content stream is a small FlateDecode stream that inflates
/// past the per-stream bound (a PDF flate bomb).
pub fn flate_bomb_pdf() -> Vec<u8> {
    binary_pdf(&[
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>".to_vec(),
        bomb_stream(""),
    ])
}

/// The flate bomb in a form XObject whose dictionary uses a bare structure
/// name (`/S Code`) in a tagged document. lopdf drops that object as written;
/// pdf-inspector rewrites `/S Code` to `/S /Code` before loading, which
/// brings it back, and would then decode it without a bound. The page also
/// carries text, so a pre-flight that missed the bomb would let it through.
pub fn struct_name_bomb_pdf() -> Vec<u8> {
    let content = "BT /F1 12 Tf 72 720 Td (Orcel WI-05 fixture) Tj ET /X1 Do";
    binary_pdf(&[
        b"<< /Type /Catalog /Pages 2 0 R /StructTreeRoot 6 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
          /Resources << /Font << /F1 7 0 R >> /XObject << /X1 4 0 R >> >> /Contents 5 0 R >>"
            .to_vec(),
        bomb_stream("/Type /XObject /Subtype /Form /BBox [0 0 1 1] /S Code "),
        format!(
            "<< /Length {} >>\nstream\n{content}\nendstream",
            content.len()
        )
        .into_bytes(),
        b"<< /Type /StructTreeRoot >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
    ])
}

/// The zero bytes of the largest `zlib_zeros` stream that stays within the
/// per-stream bound (64 MiB): 67,108,639 bytes from about 413 KiB.
pub const FORM_ZEROS: usize = 1 + 258 * 260_111;

/// #391: one form XObject that inflates to just under 64 MiB, drawn by every
/// one of `pages` pages, each of which also carries text. Its one decode
/// fits the pre-flight's bounds (64 MiB per stream, 256 MiB in all), so it
/// gets past them; pdf-inspector decodes it again on every page that draws
/// it, so four draws exhaust the decode budget. `zeros` sets the form's
/// size (at most [`FORM_ZEROS`]).
pub fn repeated_form_pdf(pages: usize, zeros: usize) -> Vec<u8> {
    let data = zlib_zeros(zeros);
    let mut form = format!(
        "<< /Type /XObject /Subtype /Form /BBox [0 0 1 1] /Length {} /Filter /FlateDecode >>\nstream\n",
        data.len()
    )
    .into_bytes();
    form.extend_from_slice(&data);
    form.extend_from_slice(b"\nendstream");
    let content = "BT /F1 12 Tf 72 720 Td (Orcel WI-05 fixture) Tj ET /X1 Do";
    let kids: Vec<String> = (0..pages)
        .map(|index| format!("{} 0 R", index + 6))
        .collect();
    let mut objects = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        format!(
            "<< /Type /Pages /Kids [{}] /Count {pages} >>",
            kids.join(" ")
        )
        .into_bytes(),
        form,
        format!(
            "<< /Length {} >>\nstream\n{content}\nendstream",
            content.len()
        )
        .into_bytes(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
    ];
    for _ in 0..pages {
        objects.push(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
              /Resources << /Font << /F1 5 0 R >> /XObject << /X1 3 0 R >> >> /Contents 4 0 R >>"
                .to_vec(),
        );
    }
    binary_pdf(&objects)
}

/// Debug builds only: the input that makes the parser abort, so a test can
/// prove a crash is contained and reported (`src/main.rs`).
pub const ABORT_TRIGGER: &[u8] = b"ORCEL-WI05-TEST-ABORT";

/// Debug builds only: a prefix that makes the parser run the PDF after it
/// through pdf-inspector alone, with no pre-flight and no parity watch
/// (`src/main.rs`).
pub const UNCHECKED_TRIGGER: &[u8] = b"ORCEL-WI05-TEST-UNCHECKED\n";

/// A macro project under an innocent name, recognisable only by the content
/// type the package declares for it.
pub fn renamed_macro_docx() -> Vec<u8> {
    zip(&[
        (
            "[Content_Types].xml",
            content_types(
                "<Override PartName=\"/word/data.bin\" \
                 ContentType=\"application/vnd.ms-office.vbaProject\"/>",
            ),
        ),
        ("_rels/.rels", root_rels()),
        ("word/document.xml", document_xml(&paragraph("x"), "")),
        ("word/data.bin", b"Attribute VB_Name = \"Module1\"".to_vec()),
    ])
}

/// `slides` slides under names that are not `ppt/slides/slideN.xml`,
/// recognisable only by their declared content type.
pub fn renamed_slides_pptx(slides: usize) -> Vec<u8> {
    let overrides: String = (1..=slides)
        .map(|index| {
            format!(
                "<Override PartName=\"/ppt/p{index}.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slide+xml\"/>"
            )
        })
        .collect();
    let names: Vec<String> = (1..=slides)
        .map(|index| format!("ppt/p{index}.xml"))
        .collect();
    let mut entries = vec![("[Content_Types].xml", content_types(&overrides))];
    for name in &names {
        entries.push((name.as_str(), b"<p:sld/>".to_vec()));
    }
    zip(&entries)
}

/// A non-canonical `%PDF-` marker first and the real, canonical header on
/// a later line: pdf-inspector would start at the second, lopdf at the first.
pub fn shifted_header_pdf() -> Vec<u8> {
    let mut bytes = b"%PDF-x not a version\n".to_vec();
    bytes.extend_from_slice(&text_pdf());
    bytes
}

/// A one-page PDF whose cross-reference entries are 19 bytes (a bare LF
/// instead of the two-byte end of line): lopdf alone refuses to load it, and
/// pdf-inspector loads it only through its container repair
/// (`rebuild_short_xref_entries`). The shape is pdf-inspector 1.21.0's own
/// test document for that path (`synthetic_pdf_with_xref_terminator`).
pub fn short_xref_pdf() -> Vec<u8> {
    let header = "%PDF-1.7\n";
    let obj1 = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";
    let obj2 = "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n";
    let obj3 = "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n";
    let o1 = header.len();
    let o2 = o1 + obj1.len();
    let o3 = o2 + obj2.len();
    let body = format!("{header}{obj1}{obj2}{obj3}");
    let xref = body.len();
    format!(
        "{body}xref\n0 4\n0000000000 65535 f\n{o1:010} 00000 n\n{o2:010} 00000 n\n\
         {o3:010} 00000 n\ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    )
    .into_bytes()
}

/// A tagged PDF with a bare structure name that pdf-inspector rewrites.
pub fn bare_struct_name_pdf() -> Vec<u8> {
    text_pdf_with(
        &["Orcel WI-05 fixture"],
        "/StructTreeRoot << /Type /StructTreeRoot >> ",
        "/OrcelTag << /S P >> ",
    )
}

/// The normal page plus `containers` object streams that each hold object
/// 9, which the cross-reference table does not place. With two containers
/// lopdf's choice of copy depends on task order.
pub fn object_stream_member_pdf(containers: usize) -> Vec<u8> {
    let content = "BT /F1 12 Tf 72 720 Td (Orcel WI-05 fixture) Tj ET";
    let mut objects = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".into(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
         /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
            .into(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".into(),
        stream(content),
    ];
    for copy in 0..containers {
        let body = format!("9 0 << /OrcelCopy {copy} >>");
        objects.push(format!(
            "<< /Type /ObjStm /N 1 /First 4 /Length {} >>\nstream\n{body}\nendstream",
            body.len()
        ));
    }
    pdf(&objects, "")
}
