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
