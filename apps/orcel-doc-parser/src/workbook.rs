//! XLSX to Markdown with source cell references (F5, Journey 2). Orcel's own
//! code, not from the donor: `document.rs` runs its pre-flight over the whole
//! package first, then hands an XLSX here, so anydoc's sheet reader is not on
//! this path.
//!
//! Every cell with content is one table row: its reference, the value as last
//! saved, its type, its number format and its formula. A report can therefore
//! name the cell a figure came from.
//!
//! Nothing is calculated and nothing is followed. A value is what the file
//! says was saved. A formula that may reach outside the workbook is marked
//! `external`, since its saved value may be stale, and links, connections, pivot
//! caches and query tables are only counted: their targets are never read, shown
//! or refreshed. That mark is a text check, so it can only be a caution.
//!
//! **A structural element out of its place is refused, not skipped.** A value
//! that's shown must be the value the cell holds, so only elements in the
//! spreadsheet namespace count, and each element this reader relies on must sit
//! exactly where it reads it ([`check_placement`]): inside `mc:AlternateContent`
//! or any other wrapper, it could change what a spreadsheet application shows.
//! Other content in such wrappers, which Excel writes for its own features, is
//! left alone. A cell holding anything unexpected is `malformed`, as is a reference
//! that isn't valid, that appears twice, or that disagrees with its row.
//!
//! Cell content is untrusted. [`escaped`] keeps each cell on its own row, so
//! content can never pass itself off as another cell.

use crate::document::{read_zip_text, relationship_part_for, resolve_part, ZipReadBudget};
use orcel_provider_process::document_parser::{ParseRefusal, MAX_CHARS, MAX_PAGES};
use roxmltree::{Document, Node, ParsingOptions};
use std::collections::{HashMap, HashSet};
use std::io::Cursor;

/// One part's XML tree: elements and text, and attributes. These keep a typical
/// part well inside the contained memory limit, and the per-element bound keeps
/// the XML parser's duplicate-attribute check from going quadratic. Past any of
/// them the workbook is `archive_limit`. A sheet this size can't fit in the frame
/// anyway. Containment remains the final limit on what's left.
const MAX_PART_NODES: u32 = 2_000_000;
const MAX_PART_ATTRIBUTES: usize = 2_000_000;
const MAX_ELEMENT_ATTRIBUTES: usize = 256;
/// Rows in one sheet and cells in the workbook, counted whether or not they hold
/// content. Far past what the frame can carry; past them it's `archive_limit`.
const MAX_SHEET_ROWS: usize = 200_000;
const MAX_WORKBOOK_CELLS: usize = 500_000;
const MAX_COLUMN: u32 = 18_278; // ZZZ: what three letters can name; Excel stops at XFD.
const MAX_ROW: u32 = 1_048_576;

const SHEET_NAMESPACES: [&str; 2] = [
    "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "http://purl.oclc.org/ooxml/spreadsheetml/main",
];
const RELATIONSHIP_ATTRIBUTE_NAMESPACES: [&str; 2] = [
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "http://purl.oclc.org/ooxml/officeDocument/relationships",
];
/// Each element this reader relies on, and the parents it may have, per part.
const WORKBOOK_PLACES: [(&str, &[&str]); 5] = [
    ("sheets", &["workbook"]),
    ("sheet", &["sheets"]),
    ("calcPr", &["workbook"]),
    ("definedNames", &["workbook"]),
    ("definedName", &["definedNames"]),
];
const WORKSHEET_PLACES: [(&str, &[&str]); 8] = [
    ("sheetData", &["worksheet"]),
    ("row", &["sheetData"]),
    ("c", &["row"]),
    ("f", &["c"]),
    ("v", &["c"]),
    ("is", &["c"]),
    ("t", &["is", "r", "rPh"]),
    ("r", &["is"]),
];
const STRINGS_PLACES: [(&str, &[&str]); 3] =
    [("si", &["sst"]), ("t", &["si", "r", "rPh"]), ("r", &["si"])];
const STYLES_PLACES: [(&str, &[&str]); 4] = [
    ("numFmts", &["styleSheet"]),
    ("numFmt", &["numFmts", "dxf"]),
    ("cellXfs", &["styleSheet"]),
    ("xf", &["cellXfs", "cellStyleXfs"]),
];
const PACKAGE_RELATIONSHIPS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
/// Functions whose value comes from outside the workbook, or may.
const REACHING_FUNCTIONS: [&str; 13] = [
    "WEBSERVICE(",
    "RTD(",
    "IMAGE(",
    "INDIRECT(",
    "STOCKHISTORY(",
    "CUBEVALUE(",
    "CUBEMEMBER(",
    "CUBEMEMBERPROPERTY(",
    "CUBERANKEDMEMBER(",
    "CUBEKPIMEMBER(",
    "CUBESET(",
    "CUBESETCOUNT(",
    "CALL(",
];

/// The Markdown and the number of sheets.
pub fn convert(bytes: &[u8]) -> Result<(String, usize), ParseRefusal> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| ParseRefusal::Malformed)?;
    let mut budget = ZipReadBudget::for_workbook();
    let mut part = |name: &str| read_zip_text(&mut archive, name, &mut budget);

    let root_relationships = relationships(&part("_rels/.rels").ok_or(ParseRefusal::Malformed)?)?;
    let main = root_relationships
        .iter()
        .find(|relationship| relationship.kind == "officedocument" && !relationship.external)
        .and_then(|relationship| resolve_part("", &relationship.target))
        .ok_or(ParseRefusal::Malformed)?;
    if !main.to_ascii_lowercase().ends_with(".xml") {
        // A binary workbook (XLSB): not one of the three admitted readers.
        return Err(ParseRefusal::UnsupportedFormat);
    }
    let workbook_xml = part(&main).ok_or(ParseRefusal::Malformed)?;
    let related = match part(&relationship_part_for(&main)) {
        Some(xml) => relationships(&xml)?,
        None => Vec::new(),
    };
    let workbook = parse(&workbook_xml)?;
    let root = workbook.root_element();
    if !is_sheet_element(root, "workbook") {
        return Err(ParseRefusal::Malformed);
    }
    check_placement(root, &WORKBOOK_PLACES)?;

    let mut sheets = Vec::new();
    let mut names = HashSet::new();
    for sheet in sheet_children(root, "sheets").flat_map(|list| sheet_children(list, "sheet")) {
        if sheets.len() == MAX_PAGES {
            return Err(ParseRefusal::TooManyPages);
        }
        let id = sheet
            .attributes()
            .find(|attribute| {
                attribute.name() == "id"
                    && attribute
                        .namespace()
                        .is_some_and(|ns| RELATIONSHIP_ATTRIBUTE_NAMESPACES.contains(&ns))
            })
            .map(|attribute| attribute.value())
            .ok_or(ParseRefusal::Malformed)?;
        let relationship = related
            .iter()
            .find(|relationship| relationship.id == id)
            .filter(|relationship| !relationship.external)
            .ok_or(ParseRefusal::Malformed)?;
        let name = sheet.attribute("name").ok_or(ParseRefusal::Malformed)?;
        // The name as it reads, so an escape can't make a second of the same.
        if !names.insert(decoded_xstring(name).to_lowercase()) {
            return Err(ParseRefusal::Malformed);
        }
        let part_name = match relationship.kind.as_str() {
            "worksheet" => {
                Some(resolve_part(&main, &relationship.target).ok_or(ParseRefusal::Malformed)?)
            }
            "chartsheet" | "dialogsheet" => None,
            _ => return Err(ParseRefusal::Malformed),
        };
        sheets.push(Sheet {
            name,
            hidden: sheet.attribute("state").unwrap_or("visible") != "visible",
            part: part_name,
        });
    }
    if sheets.is_empty() {
        return Err(ParseRefusal::Malformed);
    }

    let related_part = |kind: &str| {
        related
            .iter()
            .find(|relationship| relationship.kind == kind && !relationship.external)
            .and_then(|relationship| resolve_part(&main, &relationship.target))
    };
    let strings = match related_part("sharedstrings") {
        Some(name) => shared_strings(&part(&name).ok_or(ParseRefusal::Malformed)?)?,
        None => Vec::new(),
    };
    let formats = match related_part("styles") {
        Some(name) => number_formats(&part(&name).ok_or(ParseRefusal::Malformed)?)?,
        None => Vec::new(),
    };

    let mut query_tables = 0;
    for sheet in &sheets {
        if let Some(rels) = sheet
            .part
            .as_deref()
            .and_then(|name| part(&relationship_part_for(name)))
        {
            query_tables += relationships(&rels)?
                .iter()
                .filter(|relationship| relationship.kind == "querytable")
                .count();
        }
    }
    let count = |kind: &str| related.iter().filter(|r| r.kind == kind).count();
    let mut reaching_names = 0;
    for name in
        sheet_children(root, "definedNames").flat_map(|list| sheet_children(list, "definedName"))
    {
        if is_external_formula(&decoded_xstring(&element_text(name)?)) {
            reaching_names += 1;
        }
    }

    let mut out = String::from(
        "# Workbook\n\nValues are as last saved. Nothing was calculated, and no link was followed or refreshed.\n",
    );
    out.push_str(&format!("\nSheets ({}):\n", sheets.len()));
    for sheet in &sheets {
        out.push_str(&format!("- {}\n", sheet.title()));
    }
    let mut notices = Vec::new();
    for (found, what) in [
        (count("externallink"), "External workbook links"),
        (reaching_names, "Defined names that may reach outside"),
        (count("connections"), "Data connection parts"),
        (count("pivotcachedefinition"), "Pivot caches"),
        (query_tables, "Query tables"),
    ] {
        if found > 0 {
            notices.push(format!(
                "{what}: {found}. Not used or refreshed, so values depending on them may be stale."
            ));
        }
    }
    for calculation in sheet_children(root, "calcPr") {
        if matches!(calculation.attribute("fullCalcOnLoad"), Some("1" | "true")) {
            notices.push(
                "This workbook asks to be recalculated when opened, so saved values may be stale."
                    .to_owned(),
            );
        }
        if calculation.attribute("calcMode") == Some("manual") {
            notices.push(
                "This workbook calculates manually, so saved values may be stale.".to_owned(),
            );
        }
    }
    for notice in notices {
        out.push('\n');
        out.push_str(&notice);
        out.push('\n');
    }

    let mut chars = out.chars().count();
    let mut cells_read = 0_usize;
    for sheet in &sheets {
        // The whole text is cut and flagged at MAX_CHARS, so stop reading then.
        if chars > MAX_CHARS {
            break;
        }
        let Some(name) = &sheet.part else {
            continue;
        };
        let xml = part(name).ok_or(ParseRefusal::Malformed)?;
        let text = sheet_markdown(sheet, &xml, &strings, &formats, &mut cells_read)?;
        chars += text.chars().count();
        out.push_str(&text);
    }
    Ok((out, sheets.len()))
}

struct Sheet<'a> {
    name: &'a str,
    hidden: bool,
    /// None for a chart or dialog sheet, which holds no cells.
    part: Option<String>,
}

impl Sheet<'_> {
    fn title(&self) -> String {
        let mut title = escaped(&decoded_xstring(self.name));
        if self.part.is_none() {
            title.push_str(" (no cells)");
        }
        if self.hidden {
            title.push_str(" (hidden)");
        }
        title
    }
}

struct Relationship {
    id: String,
    kind: String,
    target: String,
    external: bool,
}

fn relationships(xml: &str) -> Result<Vec<Relationship>, ParseRefusal> {
    let document = parse(xml)?;
    let mut found = Vec::new();
    let mut ids = HashSet::new();
    for node in document.root_element().children().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "Relationship"
            && node.tag_name().namespace() == Some(PACKAGE_RELATIONSHIPS)
    }) {
        let (Some(id), Some(kind), Some(target)) = (
            node.attribute("Id"),
            node.attribute("Type"),
            node.attribute("Target"),
        ) else {
            return Err(ParseRefusal::Malformed);
        };
        if !ids.insert(id) {
            return Err(ParseRefusal::Malformed);
        }
        found.push(Relationship {
            id: id.to_owned(),
            kind: kind.rsplit('/').next().unwrap_or("").to_ascii_lowercase(),
            target: target.to_owned(),
            external: node
                .attribute("TargetMode")
                .is_some_and(|mode| mode.eq_ignore_ascii_case("external")),
        });
    }
    Ok(found)
}

fn parse(xml: &str) -> Result<Document<'_>, ParseRefusal> {
    check_attributes(xml)?;
    let options = ParsingOptions {
        nodes_limit: MAX_PART_NODES,
        ..ParsingOptions::default()
    };
    Document::parse_with_options(xml, options).map_err(|error| match error {
        roxmltree::Error::NodesLimitReached => ParseRefusal::ArchiveLimit,
        _ => ParseRefusal::Malformed,
    })
}

/// Bound attributes before the XML parser sees them. Comments, CDATA and
/// processing instructions are skipped whole, since a quote in one means nothing.
/// An attribute value can't hold a raw `<`, so a tag runs from its `<` to its
/// unquoted `>`. Malformed XML is left for the parser to refuse.
fn check_attributes(xml: &str) -> Result<(), ParseRefusal> {
    let bytes = xml.as_bytes();
    let skip_past = |from: usize, end: &[u8]| {
        bytes[from..]
            .windows(end.len())
            .position(|window| window == end)
            .map(|offset| from + offset + end.len())
    };
    let mut total = 0_usize;
    let mut at = 0;
    while let Some(offset) = bytes[at..].iter().position(|byte| *byte == b'<') {
        at += offset;
        let rest = &bytes[at..];
        let skipped = if rest.starts_with(b"<!--") {
            Some(skip_past(at + 4, b"-->"))
        } else if rest.starts_with(b"<![CDATA[") {
            Some(skip_past(at + 9, b"]]>"))
        } else if rest.starts_with(b"<?") {
            Some(skip_past(at + 2, b"?>"))
        } else {
            None
        };
        if let Some(next) = skipped {
            match next {
                Some(next) => {
                    at = next;
                    continue;
                }
                None => return Ok(()),
            }
        }
        at += 1;
        let mut quote = None;
        let mut in_tag = 0_usize;
        while let Some(byte) = bytes.get(at).copied() {
            at += 1;
            match (quote, byte) {
                (Some(open), _) if byte == open => quote = None,
                (Some(_), _) => {}
                (None, b'"' | b'\'') => quote = Some(byte),
                (None, b'=') => in_tag += 1,
                (None, b'>') => break,
                (None, _) => {}
            }
        }
        total += in_tag;
        if in_tag > MAX_ELEMENT_ATTRIBUTES || total > MAX_PART_ATTRIBUTES {
            return Err(ParseRefusal::ArchiveLimit);
        }
    }
    Ok(())
}

/// Every element this reader relies on must be exactly where it reads it. Inside
/// `mc:AlternateContent` or another wrapper it would be missed, and a spreadsheet
/// application might use it, so what's shown could differ from what's there.
fn check_placement(root: Node<'_, '_>, places: &[(&str, &[&str])]) -> Result<(), ParseRefusal> {
    for node in root.descendants().filter(Node::is_element) {
        for (name, parents) in places {
            if is_sheet_element(node, name) {
                let placed = node
                    .parent()
                    .is_some_and(|parent| parents.iter().any(|p| is_sheet_element(parent, p)));
                if !placed {
                    return Err(ParseRefusal::Malformed);
                }
            }
        }
    }
    Ok(())
}

fn is_sheet_element(node: Node<'_, '_>, name: &str) -> bool {
    node.is_element()
        && node.tag_name().name() == name
        && node
            .tag_name()
            .namespace()
            .is_some_and(|namespace| SHEET_NAMESPACES.contains(&namespace))
}

fn sheet_children<'a, 'input>(
    node: Node<'a, 'input>,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'input>> {
    node.children()
        .filter(move |child| is_sheet_element(*child, name))
}

/// All of an element's text, across comments and processing instructions, which
/// split it into several nodes. Child elements have no place here.
fn element_text(node: Node<'_, '_>) -> Result<String, ParseRefusal> {
    let mut text = String::new();
    for child in node.children() {
        if child.is_element() {
            return Err(ParseRefusal::Malformed);
        }
        if child.is_text() {
            text.push_str(child.text().unwrap_or(""));
        }
    }
    Ok(text)
}

/// Decode the `_xHHHH_` escapes the file format uses for characters XML can't
/// hold (ECMA-376 `ST_Xstring`): `_x000D_` is a carriage return and `_x005F_` an
/// underscore. Anything else is left as written, including a lone surrogate.
fn decoded_xstring(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("_x") {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let code = rest
            .get(2..6)
            .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .filter(|_| rest.as_bytes().get(6) == Some(&b'_'))
            .and_then(|digits| u32::from_str_radix(digits, 16).ok())
            .and_then(char::from_u32);
        match code {
            Some(character) => {
                out.push(character);
                rest = &rest[7..];
            }
            None => {
                out.push_str("_x");
                rest = &rest[2..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Text of a run-bearing element (`si`, `is`): its `t` and its runs' `t`, in
/// order. Phonetic hints (`rPh`) aren't the cell's value.
fn rich_text(node: Node<'_, '_>) -> Result<String, ParseRefusal> {
    let mut text = String::new();
    for child in node.children().filter(Node::is_element) {
        // Each `t` on its own: an escape can't span two of them.
        if is_sheet_element(child, "t") {
            text.push_str(&decoded_xstring(&element_text(child)?));
        } else if is_sheet_element(child, "r") {
            for run in sheet_children(child, "t") {
                text.push_str(&decoded_xstring(&element_text(run)?));
            }
        }
    }
    Ok(text)
}

fn shared_strings(xml: &str) -> Result<Vec<String>, ParseRefusal> {
    let document = parse(xml)?;
    check_placement(document.root_element(), &STRINGS_PLACES)?;
    sheet_children(document.root_element(), "si")
        .map(rich_text)
        .collect()
}

/// Each cell style's number format: its code if custom, `builtin <id>` if
/// predefined, nothing for General (id 0).
fn number_formats(xml: &str) -> Result<Vec<String>, ParseRefusal> {
    let document = parse(xml)?;
    let root = document.root_element();
    check_placement(root, &STYLES_PLACES)?;
    let custom: HashMap<&str, &str> = sheet_children(root, "numFmts")
        .flat_map(|list| sheet_children(list, "numFmt"))
        .filter_map(|format| {
            Some((
                format.attribute("numFmtId")?,
                format.attribute("formatCode")?,
            ))
        })
        .collect();
    Ok(sheet_children(root, "cellXfs")
        .flat_map(|list| sheet_children(list, "xf"))
        .map(|style| match style.attribute("numFmtId").unwrap_or("0") {
            "0" => String::new(),
            id => custom
                .get(id)
                .map_or_else(|| format!("builtin {id}"), |code| (*code).to_owned()),
        })
        .collect())
}

/// A1-style reference: at most three uppercase letters, then a row in range.
fn valid_reference(reference: &str) -> bool {
    let letters = reference.bytes().take_while(u8::is_ascii_uppercase).count();
    let (column, row) = reference.split_at(letters);
    let column_number = column.bytes().fold(0_u32, |sum, letter| {
        sum.saturating_mul(26) + u32::from(letter - b'A') + 1
    });
    (1..=3).contains(&letters)
        && column_number <= MAX_COLUMN
        && !row.starts_with('0')
        && row.bytes().all(|digit| digit.is_ascii_digit())
        && row
            .parse::<u32>()
            .is_ok_and(|row| (1..=MAX_ROW).contains(&row))
}

/// Whether a formula may reach outside the workbook: `[1]Sheet!A1`,
/// `[Book.xlsx]S!A1` or `[1]!Name` (an external workbook), `app|topic!item` (DDE),
/// or a function that fetches or resolves names at run time. It looks at the
/// whole text, string literals included: a false positive only adds a caution,
/// while a quote inside a sheet name could hide a real link from a parser of
/// strings. It can still miss a form it doesn't know.
fn is_external_formula(formula: &str) -> bool {
    let upper: String = formula
        .chars()
        .filter(|character| !character.is_whitespace())
        .map(|character| character.to_ascii_uppercase())
        .collect();
    upper.contains('|')
        || REACHING_FUNCTIONS.iter().any(|name| upper.contains(name))
        || upper
            .find(']')
            .is_some_and(|close| upper[close..].contains('!'))
}

/// One line of a table cell. Content can't end the row, add a column or start
/// a line, and marks that reorder or break lines on screen are shown as codes.
fn escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}' => {
                out.push_str(&format!("\\u{{{:x}}}", u32::from(character)));
            }
            control if control.is_control() => {
                out.push_str(&format!("\\u{{{:x}}}", u32::from(control)));
            }
            other => out.push(other),
        }
    }
    out
}

struct Formula {
    text: String,
    external: bool,
}

/// The saved value and its type name. Each type's value must be one, so the
/// type column can be relied on; a number is shown exactly as saved.
fn saved_value(
    cell: Node<'_, '_>,
    strings: &[String],
) -> Result<Option<(String, &'static str)>, ParseRefusal> {
    let kind = cell.attribute("t").unwrap_or("n");
    let inline = sheet_children(cell, "is").next();
    let value = sheet_children(cell, "v").next();
    if kind == "inlineStr" {
        if value.is_some() {
            return Err(ParseRefusal::Malformed);
        }
        return inline
            .map(|text| Ok((rich_text(text)?, "text")))
            .transpose();
    }
    if inline.is_some() {
        return Err(ParseRefusal::Malformed);
    }
    let Some(value) = value else {
        return Ok(None);
    };
    let value = element_text(value)?;
    // openpyxl writes `<v />` for a formula with no saved value. Only a formula's
    // text result can truly be empty.
    if kind != "str" && value.trim().is_empty() {
        return Ok(None);
    }
    let found = match kind {
        "n" => {
            if !value.trim().parse::<f64>().is_ok_and(f64::is_finite) {
                return Err(ParseRefusal::Malformed);
            }
            (value.trim().to_owned(), "number")
        }
        "s" => {
            let index: usize = value.trim().parse().map_err(|_| ParseRefusal::Malformed)?;
            let text = strings.get(index).ok_or(ParseRefusal::Malformed)?;
            (text.clone(), "text")
        }
        "str" => (decoded_xstring(&value), "text"),
        "b" => match value.trim() {
            "0" => ("FALSE".to_owned(), "boolean"),
            "1" => ("TRUE".to_owned(), "boolean"),
            _ => return Err(ParseRefusal::Malformed),
        },
        "e" => {
            if !value.starts_with('#') {
                return Err(ParseRefusal::Malformed);
            }
            (value, "error")
        }
        "d" => {
            let date_like = value.starts_with(|first: char| first.is_ascii_digit())
                && value
                    .chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, '-' | ':' | '.' | 'T' | 'Z' | '+'));
            if !date_like {
                return Err(ParseRefusal::Malformed);
            }
            (value, "date")
        }
        _ => return Err(ParseRefusal::Malformed),
    };
    Ok(Some(found))
}

/// The sheet's cells, refusing any shape they could hide in. Anything this reader
/// wouldn't show must not be there. `extLst` is an extension list, which holds no
/// cells.
fn sheet_cells<'a, 'input>(
    worksheet: Node<'a, 'input>,
) -> Result<Vec<(Node<'a, 'input>, Option<&'a str>)>, ParseRefusal> {
    if !is_sheet_element(worksheet, "worksheet") {
        return Err(ParseRefusal::Malformed);
    }
    let mut data = sheet_children(worksheet, "sheetData");
    let sheet_data = data.next().ok_or(ParseRefusal::Malformed)?;
    if data.next().is_some() {
        return Err(ParseRefusal::Malformed);
    }
    let mut cells = Vec::new();
    let mut rows = 0_usize;
    for row in sheet_data.children().filter(Node::is_element) {
        if !is_sheet_element(row, "row") {
            return Err(ParseRefusal::Malformed);
        }
        rows += 1;
        if rows > MAX_SHEET_ROWS {
            return Err(ParseRefusal::ArchiveLimit);
        }
        for cell in row.children().filter(Node::is_element) {
            if is_sheet_element(cell, "extLst") {
                continue;
            }
            if !is_sheet_element(cell, "c") {
                return Err(ParseRefusal::Malformed);
            }
            let mut seen = HashSet::new();
            for child in cell.children().filter(Node::is_element) {
                let name = child.tag_name().name();
                let known = ["f", "v", "is", "extLst"]
                    .iter()
                    .any(|known| is_sheet_element(child, known));
                if !known || !seen.insert(name) {
                    return Err(ParseRefusal::Malformed);
                }
            }
            if cells.len() == MAX_WORKBOOK_CELLS {
                return Err(ParseRefusal::ArchiveLimit);
            }
            cells.push((cell, row.attribute("r")));
        }
    }
    Ok(cells)
}

fn sheet_markdown(
    sheet: &Sheet<'_>,
    xml: &str,
    strings: &[String],
    formats: &[String],
    cells_read: &mut usize,
) -> Result<String, ParseRefusal> {
    let document = parse(xml)?;
    check_placement(document.root_element(), &WORKSHEET_PLACES)?;
    let cells = sheet_cells(document.root_element())?;
    *cells_read += cells.len();
    if *cells_read > MAX_WORKBOOK_CELLS {
        return Err(ParseRefusal::ArchiveLimit);
    }

    let mut out = format!(
        "\n## Sheet: {}\n\n| Cell | Value | Type | Format | Formula | Note |\n|---|---|---|---|---|---|\n",
        sheet.title()
    );
    let mut seen = HashSet::new();
    // A shared formula's text is in its first cell, and an index can be reused,
    // so a member belongs to the latest one before it.
    let mut shared: HashMap<&str, (&str, bool)> = HashMap::new();
    let mut rows = 0_usize;
    for (cell, row) in cells {
        let reference = cell.attribute("r").ok_or(ParseRefusal::Malformed)?;
        if !valid_reference(reference) || !seen.insert(reference) {
            return Err(ParseRefusal::Malformed);
        }
        let digits = reference.trim_start_matches(|c: char| c.is_ascii_uppercase());
        if row.is_some_and(|row| row != digits) {
            return Err(ParseRefusal::Malformed);
        }
        let formula = match sheet_children(cell, "f").next() {
            None => None,
            Some(formula) => {
                let text = decoded_xstring(&element_text(formula)?);
                let kind = formula.attribute("t");
                if text.trim().is_empty() {
                    match kind {
                        Some("shared") => {
                            let index = formula.attribute("si").ok_or(ParseRefusal::Malformed)?;
                            let (origin, external) =
                                *shared.get(index).ok_or(ParseRefusal::Malformed)?;
                            Some(Formula {
                                text: format!("shared with {origin}"),
                                external,
                            })
                        }
                        Some("dataTable") => Some(Formula {
                            text: "data table".to_owned(),
                            external: false,
                        }),
                        _ => return Err(ParseRefusal::Malformed),
                    }
                } else {
                    let external = is_external_formula(&text);
                    if kind == Some("shared") {
                        let index = formula.attribute("si").ok_or(ParseRefusal::Malformed)?;
                        shared.insert(index, (reference, external));
                    }
                    Some(Formula {
                        text: format!("={text}"),
                        external,
                    })
                }
            }
        };
        let value = saved_value(cell, strings)?;
        if value.is_none() && formula.is_none() {
            continue; // A formatted but empty cell.
        }
        let format = cell
            .attribute("s")
            .and_then(|style| style.parse::<usize>().ok())
            .and_then(|style| formats.get(style))
            .map_or("", String::as_str);
        let mut notes = Vec::new();
        if value.is_none() {
            notes.push("no saved value");
        }
        if formula.as_ref().is_some_and(|formula| formula.external) {
            notes.push("external, not refreshed");
        }
        let (value, kind) = value.unwrap_or((String::new(), "empty"));
        out.push_str(&format!(
            "| {reference} | {} | {kind} | {} | {} | {} |\n",
            escaped(&value),
            escaped(format),
            escaped(formula.as_ref().map_or("", |formula| formula.text.as_str())),
            notes.join("; "),
        ));
        rows += 1;
        if out.len() > MAX_CHARS * 4 {
            break; // Past what the frame can carry, whatever the characters.
        }
    }
    if rows == 0 {
        out.push_str("| | No cells with content. | | | | |\n");
    }
    Ok(out)
}

#[cfg(test)]
#[path = "workbook_tests.rs"]
mod tests;
