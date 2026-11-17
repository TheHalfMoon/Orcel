//! The `html` and `json` content formats, rendered from extracted blocks.
//!
//! New in P-1 (TinyFish fetch contract T16: markdown default, `html` as
//! cleaned semantic HTML, `json` as a document tree). Orcel-authored.

use crate::types::{ContentBlock, CorpusDoc, DocumentTree};

/// Escapes text for HTML element content and attribute values.
pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Cleaned semantic HTML: one `<article>` with the title and the main-content
/// blocks only. No scripts, styles, attributes from the source or links;
/// every text node is escaped.
pub fn render_html(doc: &CorpusDoc) -> String {
    let mut out = String::from("<article>");
    out.push_str(&format!("<h1>{}</h1>", escape_html(&doc.title)));
    let mut open_list: Option<bool> = None;
    for block in &doc.blocks {
        let ordered = match block {
            ContentBlock::ListItem { ordered, .. } => Some(*ordered),
            _ => None,
        };
        if open_list.is_some() && open_list != ordered {
            out.push_str(if open_list == Some(true) {
                "</ol>"
            } else {
                "</ul>"
            });
            open_list = None;
        }
        match block {
            ContentBlock::Heading { level, text } => {
                let level = (*level).clamp(1, 6);
                out.push_str(&format!("<h{level}>{}</h{level}>", escape_html(text)));
            }
            ContentBlock::Paragraph { text } => {
                out.push_str(&format!("<p>{}</p>", escape_html(text)));
            }
            ContentBlock::ListItem { ordered, text } => {
                if open_list.is_none() {
                    out.push_str(if *ordered { "<ol>" } else { "<ul>" });
                    open_list = Some(*ordered);
                }
                out.push_str(&format!("<li>{}</li>", escape_html(text)));
            }
            ContentBlock::Quote { text } => {
                out.push_str(&format!("<blockquote>{}</blockquote>", escape_html(text)));
            }
            ContentBlock::Code { text } => {
                out.push_str(&format!("<pre><code>{}</code></pre>", escape_html(text)));
            }
        }
    }
    if let Some(ordered) = open_list {
        out.push_str(if ordered { "</ol>" } else { "</ul>" });
    }
    out.push_str("</article>");
    out
}

/// The document as a typed block tree.
pub fn render_json(doc: &CorpusDoc) -> DocumentTree {
    DocumentTree {
        url: doc.url.clone(),
        title: doc.title.clone(),
        published_date: doc.published_date.clone(),
        author: doc.author.clone(),
        language: doc.language.clone(),
        blocks: doc.blocks.clone(),
    }
}
