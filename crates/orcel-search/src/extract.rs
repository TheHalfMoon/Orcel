//! Page processing: HTML to title, metadata, main text, markdown and blocks.
//!
//! Ported from `orcel-poc/src/text/extract.ts` (Orcel-authored). No
//! rendering, no script execution, no anti-bot handling: it reads the HTML a
//! plain GET returns, which the governed fetch supplies.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::highlights::collapse_whitespace;
use crate::html::{self, Dom, HtmlLimit, NodeId, NodeKind, ParseStats};
use crate::tokenize::fold_diacritics;
use crate::types::{ContentBlock, DocCategory};
use crate::url;

const DROP_TAGS: [&str; 11] = [
    "script", "style", "noscript", "iframe", "svg", "canvas", "form", "nav", "footer", "aside",
    "template",
];
const DROP_CLASSES: [&str; 5] = [
    "cookie-banner",
    "newsletter",
    "advertisement",
    "sidebar",
    "comments",
];
const BLOCK_TAGS: [&str; 15] = [
    "p",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "li",
    "blockquote",
    "pre",
    "figcaption",
    "td",
    "th",
    "dd",
    "dt",
];
const NEWS_HOSTS: [&str; 15] = [
    "reuters.com",
    "apnews.com",
    "bbc.co.uk",
    "bbc.com",
    "nytimes.com",
    "theguardian.com",
    "washingtonpost.com",
    "bloomberg.com",
    "ft.com",
    "wsj.com",
    "cnbc.com",
    "techcrunch.com",
    "theverge.com",
    "arstechnica.com",
    "wired.com",
];
const RESEARCH_HOSTS: [&str; 7] = [
    "arxiv.org",
    "doi.org",
    "pubmed.ncbi.nlm.nih.gov",
    "openreview.net",
    "acm.org",
    "nature.com",
    "science.org",
];

/// The result of extracting one page.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractedPage {
    pub title: String,
    /// Non-heading blocks joined with blank lines: what citations quote.
    pub text: String,
    /// Every block as markdown, headings included.
    pub markdown: String,
    /// The same blocks as a typed tree, for the `html` and `json` formats.
    pub blocks: Vec<ContentBlock>,
    pub published_date: Option<String>,
    pub author: Option<String>,
    pub site_name: Option<String>,
    pub language: Option<String>,
    pub description: Option<String>,
    /// Declared `og:type`, such as `article`, `website` or `profile`.
    pub open_graph_type: Option<String>,
    /// Deterministic work counters, for bounding the cost in tests.
    pub stats: ExtractStats,
}

/// Work counters of one extraction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExtractStats {
    pub parse: ParseStats,
    /// Nodes in the tree.
    pub nodes: usize,
    /// Node and child-edge visits of the post-order analysis.
    pub analysis_steps: usize,
}

fn is_dropped(dom: &Dom, id: NodeId) -> bool {
    let Some(tag) = dom.tag(id) else {
        return false;
    };
    DROP_TAGS.contains(&tag)
        || dom.attr(id, "aria-hidden") == Some("true")
        || dom.attr(id, "hidden").is_some()
        || DROP_CLASSES.iter().any(|c| dom.has_class(id, c))
        || dom.attr(id, "id") == Some("comments")
}

fn is_block(dom: &Dom, id: NodeId) -> bool {
    dom.tag(id).is_some_and(|t| BLOCK_TAGS.contains(&t))
}

fn meta(dom: &Dom, metas: &[NodeId], names: &[&str]) -> Option<String> {
    for name in names {
        for attribute in ["property", "name", "itemprop"] {
            let found = metas
                .iter()
                .copied()
                .find(|id| dom.attr(*id, attribute) == Some(name));
            if let Some(id) = found {
                let value = dom.attr(id, "content").unwrap_or("").trim().to_string();
                if !value.is_empty() {
                    return Some(value);
                }
                break;
            }
        }
    }
    None
}

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn ymd(year: u32, month: u32, day: u32) -> Option<String> {
    if !(1000..=9999).contains(&year) || !(1..=12).contains(&month) {
        return None;
    }
    if day == 0 || day > days_in_month(year, month) {
        return None;
    }
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

/// Normalises a published date to `YYYY-MM-DD`.
///
/// Accepts an ISO date or datetime prefix, `YYYY/MM/DD`, and English
/// day-month-year or month-day-year forms with an optional weekday and time
/// (`Wed, 11 Feb 2026 09:00:00 GMT`, `February 11, 2026`). The time and zone
/// are ignored, so the calendar date is the one written in the source; the
/// proof of concept's `Date` fallback shifts it by the host time zone.
pub fn normalise_date(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let bytes = trimmed.as_bytes();
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let slice = trimmed.get(range)?;
        if slice.bytes().all(|b| b.is_ascii_digit()) {
            slice.parse().ok()
        } else {
            None
        }
    };
    if bytes.len() >= 10 && (bytes[4] == b'-' || bytes[4] == b'/') && bytes[7] == bytes[4] {
        if let (Some(y), Some(m), Some(d)) = (digits(0..4), digits(5..7), digits(8..10)) {
            if bytes[4] == b'-' {
                // An ISO prefix is taken as written, as the proof of concept does.
                return Some(trimmed[..10].to_string());
            }
            return ymd(y, m, d);
        }
    }
    let mut year = None;
    let mut month = None;
    let mut day = None;
    for token in trimmed.split(|c: char| c.is_whitespace() || c == ',') {
        if token.is_empty() || token.contains(':') {
            continue;
        }
        let lower = token.to_ascii_lowercase();
        let lower = lower.trim_end_matches('.');
        if let Some(index) = MONTHS.iter().position(|m| lower.starts_with(m)) {
            if month.is_none() && lower.chars().all(|c| c.is_ascii_alphabetic()) {
                month = Some(index as u32 + 1);
                continue;
            }
        }
        let numeric = lower.trim_end_matches(['s', 't', 'n', 'd', 'r', 'h']);
        if !numeric.is_empty() && numeric.bytes().all(|b| b.is_ascii_digit()) {
            let value: u32 = numeric.parse().ok()?;
            if numeric.len() == 4 && year.is_none() {
                year = Some(value);
            } else if numeric.len() <= 2 && day.is_none() {
                day = Some(value);
            }
        }
    }
    ymd(year?, month?, day?)
}

fn collect_json_ld(dom: &Dom) -> Vec<Value> {
    let mut nodes = Vec::new();
    let scripts = dom.find_all(0, |d, id| {
        d.tag(id) == Some("script")
            && d.attr(id, "type")
                .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/ld+json"))
    });
    for script in scripts {
        let raw = dom.text_content(script);
        let Ok(parsed) = serde_json::from_str::<Value>(raw.trim()) else {
            continue;
        };
        let mut queue: std::collections::VecDeque<Value> = match parsed {
            Value::Array(items) => items.into(),
            other => vec![other].into(),
        };
        while let Some(node) = queue.pop_front() {
            match node {
                Value::Array(items) => queue.extend(items),
                Value::Object(ref map) => {
                    if let Some(Value::Array(graph)) = map.get("@graph") {
                        queue.extend(graph.iter().cloned());
                    }
                    nodes.push(node);
                }
                _ => {}
            }
        }
    }
    nodes
}

fn json_ld_author(node: &Value) -> Option<String> {
    match node.get("author")? {
        Value::String(name) => Some(name.clone()),
        Value::Array(items) => {
            let names: Vec<String> = items
                .iter()
                .filter_map(|a| match a {
                    Value::String(s) => Some(s.clone()),
                    other => other
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                })
                .filter(|n| !n.trim().is_empty())
                .collect();
            if names.is_empty() {
                None
            } else {
                Some(names.join(", "))
            }
        }
        other => other
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string),
    }
}

/// Text measures of one subtree, combined bottom-up so the trimmed text
/// length of every node is known after one post-order pass.
#[derive(Debug, Clone, Copy, Default)]
struct Span {
    chars: usize,
    leading_ws: usize,
    trailing_ws: usize,
    all_ws: bool,
}

impl Span {
    fn of_text(text: &str) -> Self {
        let chars = text.chars().count();
        let leading_ws = text.chars().take_while(|c| c.is_whitespace()).count();
        if leading_ws == chars {
            return Self {
                chars,
                leading_ws,
                trailing_ws: chars,
                all_ws: true,
            };
        }
        Self {
            chars,
            leading_ws,
            trailing_ws: text.chars().rev().take_while(|c| c.is_whitespace()).count(),
            all_ws: false,
        }
    }

    fn empty() -> Self {
        Self {
            all_ws: true,
            ..Self::default()
        }
    }

    fn then(self, next: Self) -> Self {
        Self {
            chars: self.chars + next.chars,
            leading_ws: if self.all_ws {
                self.chars + next.leading_ws
            } else {
                self.leading_ws
            },
            trailing_ws: if next.all_ws {
                next.chars + self.trailing_ws
            } else {
                next.trailing_ws
            },
            all_ws: self.all_ws && next.all_ws,
        }
    }

    /// Characters of the subtree text after trimming whitespace.
    fn trimmed(self) -> usize {
        if self.all_ws {
            0
        } else {
            self.chars - self.leading_ws - self.trailing_ws
        }
    }
}

/// Per-node facts from one post-order pass: trimmed text length and whether
/// a block element sits below the node.
struct Analysis {
    span: Vec<Span>,
    block_below: Vec<bool>,
    steps: usize,
}

fn analyse(dom: &Dom) -> Analysis {
    let mut span = vec![Span::empty(); dom.nodes.len()];
    let mut block_below = vec![false; dom.nodes.len()];
    let mut steps = 0;
    let mut order = dom.post_order(0);
    order.push(0);
    for id in order {
        steps += 1 + dom.nodes[id].children.len();
        if let NodeKind::Text(text) = &dom.nodes[id].kind {
            span[id] = Span::of_text(text);
            continue;
        }
        let mut acc = Span::empty();
        let mut below = false;
        for &child in &dom.nodes[id].children {
            acc = acc.then(span[child]);
            below = below || block_below[child] || is_block(dom, child);
        }
        span[id] = acc;
        block_below[id] = below;
    }
    Analysis {
        span,
        block_below,
        steps,
    }
}

fn pick_longest(
    dom: &Dom,
    facts: &Analysis,
    predicate: impl Fn(&Dom, NodeId) -> bool,
) -> Option<NodeId> {
    let mut best = None;
    let mut best_length = 0;
    for id in dom.find_all(0, predicate) {
        let length = facts.span[id].trimmed();
        if length > best_length {
            best = Some(id);
            best_length = length;
        }
    }
    best
}

fn choose_root(dom: &Dom, facts: &Analysis) -> NodeId {
    let candidates = [
        pick_longest(dom, facts, |d, id| d.tag(id) == Some("article")),
        pick_longest(dom, facts, |d, id| d.tag(id) == Some("main")),
        pick_longest(dom, facts, |d, id| d.attr(id, "role") == Some("main")),
        pick_longest(dom, facts, |d, id| {
            d.attr(id, "itemprop") == Some("articleBody")
        }),
        pick_longest(dom, facts, |d, id| {
            ["post-content", "entry-content", "article-body", "content"]
                .iter()
                .any(|c| d.has_class(id, c))
                || d.attr(id, "id") == Some("content")
        }),
    ];
    let mut best = dom.body().or_else(|| dom.document_element()).unwrap_or(0);
    let mut best_length = facts.span[best].trimmed();
    for candidate in candidates.into_iter().flatten() {
        let length = facts.span[candidate].trimmed();
        // A container wins only when it is dense enough to be the content.
        if length > 100 && length as f64 >= best_length as f64 * 0.5 {
            best = candidate;
            best_length = length;
        }
    }
    best
}

fn block_for(dom: &Dom, id: NodeId, text: &str) -> (ContentBlock, String) {
    let tag = dom.tag(id).unwrap_or("p");
    match tag {
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
            let level: u8 = tag[1..].parse().unwrap_or(1);
            let hashes = "#".repeat(usize::from(level.min(4)));
            (
                ContentBlock::Heading {
                    level,
                    text: text.to_string(),
                },
                format!("{hashes} {text}"),
            )
        }
        "li" => {
            let ordered = dom
                .parent_element(id)
                .and_then(|p| dom.tag(p))
                .is_some_and(|t| t == "ol");
            let marker = if ordered { "1." } else { "-" };
            (
                ContentBlock::ListItem {
                    ordered,
                    text: text.to_string(),
                },
                format!("{marker} {text}"),
            )
        }
        "blockquote" => (
            ContentBlock::Quote {
                text: text.to_string(),
            },
            text.split('\n')
                .map(|line| format!("> {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        "pre" => (
            ContentBlock::Code {
                text: text.trim().to_string(),
            },
            format!("```\n{}\n```", text.trim()),
        ),
        _ => (
            ContentBlock::Paragraph {
                text: text.to_string(),
            },
            text.to_string(),
        ),
    }
}

struct Block {
    text: String,
    markdown: String,
    block: ContentBlock,
    heading: bool,
}

fn collect_blocks(dom: &Dom, facts: &Analysis, root: NodeId, drop_title: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for id in dom.find_all(root, is_block) {
        // Keep the leaf-most block: a <p> inside <li> is the block, not the <li>.
        // Leaf blocks never nest, so reading their text is linear overall.
        if facts.block_below[id] {
            continue;
        }
        let text = collapse_whitespace(&dom.text_content(id));
        if text.is_empty() || text == drop_title {
            continue;
        }
        if !seen.insert(fold_diacritics(&text.to_lowercase())) {
            continue;
        }
        let (block, markdown) = block_for(dom, id, &text);
        let heading = matches!(block, ContentBlock::Heading { .. });
        blocks.push(Block {
            text,
            markdown,
            block,
            heading,
        });
    }
    if blocks.is_empty() {
        let fallback = collapse_whitespace(&dom.text_content(root));
        if !fallback.is_empty() {
            blocks.push(Block {
                markdown: fallback.clone(),
                block: ContentBlock::Paragraph {
                    text: fallback.clone(),
                },
                text: fallback,
                heading: false,
            });
        }
    }
    blocks
}

/// Extracts title, metadata and main content from `html` fetched at `url`.
/// Refuses input past the [`html::MAX_HTML_BYTES`] and [`html::MAX_NODES`]
/// limits; otherwise the work is linear in the input.
pub fn extract_page(html_source: &str, page_url: &str) -> Result<ExtractedPage, HtmlLimit> {
    let mut dom = html::parse(html_source)?;
    // JSON-LD lives inside <script>, so it is read before scripts are dropped.
    let json_ld = collect_json_ld(&dom);
    let dropped = dom.find_all(0, is_dropped);
    dom.remove_all(&dropped);
    let facts = analyse(&dom);
    let metas = dom.find_all(0, |d, id| d.tag(id) == Some("meta"));

    let non_empty = |value: String| {
        let value = collapse_whitespace(&value);
        (!value.is_empty()).then_some(value)
    };
    let og_title = meta(&dom, &metas, &["og:title", "twitter:title"]);
    let h1 = dom
        .find(0, |d, id| d.tag(id) == Some("h1"))
        .and_then(|id| non_empty(dom.text_content(id)));
    let doc_title = dom
        .find(0, |d, id| d.tag(id) == Some("title"))
        .and_then(|id| non_empty(dom.text_content(id)));
    let title = collapse_whitespace(
        &og_title
            .or_else(|| h1.clone())
            .or(doc_title)
            .unwrap_or_else(|| page_url.to_string()),
    );

    let published_date = meta(
        &dom,
        &metas,
        &[
            "article:published_time",
            "datePublished",
            "og:updated_time",
            "date",
        ],
    )
    .and_then(|d| normalise_date(&d))
    .or_else(|| {
        let time_attr = dom
            .find(0, |d, id| {
                d.tag(id) == Some("time") && d.attr(id, "datetime").is_some()
            })
            .and_then(|id| dom.attr(id, "datetime").map(str::to_string));
        let time_text = || {
            dom.find(0, |d, id| d.tag(id) == Some("time"))
                .map(|id| dom.text_content(id))
        };
        time_attr
            .or_else(time_text)
            .and_then(|d| normalise_date(&d))
    })
    .or_else(|| {
        json_ld
            .iter()
            .find_map(|node| node.get("datePublished").and_then(Value::as_str))
            .and_then(normalise_date)
    });

    let author = meta(
        &dom,
        &metas,
        &["author", "article:author", "twitter:creator"],
    )
    .or_else(|| {
        json_ld
            .iter()
            .filter_map(json_ld_author)
            .find(|name| !name.is_empty())
    });
    let site_name = meta(&dom, &metas, &["og:site_name"]);
    let description = meta(&dom, &metas, &["description", "og:description"]);
    let language = dom
        .document_element()
        .and_then(|id| dom.attr(id, "lang"))
        .map(str::to_string);
    let open_graph_type = meta(&dom, &metas, &["og:type"]);

    let root = choose_root(&dom, &facts);
    let blocks = collect_blocks(&dom, &facts, root, &title);
    let final_title = if title.is_empty() {
        h1.unwrap_or_else(|| page_url.to_string())
    } else {
        title
    };

    let stats = ExtractStats {
        parse: dom.stats,
        nodes: dom.nodes.len(),
        analysis_steps: facts.steps,
    };
    Ok(ExtractedPage {
        stats,
        title: final_title,
        // Headings stay in markdown (where they also boost the index) but are
        // kept out of text so citations quote sentences, not section titles.
        text: blocks
            .iter()
            .filter(|b| !b.heading)
            .map(|b| b.text.as_str())
            .collect::<Vec<_>>()
            .join("\n\n"),
        markdown: blocks
            .iter()
            .map(|b| b.markdown.as_str())
            .collect::<Vec<_>>()
            .join("\n\n"),
        blocks: blocks.into_iter().map(|b| b.block).collect(),
        published_date,
        author,
        site_name,
        language,
        description,
        open_graph_type,
    })
}

fn host_is(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// Infers the Exa category from the URL host and the declared `og:type`.
pub fn infer_category(page_url: &str, open_graph_type: Option<&str>) -> DocCategory {
    let (host, path) =
        url::parse(page_url).map_or((String::new(), String::new()), |p| (p.host, p.path));
    let og = open_graph_type.unwrap_or("");
    let og_lower = og.to_ascii_lowercase();
    if host_is(&host, "github.com") {
        return DocCategory::Github;
    }
    if host_is(&host, "linkedin.com") {
        return DocCategory::LinkedinProfile;
    }
    if path.to_ascii_lowercase().ends_with(".pdf") || og == "application/pdf" {
        return DocCategory::Pdf;
    }
    if RESEARCH_HOSTS.iter().any(|d| host_is(&host, d)) {
        return DocCategory::ResearchPaper;
    }
    if og_lower.contains("newsarticle") || og_lower.contains("blogposting") {
        return DocCategory::News;
    }
    if NEWS_HOSTS.iter().any(|d| host_is(&host, d)) {
        return DocCategory::News;
    }
    if og == "profile" {
        return DocCategory::LinkedinProfile;
    }
    if host.ends_with("substack.com") || host.ends_with("medium.com") {
        return DocCategory::PersonalSite;
    }
    if host.ends_with("crunchbase.com") {
        return DocCategory::Company;
    }
    DocCategory::General
}

/// Lowercase hex SHA-256 of the UTF-8 bytes: the citation fingerprint.
pub fn content_hash(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
