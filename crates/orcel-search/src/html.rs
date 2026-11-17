//! A small, tolerant HTML tree builder for main-content extraction.
//!
//! The proof of concept parses with `linkedom`. This crate takes no HTML
//! dependency, so it builds its own tree with the implied-end rules that
//! matter for article pages (`p`, `li`, `dt`/`dd`, table cells, `option`),
//! void elements, raw-text `script`/`style` and RCDATA `title`/`textarea`.
//! It is not a full HTML5 tree builder: it does not run scripts, reparent
//! misnested formatting elements or apply foster parenting.

/// Index of a node in [`Dom::nodes`].
pub type NodeId = usize;

/// What a node is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    /// The synthetic root.
    Document,
    /// An element with its lowercase tag and attributes (lowercase names).
    Element {
        tag: String,
        attrs: Vec<(String, String)>,
    },
    /// Decoded character data (raw for `script` and `style`).
    Text(String),
}

/// One node of the tree.
#[derive(Debug, Clone)]
pub struct Node {
    pub kind: NodeKind,
    pub parent: Option<NodeId>,
    pub children: Vec<NodeId>,
}

/// A parsed document. Node 0 is the [`NodeKind::Document`] root.
#[derive(Debug, Clone)]
pub struct Dom {
    pub nodes: Vec<Node>,
    /// Work counters, so tests can bound the cost deterministically.
    pub stats: ParseStats,
}

/// Largest HTML input accepted, in bytes.
pub const MAX_HTML_BYTES: usize = 5 * 1024 * 1024;
/// Most nodes (elements and text runs) one document may build.
pub const MAX_NODES: usize = 200_000;
/// Deepest open-element stack; elements past it are attached but not opened.
pub const MAX_OPEN_DEPTH: usize = 512;
/// Most attributes kept per tag; the rest are parsed and discarded.
pub const MAX_ATTRIBUTES: usize = 256;
/// Longest attribute value kept, in bytes (cut at a character boundary).
pub const MAX_ATTRIBUTE_VALUE_BYTES: usize = 8 * 1024;

/// Deterministic work counters of one parse.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParseStats {
    /// Input bytes.
    pub input_bytes: usize,
    /// Tag lookups made by implied-end and end-tag rules (constant per tag).
    pub stack_steps: usize,
    /// Deepest open-element stack reached.
    pub max_depth: usize,
    /// Attributes discarded past [`MAX_ATTRIBUTES`].
    pub dropped_attributes: usize,
}

/// Why a document was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HtmlLimit {
    /// The input exceeds [`MAX_HTML_BYTES`].
    InputTooLarge { bytes: usize },
    /// The tree would exceed [`MAX_NODES`].
    TooManyNodes,
}

impl std::fmt::Display for HtmlLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InputTooLarge { bytes } => write!(
                f,
                "HTML input of {bytes} bytes exceeds the {MAX_HTML_BYTES}-byte limit"
            ),
            Self::TooManyNodes => write!(f, "HTML input builds more than {MAX_NODES} nodes"),
        }
    }
}

fn truncate_to_boundary(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

const VOID: [&str; 14] = [
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

const CLOSES_P: [&str; 32] = [
    "address",
    "article",
    "aside",
    "blockquote",
    "details",
    "div",
    "dl",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "ul",
    "dd",
    "dt",
    "menu",
];

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | ':' | '_' | '.')
}

/// Decodes character references: numeric, hexadecimal and the common named
/// set. Unknown names are kept verbatim.
pub fn decode_entities(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        let end = after
            .char_indices()
            .take(32)
            .find(|(_, c)| *c == ';')
            .map(|(i, _)| i);
        let decoded = end.and_then(|end| decode_reference(&after[..end]).map(|d| (d, end)));
        match decoded {
            Some((text, end)) => {
                out.push_str(&text);
                rest = &after[end + 1..];
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

fn decode_reference(name: &str) -> Option<String> {
    if let Some(number) = name.strip_prefix('#') {
        let code = if let Some(hex) = number.strip_prefix(['x', 'X']) {
            u32::from_str_radix(hex, 16).ok()?
        } else {
            number.parse::<u32>().ok()?
        };
        let c = match code {
            0 => '\u{fffd}',
            _ => char::from_u32(code).unwrap_or('\u{fffd}'),
        };
        return Some(c.to_string());
    }
    let c = match name {
        "amp" => "&",
        "lt" => "<",
        "gt" => ">",
        "quot" => "\"",
        "apos" => "'",
        "nbsp" => "\u{a0}",
        "ndash" => "\u{2013}",
        "mdash" => "\u{2014}",
        "hellip" => "\u{2026}",
        "lsquo" => "\u{2018}",
        "rsquo" => "\u{2019}",
        "ldquo" => "\u{201c}",
        "rdquo" => "\u{201d}",
        "laquo" => "\u{ab}",
        "raquo" => "\u{bb}",
        "copy" => "\u{a9}",
        "reg" => "\u{ae}",
        "trade" => "\u{2122}",
        "middot" => "\u{b7}",
        "bull" => "\u{2022}",
        "deg" => "\u{b0}",
        "times" => "\u{d7}",
        "euro" => "\u{20ac}",
        "pound" => "\u{a3}",
        "sect" => "\u{a7}",
        "para" => "\u{b6}",
        "shy" => "\u{ad}",
        "zwj" => "\u{200d}",
        "zwnj" => "\u{200c}",
        "thinsp" => "\u{2009}",
        "ensp" => "\u{2002}",
        "emsp" => "\u{2003}",
        _ => return None,
    };
    Some(c.to_string())
}

struct Builder {
    dom: Dom,
    stack: Vec<NodeId>,
    /// Stack depths of the open elements of each tag, innermost last, so a
    /// rule finds its nearest tag and boundary without scanning the stack.
    open: std::collections::HashMap<String, Vec<usize>>,
    over_limit: bool,
}

impl Builder {
    fn current(&self) -> NodeId {
        self.stack.last().copied().unwrap_or(0)
    }

    fn append(&mut self, kind: NodeKind) -> NodeId {
        let parent = self.current();
        let id = self.dom.nodes.len();
        if id >= MAX_NODES {
            self.over_limit = true;
            return parent;
        }
        self.dom.nodes.push(Node {
            kind,
            parent: Some(parent),
            children: Vec::new(),
        });
        self.dom.nodes[parent].children.push(id);
        id
    }

    fn text(&mut self, text: String) {
        if text.is_empty() {
            return;
        }
        let parent = self.current();
        if let Some(&last) = self.dom.nodes[parent].children.last() {
            if let NodeKind::Text(existing) = &mut self.dom.nodes[last].kind {
                existing.push_str(&text);
                return;
            }
        }
        self.append(NodeKind::Text(text));
    }

    /// Depth of the innermost open element whose tag is in `names`.
    fn nearest(&self, names: &[&str]) -> Option<usize> {
        names
            .iter()
            .filter_map(|name| {
                self.open
                    .get(*name)
                    .and_then(|depths| depths.last().copied())
            })
            .max()
    }

    /// Depth of the nearest open element whose tag is in `tags`, unless an
    /// element in `boundaries` is closer. Constant work per call (one lookup
    /// per name), with no stack scan and no allocation.
    fn find_open(&mut self, tags: &[&str], boundaries: &[&str]) -> Option<usize> {
        self.dom.stats.stack_steps += tags.len() + boundaries.len();
        let found = self.nearest(tags)?;
        match self.nearest(boundaries) {
            Some(boundary) if boundary > found => None,
            _ => Some(found),
        }
    }

    /// Pops up to and including the nearest open `tag`, unless a `boundary`
    /// element is closer.
    fn close_open(&mut self, tags: &[&str], boundaries: &[&str]) {
        if let Some(depth) = self.find_open(tags, boundaries) {
            self.pop_to(depth);
        }
    }

    /// Pops every element at `depth` and above. Each element is pushed once,
    /// so pops are linear over the whole parse.
    fn pop_to(&mut self, depth: usize) {
        while self.stack.len() > depth {
            let Some(id) = self.stack.pop() else {
                break;
            };
            if let Some(tag) = self.dom.tag(id) {
                if let Some(depths) = self.open.get_mut(tag) {
                    depths.pop();
                }
            }
        }
    }

    fn start(&mut self, tag: String, attrs: Vec<(String, String)>, self_closing: bool) {
        const SCOPE: [&str; 8] = [
            "table", "td", "th", "button", "caption", "html", "template", "object",
        ];
        if CLOSES_P.contains(&tag.as_str()) {
            self.close_open(&["p"], &SCOPE);
        }
        match tag.as_str() {
            "li" => self.close_open(&["li"], &["ul", "ol", "menu", "table"]),
            "dt" | "dd" => self.close_open(&["dt", "dd"], &["dl", "table"]),
            "tr" => self.close_open(&["tr"], &["table", "thead", "tbody", "tfoot"]),
            "td" | "th" => self.close_open(&["td", "th"], &["tr", "table"]),
            "thead" | "tbody" | "tfoot" => {
                self.close_open(&["thead", "tbody", "tfoot"], &["table"]);
            }
            "option" => self.close_open(&["option"], &["select", "datalist"]),
            _ => {}
        }
        let void = VOID.contains(&tag.as_str());
        let id = self.append(NodeKind::Element { tag, attrs });
        if self.over_limit {
            return;
        }
        if !void && !self_closing && self.stack.len() < MAX_OPEN_DEPTH {
            if let Some(tag) = self.dom.tag(id) {
                let depth = self.stack.len();
                match self.open.get_mut(tag) {
                    Some(depths) => depths.push(depth),
                    None => {
                        self.open.insert(tag.to_string(), vec![depth]);
                    }
                }
            }
            self.stack.push(id);
            self.dom.stats.max_depth = self.dom.stats.max_depth.max(self.stack.len());
        }
    }

    fn end(&mut self, tag: &str) {
        if matches!(tag, "html" | "body" | "head") {
            return;
        }
        self.close_open(&[tag], &[]);
    }
}

fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    let hay = haystack.as_bytes();
    let pin = needle.as_bytes();
    if pin.is_empty() || hay.len() < pin.len() {
        return None;
    }
    (0..=hay.len() - pin.len()).find(|&i| hay[i..i + pin.len()].eq_ignore_ascii_case(pin))
}

/// A parsed start tag.
struct StartTag {
    tag: String,
    attrs: Vec<(String, String)>,
    self_closing: bool,
    /// Bytes consumed from the `<`.
    consumed: usize,
    /// Attributes discarded past [`MAX_ATTRIBUTES`].
    dropped: usize,
}

/// Parses the start tag at `input[0] == '<'`. Attribute names are
/// deduplicated through a set (first one wins), at most
/// [`MAX_ATTRIBUTES`] are kept and values are cut to
/// [`MAX_ATTRIBUTE_VALUE_BYTES`] before decoding, so the cost is linear.
fn parse_start_tag(input: &str) -> Option<StartTag> {
    let bytes = input.as_bytes();
    let mut i = 1;
    let name_start = i;
    while i < bytes.len() && is_name_char(bytes[i] as char) {
        i += 1;
    }
    if i == name_start {
        return None;
    }
    let tag = input[name_start..i].to_ascii_lowercase();
    let mut attrs = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut dropped = 0usize;
    let mut self_closing = false;
    loop {
        while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
            i += 1;
        }
        let done = |consumed: usize, attrs, self_closing| {
            Some(StartTag {
                tag: tag.clone(),
                attrs,
                self_closing,
                consumed,
                dropped,
            })
        };
        if i >= bytes.len() {
            return done(bytes.len(), attrs, self_closing);
        }
        match bytes[i] {
            b'>' => return done(i + 1, attrs, self_closing),
            b'/' => {
                self_closing = true;
                i += 1;
                continue;
            }
            _ => {}
        }
        self_closing = false;
        let attr_start = i;
        while i < bytes.len()
            && !(bytes[i] as char).is_ascii_whitespace()
            && !matches!(bytes[i], b'=' | b'>' | b'/')
        {
            i += 1;
        }
        let raw_name = &input[attr_start..i];
        while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
            i += 1;
        }
        let mut raw_value = "";
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                let value_start = i + 1;
                let value_end = input[value_start..]
                    .bytes()
                    .position(|b| b == quote)
                    .map_or(bytes.len(), |p| value_start + p);
                raw_value = &input[value_start..value_end];
                i = (value_end + 1).min(bytes.len());
            } else {
                let value_start = i;
                while i < bytes.len()
                    && !(bytes[i] as char).is_ascii_whitespace()
                    && bytes[i] != b'>'
                {
                    i += 1;
                }
                raw_value = &input[value_start..i];
            }
        }
        if raw_name.is_empty() {
            continue;
        }
        if attrs.len() >= MAX_ATTRIBUTES {
            dropped += 1;
            continue;
        }
        let name = raw_name.to_ascii_lowercase();
        if seen.insert(name.clone()) {
            let value = decode_entities(truncate_to_boundary(raw_value, MAX_ATTRIBUTE_VALUE_BYTES));
            attrs.push((name, value));
        }
    }
}

/// Parses `html` into a [`Dom`]. Malformed markup degrades to text or is
/// skipped; only the size limits refuse: more than [`MAX_HTML_BYTES`] of
/// input or more than [`MAX_NODES`] nodes. Every scan moves forward through
/// the input, and stack rules are bounded by [`MAX_OPEN_DEPTH`], so the work
/// is linear in the input.
pub fn parse(html: &str) -> Result<Dom, HtmlLimit> {
    if html.len() > MAX_HTML_BYTES {
        return Err(HtmlLimit::InputTooLarge { bytes: html.len() });
    }
    let mut builder = Builder {
        dom: Dom {
            nodes: vec![Node {
                kind: NodeKind::Document,
                parent: None,
                children: Vec::new(),
            }],
            stats: ParseStats {
                input_bytes: html.len(),
                ..ParseStats::default()
            },
        },
        stack: Vec::new(),
        open: std::collections::HashMap::new(),
        over_limit: false,
    };
    let mut i = 0usize;
    let bytes = html.as_bytes();
    let mut text_start = 0usize;
    while i < bytes.len() {
        if builder.over_limit {
            return Err(HtmlLimit::TooManyNodes);
        }
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let rest = &html[i..];
        let next = rest.as_bytes().get(1).copied().unwrap_or(0);
        let flush = |builder: &mut Builder, from: usize, to: usize| {
            if from < to {
                builder.text(decode_entities(&html[from..to]));
            }
        };
        if let Some(comment) = rest.strip_prefix("<!--") {
            flush(&mut builder, text_start, i);
            let end = comment.find("-->").map_or(html.len(), |p| i + 4 + p + 3);
            i = end;
            text_start = i;
        } else if next == b'!' || next == b'?' {
            flush(&mut builder, text_start, i);
            let end = rest.find('>').map_or(html.len(), |p| i + p + 1);
            i = end;
            text_start = i;
        } else if next == b'/' && rest.as_bytes().get(2).is_some_and(u8::is_ascii_alphabetic) {
            flush(&mut builder, text_start, i);
            let name_end = rest[2..]
                .find(|c: char| !is_name_char(c))
                .map_or(rest.len(), |p| p + 2);
            let tag = rest[2..name_end].to_ascii_lowercase();
            let end = rest.find('>').map_or(html.len(), |p| i + p + 1);
            builder.end(&tag);
            i = end;
            text_start = i;
        } else if next.is_ascii_alphabetic() {
            let Some(StartTag {
                tag,
                attrs,
                self_closing,
                consumed,
                dropped,
            }) = parse_start_tag(rest)
            else {
                i += 1;
                continue;
            };
            builder.dom.stats.dropped_attributes += dropped;
            flush(&mut builder, text_start, i);
            i += consumed;
            let raw = matches!(tag.as_str(), "script" | "style" | "noscript");
            let rcdata = matches!(tag.as_str(), "title" | "textarea");
            if (raw || rcdata) && !self_closing {
                let close = format!("</{tag}");
                let content_end = find_ci(&html[i..], &close).map_or(html.len(), |p| i + p);
                builder.start(tag.clone(), attrs, false);
                let content = &html[i..content_end];
                if raw {
                    builder.text(content.to_string());
                } else {
                    builder.text(decode_entities(content));
                }
                builder.end(&tag);
                i = html[content_end..]
                    .find('>')
                    .map_or(html.len(), |p| content_end + p + 1);
            } else {
                builder.start(tag, attrs, self_closing);
            }
            text_start = i;
        } else {
            i += 1;
        }
    }
    if text_start < html.len() {
        builder.text(decode_entities(&html[text_start..]));
    }
    if builder.over_limit {
        return Err(HtmlLimit::TooManyNodes);
    }
    Ok(builder.dom)
}

impl Dom {
    /// Lowercase tag of an element, `None` for text and the root.
    pub fn tag(&self, id: NodeId) -> Option<&str> {
        match &self.nodes.get(id)?.kind {
            NodeKind::Element { tag, .. } => Some(tag.as_str()),
            _ => None,
        }
    }

    /// Attribute value of an element.
    pub fn attr(&self, id: NodeId, name: &str) -> Option<&str> {
        match &self.nodes.get(id)?.kind {
            NodeKind::Element { attrs, .. } => attrs
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str()),
            _ => None,
        }
    }

    /// True when the class attribute lists `class`.
    pub fn has_class(&self, id: NodeId, class: &str) -> bool {
        self.attr(id, "class")
            .is_some_and(|value| value.split_ascii_whitespace().any(|c| c == class))
    }

    /// Children of `id`, empty for an id that is not in the tree.
    fn children_of(&self, id: NodeId) -> &[NodeId] {
        self.nodes
            .get(id)
            .map_or(&[], |node| node.children.as_slice())
    }

    /// Element descendants of `root` in document order (excluding `root`);
    /// empty for an id that is not in the tree.
    pub fn descendants(&self, root: NodeId) -> Vec<NodeId> {
        let mut out = Vec::new();
        let mut stack: Vec<NodeId> = self.children_of(root).iter().rev().copied().collect();
        while let Some(id) = stack.pop() {
            if matches!(
                self.nodes.get(id).map(|n| &n.kind),
                Some(NodeKind::Element { .. })
            ) {
                out.push(id);
                stack.extend(self.children_of(id).iter().rev().copied());
            }
        }
        out
    }

    /// First element in document order matching `predicate`.
    pub fn find(&self, root: NodeId, predicate: impl Fn(&Dom, NodeId) -> bool) -> Option<NodeId> {
        self.descendants(root)
            .into_iter()
            .find(|id| predicate(self, *id))
    }

    /// All elements in document order matching `predicate`.
    pub fn find_all(&self, root: NodeId, predicate: impl Fn(&Dom, NodeId) -> bool) -> Vec<NodeId> {
        self.descendants(root)
            .into_iter()
            .filter(|id| predicate(self, *id))
            .collect()
    }

    /// Concatenated text of a node and its descendants; empty for an id
    /// that is not in the tree.
    pub fn text_content(&self, id: NodeId) -> String {
        let mut out = String::new();
        let mut stack = vec![id];
        while let Some(node) = stack.pop() {
            match self.nodes.get(node).map(|n| &n.kind) {
                Some(NodeKind::Text(text)) => out.push_str(text),
                Some(_) => stack.extend(self.children_of(node).iter().rev().copied()),
                None => {}
            }
        }
        out
    }

    /// Detaches every node in `ids` from its parent in one pass over the
    /// tree; removed subtrees no longer appear in traversals.
    pub fn remove_all(&mut self, ids: &[NodeId]) {
        if ids.is_empty() {
            return;
        }
        let mut removed = vec![false; self.nodes.len()];
        for &id in ids {
            if let Some(flag) = removed.get_mut(id) {
                *flag = true;
            }
        }
        for (id, node) in self.nodes.iter_mut().enumerate() {
            if removed[id] {
                node.parent = None;
            }
            if node.children.iter().any(|child| removed[*child]) {
                node.children.retain(|child| !removed[*child]);
            }
        }
    }

    /// Element and text nodes under `root` (excluding `root`) in post-order:
    /// every node after all of its descendants. Empty for an id that is not
    /// in the tree.
    pub fn post_order(&self, root: NodeId) -> Vec<NodeId> {
        let mut out = Vec::new();
        let mut stack: Vec<(NodeId, bool)> = self
            .children_of(root)
            .iter()
            .rev()
            .map(|c| (*c, false))
            .collect();
        while let Some((id, expanded)) = stack.pop() {
            if expanded {
                out.push(id);
                continue;
            }
            stack.push((id, true));
            stack.extend(self.children_of(id).iter().rev().map(|c| (*c, false)));
        }
        out
    }

    /// The parent element, if any.
    pub fn parent_element(&self, id: NodeId) -> Option<NodeId> {
        let parent = self.nodes.get(id)?.parent?;
        self.tag(parent).map(|_| parent)
    }

    /// The first `html` element.
    pub fn document_element(&self) -> Option<NodeId> {
        self.find(0, |dom, id| dom.tag(id) == Some("html"))
    }

    /// The first `body` element.
    pub fn body(&self) -> Option<NodeId> {
        self.find(0, |dom, id| dom.tag(id) == Some("body"))
    }
}
