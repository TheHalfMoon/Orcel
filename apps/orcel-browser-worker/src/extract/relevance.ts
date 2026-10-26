// WI-03: query-focused relevance filters over the content model, applied
// before Markdown is produced, so only relevant blocks reach the caller.
//
// Ported from unclecode/crawl4ai at commit
// 94b67888ca8b335ff2121423a50e06dd27661922, `crawl4ai/content_filter_strategy.py`
// (blob 24634ac328669dd5c0ed6cf0b5afb73e798178bc): `BM25ContentFilter` (with the base class's
// `extract_text_chunks`) and `PruningContentFilter`; and `clean_tokens` from
// `crawl4ai/utils.py` (blob b2e2cba7cfcac7327192143ad0308f9c1922d552); BM25 Okapi as in `rank_bm25`
// (k1 1.5, b 0.75, epsilon 0.25), which the donor calls. Apache License 2.0;
// the attribution notice is in
// docs/orcel/notices/crawl4ai-Apache-2.0-attribution.txt.
//
// Modifications for Orcel. Both filters work on the content model (rendered,
// visible text only) instead of raw HTML, so hidden text can never become
// relevant, and they return a pruned tree instead of HTML strings. An empty
// query (or one with no word left after stop words) means no filtering; the
// donor instead derives a query from the page's title, meta tags or first
// long paragraph, which here would let the page choose its own relevance.
// BM25: no stemming (the donor's `use_stemming=False` path); query and
// chunk words are split on white space as in the donor, then stripped of
// leading and trailing punctuation so "policy." matches "policy"; the text
// pieces of a chunk are joined with a space (the donor joins them with
// nothing, so `Hello <b>world</b>` became one word); a kept chunk keeps its
// own text and the images and breaks of its element, instead of the
// element's whole subtree, so text is never repeated; the query is bounded.
// Pruning: the donor's dynamic threshold (its fixed one keeps every block
// that has any text, so boilerplate links survive; the donor's own link and
// tag tests use the dynamic one), without `min_word_threshold`; `tag_len` is the length of the content
// model serialised as HTML, which no longer contains hidden markup; the
// class and id term is kept as in the donor, where it is never above zero
// (it is only ever negative, then clamped at zero), so it adds weight but no
// score.

import type { ContentElement, ContentNode, ContentText } from "./model.js";

export type RelevanceMethod = "bm25" | "pruning";

export interface RelevanceOptions {
  /// The words to look for. Empty means no filtering. Pruning does not use
  /// the words, only whether the filter is asked for.
  query: string;
  method: RelevanceMethod;
  /// Minimum score of a kept block (BM25 score times the tag's weight, or
  /// the pruning composite score). Defaults to the donor's.
  threshold?: number;
}

/// Longest relevance query, in UTF-8 bytes.
export const MAX_RELEVANCE_QUERY_BYTES = 1024;
/// Most query words scored (BM25 is linear in them).
export const MAX_RELEVANCE_QUERY_WORDS = 32;

export const RELEVANCE_DEFAULT_THRESHOLD: Readonly<Record<RelevanceMethod, number>> = {
  bm25: 1.0,
  pruning: 0.48
};

/// Refuses options the filter cannot honour; returns nothing when they are
/// usable.
export function checkRelevance(options: RelevanceOptions): void {
  if (options.method !== "bm25" && options.method !== "pruning") throw new Error("unknown relevance method");
  if (typeof options.query !== "string" || Buffer.byteLength(options.query, "utf8") > MAX_RELEVANCE_QUERY_BYTES) {
    throw new Error("relevance query is too long");
  }
  if (/\p{Cc}/u.test(options.query)) throw new Error("relevance query has control characters");
  const threshold = options.threshold;
  if (threshold !== undefined && !(Number.isFinite(threshold) && threshold >= 0)) {
    throw new Error("relevance threshold must be a finite non-negative number");
  }
}

/// The relevant part of `root`, or `root` itself when there is nothing to
/// filter by.
export function filterRelevant(root: ContentElement, options: RelevanceOptions): ContentElement {
  checkRelevance(options);
  if (options.query.trim() === "") return root;
  const threshold = options.threshold ?? RELEVANCE_DEFAULT_THRESHOLD[options.method];
  if (options.method === "pruning") return prune(root, threshold);
  const query = words(options.query).slice(0, MAX_RELEVANCE_QUERY_WORDS);
  if (query.length === 0) return root;
  return bm25Filter(root, query, threshold);
}

// --- shared --------------------------------------------------------------

/// The donor works from `<body>`; the model's root holds the document.
function bodyOf(root: ContentElement): ContentElement {
  const pending: ContentNode[] = [root];
  while (pending.length > 0) {
    const node = pending.pop()!;
    if (node.kind !== "element") continue;
    if (node.tag === "body") return node;
    for (let i = node.children.length - 1; i >= 0; i--) pending.push(node.children[i]!);
  }
  return root;
}

/// Rebuilds `root` with `body` replaced (the path to it is copied, nothing
/// else is).
function replaceBody(root: ContentElement, body: ContentElement, replacement: ContentElement): ContentElement {
  if (root === body) return replacement;
  const path: ContentElement[] = [];
  const pending: Array<{ node: ContentElement; depth: number }> = [{ node: root, depth: 0 }];
  while (pending.length > 0) {
    const { node, depth } = pending.pop()!;
    path.length = depth;
    path.push(node);
    if (node === body) break;
    for (let i = node.children.length - 1; i >= 0; i--) {
      const child = node.children[i]!;
      if (child.kind === "element") pending.push({ node: child, depth: depth + 1 });
    }
  }
  let rebuilt = replacement;
  for (let i = path.length - 2; i >= 0; i--) {
    const parent = path[i]!;
    const child = path[i + 1]!;
    rebuilt = { ...parent, children: parent.children.map((c) => (c === child ? rebuilt : c)) };
  }
  return rebuilt;
}

// --- BM25 ----------------------------------------------------------------

/// `clean_tokens` (crawl4ai/utils.py): noise and stop words.
const NOISE = new Set(["ccp", "up", "a", "an", "at", "by", "in", "of", "on", "to", "the"]);
const NOISE_PREFIXES = ["↑", "▲", "⬆"];
const STOP_WORDS = new Set(
  (
    "a about above across after against all along although am among an and any are around as at be because been " +
    "before behind being below beneath beside between beyond both but by can can't cannot could couldn't did do " +
    "does doing down during each except few for from had has have having he her hers herself him himself his how " +
    "i in inside into is it its itself may me might mine more most must mustn't my myself n't near no none nor " +
    "not of off on or other our ours ourselves out outside over past shall she should shouldn't since so some " +
    "such that the their theirs them themselves these they this those through to toward under underneath unless " +
    "until up upon us was we were what when where which who whom whose why will with within won't would wouldn't " +
    "yet you your yours yourself"
  ).split(" ")
);

/// Lower-cased white-space words without edge punctuation, minus noise and
/// stop words and words of two characters or fewer.
function words(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.toLowerCase().split(/\s+/)) {
    if (NOISE_PREFIXES.some((prefix) => raw.startsWith(prefix))) continue;
    const word = raw.replace(/^[^\p{L}\p{N}]+|[^\p{L}\p{N}]+$/gu, "");
    if ([...word].length > 2 && !NOISE.has(word) && !STOP_WORDS.has(word)) out.push(word);
  }
  return out;
}

/// Elements that do not end a chunk (`extract_text_chunks`' INLINE_TAGS).
const INLINE = new Set([
  "a", "abbr", "acronym", "b", "bdo", "big", "br", "button", "cite", "code", "dfn", "em", "i", "img", "input",
  "kbd", "label", "map", "object", "q", "samp", "script", "select", "small", "span", "strong", "sub", "sup",
  "textarea", "time", "tt", "var"
]);

/// The donor's tag weights for a chunk's closing element.
const PRIORITY: Readonly<Record<string, number>> = {
  h1: 5.0,
  h2: 4.0,
  h3: 3.0,
  title: 4.0,
  strong: 2.0,
  b: 1.5,
  em: 1.5,
  blockquote: 2.0,
  code: 2.0,
  pre: 1.5,
  th: 1.5
};

interface Chunk {
  text: string;
  element: ContentElement;
  pieces: ContentText[];
}

/// Text in document order, cut into chunks where a block element ends.
function textChunks(body: ContentElement): Chunk[] {
  const chunks: Chunk[] = [];
  let text: string[] = [];
  let pieces: ContentText[] = [];
  const flush = (element: ContentElement): void => {
    const joined = text.join(" ").split(/\s+/).filter(Boolean).join(" ");
    if (joined) chunks.push({ text: joined, element, pieces });
    text = [];
    pieces = [];
  };
  const pending: Array<{ node: ContentNode; visited: boolean }> = [{ node: body, visited: false }];
  while (pending.length > 0) {
    const { node, visited } = pending.pop()!;
    if (node.kind === "text") {
      const trimmed = node.text.trim();
      if (trimmed) {
        text.push(trimmed);
        pieces.push(node);
      }
      continue;
    }
    if (visited) {
      if (text.length > 0 && !INLINE.has(node.tag)) flush(node);
      continue;
    }
    if (node.children.length === 0) continue;
    pending.push({ node, visited: true });
    for (let i = node.children.length - 1; i >= 0; i--) pending.push({ node: node.children[i]!, visited: false });
  }
  if (text.length > 0) flush(body);
  return chunks;
}

/// BM25 Okapi scores of `corpus` for `query` (rank_bm25's BM25Okapi).
export function bm25Scores(corpus: readonly string[][], query: readonly string[]): number[] {
  const k1 = 1.5;
  const b = 0.75;
  const epsilon = 0.25;
  const size = corpus.length;
  const lengths = corpus.map((doc) => doc.length);
  const average = size > 0 ? lengths.reduce((sum, n) => sum + n, 0) / size : 0;
  const frequencies = corpus.map((doc) => {
    const counts = new Map<string, number>();
    for (const word of doc) counts.set(word, (counts.get(word) ?? 0) + 1);
    return counts;
  });
  const documents = new Map<string, number>();
  for (const counts of frequencies) for (const word of counts.keys()) documents.set(word, (documents.get(word) ?? 0) + 1);
  const idf = new Map<string, number>();
  const negative: string[] = [];
  let idfSum = 0;
  for (const [word, n] of documents) {
    const value = Math.log(size - n + 0.5) - Math.log(n + 0.5);
    idf.set(word, value);
    idfSum += value;
    if (value < 0) negative.push(word);
  }
  const floor = documents.size > 0 ? (epsilon * idfSum) / documents.size : 0;
  for (const word of negative) idf.set(word, floor);
  const scores = new Array<number>(size).fill(0);
  // An empty corpus (every chunk only stop words) scores nothing.
  if (average === 0) return scores;
  for (const word of query) {
    const weight = idf.get(word) ?? 0;
    if (weight === 0) continue;
    for (let i = 0; i < size; i++) {
      const f = frequencies[i]!.get(word) ?? 0;
      scores[i]! += (weight * (f * (k1 + 1))) / (f + k1 * (1 - b + (b * lengths[i]!) / average));
    }
  }
  return scores;
}

function bm25Filter(root: ContentElement, query: readonly string[], threshold: number): ContentElement {
  const body = bodyOf(root);
  const chunks = textChunks(body);
  const scores = bm25Scores(
    chunks.map((chunk) => words(chunk.text)),
    query
  );
  const keptText = new Set<ContentText>();
  const owners = new Set<ContentElement>();
  const seen = new Set<string>();
  chunks.forEach((chunk, i) => {
    const score = scores[i]! * (PRIORITY[chunk.element.tag] ?? 1.0);
    if (score < threshold || seen.has(chunk.text)) return;
    seen.add(chunk.text);
    owners.add(chunk.element);
    for (const piece of chunk.pieces) keptText.add(piece);
  });
  return replaceBody(root, body, keepOnly(body, keptText, owners) ?? { ...body, children: [] });
}

/// `node` reduced to the kept text, the elements that hold it, and the
/// childless elements (images, breaks) inside a kept chunk's element.
function keepOnly(
  node: ContentElement,
  keptText: ReadonlySet<ContentText>,
  owners: ReadonlySet<ContentElement>
): ContentElement | null {
  // Post-order without recursion: deep pages must not overflow the stack.
  const built = new Map<ContentElement, ContentElement | null>();
  const pending: Array<{ node: ContentElement; inOwner: boolean; visited: boolean }> = [
    { node, inOwner: owners.has(node), visited: false }
  ];
  const inOwnerOf = new Map<ContentElement, boolean>();
  while (pending.length > 0) {
    const entry = pending.pop()!;
    if (!entry.visited) {
      inOwnerOf.set(entry.node, entry.inOwner);
      pending.push({ ...entry, visited: true });
      for (const child of entry.node.children) {
        if (child.kind === "element") {
          pending.push({ node: child, inOwner: entry.inOwner || owners.has(child), visited: false });
        }
      }
      continue;
    }
    const children: ContentNode[] = [];
    for (const child of entry.node.children) {
      if (child.kind === "text") {
        if (keptText.has(child)) children.push(child);
      } else {
        const kept = built.get(child);
        if (kept) children.push(kept);
        else if (child.children.length === 0 && inOwnerOf.get(child)) children.push(child);
      }
    }
    built.set(entry.node, children.length > 0 ? { ...entry.node, children } : null);
  }
  return built.get(node) ?? null;
}

// --- pruning ---------------------------------------------------------------

/// `RelevantContentFilter.excluded_tags`, removed before scoring.
const EXCLUDED = new Set(["nav", "footer", "header", "aside", "script", "style", "form", "iframe", "noscript"]);
const TAG_WEIGHTS: Readonly<Record<string, number>> = {
  div: 0.5,
  p: 1.0,
  article: 1.5,
  section: 1.0,
  span: 0.3,
  li: 0.5,
  ul: 0.5,
  ol: 0.5,
  h1: 1.2,
  h2: 1.1,
  h3: 1.0,
  h4: 0.9,
  h5: 0.8,
  h6: 0.7
};
const METRIC_WEIGHTS = { textDensity: 0.4, linkDensity: 0.2, tagWeight: 0.2, classIdWeight: 0.1, textLength: 0.1 };
/// Dynamic threshold: important tags are kept more easily.
const TAG_IMPORTANCE: Readonly<Record<string, number>> = {
  article: 1.5,
  main: 1.4,
  section: 1.3,
  p: 1.2,
  h1: 1.4,
  h2: 1.3,
  h3: 1.2,
  div: 0.7,
  span: 0.6
};
const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"]);

const escapedLength = (text: string, attribute: boolean): number => {
  let extra = 0;
  for (const ch of text) {
    if (ch === "&") extra += 4;
    else if (ch === "<" || ch === ">") extra += 3;
    else if (attribute && ch === '"') extra += 5;
  }
  return text.length + extra;
};

/// `NavigableString` of a single-child chain, as bs4's `.string`.
function stringOf(node: ContentNode): string | null {
  let at: ContentNode = node;
  for (;;) {
    if (at.kind === "text") return at.text;
    if (at.children.length !== 1) return null;
    at = at.children[0]!;
  }
}

interface Metrics {
  textLen: number;
  tagLen: number;
}

function prune(root: ContentElement, threshold: number): ContentElement {
  const body = bodyOf(root);
  // Excluded tags go first, as in the donor; then each element's text
  // length and serialised inner length, bottom-up, once.
  const metrics = new Map<ContentElement, Metrics>();
  const cleaned = new Map<ContentElement, ContentElement>();
  const pending: Array<{ node: ContentElement; visited: boolean }> = [{ node: body, visited: false }];
  while (pending.length > 0) {
    const { node, visited } = pending.pop()!;
    if (!visited) {
      pending.push({ node, visited: true });
      for (const child of node.children) {
        if (child.kind === "element" && !EXCLUDED.has(child.tag)) pending.push({ node: child, visited: false });
      }
      continue;
    }
    const children: ContentNode[] = [];
    let textLen = 0;
    let tagLen = 0;
    for (const child of node.children) {
      if (child.kind === "text") {
        children.push(child);
        textLen += child.text.trim().length;
        tagLen += escapedLength(child.text, false);
        continue;
      }
      const kept = cleaned.get(child);
      if (!kept) continue;
      children.push(kept);
      const inner = metrics.get(kept)!;
      textLen += inner.textLen;
      let open = 1 + kept.tag.length;
      for (const [name, value] of kept.attrs) open += 4 + name.length + escapedLength(value, true);
      tagLen += VOID.has(kept.tag) && kept.children.length === 0 ? open + 2 : open + 1 + inner.tagLen + 3 + kept.tag.length;
    }
    const element: ContentElement = { ...node, children };
    cleaned.set(node, element);
    metrics.set(element, { textLen, tagLen });
  }

  // Whether `node` stays: its composite score against its own threshold.
  const keeps = (node: ContentElement): boolean => {
    const { textLen, tagLen } = metrics.get(node)!;
    let linkTextLen = 0;
    for (const child of node.children) {
      if (child.kind === "element" && child.tag === "a") linkTextLen += stringOf(child)?.trim().length ?? 0;
    }
    let bar = threshold;
    if ((TAG_IMPORTANCE[node.tag] ?? 0.7) > 1) bar *= 0.8;
    if ((tagLen > 0 ? textLen / tagLen : 0) > 0.4) bar *= 0.9;
    if ((textLen > 0 ? linkTextLen / textLen : 1) > 0.6) bar *= 1.2;
    let total = 0;
    total += METRIC_WEIGHTS.textDensity * (tagLen > 0 ? textLen / tagLen : 0);
    total += METRIC_WEIGHTS.linkDensity * (1 - (textLen > 0 ? linkTextLen / textLen : 0));
    total += METRIC_WEIGHTS.tagWeight * (TAG_WEIGHTS[node.tag] ?? 0.5);
    // The class and id term: never above zero in the donor (see above).
    total += METRIC_WEIGHTS.classIdWeight * 0;
    total += METRIC_WEIGHTS.textLength * Math.log(textLen + 1);
    const weights =
      METRIC_WEIGHTS.textDensity +
      METRIC_WEIGHTS.linkDensity +
      METRIC_WEIGHTS.tagWeight +
      METRIC_WEIGHTS.classIdWeight +
      METRIC_WEIGHTS.textLength;
    return total / weights >= bar;
  };

  // Top-down: a removed element takes its subtree; a kept one has its
  // element children scored in turn (text stays with its parent).
  const kept = new Map<ContentElement, ContentElement>();
  const cleanBody = cleaned.get(body)!;
  if (!keeps(cleanBody)) return replaceBody(root, body, { ...cleanBody, children: [] });
  const order: ContentElement[] = [cleanBody];
  const survivors = new Set<ContentElement>([cleanBody]);
  for (let i = 0; i < order.length; i++) {
    for (const child of order[i]!.children) {
      if (child.kind === "element" && keeps(child)) {
        survivors.add(child);
        order.push(child);
      }
    }
  }
  for (let i = order.length - 1; i >= 0; i--) {
    const node = order[i]!;
    const children: ContentNode[] = [];
    for (const child of node.children) {
      if (child.kind === "text") children.push(child);
      else if (survivors.has(child)) children.push(kept.get(child)!);
    }
    kept.set(node, { ...node, children });
  }
  return replaceBody(root, body, kept.get(cleanBody)!);
}
