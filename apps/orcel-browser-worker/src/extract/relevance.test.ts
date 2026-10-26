import assert from "node:assert/strict";
import { test } from "node:test";
import type { ContentElement, ContentNode } from "./model.js";
import {
  bm25Scores,
  filterRelevant as filterWith,
  MAX_RELEVANCE_QUERY_BYTES,
  type RelevanceOptions
} from "./relevance.js";

const el = (tag: string, attrs: Record<string, string>, ...children: Array<ContentNode | string>): ContentElement => ({
  kind: "element",
  tag,
  attrs: new Map(Object.entries(attrs)),
  children: children.map((c) => (typeof c === "string" ? { kind: "text", text: c } : c)),
  shown: true
});
const page = (...body: Array<ContentNode | string>): ContentElement =>
  el("#root", {}, el("html", {}, el("body", {}, ...body)));
const filterRelevant = (root: ContentElement, options: RelevanceOptions): ContentElement => filterWith(root, options).root;

/// The text of a tree, without recursion (some trees are deep).
function text(node: ContentNode): string {
  const out: string[] = [];
  const pending: ContentNode[] = [node];
  while (pending.length > 0) {
    const at = pending.pop()!;
    if (at.kind === "text") out.push(at.text);
    else for (let i = at.children.length - 1; i >= 0; i--) pending.push(at.children[i]!);
  }
  return out.join(" ");
}
function elements(node: ContentNode, tag: string): ContentElement[] {
  const out: ContentElement[] = [];
  const pending: ContentNode[] = [node];
  while (pending.length > 0) {
    const at = pending.pop()!;
    if (at.kind === "text") continue;
    if (at.tag === tag) out.push(at);
    for (let i = at.children.length - 1; i >= 0; i--) pending.push(at.children[i]!);
  }
  return out;
}
const bm25 = (query: string, threshold: number): RelevanceOptions => ({ query, method: "bm25", threshold });
const pruning: RelevanceOptions = { method: "pruning" };
const occurrences = (haystack: string, needle: string): number => haystack.split(needle).length - 1;
const paragraphs = (root: ContentElement): string[] => elements(root, "p").map(text);

// --- ported: crawl4ai tests/test_issue_1213_bm25_dedup.py ------------------

const TARGET =
  "Python is a versatile programming language widely used for web development, " +
  "data science, machine learning, and automation tasks across the industry.";
const FILLER_TEXT = [
  "JavaScript powers interactive websites and runs in every modern browser environment.",
  "Rust provides memory safety without garbage collection through its ownership model.",
  "Go was designed at Google for building scalable network services and cloud infrastructure.",
  "Ruby on Rails popularized convention over configuration in web application frameworks.",
  "TypeScript adds static type checking to JavaScript for large-scale application development.",
  "Java remains dominant in enterprise software and Android mobile application development.",
  "C++ is essential for game engines, operating systems, and high-performance computing."
];
const FILLER = FILLER_TEXT.map((t) => el("p", {}, t));
const withTarget = (copies: number, ...extra: ContentElement[]): ContentElement =>
  page(...Array.from({ length: copies }, () => el("p", {}, TARGET)), ...FILLER, ...extra);

test("ported: exact duplicates are collapsed to one", () => {
  const out = text(filterRelevant(withTarget(5), bm25("Python programming", 0.01)));
  assert.equal(occurrences(out, "versatile"), 1);
});

test("ported: unique paragraphs are kept, and none is repeated", () => {
  // "programming" is only in the target; "languages" is in no chunk.
  assert.deepEqual(paragraphs(filterRelevant(withTarget(1), bm25("programming languages", 0.01))), [TARGET]);
  // "application" is in three filler paragraphs: all three, once each, in order.
  assert.deepEqual(paragraphs(filterRelevant(withTarget(1), bm25("application", 0.01))), [
    FILLER_TEXT[3],
    FILLER_TEXT[4],
    FILLER_TEXT[5]
  ]);
});

test("ported: duplicates after the filler collapse; uniques stay", () => {
  const out = filterRelevant(withTarget(1, el("p", {}, TARGET), el("p", {}, TARGET)), bm25("Python programming", 0.01));
  assert.deepEqual(paragraphs(out), [TARGET]);
});

test("ported: the first occurrence is kept, in document order", () => {
  const first = "Python was created by Guido van Rossum in the early nineties as a successor to the ABC language.";
  const second = "Python supports multiple programming paradigms including procedural and functional styles.";
  const out = text(filterRelevant(page(el("p", {}, first), el("p", {}, second), el("p", {}, first), ...FILLER), bm25("Python history", 0.01)));
  assert.equal(occurrences(out, "Guido"), 1);
  assert.ok(out.indexOf("Guido") < out.indexOf("paradigms"));
});

test("ported: a threshold nothing reaches leaves an empty body, and says so", () => {
  const result = filterWith(withTarget(1), bm25("Python programming", 1000));
  assert.equal(text(result.root).trim(), "");
  assert.equal(result.nothingRelevant, true);
  assert.equal(result.timedOut, false);
  assert.equal(filterWith(withTarget(1), bm25("Python programming", 0.01)).nothingRelevant, false);
});

// --- ported: crawl4ai tests/async/test_content_filter_prune.py -------------

test("ported: link-heavy blocks are pruned and the content paragraph stays", () => {
  const root = page(
    el(
      "div",
      { class: "content" },
      el("p", {}, "Good content paragraph that should remain."),
      el(
        "div",
        { class: "links" },
        el("a", { href: "#" }, "Link 1"),
        el("a", { href: "#" }, "Link 2"),
        el("a", { href: "#" }, "Link 3"),
        el("a", { href: "#" }, "Link 4")
      )
    )
  );
  const out = filterRelevant(root, pruning);
  assert.deepEqual(paragraphs(out), ["Good content paragraph that should remain."]);
  assert.equal(elements(out, "a").length, 0, "the link block is gone");
});

test("ported: important tags are kept, and the output is the same every run", () => {
  const root = page(
    el(
      "article",
      {},
      el("h1", {}, "Article Title"),
      el("p", { class: "summary" }, "Short summary."),
      el(
        "div",
        { class: "content" },
        el(
          "p",
          {},
          "Long high-quality paragraph with substantial content that should definitely survive the pruning process. " +
            "This content has good text density and proper formatting which makes it valuable for retention."
        )
      ),
      el("div", { class: "comments" }, el("p", {}, "Short comment 1"), el("p", {}, "Short comment 2"))
    )
  );
  const out = filterRelevant(root, pruning);
  assert.equal(elements(out, "article").length, 1);
  assert.equal(elements(out, "h1").length, 1);
  assert.match(text(out), /Long high-quality paragraph/);
  assert.deepEqual(filterRelevant(root, pruning), out);
});

test("pruning removes excluded tags, empty boxes and loose body text, as the donor does", () => {
  const root = page(
    el("nav", {}, "Home About Pricing"),
    el("header", {}, "Site header"),
    "Loose body text menu",
    el("p", {}, "The refund policy allows returns within thirty days of purchase for any reason."),
    el("div", {}, el("span", {})),
    el("footer", {}, "Copyright")
  );
  const out = filterRelevant(root, pruning);
  const body = elements(out, "body")[0]!;
  assert.deepEqual(
    body.children.map((child) => (child.kind === "element" ? child.tag : "#text")),
    ["p"]
  );
  assert.match(text(out), /refund policy/);
});

// --- BM25 itself -----------------------------------------------------------

test("BM25 Okapi gives rank_bm25's scores", () => {
  // Literal values from an independent Python evaluation of BM25Okapi on
  // this corpus ("refund" is in two of three documents, so its idf is
  // negative and takes the epsilon floor).
  const scores = bm25Scores(
    [
      ["refund", "policy"],
      ["shipping", "times"],
      ["refund", "window", "days"]
    ],
    ["refund", "policy"]
  );
  const expected = [0.6369072662731181, 0, 0.07543838325658092];
  scores.forEach((s, i) => assert.ok(Math.abs(s - expected[i]!) < 1e-12, `${i}: ${s} vs ${expected[i]}`));
  assert.deepEqual(bm25Scores([[], []], ["refund"]), [0, 0], "no words, no NaN");
});

test("a query for one section keeps that section; headings weigh more", () => {
  const root = page(
    el("h2", {}, "Shipping"),
    el("p", {}, "Orders ship within two business days from our warehouse."),
    el("h2", {}, "Refund policy"),
    el("p", {}, "Under this refund policy, money is returned within thirty days; the refund goes to the original card."),
    el("h2", {}, "Contact"),
    el("p", {}, "Write to the support desk for anything else.")
  );
  // The paragraph scores about 0.94 (BM25 favours short chunks); the
  // unrelated ones score zero.
  const out = text(filterRelevant(root, bm25("refund policy", 0.5)));
  assert.match(out, /Refund policy/);
  assert.match(out, /refund goes to the original card/);
  assert.ok(!out.includes("warehouse") && !out.includes("support desk"));
});

test("text pieces are joined with a space, and edge punctuation does not hide a word", () => {
  const root = page(
    el("p", {}, "Read the", el("b", {}, "policy."), "today"),
    el("p", {}, "Unrelated words about shipping and delivery times."),
    el("p", {}, "More unrelated words about cartons and parcels.")
  );
  const out = text(filterRelevant(root, bm25("policy", 0.5)));
  assert.match(out, /policy\./);
  assert.ok(!out.includes("shipping"));
});

test("a kept chunk keeps only its own images, even when a container closes it", () => {
  const img = (alt: string) => el("img", { alt, src: `https://site.test/${alt}.png` });
  const alts = (root: ContentElement) => elements(root, "img").map((image) => image.attrs.get("alt"));
  const root = page(
    el("p", {}, "The refund form is shown here.", img("form")),
    el("p", {}, "A photo of the warehouse floor.", img("floor")),
    el("p", {}, "Another unrelated caption about parcels.")
  );
  assert.deepEqual(alts(filterRelevant(root, bm25("refund form", 0.5))), ["form"]);
  // Loose text after nested blocks is closed by the body; the images in the
  // dropped paragraphs are not that chunk's.
  const loose = page(
    el("p", {}, "Unrelated caption about parcels.", img("parcel")),
    el("figure", {}, img("figure")),
    el("p", {}, "Another unrelated caption about cartons."),
    "Refund policy details follow here.",
    img("refund")
  );
  assert.deepEqual(alts(filterRelevant(loose, bm25("refund policy", 0.5))), ["refund"]);
});

// --- Orcel's negatives -------------------------------------------------------

test("an empty query, or one of only stop words, filters nothing; pruning needs none", () => {
  const root = withTarget(1);
  for (const query of ["", "   ", "the of and to", undefined]) {
    const result = filterWith(root, query === undefined ? { method: "bm25" } : { method: "bm25", query });
    assert.equal(result.root, root);
    assert.equal(result.nothingRelevant, false);
  }
  assert.notEqual(filterRelevant(root, pruning), root, "pruning runs without a query");
});

test("bad options are refused", () => {
  const root = withTarget(1);
  assert.throws(() => filterRelevant(root, bm25("x".repeat(MAX_RELEVANCE_QUERY_BYTES + 1), 1)));
  assert.throws(() => filterRelevant(root, bm25("a\u0007b", 1)));
  assert.throws(() => filterRelevant(root, bm25("python", -1)));
  assert.throws(() => filterRelevant(root, bm25("python", Number.NaN)));
  assert.throws(() => filterRelevant(root, { query: "python", method: "llm" as "bm25" }));
});

test("page text cannot make word splitting slow", () => {
  // A long punctuation run inside one word was quadratic with a regex.
  const hostile = page(el("p", {}, `a${"!".repeat(200_000)}b refund`), el("p", {}, "other words here"));
  const started = Date.now();
  filterRelevant(hostile, bm25("refund", 0.01));
  assert.ok(Date.now() - started < 2_000, `${Date.now() - started} ms`);
});

test("filtering stops at the deadline and reports it", () => {
  const wide = page(...Array.from({ length: 20_000 }, (_, i) => el("p", {}, `paragraph ${i} about refund parcels`)));
  for (const options of [bm25("refund", 0.01), pruning]) {
    const result = filterWith(wide, options, Date.now() - 1);
    assert.equal(result.timedOut, true);
    assert.equal(text(result.root).trim(), "");
  }
});

test("deep and wide pages are filtered without recursion and quickly", () => {
  let deep: ContentElement = el("p", {}, "refund policy text at the bottom of a deep tree");
  for (let i = 0; i < 20_000; i++) deep = el("div", {}, deep);
  const wide = Array.from({ length: 20_000 }, (_, i) => el("p", {}, `paragraph ${i} about shipping parcels`));
  const started = Date.now();
  assert.match(text(filterRelevant(page(deep, ...wide), bm25("refund policy", 1))), /refund policy/);
  const pruned = filterRelevant(page(deep, ...wide), pruning);
  assert.match(text(pruned), /refund policy text at the bottom/);
  assert.equal(elements(pruned, "p").length, 20_001);
  assert.ok(Date.now() - started < 4_000);
});
