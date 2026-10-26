import assert from "node:assert/strict";
import { test } from "node:test";
import type { ContentElement, ContentNode } from "./model.js";
import { bm25Scores, filterRelevant, MAX_RELEVANCE_QUERY_BYTES, type RelevanceOptions } from "./relevance.js";

const el = (tag: string, attrs: Record<string, string>, ...children: Array<ContentNode | string>): ContentElement => ({
  kind: "element",
  tag,
  attrs: new Map(Object.entries(attrs)),
  children: children.map((c) => (typeof c === "string" ? { kind: "text", text: c } : c)),
  shown: true
});
const page = (...body: Array<ContentNode | string>): ContentElement =>
  el("#root", {}, el("html", {}, el("body", {}, ...body)));

function text(node: ContentNode): string {
  if (node.kind === "text") return node.text;
  return node.children.map(text).join(" ");
}
function count(node: ContentNode, tag: string): number {
  if (node.kind === "text") return 0;
  return (node.tag === tag ? 1 : 0) + node.children.reduce((sum, child) => sum + count(child, tag), 0);
}
const bm25 = (query: string, threshold: number): RelevanceOptions => ({ query, method: "bm25", threshold });
const occurrences = (haystack: string, needle: string): number => haystack.split(needle).length - 1;

// --- ported: crawl4ai tests/test_issue_1213_bm25_dedup.py ------------------

const TARGET =
  "Python is a versatile programming language widely used for web development, " +
  "data science, machine learning, and automation tasks across the industry.";
const FILLER = [
  "JavaScript powers interactive websites and runs in every modern browser environment.",
  "Rust provides memory safety without garbage collection through its ownership model.",
  "Go was designed at Google for building scalable network services and cloud infrastructure.",
  "Ruby on Rails popularized convention over configuration in web application frameworks.",
  "TypeScript adds static type checking to JavaScript for large-scale application development.",
  "Java remains dominant in enterprise software and Android mobile application development.",
  "C++ is essential for game engines, operating systems, and high-performance computing."
].map((t) => el("p", {}, t));
const withTarget = (copies: number, ...extra: ContentElement[]): ContentElement =>
  page(...Array.from({ length: copies }, () => el("p", {}, TARGET)), ...FILLER, ...extra);

test("ported: exact duplicates are collapsed to one", () => {
  const out = text(filterRelevant(withTarget(5), bm25("Python programming", 0.01)));
  assert.equal(occurrences(out, "versatile"), 1);
});

test("ported: unique paragraphs are kept, and none is repeated", () => {
  const out = filterRelevant(withTarget(1), bm25("programming languages", 0.01));
  assert.ok(count(out, "p") >= 1);
  const paragraphs = (out.children[0] as ContentElement).children[0] as ContentElement;
  const texts = paragraphs.children.map(text);
  assert.equal(new Set(texts).size, texts.length);
});

test("ported: duplicates after the filler collapse; uniques stay", () => {
  const out = text(filterRelevant(withTarget(1, el("p", {}, TARGET), el("p", {}, TARGET)), bm25("Python programming", 0.01)));
  assert.equal(occurrences(out, "versatile"), 1);
});

test("ported: the first occurrence is kept, in document order", () => {
  const first = "Python was created by Guido van Rossum in the early nineties as a successor to the ABC language.";
  const second = "Python supports multiple programming paradigms including procedural and functional styles.";
  const out = text(filterRelevant(page(el("p", {}, first), el("p", {}, second), el("p", {}, first), ...FILLER), bm25("Python history", 0.01)));
  assert.equal(occurrences(out, "Guido"), 1);
  assert.ok(out.indexOf("Guido") < out.indexOf("paradigms"));
});

test("ported: a threshold nothing reaches leaves an empty body", () => {
  const out = filterRelevant(withTarget(1), bm25("Python programming", 1000));
  assert.equal(text(out).trim(), "");
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
  const out = filterRelevant(root, { query: "x", method: "pruning" });
  assert.match(text(out).toLowerCase(), /good content paragraph/);
  assert.ok(count(out, "a") < 2, "the link block is gone");
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
  const options: RelevanceOptions = { query: "x", method: "pruning" };
  const out = filterRelevant(root, options);
  assert.ok(count(out, "article") + count(out, "h1") > 0);
  assert.match(text(out), /Long high-quality paragraph/);
  assert.deepEqual(filterRelevant(root, options), out);
});

test("pruning removes the excluded tags and empty boxes", () => {
  const root = page(
    el("nav", {}, "Home About Pricing"),
    el("header", {}, "Site header"),
    el("p", {}, "The refund policy allows returns within thirty days of purchase for any reason."),
    el("div", {}, el("span", {})),
    el("footer", {}, "Copyright")
  );
  const out = text(filterRelevant(root, { query: "x", method: "pruning" }));
  assert.match(out, /refund policy/);
  for (const gone of ["Home About", "Site header", "Copyright"]) assert.ok(!out.includes(gone), gone);
});

// --- BM25 itself -----------------------------------------------------------

test("BM25 Okapi matches rank_bm25 on a small corpus", () => {
  // rank_bm25 BM25Okapi([["refund","policy"],["shipping","times"],["refund","window","days"]])
  //   .get_scores(["refund","policy"]) — computed by hand below.
  const corpus = [
    ["refund", "policy"],
    ["shipping", "times"],
    ["refund", "window", "days"]
  ];
  const scores = bm25Scores(corpus, ["refund", "policy"]);
  const n = 3;
  const avg = 7 / 3;
  const raw = (df: number) => Math.log(n - df + 0.5) - Math.log(df + 0.5);
  const words = { refund: raw(2), policy: raw(1), shipping: raw(1), times: raw(1), window: raw(1), days: raw(1) };
  const mean = Object.values(words).reduce((a, b) => a + b, 0) / 6;
  const idfRefund = words.refund < 0 ? 0.25 * mean : words.refund;
  const term = (idf: number, f: number, len: number) => (idf * f * 2.5) / (f + 1.5 * (0.25 + (0.75 * len) / avg));
  const expected = [term(idfRefund, 1, 2) + term(words.policy, 1, 2), 0, term(idfRefund, 1, 3)];
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

test("a kept chunk keeps its images; dropped chunks take theirs", () => {
  const img = (alt: string) => el("img", { alt, src: `https://site.test/${alt}.png` });
  const root = page(
    el("p", {}, "The refund form is shown here.", img("form")),
    el("p", {}, "A photo of the warehouse floor.", img("floor")),
    el("p", {}, "Another unrelated caption about parcels.")
  );
  const out = filterRelevant(root, bm25("refund form", 0.5));
  assert.equal(count(out, "img"), 1);
  const alts: string[] = [];
  const pending: ContentNode[] = [out];
  while (pending.length > 0) {
    const at = pending.pop()!;
    if (at.kind === "element") {
      if (at.tag === "img") alts.push(at.attrs.get("alt") ?? "");
      pending.push(...at.children);
    }
  }
  assert.deepEqual(alts, ["form"]);
});

// --- Orcel's negatives -------------------------------------------------------

test("an empty query, or one of only stop words, filters nothing", () => {
  const root = withTarget(1);
  assert.equal(filterRelevant(root, bm25("", 1)), root);
  assert.equal(filterRelevant(root, bm25("   ", 1)), root);
  assert.equal(filterRelevant(root, bm25("the of and to", 1)), root);
  assert.equal(filterRelevant(root, { query: "", method: "pruning" }), root);
});

test("bad options are refused", () => {
  const root = withTarget(1);
  assert.throws(() => filterRelevant(root, bm25("x".repeat(MAX_RELEVANCE_QUERY_BYTES + 1), 1)));
  assert.throws(() => filterRelevant(root, bm25("a\u0007b", 1)));
  assert.throws(() => filterRelevant(root, bm25("python", -1)));
  assert.throws(() => filterRelevant(root, bm25("python", Number.NaN)));
  assert.throws(() => filterRelevant(root, { query: "python", method: "llm" as "bm25" }));
});

test("deep and wide pages are filtered without recursion and quickly", () => {
  let deep: ContentElement = el("p", {}, "refund policy text at the bottom of a deep tree");
  for (let i = 0; i < 20_000; i++) deep = el("div", {}, deep);
  const wide = Array.from({ length: 20_000 }, (_, i) => el("p", {}, `paragraph ${i} about shipping parcels`));
  const started = Date.now();
  assert.match(text2(filterRelevant(page(deep, ...wide), bm25("refund policy", 1))), /refund policy/);
  filterRelevant(page(deep, ...wide), { query: "x", method: "pruning" });
  assert.ok(Date.now() - started < 4_000);
});

/// `text` without recursion, for the deep tree.
function text2(node: ContentNode): string {
  const out: string[] = [];
  const pending: ContentNode[] = [node];
  while (pending.length > 0) {
    const at = pending.pop()!;
    if (at.kind === "text") out.push(at.text);
    else for (let i = at.children.length - 1; i >= 0; i--) pending.push(at.children[i]!);
  }
  return out.join(" ");
}
