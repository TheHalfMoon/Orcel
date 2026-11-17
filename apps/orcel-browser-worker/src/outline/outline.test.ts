// W2-03: tests for the accessibility outline, the schema extraction and the
// outline targets, against a fake read-only CDP session (no engine, no
// network, no model).

import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";
import {
  boundOutline,
  captureOutline,
  MAX_AX_DEPTH,
  MAX_OUTLINE_DEPTH,
  MAX_OUTLINE_JSON_BYTES,
  MAX_OUTLINE_NAME_BYTES,
  MAX_OUTLINE_NODES,
  OUTLINE_METHODS,
  OutlineRefused,
  readOnlyCdp,
  type OutlineNode
} from "./capture.js";
import { buildHierarchicalTree, decorateRoles, MAX_TREE_DEPTH, removeRedundantStaticTextChildren, withholdNames, type A11yNode, type AxNode } from "./a11y-tree.js";
import { MAX_DOM_NODES } from "./dom-tree.js";
import { extractBySchema, MAX_SCHEMA_LIST_ITEMS, nodeText } from "./schema-extract.js";
import { resolveOutlineTarget } from "./targets.js";
import { cleanText, untrustedText } from "./tree-format.js";
import type { CdpReader } from "./dom-tree.js";
import type { CdpDomNode } from "./xpath.js";

// --- A fixture page --------------------------------------------------------

const el = (be: number, name: string, children: CdpDomNode[] = [], attributes?: string[]): CdpDomNode => ({
  nodeId: be,
  backendNodeId: be,
  nodeType: name.startsWith("#text") ? 3 : name === "#document" ? 9 : 1,
  nodeName: name.startsWith("#text") ? "#text" : name,
  childNodeCount: children.length,
  children,
  ...(attributes ? { attributes } : {})
});

function fixtureDom(): CdpDomNode {
  const iframe = { ...el(27, "IFRAME"), contentDocument: el(28, "#document", [el(29, "HTML", [el(30, "BODY", [el(31, "INPUT")])])]) };
  return el(1, "#document", [
    el(2, "HTML", [
      el(3, "HEAD"),
      el(4, "BODY", [
        el(5, "H1", [el(6, "#text")]),
        el(7, "A", [el(8, "#text")]),
        el(32, "A", [el(34, "#text")]),
        el(9, "P", [el(10, "#text")]),
        el(11, "LABEL", [el(12, "#text"), el(13, "INPUT", [], ["type", "password"])]),
        el(14, "DIV", [el(15, "#text"), el(16, "INPUT", [], ["type", "text"])]),
        el(17, "BUTTON"),
        el(18, "DIV", [el(19, "#text")]),
        el(20, "X-PAY", [el(21, "#text"), el(35, "#text")]),
        el(22, "UL", [el(23, "LI", [el(24, "#text")]), el(25, "LI", [el(26, "#text")])]),
        el(33, "H2"),
        iframe
      ])
    ])
  ]);
}

const contents = (value: string) => ({ value, sources: [{ type: "contents", value: { value } }] });
const text = (id: string, be: number, parent: string, value: string): AxNode => ({ nodeId: id, role: { value: "StaticText" }, name: { value }, parentId: parent, backendDOMNodeId: be });

function fixtureAx(): AxNode[] {
  return [
    { nodeId: "1", role: { value: "RootWebArea" }, name: contents("Park fees"), childIds: ["2"], backendDOMNodeId: 1 },
    { nodeId: "2", ignored: true, role: { value: "none" }, parentId: "1", childIds: ["4"], backendDOMNodeId: 2 },
    {
      nodeId: "4",
      role: { value: "generic" },
      parentId: "2",
      childIds: ["5", "7", "32", "9", "11", "14", "17", "18", "20", "22", "33", "27", "31"],
      backendDOMNodeId: 4
    },
    { nodeId: "5", role: { value: "heading" }, name: contents("Fees & passes"), parentId: "4", childIds: ["6"], backendDOMNodeId: 5 },
    text("6", 6, "5", "Fees & passes"),
    {
      nodeId: "7",
      role: { value: "link" },
      name: contents("Pay\u202e online"),
      parentId: "4",
      childIds: ["8"],
      backendDOMNodeId: 7,
      properties: [{ name: "url", value: { value: "https://fixture.test/pay" } }]
    },
    text("8", 8, "7", "Pay online"),
    {
      nodeId: "32",
      role: { value: "link" },
      name: contents("Run"),
      parentId: "4",
      childIds: ["34"],
      backendDOMNodeId: 32,
      properties: [{ name: "url", value: { value: "javascript:alert(1)" } }]
    },
    text("34", 34, "32", "Run"),
    { nodeId: "9", role: { value: "paragraph" }, parentId: "4", childIds: ["10"], backendDOMNodeId: 9 },
    text("10", 10, "9", "Entrance fee is $35."),
    { nodeId: "11", role: { value: "LabelText" }, parentId: "4", childIds: ["12", "13"], backendDOMNodeId: 11 },
    text("12", 12, "11", "Password"),
    {
      nodeId: "13",
      role: { value: "textbox" },
      name: { value: "Password", sources: [{ type: "relatedElement", value: { value: "Password" } }] },
      parentId: "11",
      backendDOMNodeId: 13,
      properties: [{ name: "editable", value: { value: "plaintext" } }]
    },
    { nodeId: "14", role: { value: "generic" }, parentId: "4", childIds: ["15", "16"], backendDOMNodeId: 14 },
    text("15", 15, "14", "Card"),
    { nodeId: "16", role: { value: "textbox" }, name: contents(""), parentId: "14", childIds: ["16a"], backendDOMNodeId: 16 },
    { nodeId: "16a", role: { value: "StaticText" }, name: { value: "4111 1111 1111 1111" }, parentId: "16" },
    {
      nodeId: "17",
      role: { value: "button" },
      name: { value: "Card 4111 1111 1111 1111", sources: [{ type: "relatedElement", attribute: "aria-labelledby", value: { value: "Card 4111" } }] },
      parentId: "4",
      backendDOMNodeId: 17
    },
    {
      nodeId: "18",
      role: { value: "generic" },
      name: contents("draft message"),
      parentId: "4",
      childIds: ["19"],
      backendDOMNodeId: 18,
      properties: [{ name: "editable", value: { value: "richtext" } }]
    },
    text("19", 19, "18", "draft message"),
    { nodeId: "20", role: { value: "generic" }, parentId: "4", childIds: ["21", "35"], backendDOMNodeId: 20 },
    text("21", 21, "20", "Pay"),
    text("35", 35, "20", "now"),
    { nodeId: "22", role: { value: "list" }, parentId: "4", childIds: ["23", "25"], backendDOMNodeId: 22 },
    { nodeId: "23", role: { value: "listitem" }, parentId: "22", childIds: ["24"], backendDOMNodeId: 23 },
    text("24", 24, "23", "Adult $35"),
    { nodeId: "25", role: { value: "listitem" }, parentId: "22", childIds: ["26"], backendDOMNodeId: 25 },
    text("26", 26, "25", "Child free"),
    { nodeId: "33", role: { value: "heading" }, name: { value: "No sources" }, parentId: "4", backendDOMNodeId: 33 },
    { nodeId: "27", role: { value: "Iframe" }, parentId: "4", backendDOMNodeId: 27 },
    // A node of the iframe's document: never part of the main outline.
    { nodeId: "31", role: { value: "textbox" }, name: contents("inner"), parentId: "4", backendDOMNodeId: 31 }
  ];
}

function fakeCdp(dom = fixtureDom(), ax = fixtureAx()) {
  const methods: string[] = [];
  const params: Array<Record<string, unknown> | undefined> = [];
  const session = {
    async send(method: string, param?: Record<string, unknown>): Promise<unknown> {
      methods.push(method);
      params.push(param);
      if (method === "DOM.getDocument") return { root: dom };
      if (method === "Accessibility.getFullAXTree") return { nodes: ax };
      if (method === "Runtime.evaluate") return { result: { value: "ran page script" } };
      return {};
    }
  };
  return { cdp: readOnlyCdp(session as never), methods, params, raw: session };
}

function all(nodes: OutlineNode[]): OutlineNode[] {
  const out: OutlineNode[] = [];
  const stack = [...nodes];
  while (stack.length) {
    const node = stack.shift()!;
    out.push(node);
    stack.unshift(...node.children);
  }
  return out;
}

const byId = (nodes: OutlineNode[], id: string) => all(nodes).find((n) => n.id === id);

// --- Capture ---------------------------------------------------------------

test("the outline is read with the five allowed CDP read methods only", async () => {
  const { cdp, methods } = fakeCdp();
  await captureOutline(cdp);
  assert.ok(methods.length > 0);
  for (const method of methods) assert.ok(OUTLINE_METHODS.has(method), method);
  await assert.rejects(cdp.send("Runtime.evaluate", { expression: "1" }), OutlineRefused);
  await assert.rejects(cdp.send("Input.dispatchMouseEvent"), OutlineRefused);
  await assert.rejects(cdp.send("DOM.setAttributeValue"), OutlineRefused);
  assert.ok(!methods.includes("Runtime.evaluate"));
});

test("the outline keeps page structure, links and text, with element XPaths", async () => {
  const { cdp } = fakeCdp();
  const { nodes, truncated } = await captureOutline(cdp);
  assert.equal(truncated, false);
  const heading = byId(nodes, "0-5");
  assert.deepEqual(heading && { role: heading.role, name: heading.name, xpath: heading.xpath }, {
    role: "heading",
    name: "Fees & passes",
    xpath: "/html[1]/body[1]/h1[1]"
  });
  // Its redundant text child was pruned (Stagehand's removeRedundantStaticTextChildren).
  assert.deepEqual(heading?.children, []);
  const link = byId(nodes, "0-7");
  assert.equal(link?.url, "https://fixture.test/pay");
  // The bidirectional override is gone from the cleaned name.
  assert.equal(link?.name, "Pay online");
  // A javascript: URL never crosses.
  assert.equal(byId(nodes, "0-32")?.url, undefined);
  assert.equal(byId(nodes, "0-10")?.name, "Entrance fee is $35.");
  // A generic node shows a plain tag, never a custom element's name.
  assert.equal(byId(nodes, "0-4")?.role, "body");
  assert.equal(byId(nodes, "0-20")?.role, "generic");
  // The iframe is a leaf; its document's nodes are not in the outline.
  assert.equal(byId(nodes, "0-27")?.children.length, 0);
  assert.equal(byId(nodes, "0-31"), undefined);
});

test("no field value and no name that could carry one reaches the outline", async () => {
  const { cdp } = fakeCdp();
  const { nodes } = await captureOutline(cdp);
  const wire = JSON.stringify(nodes);
  for (const secret of ["4111", "draft message", "hunter2"]) assert.ok(!wire.includes(secret), secret);
  assert.ok(!wire.includes('"value"'));
  // The password field (a control) and its label (which holds it) carry no name.
  assert.equal(byId(nodes, "0-13")?.name, "");
  assert.equal(byId(nodes, "0-11")?.name, "");
  // The label's own text node is plain text and stays.
  assert.equal(byId(nodes, "0-12")?.name, "Password");
  // Named through aria-labelledby: withheld.
  assert.equal(byId(nodes, "0-17")?.name, "");
  // A name whose source the engine did not report: withheld.
  assert.equal(byId(nodes, "0-33")?.name, "");
});

test("decorated roles and name withholding follow the module rules", () => {
  const opts = { tagNameMap: { "0-1": "div", "0-2": "input, file", "0-3": "html" }, scrollableMap: { "0-1": true }, encode: (be: number) => `0-${be}` };
  const decorated = decorateRoles(
    [
      { nodeId: "a", role: { value: "generic" }, backendDOMNodeId: 1, childIds: ["b"] },
      { nodeId: "b", role: { value: "button" }, name: contents("Upload"), parentId: "a", backendDOMNodeId: 2 },
      { nodeId: "c", role: { value: "generic" }, backendDOMNodeId: 3 }
    ],
    opts
  );
  assert.equal(decorated[0]?.role, "scrollable, div");
  assert.equal(decorated[1]?.role, "input, file");
  assert.equal(decorated[1]?.control, true);
  assert.equal(decorated[2]?.role, "scrollable, html");
  const flat: A11yNode[] = [
    { nodeId: "p", role: "button", name: "Pay 4111", childIds: ["q"] },
    { nodeId: "q", role: "textbox", name: "4111", control: true, parentId: "p" },
    { nodeId: "h", role: "heading", name: "Fees", childIds: ["t"] },
    { nodeId: "t", role: "StaticText", name: "Fees", parentId: "h" }
  ];
  assert.equal(withholdNames(flat), 2);
  assert.deepEqual(flat.map((n) => n.name), ["", "", "Fees", "Fees"]);
  // An incomplete list (a named child is missing) withholds every name but
  // a text node's own text.
  const cut: A11yNode[] = [
    { nodeId: "h", role: "heading", name: "Fees", childIds: ["t", "gone"] },
    { nodeId: "t", role: "StaticText", name: "Fees", parentId: "h" }
  ];
  withholdNames(cut);
  assert.deepEqual(cut.map((n) => n.name), ["", "Fees"]);
  // Stagehand's static-text dedupe.
  const parent: A11yNode = { nodeId: "x", role: "link", name: "Read  more" };
  const kids: A11yNode[] = [
    { nodeId: "y", role: "StaticText", name: "Read" },
    { nodeId: "z", role: "StaticText", name: "more" }
  ];
  assert.deepEqual(removeRedundantStaticTextChildren(parent, kids), kids);
  assert.deepEqual(removeRedundantStaticTextChildren({ ...parent, name: "Readmore" }, kids), []);
  const { tree: built } = buildHierarchicalTree(
    [
      { nodeId: "r", role: "generic", childIds: ["s"] },
      { nodeId: "s", role: "heading", name: "Only", parentId: "r" }
    ],
    { tagNameMap: {}, scrollableMap: {}, encode: (be) => `0-${be}` }
  );
  // A structural node with one child is replaced by it.
  assert.equal(built[0]?.nodeId, "s");
});

test("the outline is bounded in nodes, depth, name bytes and frame bytes", () => {
  const wide: A11yNode[] = [
    {
      nodeId: "r",
      role: "list",
      encodedId: "0-1",
      children: Array.from({ length: 2000 }, (_, i) => ({ nodeId: `n${i}`, role: "listitem", name: `item ${i} ${"x".repeat(200)}`, encodedId: `0-${i + 2}` }))
    }
  ];
  const big = boundOutline(wide, {}, {});
  assert.equal(big.truncated, true);
  assert.ok(all(big.nodes).length <= MAX_OUTLINE_NODES);
  assert.ok(Buffer.byteLength(JSON.stringify(big.nodes), "utf8") <= MAX_OUTLINE_JSON_BYTES);
  let deep: A11yNode = { nodeId: "leaf", role: "group", encodedId: "0-1" };
  for (let i = 0; i < MAX_OUTLINE_DEPTH + 10; i++) deep = { nodeId: `d${i}`, role: "group", encodedId: `0-${i + 2}`, children: [deep] };
  const deepOut = boundOutline([deep], {}, {});
  assert.equal(deepOut.truncated, true);
  const long = boundOutline([{ nodeId: "a", role: "heading", name: "\u00e9".repeat(MAX_OUTLINE_NAME_BYTES), encodedId: "0-1" }], {}, {});
  assert.ok(Buffer.byteLength(long.nodes[0]!.name, "utf8") <= MAX_OUTLINE_NAME_BYTES);
  // Malformed ids and roles never cross as given.
  const odd = boundOutline([{ nodeId: "a", role: "role<script>", encodedId: "9-1; drop" }], {}, {});
  assert.deepEqual(odd.nodes[0] && { id: odd.nodes[0].id, role: odd.nodes[0].role }, { id: "", role: "generic" });
});

test("a malformed accessibility tree fails the outline", async () => {
  const { cdp } = fakeCdp(fixtureDom(), "nope" as unknown as AxNode[]);
  await assert.rejects(captureOutline(cdp));
});

// --- Untrusted text --------------------------------------------------------

test("untrusted page text is repaired, stripped and bounded", () => {
  // Lone surrogates are repaired (Stagehand's toWellFormed).
  assert.equal(untrustedText("a\ud800b", 64), "a\ufffdb");
  assert.equal(untrustedText("pay\u202enow\u2066x\u2069", 64), "paynowx");
  assert.equal(untrustedText("zero\u200bwidth\ufeff", 64), "zerowidth");
  assert.equal(untrustedText("line\nbreak\u2028sep\ttab", 64), "line break sep tab");
  assert.equal(untrustedText("bell\u0007nul\u0000del\u007fc1\u0085", 64), "bellnuldelc1");
  assert.equal(untrustedText("  many   spaces\u00a0 here ", 64), "many spaces here");
  assert.equal(untrustedText("\ue000private use", 64), "private use");
  assert.equal(untrustedText("\u00e9\u00e9\u00e9", 5), "\u00e9\u00e9");
  assert.equal(cleanText("\u00a0 x \u00a0"), "x");
});

// --- Schema extraction -----------------------------------------------------

test("schema fields extract text, lists and URLs from the outline without a model", async () => {
  const { cdp } = fakeCdp();
  const { nodes } = await captureOutline(cdp);
  const { values, truncated } = extractBySchema(nodes, [
    { key: "title", take: "text", role: "heading", name: "Fees & passes" },
    { key: "fee", take: "text", xpath: "/html[1]/body[1]/p[1]" },
    { key: "rows", take: "texts", role: "listitem" },
    { key: "rows_by_path", take: "texts", xpath: "/html[1]/body[1]/ul[1]" },
    { key: "pay", take: "url", role: "link", name: "Pay online" },
    { key: "script", take: "url", role: "link", name: "Run" },
    { key: "missing", take: "text", role: "table" },
    { key: "password", take: "text", role: "textbox" },
    { key: "button", take: "text", role: "button" }
  ]);
  assert.equal(truncated, false);
  assert.deepEqual(values, [
    { key: "title", found: true, text: "Fees & passes" },
    { key: "fee", found: true, text: "Entrance fee is $35." },
    { key: "rows", found: true, texts: ["Adult $35", "Child free"] },
    { key: "rows_by_path", found: true, texts: ["Adult $35", "Child free"] },
    { key: "pay", found: true, url: "https://fixture.test/pay" },
    { key: "script", found: false },
    { key: "missing", found: false },
    // Withheld names extract nothing: a schema can never read a value.
    { key: "password", found: false },
    { key: "button", found: false }
  ]);
});

test("schema lists are bounded", () => {
  const nodes: OutlineNode[] = Array.from({ length: MAX_SCHEMA_LIST_ITEMS + 5 }, (_, i) => ({ id: `0-${i}`, role: "row", name: `r${i}`, xpath: "", children: [] }));
  const { values, truncated } = extractBySchema(nodes, [{ key: "rows", take: "texts", role: "row" }]);
  assert.equal(truncated, true);
  assert.equal(values[0]?.texts?.length, MAX_SCHEMA_LIST_ITEMS);
  assert.equal(nodeText({ id: "0-1", role: "cell", name: "", xpath: "", children: [{ id: "", role: "StaticText", name: "a", xpath: "", children: [] }] }, 16), "a");
});

// --- Targets ---------------------------------------------------------------

test("an outline id resolves to its XPath, role and name, or to nothing", async () => {
  const { cdp } = fakeCdp();
  const { nodes } = await captureOutline(cdp);
  assert.deepEqual(resolveOutlineTarget(nodes, "0-7"), { id: "0-7", xpath: "/html[1]/body[1]/a[1]", role: "link", name: "Pay online" });
  assert.equal(resolveOutlineTarget(nodes, "0-999"), null);
  assert.equal(resolveOutlineTarget(nodes, "xpath=/html"), null);
});

// --- No network ------------------------------------------------------------

test("the outline modules import nothing that can reach a network or run a model", () => {
  const dir = new URL("../../src/outline/", import.meta.url);
  const sources = readdirSync(dir).filter((name) => name.endsWith(".ts") && !name.endsWith(".test.ts"));
  assert.ok(sources.length >= 6);
  for (const name of sources) {
    const source = readFileSync(new URL(name, dir), "utf8");
    for (const banned of ["node:http", "node:https", "node:net", "node:dgram", "node:tls", "fetch(", "WebSocket", "XMLHttpRequest", "browserbase", "Runtime.evaluate", "Runtime.callFunctionOn", "openai", "anthropic"]) {
      const lines = source.split("\n").filter((line) => !line.trimStart().startsWith("//") && !line.trimStart().startsWith("*"));
      assert.ok(!lines.join("\n").toLowerCase().includes(banned.toLowerCase()), `${name} mentions ${banned}`);
    }
    const imports = [...source.matchAll(/from "([^"]+)"/g)].map((m) => m[1]!);
    for (const spec of imports) assert.ok(spec.startsWith("./"), `${name} imports ${spec}`);
  }
});

// --- Review fixes ----------------------------------------------------------

test("an unnamed editable generic with one text child leaks nothing after pruning", async () => {
  const dom = el(1, "#document", [el(2, "HTML", [el(4, "BODY", [el(18, "SPAN", [el(19, "#text")]), el(5, "H1", [el(6, "#text")])])])]);
  const ax: AxNode[] = [
    { nodeId: "1", role: { value: "RootWebArea" }, childIds: ["4"], backendDOMNodeId: 1 },
    { nodeId: "4", role: { value: "generic" }, parentId: "1", childIds: ["18", "5"], backendDOMNodeId: 4 },
    // contenteditable span: structural, no name, one child the engine does
    // not mark editable. Pruning lifts the child into its place.
    { nodeId: "18", role: { value: "generic" }, parentId: "4", childIds: ["19"], backendDOMNodeId: 18, properties: [{ name: "editable", value: { value: "richtext" } }] },
    text("19", 19, "18", "typed secret 4111"),
    { nodeId: "5", role: { value: "heading" }, name: contents("Fees"), parentId: "4", childIds: ["6"], backendDOMNodeId: 5 },
    text("6", 6, "5", "Fees")
  ];
  const { cdp } = fakeCdp(dom, ax);
  const { nodes } = await captureOutline(cdp);
  const wire = JSON.stringify(nodes);
  assert.ok(!wire.includes("typed secret"), wire);
  // The lifted text node is still there, nameless.
  assert.equal(byId(nodes, "0-19")?.name, "");
  assert.equal(byId(nodes, "0-5")?.name, "Fees");
});

test("past the DOM index bound, names from contents are withheld", async () => {
  const spans: CdpDomNode[] = Array.from({ length: MAX_DOM_NODES + 10 }, (_, i) => el(1000 + i, "SPAN"));
  const dom = el(1, "#document", [el(2, "HTML", [el(4, "BODY", [el(5, "H1", [el(6, "#text")]), ...spans])])]);
  const ax: AxNode[] = [
    { nodeId: "1", role: { value: "RootWebArea" }, childIds: ["4"], backendDOMNodeId: 1 },
    { nodeId: "4", role: { value: "generic" }, parentId: "1", childIds: ["5"], backendDOMNodeId: 4 },
    { nodeId: "5", role: { value: "heading" }, name: contents("Pay 4111"), parentId: "4", childIds: ["6", "x"], backendDOMNodeId: 5 },
    text("6", 6, "5", "Pay"),
    // An input past the index bound: its tag is unknown and the engine gave
    // it no control role, so only the truncation rule protects the heading.
    { nodeId: "x", role: { value: "generic" }, name: contents("4111"), parentId: "5", backendDOMNodeId: 1000 + MAX_DOM_NODES + 5 }
  ];
  const { cdp } = fakeCdp(dom, ax);
  const { nodes, truncated } = await captureOutline(cdp);
  assert.equal(truncated, true);
  assert.ok(!JSON.stringify(nodes).includes("4111"));
  assert.equal(byId(nodes, "0-5")?.name, "");
  assert.equal(byId(nodes, "0-6")?.name, "Pay");
});

test("a very deep page is depth-capped, not a stack overflow", async () => {
  const levels = 20_000;
  const ax: AxNode[] = [{ nodeId: "1", role: { value: "RootWebArea" }, childIds: ["d0"], backendDOMNodeId: 1 }];
  for (let i = 0; i < levels; i++) {
    ax.push({ nodeId: `d${i}`, role: { value: "group" }, name: contents(`level ${i}`), parentId: i === 0 ? "1" : `d${i - 1}`, childIds: i + 1 < levels ? [`d${i + 1}`] : [] });
  }
  const { cdp, methods, params } = fakeCdp(el(1, "#document", [el(2, "HTML")]), ax);
  const { nodes, truncated } = await captureOutline(cdp);
  assert.equal(truncated, true);
  let depth = 0;
  for (let n = nodes[0]; n && n.children.length > 0; n = n.children[0]) depth += 1;
  assert.ok(depth <= MAX_OUTLINE_DEPTH && depth <= MAX_TREE_DEPTH);
  // The engine is asked for a bounded depth.
  assert.deepEqual(params[methods.indexOf("Accessibility.getFullAXTree")], { depth: MAX_AX_DEPTH });
});
