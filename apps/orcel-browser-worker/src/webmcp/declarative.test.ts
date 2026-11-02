import assert from "node:assert/strict";
import { test } from "node:test";
import { discoverDeclarativeTools, LIMITS, type DomElement, type DomNode } from "./declarative.js";
import { documentModel, MAX_SNAPSHOT_NODES, type CapturedSnapshot } from "./dom-snapshot.js";
import { readFileSync } from "node:fs";
import { vectorCases } from "./vectors.fixture.js";
import { fitTools } from "./fit.js";
import { captureWithin, DETACH_WAIT_MS } from "./capture.js";
import { encodeFrame } from "../protocol.js";

let nextNode = 1;

interface Mutable {
  kind: "element";
  tag: string;
  attrs: Map<string, string>;
  children: DomNode[];
  parent: Mutable | null;
  node: number;
}

function el(tag: string, attrs: Record<string, string> = {}, ...children: Array<Mutable | string>): Mutable {
  const element: Mutable = { kind: "element", tag, attrs: new Map(Object.entries(attrs)), children: [], parent: null, node: nextNode++ };
  for (const child of children) {
    if (typeof child === "string") {
      element.children.push({ kind: "text", text: child, parent: element });
    } else {
      child.parent = element;
      element.children.push(child);
    }
  }
  return element;
}

const doc = (...children: Array<Mutable | string>): DomElement => el("#root", {}, el("html", {}, el("body", {}, ...children)));

test("a declared form becomes a bounded tool with a schema from its controls", () => {
  const { tools, truncated } = discoverDeclarativeTools(
    doc(
      el(
        "form",
        { toolname: "search_flights", tooldescription: "Search flights.", tooltitle: "Flights", toolautosubmit: "" },
        el("label", { for: "from" }, "From airport"),
        el("input", { id: "from", name: "from", required: "", pattern: "[A-Z]{3}" }),
        el("input", { name: "seats", type: "number", min: "1", max: "9" }),
        el("select", { name: "cabin" }, el("option", { value: "eco" }, "Economy"), el("option", {}, "Business")),
        el(
          "fieldset",
          { toolparamdescription: "Trip type" },
          el("input", { type: "radio", name: "trip", value: "one" }),
          el("input", { type: "radio", name: "trip", value: "return" })
        ),
        el("input", { type: "checkbox", name: "meal", value: "veg" }),
        el("input", { type: "checkbox", name: "meal", value: "halal" }),
        el("input", { type: "date", name: "when" }),
        el("input", { type: "hidden", name: "csrf", value: "tok-123" })
      )
    )
  );
  assert.equal(truncated, false);
  assert.equal(tools.length, 1);
  const [tool] = tools;
  assert.ok(tool);
  assert.equal(tool.name, "search_flights");
  assert.equal(tool.title, "Flights");
  assert.equal(tool.autosubmit, true);
  assert.equal(tool.has_password, false);
  assert.deepEqual(tool.params, [
    { name: "from", required: true, control: "text", has_default: false, type: "string", pattern: "[A-Z]{3}", description: "From airport" },
    { name: "seats", required: false, control: "text", has_default: false, type: "number", minimum: 1, maximum: 9, multiple_of: 1 },
    { name: "cabin", required: false, control: "select", has_default: false, type: "string", enum: ["eco", "Business"] },
    { name: "trip", required: false, control: "radio", has_default: false, type: "string", enum: ["one", "return"], description: "Trip type" },
    { name: "meal", required: false, control: "checkboxes", has_default: false, type: "array", items_enum: ["veg", "halal"] },
    { name: "when", required: false, control: "text", has_default: false, type: "string", format: "date", description: "Dates MUST be provided in 'YYYY-MM-DD' format." }
  ]);
  // The hidden field (no description) is not a parameter and its value never appears.
  assert.ok(!JSON.stringify(tools).includes("tok-123"));
});

test("values never leave, and password controls flag the tool instead of becoming parameters", () => {
  const { tools } = discoverDeclarativeTools(
    doc(
      el(
        "form",
        { toolname: "login", tooldescription: "Sign in." },
        el("input", { name: "user", value: "alice" }),
        el("input", { name: "pass", type: "password", value: "hunter2" })
      )
    )
  );
  assert.equal(tools[0]?.has_password, true);
  assert.deepEqual(tools[0]?.params.map((p) => p.name), ["user"]);
  const text = JSON.stringify(tools);
  assert.ok(!text.includes("alice") && !text.includes("hunter2"));
});

test("undeclared, misnamed and duplicate forms are not tools; the first name wins", () => {
  const { tools, truncated } = discoverDeclarativeTools(
    doc(
      el("form", { toolname: "no_description" }),
      el("form", { toolname: "bad name!", tooldescription: "x" }),
      el("form", { toolname: "dup", tooldescription: "first" }),
      el("form", { toolname: "dup", tooldescription: "second" })
    )
  );
  assert.deepEqual(tools.map((t) => [t.name, t.description]), [["dup", "first"]]);
  assert.equal(truncated, true, "an invalid name is reported as dropped");
});

test("disabled, read-only, nested and foreign controls are excluded; form= owners are included", () => {
  const { tools } = discoverDeclarativeTools(
    doc(
      el(
        "form",
        { toolname: "t", tooldescription: "d", id: "f1" },
        el("input", { name: "ok" }),
        el("input", { name: "off", disabled: "" }),
        el("fieldset", { disabled: "" }, el("input", { name: "inside_disabled" })),
        el("input", { name: "ro", readonly: "" }),
        el("input", { name: "elsewhere", form: "f2" })
      ),
      el("input", { name: "outside", form: "f1" })
    )
  );
  assert.deepEqual(tools[0]?.params.map((p) => p.name), ["ok", "outside"]);
});

test("every collection and string is bounded", () => {
  const many = Array.from({ length: LIMITS.tools + 3 }, (_, i) => el("form", { toolname: `t${i}`, tooldescription: "d" }));
  const result = discoverDeclarativeTools(doc(...many));
  assert.equal(result.tools.length, LIMITS.tools);
  assert.equal(result.truncated, true);
  const long = discoverDeclarativeTools(doc(el("form", { toolname: "long", tooldescription: "x".repeat(5000) })));
  assert.equal(long.tools[0]?.description.length, LIMITS.description);
  assert.equal(long.truncated, true);
  const options = Array.from({ length: LIMITS.choices + 1 }, (_, i) => el("option", { value: `v${i}` }));
  const select = discoverDeclarativeTools(doc(el("form", { toolname: "s", tooldescription: "d" }, el("select", { name: "pick" }, ...options))));
  assert.deepEqual(select.tools[0]?.params, [], "too many choices drops the parameter");
});

function snapshot(nodes: Array<[parent: number, type: number, name: string, value?: string | undefined, attrs?: string[]]>): CapturedSnapshot {
  const strings: string[] = [];
  const id = (s: string): number => {
    const at = strings.indexOf(s);
    if (at >= 0) return at;
    strings.push(s);
    return strings.length - 1;
  };
  return {
    strings,
    documents: [
      {
        nodes: {
          parentIndex: nodes.map((n) => n[0]),
          nodeType: nodes.map((n) => n[1]),
          nodeName: nodes.map((n) => id(n[2])),
          nodeValue: nodes.map((n) => (n[3] === undefined ? -1 : id(n[3]))),
          backendNodeId: nodes.map((_, i) => 100 + i),
          attributes: nodes.map((n) => (n[4] ?? []).map(id))
        }
      }
    ]
  };
}

test("the snapshot model keeps shadow trees and text, and drops other node kinds", () => {
  const model = documentModel(
    snapshot([
      [-1, 9, "#document"],
      [0, 1, "HTML"],
      [1, 1, "BODY"],
      [2, 1, "X-HOST"],
      [3, 11, "#document-fragment"],
      [4, 1, "FORM", undefined, ["toolname", "shadowed", "tooldescription", "In a shadow root"]],
      [5, 1, "LABEL"],
      [6, 3, "#text", "Query"],
      [6, 1, "INPUT", undefined, ["name", "q"]],
      [2, 8, "#comment", "ignored"]
    ])
  );
  assert.equal(model.truncated, false);
  const { tools } = discoverDeclarativeTools(model.root);
  assert.deepEqual(tools.map((t) => [t.name, t.node, t.params]), [
    ["shadowed", 105, [{ name: "q", required: false, control: "text", has_default: false, type: "string", description: "Query" }]]
  ]);
});

test("the snapshot model is bounded", () => {
  const nodes: Array<[number, number, string]> = [[-1, 9, "#document"]];
  for (let i = 1; i <= MAX_SNAPSHOT_NODES + 5; i++) nodes.push([0, 1, "DIV"]);
  assert.equal(documentModel(snapshot(nodes)).truncated, true);
});


test("a DOM deeper than any call stack is walked without recursion", () => {
  let inner = el("form", { toolname: "deep", tooldescription: "At the bottom." }, el("label", {}, "Deep field ", el("input", { name: "d" })));
  for (let i = 0; i < 200_000; i++) inner = el("div", {}, inner);
  const { tools } = discoverDeclarativeTools(doc(inner));
  assert.deepEqual(tools.map((t) => [t.name, t.params]), [["deep", [{ name: "d", required: false, control: "text", has_default: false, type: "string", description: "Deep field" }]]]);
});

const LONE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
function strings(value: unknown, out: string[] = []): string[] {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const item of value) strings(item, out);
  else if (value && typeof value === "object") for (const item of Object.values(value)) strings(item, out);
  return out;
}

test("text is well formed, control- and bidi-free, and cut at whole code points", () => {
  const emoji = "\u{1F600}";
  const { tools } = discoverDeclarativeTools(
    doc(
      el(
        "form",
        { toolname: "e", tooldescription: "x\ud800y " + "a".repeat(LIMITS.description) + emoji, tooltitle: "T\u0001it\u202ele\udc00" },
        el("label", {}, "Lab\ud800el ", el("input", { name: "q" })),
        el("input", { name: "bad\u0007name" }),
        el("input", { name: "pat", pattern: "a\u0000b" }),
        el("select", { name: "lone" }, el("option", { value: "lone\ud800" })),
        el("select", { name: "bidi" }, el("option", { value: "a\u202eb" }))
      )
    )
  );
  const [tool] = tools;
  assert.ok(tool);
  for (const text of strings(tools)) assert.ok(!LONE.test(text), JSON.stringify(text));
  assert.ok(tool.description.startsWith("x\ufffdy "));
  assert.equal(Array.from(tool.description).length, LIMITS.description);
  assert.equal(tool.title, "Title\ufffd");
  assert.deepEqual(tool.params, [
    { name: "q", required: false, control: "text", has_default: false, type: "string", description: "Lab\ufffdel" },
    { name: "pat", required: false, control: "text", has_default: false, type: "string" }
  ]);
});

test("number schemas stay inside the host's subset", () => {
  const { tools } = discoverDeclarativeTools(
    doc(
      el(
        "form",
        { toolname: "n", tooldescription: "d" },
        el("input", { name: "pat", type: "number", pattern: "[0-9]+" }),
        el("input", { name: "inverted", type: "number", min: "10", max: "1" }),
        el("input", { name: "range_high", type: "range", min: "200" }),
        el("input", { name: "range_ok", type: "range", min: "5" })
      )
    )
  );
  assert.deepEqual(tools[0]?.params, [
    { name: "pat", required: false, control: "text", has_default: false, type: "number", multiple_of: 1 },
    { name: "inverted", required: false, control: "text", has_default: false, type: "number", multiple_of: 1 },
    { name: "range_high", required: false, control: "text", has_default: false, type: "number", multiple_of: 1 },
    { name: "range_ok", required: false, control: "text", has_default: false, type: "number", minimum: 5, maximum: 100, multiple_of: 1 }
  ]);
});

test("discovery is linear and bounded by its CPU budget", () => {
  // A deep chain with many controls, and nested declared forms around it.
  let chain = el("div", {}, ...Array.from({ length: 40_000 }, (_, i) => el("input", { name: `c${i}` })));
  for (let i = 0; i < 40_000; i++) chain = el("div", {}, chain);
  let nested = el("form", { toolname: "inner", tooldescription: "d" }, chain);
  for (let i = 0; i < 31; i++) nested = el("form", { toolname: `outer${i}`, tooldescription: "d" }, nested);
  const started = Date.now();
  const found = discoverDeclarativeTools(doc(nested));
  assert.ok(Date.now() - started < 3_000, `took ${Date.now() - started} ms`);
  assert.equal(found.tools.length, 32);
  // An exhausted budget truncates instead of running late.
  const late = discoverDeclarativeTools(doc(nested), 0);
  assert.equal(late.truncated, true);
});

test("editable regions never contribute text, and labels label one control", () => {
  const { tools } = discoverDeclarativeTools(
    doc(
      el(
        "form",
        { toolname: "t", tooldescription: "d" },
        el("label", {}, "Query ", el("div", { contenteditable: "" }, "USER TYPED SECRET"), el("span", { role: "textbox" }, "ALSO TYPED"), el("input", { name: "q" }), el("input", { name: "second" }))
      )
    )
  );
  assert.deepEqual(tools[0]?.params, [
    { name: "q", required: false, control: "text", has_default: false, type: "string", description: "Query" },
    { name: "second", required: false, control: "text", has_default: false, type: "string" }
  ]);
});

test("tree scopes, legends, exact attribute names and reserved names follow the DOM", () => {
  const { tools } = discoverDeclarativeTools(
    doc(
      el(
        "form",
        { toolname: "scoped", tooldescription: "d", id: "f" },
        el("input", { name: "light" }),
        // Shadow-tree controls are never associated with a light-DOM form.
        el("x-host", {}, el("#shadow-root", {}, el("input", { name: "shadowed" }), el("input", { name: "by_id", form: "f" }))),
        el("fieldset", { disabled: "" }, el("legend", {}, el("input", { name: "in_legend" })), el("input", { name: "off" }))
      ),
      el("form", { TOOLNAME: "upper", tooldescription: "d" }),
      el("form", { toolname: "d1-w1", tooldescription: "looks like a host identity" })
    )
  );
  assert.deepEqual(tools.map((t) => [t.name, t.params.map((p) => p.name)]), [["scoped", ["light", "in_legend"]]]);
});

test("password-like controls flag the tool even when disabled", () => {
  const { tools } = discoverDeclarativeTools(
    doc(
      el("form", { toolname: "a", tooldescription: "d" }, el("input", { type: "password", name: "p", disabled: "" })),
      el("form", { toolname: "b", tooldescription: "d" }, el("input", { name: "code", autocomplete: "one-time-code" }), el("input", { name: "user" }))
    )
  );
  assert.deepEqual(tools.map((t) => [t.name, t.has_password, t.params.map((p) => p.name)]), [
    ["a", true, []],
    ["b", true, ["user"]]
  ]);
});

test("the worker's output for awkward markup equals the shared host vectors", () => {
  const pinned: unknown = JSON.parse(readFileSync(new URL("../../src/webmcp/shared-vectors.json", import.meta.url), "utf8"));
  const produced: Record<string, unknown> = {};
  for (const [name, root] of Object.entries(vectorCases())) produced[name] = discoverDeclarativeTools(root);
  assert.deepEqual(produced, pinned, "regenerate shared-vectors.json only together with the host validator");
});

test("the frame fit is linear and keeps the longest prefix that fits", () => {
  // 32 tools at their bounds, each far larger than one frame on its own.
  const options = Array.from({ length: LIMITS.choices }, (_, i) => el("option", { value: `${i}`.padEnd(LIMITS.choice, "v") }));
  const big = Array.from({ length: LIMITS.tools }, (_, t) =>
    el("form", { toolname: `t${t}`, tooldescription: "d".repeat(LIMITS.description) }, ...Array.from({ length: LIMITS.params }, (_, p) => el("select", { name: `p${p}` }, ...options.map((o) => el("option", { value: o.attrs.get("value") ?? "" })))))
  );
  const { tools } = discoverDeclarativeTools(doc(...big));
  assert.equal(tools.length, LIMITS.tools);
  const started = Date.now();
  const fitted = fitTools(123456, "https://fixture.test/x", false, tools);
  assert.ok(Date.now() - started < 1_000, `fit took ${Date.now() - started} ms`);
  assert.equal(fitted.truncated, true);
  // Whatever was kept encodes within the frame bound.
  encodeFrame({ frame: "discovered", disc_id: 123456, ...fitted });
  // Small tools all fit and nothing is marked truncated.
  const small = discoverDeclarativeTools(doc(el("form", { toolname: "a", tooldescription: "d" }), el("form", { toolname: "b", tooldescription: "d" })));
  const kept = fitTools(1, "https://fixture.test/", false, small.tools);
  assert.deepEqual([kept.truncated, kept.tools.length], [false, 2]);
});

test("a capture that never settles fails on time, even if detaching hangs too", async () => {
  const never = new Promise<never>(() => {});
  let detaches = 0;
  const hung = { capture: () => never, detach: () => (detaches++, never) };
  // Ordered, not timed (#575): a sentinel timer set before the capture and
  // due half way through the detach grace period must not fire before the
  // timed-out capture rejects. Expired timers run in order, with microtasks
  // between them, so a slow runner cannot reorder them; a timed-out capture
  // that waited for the hanging detach would let the sentinel fire first.
  let late = false;
  const sentinel = setTimeout(() => (late = true), 100 + DETACH_WAIT_MS / 2);
  await assert.rejects(captureWithin(hung, 100), /timed out/);
  clearTimeout(sentinel);
  assert.equal(late, false, "the timed-out capture waited for the hanging detach");
  assert.equal(detaches, 1, "the session was not released");
  // A capture that finishes waits at most the grace period for a hanging
  // detach: it settles before a sentinel due at twice that period.
  const quick = { capture: async () => ({ documents: [], strings: [] }), detach: () => never };
  let overdue = false;
  const limit = setTimeout(() => (overdue = true), DETACH_WAIT_MS * 2);
  assert.deepEqual(await captureWithin(quick, 1_000), { documents: [], strings: [] });
  clearTimeout(limit);
  assert.equal(overdue, false, "the finished capture waited past the grace period");
});

test("a tool is self-contained only when position and ownership agree", () => {
  const button = () => el("button", {}, "Go");
  const discover = (...children: Array<Mutable | string>) => discoverDeclarativeTools(doc(...children)).tools.map((t) => [t.name, t.self_contained]);
  assert.deepEqual(
    discover(
      el("form", { toolname: "plain", tooldescription: "d" }, el("input", { name: "q" }), button()),
      el("form", { toolname: "no_button", tooldescription: "d" }, el("input", { name: "q" })),
      el("form", { toolname: "decoy", tooldescription: "d", id: "f" }, el("input", { name: "q", form: "nowhere" }), button()),
      el("form", { toolname: "owned_outside", tooldescription: "d", id: "g" }, button()),
      el("input", { name: "q", form: "g" }),
      el("form", { toolname: "other_button", tooldescription: "d" }, el("input", { name: "q" }), el("button", { form: "x" }, "Go")),
      el("form", { toolname: "formmethod", tooldescription: "d" }, el("input", { name: "q" }), el("button", { formmethod: "post" }, "Go")),
      el("form", { toolname: "shadowed", tooldescription: "d" }, el("x-c", {}, el("#shadow-root", {}, el("input", { name: "q" }))), button()),
      el("form", { toolname: "popup", tooldescription: "d", target: "_blank" }, el("input", { name: "q" }), button()),
      el("form", { toolname: "multipart", tooldescription: "d", method: "post", enctype: "multipart/form-data" }, el("input", { name: "q" }), button()),
      el("form", { toolname: "reset_only", tooldescription: "d" }, el("input", { name: "q" }), el("button", { type: "reset" }, "Clear"))
    ),
    [
      ["plain", true],
      ["no_button", false],
      ["decoy", false],
      ["owned_outside", false],
      ["other_button", false],
      ["formmethod", false],
      ["shadowed", false],
      ["popup", false],
      ["multipart", false],
      ["reset_only", false]
    ]
  );
});

test("flattened shadow trees (as Edge reports them) get their boundary back, and their forms never execute", () => {
  // Edge's snapshot has no shadow-root node: shadow content sits under its
  // host, marked with `shadowRootType`.
  const base = snapshot([
    [-1, 9, "#document"],
    [0, 1, "HTML"],
    [1, 1, "BODY"],
    [2, 1, "FORM", undefined, ["toolname", "outer", "tooldescription", "d"]],
    [3, 1, "X-FIELD"],
    [4, 1, "INPUT", undefined, ["name", "shadowed"]],
    [3, 1, "INPUT", undefined, ["name", "light"]],
    [3, 1, "BUTTON"],
    [2, 1, "X-APP"],
    [8, 1, "FORM", undefined, ["toolname", "inner", "tooldescription", "d"]],
    [9, 1, "INPUT", undefined, ["name", "q"]],
    [9, 1, "BUTTON"]
  ]);
  const doc0 = base.documents[0];
  assert.ok(doc0);
  doc0.nodes.shadowRootType = { index: [5, 9, 10, 11], value: [0, 0, 0, 0] };
  const { tools } = discoverDeclarativeTools(documentModel(base).root);
  assert.deepEqual(
    tools.map((t) => [t.name, t.self_contained, t.params.map((p) => p.name)]),
    [
      // The shadow field is not the outer form's, and makes it unsafe.
      ["outer", false, ["light"]],
      // A form inside a shadow tree is discovered but never executable.
      ["inner", false, ["q"]]
    ]
  );
});

test("fixed names, base targets and charsets are reported for execution", () => {
  const go = () => el("button", { name: "confirm", value: "yes" }, "Go");
  const tools = (...children: Array<Mutable | string>) => discoverDeclarativeTools(doc(...children)).tools;
  const [plain] = tools(
    el("form", { toolname: "plain", tooldescription: "d" }, el("input", { name: "q" }), el("input", { type: "hidden", name: "csrf", value: "secret-token" }), el("input", { name: "ro", readonly: "" }), go())
  );
  assert.ok(plain);
  assert.equal(plain.self_contained, true);
  assert.deepEqual([...plain.fixed_names].sort(), ["confirm", "csrf", "ro"]);
  assert.equal(plain.utf8, true);
  assert.ok(!JSON.stringify(plain).includes("secret-token"), "a hidden value crossed");
  // A document-wide <base target> sends the submission elsewhere.
  const [based] = tools(el("base", { target: "fr" }), el("form", { toolname: "based", tooldescription: "d" }, el("input", { name: "q" }), go()));
  assert.equal(based?.self_contained, false);
  const [own] = tools(el("base", { target: "fr" }), el("form", { toolname: "own", tooldescription: "d", target: "_self" }, el("input", { name: "q" }), go()));
  assert.equal(own?.self_contained, true, "the form's own target wins over the base");
  // HTML does not trim a button's type: " button" is invalid, so it submits,
  // and its override makes the form not self-contained.
  const [spaced] = tools(el("form", { toolname: "spaced", tooldescription: "d" }, el("input", { name: "q" }), el("button", { type: " button", formaction: "/elsewhere" }, "Go")));
  assert.equal(spaced?.self_contained, false);
  const [plainButton] = tools(el("form", { toolname: "plain_button", tooldescription: "d" }, el("input", { name: "q" }), el("button", { type: "BUTTON", formaction: "/x" }, "No"), go()));
  assert.equal(plainButton?.self_contained, true, "a real button type is not a submitter");
  // Charsets: accept-charset, and the document's encoding as the engine
  // reports it; an unreported one is not UTF-8.
  const [latin] = tools(el("form", { toolname: "latin", tooldescription: "d", "accept-charset": "windows-1252" }, el("input", { name: "q" }), go()));
  assert.equal(latin?.utf8, false);
  const form = () => doc(el("form", { toolname: "enc", tooldescription: "d" }, el("input", { name: "q" }), go()));
  assert.equal(discoverDeclarativeTools(form(), 1000, "windows-1252").tools[0]?.utf8, false);
  assert.equal(discoverDeclarativeTools(form(), 1000, "").tools[0]?.utf8, false);
  assert.equal(discoverDeclarativeTools(form(), 1000, "utf-8").tools[0]?.utf8, true);
  // A meta in the page is not read: the engine's encoding decides.
  const [meta] = tools(el("meta", { charset: "ISO-8859-1" }), el("form", { toolname: "meta", tooldescription: "d" }, el("input", { name: "q" }), go()));
  assert.equal(meta?.utf8, true);
  // Names the browser adds: an image button's coordinates, a dirname.
  const [image] = tools(el("form", { toolname: "image", tooldescription: "d" }, el("input", { name: "q", dirname: "q.dir" }), el("input", { type: "image", name: "img", src: "/i.png" })));
  assert.deepEqual([...(image?.fixed_names ?? [])].sort(), ["img", "img.x", "img.y", "q.dir"]);
  const [bare] = tools(el("form", { toolname: "bare", tooldescription: "d" }, el("input", { name: "q" }), el("input", { type: "image", src: "/i.png" })));
  assert.deepEqual([...(bare?.fixed_names ?? [])].sort(), ["x", "y"]);
});

test("a parameter the page already fills is reported as having a default", () => {
  const go = () => el("button", {}, "Go");
  const [tool] = discoverDeclarativeTools(
    doc(
      el(
        "form",
        { toolname: "defaults", tooldescription: "d" },
        el("input", { name: "empty" }),
        el("input", { name: "year", value: "2026" }),
        el("textarea", { name: "note" }, "prefilled"),
        el("textarea", { name: "blank" }),
        el("input", { type: "checkbox", name: "on", checked: "" }),
        el("input", { type: "checkbox", name: "off" }),
        el("select", { name: "many", multiple: "" }, el("option", { value: "a", selected: "" }), el("option", { value: "b" })),
        el("select", { name: "none", multiple: "" }, el("option", { value: "a" })),
        go()
      )
    )
  ).tools;
  assert.deepEqual(
    tool?.params.map((p) => [p.name, p.has_default]),
    [
      ["empty", false],
      ["year", true],
      ["note", true],
      ["blank", false],
      ["on", true],
      ["off", false],
      ["many", true],
      ["none", false]
    ]
  );
});

test("the snapshot model reports the engine's encoding and live control state", () => {
  const strings: string[] = [];
  const id = (s: string) => {
    const at = strings.indexOf(s);
    return at >= 0 ? at : strings.push(s) - 1;
  };
  const model = documentModel({
    strings,
    documents: [
      {
        encodingName: id("windows-1252"),
        nodes: {
          parentIndex: [-1, 0, 1, 2, 2, 2, 5],
          nodeType: [9, 1, 1, 1, 1, 1, 1],
          nodeName: ["#document", "HTML", "FORM", "INPUT", "INPUT", "SELECT", "OPTION"].map(id),
          nodeValue: [-1, -1, -1, -1, -1, -1, -1],
          backendNodeId: [1, 2, 3, 4, 5, 6, 7],
          attributes: [[], [], [], [id("name"), id("typed")], [id("type"), id("checkbox"), id("name"), id("box")], [id("name"), id("pick"), id("multiple"), id("")], [id("value"), id("v")]],
          inputValue: { index: [3], value: [id("typed by script")] },
          inputChecked: { index: [4] },
          optionSelected: { index: [6] }
        }
      }
    ]
  });
  assert.equal(model.encoding, "windows-1252");
  const form = model.root.children[0] as DomElement;
  const [typed, box, pick] = (form.children[0] as DomElement).children as DomElement[];
  assert.deepEqual([typed?.live, box?.live, (pick?.children[0] as DomElement).live], [{ value: "typed by script" }, { checked: true }, { selected: true }]);
});
