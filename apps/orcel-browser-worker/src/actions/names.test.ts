import assert from "node:assert/strict";
import { test } from "node:test";
import type { Page } from "playwright-core";
import { DISALLOWED, MAX_LABELLEDBY_IDS, MAX_NAMED_CONTROLS, nameControls, TEXT_ELEMENTS } from "./names.js";
import type { SnapshotNode } from "../snapshot.js";

/// A small DOM: light children, an optional open shadow tree, parents.
interface El {
  tag: string;
  attrs: Record<string, string>;
  children: El[];
  shadow: El[];
  parent: El | null;
  /// `getAttribute` throws (a detached or hostile element).
  unreadable?: boolean;
}

function el(tag: string, attrs: Record<string, string> = {}, ...children: El[]): El {
  const element: El = { tag, attrs, children, shadow: [], parent: null };
  for (const child of children) child.parent = element;
  return element;
}

/// `host` gets an open shadow tree holding `children` (their parent chain
/// ends at the shadow root: `parent` is null, like XPath sees it).
function shadowHost(host: El, ...children: El[]): El {
  host.shadow = children;
  return host;
}

/// Light-tree descendants (XPath), or every descendant including open
/// shadow trees (Playwright's CSS).
function descendants(element: El, pierce: boolean): El[] {
  const kids = pierce ? [...element.children, ...element.shadow] : element.children;
  return kids.flatMap((child) => [child, ...descendants(child, pierce)]);
}

const ROOT_OK = new Set([...TEXT_ELEMENTS, "label", "div", "p", "legend", "li", "td", "th", "dt", "dd", "h1", "h2", "h3", "h4", "h5", "h6"]);
const NAMING = ["aria-labelledby", "aria-label", "aria-owns", "aria-describedby", "aria-details", "role", "slot", "contenteditable"];
const naming = (element: El) => NAMING.some((name) => element.attrs[name] !== undefined);

/// The exact selectors `nameControls` uses, relative to one element.
function select(element: El, selector: string): El[] {
  switch (selector) {
    case "xpath=ancestor::html":
    case "xpath=ancestor::label": {
      const tag = selector.slice("xpath=ancestor::".length);
      const up: El[] = [];
      for (let at = element.parent; at; at = at.parent) if (at.tag === tag) up.push(at);
      return up;
    }
    case "xpath=.//*[not(self::option or self::optgroup)]":
      return descendants(element, false).filter((d) => d.tag !== "option" && d.tag !== "optgroup");
    case "xpath=.//option | .//optgroup":
      return descendants(element, false).filter((d) => d.tag === "option" || d.tag === "optgroup");
    case "xpath=.//*":
      return descendants(element, false);
    case "css=*":
      return descendants(element, true);
    case DISALLOWED: {
      const self = !ROOT_OK.has(element.tag) || naming(element) ? [element] : [];
      return [...self, ...descendants(element, false).filter((d) => !TEXT_ELEMENTS.includes(d.tag) || naming(d))];
    }
    default:
      throw new Error(`unexpected selector ${selector}`);
  }
}

interface StubLocator {
  all: () => El[];
  locator: (selector: string) => StubLocator;
  and: (other: StubLocator) => StubLocator;
  or: (other: StubLocator) => StubLocator;
  count: () => Promise<number>;
  getAttribute: (name: string) => Promise<string | null>;
}

function page(html: El, refs: Record<string, El>) {
  let reads = 0;
  const located = (all: () => El[]): StubLocator => ({
    all,
    locator: (selector) => located(() => [...new Set(all().flatMap((element) => select(element, selector)))]),
    and: (other) => located(() => all().filter((element) => other.all().includes(element))),
    or: (other) => located(() => [...new Set([...all(), ...other.all()])]),
    count: async () => all().length,
    getAttribute: async (name) => {
      reads += 1;
      const found = all();
      if (found.length !== 1 || found[0]!.unreadable) throw new Error("Timeout 500ms exceeded");
      return found[0]!.attrs[name] ?? null;
    }
  });
  const stub = {
    locator: (selector: string) => {
      if (selector.startsWith("aria-ref=")) {
        const target = refs[selector.slice("aria-ref=".length)];
        return located(() => (target ? [target] : []));
      }
      if (selector === "input, select") return located(() => descendants(html, true).filter((d) => d.tag === "input" || d.tag === "select"));
      const byId = /^xpath=\/\/\*\[@id="([^"]*)"\]$/.exec(selector);
      if (byId) return located(() => descendants(html, false).filter((d) => d.attrs.id === byId[1]));
      const forId = /^xpath=\/\/label\[@for="([^"]*)"\]$/.exec(selector);
      if (forId) return located(() => descendants(html, false).filter((d) => d.tag === "label" && d.attrs.for === forId[1]));
      throw new Error(`unexpected page selector ${selector}`);
    }
  };
  return { stub: stub as unknown as Pick<Page, "locator">, reads: () => reads };
}

const node = (ref: string, role: string, name: string, children: SnapshotNode[] = []): SnapshotNode => ({ ref, role, name, children });

test("SG-000122 A5: a name passes only when every contributing element holds text and text-level elements only", async () => {
  const pw = () => el("input", { type: "password", id: "pw", value: "HUNTER2" });
  const inShadow = el("input", { type: "text", "aria-label": "Inside" });
  const refs: Record<string, El> = {
    // A checkbox whose label wraps a textbox holding a value.
    e1: el("input", { type: "checkbox" }),
    // A checkbox whose label wraps a select.
    e2: el("input", { type: "checkbox" }),
    // A field named through aria-labelledby by a password field.
    e3: el("input", { type: "text", "aria-labelledby": "pw-label pw" }),
    // A field described by a password field: descriptions never join a name.
    e4: el("input", { type: "text", "aria-label": "Notes", "aria-describedby": "pw" }),
    // Labels holding only text, text-level elements and their own control.
    e5: el("input", { type: "text", value: "Old Name" }),
    e6: el("select", {}, el("option", {}), el("optgroup", {}, el("option", {}))),
    e7: el("input", { type: "checkbox" }),
    e8: el("input", { type: "text", id: "city" }),
    // A label for the field's id that holds another control.
    e9: el("input", { type: "text", id: "zip" }),
    // A label that owns a password field.
    e10: el("input", { type: "checkbox" }),
    // aria-labelledby on plain text, and on text holding an editable region.
    e11: el("input", { type: "search", "aria-labelledby": "find" }),
    e12: el("input", { type: "text", "aria-labelledby": "rich" }),
    // aria-labelledby naming the field itself, or an element holding it.
    e13: el("input", { type: "text", id: "self", "aria-labelledby": "self" }),
    e14: el("input", { type: "text", "aria-labelledby": "around" }),
    // Too many ids, and an id a selector should not carry.
    e15: el("input", { type: "text", "aria-labelledby": Array.from({ length: MAX_LABELLEDBY_IDS + 1 }, () => "find").join(" ") }),
    e16: el("input", { type: "text", "aria-labelledby": "bad\u0001id" }),
    // An element the attribute reads fail on.
    e17: Object.assign(el("input", { type: "text" }), { unreadable: true }),
    // Not an input or select, roles that are not form controls, a frame.
    e18: el("textarea"),
    e19: el("div", { role: "checkbox" }),
    e20: el("a", { href: "/x" }),
    e21: el("button"),
    f1e1: el("input", { type: "text" }),
    // Judge cases: (a) an element inside the label names the password
    // field; (b) the label itself has aria-labelledby; (c) the label hosts a
    // shadow tree with a slot; (d) a button inside the label.
    e22: el("input", { type: "checkbox" }),
    e23: el("input", { type: "checkbox" }),
    e24: el("input", { type: "checkbox" }),
    e25: el("input", { type: "checkbox" }),
    // An output, a contenteditable and a nested label inside the label.
    e26: el("input", { type: "checkbox" }),
    e27: el("input", { type: "checkbox" }),
    e28: el("input", { type: "checkbox" }),
    // A control inside a shadow tree; one that owns elements; a customizable
    // select holding more than options; an element of no allowed kind.
    e29: inShadow,
    e31: el("input", { type: "text", "aria-label": "Owner", "aria-owns": "pw" }),
    e32: el("select", {}, el("option", {}), el("img", { alt: "x" })),
    e33: el("input", { type: "checkbox" })
  };
  const body = el(
    "body",
    {},
    el("label", {}, refs.e1!, el("input", { type: "text", value: "TYPED" })),
    el("label", {}, refs.e2!, el("select", {}, el("option", {}))),
    el("span", { id: "pw-label" }),
    pw(),
    refs.e3!,
    refs.e4!,
    el("label", {}, el("b", {}, el("span", {})), refs.e5!),
    el("label", {}, refs.e6!, el("span", {})),
    el("label", {}, refs.e7!, el("em", {}), el("br", {})),
    el("label", { for: "city" }, el("b", {})),
    refs.e8!,
    el("label", { for: "zip" }, el("input", { type: "text", value: "OTHER" })),
    refs.e9!,
    el("label", { "aria-owns": "pw" }, refs.e10!),
    el("span", { id: "find" }, el("strong", {})),
    refs.e11!,
    el("div", { id: "rich" }, el("span", { contenteditable: "" })),
    refs.e12!,
    refs.e13!,
    el("div", { id: "around" }, refs.e14!),
    refs.e15!,
    refs.e16!,
    refs.e17!,
    refs.e18!,
    refs.e19!,
    refs.e20!,
    refs.e21!,
    refs.f1e1!,
    el("label", {}, refs.e22!, el("span", { "aria-labelledby": "pw" })),
    el("label", { "aria-labelledby": "pw" }, refs.e23!),
    shadowHost(el("label", {}, refs.e24!), el("slot", {})),
    el("label", {}, refs.e25!, el("button", { id: "b" })),
    el("label", {}, refs.e26!, el("output", {})),
    el("label", {}, refs.e27!, el("span", { contenteditable: "true" })),
    el("label", {}, el("label", {}, refs.e28!)),
    shadowHost(el("x-field", {}), el("label", {}, inShadow)),
    refs.e31!,
    el("label", {}, refs.e32!),
    el("label", {}, refs.e33!, el("img", { alt: "x" }))
  );
  const html = el("html", {}, body);
  const roles: Record<string, string> = {
    e2: "checkbox",
    e3: "textbox",
    e4: "textbox",
    e5: "textbox",
    e6: "combobox",
    e8: "textbox",
    e9: "textbox",
    e11: "searchbox",
    e12: "textbox",
    e13: "textbox",
    e14: "textbox",
    e15: "textbox",
    e16: "textbox",
    e17: "textbox",
    e18: "textbox",
    e20: "link",
    e21: "button",
    f1e1: "textbox",
    e29: "textbox",
    e31: "textbox",
    e32: "combobox"
  };
  const children = Object.keys(refs).map((ref) => node(ref, roles[ref] ?? "checkbox", `name of ${ref}`));
  // A node with an empty name is not named either.
  refs.e34 = el("input", { type: "text" });
  body.children.push(refs.e34);
  refs.e34.parent = body;
  children.push(node("e34", "textbox", ""));
  const nodes = [node("e40", "form", "", children)];
  await nameControls(page(html, refs).stub, nodes);
  const named = nodes[0]!.children.filter((child) => child.named === true).map((child) => child.ref);
  assert.deepEqual(named, ["e4", "e5", "e6", "e7", "e8", "e11"]);
  assert.equal(nodes[0]!.named, undefined);
  // The names themselves are untouched: the host bounds and marks them.
  assert.equal(nodes[0]!.children.find((child) => child.ref === "e5")!.name, "name of e5");
});

test("SG-000122 A5: names are checked for at most MAX_NAMED_CONTROLS controls and within the budget", async () => {
  const refs: Record<string, El> = {};
  const nodes: SnapshotNode[] = [];
  const body = el("body");
  const html = el("html", {}, body);
  for (let index = 1; index <= MAX_NAMED_CONTROLS + 3; index += 1) {
    const field = el("input", { type: "text", "aria-label": `Field ${index}` });
    field.parent = body;
    body.children.push(field);
    refs[`e${index}`] = field;
    nodes.push(node(`e${index}`, "textbox", `Field ${index}`));
  }
  await nameControls(page(html, refs).stub, nodes);
  assert.equal(nodes.filter((n) => n.named).length, MAX_NAMED_CONTROLS);
  // An exhausted budget names nothing, and reads nothing.
  const fresh = nodes.map((n) => node(n.ref, n.role, n.name));
  const { stub, reads } = page(html, refs);
  await nameControls(stub, fresh, -1);
  assert.equal(fresh.filter((n) => n.named).length, 0);
  assert.equal(reads(), 0);
});
