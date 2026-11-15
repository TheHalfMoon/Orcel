import assert from "node:assert/strict";
import { test } from "node:test";
import type { Page } from "playwright-core";
import { MAX_LABELLEDBY_IDS, MAX_NAMED_CONTROLS, nameControls } from "./names.js";
import type { SnapshotNode } from "../snapshot.js";

/// A small DOM: enough of the tree for labels, ids and descendants.
interface El {
  tag: string;
  attrs: Record<string, string>;
  children: El[];
  parent: El | null;
  /// `getAttribute` throws (a detached or hostile element).
  unreadable?: boolean;
}

function el(tag: string, attrs: Record<string, string> = {}, ...children: El[]): El {
  const element: El = { tag, attrs, children, parent: null };
  for (const child of children) child.parent = element;
  return element;
}

function descendants(element: El): El[] {
  return element.children.flatMap((child) => [child, ...descendants(child)]);
}

/// The selector forms `nameControls` uses: comma lists of a tag and
/// attribute tests (`[a]`, `[a="v"]`, `[a~="v" i]`), with one `:not(...)`.
function matches(element: El, css: string): boolean {
  return css.split(/,\s*(?![^()]*\))/).some((raw) => {
    const part = raw.trim();
    const [head, not] = part.split(":not(");
    if (not !== undefined && matches(element, not.replace(/\)$/, ""))) return false;
    const tag = /^[a-z]+/.exec(head!)?.[0];
    if (tag !== undefined && element.tag !== tag) return false;
    for (const [, name, op, value, flag] of head!.matchAll(/\[([\w-]+)(?:(~?)="((?:[^"\\]|\\.)*)"( i)?)?\]/g)) {
      const actual = element.attrs[name!];
      if (actual === undefined) return false;
      if (value === undefined) continue;
      const wanted = value.replace(/\\(.)/g, "$1");
      const [a, w] = flag ? [actual.toLowerCase(), wanted.toLowerCase()] : [actual, wanted];
      if (op === "~" ? !a.split(/\s+/).includes(w) : a !== w) return false;
    }
    return true;
  });
}

interface StubLocator {
  all: () => El[];
  locator: (selector: string) => StubLocator;
  and: (other: StubLocator) => StubLocator;
  or: (other: StubLocator) => StubLocator;
  count: () => Promise<number>;
  getAttribute: (name: string) => Promise<string | null>;
}

function page(root: El, refs: Record<string, El>) {
  let reads = 0;
  const located = (all: () => El[]): StubLocator => ({
    all,
    locator: (selector) =>
      located(() => {
        const found = all().flatMap((element) => {
          if (selector === "xpath=ancestor::label") {
            const up: El[] = [];
            for (let at = element.parent; at; at = at.parent) if (at.tag === "label") up.push(at);
            return up;
          }
          return descendants(element).filter((d) => matches(d, selector));
        });
        return [...new Set(found)];
      }),
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
      return located(() => descendants(root).filter((element) => matches(element, selector)));
    }
  };
  return { stub: stub as unknown as Pick<Page, "locator">, reads: () => reads };
}

const node = (ref: string, role: string, name: string, children: SnapshotNode[] = []): SnapshotNode => ({ ref, role, name, children });

test("SG-000122 A5: a name passes only when no embedded or referenced control can contribute to it", async () => {
  const refs: Record<string, El> = {
    // A checkbox whose label wraps a textbox holding a value.
    e1: el("input", { type: "checkbox" }),
    // A checkbox whose label wraps a select.
    e2: el("input", { type: "checkbox" }),
    // A field named through aria-labelledby by a password field.
    e3: el("input", { type: "text", "aria-labelledby": "pw-label pw" }),
    // A field described by a password field: descriptions never join a name.
    e4: el("input", { type: "text", "aria-label": "Notes", "aria-describedby": "pw" }),
    // Labels that hold only the control they label.
    e5: el("input", { type: "text", value: "Old Name" }),
    e6: el("select", {}, el("option", {}), el("option", {})),
    e7: el("input", { type: "checkbox" }),
    e8: el("input", { type: "text", id: "city" }),
    // A label for the field's id that holds another control.
    e9: el("input", { type: "text", id: "zip" }),
    // A label that owns a password field.
    e10: el("input", { type: "checkbox" }),
    // aria-labelledby on plain text, and on text holding an editable region.
    e11: el("input", { type: "search", "aria-labelledby": "find" }),
    e12: el("input", { type: "text", "aria-labelledby": "rich" }),
    // aria-labelledby naming the field itself.
    e13: el("input", { type: "text", id: "self", "aria-labelledby": "self" }),
    // A custom widget inside a wrapping label.
    e14: el("input", { type: "radio" }),
    // Too many ids, and an id a selector should not carry.
    e15: el("input", { type: "text", "aria-labelledby": Array.from({ length: MAX_LABELLEDBY_IDS + 1 }, () => "find").join(" ") }),
    e16: el("input", { type: "text", "aria-labelledby": "bad\u0001id" }),
    // An element the attribute reads fail on.
    e17: Object.assign(el("input", { type: "text" }), { unreadable: true }),
    // Not an input or select: a textarea and a custom checkbox.
    e18: el("textarea"),
    e19: el("div", { role: "checkbox" }),
    // Roles that are not form controls, and a control inside a frame.
    e20: el("a", { href: "/x" }),
    e21: el("button"),
    f1e1: el("input", { type: "text" })
  };
  const root = el(
    "body",
    {},
    el("label", {}, refs.e1!, el("input", { type: "text", value: "TYPED" })),
    el("label", {}, refs.e2!, el("select", {}, el("option", {}))),
    el("span", { id: "pw-label" }),
    el("input", { type: "password", id: "pw", value: "HUNTER2" }),
    refs.e3!,
    refs.e4!,
    el("label", {}, refs.e5!),
    el("label", {}, refs.e6!, el("span", {})),
    el("label", {}, refs.e7!, el("span", {})),
    el("label", { for: "city" }, el("b", {})),
    refs.e8!,
    el("label", { for: "zip" }, el("input", { type: "text", value: "OTHER" })),
    refs.e9!,
    el("label", { "aria-owns": "pw" }, refs.e10!),
    el("span", { id: "find" }),
    refs.e11!,
    el("div", { id: "rich" }, el("span", { contenteditable: "" })),
    refs.e12!,
    refs.e13!,
    el("label", {}, refs.e14!, el("div", { role: "Slider" })),
    refs.e15!,
    refs.e16!,
    refs.e17!,
    refs.e18!,
    refs.e19!,
    refs.e20!,
    refs.e21!,
    refs.f1e1!
  );
  const roles: Record<string, string> = {
    e1: "checkbox",
    e2: "checkbox",
    e3: "textbox",
    e4: "textbox",
    e5: "textbox",
    e6: "combobox",
    e7: "checkbox",
    e8: "textbox",
    e9: "textbox",
    e10: "checkbox",
    e11: "searchbox",
    e12: "textbox",
    e13: "textbox",
    e14: "radio",
    e15: "textbox",
    e16: "textbox",
    e17: "textbox",
    e18: "textbox",
    e19: "checkbox",
    e20: "link",
    e21: "button",
    f1e1: "textbox"
  };
  const children = Object.keys(refs).map((ref) => node(ref, roles[ref]!, `name of ${ref}`));
  // A node with an empty name is not named either.
  refs.e22 = el("input", { type: "text" });
  root.children.push(refs.e22);
  refs.e22.parent = root;
  children.push(node("e22", "textbox", ""));
  const nodes = [node("e30", "form", "", children)];
  await nameControls(page(root, refs).stub, nodes);
  const named = nodes[0]!.children.filter((child) => child.named === true).map((child) => child.ref);
  assert.deepEqual(named, ["e4", "e5", "e6", "e7", "e8", "e11"]);
  assert.equal(nodes[0]!.named, undefined);
  // The names themselves are untouched: the host bounds and marks them.
  assert.equal(nodes[0]!.children.find((child) => child.ref === "e5")!.name, "name of e5");
});

test("SG-000122 A5: names are checked for at most MAX_NAMED_CONTROLS controls and within the budget", async () => {
  const refs: Record<string, El> = {};
  const nodes: SnapshotNode[] = [];
  const root = el("body");
  for (let index = 1; index <= MAX_NAMED_CONTROLS + 3; index += 1) {
    const field = el("input", { type: "text", "aria-label": `Field ${index}` });
    field.parent = root;
    root.children.push(field);
    refs[`e${index}`] = field;
    nodes.push(node(`e${index}`, "textbox", `Field ${index}`));
  }
  await nameControls(page(root, refs).stub, nodes);
  assert.equal(nodes.filter((n) => n.named).length, MAX_NAMED_CONTROLS);
  // An exhausted budget names nothing, and reads nothing.
  const fresh = nodes.map((n) => node(n.ref, n.role, n.name));
  const { stub, reads } = page(root, refs);
  await nameControls(stub, fresh, -1);
  assert.equal(fresh.filter((n) => n.named).length, 0);
  assert.equal(reads(), 0);
});
