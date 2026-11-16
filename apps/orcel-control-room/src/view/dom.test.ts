// SG-000119 A4: the view writes text only. A recording document stands in
// for the browser's: it fails the test if anything assigns an HTML sink, and
// records what was created, so the tests can show that orceld's strings
// arrive as textContent and that no tag or attribute outside the view's
// closed set can be drawn.

import assert from "node:assert/strict";
import { test } from "node:test";

import { ATTRIBUTES, TAGS, h, materialise, show, type DocumentLike, type ElementLike } from "./dom.js";
import { statusNodes, taskDetailNodes } from "./present.js";

class FakeElement implements ElementLike {
  public readonly attributes = new Map<string, string>();
  public readonly children: FakeElement[] = [];
  private text: string | null = null;

  public constructor(public readonly tag: string) {
    for (const sink of ["innerHTML", "outerHTML"]) {
      Object.defineProperty(this, sink, {
        set() {
          throw new Error(`${sink} was assigned`);
        },
      });
    }
  }

  public get textContent(): string | null {
    return this.text ?? this.children.map((child) => child.textContent).join("");
  }

  public set textContent(value: string | null) {
    this.children.length = 0;
    this.text = value;
  }

  public setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
  }

  public append(...children: ElementLike[]): void {
    this.children.push(...(children as FakeElement[]));
  }

  public replaceChildren(...children: ElementLike[]): void {
    this.text = null;
    this.children.length = 0;
    this.append(...children);
  }

  public insertAdjacentHTML(): void {
    throw new Error("insertAdjacentHTML was called");
  }
}

const fakeDocument: DocumentLike & { created: FakeElement[] } = {
  created: [],
  createElement(tag: string) {
    const element = new FakeElement(tag);
    this.created.push(element);
    return element;
  },
};

function walk(element: FakeElement): FakeElement[] {
  return [element, ...element.children.flatMap(walk)];
}

test("hostile strings from orceld arrive as text, never as markup", () => {
  const hostile = '<img src=x onerror="alert(1)"><script>fetch("https://evil.invalid")</script>';
  const container = new FakeElement("div");
  show(fakeDocument, container, taskDetailNodes({
    state: "ok",
    value: {
      task_id: "t1",
      workspace_id: "default",
      kind: "report",
      state: "verified",
      owner: "earlier_run",
      created_at_ms: { state: "absent" },
      updated_at_ms: { state: "absent" },
      folder: { state: "shown", value: hostile },
      sources: [],
      proposal: { state: "absent" },
      report: { state: "absent" },
      check: { state: "absent" },
      steps: [],
      withheld: 0,
    },
  }));
  const elements = walk(container);
  assert.ok(elements.some((element) => element.textContent === hostile), "the string is shown verbatim, as text");
  for (const element of elements) {
    assert.ok(TAGS.includes(element.tag as never) || element === container, element.tag);
    assert.ok(!["img", "script", "a", "button", "input", "form", "iframe"].includes(element.tag));
    for (const name of element.attributes.keys()) assert.ok((ATTRIBUTES as readonly string[]).includes(name), name);
  }
});

test("only the closed tags and attributes can be drawn", () => {
  assert.throws(() => materialise(fakeDocument, { tag: "a" as never, text: "x" }), /tag outside/u);
  assert.throws(() => materialise(fakeDocument, { tag: "script" as never, text: "x" }), /tag outside/u);
  assert.throws(() => materialise(fakeDocument, { tag: "p", attrs: { href: "file:///C:/" } as never, text: "x" }), /attribute outside/u);
  assert.throws(() => materialise(fakeDocument, { tag: "p", attrs: { onclick: "x()" } as never, text: "x" }), /attribute outside/u);
  assert.throws(() => materialise(fakeDocument, { tag: "p", attrs: { style: "x" } as never, text: "x" }), /attribute outside/u);
  for (const tag of ["a", "button", "input", "form", "select", "textarea", "img", "iframe", "object", "embed", "script", "style", "link"]) {
    assert.ok(!(TAGS as readonly string[]).includes(tag), tag);
  }
  for (const name of ["href", "src", "style", "srcdoc", "action", "formaction", "tabindex"]) {
    assert.ok(!(ATTRIBUTES as readonly string[]).includes(name), name);
  }
  assert.ok(!(ATTRIBUTES as readonly string[]).some((name) => name.startsWith("on")));
});

test("a status answer is drawn with textContent into the closed set", () => {
  const container = new FakeElement("div");
  const shown = <T>(value: T) => ({ state: "shown" as const, value });
  show(
    fakeDocument,
    container,
    statusNodes(
      {
        state: "ok",
        value: {
          name: shown("orceld\u202E"),
          version: shown("1"),
          app_api: shown("orcel-app-api/1"),
          internal_protocol_version: { state: "withheld" },
          os: shown("windows"),
          arch: shown("x86_64"),
          mode: shown("SG-000039_CLIPBOARD_WRITE"),
          policy_revision: shown("1"),
          started_at_ms: { state: "absent" },
          uptime_ms: { state: "absent" },
          events: { state: "absent" },
          clients: { state: "absent" },
          endpoint_wait: { state: "absent" },
          withheld: 2,
        },
      },
      { state: "live" },
    ),
  );
  const text = container.textContent ?? "";
  assert.ok(text.includes("orceld\uFFFD"), "the bidi override was replaced");
  assert.ok(text.includes("2 fields withheld"));
  assert.ok(walk(container).every((element) => element === container || TAGS.includes(element.tag as never)));
  container.replaceChildren(materialise(fakeDocument, h("p", null, "again")));
  assert.equal(container.textContent, "again");
});
