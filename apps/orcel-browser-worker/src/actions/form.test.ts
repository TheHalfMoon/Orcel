import assert from "node:assert/strict";
import { test } from "node:test";
import { formAction, type FormPage } from "./form.js";
import { NavigationError } from "../worker.js";

interface Element {
  tag: string;
  attrs?: Record<string, string>;
  options?: string[];
}

/// Whether `element` matches the CSS lists the actions use, enough for
/// these tests: tag names, typed inputs, the input exclusions and
/// contenteditable.
function matchesCss(element: Element, css: string): boolean {
  const type = (element.attrs?.type ?? "text").toLowerCase();
  return css.split(/,\s*(?![^()]*\))/).some((raw) => {
    const part = raw.trim();
    if (part.startsWith("input:not(")) {
      const excluded = [...part.matchAll(/type="(\w+)"/g)].map((m) => m[1]);
      return element.tag === "input" && !excluded.includes(type);
    }
    const typed = /^input\[type="(\w+)" i\]$/.exec(part);
    if (typed) return element.tag === "input" && type === typed[1];
    if (part.startsWith("[contenteditable]")) {
      const editable = element.attrs?.contenteditable;
      return editable !== undefined && editable.toLowerCase() !== "false";
    }
    return element.tag === part;
  });
}

/// A page whose refs name elements; records the Playwright calls made.
function page(refs: Record<string, Element[]>) {
  const calls: string[] = [];
  const located = (matches: Element[]): Record<string, unknown> => ({
    and: (other: { css: string }) => located(matches.filter((element) => matchesCss(element, other.css))),
    count: async () => matches.length,
    getAttribute: async (name: string) => matches[0]?.attrs?.[name] ?? null,
    fill: async (value: string) => {
      calls.push(`fill ${JSON.stringify(value)}`);
    },
    selectOption: async (options: Array<{ label: string }>) => {
      calls.push(`select ${options.map((o) => o.label).join("|")}`);
      return options.filter((o) => matches[0]?.options?.includes(o.label)).map((o) => o.label);
    },
    setChecked: async (checked: boolean) => {
      calls.push(`check ${checked}`);
    }
  });
  const stub = {
    locator: (selector: string) => {
      if (selector.startsWith("aria-ref=")) return located(refs[selector.slice("aria-ref=".length)] ?? []);
      return { css: selector };
    },
    mainFrame: () => ({ getByRole: () => located([]) })
  };
  return { stub: stub as unknown as FormPage, calls };
}

const reason = (expected: string) => (error: unknown) => error instanceof NavigationError && error.reason === expected;

test("BR-02 fill types into the approved text control only", async () => {
  const { stub, calls } = page({
    e1: [{ tag: "input", attrs: { type: "email", name: "email" } }],
    e2: [{ tag: "textarea", attrs: { name: "note" } }],
    e3: [{ tag: "div", attrs: { contenteditable: "true" } }]
  });
  await formAction(stub, "e1", { action: "fill", value: "ada@example.test" });
  await formAction(stub, "e2", { action: "fill", value: "" });
  await formAction(stub, "e3", { action: "fill", value: "Hello" });
  assert.deepEqual(calls, ['fill "ada@example.test"', 'fill ""', 'fill "Hello"']);
});

test("BR-02 fill refuses secret fields, non-controls and the wrong kind of input", async () => {
  const { stub, calls } = page({
    e1: [{ tag: "input", attrs: { type: "password" } }],
    e2: [{ tag: "input", attrs: { type: "text", autocomplete: "cc-number" } }],
    e3: [{ tag: "input", attrs: { type: "text", name: "otp" } }],
    // A non-control inside a label: Playwright would fill the label's control.
    e4: [{ tag: "span", attrs: { role: "textbox" } }],
    e5: [{ tag: "input", attrs: { type: "checkbox" } }],
    e6: [{ tag: "input", attrs: { type: "hidden" } }],
    e7: [{ tag: "div", attrs: { contenteditable: "false" } }]
  });
  for (const ref of ["e1", "e2", "e3", "e4", "e5", "e6", "e7"]) {
    await assert.rejects(formAction(stub, ref, { action: "fill", value: "x" }), reason("denied"), ref);
  }
  await assert.rejects(formAction(stub, "e9", { action: "fill", value: "x" }), reason("stale"));
  assert.deepEqual(calls, [], "nothing was typed");
});

test("BR-02 select chooses native options by label; a missing option fails", async () => {
  const { stub, calls } = page({
    e1: [{ tag: "select", options: ["Lisbon", "Porto"] }],
    e2: [{ tag: "input", attrs: { type: "text", role: "combobox" } }]
  });
  await formAction(stub, "e1", { action: "select", values: ["Porto"] });
  await assert.rejects(formAction(stub, "e1", { action: "select", values: ["Paris"] }), reason("failed"));
  await assert.rejects(formAction(stub, "e2", { action: "select", values: ["Porto"] }), reason("denied"));
  assert.deepEqual(calls, ["select Porto", "select Paris"]);
});

test("BR-02 check sets only a checkbox or radio", async () => {
  const { stub, calls } = page({
    e1: [{ tag: "input", attrs: { type: "checkbox" } }],
    e2: [{ tag: "input", attrs: { type: "Radio" } }],
    e3: [{ tag: "label" }]
  });
  await formAction(stub, "e1", { action: "check", checked: true });
  await formAction(stub, "e2", { action: "check", checked: false });
  await assert.rejects(formAction(stub, "e3", { action: "check", checked: true }), reason("denied"));
  assert.deepEqual(calls, ["check true", "check false"]);
});
