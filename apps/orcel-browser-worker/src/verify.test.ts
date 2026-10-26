import assert from "node:assert/strict";
import { test } from "node:test";
import { MAX_VERIFY_COUNT, runProbes, textPattern, type VerifyPage } from "./verify.js";

interface Element {
  tag?: string;
  role?: string;
  name?: string;
  text?: string;
  visible: boolean;
  attrs?: Record<string, string>;
  value?: string;
  checked?: boolean;
}

/// Whether `element` matches the CSS lists the probes use (`input`,
/// `textarea`, `select`, typed inputs, roles), enough for these tests.
function matchesCss(element: Element, css: string): boolean {
  return css.split(",").some((raw) => {
    const part = raw.trim();
    const typed = /^input\[type="(\w+)" i\]$/.exec(part);
    if (typed) return element.tag === "input" && (element.attrs?.type ?? "").toLowerCase() === typed[1];
    const role = /^\[role="([\w-]+)"\]$/.exec(part);
    if (role) return element.attrs?.role === role[1];
    return element.tag === part;
  });
}

/// A page of frames holding elements, and refs naming elements; records
/// every query so tests can see what was asked.
function page(frames: Element[][], refs: Record<string, Element[]> = {}) {
  const queries: string[] = [];
  const located = (matches: Element[]): Record<string, unknown> => ({
    filter: (options: { visible: boolean }) => located(matches.filter((element) => element.visible === options.visible)),
    and: (other: { css: string }) => located(matches.filter((element) => matchesCss(element, other.css))),
    count: async () => matches.length,
    getAttribute: async (name: string) => matches[0]?.attrs?.[name] ?? null,
    inputValue: async () => {
      const value = matches[0]?.value;
      if (value === undefined) throw new Error("not an input");
      return value;
    },
    isChecked: async () => {
      const checked = matches[0]?.checked;
      if (checked === undefined) throw new Error("not a checkbox");
      return checked;
    }
  });
  const stub = {
    locator: (selector: string) => {
      queries.push(selector);
      if (selector.startsWith("aria-ref=")) return located(refs[selector.slice("aria-ref=".length)] ?? []);
      return { css: selector };
    },
    frames: () =>
      frames.map((elements) => ({
        getByRole: (role: string, options: { name: string; exact: boolean }) => {
          queries.push(`role ${role} ${JSON.stringify(options.name)} exact=${options.exact}`);
          return located(elements.filter((e) => e.role === role && e.name === options.name));
        },
        getByText: (pattern: RegExp) => {
          queries.push(`text ${pattern.source} flags=${pattern.flags}`);
          return located(elements.filter((e) => e.text !== undefined && pattern.test(e.text)));
        }
      }))
  };
  return { stub: stub as unknown as VerifyPage, queries };
}

test("BR-07 visible role and name: exact, across frames, visible only", async () => {
  const { stub, queries } = page([
    [
      { role: "button", name: "Pay", visible: true },
      { role: "button", name: "Pay", visible: false },
      { role: "button", name: "Pay later", visible: true }
    ],
    [{ role: "button", name: "Pay", visible: true }]
  ]);
  assert.deepEqual(await runProbes(stub, [{ probe: "visible_role", role: "button", name: "Pay" }]), [{ result: "visible", count: 2 }]);
  assert.ok(queries.includes('role button "Pay" exact=true'));
});

test("BR-07 visible text: case-sensitive literal substring, white space normalised, hidden text excluded", async () => {
  const { stub, queries } = page([
    [
      { text: "Your order is\n   confirmed.", visible: true },
      { text: "Order confirmed (hidden copy)", visible: false },
      { text: "order confirmed", visible: true },
      { text: "Total: $1.50 (a.b)", visible: true }
    ]
  ]);
  assert.deepEqual(await runProbes(stub, [{ probe: "visible_text", text: "order is confirmed" }]), [{ result: "visible", count: 1 }]);
  assert.deepEqual(await runProbes(stub, [{ probe: "visible_text", text: "Order confirmed" }]), [{ result: "visible", count: 0 }]);
  // Regular-expression characters are literal; a non-breaking space is white space.
  assert.deepEqual(await runProbes(stub, [{ probe: "visible_text", text: "$1.50 (a.b)" }]), [{ result: "visible", count: 1 }]);
  assert.deepEqual(await runProbes(stub, [{ probe: "visible_text", text: "$1x50" }]), [{ result: "visible", count: 0 }]);
  assert.ok(queries.every((query) => !query.startsWith("text") || query.endsWith("flags=")), "no case-insensitive flag");
  assert.equal(textPattern("  a.b   c ").source, "a\\.b\\s+c");
});

test("BR-07 counts are capped", async () => {
  const many = Array.from({ length: MAX_VERIFY_COUNT + 5 }, () => ({ text: "row", visible: true }));
  const { stub } = page([many, many]);
  assert.deepEqual(await runProbes(stub, [{ probe: "visible_text", text: "row" }]), [{ result: "visible", count: MAX_VERIFY_COUNT }]);
});

test("BR-07 values: only from the ref'd element when it is itself a field, never a secret one, bounded", async () => {
  const input = (attrs: Record<string, string>, value?: string): Element =>
    value === undefined ? { tag: "input", visible: true, attrs } : { tag: "input", visible: true, attrs, value };
  const { stub } = page([], {
    e1: [input({ type: "text", name: "email" }, "Ada Lovelace")],
    e2: [input({ type: "Password" }, "hunter2")],
    e3: [input({ type: "text", autocomplete: "one-time-code" }, "123456")],
    e4: [input({ autocomplete: "billing cc-number" }, "4111111111111111")],
    e5: [input({ type: "text", name: "card_cvc" }, "123")],
    e6: [input({ type: "text", id: "login-pin" }, "1234")],
    // A non-field inside a label: Playwright's inputValue would follow the
    // label to its (password) control, so nothing is read.
    e7: [{ tag: "span", visible: true, attrs: { role: "textbox" }, value: "hunter2" }],
    e8: [{ tag: "textarea", visible: true, attrs: {}, value: "x".repeat(1025) }],
    e9: [input({}, "a"), input({}, "b")]
  });
  assert.deepEqual(
    await runProbes(stub, ["e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "e10", "f1e1"].map((ref) => ({ probe: "value" as const, ref }))),
    [
      { result: "value", value: "Ada Lovelace" },
      { result: "unavailable", reason: "secret" },
      { result: "unavailable", reason: "secret" },
      { result: "unavailable", reason: "secret" },
      { result: "unavailable", reason: "secret" },
      { result: "unavailable", reason: "secret" },
      { result: "unavailable", reason: "not_a_field" },
      { result: "unavailable", reason: "too_long" },
      { result: "unavailable", reason: "stale" },
      { result: "unavailable", reason: "stale" },
      { result: "unavailable", reason: "not_a_field" }
    ]
  );
});

test("BR-07 checked state only from a checkbox, radio or switch the ref names", async () => {
  const { stub } = page([], {
    e1: [{ tag: "input", visible: true, attrs: { type: "checkbox" }, checked: true }],
    e2: [{ tag: "div", visible: true, attrs: { role: "switch" }, checked: false }],
    e3: [{ tag: "label", visible: true, attrs: {}, checked: true }],
    e4: [{ tag: "input", visible: true, attrs: { type: "checkbox" } }]
  });
  assert.deepEqual(
    await runProbes(stub, ["e1", "e2", "e3", "e4", "e9"].map((ref) => ({ probe: "checked" as const, ref }))),
    [
      { result: "checked", checked: true },
      { result: "checked", checked: false },
      { result: "unavailable", reason: "not_a_field" },
      { result: "unavailable", reason: "not_a_field" },
      { result: "unavailable", reason: "stale" }
    ]
  );
});

test("BR-07 all probes share one time budget", async () => {
  const slow = {
    locator: () => ({ count: () => new Promise<number>(() => {}) }),
    frames: () => []
  } as unknown as VerifyPage;
  const started = Date.now();
  await assert.rejects(runProbes(slow, [{ probe: "value", ref: "e1" }], 50), /budget/);
  assert.ok(Date.now() - started < 1_000);
});
