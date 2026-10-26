import assert from "node:assert/strict";
import { test } from "node:test";
import { MAX_VERIFY_COUNT, runProbes, type VerifyPage } from "./verify.js";

interface Element {
  role?: string;
  name?: string;
  text?: string;
  visible: boolean;
  attrs?: Record<string, string>;
  value?: string;
  checked?: boolean;
}

/// A page of frames holding elements, and refs naming elements; records
/// every query so tests can see what was asked.
function page(frames: Element[][], refs: Record<string, Element[]> = {}) {
  const queries: string[] = [];
  const located = (matches: Element[]) => ({
    filter: (options: { visible: boolean }) => {
      queries.push(`filter visible=${options.visible}`);
      return located(matches.filter((element) => element.visible === options.visible));
    },
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
      return located(refs[selector.replace(/^aria-ref=/, "")] ?? []);
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
  const { stub, queries } = page(
    [
      [
        { role: "button", name: "Pay", visible: true },
        { role: "button", name: "Pay", visible: false },
        { role: "button", name: "Pay later", visible: true }
      ],
      [{ role: "button", name: "Pay", visible: true }]
    ],
    {}
  );
  assert.deepEqual(await runProbes(stub, [{ probe: "visible_role", role: "button", name: "Pay" }]), [
    { result: "visible", count: 2 }
  ]);
  assert.ok(queries.includes('role button "Pay" exact=true'));
});

test("BR-07 visible text: a case-sensitive literal substring; hidden text does not count", async () => {
  const { stub, queries } = page([
    [
      { text: "Your order is confirmed.", visible: true },
      { text: "Order confirmed (hidden copy)", visible: false },
      { text: "order confirmed", visible: true },
      { text: "Total: $1.50 (a.b)", visible: true }
    ]
  ]);
  assert.deepEqual(await runProbes(stub, [{ probe: "visible_text", text: "order is confirmed" }]), [{ result: "visible", count: 1 }]);
  assert.deepEqual(await runProbes(stub, [{ probe: "visible_text", text: "Order confirmed" }]), [{ result: "visible", count: 0 }]);
  // Regular-expression characters in the text are literal.
  assert.deepEqual(await runProbes(stub, [{ probe: "visible_text", text: "$1.50 (a.b)" }]), [{ result: "visible", count: 1 }]);
  assert.deepEqual(await runProbes(stub, [{ probe: "visible_text", text: "$1x50" }]), [{ result: "visible", count: 0 }]);
  assert.ok(queries.every((query) => !query.startsWith("text") || query.endsWith("flags=")), "no case-insensitive flag");
});

test("BR-07 counts are capped", async () => {
  const many = Array.from({ length: MAX_VERIFY_COUNT + 5 }, () => ({ text: "row", visible: true }));
  const { stub } = page([many, many]);
  assert.deepEqual(await runProbes(stub, [{ probe: "visible_text", text: "row" }]), [{ result: "visible", count: MAX_VERIFY_COUNT }]);
});

test("BR-07 values: read from the ref'd field only, never from a secret field, and bounded", async () => {
  const { stub } = page([], {
    e1: [{ visible: true, value: "Ada Lovelace", attrs: { type: "text" } }],
    e2: [{ visible: true, value: "hunter2", attrs: { type: "Password" } }],
    e3: [{ visible: true, value: "123456", attrs: { type: "text", autocomplete: "one-time-code" } }],
    e4: [{ visible: true, value: "4111111111111111", attrs: { autocomplete: "billing cc-number" } }],
    e5: [{ visible: true, attrs: {} }],
    e6: [{ visible: true, value: "x".repeat(1025), attrs: {} }],
    e7: [
      { visible: true, value: "a", attrs: {} },
      { visible: true, value: "b", attrs: {} }
    ]
  });
  assert.deepEqual(
    await runProbes(stub, ["e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8"].map((ref) => ({ probe: "value" as const, ref }))),
    [
      { result: "value", value: "Ada Lovelace" },
      { result: "unavailable", reason: "secret" },
      { result: "unavailable", reason: "secret" },
      { result: "unavailable", reason: "secret" },
      { result: "unavailable", reason: "not_a_field" },
      { result: "unavailable", reason: "too_long" },
      { result: "unavailable", reason: "stale" },
      { result: "unavailable", reason: "stale" }
    ]
  );
});

test("BR-07 checked state from the ref'd element, typed when it has none", async () => {
  const { stub } = page([], {
    e1: [{ visible: true, checked: true }],
    e2: [{ visible: true, checked: false }],
    e3: [{ visible: true }]
  });
  assert.deepEqual(
    await runProbes(stub, ["e1", "e2", "e3", "e9"].map((ref) => ({ probe: "checked" as const, ref }))),
    [
      { result: "checked", checked: true },
      { result: "checked", checked: false },
      { result: "unavailable", reason: "not_a_field" },
      { result: "unavailable", reason: "stale" }
    ]
  );
});
