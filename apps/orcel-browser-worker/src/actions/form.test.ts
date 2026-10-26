import assert from "node:assert/strict";
import { test } from "node:test";
import { formAction, type FormPage } from "./form.js";
import { NavigationError } from "../worker.js";

interface Element {
  tag: string;
  attrs?: Record<string, string>;
  options?: string[];
  /// `getAttribute` throws (a detached or hostile element).
  unreadable?: boolean;
  /// The page turns the field into a password after this many attribute
  /// reads (between the secret check and the fill).
  flipAfterReads?: number;
  /// Focusing the element moves focus elsewhere (a page script, or an
  /// element that cannot take focus).
  refusesFocus?: boolean;
}

/// Whether `element` matches one of the CSS lists the actions use, enough
/// for these tests: tag names, typed inputs, `:not([type=...])`,
/// `:not([autocomplete~=...])`, `:not([name*=...])`/`:not([id*=...])` and
/// contenteditable.
let focused: Element | null = null;

function matchesCss(element: Element, css: string): boolean {
  if (css === ":focus") return element === focused;
  const attrs = element.attrs ?? {};
  const type = (attrs.type ?? "text").toLowerCase();
  return css.split(/,\s*(?![^()]*\))/).some((raw) => {
    const part = raw.trim();
    const head = part.split(":not(")[0]!;
    const nots = [...part.matchAll(/:not\(\[([\w-]+)([~*]?)="([^"]+)"(?: i)?\]\)/g)];
    const excluded = nots.some(([, name, op, value]) => {
      const actual = (attrs[name!] ?? (name === "type" ? "text" : "")).toLowerCase();
      const wanted = value!.toLowerCase();
      if (op === "~") return actual.split(/\s+/).includes(wanted);
      if (op === "*") return actual.includes(wanted);
      return actual === wanted;
    });
    if (excluded) return false;
    if (head === "input") return element.tag === "input";
    if (head === "*") return true;
    const typed = /^input\[type="(\w+)" i\]$/.exec(head);
    if (typed) return element.tag === "input" && type === typed[1];
    if (head.startsWith("[contenteditable]")) {
      return attrs.contenteditable !== undefined && attrs.contenteditable.toLowerCase() !== "false";
    }
    return element.tag === head;
  });
}

/// A page whose refs (and, for the BR-01 fallback, role queries) name
/// elements. Like Playwright, an action re-resolves its locator when it
/// acts, so a page that changes an element between a check and the action
/// is seen at the action. Records the actions taken.
function page(refs: Record<string, Element[]>, byRole: Element[] = []) {
  const calls: string[] = [];
  const located = (matches: () => Element[], css?: string): Record<string, unknown> => {
    const now = () => matches().filter((element) => css === undefined || matchesCss(element, css));
    const one = (): Element => {
      const found = now();
      if (found.length !== 1) throw new Error("Timeout 5000ms exceeded waiting for locator");
      return found[0]!;
    };
    return {
      and: (other: { css: string }) => located(now, other.css),
      count: async () => now().length,
      getAttribute: async (name: string) => {
        const element = one();
        if (element.unreadable) throw new Error("detached");
        const value = element.attrs?.[name] ?? null;
        if (element.flipAfterReads !== undefined && --element.flipAfterReads === 0) element.attrs = { ...element.attrs, type: "password" };
        return value;
      },
      fill: async (value: string) => {
        one();
        calls.push(`fill ${JSON.stringify(value)}`);
      },
      selectOption: async (options: Array<{ label: string }>) => {
        const element = one();
        calls.push(`select ${options.map((o) => o.label).join("|")}`);
        return options.filter((o) => element.options?.includes(o.label)).map((o) => o.label);
      },
      setChecked: async (checked: boolean) => {
        one();
        calls.push(`check ${checked}`);
      },
      focus: async () => {
        const element = one();
        focused = element.refusesFocus ? null : element;
      },
      hover: async () => {
        one();
        calls.push("hover");
      }
    };
  };
  const stub = {
    locator: (selector: string) => {
      if (selector.startsWith("aria-ref=")) return located(() => refs[selector.slice("aria-ref=".length)] ?? []);
      return { css: selector };
    },
    mainFrame: () => ({ getByRole: () => located(() => byRole) }),
    keyboard: {
      press: async (key: string) => {
        calls.push(`press ${JSON.stringify(key)}`);
      }
    }
  };
  focused = null;
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
    e2: [{ tag: "input", attrs: { type: "text", autocomplete: "billing cc-number" } }],
    e3: [{ tag: "input", attrs: { type: "text", name: "otp" } }],
    // A non-control inside a label: Playwright would fill the label's control.
    e4: [{ tag: "span", attrs: { role: "textbox" } }],
    e5: [{ tag: "input", attrs: { type: "checkbox" } }],
    e6: [{ tag: "input", attrs: { type: "hidden" } }],
    e7: [{ tag: "div", attrs: { contenteditable: "false" } }],
    e8: [{ tag: "input", attrs: { type: "text", name: "login_pin" } }],
    // An attribute that cannot be read counts as secret.
    e9: [{ tag: "input", attrs: { type: "text" }, unreadable: true }]
  });
  for (const ref of ["e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9"]) {
    await assert.rejects(formAction(stub, ref, { action: "fill", value: "x" }), reason("denied"), ref);
  }
  await assert.rejects(formAction(stub, "e10", { action: "fill", value: "x" }), reason("stale"));
  assert.deepEqual(calls, [], "nothing was typed");
});

test("BR-02 a field turned secret after the check is still not filled", async () => {
  // The secret check reads four attributes; right after it, the page turns
  // the field into a password. The fill resolves its own locator, which
  // excludes password fields, so nothing is typed.
  const field: Element = { tag: "input", attrs: { type: "text", name: "code" }, flipAfterReads: 4 };
  const { stub, calls } = page({ e1: [field] });
  await assert.rejects(formAction(stub, "e1", { action: "fill", value: "1234" }), reason("timeout"));
  assert.equal(field.attrs?.type, "password", "the page flipped the field after the check");
  assert.deepEqual(calls, [], "nothing was typed");
});

test("BR-02 the role and name fallback acts on the one matching control, with the same checks", async () => {
  const { stub, calls } = page({}, [{ tag: "input", attrs: { type: "text", name: "full_name" } }]);
  await formAction(stub, "e1", { action: "fill", value: "Ada" }, { role: "textbox", name: "Full name" });
  assert.deepEqual(calls, ['fill "Ada"']);
  const secret = page({}, [{ tag: "input", attrs: { type: "password" } }]);
  await assert.rejects(
    formAction(secret.stub, "e1", { action: "fill", value: "x" }, { role: "textbox", name: "Password" }),
    reason("denied")
  );
  assert.deepEqual(secret.calls, []);
});

test("BR-02 select chooses native options by label; a missing option fails; repeats are refused", async () => {
  const { stub, calls } = page({
    e1: [{ tag: "select", options: ["Lisbon", "Porto"] }],
    e2: [{ tag: "input", attrs: { type: "text", role: "combobox" } }]
  });
  await formAction(stub, "e1", { action: "select", values: ["Porto"] });
  await assert.rejects(formAction(stub, "e1", { action: "select", values: ["Paris"] }), reason("failed"));
  await assert.rejects(formAction(stub, "e1", { action: "select", values: ["Porto", "Porto"] }), reason("denied"));
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

test("BR-02 press sends an allowed key to the approved element, never into a secret field", async () => {
  const { stub, calls } = page({
    e1: [{ tag: "input", attrs: { type: "search", name: "q" } }],
    e2: [{ tag: "div", attrs: { role: "dialog" } }],
    e3: [{ tag: "input", attrs: { type: "password" } }],
    e4: [{ tag: "input", attrs: { type: "text", name: "user_pin" } }],
    // Cannot take focus: the key would go wherever focus was.
    e5: [{ tag: "div", attrs: { role: "dialog" }, refusesFocus: true }],
    e6: [{ tag: "textarea", attrs: { name: "note" } }],
    e7: [{ tag: "button" }]
  });
  await formAction(stub, "e1", { action: "press", key: "Enter" });
  await formAction(stub, "e2", { action: "press", key: "Escape" });
  await formAction(stub, "e7", { action: "press", key: "Space" });
  for (const ref of ["e3", "e4"]) {
    await assert.rejects(formAction(stub, ref, { action: "press", key: "Space" }), reason("denied"), ref);
  }
  await assert.rejects(formAction(stub, "e5", { action: "press", key: "Escape" }), reason("denied"), "focus must take");
  await assert.rejects(formAction(stub, "e6", { action: "press", key: "Enter" }), reason("denied"), "no line breaks");
  await formAction(stub, "e6", { action: "press", key: "Tab" });
  assert.deepEqual(calls, ['press "Enter"', 'press "Escape"', 'press " "', 'press "Tab"']);
});

test("BR-02 hover acts on the approved element only", async () => {
  const { stub, calls } = page({ e1: [{ tag: "a", attrs: { href: "/menu" } }] });
  await formAction(stub, "e1", { action: "hover" });
  await assert.rejects(formAction(stub, "e2", { action: "hover" }), reason("stale"));
  assert.deepEqual(calls, ["hover"]);
});
