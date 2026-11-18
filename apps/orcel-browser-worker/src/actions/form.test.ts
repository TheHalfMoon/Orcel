import assert from "node:assert/strict";
import { test } from "node:test";
import { classifyControls, formAction, MAX_CLASSIFIED_CONTROLS, type FormPage } from "./form.js";
import type { SnapshotNode } from "../snapshot.js";
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
  /// Another element covers this one (Playwright's hit-target check).
  covered?: boolean;
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
    const nots = [...part.matchAll(/:not\(\[([\w-]+)([~*^$]?)="([^"]+)"(?: i)?\]\)/g)];
    const excluded = nots.some(([, name, op, value]) => {
      const actual = (attrs[name!] ?? (name === "type" ? "text" : "")).toLowerCase();
      const wanted = value!.toLowerCase();
      if (op === "~") return actual.split(/\s+/).includes(wanted);
      if (op === "*") return actual.includes(wanted);
      if (op === "^") return actual.startsWith(wanted);
      if (op === "$") return actual.endsWith(wanted);
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
        if (one().covered) {
          throw Object.assign(
            new Error(
              [
                "locator.setChecked: Timeout 5000ms exceeded.",
                "Call log:",
                "  - attempting click action",
                '      - <div class="overlay"></div> intercepts pointer events'
              ].join("\n")
            ),
            { name: "TimeoutError" }
          );
        }
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

test("SG-000122 fill types only into a single-line text field: text, search, email, url, tel, or a missing or unknown type", async () => {
  const { stub, calls } = page({
    e1: [{ tag: "input", attrs: { type: "email", name: "email" } }],
    e2: [{ tag: "input", attrs: { name: "plain" } }],
    e3: [{ tag: "input", attrs: { type: "SEARCH", name: "q" } }],
    e4: [{ tag: "input", attrs: { type: "url", name: "site" } }],
    e5: [{ tag: "input", attrs: { type: "tel", name: "phone" } }],
    // An unknown type is the text state.
    e6: [{ tag: "input", attrs: { type: "datetime", name: "when" } }]
  });
  for (const [ref, value] of [["e1", "ada@example.test"], ["e2", ""], ["e3", "q"], ["e4", "https://a.test/"], ["e5", "+1 555"], ["e6", "x"]]) {
    await formAction(stub, ref!, { action: "fill", value: value! });
  }
  assert.equal(calls.length, 6);
});

test("SG-000122 fill and Enter refuse a textarea, a contenteditable and every other input type", async () => {
  const others = ["password", "number", "date", "datetime-local", "month", "week", "time", "color", "range", "file", "hidden", "checkbox", "radio", "submit", "button", "reset", "image"];
  const refs: Record<string, Element[]> = {
    t1: [{ tag: "textarea", attrs: { name: "note" } }],
    t2: [{ tag: "div", attrs: { contenteditable: "true" } }],
    t3: [{ tag: "div", attrs: { contenteditable: "" } }]
  };
  others.forEach((type, index) => {
    refs[`e${index + 1}`] = [{ tag: "input", attrs: { type: type.toUpperCase(), name: "field" } }];
  });
  const { stub, calls } = page(refs);
  for (const ref of Object.keys(refs)) {
    await assert.rejects(formAction(stub, ref, { action: "fill", value: "x" }), reason("denied"), `fill ${ref}`);
    await assert.rejects(formAction(stub, ref, { action: "enter" }), reason("denied"), `enter ${ref}`);
  }
  assert.deepEqual(calls, [], "nothing was typed or pressed");
});

test("SG-000122 enter presses Enter, and only Enter, in the focused single-line field, never a secret one", async () => {
  const { stub, calls } = page({
    e1: [{ tag: "input", attrs: { type: "search", name: "q" } }],
    e2: [{ tag: "input", attrs: { type: "text", name: "user_pin" } }],
    e3: [{ tag: "input", attrs: { type: "text", autocomplete: "one-time-code" } }],
    e4: [{ tag: "input", attrs: { type: "text", name: "city" }, refusesFocus: true }],
    e5: [{ tag: "button" }],
    e6: [{ tag: "select", options: ["Porto"] }],
    e7: [{ tag: "input", attrs: { type: "checkbox" } }],
    e8: [{ tag: "a", attrs: { href: "/x" } }]
  });
  await formAction(stub, "e1", { action: "enter" });
  for (const ref of ["e2", "e3", "e5", "e6", "e7", "e8"]) {
    await assert.rejects(formAction(stub, ref, { action: "enter" }), reason("denied"), ref);
  }
  await assert.rejects(formAction(stub, "e4", { action: "enter" }), reason("denied"), "focus must take");
  await assert.rejects(formAction(stub, "e9", { action: "enter" }), reason("stale"));
  assert.deepEqual(calls, ['press "Enter"']);
});

test("SG-000122 observation classifies main-frame form controls only, and only as the closed kinds", async () => {
  const { stub } = page({
    e1: [{ tag: "input", attrs: { type: "text", name: "full_name" } }],
    e2: [{ tag: "input", attrs: { type: "password", name: "pw" } }],
    e3: [{ tag: "textarea", attrs: { name: "note" } }],
    e4: [{ tag: "select", options: ["Lisbon", "Porto"] }],
    e5: [{ tag: "input", attrs: { type: "checkbox", name: "terms" } }],
    e6: [{ tag: "input", attrs: { type: "Radio", name: "plan" } }],
    e7: [{ tag: "input", attrs: { type: "search", name: "q" } }],
    e8: [{ tag: "div", attrs: { role: "checkbox" } }],
    e9: [{ tag: "input", attrs: { type: "number", name: "count" } }],
    e10: [{ tag: "input", attrs: { type: "text", list: "cities" } }],
    e11: [{ tag: "a", attrs: { href: "/x" } }],
    f1e1: [{ tag: "input", attrs: { type: "text" } }]
  });
  const node = (ref: string, role: string, children: SnapshotNode[] = []): SnapshotNode => ({ ref, role, name: "", children });
  const nodes = [
    node("e20", "form", [
      node("e1", "textbox"),
      node("e2", "textbox"),
      node("e3", "textbox"),
      node("e4", "combobox"),
      node("e5", "checkbox"),
      node("e6", "radio"),
      node("e7", "searchbox"),
      node("e8", "checkbox"),
      node("e9", "spinbutton"),
      node("e10", "combobox"),
      node("e11", "link"),
      node("f1e1", "textbox"),
      node("e12", "textbox")
    ])
  ];
  await classifyControls(stub, nodes);
  const kinds = Object.fromEntries(nodes[0]!.children.map((child) => [child.ref, child.control]));
  assert.deepEqual(kinds, {
    e1: "line",
    e2: undefined,
    e3: undefined,
    e4: "select",
    e5: "toggle",
    e6: "toggle",
    e7: "line",
    e8: undefined,
    e9: undefined,
    e10: "line",
    e11: undefined,
    f1e1: undefined,
    e12: undefined
  });
  assert.equal(nodes[0]!.control, undefined);
  // Past the bound, nodes carry no kind.
  const many: Record<string, Element[]> = {};
  const manyNodes: SnapshotNode[] = [];
  for (let index = 1; index <= MAX_CLASSIFIED_CONTROLS + 3; index += 1) {
    many[`e${index}`] = [{ tag: "input", attrs: { type: "text" } }];
    manyNodes.push(node(`e${index}`, "textbox"));
  }
  await classifyControls(page(many).stub, manyNodes);
  assert.equal(manyNodes.filter((n) => n.control === "line").length, MAX_CLASSIFIED_CONTROLS);
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
  // The secret check reads six attributes; during it, the page turns the
  // field into a password. OB-07b: the check after focus sees it and
  // refuses before any text goes in.
  const field: Element = { tag: "input", attrs: { type: "text", name: "code" }, flipAfterReads: 4 };
  const { stub, calls } = page({ e1: [field] });
  await assert.rejects(formAction(stub, "e1", { action: "fill", value: "1234" }), reason("denied"));
  assert.equal(field.attrs?.type, "password", "the page flipped the field after the check");
  assert.deepEqual(calls, [], "nothing was typed");
  // Turned secret during the second check: its later reads resolve the
  // fill's own locator, which excludes password fields, so they fail and
  // the field counts as secret; nothing is typed either.
  const late: Element = { tag: "input", attrs: { type: "text", name: "code" }, flipAfterReads: 7 };
  const second = page({ e1: [late] });
  await assert.rejects(formAction(second.stub, "e1", { action: "fill", value: "1234" }), reason("denied"));
  assert.equal(late.attrs?.type, "password");
  assert.deepEqual(second.calls, [], "nothing was typed");
});

test("OB-07b fill refuses password-like fields by label, placeholder, PIN name or password autocomplete, and only those", async () => {
  const { stub, calls } = page({
    e1: [{ tag: "input", attrs: { type: "text", "aria-label": "Password" } }],
    e2: [{ tag: "input", attrs: { type: "text", placeholder: "Enter your passcode" } }],
    e3: [{ tag: "input", attrs: { type: "text", name: "pin" } }],
    e4: [{ tag: "input", attrs: { type: "text", id: "card-pin" } }],
    e5: [{ tag: "input", attrs: { type: "text", autocomplete: "current-password" } }],
    e6: [{ tag: "input", attrs: { type: "text", autocomplete: "username new-password" } }],
    e7: [{ tag: "input", attrs: { type: "text", name: "pin_code" } }],
    // Not secret: "pin" inside another word, and an ordinary username.
    e8: [{ tag: "input", attrs: { type: "text", name: "shipping_city" } }],
    e9: [{ tag: "input", attrs: { type: "email", autocomplete: "username", "aria-label": "Email" } }]
  });
  for (const ref of ["e1", "e2", "e3", "e4", "e5", "e6", "e7"]) {
    await assert.rejects(formAction(stub, ref, { action: "fill", value: "x" }), reason("denied"), ref);
  }
  assert.deepEqual(calls, [], "nothing was typed into a secret field");
  await formAction(stub, "e8", { action: "fill", value: "Riyadh" });
  await formAction(stub, "e9", { action: "fill", value: "a@example.test" });
  assert.deepEqual(calls, ['fill "Riyadh"', 'fill "a@example.test"']);
});

test("OB-07b the fill locator itself excludes every secret field, whatever the first check said", async () => {
  // A page that answers the attribute reads as "text" but whose element is
  // a password field when the fill resolves: the fill's own locator
  // (FILLABLE, with NOT_SECRET) never resolves to it.
  for (const attrs of [
    { type: "password" },
    { type: "text", autocomplete: "current-password" },
    { type: "text", name: "pass" },
    { type: "text", name: "pin" },
    { type: "text", placeholder: "password" }
  ]) {
    const field: Element = { tag: "input", attrs: { type: "text" } };
    const { stub, calls } = page({ e1: [field] });
    // Swap the element's attributes after the control was resolved.
    const pending = formAction(stub, "e1", { action: "fill", value: "x" });
    field.attrs = attrs;
    await assert.rejects(pending, (error: unknown) => error instanceof NavigationError && (error.reason === "denied" || error.reason === "timeout"), JSON.stringify(attrs));
    assert.deepEqual(calls, [], JSON.stringify(attrs));
  }
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
  // SG-000122: exactly one option.
  await assert.rejects(formAction(stub, "e1", { action: "select", values: ["Lisbon", "Porto"] }), reason("denied"));
  await assert.rejects(formAction(stub, "e1", { action: "select", values: [] }), reason("denied"));
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
    e7: [{ tag: "button" }],
    // A text field that declares itself a button: Space would still type.
    e8: [{ tag: "input", attrs: { type: "text", role: "button" } }],
    e9: [{ tag: "div", attrs: { contenteditable: "true" } }]
  });
  await formAction(stub, "e1", { action: "press", key: "Enter" });
  await formAction(stub, "e2", { action: "press", key: "Escape" });
  await formAction(stub, "e7", { action: "press", key: "Space" });
  for (const ref of ["e3", "e4"]) {
    await assert.rejects(formAction(stub, ref, { action: "press", key: "Space" }), reason("denied"), ref);
  }
  await assert.rejects(formAction(stub, "e5", { action: "press", key: "Escape" }), reason("denied"), "focus must take");
  await assert.rejects(formAction(stub, "e6", { action: "press", key: "Enter" }), reason("denied"), "no line breaks");
  await assert.rejects(formAction(stub, "e8", { action: "press", key: "Space" }), reason("denied"), "Space types into fields");
  await assert.rejects(formAction(stub, "e9", { action: "press", key: "Enter" }), reason("denied"), "no line breaks in contenteditable");
  await formAction(stub, "e6", { action: "press", key: "Tab" });
  assert.deepEqual(calls, ['press "Enter"', 'press "Escape"', 'press " "', 'press "Tab"']);
});

test("BR-02 hover acts on the approved element only", async () => {
  const { stub, calls } = page({ e1: [{ tag: "a", attrs: { href: "/menu" } }] });
  await formAction(stub, "e1", { action: "hover" });
  await assert.rejects(formAction(stub, "e2", { action: "hover" }), reason("stale"));
  assert.deepEqual(calls, ["hover"]);
});

test("BR-04 an element covered by another is not acted on and the reason is typed", async () => {
  const { stub, calls } = page({ e1: [{ tag: "input", attrs: { type: "checkbox" }, covered: true }] });
  await assert.rejects(formAction(stub, "e1", { action: "check", checked: true }), reason("occluded"));
  assert.deepEqual(calls, []);
});
