// BR-02: approved element actions — fill a field, select options, set a
// checkbox or radio, press a key, hover. Each acts on exactly one element
// the host approved, only when that element is itself the right kind of
// control, and never types into a field that looks secret.
//
// Adapted from microsoft/playwright at commit
// 1b025d7e20a026371cd5f98ba0cdce48892737c8,
// `packages/playwright-core/src/tools/backend/form.ts` (blob
// 193e2b3d084e713c4bb0e3d37d77e5201748dbd5; browser_fill_form: `locator.fill`,
// `locator.selectOption`, `locator.setChecked`). Apache
// License 2.0, Copyright (c) Microsoft Corporation; notice in
// docs/orcel/notices/playwright-Apache-2.0.txt. Modifications for Orcel:
// one action per frame, approved by the host for this element and this exact
// value; the element must itself be the control (Playwright's form calls
// otherwise follow a label to its control); fill refuses fields that look
// secret (SG-000077), fill clears first (Browser Use semantics, and
// Playwright's `fill`); select chooses native `<select>` options by their
// visible label only; frames, zod schemas, the MCP response builder and code
// generation are not ported. Press and hover are adapted from the same
// commit's `keyboard.ts` (blob f8f3abd271a0524d3258ae9c0c5f3c96171b0d5c,
// `locator.press`) and `snapshot.ts` (blob
// cda3d0fa6cfb8ff7a28a104e32ce34f4b5573588, browser_hover: `locator.hover`):
// a key from a closed list (no characters but Space, no deletion, no
// modifiers), sent only after the approved element itself holds focus, never
// to a field that looks secret, never Enter into a textarea; a page script
// can still move focus while the key is delivered.
//
// SG-000122 slice A1 narrows these to the grain: a fill types only into a
// single-line text field (an input whose type state is text, search, email,
// url or tel; a missing or unknown type is text), never a textarea or a
// contenteditable; `enter` presses Enter, and no other key, only in such a
// field; a select chooses exactly one option. At observation the worker
// reports which main-frame form controls are such fields, native selects or
// checkbox and radio inputs (`classifyControls`), so the host can refuse
// before it sends anything; the checks here run again on the element itself.

import type { Locator, Page } from "playwright-core";
import type { ApprovedTarget } from "../protocol.js";
import type { FormControl, SnapshotNode } from "../snapshot.js";
import { isSecretField } from "../verify.js";
import { NavigationError } from "../worker.js";
import { approvedElement, isOcclusion, type TargetPage } from "./targets.js";

export type FormAction =
  | { action: "fill"; value: string }
  | { action: "select"; values: string[] }
  | { action: "check"; checked: boolean }
  | { action: "press"; key: PressKey }
  | { action: "hover" }
  | { action: "enter" };

/// The keys an approved press may send (mirrors the host): navigation and
/// editing keys only, no characters (Space aside) and no modifiers.
export const PRESS_KEYS = [
  "Enter",
  "Tab",
  "Escape",
  "ArrowUp",
  "ArrowDown",
  "ArrowLeft",
  "ArrowRight",
  "Home",
  "End",
  "PageUp",
  "PageDown",
  "Space"
] as const;
export type PressKey = (typeof PRESS_KEYS)[number];

/// The page surface form actions use (a Playwright `Page`, or a test stub).
export type FormPage = TargetPage & Pick<Page, "locator" | "keyboard">;

/// What no fill ever resolves to, part of the locator the fill itself
/// resolves (so a page that turns a field secret after the check is still
/// refused when Playwright acts): password inputs, secret `autocomplete`
/// tokens, and names or ids that suggest a secret.
const NOT_SECRET = [
  ':not([type="password" i])',
  ':not([autocomplete~="current-password" i]):not([autocomplete~="new-password" i]):not([autocomplete~="one-time-code" i])',
  ':not([autocomplete~="cc-number" i]):not([autocomplete~="cc-csc" i]):not([autocomplete~="cc-exp" i]):not([autocomplete~="cc-exp-month" i]):not([autocomplete~="cc-exp-year" i])',
  ...["pass", "pwd", "otp", "cvc", "cvv", "csc", "secret", "token"].map((part) => `:not([name*="${part}" i]):not([id*="${part}" i])`)
].join("");
/// SG-000122: a single-line text field: an input whose type state is text,
/// search, email, url or tel. HTML matches the type attribute ASCII
/// case-insensitively and treats a missing or unknown one as text, so the
/// field is any input whose type is none of the other known types.
export const SINGLE_LINE_INPUT = `input${[
  "hidden",
  "password",
  "number",
  "date",
  "datetime-local",
  "month",
  "week",
  "time",
  "color",
  "range",
  "file",
  "checkbox",
  "radio",
  "submit",
  "button",
  "reset",
  "image"
]
  .map((type) => `:not([type="${type}" i])`)
  .join("")}`;
/// Controls a value can be typed into: single-line text fields that do not
/// look secret (SG-000122: never a textarea or contenteditable).
const FILLABLE = `${SINGLE_LINE_INPUT}${NOT_SECRET}`;
const SELECTABLE = "select";
const CHECKABLE = 'input[type="checkbox" i], input[type="radio" i]';
/// One action's own budget, under the host's reply deadline.
export const FORM_ACTION_TIMEOUT_MS = 5_000;

/// Any element that is not a secret field (a key could type into it).
const PRESSABLE = `*${NOT_SECRET}`;
/// Anything a key could type into (Space is never pressed there): every
/// input that is not a button, checkbox, radio, file, range or color input,
/// a textarea, or a contenteditable.
const TYPABLE = [
  'input:not([type="hidden" i]):not([type="checkbox" i]):not([type="radio" i]):not([type="submit" i]):not([type="button" i]):not([type="reset" i]):not([type="file" i]):not([type="image" i]):not([type="range" i]):not([type="color" i])',
  "textarea",
  '[contenteditable]:not([contenteditable="false" i])'
].join(", ");
const HOVERABLE = "*";

const kindOf = (action: FormAction): string => {
  switch (action.action) {
    case "fill":
      return FILLABLE;
    case "select":
      return SELECTABLE;
    case "check":
      return CHECKABLE;
    case "press":
      return PRESSABLE;
    case "hover":
      return HOVERABLE;
    case "enter":
      return FILLABLE;
  }
};

/// The approved element, when it is itself a control of the action's kind.
async function control(page: FormPage, ref: string, action: FormAction, target?: ApprovedTarget): Promise<Locator> {
  const element = await approvedElement(page, ref, target);
  const own = element.and(page.locator(kindOf(action)));
  if ((await own.count().catch(() => 0)) !== 1) throw new NavigationError("denied");
  return own;
}

/// Performs one approved form action on the primary page. Rejects with
/// NavigationError: "stale" (the element is gone), "denied" (not the right
/// control, or a secret field), "occluded" (BR-04: another element covered
/// it and the pointer action was never performed; only check and hover are
/// hit-tested, fill, select and press are not), "timeout" or "failed".
export async function formAction(page: FormPage, ref: string, action: FormAction, target?: ApprovedTarget): Promise<void> {
  const own = await control(page, ref, action, target);
  const options = { timeout: FORM_ACTION_TIMEOUT_MS };
  try {
    switch (action.action) {
      case "fill":
        if (await isSecretField(own)) throw new NavigationError("denied");
        await own.fill(action.value, options);
        return;
      case "select": {
        // SG-000122: exactly one option of a native select.
        if (action.values.length !== 1) throw new NavigationError("denied");
        const chosen = await own.selectOption(
          action.values.map((label) => ({ label })),
          options
        );
        if (chosen.length !== action.values.length) throw new NavigationError("failed");
        return;
      }
      case "check":
        await own.setChecked(action.checked, options);
        return;
      case "press": {
        if (await isSecretField(own)) throw new NavigationError("denied");
        // Enter in a multi-line field would add a line (multi-line values are refused).
        if (action.key === "Enter" && (await own.and(page.locator('textarea, [contenteditable]:not([contenteditable="false" i])')).count()) > 0) {
          throw new NavigationError("denied");
        }
        // Space never types into a field, whatever role the page declares.
        if (action.key === "Space" && (await own.and(page.locator(TYPABLE)).count()) > 0) throw new NavigationError("denied");
        await own.focus(options);
        // The key goes to whatever holds focus: only the approved element.
        if ((await own.and(page.locator(":focus")).count()) !== 1) throw new NavigationError("denied");
        await page.keyboard.press(action.key === "Space" ? " " : action.key);
        return;
      }
      case "hover":
        await own.hover(options);
        return;
      case "enter": {
        // SG-000122: Enter only, only in a single-line text field (the
        // locator above), never a secret one, and only once the approved
        // field itself holds focus. It may submit what the page holds.
        if (await isSecretField(own)) throw new NavigationError("denied");
        await own.focus(options);
        if ((await own.and(page.locator(":focus")).count()) !== 1) throw new NavigationError("denied");
        await page.keyboard.press("Enter");
        return;
      }
    }
  } catch (error) {
    if (error instanceof NavigationError) throw error;
    // BR-04: covered by another element: nothing was done.
    if (isOcclusion(error)) throw new NavigationError("occluded");
    const message = error instanceof Error ? error.message : "";
    throw new NavigationError(/timeout/i.test(message) ? "timeout" : "failed");
  }
}

/// SG-000122: main-frame form controls classified at most per observation,
/// and the time the classification may take (under the host's reply bound).
export const MAX_CLASSIFIED_CONTROLS = 64;
export const CLASSIFY_BUDGET_MS = 3_000;

/// The kinds a node of each role may be, tried in order.
const CONTROL_KINDS: Readonly<Record<string, ReadonlyArray<readonly [FormControl, string]>>> = {
  textbox: [["line", SINGLE_LINE_INPUT]],
  searchbox: [["line", SINGLE_LINE_INPUT]],
  combobox: [
    ["line", SINGLE_LINE_INPUT],
    ["select", SELECTABLE]
  ],
  listbox: [["select", SELECTABLE]],
  checkbox: [["toggle", CHECKABLE]],
  radio: [["toggle", CHECKABLE]]
};

/// SG-000122: marks each main-frame form-control node of a fresh snapshot
/// with its kind: `line` for a single-line text field, `select` for a native
/// select, `toggle` for a checkbox or radio input. Read-only (CSS matching on
/// the element its ref names, no page script); a node that is anything else,
/// is inside a frame, or is past the bound or the time budget, carries no
/// kind, so the host refuses form actions on it.
export async function classifyControls(page: Pick<Page, "locator">, nodes: SnapshotNode[], budgetMs = CLASSIFY_BUDGET_MS): Promise<void> {
  const deadline = Date.now() + budgetMs;
  let classified = 0;
  const visit = async (node: SnapshotNode): Promise<void> => {
    if (classified >= MAX_CLASSIFIED_CONTROLS || Date.now() > deadline) return;
    const kinds = Object.hasOwn(CONTROL_KINDS, node.role) ? CONTROL_KINDS[node.role] : undefined;
    if (kinds && /^e\d+$/.test(node.ref)) {
      classified += 1;
      const element = page.locator(`aria-ref=${node.ref}`);
      if ((await element.count().catch(() => 0)) === 1) {
        for (const [kind, css] of kinds) {
          if ((await element.and(page.locator(css)).count().catch(() => 0)) === 1) {
            node.control = kind;
            break;
          }
        }
      }
    }
    for (const child of node.children) await visit(child);
  };
  for (const node of nodes) await visit(node);
}
