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

import type { Locator, Page } from "playwright-core";
import type { ApprovedTarget } from "../protocol.js";
import { isSecretField } from "../verify.js";
import { NavigationError } from "../worker.js";
import { approvedElement, type TargetPage } from "./targets.js";

export type FormAction =
  | { action: "fill"; value: string }
  | { action: "select"; values: string[] }
  | { action: "check"; checked: boolean }
  | { action: "press"; key: PressKey }
  | { action: "hover" };

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
/// Controls a value can be typed into.
const FILLABLE = [
  `input:not([type="hidden" i]):not([type="checkbox" i]):not([type="radio" i]):not([type="submit" i]):not([type="button" i]):not([type="reset" i]):not([type="file" i]):not([type="image" i]):not([type="range" i]):not([type="color" i])${NOT_SECRET}`,
  `textarea${NOT_SECRET}`,
  `[contenteditable]:not([contenteditable="false" i])${NOT_SECRET}`
].join(", ");
const SELECTABLE = "select";
const CHECKABLE = 'input[type="checkbox" i], input[type="radio" i]';
/// One action's own budget, under the host's reply deadline.
export const FORM_ACTION_TIMEOUT_MS = 5_000;

/// Any element that is not a secret field (a key could type into it).
const PRESSABLE = `*${NOT_SECRET}`;
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
/// control, or a secret field), "timeout" or "failed".
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
        if (new Set(action.values).size !== action.values.length) throw new NavigationError("denied");
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
        if (action.key === "Space" && (await own.and(page.locator(FILLABLE)).count()) > 0) throw new NavigationError("denied");
        await own.focus(options);
        // The key goes to whatever holds focus: only the approved element.
        if ((await own.and(page.locator(":focus")).count()) !== 1) throw new NavigationError("denied");
        await page.keyboard.press(action.key === "Space" ? " " : action.key);
        return;
      }
      case "hover":
        await own.hover(options);
        return;
    }
  } catch (error) {
    if (error instanceof NavigationError) throw error;
    const message = error instanceof Error ? error.message : "";
    throw new NavigationError(/timeout/i.test(message) ? "timeout" : "failed");
  }
}
