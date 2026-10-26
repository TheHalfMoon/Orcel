// BR-02 (first slice): approved form actions — fill a field, select
// options, set a checkbox or radio. Each acts on exactly one element the
// host approved, only when that element is itself the right kind of form
// control, and never on a field that looks secret.
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
// generation are not ported.

import type { Locator, Page } from "playwright-core";
import type { ApprovedTarget } from "../protocol.js";
import { isSecretField } from "../verify.js";
import { NavigationError } from "../worker.js";
import { approvedElement, type TargetPage } from "./targets.js";

export type FormAction =
  | { action: "fill"; value: string }
  | { action: "select"; values: string[] }
  | { action: "check"; checked: boolean };

/// The page surface form actions use (a Playwright `Page`, or a test stub).
export type FormPage = TargetPage & Pick<Page, "locator">;

/// Controls a value can be typed into.
const FILLABLE =
  'input:not([type="hidden" i]):not([type="checkbox" i]):not([type="radio" i]):not([type="submit" i]):not([type="button" i]):not([type="reset" i]):not([type="file" i]):not([type="image" i]):not([type="range" i]):not([type="color" i]), textarea, [contenteditable]:not([contenteditable="false" i])';
const SELECTABLE = "select";
const CHECKABLE = 'input[type="checkbox" i], input[type="radio" i]';
/// One action's own budget, under the host's reply deadline.
export const FORM_ACTION_TIMEOUT_MS = 5_000;

const kindOf = (action: FormAction): string =>
  action.action === "fill" ? FILLABLE : action.action === "select" ? SELECTABLE : CHECKABLE;

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
    }
  } catch (error) {
    if (error instanceof NavigationError) throw error;
    const message = error instanceof Error ? error.message : "";
    throw new NavigationError(/timeout/i.test(message) ? "timeout" : "failed");
  }
}
