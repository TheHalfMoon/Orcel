// SG-000122 slice A5: which main-frame form controls may show their
// accessible name to the host's caller.
//
// The name itself is the one Playwright's accessibility snapshot computed
// for the node, in Playwright's isolated (utility) world, never by page
// script. That computation follows the accessible-name rules, which add an
// embedded or referenced control's value, selected option label or text to
// the name: a label that wraps a checkbox and a textbox names the checkbox
// with the textbox's value, and aria-labelledby (or aria-owns) can point at a
// password field (measured on Edge with Playwright 1.63). So a name is passed
// on only when nothing of that kind can contribute: every labelling element
// (a wrapping label, a label for the control's id, each element
// aria-labelledby names) is checked, again only with Playwright's own
// isolated-world locators (CSS, XPath and attribute reads), to hold no
// control other than the named control itself and to own nothing through
// aria-owns. A control whose name cannot be shown that way carries no name.
// aria-describedby never adds to a name, and descriptions are not sent.
//
// A page can still put any text it likes into a name (an aria-label, a
// label's text): the host bounds it and marks it untrusted, and a name never
// grants anything.

import type { Locator, Page } from "playwright-core";
import type { SnapshotNode } from "../snapshot.js";

/// The roles whose names may cross (SG-000122 rule change (b)).
export const NAMED_ROLES: ReadonlySet<string> = new Set(["textbox", "searchbox", "combobox", "listbox", "checkbox", "radio"]);
/// Main-frame form controls named at most per observation, and the time the
/// checks may take (under the host's observation bound, after the snapshot
/// and the classification).
export const MAX_NAMED_CONTROLS = 64;
export const NAME_BUDGET_MS = 2_000;
/// The most ids an aria-labelledby may name before the name is withheld.
export const MAX_LABELLEDBY_IDS = 8;
const READ_TIMEOUT_MS = 500;

/// The elements a name may belong to: an input or a native select.
const NAMEABLE = "input, select";
const WIDGET_ROLES = [
  "textbox",
  "searchbox",
  "combobox",
  "listbox",
  "option",
  "spinbutton",
  "slider",
  "scrollbar",
  "progressbar",
  "meter",
  "checkbox",
  "radio",
  "switch",
  "menuitemcheckbox",
  "menuitemradio",
  "treeitem"
];
/// Anything whose value, selection or text an accessible name could carry,
/// and anything that pulls other elements into one (aria-owns).
export const CONTRIBUTING = [
  "input",
  "select",
  "textarea",
  "option",
  "datalist",
  "meter",
  "progress",
  '[contenteditable]:not([contenteditable="false" i])',
  "[aria-owns]",
  ...WIDGET_ROLES.map((role) => `[role~="${role}" i]`)
].join(", ");

/// A CSS string literal for an id, or null when the id holds a character
/// a selector should not carry.
function cssString(value: string): string | null {
  if (value.length === 0 || value.length > 256 || /[\u0000-\u001f\u007f-\u009f]/.test(value)) return null;
  return `"${value.replace(/[\\"]/g, (ch) => `\\${ch}`)}"`;
}

async function attribute(element: Locator, name: string): Promise<string | null | undefined> {
  try {
    return await element.getAttribute(name, { timeout: READ_TIMEOUT_MS });
  } catch {
    return undefined;
  }
}

/// Whether `element`'s computed name can carry nothing but text: no
/// labelling element holds another control or owns anything, and no element
/// aria-labelledby names is or holds a control. Any failed read is "no".
export async function nameIsTextOnly(page: Pick<Page, "locator">, element: Locator): Promise<boolean> {
  const contributing = page.locator(CONTRIBUTING);
  const labelledby = await attribute(element, "aria-labelledby");
  if (labelledby === undefined) return false;
  const ids = (labelledby ?? "").split(/[\t\n\f\r ]+/).filter((id) => id.length > 0);
  if (ids.length > MAX_LABELLEDBY_IDS) return false;
  for (const id of ids) {
    const literal = cssString(id);
    if (literal === null) return false;
    // Every element with that id, in any tree: the referenced element and
    // what it holds contribute to the name.
    const referenced = page.locator(`[id=${literal}]`);
    if ((await referenced.and(contributing).or(referenced.locator(CONTRIBUTING)).count()) > 0) return false;
  }
  const id = await attribute(element, "id");
  if (id === undefined) return false;
  let labels = element.locator("xpath=ancestor::label");
  if (id !== null && id.length > 0) {
    const literal = cssString(id);
    if (literal === null) return false;
    labels = labels.or(page.locator(`label[for=${literal}]`));
  }
  if ((await labels.and(page.locator("[aria-owns]")).count()) > 0) return false;
  // A label holds the control it labels (and a select its own options,
  // which never join the select's own name); it may hold nothing else that
  // contributes.
  const inside = labels.locator(CONTRIBUTING);
  const total = await inside.count();
  return total === (await inside.and(element.or(element.locator(CONTRIBUTING))).count());
}

/// SG-000122 slice A5: marks each main-frame node of a named role whose
/// element is an input or a native select, and whose computed name is not
/// empty and can carry nothing but text (`nameIsTextOnly`), as `named`. Any
/// other node, a node inside a frame, or one past the bound or the time
/// budget, is not named, so the host sends no name for it.
export async function nameControls(page: Pick<Page, "locator">, nodes: SnapshotNode[], budgetMs = NAME_BUDGET_MS): Promise<void> {
  const deadline = Date.now() + budgetMs;
  let checked = 0;
  const visit = async (node: SnapshotNode): Promise<void> => {
    if (checked >= MAX_NAMED_CONTROLS || Date.now() > deadline) return;
    if (NAMED_ROLES.has(node.role) && /^e\d+$/.test(node.ref) && node.name.length > 0) {
      checked += 1;
      const element = page.locator(`aria-ref=${node.ref}`);
      try {
        if ((await element.and(page.locator(NAMEABLE)).count()) === 1 && (await nameIsTextOnly(page, element)) && Date.now() <= deadline) {
          node.named = true;
        }
      } catch {
        // Not named.
      }
    }
    for (const child of node.children) await visit(child);
  };
  for (const node of nodes) await visit(node);
}
