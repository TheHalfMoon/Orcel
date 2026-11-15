// SG-000122 slice A5: which main-frame form controls may show their
// accessible name to the host's caller.
//
// The name itself is the one Playwright's accessibility snapshot computed
// for the node, in Playwright's isolated (utility) world, never by page
// script. That computation follows the accessible-name rules, which pull in
// much more than text: an embedded control's value or selected option label,
// whatever an element inside a label names through aria-labelledby, a label's
// own aria-labelledby, content slotted into a shadow tree, a button's own
// label (each measured on Edge with Playwright 1.63 to carry a password
// field's value). So the check is deny-by-default: a name is passed on only
// when every element that can contribute to it (each wrapping label, each
// label for the control's id, each element aria-labelledby names) is in the
// document's own tree and holds nothing but text and a small allowlist of
// text-level elements (`TEXT_ELEMENTS`), none of which carries an attribute
// that can name, own, label, slot or edit, and none of which hosts a shadow
// tree. A wrapping label may also hold the named control itself (and a select
// its own options); a referenced element may not. A control inside a shadow
// tree, or one that owns elements, is never named. Every check uses only
// Playwright's own isolated-world locators (XPath, CSS and attribute reads).
// A control whose name cannot be shown that way carries no name.
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
/// The only elements a contributing subtree may hold besides text.
export const TEXT_ELEMENTS = ["span", "b", "i", "em", "strong", "small", "abbr", "br", "sup", "sub", "mark"];
/// What a contributing element may be itself: a label, a text element, or a
/// plain block of text that aria-labelledby names.
const ROOT_ELEMENTS = [...TEXT_ELEMENTS, "label", "div", "p", "legend", "li", "td", "th", "dt", "dd", "h1", "h2", "h3", "h4", "h5", "h6"];
/// Attributes that let an element name, label, own, slot or edit anything.
const NAMING_ATTRIBUTES = ["aria-labelledby", "aria-label", "aria-owns", "aria-describedby", "aria-details", "role", "slot", "contenteditable"];

const isAny = (tags: string[]) => tags.map((tag) => `self::${tag}`).join(" or ");
const hasAny = NAMING_ATTRIBUTES.map((name) => `@${name}`).join(" or ");
/// Relative to a contributing element: itself when it is not allowed, and
/// every element under it that is not allowed (light tree only).
export const DISALLOWED = `xpath=self::*[not(${isAny(ROOT_ELEMENTS)}) or ${hasAny}] | .//*[not(${isAny(TEXT_ELEMENTS)}) or ${hasAny}]`;

/// An XPath string literal, or null when the text holds both quote kinds or
/// a character a selector should not carry.
function xpathString(value: string): string | null {
  if (value.length === 0 || value.length > 256 || /[\u0000-\u001f\u007f-\u009f]/.test(value)) return null;
  if (!value.includes('"')) return `"${value}"`;
  if (!value.includes("'")) return `'${value}'`;
  return null;
}

async function attribute(element: Locator, name: string): Promise<string | null | undefined> {
  try {
    return await element.getAttribute(name, { timeout: READ_TIMEOUT_MS });
  } catch {
    return undefined;
  }
}

/// Whether the elements of `roots` hold only allowed content: nothing
/// disallowed but what `own` matches, and no shadow tree (Playwright's CSS
/// sees into open shadow trees, XPath does not, so the two counts differ
/// when one is there).
async function textOnly(roots: Locator, own: Locator | null): Promise<boolean> {
  const disallowed = roots.locator(DISALLOWED);
  const total = await disallowed.count();
  const allowed = own === null ? 0 : await disallowed.and(own).count();
  if (total !== allowed) return false;
  return (await roots.locator("css=*").count()) === (await roots.locator("xpath=.//*").count());
}

/// Whether `element`'s computed name can carry nothing but text (see the
/// module comment). Any failed read is "no".
export async function nameIsTextOnly(page: Pick<Page, "locator">, element: Locator): Promise<boolean> {
  // In the document's own tree (not inside a shadow tree), owning nothing.
  if ((await element.locator("xpath=ancestor::html").count()) !== 1) return false;
  const owns = await attribute(element, "aria-owns");
  if (owns !== null) return false;
  // A select's own options never join its own name; anything else inside a
  // select (a customizable select's content) withholds it.
  if ((await element.locator("xpath=.//*[not(self::option or self::optgroup)]").count()) !== 0) return false;
  const labelledby = await attribute(element, "aria-labelledby");
  if (labelledby === undefined) return false;
  const ids = (labelledby ?? "").split(/[\t\n\f\r ]+/).filter((id) => id.length > 0);
  if (ids.length > MAX_LABELLEDBY_IDS) return false;
  for (const id of ids) {
    const literal = xpathString(id);
    if (literal === null) return false;
    // Every element of the document's tree with that id; what aria-labelledby
    // names may not hold the control itself either.
    if (!(await textOnly(page.locator(`xpath=//*[@id=${literal}]`), null))) return false;
  }
  const id = await attribute(element, "id");
  if (id === undefined) return false;
  let labels = element.locator("xpath=ancestor::label");
  if (id !== null && id.length > 0) {
    const literal = xpathString(id);
    if (literal === null) return false;
    labels = labels.or(page.locator(`xpath=//label[@for=${literal}]`));
  }
  return textOnly(labels, element.or(element.locator("xpath=.//option | .//optgroup")));
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
