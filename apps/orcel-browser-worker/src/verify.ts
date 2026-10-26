// BR-07: read-only probes behind the host's postcondition verifier. The
// worker only counts and reads; the host decides pass or fail, records the
// evidence, and never forwards a field's value.
//
// Adapted from microsoft/playwright at commit
// 1b025d7e20a026371cd5f98ba0cdce48892737c8,
// `packages/playwright-core/src/tools/backend/verify.ts` (blob
// a27eb72ef5ad80ae654c8dac975db1542ee97071): `browser_verify_element_visible`,
// `browser_verify_text_visible` and `browser_verify_value`. Apache License
// 2.0, Copyright (c) Microsoft Corporation. Modifications for Orcel: the
// probes return observations (a count of visible matches, a value, a
// checked state) and never a verdict; an element is matched by its exact
// role and accessible name and counted only when visible (the donor counts
// any match, then asserts visibility separately); text is a case-sensitive
// substring of an element's text with runs of white space matching any
// white space, counted only when visible (the donor matches
// case-insensitively); a value or checked state is read only from the
// element a main-frame ref names, and only when that element is itself a
// form control (Playwright's value and checked reads otherwise follow a
// label to its control, which could be a password field); never from a
// field that looks secret (a password type, a secret `autocomplete` token,
// or a name or id such as password, pin, otp, cvc); values are bounded; all
// probes together must finish within `VERIFY_BUDGET_MS`, under the host's
// reply deadline; the list check is not ported. Known limit: a field masked
// only by CSS (`-webkit-text-security`) with an innocuous name is not
// recognised as secret; the host bounds how many values a field can be
// checked against, so such a field cannot be guessed.

import type { Locator, Page } from "playwright-core";

/// Probes in one verification (mirrors the host).
export const MAX_VERIFY_PROBES = 16;
/// Longest text, name or value a probe sends or reads (mirrors the host).
export const MAX_VERIFY_TEXT_BYTES = 1024;
/// Visible matches counted at most.
export const MAX_VERIFY_COUNT = 1000;
/// All probes of one verification, under the host's 10-second reply bound.
export const VERIFY_BUDGET_MS = 6_000;
const READ_TIMEOUT_MS = 1_000;

export type VerifyProbe =
  | { probe: "visible_role"; role: string; name: string }
  | { probe: "visible_text"; text: string }
  | { probe: "value"; ref: string }
  | { probe: "checked"; ref: string };

export type VerifyUnavailable = "stale" | "secret" | "not_a_field" | "too_long";

export type VerifyResult =
  | { result: "visible"; count: number }
  | { result: "value"; value: string }
  | { result: "checked"; checked: boolean }
  | { result: "unavailable"; reason: VerifyUnavailable };

/// The page surface the probes use (a Playwright `Page`, or a test stub).
export type VerifyPage = Pick<Page, "locator" | "frames">;

/// Elements whose own value can be read (no label is followed).
const VALUE_FIELD = "input, textarea, select";
/// Elements whose own checked state can be read.
/// (Playwright reads these without following a label; a switch or menu item
/// inside a label would be read through the label's control.)
const CHECKED_FIELD = 'input[type="checkbox" i], input[type="radio" i], [role="checkbox"], [role="radio"]';
/// `autocomplete` tokens that mark a field whose value is a secret.
const SECRET_AUTOCOMPLETE = /(?:^|\s)(?:current-password|new-password|one-time-code|cc-number|cc-csc|cc-exp(?:-month|-year)?)(?:\s|$)/i;
/// Names and ids that suggest a secret.
const SECRET_NAME = /pass(?:word|code|phrase)?|pwd|(?:^|[^a-z])pin(?:$|[^a-z])|pin[_-]?code|otp|one[_-]?time|cvc|cvv|csc|security[_-]?code|card[_-]?number|secret|token/i;
/// Camel-case `Pin` (`userPin`, `cardPinCode`).
const SECRET_CAMEL = /[a-z]Pin(?:$|[A-Z_-])/;

const escapeRegExp = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/// `text` as a case-sensitive pattern in which any run of white space
/// matches any run of white space (as the page's text may wrap).
export function textPattern(text: string): RegExp {
  const words = text.trim().split(/\s+/).filter(Boolean).map(escapeRegExp);
  return new RegExp(words.join("\\s+"));
}

async function countVisible(locators: Locator[]): Promise<number> {
  let total = 0;
  for (const locator of locators) {
    total += await locator
      .filter({ visible: true })
      .count()
      .catch(() => 0);
    if (total >= MAX_VERIFY_COUNT) return MAX_VERIFY_COUNT;
  }
  return total;
}

/// The form control a main-frame ref names: "stale" when the ref names no
/// element or several, "not_a_field" when the element is not itself a
/// control of `kind`.
async function field(page: VerifyPage, ref: string, kind: string): Promise<Locator | VerifyUnavailable> {
  if (!/^e\d+$/.test(ref)) return "not_a_field";
  const named = page.locator(`aria-ref=${ref}`);
  if ((await named.count().catch(() => 0)) !== 1) return "stale";
  const control = named.and(page.locator(kind));
  return (await control.count().catch(() => 0)) === 1 ? control : "not_a_field";
}

/// Whether a form control looks secret (its type, `autocomplete`, name or
/// id): its value is never read, and it is never filled (BR-02).
export async function isSecretField(control: Locator): Promise<boolean> {
  // A read that fails counts as secret (fail closed); an absent attribute
  // reads as empty.
  const UNREADABLE = Symbol("unreadable");
  const read = async (name: string): Promise<string | typeof UNREADABLE> => {
    try {
      return ((await control.getAttribute(name, { timeout: READ_TIMEOUT_MS })) ?? "").trim();
    } catch {
      return UNREADABLE;
    }
  };
  const values = [await read("type"), await read("autocomplete"), await read("name"), await read("id")];
  if (values.some((value) => value === UNREADABLE)) return true;
  const [type, autocomplete, name, id] = values as string[];
  if (type!.toLowerCase() === "password") return true;
  if (SECRET_AUTOCOMPLETE.test(autocomplete!)) return true;
  return [name!, id!].some((text) => SECRET_NAME.test(text) || SECRET_CAMEL.test(text));
}

async function probeOne(page: VerifyPage, probe: VerifyProbe): Promise<VerifyResult> {
  switch (probe.probe) {
    case "visible_role": {
      const role = probe.role as Parameters<Page["getByRole"]>[0];
      const count = await countVisible(page.frames().map((frame) => frame.getByRole(role, { name: probe.name, exact: true })));
      return { result: "visible", count };
    }
    case "visible_text": {
      const pattern = textPattern(probe.text);
      const count = await countVisible(page.frames().map((frame) => frame.getByText(pattern)));
      return { result: "visible", count };
    }
    case "value": {
      const control = await field(page, probe.ref, VALUE_FIELD);
      if (typeof control === "string") return { result: "unavailable", reason: control };
      if (await isSecretField(control)) return { result: "unavailable", reason: "secret" };
      let value: string;
      try {
        value = await control.inputValue({ timeout: READ_TIMEOUT_MS });
      } catch {
        return { result: "unavailable", reason: "not_a_field" };
      }
      if (Buffer.byteLength(value, "utf8") > MAX_VERIFY_TEXT_BYTES) return { result: "unavailable", reason: "too_long" };
      return { result: "value", value };
    }
    case "checked": {
      const control = await field(page, probe.ref, CHECKED_FIELD);
      if (typeof control === "string") return { result: "unavailable", reason: control };
      try {
        return { result: "checked", checked: await control.isChecked({ timeout: READ_TIMEOUT_MS }) };
      } catch {
        return { result: "unavailable", reason: "not_a_field" };
      }
    }
  }
}

/// Runs the probes in order; one result per probe. Rejects when they do not
/// all finish within `budgetMs`.
export async function runProbes(page: VerifyPage, probes: readonly VerifyProbe[], budgetMs = VERIFY_BUDGET_MS): Promise<VerifyResult[]> {
  let timer: NodeJS.Timeout | undefined;
  const late = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("verification budget exceeded")), budgetMs);
  });
  let cancelled = false;
  const work = (async () => {
    const results: VerifyResult[] = [];
    for (const probe of probes) {
      // Past the budget, the remaining probes are not run.
      if (cancelled) throw new Error("verification budget exceeded");
      results.push(await probeOne(page, probe));
    }
    return results;
  })();
  // A rejection after the budget won must not go unhandled.
  work.catch(() => {});
  try {
    return await Promise.race([work, late]);
  } finally {
    cancelled = true;
    clearTimeout(timer);
  }
}
