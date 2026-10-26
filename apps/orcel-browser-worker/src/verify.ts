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
// substring of an element's text, counted only when visible (the donor
// matches case-insensitively); a value is read only from an element named
// by the latest observation's ref, never from a password, one-time-code or
// payment-card field, and only up to `MAX_VERIFY_TEXT_BYTES`; the list check
// is not ported.

import type { Locator, Page } from "playwright-core";

/// Probes in one verification (mirrors the host).
export const MAX_VERIFY_PROBES = 16;
/// Longest text, name or value a probe sends or reads (mirrors the host).
export const MAX_VERIFY_TEXT_BYTES = 1024;
/// Visible matches counted at most.
export const MAX_VERIFY_COUNT = 1000;
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

/// `autocomplete` tokens that mark a field whose value is a secret.
const SECRET_AUTOCOMPLETE = /(?:^|\s)(?:current-password|new-password|one-time-code|cc-number|cc-csc|cc-exp(?:-month|-year)?)(?:\s|$)/i;

const escapeRegExp = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

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

/// The one element a ref names, or null when it names none or several.
async function byRef(page: VerifyPage, ref: string): Promise<Locator | null> {
  const locator = page.locator(`aria-ref=${ref}`);
  return (await locator.count().catch(() => 0)) === 1 ? locator : null;
}

async function isSecret(locator: Locator): Promise<boolean> {
  const type = (await locator.getAttribute("type", { timeout: READ_TIMEOUT_MS }).catch(() => null)) ?? "";
  const autocomplete = (await locator.getAttribute("autocomplete", { timeout: READ_TIMEOUT_MS }).catch(() => null)) ?? "";
  return type.trim().toLowerCase() === "password" || SECRET_AUTOCOMPLETE.test(autocomplete);
}

async function probeOne(page: VerifyPage, probe: VerifyProbe): Promise<VerifyResult> {
  switch (probe.probe) {
    case "visible_role": {
      const role = probe.role as Parameters<Page["getByRole"]>[0];
      const count = await countVisible(page.frames().map((frame) => frame.getByRole(role, { name: probe.name, exact: true })));
      return { result: "visible", count };
    }
    case "visible_text": {
      const pattern = new RegExp(escapeRegExp(probe.text));
      const count = await countVisible(page.frames().map((frame) => frame.getByText(pattern)));
      return { result: "visible", count };
    }
    case "value": {
      const locator = await byRef(page, probe.ref);
      if (!locator) return { result: "unavailable", reason: "stale" };
      if (await isSecret(locator)) return { result: "unavailable", reason: "secret" };
      let value: string;
      try {
        value = await locator.inputValue({ timeout: READ_TIMEOUT_MS });
      } catch {
        return { result: "unavailable", reason: "not_a_field" };
      }
      if (Buffer.byteLength(value, "utf8") > MAX_VERIFY_TEXT_BYTES) return { result: "unavailable", reason: "too_long" };
      return { result: "value", value };
    }
    case "checked": {
      const locator = await byRef(page, probe.ref);
      if (!locator) return { result: "unavailable", reason: "stale" };
      try {
        return { result: "checked", checked: await locator.isChecked({ timeout: READ_TIMEOUT_MS }) };
      } catch {
        return { result: "unavailable", reason: "not_a_field" };
      }
    }
  }
}

/// Runs the probes in order; one result per probe.
export async function runProbes(page: VerifyPage, probes: readonly VerifyProbe[]): Promise<VerifyResult[]> {
  const results: VerifyResult[] = [];
  for (const probe of probes) results.push(await probeOne(page, probe));
  return results;
}
