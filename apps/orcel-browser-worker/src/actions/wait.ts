// BR-02: a bounded wait for text to appear or disappear on the primary
// page. Read-only: it acts on nothing and needs no approval.
//
// Adapted from microsoft/playwright at commit
// 1b025d7e20a026371cd5f98ba0cdce48892737c8,
// `packages/playwright-core/src/tools/backend/wait.ts` (blob
// 11aa2a8d5e29a5591b808b495e6fb0a202a08aea): `browser_wait_for`. Apache License
// 2.0, Copyright (c) Microsoft Corporation; notice in
// docs/orcel/notices/playwright-Apache-2.0.txt. Modifications for Orcel: one
// text per wait, matched as BR-07 matches visible text (case-sensitive,
// white space normalised); the main frame only; bounded to
// `MAX_WAIT_MS`; the outcome is reported (met or not), never thrown; the
// donor's plain time wait is not ported (the host can wait itself).

import type { Page } from "playwright-core";
import { textPattern } from "../verify.js";

/// The longest wait (mirrors the host), under its reply deadline.
export const MAX_WAIT_MS = 8_000;

export type WaitPage = Pick<Page, "getByText">;

/// Whether `text` became visible (`appear`) or stopped being visible within
/// `timeoutMs`.
export async function waitForText(page: WaitPage, text: string, appear: boolean, timeoutMs: number): Promise<boolean> {
  const locator = page.getByText(textPattern(text)).first();
  try {
    await locator.waitFor({ state: appear ? "visible" : "hidden", timeout: Math.min(timeoutMs, MAX_WAIT_MS) });
    return true;
  } catch {
    return false;
  }
}
