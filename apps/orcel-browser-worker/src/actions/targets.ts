// BR-01: resolving the element an approved action targets.

import type { Locator, Page } from "playwright-core";
import type { ApprovedTarget } from "../protocol.js";
import { NavigationError } from "../worker.js";

/// The page surface `approvedElement` uses (a Playwright `Page`, or a test
/// stub).
export type TargetPage = Pick<Page, "locator" | "mainFrame">;

/// BR-01: the approved element. Its snapshot ref when that still names an
/// element; otherwise, after a re-render replaced it, the one element in
/// the main frame whose role and accessible name equal the approved ones
/// (Playwright's role locator with an exact name, which reads the
/// accessibility tree and runs no page script). Anything else (a ref inside
/// a frame, no approved target, no match or several) is stale and nothing
/// is clicked. The host still confines the click's navigation or download
/// to the approved destination.
export async function approvedElement(page: TargetPage, ref: string, target?: ApprovedTarget): Promise<Locator> {
  const byRef = page.locator(`aria-ref=${ref}`);
  if ((await byRef.count().catch(() => 0)) === 1) return byRef;
  if (!target || !/^e\d+$/.test(ref) || target.name.length === 0) throw new NavigationError("stale");
  const byRole = page
    .mainFrame()
    .getByRole(target.role as Parameters<Page["getByRole"]>[0], { name: target.name, exact: true });
  if ((await byRole.count().catch(() => 0)) !== 1) throw new NavigationError("stale");
  return byRole;
}

