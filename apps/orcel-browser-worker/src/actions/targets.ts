// BR-01: resolving the element an approved action targets.

import type { Locator, Page } from "playwright-core";
import type { ApprovedTarget } from "../protocol.js";
import { NavigationError } from "../worker.js";

/// BR-04: whether a Playwright pointer action timed out because another
/// element covered the target, without the action ever being performed.
/// Read from the action's call log (playwright-core 1.63, pinned): every
/// attempt logs "attempting|retrying <action> action", a blocked attempt
/// logs "<element> intercepts pointer events", and a delivered one logs
/// "performing <action> action". So: a TimeoutError, no attempt ever
/// performed, and the last attempt blocked by interception. Lines before
/// the first attempt (which quote the page's own markup) are never read as
/// interceptions. Anything else is not an occlusion: the caller reports a
/// plain failure (after dispatch, an unknown outcome). This reads Playwright's
/// call-log format (including its "N × " compression of repeated lines);
/// a Playwright upgrade must re-check occlusion.test.ts against a real log.
export function isOcclusion(error: unknown): boolean {
  if (!(error instanceof Error) || error.name !== "TimeoutError") return false;
  // Playwright compresses repeated runs of lines as "N × <line>".
  const lines = error.message.split("\n").map((line) =>
    line
      .trim()
      .replace(/^- /, "")
      .replace(/^\d+ × /, "")
      .replace(/^- /, "")
  );
  if (lines.some((line) => /^performing \w+ action( \(trial run\))?$/.test(line))) return false;
  let last = -1;
  lines.forEach((line, at) => {
    if (/^(attempting|retrying) \w+ action( \(trial run\))?$/.test(line)) last = at;
  });
  if (last < 0) return false;
  return lines.slice(last + 1).some((line) => / intercepts pointer events$/.test(line));
}

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
