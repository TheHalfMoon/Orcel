// BR-01: resolving the element an approved action targets.

import type { Locator, Page } from "playwright-core";
import type { ApprovedTarget } from "../protocol.js";
import { NavigationError } from "../worker.js";

/// BR-04: whether a Playwright pointer action timed out because another
/// element covered the target, without the action ever being performed.
/// Read from the action's call log (playwright-core 1.63, pinned; captured
/// from a real click on a covered link in occlusion.test.ts): lines are
/// wrapped in terminal colour codes; repeated runs are compressed as
/// "N × <line>"; each attempt logs "attempting|retrying <action> action",
/// then the reason it could not act ("element is not visible", "<element>
/// intercepts pointer events", ...); a delivered one logs "performing
/// <action> action"; the log usually ends in a "waiting Nms" pause before
/// the next retry. So: a TimeoutError, no attempt ever performed, and the
/// most recent reason (after the first attempt; the lines before it quote
/// the page's own markup) an interception. Anything else is not an
/// occlusion: the caller reports a plain failure (after dispatch, an
/// unknown outcome). A Playwright upgrade must re-check the captured log.
export function isOcclusion(error: unknown): boolean {
  if (!(error instanceof Error) || error.name !== "TimeoutError") return false;
  const lines = error.message
    .replace(/\u001b\[[0-9;]*m/g, "")
    .split("\n")
    .map((line) =>
      line
        .trim()
        .replace(/^- /, "")
        .replace(/^\d+ × /, "")
        .replace(/^- /, "")
    );
  if (lines.some((line) => /^performing \w+ action( \(trial run\))?$/.test(line))) return false;
  const first = lines.findIndex((line) => /^(attempting|retrying) \w+ action( \(trial run\))?$/.test(line));
  if (first < 0) return false;
  // Reasons only: a re-resolved target ("locator resolved to <its own
  // markup>") is page text, and an interception line names the covering
  // element's markup first. An attempt that times out still waiting to
  // settle logs no reason of its own, so an earlier interception decides:
  // nothing was performed either way.
  const intercepted = (line: string) => line.startsWith("<") && / intercepts pointer events$/.test(line);
  const reasons = lines
    .slice(first + 1)
    .filter((line) => !line.startsWith("locator resolved to"))
    .filter(
      (line) =>
        intercepted(line) ||
        /^element is not /.test(line) ||
        /^element is outside of the viewport/.test(line) ||
        /^element was detached/.test(line)
    );
  const latest = reasons.at(-1);
  return latest !== undefined && intercepted(latest);
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
