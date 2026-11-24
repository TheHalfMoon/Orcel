// Why a navigation failed, and the one line on stderr that says where (#438,
// #584): fixed stage names, milliseconds and an engine error code, never a URL
// or page content.

import { netErrorCode, probeBrowser, traceLine, traceMark, type ProbeSession } from "./navigation-trace.js";

/// What the page that failed to navigate is asked.
export interface FailedPage {
  /// Whether Orcel itself refused the document.
  refusedByOrcel(): boolean;
  closed(): boolean;
  /// Opens a CDP session for the probe (`probeBrowser`).
  attach(): Promise<ProbeSession>;
}

/// The typed reason for `error`, what `page.goto` threw.
export async function gotoFailure(
  error: unknown,
  page: FailedPage,
  write: (line: string) => void = (line) => void process.stderr.write(line)
): Promise<"denied" | "timeout" | "failed"> {
  const message = String((error as Error).message);
  // The engine reports its own cancellations with the same error as
  // Orcel's refusals: "denied" only for a refusal Orcel made. Anything
  // else falls through to "failed" below (logged with its error code).
  if (message.includes("ERR_BLOCKED_BY_CLIENT")) {
    if (page.refusedByOrcel()) return "denied";
    traceMark("blocked_not_by_orcel");
  }
  if ((error as Error).name === "TimeoutError") {
    // #438: where it stalled, for the host's failure diagnostics. #584: and whether
    // the engine's browser process answers. The renderer is not asked: while a
    // navigation is pending it answers nothing even when healthy.
    for (const mark of await probeBrowser(() => page.attach())) traceMark(mark);
    traceMark(`page_closed_${page.closed()}`);
    write(`orcel-browser-worker: ${traceLine()}\n`);
    return "timeout";
  }
  // #584: why the engine gave up, which "failed" alone doesn't say.
  write(`orcel-browser-worker: goto failed ${netErrorCode(message)} ${traceLine()}\n`);
  return "failed";
}
