// Which refusals Orcel itself made, so a navigation failure is reported as
// Orcel's "denied" only when Orcel refused it.
//
// Orcel refuses a request with net::ERR_BLOCKED_BY_CLIENT (route.abort
// "blockedbyclient", or Fetch.failRequest "BlockedByClient" for a redirect
// hop). The engine uses the same error for its own cancellations: Edge 157's
// HTTPS auto-upgrade cancelled the http:// navigation it replaced with exactly
// this error, before #771 turned the feature off. An error code alone
// therefore does not say who refused. Every refusal point records what it
// refused here; a navigation failure is "denied" only when it matches a
// refusal recorded since the navigation began. A failure with no matching
// refusal is the engine's (or the network's) own, and is reported as
// "failed": it still fails closed, it is just not claimed as a policy denial.
//
// One ledger per engine lifetime (installRoutes creates it), holding at most
// MAX_REFUSALS entries; older entries are dropped first. A dropped entry can
// only turn a "denied" into a "failed", never the other way.

import type { Page, Request } from "playwright-core";

/// The most refusals one engine lifetime keeps.
export const MAX_REFUSALS = 256;

interface Refusal {
  seq: number;
  /// The refused URL without its fragment (which never reaches the network,
  /// and which the two event sources report differently).
  url: string;
  /// The frame whose main document was refused (an opaque identity: a
  /// Playwright Frame), or null for anything else.
  document: unknown;
}

function withoutFragment(url: string): string {
  const hash = url.indexOf("#");
  return hash < 0 ? url : url.slice(0, hash);
}

export class RefusalLedger {
  private seq = 0;
  private readonly entries: Refusal[] = [];

  /// Records one refusal Orcel made. `documentOf` is the frame whose own
  /// document request (or redirect hop) was refused, when it was one.
  record(url: string, documentOf: unknown = null): void {
    this.seq += 1;
    this.entries.push({ seq: this.seq, url: withoutFragment(url), document: documentOf });
    if (this.entries.length > MAX_REFUSALS) this.entries.shift();
  }

  /// A position to look back to: refusals recorded after it are "since".
  mark(): number {
    return this.seq;
  }

  /// Whether Orcel refused `url` after `mark`.
  refusedSince(mark: number, url: string): boolean {
    const wanted = withoutFragment(url);
    return this.entries.some((entry) => entry.seq > mark && entry.url === wanted);
  }

  /// Whether Orcel refused a document of `frame` after `mark`.
  refusedDocumentSince(mark: number, frame: unknown): boolean {
    return this.entries.some((entry) => entry.seq > mark && entry.document !== null && entry.document === frame);
  }

  get size(): number {
    return this.entries.length;
  }
}

/// The frame whose document `request` is, or null (a subresource, or a
/// service-worker request, which has no frame).
export function documentFrameOf(request: Pick<Request, "isNavigationRequest" | "frame">): unknown {
  try {
    return request.isNavigationRequest() ? request.frame() : null;
  } catch {
    return null;
  }
}

/// The page surface a watch needs (a Playwright `Page`, or a test stub).
export type WatchedPage = Pick<Page, "on" | "off" | "mainFrame">;

export interface NavigationWatch {
  /// Whether the main frame's navigation failure since the watch began was a
  /// refusal Orcel made: one of the main-frame navigation requests that
  /// failed (or, when the engine reported none, `fallbackUrl`) was refused
  /// by Orcel, or Orcel refused a document of the main frame.
  refusedByOrcel(fallbackUrl?: string): boolean;
  /// Stops listening (idempotent).
  stop(): void;
}

/// Starts watching `page`'s main-frame navigation failures against `ledger`.
export function watchNavigation(page: WatchedPage, ledger: RefusalLedger): NavigationWatch {
  const mark = ledger.mark();
  const main = page.mainFrame();
  const failed: string[] = [];
  const onFailed = (request: Request) => {
    if (failed.length < 64 && documentFrameOf(request) === main) failed.push(request.url());
  };
  page.on("requestfailed", onFailed);
  let stopped = false;
  return {
    refusedByOrcel(fallbackUrl?: string): boolean {
      const urls = failed.length > 0 ? failed : fallbackUrl === undefined ? [] : [fallbackUrl];
      return urls.some((url) => ledger.refusedSince(mark, url)) || ledger.refusedDocumentSince(mark, main);
    },
    stop(): void {
      if (stopped) return;
      stopped = true;
      page.off("requestfailed", onFailed);
    }
  };
}
