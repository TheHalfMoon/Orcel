// SG-000135 OB-03: the tabs of one engine lifetime.
//
// A lifetime has several pages ("tabs"), each with a worker-issued tab id;
// one is active, and every existing action (navigate, observe, verify, form
// actions, extract, screenshot) acts on the active tab's page. A host
// navigation still runs in a fresh page (entry.ts), which replaces the
// tab's page and keeps its id. The host opens, switches and closes tabs; a
// page the page itself opened (a popup) becomes a tab only once its first
// document was admitted by the host's SG-000075 rules (the route stack
// already decides every request; `admitPopup` waits for the outcome), and
// only while the lifetime is under its tab cap. Anything else is closed.

/// The most tabs one lifetime holds (mirrors the host and orceld).
export const MAX_TABS = 8;
/// How long a popup's first document may take before it is closed.
export const POPUP_ADMISSION_MS = 10_000;
/// The most popups waiting for admission at once; any further popup is
/// closed at once.
export const MAX_PENDING_POPUPS = 4;
/// A page-initiated navigation counts as in flight for at most this long.
export const NAVIGATION_WATCH_MS = 30_000;

/// What a tab report carries: its id and the page's URL (bounded; empty
/// when longer than the bound or not a document URL).
export interface TabInfo {
  tab: number;
  url: string;
}

/// The page surface the registry reads.
export interface TabPage {
  url(): string;
  isClosed(): boolean;
}

export class TabRegistry<P extends TabPage> {
  private readonly pages = new Map<number, P>();
  private nextId = 1;
  private activeId: number | null = null;

  constructor(private readonly maxUrlBytes: number) {}

  /// Register `page` as a new tab; null when the lifetime is at its cap.
  add(page: P): number | null {
    if (this.pages.size >= MAX_TABS) return null;
    const id = this.nextId++;
    this.pages.set(id, page);
    if (this.activeId === null) this.activeId = id;
    return id;
  }

  get size(): number {
    return this.pages.size;
  }

  get active(): number | null {
    return this.activeId;
  }

  /// The active tab's page.
  activePage(): P | null {
    return this.activeId === null ? null : (this.pages.get(this.activeId) ?? null);
  }

  page(id: number): P | null {
    return this.pages.get(id) ?? null;
  }

  idOf(page: P): number | null {
    for (const [id, held] of this.pages) if (held === page) return id;
    return null;
  }

  /// Make `id` the active tab; false when there is no such tab.
  activate(id: number): boolean {
    if (!this.pages.has(id)) return false;
    this.activeId = id;
    return true;
  }

  /// A navigation's fresh page takes over tab `id`.
  replace(id: number, page: P): boolean {
    if (!this.pages.has(id)) return false;
    this.pages.set(id, page);
    return true;
  }

  /// Drop tab `id` at the host's request. When it was active, the most
  /// recently opened remaining tab becomes active (or none); the host learns
  /// that from its reply.
  remove(id: number): boolean {
    if (!this.pages.delete(id)) return false;
    if (this.activeId === id) {
      const remaining = [...this.pages.keys()];
      this.activeId = remaining.length > 0 ? Math.max(...remaining) : null;
    }
    return true;
  }

  /// Drop tab `id` because its page went away by itself (window.close, a
  /// crash). No tab becomes active: the host has not been told, so every
  /// action fails until the host sends a tab request and learns the tabs.
  /// Another tab silently taking its place would let an action approved on
  /// one page land on another.
  dropClosed(id: number): boolean {
    if (!this.pages.delete(id)) return false;
    if (this.activeId === id) this.activeId = null;
    return true;
  }

  /// Every tab in id order, with its page's URL (bounded).
  list(): TabInfo[] {
    return [...this.pages.entries()]
      .sort(([a], [b]) => a - b)
      .map(([tab, page]) => ({ tab, url: boundedUrl(page.isClosed() ? "" : page.url(), this.maxUrlBytes) }));
  }
}

/// `url` when it is an https or about:blank URL within `maxBytes` and free
/// of control characters; otherwise empty.
export function boundedUrl(url: string, maxBytes: number): string {
  if (Buffer.byteLength(url, "utf8") > maxBytes || /[\u0000-\u001f\u007f]/.test(url)) return "";
  return url.startsWith("https://") || url === "about:blank" ? url : "";
}

/// The events of a page the watchers read (a Playwright `Page`, or a stub).
export interface WatchedRequest {
  isNavigationRequest(): boolean;
  frame(): unknown;
  url(): string;
}
export interface WatchedResponse {
  request(): WatchedRequest;
  url(): string;
  status(): number;
}
export interface WatchedPage {
  mainFrame(): unknown;
  on(event: "request" | "requestfailed", listener: (request: WatchedRequest) => void): unknown;
  on(event: "response", listener: (response: WatchedResponse) => void): unknown;
  on(event: "load" | "domcontentloaded" | "close", listener: () => void): unknown;
  off(event: "requestfailed", listener: (request: WatchedRequest) => void): unknown;
  off(event: "response", listener: (response: WatchedResponse) => void): unknown;
  off(event: "close", listener: () => void): unknown;
}

function isMainDocument(page: WatchedPage, request: WatchedRequest): boolean {
  return request.isNavigationRequest() && request.frame() === page.mainFrame();
}

/// Whether a main-frame navigation of `page` is in flight: started and not
/// yet loaded or failed (a screenshot is refused meanwhile). A navigation
/// that never settles stops counting after NAVIGATION_WATCH_MS.
export class NavigationWatch {
  private since: number | null = null;

  constructor(page: WatchedPage, private readonly now: () => number = Date.now) {
    page.on("request", (request: WatchedRequest) => {
      if (isMainDocument(page, request)) this.since = this.now();
    });
    page.on("requestfailed", (request: WatchedRequest) => {
      if (isMainDocument(page, request)) this.since = null;
    });
    const settled = () => {
      this.since = null;
    };
    page.on("domcontentloaded", settled);
    page.on("load", settled);
  }

  get loading(): boolean {
    return this.since !== null && this.now() - this.since < NAVIGATION_WATCH_MS;
  }
}

/// Wait for a popup's first main-frame document: true once one was
/// admitted (the host allowed its request and an https response arrived),
/// false when it was refused, failed, closed, is not an https document, or
/// nothing arrived within `timeoutMs`.
export function admitPopup(page: WatchedPage, timeoutMs: number = POPUP_ADMISSION_MS): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    let done = false;
    const finish = (admitted: boolean) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      page.off("response", onResponse);
      page.off("requestfailed", onFailed);
      page.off("close", onClose);
      resolve(admitted);
    };
    const onResponse = (response: WatchedResponse) => {
      // A redirect hop is not the document: its next hop is decided first.
      if (!isMainDocument(page, response.request()) || (response.status() >= 300 && response.status() < 400)) return;
      finish(response.url().startsWith("https://"));
    };
    const onFailed = (request: WatchedRequest) => {
      if (isMainDocument(page, request)) finish(false);
    };
    const onClose = () => finish(false);
    const timer = setTimeout(() => finish(false), timeoutMs);
    page.on("response", onResponse);
    page.on("requestfailed", onFailed);
    page.on("close", onClose);
  });
}
