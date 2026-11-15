// SG-000108 slice 3a: classify each engine request for the host's
// navigation policy. The worker never decides: it describes the request
// (kind, URL, requesting origin) and applies the host's answer.

export type RouteKind = "document" | "redirect" | "frame" | "popup" | "fetch" | "subresource" | "service_worker";

export interface RouteQuery {
  kind: RouteKind;
  url: string;
  /// The requesting context's origin; empty for a top-level document.
  origin: string;
  /// What the request carries besides its URL (the host checks an approved
  /// form submission against it). Absent means a GET with no body.
  detail?: RequestDetail;
  /// SG-000122 A6: set (true) only on a redirect hop of the primary page's
  /// main-frame document, so the host can tell an approved Enter's own
  /// redirect from a subresource's, a frame's or a popup's. Absent means
  /// not the document.
  mainDocument?: true;
}

/// SG-000122 A6: the query for one redirect hop the CDP guard paused.
/// `primary` says whether the guard's page is the page the host navigates;
/// only a `Document` hop of that page's main frame is the main document.
export function redirectHop(
  url: string,
  from: string,
  resourceType: string,
  frameId: string,
  mainFrameId: string,
  primary: boolean
): RouteQuery {
  const query: RouteQuery = { kind: "redirect", url, origin: originOf(from) };
  if (primary && resourceType === "Document" && mainFrameId !== "" && frameId === mainFrameId) query.mainDocument = true;
  return query;
}

export interface RequestDetail {
  /// Upper-case HTTP method.
  method: string;
  contentType: string;
  /// The body, only when it is a URL-encoded form of printable ASCII within
  /// MAX_ROUTE_BODY_BYTES; otherwise null (the host then refuses it as a
  /// submission).
  body: string | null;
  bodyBytes: number;
}

/// Upper bound on a request body described to the host.
export const MAX_ROUTE_BODY_BYTES = 16 * 1024;

/// The parts of a Playwright request `requestDetail` reads.
export interface RequestBodyLike {
  method(): string;
  headers(): Record<string, string>;
  postDataBuffer(): Buffer | null;
}

/// Describe a request's method and body for the host.
export function requestDetail(request: RequestBodyLike): RequestDetail {
  const method = request.method().toUpperCase().slice(0, 16);
  const contentType = (request.headers()["content-type"] ?? "").slice(0, 256);
  const buffer = request.postDataBuffer();
  const bodyBytes = buffer?.length ?? 0;
  let body: string | null = null;
  const urlencoded = contentType.split(";")[0]?.trim().toLowerCase() === "application/x-www-form-urlencoded";
  if (buffer && urlencoded && bodyBytes <= MAX_ROUTE_BODY_BYTES && buffer.every((byte) => byte >= 0x20 && byte < 0x7f)) {
    body = buffer.toString("ascii");
  } else if (!buffer) {
    body = "";
  }
  return { method, contentType: /^[\x20-\x7e]*$/.test(contentType) ? contentType : "", body, bodyBytes };
}

/// The subset of Playwright's Request and Frame this module reads, so it can
/// be tested without an engine.
export interface FrameLike {
  url(): string;
  parentFrame(): FrameLike | null;
  page(): unknown;
}

export interface RequestLike {
  url(): string;
  resourceType(): string;
  isNavigationRequest(): boolean;
  redirectedFrom(): RequestLike | null;
  serviceWorker(): unknown;
  frame(): FrameLike;
}

/// `https://host[:port]` for an http(s) URL, otherwise empty.
export function originOf(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.origin : "";
  } catch {
    return "";
  }
}

/// Describe a request. `primary` is the page the host navigates; any other
/// page is a popup, whose origin is that of the primary page (its opener).
export function classifyRequest(request: RequestLike, primary: unknown, primaryUrl: () => string): RouteQuery {
  const url = request.url();
  if (request.serviceWorker()) {
    return { kind: "service_worker", url, origin: originOf(url) };
  }
  const frame = request.frame();
  if (request.isNavigationRequest()) {
    const redirected = request.redirectedFrom();
    if (redirected) {
      // SG-000122 A6: the primary page's own main-frame document says so.
      const main = frame.parentFrame() === null && frame.page() === primary;
      return main
        ? { kind: "redirect", url, origin: originOf(redirected.url()), mainDocument: true }
        : { kind: "redirect", url, origin: originOf(redirected.url()) };
    }
    const parent = frame.parentFrame();
    if (parent) return { kind: "frame", url, origin: originOf(parent.url()) };
    if (frame.page() !== primary) return { kind: "popup", url, origin: originOf(primaryUrl()) };
    return { kind: "document", url, origin: "" };
  }
  const type = request.resourceType();
  const kind: RouteKind = type === "fetch" || type === "xhr" ? "fetch" : "subresource";
  return { kind, url, origin: originOf(frame.url()) };
}
