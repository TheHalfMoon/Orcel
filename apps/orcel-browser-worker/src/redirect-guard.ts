// SG-000108 slice 3a/3d: host decisions for redirect hops, and inert
// capture of an approved download.
//
// Playwright's routes see only the first request of a navigation; Chromium
// follows redirects internally without calling them (measured: a
// cross-origin hop to another admitted name went out unasked). The CDP Fetch
// domain does pause every redirect hop at the request stage, marked with
// `redirectedRequestId`, so each page gets a Fetch session that forwards
// exactly those hops to the host as `redirect` queries and passes every
// other request through to the route stack (which asks the host itself).
//
// Slice 3d: headless Edge renders a PDF navigation in its built-in viewer
// (no download event, and the navigation response body is the viewer's
// wrapper page; both measured). While the host asks for a download, the
// guard also pauses the next main-frame document at the response stage,
// takes the original bytes with Fetch.getResponseBody (no new request), and
// fulfils the navigation with an inert blank page, so the document is never
// rendered.

import type { BrowserContext, CDPSession, Page } from "playwright-core";
import { redirectHop } from "./routing.js";
import type { RoutePolicy } from "./worker.js";

/// Upper bound on a captured document (mirrors the host's transfer bound).
export const MAX_CAPTURE_BYTES = 8 * 1024 * 1024;

interface RequestPaused {
  requestId: string;
  request: { url: string };
  resourceType: string;
  frameId: string;
  redirectedRequestId?: string;
  responseStatusCode?: number;
  responseHeaders?: Array<{ name: string; value: string }>;
}

export interface CapturedDocument {
  url: string;
  status: number;
  media: string;
  disposition: string;
  body: Buffer;
}

export interface RedirectGuard {
  /// Capture the next main-frame document response of this page instead of
  /// rendering it. Resolves with the original bytes; rejects on timeout or
  /// an oversized body. Only one capture at a time.
  captureNextDocument(timeoutMs: number): Promise<CapturedDocument>;
}

const REQUEST_STAGE = [{ urlPattern: "*", requestStage: "Request" as const }];
const WITH_DOCUMENT_RESPONSES = [
  ...REQUEST_STAGE,
  { urlPattern: "*", resourceType: "Document" as const, requestStage: "Response" as const }
];

export async function attachRedirectGuard(
  context: BrowserContext,
  page: Page,
  policy: RoutePolicy,
  isPrimary: () => boolean = () => false
): Promise<RedirectGuard> {
  const session: CDPSession = await context.newCDPSession(page);
  // Interception ids of earlier hops map to their URLs, so each hop's
  // requesting origin is the origin of the response that redirected it.
  const urls = new Map<string, string>();
  let capture: { resolve: (doc: CapturedDocument) => void; reject: (error: Error) => void } | null = null;
  // Set once a capture gave up (timeout): any later main-frame document of
  // this page is failed rather than rendered.
  let spent = false;

  const fail = (requestId: string): Promise<unknown> =>
    session.send("Fetch.failRequest", { requestId, errorReason: "BlockedByClient" }).catch(() => {});

  // Read the paused response body as a stream in bounded chunks, so an
  // oversized body (even without a content-length) is never held whole.
  const boundedBody = async (requestId: string): Promise<Buffer> => {
    const { stream } = (await session.send("Fetch.takeResponseBodyAsStream", { requestId })) as { stream: string };
    const chunks: Buffer[] = [];
    let total = 0;
    try {
      for (;;) {
        const chunk = (await session.send("IO.read", { handle: stream, size: 64 * 1024 })) as {
          data: string;
          base64Encoded?: boolean;
          eof: boolean;
        };
        const bytes = Buffer.from(chunk.data, chunk.base64Encoded ? "base64" : "utf8");
        total += bytes.length;
        if (total > MAX_CAPTURE_BYTES) throw new Error("oversized");
        chunks.push(bytes);
        if (chunk.eof) return Buffer.concat(chunks);
      }
    } finally {
      await session.send("IO.close", { handle: stream }).catch(() => {});
    }
  };

  const onResponse = async (event: RequestPaused): Promise<void> => {
    const { requestId } = event;
    const pending = capture;
    if (event.frameId !== mainFrame) {
      // Only the main frame's document is captured; anything else (an
      // iframe racing the capture) continues untouched.
      await session.send("Fetch.continueRequest", { requestId });
      return;
    }
    if (!pending) {
      if (spent) await fail(requestId);
      else await session.send("Fetch.continueRequest", { requestId });
      return;
    }
    capture = null;
    const header = (name: string): string =>
      event.responseHeaders?.find((h) => h.name.toLowerCase() === name)?.value ?? "";
    const status = event.responseStatusCode ?? 0;
    try {
      // Redirects are not followed: the approved document is exactly the
      // link the host approved.
      if (status < 200 || status >= 300) throw new Error("status");
      const declared = Number(header("content-length"));
      if (Number.isFinite(declared) && declared > MAX_CAPTURE_BYTES) throw new Error("oversized");
      const body = await boundedBody(requestId);
      pending.resolve({
        url: event.request.url,
        status,
        media: header("content-type"),
        disposition: header("content-disposition"),
        body
      });
    } catch (error) {
      pending.reject(error as Error);
    } finally {
      // The document is never rendered: an inert blank page replaces it
      // (or, if that fails, the request fails), and response-stage pausing
      // ends either way.
      try {
        await session.send("Fetch.fulfillRequest", {
          requestId,
          responseCode: 200,
          responseHeaders: [{ name: "content-type", value: "text/plain" }],
          body: ""
        });
      } catch {
        await fail(requestId);
      }
      await session.send("Fetch.enable", { patterns: REQUEST_STAGE }).catch(() => {});
    }
  };

  // SG-000122 A6: the main frame's id, once known (a hop paused before it
  // is known is not marked as the main document).
  let mainFrameId = "";
  session.on("Fetch.requestPaused", (event: RequestPaused) => {
    void (async () => {
      const { requestId } = event;
      const url = event.request.url;
      try {
        if (event.responseStatusCode !== undefined) {
          await onResponse(event);
          return;
        }
        if (urls.size > 512) urls.clear();
        urls.set(requestId, url);
        if (event.redirectedRequestId === undefined) {
          await session.send("Fetch.continueRequest", { requestId });
          return;
        }
        const from = urls.get(event.redirectedRequestId) ?? "";
        let allow = false;
        try {
          allow = await policy.decide(redirectHop(url, from, event.resourceType, event.frameId, mainFrameId, isPrimary()));
        } catch {
          allow = false;
        }
        if (allow) await session.send("Fetch.continueRequest", { requestId });
        else await session.send("Fetch.failRequest", { requestId, errorReason: "BlockedByClient" });
      } catch {
        // The target went away; nothing is left to decide.
      }
    })();
  });
  const tree = (await session.send("Page.getFrameTree")) as { frameTree: { frame: { id: string } } };
  const mainFrame = tree.frameTree.frame.id;
  mainFrameId = mainFrame;
  // Speculation-rules prerendering loads pages in hidden targets that
  // neither routes nor this guard see; the seeded profile preference stops
  // it, and this per-page switch stays as a second layer.
  await session.send("Page.setPrerenderingAllowed", { isAllowed: false });
  await session.send("Fetch.enable", { patterns: REQUEST_STAGE });

  return {
    async captureNextDocument(timeoutMs: number): Promise<CapturedDocument> {
      if (capture || spent) throw new Error("a capture is already armed or spent");
      const captured = new Promise<CapturedDocument>((resolve, reject) => {
        capture = { resolve, reject };
      });
      await session.send("Fetch.enable", { patterns: WITH_DOCUMENT_RESPONSES });
      let timer: NodeJS.Timeout | undefined;
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error("capture timed out"), { name: "TimeoutError" })), timeoutMs);
      });
      try {
        return await Promise.race([captured, timeout]);
      } finally {
        clearTimeout(timer);
        if (capture) {
          // Gave up: from now on this page's main-frame documents are
          // failed, never rendered (the worker closes the page).
          spent = true;
          capture = null;
          await session.send("Fetch.enable", { patterns: REQUEST_STAGE }).catch(() => {});
        }
      }
    }
  };
}
