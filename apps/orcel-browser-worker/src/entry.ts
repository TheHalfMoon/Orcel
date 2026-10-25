// SG-000108 worker: stdio framing around `Worker`, with the engine launched
// by playwright-core exactly as the host specified. Loaded by main.js only
// after the resolve guard is installed.
//
// stdout carries frames only: the global console is replaced by one whose
// every method writes to stderr, so no library output can corrupt the channel.

import { Console } from "node:console";
import { existsSync, writeFileSync } from "node:fs";
import { chromium, type Locator, type Page } from "playwright-core";
import { refusedWorkerVariables, startupRefusal } from "./environment.js";
import { safeText } from "./extract/clean.js";
import { encodeFrame, FETCH_TEXT_MEDIA, FrameDecoder, MAX_EXTRACT_PIECES, MAX_FETCH_TEXT_BYTES, MAX_FRAME_BYTES, MAX_PIECE_BYTES, ProtocolViolation, type ApprovedTarget, type ExecField, type WorkerFrame } from "./protocol.js";
import { CONTENT_STYLES, EXTRACT_DEFAULTS, extractMarkdown } from "./extract/index.js";
import type { LayoutSnapshot } from "./extract/model.js";
import { toPieces } from "./extract/pieces.js";
import { installRoutes } from "./routes.js";
import { boundSnapshot } from "./snapshot.js";
import { discoverDeclarativeTools, DISCOVERY_BUDGET_MS } from "./webmcp/declarative.js";
import { CAPTURE_TIMEOUT_MS, DISCOVERY_TOTAL_MS, fitTools } from "./webmcp/fit.js";
import { captureWithin } from "./webmcp/capture.js";
import { fitBlocks, MAX_RESULT_BLOCKS, structuredData } from "./webmcp/structured.js";
import { documentModel, type CapturedSnapshot } from "./webmcp/dom-snapshot.js";
import { NavigationError, Worker, type EngineSession, type Launcher, type LaunchSpec, type RoutePolicy } from "./worker.js";

const startup = startupRefusal(process.execArgv, process.version);
if (startup !== null) {
  process.stderr.write(`orcel-browser-worker: refused to start: ${startup}\n`);
  process.exit(2);
}
const refused = refusedWorkerVariables(process.env);
if (refused.length > 0) {
  process.stderr.write(`orcel-browser-worker: refused environment variables: ${refused.join(", ")}\n`);
  process.exit(2);
}

globalThis.console = new Console({ stdout: process.stderr, stderr: process.stderr });

const playwrightLauncher: Launcher = {
  async launch(spec: LaunchSpec, policy: RoutePolicy): Promise<EngineSession> {
    // `ignoreDefaultArgs: true` keeps Playwright from adding any flag: the
    // engine receives exactly the host-built argv (which already carries the
    // profile, the pipe, and the blank page).
    const context = await chromium.launchPersistentContext(spec.profile_dir, {
      executablePath: spec.engine,
      ignoreDefaultArgs: true,
      args: spec.argv,
      env: spec.env,
      headless: true,
      // Downloads never happen through the engine: an approved document is
      // captured by the redirect guard instead (slice 3d).
      acceptDownloads: false,
      // "allow" keeps service-worker requests visible to routing; the
      // route stack refuses every registration (#301).
      serviceWorkers: "allow",
      handleSIGINT: false,
      handleSIGTERM: false,
      handleSIGHUP: false,
      timeout: 30_000
    });
    // Each host navigation runs in a fresh page: Chromium can commit an
    // earlier refused navigation's error page late (even more than once),
    // which would interrupt a navigation in the same page. The previous
    // page is closed once the new one has its redirect guard.
    let primary: Page = context.pages()[0] ?? (await context.newPage());
    const routes = await installRoutes(context, () => primary, policy);
    let closing = false;
    // Each host navigation runs in a fresh page (see above).
    const open = async (url: string) => {
      const previous = primary;
      const page = await context.newPage();
      await routes.guardReady(page);
      primary = page;
      await previous.close().catch(() => {});
      try {
        const response = await page.goto(url, { timeout: 30_000, waitUntil: "load" });
        return { page, response };
      } catch (error) {
        const message = String((error as Error).message);
        if (message.includes("ERR_BLOCKED_BY_CLIENT")) throw new NavigationError("denied");
        if ((error as Error).name === "TimeoutError") throw new NavigationError("timeout");
        throw new NavigationError("failed");
      }
    };
    return {
      async navigate(url: string) {
        const { page, response } = await open(url);
        return { url: page.url(), status: response?.status() ?? 0 };
      },
      async fetchText(url: string) {
        const { page, response } = await open(url);
        const status = response?.status() ?? 0;
        const media = (response?.headers()["content-type"] ?? "").split(";")[0]?.trim().toLowerCase() ?? "";
        if (!response || !FETCH_TEXT_MEDIA.includes(media)) return { url: page.url(), status, media, text: "", truncated: false };
        let body: Buffer;
        try {
          body = await response.body();
        } catch {
          throw new NavigationError("failed");
        }
        // Text only: controls, invisible characters and lone surrogates
        // are removed, and the text is cut to fit one frame.
        const text = safeText(new TextDecoder("utf-8").decode(body.subarray(0, 4 * MAX_FETCH_TEXT_BYTES)));
        const { pieces } = toPieces([{ content: text, index: 0, total: 1, start: 0, end: text.length, overlap: "", hasMore: false }], MAX_FETCH_TEXT_BYTES, 1);
        const kept = pieces[0]?.content ?? "";
        return { url: page.url(), status, media, text: kept, truncated: kept.length < text.length || body.length > 4 * MAX_FETCH_TEXT_BYTES };
      },
      async activate(ref: string, target?: ApprovedTarget) {
        return clickAndLoad(primary, await approvedElement(primary, ref, target));
      },
      async execute(tool: string, fields: ExecField[]) {
        const page = primary;
        // Host-built selectors only: the tool name is [A-Za-z0-9_.-] and
        // field names are quoted as CSS strings.
        const quoted = (value: string): string => `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
        const form = page.locator(`form[toolname=${quoted(tool)}]`);
        // One budget for locating and filling every field: a page that keeps
        // a control unactionable cannot hold the call past the host's
        // deadline (filling 10 s, then the click and load, then the capture).
        const fillDeadline = Date.now() + FILL_BUDGET_MS;
        const timeout = (): number => {
          const remaining = fillDeadline - Date.now();
          if (remaining <= 0) throw new NavigationError("timeout");
          return Math.min(5_000, remaining);
        };
        try {
          if ((await form.count()) !== 1) throw new NavigationError("failed");
          for (const field of fields) {
            const name = `[name=${quoted(field.name)}]`;
            const valueOf = (value: string): string => (value === "on" ? ":not([value])" : `[value=${quoted(value)}]`);
            const one = async (selector: string) => {
              const control = form.locator(selector);
              if ((await control.count()) !== 1) throw new NavigationError("failed");
              return control;
            };
            switch (field.control) {
              case "text":
                await (await one(`input${name}`)).fill(field.values[0] ?? "", { timeout: timeout() });
                break;
              case "textarea":
                await (await one(`textarea${name}`)).fill(field.values[0] ?? "", { timeout: timeout() });
                break;
              case "select":
              case "select_multiple":
                await (await one(`select${name}`)).selectOption(
                  field.values.map((value) => ({ value })),
                  { timeout: timeout() }
                );
                break;
              case "checkbox":
                await (await one(`input[type="checkbox"]${name}`)).setChecked(field.values[0] === "true", { timeout: timeout() });
                break;
              case "checkboxes": {
                const all = form.locator(`input[type="checkbox"]${name}`);
                for (const box of await all.all()) await box.setChecked(false, { timeout: timeout() });
                for (const value of field.values) await (await one(`input[type="checkbox"]${name}${valueOf(value)}`)).setChecked(true, { timeout: timeout() });
                break;
              }
              case "radio":
                await (await one(`input[type="radio"]${name}${valueOf(field.values[0] ?? "")}`)).check({ timeout: timeout() });
                break;
              default:
                throw new NavigationError("failed");
            }
          }
        } catch (error) {
          if (error instanceof NavigationError) throw error;
          throw new NavigationError("failed");
        }
        // The form's default button: the first submit button in tree order.
        const submit = form.locator('button:not([type="button" i]):not([type="reset" i]), input[type="submit" i], input[type="image" i]').first();
        if ((await submit.count().catch(() => 0)) === 0) throw new NavigationError("failed");
        const { url, status } = await clickAndLoad(page, submit);
        // The submission's result: the opened document's structured data.
        let structured: string[] = [];
        let structuredComplete = false;
        try {
          const session = await context.newCDPSession(page);
          const captured = (await captureWithin(
            {
              capture: () => session.send("DOMSnapshot.captureSnapshot", { computedStyles: [] }),
              detach: () => session.detach()
            },
            CAPTURE_TIMEOUT_MS
          )) as CapturedSnapshot;
          // The blocks must fit the reply frame with room for its envelope
          // (the URL is bounded at 2 KiB).
          const all = structuredData(documentModel(captured).root);
          const fitted = fitBlocks(all, MAX_FRAME_BYTES - 4_096);
          structured = fitted.kept;
          structuredComplete = fitted.complete && all.length < MAX_RESULT_BLOCKS;
        } catch {
          structured = [];
          structuredComplete = false;
        }
        return { url, status, structured, structuredComplete };
      },
      async download(ref: string, path: string, target?: ApprovedTarget) {
        if (existsSync(path)) throw new NavigationError("failed");
        const page = primary;
        // Resolved before the capture is armed: a stale target clicks nothing.
        const element = await approvedElement(page, ref, target);
        const guard = await routes.guardReady(page);
        // Arm before clicking: the click's navigation (each request and
        // redirect hop still decided by the host) ends in a document whose
        // original bytes are captured and never rendered.
        const captured = guard.captureNextDocument(30_000);
        // The capture can settle (for example refused as oversized) while
        // the click is still in flight; without a handler attached now that
        // rejection would be unhandled and end the worker (measured).
        captured.catch(() => {});
        // On any failure the page is closed: a document arriving after the
        // capture gave up would otherwise be rendered. The host requires a
        // fresh navigation (which opens a new page) before acting again.
        const fail = async (reason: "failed" | "timeout" | "http_status" | "oversized"): Promise<never> => {
          await page.close().catch(() => {});
          throw new NavigationError(reason);
        };
        try {
          await element.click({ timeout: 5_000, noWaitAfter: true });
        } catch {
          return fail("failed");
        }
        let document;
        try {
          document = await captured;
        } catch (error) {
          // The capture's own refusals are typed (#307).
          const { name, message } = error as Error;
          if (name === "TimeoutError") return fail("timeout");
          if (message === "status") return fail("http_status");
          if (message === "oversized") return fail("oversized");
          return fail("failed");
        }
        if (document.status < 200 || document.status >= 300) return fail("http_status");
        writeFileSync(path, document.body, { flag: "wx" });
        return {
          url: document.url,
          name: suggestedName(document.url, document.disposition),
          media: document.media,
          bytes: document.body.length
        };
      },
      async observe() {
        const raw: unknown = await primary.ariaSnapshotJSON({ mode: "ai", depth: 16, timeout: 2_000 });
        return { url: primary.url(), snapshot: boundSnapshot(raw) };
      },
      async discover(discId: number) {
        // The engine serialises its own DOM: no page script runs. The whole
        // call (capture, discovery, fit) stays inside DISCOVERY_TOTAL_MS.
        const started = Date.now();
        const before = primary.url();
        const session = await context.newCDPSession(primary);
        // Playwright's protocol typings name this result differently;
        // documentModel reads every field defensively (missing arrays are
        // empty, a missing document throws into discovery_failed).
        const captured = (await captureWithin(
          {
            capture: () => session.send("DOMSnapshot.captureSnapshot", { computedStyles: [] }),
            detach: () => session.detach()
          },
          CAPTURE_TIMEOUT_MS
        )) as CapturedSnapshot;
        const model = documentModel(captured);
        // The snapshot must be of the page's document: if the page moved
        // during the capture, the result is stale and is refused.
        const url = primary.url();
        if (model.url !== url || before !== url) throw new Error("the document changed during discovery");
        const remaining = Math.max(0, DISCOVERY_TOTAL_MS - CAPTURE_TIMEOUT_MS / 2 - (Date.now() - started));
        const found = discoverDeclarativeTools(model.root, Math.min(DISCOVERY_BUDGET_MS, remaining), model.encoding);
        return fitTools(discId, url, model.truncated || found.truncated, found.tools);
      },
      async extract(options: { links: boolean; images: boolean }) {
        // The engine serialises its own DOM and layout: no page script runs,
        // and nothing on the page is scrolled, clicked or rendered first.
        const before = primary.url();
        const session = await context.newCDPSession(primary);
        const captured = (await captureWithin(
          {
            capture: () => session.send("DOMSnapshot.captureSnapshot", { computedStyles: [...CONTENT_STYLES] }),
            detach: () => session.detach()
          },
          EXTRACT_CAPTURE_TIMEOUT_MS
        )) as unknown as LayoutSnapshot;
        const url = primary.url();
        const extraction = extractMarkdown(captured, { ...options, budgetMs: EXTRACT_DEFAULTS.budgetMs });
        if (extraction.url !== url || before !== url) throw new Error("the document changed during extraction");
        const { pieces, truncated } = toPieces(extraction.chunks, MAX_PIECE_BYTES, MAX_EXTRACT_PIECES);
        return { url, truncated: extraction.truncated || truncated, pieces };
      },
      async close() {
        closing = true;
        await context.close();
      },
      onUnexpectedExit(listener) {
        context.on("close", () => {
          if (!closing) listener();
        });
      }
    };
  }
};

/// The engine's layout snapshot for an extraction (larger than discovery's
/// style-free one).
const EXTRACT_CAPTURE_TIMEOUT_MS = 5_000;

/// The worker's budget for locating and filling a tool's fields.
const FILL_BUDGET_MS = 10_000;

/// Click `target` and wait for the main frame's resulting document to load;
/// returns its URL and status. The host decides every request on the way.
/// BR-01: the approved element. Its snapshot ref when that still names an
/// element; otherwise, after a re-render replaced it, the one element in
/// the main frame whose role and accessible name equal the approved ones
/// (Playwright's role locator with an exact name, which reads the
/// accessibility tree and runs no page script). Anything else (a ref inside
/// a frame, no approved target, no match or several) is stale and nothing
/// is clicked. The host still confines the click's navigation or download
/// to the approved destination.
async function approvedElement(page: Page, ref: string, target?: ApprovedTarget): Promise<Locator> {
  const byRef = page.locator(`aria-ref=${ref}`);
  if ((await byRef.count().catch(() => 0)) === 1) return byRef;
  if (!target || !/^e\d+$/.test(ref) || target.name.length === 0) throw new NavigationError("stale");
  const byRole = page
    .mainFrame()
    .getByRole(target.role as Parameters<Page["getByRole"]>[0], { name: target.name, exact: true });
  if ((await byRole.count().catch(() => 0)) !== 1) throw new NavigationError("stale");
  return byRole;
}

async function clickAndLoad(page: Page, target: Locator): Promise<{ url: string; status: number }> {
  let status = 0;
  const onResponse = (response: import("playwright-core").Response) => {
    const request = response.request();
    if (request.isNavigationRequest() && request.frame() === page.mainFrame()) status = response.status();
  };
  page.on("response", onResponse);
  // A click that opens a popup instead of navigating the page is not the
  // approved activation: it fails at once (the popup is closed) rather than
  // waiting out the navigation timeout.
  let onPopup: ((popup: Page) => void) | undefined;
  const popped = new Promise<never>((_, reject) => {
    onPopup = (popup) => {
      void popup.close().catch(() => {});
      reject(new NavigationError("denied"));
    };
    page.on("popup", onPopup);
  });
  popped.catch(() => {});
  try {
    const navigated = page.waitForEvent("framenavigated", {
      predicate: (frame) => frame === page.mainFrame(),
      timeout: 30_000
    });
    try {
      await target.click({ timeout: 5_000 });
    } catch {
      navigated.catch(() => {});
      throw new NavigationError("failed");
    }
    await Promise.race([navigated, popped]);
    navigated.catch(() => {});
    await page.waitForLoadState("load", { timeout: 30_000 });
  } catch (error) {
    if (error instanceof NavigationError) throw error;
    if ((error as Error).name === "TimeoutError") throw new NavigationError("timeout");
    throw new NavigationError("failed");
  } finally {
    page.off("response", onResponse);
    if (onPopup) page.off("popup", onPopup);
  }
  // A refused navigation lands on Chromium's error page.
  if (page.url().startsWith("chrome-error:")) throw new NavigationError("denied");
  return { url: page.url(), status };
}

/// The file name a download would get: the Content-Disposition filename when
/// present, else the last URL path segment; never a path.
function suggestedName(url: string, disposition: string): string {
  const quoted = /filename="([^"]{1,200})"/i.exec(disposition)?.[1];
  const bare = /filename=([^;\s]{1,200})/i.exec(disposition)?.[1];
  let name = quoted ?? bare ?? "";
  if (!name) {
    try {
      name = decodeURIComponent(new URL(url).pathname.split("/").pop() ?? "");
    } catch {
      name = "";
    }
  }
  return name.replace(/[\\/:*?"<>|\x00-\x1f]/g, "_").slice(0, 200) || "download";
}

function send(frame: WorkerFrame): void {
  process.stdout.write(encodeFrame(frame));
}

function finish(exitCode: number): void {
  process.stdin.pause();
  // Exit only after the last frame has been flushed to the host.
  process.stdout.write(Buffer.alloc(0), () => process.exit(exitCode));
}

const worker = new Worker(playwrightLauncher, send, finish);
const decoder = new FrameDecoder();

// A broken pipe in either direction ends the worker; the engine is closed.
process.stdin.on("error", () => void worker.violation());
process.stdout.on("error", () => void worker.violation());

process.stdin.on("data", (chunk: Buffer) => {
  let frames: unknown[];
  try {
    frames = decoder.push(chunk);
  } catch (error) {
    if (error instanceof ProtocolViolation) {
      void worker.violation();
      return;
    }
    throw error;
  }
  for (const frame of frames) void worker.receive(frame);
});
process.stdin.on("end", () => {
  void (decoder.pendingBytes > 0 ? worker.violation() : worker.endOfInput());
});
