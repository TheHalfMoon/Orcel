// SG-000108 worker: stdio framing around `Worker`, with the engine launched
// by playwright-core exactly as the host specified. Loaded by main.js only
// after the resolve guard is installed.
//
// stdout carries frames only: the global console is replaced by one whose
// every method writes to stderr, so no library output can corrupt the channel.

import { Console } from "node:console";
import { existsSync, writeFileSync } from "node:fs";
import { chromium, type Page } from "playwright-core";
import { refusedWorkerVariables, startupRefusal } from "./environment.js";
import { safeText } from "./extract/clean.js";
import { ENGINE_LAUNCH_TIMEOUT_MS } from "./timeouts.js";
import { encodeFrame, FETCH_TEXT_MEDIA, FrameDecoder, isVisibleArgv, MAX_EXTRACT_PIECES, MAX_FETCH_TEXT_BYTES, MAX_FRAME_BYTES, MAX_PIECE_BYTES, MAX_URL_BYTES, ProtocolViolation, type ApprovedTarget, type ExecField, type WorkerFrame } from "./protocol.js";
import { CONTENT_STYLES, EXTRACT_DEFAULTS, extractMarkdown } from "./extract/index.js";
import type { LayoutSnapshot } from "./extract/model.js";
import { toPieces } from "./extract/pieces.js";
import { netErrorCode, rendererAnswers, traceLine, traceMark, traceStart, traceWatchEventLoop } from "./navigation-trace.js";
import { watchNavigation } from "./refusals.js";
import { installRoutes } from "./routes.js";
import { boundSnapshot } from "./snapshot.js";
import { runProbes } from "./verify.js";
import { discoverDeclarativeTools, DISCOVERY_BUDGET_MS } from "./webmcp/declarative.js";
import { CAPTURE_TIMEOUT_MS, DISCOVERY_TOTAL_MS, fitTools } from "./webmcp/fit.js";
import { captureWithin } from "./webmcp/capture.js";
import { fitBlocks, MAX_RESULT_BLOCKS, structuredData } from "./webmcp/structured.js";
import { documentModel, type CapturedSnapshot } from "./webmcp/dom-snapshot.js";
import { approvedElement, isOcclusion } from "./actions/targets.js";
import { clickAndLoad } from "./actions/click-load.js";
import { enterAndSettle } from "./actions/enter-load.js";
import { classifyControls, formAction } from "./actions/form.js";
import { nameControls } from "./actions/names.js";
import { waitForText } from "./actions/wait.js";
import { uploadFile } from "./actions/upload.js";
import { DialogLog } from "./actions/dialogs.js";
import { NavigationError, TabError, Worker, type EngineSession, type Launcher, type LaunchSpec, type RoutePolicy, type TabsState } from "./worker.js";
import { capturePng, fullPageClip, runExclusive, ScreenshotError } from "./screenshot.js";
import { admitPopup, MAX_PENDING_POPUPS, MAX_TABS, NavigationWatch, TabRegistry } from "./tabs.js";

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
      // SG-000135 OB-04: headless (Shadow) unless the host-built argv is
      // exactly the Visible form launchRefusal accepted. Nothing here ever
      // raises, focuses or activates the window.
      headless: !isVisibleArgv(spec.argv),
      // Downloads never happen through the engine: an approved document is
      // captured by the redirect guard instead (slice 3d).
      acceptDownloads: false,
      // "allow" keeps service-worker requests visible to routing; the
      // route stack refuses every registration (#301).
      serviceWorkers: "allow",
      handleSIGINT: false,
      handleSIGTERM: false,
      handleSIGHUP: false,
      timeout: ENGINE_LAUNCH_TIMEOUT_MS
    });
    // Each host navigation runs in a fresh page: Chromium can commit an
    // earlier refused navigation's error page late (even more than once),
    // which would interrupt a navigation in the same page. The previous
    // page is closed once the new one has its redirect guard.
    //
    // SG-000135 OB-03: the pages are tabs (tabs.ts). Every action below acts
    // on the active tab's page (`activeTab`), and its reply names that tab;
    // a navigation's fresh page takes over the active tab and keeps its id.
    // `primary` is the page the route stack classifies requests against: the
    // active tab's, or the last one while no tab is active.
    const own = new WeakSet<Page>();
    const creating = new Set<Promise<Page>>();
    const ownPage = async (): Promise<Page> => {
      const pending = context.newPage();
      creating.add(pending);
      try {
        const page = await pending;
        own.add(page);
        return page;
      } finally {
        creating.delete(pending);
      }
    };
    const first = context.pages()[0];
    let primary: Page = first ?? (await ownPage());
    own.add(primary);
    const tabs = new TabRegistry<Page>(MAX_URL_BYTES);
    const watches = new WeakMap<Page, NavigationWatch>();
    // BR-05: every dialog, on every page, is answered as it opens and logged.
    const dialogs = new DialogLog();
    dialogs.listen(context);
    const routes = await installRoutes(context, () => primary, policy);
    let closing = false;
    const syncPrimary = () => {
      const active = tabs.activePage();
      if (active) primary = active;
    };
    // Pages the worker closes itself (a navigation's previous page, a failed
    // download's page, a tab the host closed): their tab is handled where
    // they are closed.
    const workerClosed = new WeakSet<Page>();
    const closeOwn = async (page: Page) => {
      workerClosed.add(page);
      await page.close().catch(() => {});
    };
    // A tab whose page closed itself (window.close from page script) or
    // whose renderer crashed is gone, and no other tab is made active in
    // its place: every action fails until the host sends a tab request and
    // learns the tabs.
    const watchPage = (page: Page) => {
      watches.set(page, new NavigationWatch(page));
      const gone = () => {
        if (workerClosed.has(page)) return;
        const id = tabs.idOf(page);
        if (id !== null) tabs.dropClosed(id);
      };
      page.on("close", gone);
      page.on("crash", gone);
    };
    /// The active tab and its page, or a typed "stale" refusal when no tab
    /// is active.
    const activeTab = (): { tab: number; page: Page } => {
      const tab = tabs.active;
      const page = tabs.activePage();
      if (tab === null || page === null) throw new NavigationError("stale");
      return { tab, page };
    };
    tabs.add(primary);
    watchPage(primary);
    const tabsState = (): TabsState => ({ active: tabs.active ?? 0, tabs: tabs.list() });
    // A page the page itself opened (a popup) becomes a tab only once the
    // host admitted its first document and the lifetime is under its cap;
    // otherwise it is closed.
    // At most MAX_PENDING_POPUPS wait for admission at once; any further
    // popup is closed at once.
    let pendingPopups = 0;
    context.on("page", (page) => {
      void (async () => {
        await Promise.allSettled([...creating]);
        if (own.has(page) || closing) return;
        if (pendingPopups >= MAX_PENDING_POPUPS) {
          await page.close().catch(() => {});
          return;
        }
        pendingPopups += 1;
        let admitted = false;
        try {
          admitted = await admitPopup(page);
        } finally {
          pendingPopups -= 1;
        }
        if (!admitted || closing || page.isClosed() || tabs.add(page) === null) {
          await page.close().catch(() => {});
          return;
        }
        watchPage(page);
      })().catch(() => {});
    });
    // Each host navigation runs in a fresh page (see above).
    const open = async (url: string) => {
      traceStart();
      // The active tab keeps its id (its page may be one a failed download
      // closed). With no active tab (its page closed itself), nothing
      // navigates until the host sends a tab request.
      const { tab, page: previous } = activeTab();
      const page = await ownPage();
      traceMark("page_created");
      await routes.guardReady(page);
      traceMark("guard_ready");
      if (tabs.active !== tab || !tabs.replace(tab, page)) {
        await closeOwn(page);
        throw new NavigationError("stale");
      }
      watchPage(page);
      primary = page;
      await closeOwn(previous);
      traceMark("previous_closed");
      page.on("request", () => traceMark("request"));
      page.on("response", (response) => {
        traceMark("response");
        // #438: when the engine started the request, by the engine's clock.
        // Playwright knows it only once a response exists.
        const engineStart = response.request().timing().startTime;
        if (engineStart > 0) traceMark("request_engine_start", engineStart);
      });
      page.on("requestfailed", () => traceMark("request_failed"));
      page.on("domcontentloaded", () => traceMark("domcontentloaded"));
      page.on("load", () => traceMark("load"));
      page.on("crash", () => traceMark("page_crashed"));
      const stopWatching = traceWatchEventLoop();
      // Which refusals during this navigation were Orcel's own (refusals.ts).
      const watch = watchNavigation(page, routes.refusals);
      try {
        traceMark("goto");
        const response = await page.goto(url, { timeout: 30_000, waitUntil: "load" });
        stopWatching();
        watch.stop();
        return { tab, page, response };
      } catch (error) {
        stopWatching();
        watch.stop();
        const message = String((error as Error).message);
        // The engine reports its own cancellations with the same error as
        // Orcel's refusals: "denied" only for a refusal Orcel made. Anything
        // else falls through to "failed" below (logged with its error code).
        if (message.includes("ERR_BLOCKED_BY_CLIENT")) {
          if (watch.refusedByOrcel(url)) throw new NavigationError("denied");
          traceMark("blocked_not_by_orcel");
        }
        if ((error as Error).name === "TimeoutError") {
          // #438: where it stalled, for the host's failure diagnostics. #584: and whether
          // the page's renderer answers at all (a constant expression, no page data read).
          traceMark(`renderer_${(await rendererAnswers(() => page.evaluate("1"))).replace(" ", "_")}`);
          traceMark(`page_closed_${page.isClosed()}`);
          process.stderr.write(`orcel-browser-worker: ${traceLine()}
`);
          throw new NavigationError("timeout");
        }
        // #584: why the engine gave up, which "failed" alone doesn't say.
        process.stderr.write(`orcel-browser-worker: goto failed ${netErrorCode(message)} ${traceLine()}
`);
        throw new NavigationError("failed");
      }
    };
    return {
      async navigate(url: string) {
        const { tab, page, response } = await open(url);
        return { tab, url: page.url(), status: response?.status() ?? 0 };
      },
      async fetchText(url: string) {
        const { tab, page, response } = await open(url);
        const status = response?.status() ?? 0;
        const media = (response?.headers()["content-type"] ?? "").split(";")[0]?.trim().toLowerCase() ?? "";
        if (!response || !FETCH_TEXT_MEDIA.includes(media)) return { tab, url: page.url(), status, media, text: "", truncated: false };
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
        return { tab, url: page.url(), status, media, text: kept, truncated: kept.length < text.length || body.length > 4 * MAX_FETCH_TEXT_BYTES };
      },
      async activate(ref: string, target?: ApprovedTarget) {
        const { tab, page } = activeTab();
        return { tab, ...(await clickAndLoad(page, await approvedElement(page, ref, target), routes.refusals)) };
      },
      async execute(tool: string, fields: ExecField[]) {
        const { tab, page } = activeTab();
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
        // The fields are already filled: a covered submit button is a plain
        // failure here, not "occluded" (which promises nothing was done).
        const { url, status } = await clickAndLoad(page, submit, routes.refusals).catch((error: unknown) => {
          throw error instanceof NavigationError && error.reason === "occluded" ? new NavigationError("failed") : error;
        });
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
        return { tab, url, status, structured, structuredComplete };
      },
      async download(ref: string, path: string, target?: ApprovedTarget) {
        if (existsSync(path)) throw new NavigationError("failed");
        const { tab, page } = activeTab();
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
        const fail = async (reason: "failed" | "timeout" | "http_status" | "oversized" | "occluded"): Promise<never> => {
          await closeOwn(page);
          throw new NavigationError(reason);
        };
        try {
          await element.click({ timeout: 5_000, noWaitAfter: true });
        } catch (error) {
          return fail(isOcclusion(error) ? "occluded" : "failed");
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
          tab,
          url: document.url,
          name: suggestedName(document.url, document.disposition),
          media: document.media,
          bytes: document.body.length
        };
      },
      takeDialogs() {
        return dialogs.take();
      },
      async upload(ref, path, target) {
        const { tab, page } = activeTab();
        await uploadFile(page, ref, path, target);
        return { tab, url: page.url() };
      },
      async waitForText(text, appear, timeoutMs) {
        const { tab, page } = activeTab();
        const met = await waitForText(page, text, appear, timeoutMs);
        return { tab, url: page.url(), met };
      },
      async formAction(ref, act, target, acceptConfirm) {
        const { tab, page } = activeTab();
        if (acceptConfirm !== undefined) dialogs.arm(acceptConfirm, page);
        try {
          // SG-000122 slice A6: an Enter may submit; what the main frame did
          // after the key is reported (the host decided every request).
          if (act.action === "enter") return { tab, ...(await enterAndSettle(page, routes.refusals, () => formAction(page, ref, act, target))) };
          await formAction(page, ref, act, target);
        } finally {
          dialogs.disarm();
        }
        return { tab, url: page.url() };
      },
      async verify(probes) {
        const { tab, page } = activeTab();
        const results = await runProbes(page, probes);
        return { tab, url: page.url(), results };
      },
      async observe() {
        const { tab, page } = activeTab();
        const raw: unknown = await page.ariaSnapshotJSON({ mode: "ai", depth: 16, timeout: 2_000 });
        const snapshot = boundSnapshot(raw);
        // SG-000122: which main-frame form controls a form action may target.
        await classifyControls(page, snapshot.nodes);
        // SG-000122 slice A5: which of their names carry text only.
        await nameControls(page, snapshot.nodes);
        return { tab, url: page.url(), snapshot };
      },
      async discover(discId: number) {
        // The engine serialises its own DOM: no page script runs. The whole
        // call (capture, discovery, fit) stays inside DISCOVERY_TOTAL_MS.
        const started = Date.now();
        const { tab, page } = activeTab();
        const before = page.url();
        const session = await context.newCDPSession(page);
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
        const url = page.url();
        if (model.url !== url || before !== url) throw new Error("the document changed during discovery");
        const remaining = Math.max(0, DISCOVERY_TOTAL_MS - CAPTURE_TIMEOUT_MS / 2 - (Date.now() - started));
        const found = discoverDeclarativeTools(model.root, Math.min(DISCOVERY_BUDGET_MS, remaining), model.encoding);
        return { tab, ...fitTools(discId, url, model.truncated || found.truncated, found.tools) };
      },
      async extract(options: { links: boolean; images: boolean }) {
        // The engine serialises its own DOM and layout: no page script runs,
        // and nothing on the page is scrolled, clicked or rendered first.
        const { tab, page } = activeTab();
        const before = page.url();
        const session = await context.newCDPSession(page);
        const captured = (await captureWithin(
          {
            capture: () => session.send("DOMSnapshot.captureSnapshot", { computedStyles: [...CONTENT_STYLES] }),
            detach: () => session.detach()
          },
          EXTRACT_CAPTURE_TIMEOUT_MS
        )) as unknown as LayoutSnapshot;
        const url = page.url();
        const extraction = extractMarkdown(captured, { ...options, budgetMs: EXTRACT_DEFAULTS.budgetMs });
        if (extraction.url !== url || before !== url) throw new Error("the document changed during extraction");
        const { pieces, truncated } = toPieces(extraction.chunks, MAX_PIECE_BYTES, MAX_EXTRACT_PIECES);
        return { tab, url, truncated: extraction.truncated || truncated, pieces };
      },
      async screenshot(fullPage: boolean) {
        const active = tabs.activePage();
        const tab = tabs.active;
        // No active tab (its page closed itself): refused until the host
        // learns the tabs.
        if (active === null || tab === null) throw new ScreenshotError("busy");
        const page = active;
        if (page.isClosed()) throw new ScreenshotError("failed");
        const loading = () => watches.get(page)?.loading === true;
        if (loading()) throw new ScreenshotError("busy");
        return runExclusive(page, async () => {
          const before = page.url();
          let clip: { x: number; y: number; width: number; height: number } | undefined;
          let truncated = false;
          if (fullPage) {
            // The engine's own layout metrics: no page script runs.
            const session = await context.newCDPSession(page);
            let metrics: unknown;
            try {
              metrics = await session.send("Page.getLayoutMetrics");
            } catch {
              throw new ScreenshotError("failed");
            } finally {
              await session.detach().catch(() => {});
            }
            ({ clip, truncated } = fullPageClip(metrics));
          }
          const shot = await capturePng(page, clip);
          // A capture that raced a navigation, or a tab change, is of no one
          // document.
          if (loading() || page.isClosed() || page.url() !== before || tabs.active !== tab) throw new ScreenshotError("busy");
          return { ...shot, tab, url: before, truncated };
        });
      },
      async tabNew() {
        if (tabs.size >= MAX_TABS) throw new TabError("cap");
        const page = await ownPage();
        try {
          await routes.guardReady(page);
        } catch {
          await closeOwn(page);
          throw new TabError("failed");
        }
        const id = tabs.add(page);
        if (id === null) {
          await closeOwn(page);
          throw new TabError("cap");
        }
        tabs.activate(id);
        watchPage(page);
        primary = page;
        return tabsState();
      },
      async tabSwitch(tab: number) {
        if (!tabs.activate(tab)) throw new TabError("unknown_tab");
        syncPrimary();
        return tabsState();
      },
      async tabClose(tab: number) {
        const page = tabs.page(tab);
        if (page === null) throw new TabError("unknown_tab");
        if (tabs.size === 1) throw new TabError("last");
        tabs.remove(tab);
        syncPrimary();
        // Closing runs the page's own unload and pagehide handlers, which
        // may send requests (beacons); the route stack still decides each
        // one, so only the lifetime's admitted site can receive them.
        // orceld asks the takeover gate first (a write on that tab).
        await closeOwn(page);
        return tabsState();
      },
      tabs() {
        return tabsState();
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

const worker = new Worker(playwrightLauncher, send, finish, (line) => {
  process.stderr.write(`${line}\n`);
});
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
