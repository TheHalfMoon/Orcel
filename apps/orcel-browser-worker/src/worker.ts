// SG-000108 worker state machine. Transport-free: frames arrive through
// `receive`, replies leave through `send`, and the engine is behind an
// injected `Launcher` so the protocol is testable without a browser.
//
// awaiting_hello --hello--> ready --launch--> launched --shutdown--> closed
// Any violation, refused launch, engine exit, or end of input closes the
// engine and ends the worker. At most one engine per worker lifetime.
//
// Slice 3a: in `launched`, the host may send `navigate`. The navigation runs
// outside the frame queue (so ping and shutdown stay responsive) and ends
// with `navigated` or `navigation_failed`. Every engine request is described
// to the host as a `route_request`; the host's `route_decision` is applied
// immediately (decisions bypass the queue, or a navigation waiting for them
// would deadlock). A request the host does not answer in time is refused.

import type { DeclaredTool } from "./webmcp/declarative.js";
import type { Piece } from "./extract/pieces.js";
import {
  launchRefusal,
  MAX_EXTRACT_PIECES,
  MAX_ORIGIN_BYTES,
  MAX_URL_BYTES,
  parseHostFrame,
  ProtocolViolation,
  WORKER_IDENTITY,
  WORKER_PROTOCOL_GENERATION,
  type ApprovedTarget,
  type ErrorCode,
  type ExecField,
  type HostFrame,
  type NavigationFailure,
  type TabFailure,
  type WorkerFrame
} from "./protocol.js";
import { ScreenshotError, toBase64Pieces } from "./screenshot.js";
import type { TabInfo } from "./tabs.js";
import type { RequestDetail, RouteQuery } from "./routing.js";
import type { BoundedSnapshot } from "./snapshot.js";
import type { VerifyProbe, VerifyResult } from "./verify.js";
import type { FormAction } from "./actions/form.js";
import type { DismissedDialog } from "./actions/dialogs.js";
import type { BoundedOutline } from "./outline/capture.js";
import type { SchemaField, SchemaValue } from "./outline/schema-extract.js";
import { ChallengeBusy, type ChallengeReport } from "./challenge.js";

export type LaunchSpec = Extract<HostFrame, { frame: "launch" }>;

/// How long the worker waits for a host route decision before refusing.
export const ROUTE_DECISION_TIMEOUT_MS = 10_000;

/// The host's answer to a described request.
export interface RoutePolicy {
  decide(query: RouteQuery): Promise<boolean>;
}

/// SG-000135 OB-07b: a request body leaves the worker only for the top-level
/// document of an approved form execution, the one request whose body the
/// host checks (`Submission::check`). Every other body, such as a sign-in
/// form the person posts in a Visible window, is withheld: the host gets
/// `null` and size 0, never the fields. An empty body (none) stays empty.
export function withheldBody(detail: RequestDetail, armed: boolean): RequestDetail {
  if (armed || detail.body === "") return detail;
  return { ...detail, body: null, bodyBytes: 0 };
}

export class NavigationError extends Error {
  constructor(readonly reason: NavigationFailure) {
    super(reason);
  }
}

/// SG-000135 OB-03: a tab request the engine could not do.
export class TabError extends Error {
  constructor(readonly reason: TabFailure) {
    super(reason);
  }
}

/// SG-000135 OB-03: the lifetime's tabs after a tab request (`active` is 0
/// when none is).
export interface TabsState {
  active: number;
  tabs: TabInfo[];
}

export interface EngineSession {
  close(): Promise<void>;
  /// Navigate the primary page; rejects with NavigationError.
  /// SG-000135 OB-03: `tab` is the tab acted on, here and in observe,
  /// activate, formAction, verify, extract and screenshot.
  navigate(url: string): Promise<{ tab: number; url: string; status: number }>;
  /// Navigate the primary page like `navigate` (the same routes and host
  /// decisions) and return the document's text when it is plain text or
  /// XML, bounded to one frame; rejects with NavigationError.
  fetchText(url: string): Promise<{ tab: number; url: string; status: number; media: string; text: string; truncated: boolean }>;
  /// A bounded, value-free accessibility snapshot of the primary page.
  observe(): Promise<{ tab: number; url: string; snapshot: BoundedSnapshot }>;
  /// W2-03: the bounded accessibility outline of the primary page's main
  /// document, read through a read-only CDP session (no page script).
  outline(): Promise<{ tab: number; url: string; outline: BoundedOutline }>;
  /// W2-03: one value per schema field, matched in that outline (no model).
  extractSchema(fields: SchemaField[]): Promise<{ tab: number; url: string; truncated: boolean; values: SchemaValue[] }>;
  /// The primary page's declarative WebMCP tools, read without running
  /// page script; bounded so the reply frame fits.
  discover(discId: number): Promise<{ tab: number; url: string; truncated: boolean; tools: DeclaredTool[] }>;
  /// The primary page's rendered content as Markdown, read from an engine
  /// snapshot without running page script, in frame-sized pieces.
  extract(options: { links: boolean; images: boolean }): Promise<{ tab: number; url: string; truncated: boolean; pieces: Piece[] }>;
  /// Fill the declared tool form with host-validated fields, click its
  /// default submit button and wait for the resulting document; returns it
  /// with its structured data. Rejects with NavigationError.
  execute(tool: string, fields: ExecField[]): Promise<{ tab: number; url: string; status: number; structured: string[]; structuredComplete: boolean }>;
  /// Click the element with this snapshot ref (or, when the ref went
  /// stale, the one element matching the approved target) and wait for the
  /// resulting navigation to load; rejects with NavigationError.
  activate(ref: string, target?: ApprovedTarget): Promise<{ tab: number; url: string; status: number }>;
  /// Click the element with this snapshot ref (or the one matching the
  /// approved target), expect a download, and save it to `path` (which must
  /// not exist); rejects with NavigationError.
  download(ref: string, path: string, target?: ApprovedTarget): Promise<{ tab: number; url: string; name: string; media: string; bytes: number }>;
  /// BR-02: one approved form action on the element with this snapshot ref
  /// (or the one matching the approved target); resolves with the page's
  /// URL afterwards; rejects with NavigationError.
  /// With `acceptConfirm`, a confirm with exactly that message is accepted
  /// (once) while the action runs; every other dialog is dismissed.
  /// SG-000122 slice A6: an Enter also says whether the main frame committed
  /// a new document after the key (`navigated`).
  formAction(ref: string, act: FormAction, target?: ApprovedTarget, acceptConfirm?: string): Promise<{ tab: number; url: string; navigated?: boolean }>;
  /// BR-05: the dialogs dismissed since the last call (clears the log).
  takeDialogs(): { dialogs: DismissedDialog[]; truncated: boolean };
  /// BR-03: set the approved file input to the host-staged file at `path`;
  /// resolves with the page's URL; rejects with NavigationError.
  upload(ref: string, path: string, target?: ApprovedTarget): Promise<{ tab: number; url: string }>;
  /// BR-02: whether text became visible (or stopped being visible) on the
  /// primary page within the bound; read-only.
  waitForText(text: string, appear: boolean, timeoutMs: number): Promise<{ tab: number; url: string; met: boolean }>;
  /// BR-07: read-only probes of the primary page, one result per probe.
  verify(probes: VerifyProbe[]): Promise<{ tab: number; url: string; results: VerifyResult[] }>;
  /// SG-000135 OB-03: a bounded PNG of the active tab's page (the
  /// viewport, or from the top of the page within the bounds when
  /// `fullPage`), every secret field masked; rejects with ScreenshotError
  /// ("busy" while a navigation of the page is in flight).
  screenshot(fullPage: boolean): Promise<{ tab: number; url: string; png: Buffer; width: number; height: number; truncated: boolean }>;
  /// SG-000135 OB-07: classify the active tab's document as a challenge
  /// only a person can get past, read-only (the engine's DOM and layout
  /// snapshot; no page script). `status` counts only while the tab still
  /// shows `url`.
  challenge(url: string, status: number): Promise<{ tab: number; url: string; report: ChallengeReport }>;
  /// SG-000135 OB-03: open a blank tab and make it active; rejects with
  /// TabError ("cap" at MAX_TABS).
  tabNew(): Promise<TabsState>;
  /// Make tab `tab` active; rejects with TabError.
  tabSwitch(tab: number): Promise<TabsState>;
  /// Close tab `tab` (never the only one: "last"); rejects with TabError.
  tabClose(tab: number): Promise<TabsState>;
  /// The lifetime's tabs.
  tabs(): TabsState;
  /// Called once if the engine goes away without `close`.
  onUnexpectedExit(listener: () => void): void;
}

export interface Launcher {
  launch(spec: LaunchSpec, policy: RoutePolicy): Promise<EngineSession>;
}

/// SG-000135 OB-03: a screenshot whose pieces the host has not all read.
interface HeldShot {
  shotId: number;
  tab: number;
  url: string;
  width: number;
  height: number;
  bytes: number;
  truncated: boolean;
  pieces: string[];
}

export type WorkerState = "awaiting_hello" | "ready" | "launched" | "closed";

export class Worker {
  private state: WorkerState = "awaiting_hello";
  /// The last extraction's remaining pieces, until the host has read them.
  private extraction: { extId: number; tab: number; url: string; truncated: boolean; pieces: Piece[] } | null = null;
  /// SG-000135 OB-03: the last screenshot's remaining pieces, until the
  /// host has read them.
  private shot: HeldShot | null = null;
  private session: EngineSession | null = null;
  private launchedOnce = false;
  private queue: Promise<void> = Promise.resolve();
  private navigating = false;
  /// SG-000135 OB-07b: an approved form execution is in flight. Only then
  /// may a request body reach the host (`ask`).
  private executing = false;
  /// BR-02: a bounded wait is running (one at a time).
  private waiting = false;
  private nextRequestId = 0;
  private readonly pending = new Map<number, { resolve: (allow: boolean) => void; timer: NodeJS.Timeout }>();
  private readonly policy: RoutePolicy = { decide: (query) => this.ask(query) };

  constructor(
    private readonly launcher: Launcher,
    private readonly send: (frame: WorkerFrame) => void,
    private readonly finish: (exitCode: number) => void,
    /// #438: one bounded diagnostic line when the engine launch fails (the
    /// worker's stderr: a host test build keeps it, a product host discards
    /// it). Never a frame and never page content.
    private readonly diagnose: (line: string) => void = () => {}
  ) {}

  /// Frames are handled strictly in arrival order. An unexpected error in
  /// any step fails the worker closed instead of breaking the queue.
  receive(raw: unknown): Promise<void> {
    let frame: HostFrame;
    try {
      frame = parseHostFrame(raw);
    } catch (error) {
      if (error instanceof ProtocolViolation) return this.enqueue(() => this.fail("protocol_violation"));
      throw error;
    }
    if (frame.frame === "route_decision") {
      // Applied at once: a navigation in progress may be waiting for it.
      const waiter = this.pending.get(frame.request_id);
      if (this.state !== "launched" || frame.request_id > this.nextRequestId) {
        return this.enqueue(() => this.fail("protocol_violation"));
      }
      if (waiter) {
        this.pending.delete(frame.request_id);
        clearTimeout(waiter.timer);
        waiter.resolve(frame.allow);
      }
      // A late answer to a request that already timed out is ignored.
      return Promise.resolve();
    }
    return this.enqueue(() => this.handle(frame));
  }

  /// Describe a request to the host and wait (bounded) for its decision.
  private ask(query: RouteQuery): Promise<boolean> {
    if (this.state !== "launched") return Promise.resolve(false);
    if (
      query.url.length === 0 ||
      Buffer.byteLength(query.url, "utf8") > MAX_URL_BYTES ||
      Buffer.byteLength(query.origin, "utf8") > MAX_ORIGIN_BYTES ||
      /[\u0000-\u001f\u007f]/.test(query.url + query.origin)
    ) {
      return Promise.resolve(false);
    }
    const requestId = ++this.nextRequestId;
    return new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(requestId);
        resolve(false);
      }, ROUTE_DECISION_TIMEOUT_MS);
      this.pending.set(requestId, { resolve, timer });
      const detail = withheldBody(query.detail ?? { method: "GET", contentType: "", body: "", bodyBytes: 0 }, this.executing && query.kind === "document");
      this.send({
        frame: "route_request",
        request_id: requestId,
        kind: query.kind,
        url: query.url,
        origin: query.origin,
        method: detail.method,
        content_type: detail.contentType,
        body: detail.body,
        body_bytes: detail.bodyBytes,
        // SG-000122 A6: only on a main-frame document hop.
        ...(query.mainDocument === true ? { main_document: true as const } : {})
      });
    });
  }

  /// A transport-level violation (bad length, non-JSON, broken pipe).
  violation(): Promise<void> {
    return this.enqueue(() => this.fail("protocol_violation"));
  }

  endOfInput(): Promise<void> {
    return this.enqueue(() => this.close(0, null));
  }

  private enqueue(step: () => Promise<void>): Promise<void> {
    this.queue = this.queue.then(step).catch(() => this.fail("protocol_violation"));
    return this.queue;
  }

  private async handle(frame: HostFrame): Promise<void> {
    if (this.state === "closed") return;
    if (this.state === "awaiting_hello") {
      if (frame.frame !== "hello" || frame.generation !== WORKER_PROTOCOL_GENERATION) {
        return this.fail("protocol_violation");
      }
      this.state = "ready";
      this.send({ frame: "hello", generation: WORKER_PROTOCOL_GENERATION, worker: WORKER_IDENTITY });
      return;
    }
    switch (frame.frame) {
      case "hello":
      case "route_decision":
        return this.fail("protocol_violation");
      case "download": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        if (this.navigating) {
          this.send({ frame: "download_failed", dl_id: frame.dl_id, reason: "busy" });
          return;
        }
        this.navigating = true;
        void this.runDownload(this.session, frame.dl_id, frame.ref, frame.path, frame.target);
        return;
      }
      case "activate": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        if (this.navigating) {
          this.send({ frame: "activation_failed", act_id: frame.act_id, reason: "busy" });
          return;
        }
        this.navigating = true;
        void this.runActivation(this.session, frame.act_id, frame.ref, frame.target);
        return;
      }
      case "execute": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        if (this.navigating) {
          this.send({ frame: "execution_failed", exec_id: frame.exec_id, reason: "busy" });
          return;
        }
        this.navigating = true;
        void this.runExecution(this.session, frame.exec_id, frame.tool, frame.fields);
        return;
      }
      case "discover": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        try {
          const { tab, url, truncated, tools } = await this.session.discover(frame.disc_id);
          this.send({ frame: "discovered", disc_id: frame.disc_id, tab, url, truncated, tools });
        } catch {
          this.send({ frame: "discovery_failed", disc_id: frame.disc_id });
        }
        return;
      }
      case "extract": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        this.extraction = null;
        try {
          const { tab, url, truncated, pieces } = await this.session.extract({ links: frame.links, images: frame.images });
          if (pieces.length === 0 || pieces.length > MAX_EXTRACT_PIECES) throw new Error("piece count out of range");
          // A page can give itself a long URL (pushState); the pieces are
          // sized for one of at most MAX_URL_BYTES.
          if (Buffer.byteLength(url) > MAX_URL_BYTES) throw new Error("the page URL is too long");
          const first = pieces[0] ?? { chunk: 0, content: "" };
          this.send({ frame: "extracted", ext_id: frame.ext_id, tab, url, truncated, piece: 0, total: pieces.length, chunk: first.chunk, content: first.content });
          // Kept only until the host has read every piece.
          if (pieces.length > 1) this.extraction = { extId: frame.ext_id, tab, url, truncated, pieces };
        } catch {
          this.send({ frame: "extraction_failed", ext_id: frame.ext_id });
        }
        return;
      }
      case "extract_more": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        const kept = this.extraction;
        const piece = kept && kept.extId === frame.ext_id ? kept.pieces[frame.piece] : undefined;
        if (!kept || piece === undefined) {
          this.send({ frame: "extraction_failed", ext_id: frame.ext_id });
          return;
        }
        if (frame.piece === kept.pieces.length - 1) this.extraction = null;
        this.send({
          frame: "extracted",
          ext_id: frame.ext_id,
          tab: kept.tab,
          url: kept.url,
          truncated: kept.truncated,
          piece: frame.piece,
          total: kept.pieces.length,
          chunk: piece.chunk,
          content: piece.content
        });
        return;
      }
      case "form_action": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        if (this.navigating) {
          this.send({ frame: "form_failed", form_id: frame.form_id, reason: "busy" });
          return;
        }
        // Outside the queue: the action's requests need host decisions.
        this.navigating = true;
        void this.runFormAction(this.session, frame.form_id, frame.ref, frame.act, frame.target, frame.accept_confirm);
        return;
      }
      case "screenshot": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        this.shot = null;
        // A document being replaced is never captured.
        if (this.navigating) {
          this.send({ frame: "screenshot_failed", shot_id: frame.shot_id, reason: "busy" });
          return;
        }
        try {
          const { tab, url, png, width, height, truncated } = await this.session.screenshot(frame.full_page);
          const pieces = toBase64Pieces(png);
          const shot: HeldShot = { shotId: frame.shot_id, tab, url, width, height, bytes: png.length, truncated, pieces };
          this.sendShotPiece(shot, 0);
          // Kept only until the host has read every piece.
          if (pieces.length > 1) this.shot = shot;
        } catch (error) {
          const reason = error instanceof ScreenshotError ? error.reason : "failed";
          this.send({ frame: "screenshot_failed", shot_id: frame.shot_id, reason });
        }
        return;
      }
      case "screenshot_more": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        const kept = this.shot;
        if (!kept || kept.shotId !== frame.shot_id || frame.piece >= kept.pieces.length) {
          this.send({ frame: "screenshot_failed", shot_id: frame.shot_id, reason: "failed" });
          return;
        }
        if (frame.piece === kept.pieces.length - 1) this.shot = null;
        this.sendShotPiece(kept, frame.piece);
        return;
      }
      case "tab_new":
      case "tab_switch":
      case "tab_close":
      case "tabs": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        // Tabs never change while a document is being replaced.
        if (this.navigating && frame.frame !== "tabs") {
          this.send({ frame: "tab_failed", tab_req: frame.tab_req, reason: "busy" });
          return;
        }
        try {
          let state: TabsState;
          if (frame.frame === "tab_new") state = await this.session.tabNew();
          else if (frame.frame === "tab_switch") state = await this.session.tabSwitch(frame.tab);
          else if (frame.frame === "tab_close") state = await this.session.tabClose(frame.tab);
          else state = this.session.tabs();
          this.send({ frame: "tabs_state", tab_req: frame.tab_req, active: state.active, tabs: state.tabs });
        } catch (error) {
          const reason = error instanceof TabError ? error.reason : "failed";
          this.send({ frame: "tab_failed", tab_req: frame.tab_req, reason });
        }
        return;
      }
      case "dialogs": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        const { dialogs, truncated } = this.session.takeDialogs();
        this.send({ frame: "dialogs_seen", dlg_id: frame.dlg_id, dialogs, truncated });
        return;
      }
      case "upload": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        if (this.navigating) {
          this.send({ frame: "upload_failed", up_id: frame.up_id, reason: "busy" });
          return;
        }
        this.navigating = true;
        void this.runUpload(this.session, frame.up_id, frame.ref, frame.path, frame.target);
        return;
      }
      case "wait_for": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        // One at a time, and never while the document is being replaced.
        if (this.waiting || this.navigating) {
          this.send({ frame: "wait_failed", wait_id: frame.wait_id });
          return;
        }
        // Outside the queue: ping and shutdown stay responsive.
        this.waiting = true;
        void this.runWait(this.session, frame.wait_id, frame.text, frame.appear, frame.timeout_ms);
        return;
      }
      case "verify": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        // A document being replaced cannot be verified.
        if (this.navigating) {
          this.send({ frame: "verification_failed", ver_id: frame.ver_id });
          return;
        }
        try {
          const { tab, url, results } = await this.session.verify(frame.probes);
          if (results.length !== frame.probes.length) throw new Error("one result per probe");
          this.send({ frame: "verified", ver_id: frame.ver_id, tab, url, results });
        } catch {
          this.send({ frame: "verification_failed", ver_id: frame.ver_id });
        }
        return;
      }
      case "observe": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        try {
          const { tab, url, snapshot } = await this.session.observe();
          this.send({ frame: "observed", obs_id: frame.obs_id, tab, url, truncated: snapshot.truncated, nodes: snapshot.nodes });
        } catch {
          this.send({ frame: "observation_failed", obs_id: frame.obs_id });
        }
        return;
      }
      case "challenge": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        // A document being replaced is not classified: the host asks again.
        if (this.navigating) {
          this.send({ frame: "challenge_failed", chl_id: frame.chl_id, reason: "busy" });
          return;
        }
        try {
          const { tab, url, report } = await this.session.challenge(frame.url, frame.status);
          if (Buffer.byteLength(url) > MAX_URL_BYTES) throw new Error("the page URL is too long");
          this.send({ frame: "challenge_report", chl_id: frame.chl_id, tab, url, kind: report.kind, signals: report.signals, truncated: report.truncated });
        } catch (error) {
          this.send({ frame: "challenge_failed", chl_id: frame.chl_id, reason: error instanceof ChallengeBusy ? "busy" : "failed" });
        }
        return;
      }
      case "outline": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        // A document being replaced cannot be outlined.
        if (this.navigating) {
          this.send({ frame: "outline_failed", out_id: frame.out_id });
          return;
        }
        try {
          const { tab, url, outline } = await this.session.outline();
          if (Buffer.byteLength(url) > MAX_URL_BYTES) throw new Error("the page URL is too long");
          this.send({ frame: "outlined", out_id: frame.out_id, tab, url, truncated: outline.truncated, nodes: outline.nodes });
        } catch {
          this.send({ frame: "outline_failed", out_id: frame.out_id });
        }
        return;
      }
      case "extract_schema": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        if (this.navigating) {
          this.send({ frame: "schema_extraction_failed", xs_id: frame.xs_id });
          return;
        }
        try {
          const { tab, url, truncated, values } = await this.session.extractSchema(frame.fields);
          if (Buffer.byteLength(url) > MAX_URL_BYTES) throw new Error("the page URL is too long");
          if (values.length !== frame.fields.length) throw new Error("one value per field");
          this.send({ frame: "schema_extracted", xs_id: frame.xs_id, tab, url, truncated, values });
        } catch {
          this.send({ frame: "schema_extraction_failed", xs_id: frame.xs_id });
        }
        return;
      }
      case "navigate": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        if (this.navigating) {
          this.send({ frame: "navigation_failed", nav_id: frame.nav_id, reason: "busy" });
          return;
        }
        this.navigating = true;
        void this.runNavigation(this.session, frame.nav_id, frame.url);
        return;
      }
      case "fetch_text": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        if (this.navigating) {
          this.send({ frame: "fetch_failed", fetch_id: frame.fetch_id, reason: "busy" });
          return;
        }
        this.navigating = true;
        void this.runFetch(this.session, frame.fetch_id, frame.url);
        return;
      }
      case "ping":
        this.send({ frame: "pong", nonce: frame.nonce });
        return;
      case "shutdown":
        return this.close(0, { frame: "bye" });
      case "launch": {
        if (this.state !== "ready" || this.launchedOnce) return this.fail("not_ready");
        this.launchedOnce = true;
        if (launchRefusal(frame) !== null) return this.fail("launch_refused");
        let session: EngineSession;
        try {
          session = await this.launcher.launch(frame, this.policy);
        } catch (error) {
          this.diagnose(`orcel-browser-worker: launch failed: ${describeLaunchError(error)}`);
          return this.fail("launch_failed");
        }
        // A shutdown or violation may not interleave (frames are queued),
        // so the worker is still `ready` here.
        this.session = session;
        this.state = "launched";
        session.onUnexpectedExit(() => {
          if (this.session === session) {
            this.session = null;
            void this.enqueue(() => this.fail("engine_exited"));
          }
        });
        this.send({ frame: "launched" });
        return;
      }
    }
  }

  private async runNavigation(session: EngineSession, navId: number, url: string): Promise<void> {
    let outcome: WorkerFrame;
    try {
      const result = await session.navigate(url);
      outcome = { frame: "navigated", nav_id: navId, tab: result.tab, url: result.url, status: result.status };
    } catch (error) {
      const reason: NavigationFailure = error instanceof NavigationError ? error.reason : "failed";
      outcome = { frame: "navigation_failed", nav_id: navId, reason };
    }
    this.navigating = false;
    if (this.state === "launched" && this.session === session) this.settle(outcome, { frame: "navigation_failed", nav_id: navId, reason: "failed" });
  }

  private async runFetch(session: EngineSession, fetchId: number, url: string): Promise<void> {
    let outcome: WorkerFrame;
    try {
      const result = await session.fetchText(url);
      outcome = { frame: "fetched_text", fetch_id: fetchId, ...result };
    } catch (error) {
      const reason: NavigationFailure = error instanceof NavigationError ? error.reason : "failed";
      outcome = { frame: "fetch_failed", fetch_id: fetchId, reason };
    }
    this.navigating = false;
    if (this.state === "launched" && this.session === session) this.settle(outcome, { frame: "fetch_failed", fetch_id: fetchId, reason: "failed" });
  }

  private async runDownload(session: EngineSession, dlId: number, ref: string, path: string, target?: ApprovedTarget): Promise<void> {
    let outcome: WorkerFrame;
    try {
      const result = await session.download(ref, path, target);
      outcome = { frame: "downloaded", dl_id: dlId, ...result };
    } catch (error) {
      const reason: NavigationFailure = error instanceof NavigationError ? error.reason : "failed";
      outcome = { frame: "download_failed", dl_id: dlId, reason };
    }
    this.navigating = false;
    if (this.state === "launched" && this.session === session) this.settle(outcome, { frame: "download_failed", dl_id: dlId, reason: "failed" });
  }

  private async runActivation(session: EngineSession, actId: number, ref: string, target?: ApprovedTarget): Promise<void> {
    let outcome: WorkerFrame;
    try {
      const result = await session.activate(ref, target);
      outcome = { frame: "activated", act_id: actId, tab: result.tab, url: result.url, status: result.status };
    } catch (error) {
      const reason: NavigationFailure = error instanceof NavigationError ? error.reason : "failed";
      outcome = { frame: "activation_failed", act_id: actId, reason };
    }
    this.navigating = false;
    if (this.state === "launched" && this.session === session) this.settle(outcome, { frame: "activation_failed", act_id: actId, reason: "failed" });
  }

  private async runUpload(session: EngineSession, upId: number, ref: string, path: string, target?: ApprovedTarget): Promise<void> {
    let outcome: WorkerFrame;
    try {
      const { tab, url } = await session.upload(ref, path, target);
      outcome = { frame: "uploaded", up_id: upId, tab, url };
    } catch (error) {
      const reason: NavigationFailure = error instanceof NavigationError ? error.reason : "failed";
      outcome = { frame: "upload_failed", up_id: upId, reason };
    }
    this.navigating = false;
    if (this.state === "launched" && this.session === session) this.settle(outcome, { frame: "upload_failed", up_id: upId, reason: "failed" });
  }

  private async runWait(session: EngineSession, waitId: number, text: string, appear: boolean, timeoutMs: number): Promise<void> {
    let outcome: WorkerFrame;
    try {
      const { tab, url, met } = await session.waitForText(text, appear, timeoutMs);
      outcome = { frame: "waited", wait_id: waitId, tab, url, met };
    } catch {
      outcome = { frame: "wait_failed", wait_id: waitId };
    }
    this.waiting = false;
    if (this.state === "launched" && this.session === session) this.settle(outcome, { frame: "wait_failed", wait_id: waitId });
  }

  private async runFormAction(
    session: EngineSession,
    formId: number,
    ref: string,
    act: FormAction,
    target?: ApprovedTarget,
    acceptConfirm?: string
  ): Promise<void> {
    let outcome: WorkerFrame;
    try {
      const { tab, url, navigated } = await session.formAction(ref, act, target, acceptConfirm);
      // SG-000122 slice A6: only an Enter reports a committed document.
      outcome = act.action === "enter" ? { frame: "form_done", form_id: formId, tab, url, navigated: navigated === true } : { frame: "form_done", form_id: formId, tab, url };
    } catch (error) {
      const reason: NavigationFailure = error instanceof NavigationError ? error.reason : "failed";
      outcome = { frame: "form_failed", form_id: formId, reason };
    }
    this.navigating = false;
    if (this.state === "launched" && this.session === session) this.settle(outcome, { frame: "form_failed", form_id: formId, reason: "failed" });
  }

  private async runExecution(session: EngineSession, execId: number, tool: string, fields: ExecField[]): Promise<void> {
    let outcome: WorkerFrame;
    this.executing = true;
    try {
      const result = await session.execute(tool, fields);
      outcome = {
        frame: "executed",
        exec_id: execId,
        tab: result.tab,
        url: result.url,
        status: result.status,
        structured: result.structured,
        structured_complete: result.structuredComplete
      };
    } catch (error) {
      const reason: NavigationFailure = error instanceof NavigationError ? error.reason : "failed";
      outcome = { frame: "execution_failed", exec_id: execId, reason };
    }
    this.executing = false;
    this.navigating = false;
    if (this.state === "launched" && this.session === session) this.settle(outcome, { frame: "execution_failed", exec_id: execId, reason: "failed" });
  }

  private sendShotPiece(shot: HeldShot, piece: number): void {
    this.send({
      frame: "screenshot_piece",
      shot_id: shot.shotId,
      tab: shot.tab,
      url: shot.url,
      piece,
      total: shot.pieces.length,
      width: shot.width,
      height: shot.height,
      bytes: shot.bytes,
      truncated: shot.truncated,
      data: shot.pieces[piece] ?? ""
    });
  }

  /// Send an operation's outcome from a background run. If it cannot be
  /// sent (a frame past the size bound), the operation reports a typed
  /// failure instead; nothing escapes as an unhandled rejection.
  private settle(outcome: WorkerFrame, failure: WorkerFrame): void {
    try {
      this.send(outcome);
    } catch {
      try {
        this.send(failure);
      } catch {
        // The channel is gone; the host sees the end of output.
      }
    }
  }

  private fail(code: ErrorCode): Promise<void> {
    return this.close(1, { frame: "error", code });
  }

  private async close(exitCode: number, last: WorkerFrame | null): Promise<void> {
    if (this.state === "closed") return;
    this.state = "closed";
    for (const [, waiter] of this.pending) {
      clearTimeout(waiter.timer);
      waiter.resolve(false);
    }
    this.pending.clear();
    // From here on nothing can throw out of close: the engine is closed best
    // effort and the worker always finishes exactly once.
    const session = this.session;
    this.session = null;
    if (session) {
      try {
        await session.close();
      } catch {
        // The engine is gone either way; the host's Job Object reaps it.
      }
    }
    try {
      if (last) this.send(last);
    } finally {
      this.finish(exitCode);
    }
  }
}

/// #438: the launch exception's name and the first line of its message, on
/// one line, without control, line-separator or bidi characters, at most
/// 1024 code points. Never throws, whatever was thrown.
export function describeLaunchError(error: unknown): string {
  let text: string;
  try {
    const name = error instanceof Error ? error.name : typeof error;
    const message = error instanceof Error ? error.message : String(error);
    text = `${name}: ${message.split(/\r?\n/, 1)[0] ?? ""}`;
  } catch {
    text = "unprintable";
  }
  const clean = text.replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u2028-\u202e\u2066-\u2069]/g, " ");
  const points = Array.from(clean);
  return points.length > 1024 ? `${points.slice(0, 1024).join("")}…` : clean;
}
