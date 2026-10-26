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
  type WorkerFrame
} from "./protocol.js";
import type { RouteQuery } from "./routing.js";
import type { BoundedSnapshot } from "./snapshot.js";
import type { VerifyProbe, VerifyResult } from "./verify.js";

export type LaunchSpec = Extract<HostFrame, { frame: "launch" }>;

/// How long the worker waits for a host route decision before refusing.
export const ROUTE_DECISION_TIMEOUT_MS = 10_000;

/// The host's answer to a described request.
export interface RoutePolicy {
  decide(query: RouteQuery): Promise<boolean>;
}

export class NavigationError extends Error {
  constructor(readonly reason: NavigationFailure) {
    super(reason);
  }
}

export interface EngineSession {
  close(): Promise<void>;
  /// Navigate the primary page; rejects with NavigationError.
  navigate(url: string): Promise<{ url: string; status: number }>;
  /// Navigate the primary page like `navigate` (the same routes and host
  /// decisions) and return the document's text when it is plain text or
  /// XML, bounded to one frame; rejects with NavigationError.
  fetchText(url: string): Promise<{ url: string; status: number; media: string; text: string; truncated: boolean }>;
  /// A bounded, value-free accessibility snapshot of the primary page.
  observe(): Promise<{ url: string; snapshot: BoundedSnapshot }>;
  /// The primary page's declarative WebMCP tools, read without running
  /// page script; bounded so the reply frame fits.
  discover(discId: number): Promise<{ url: string; truncated: boolean; tools: DeclaredTool[] }>;
  /// The primary page's rendered content as Markdown, read from an engine
  /// snapshot without running page script, in frame-sized pieces.
  extract(options: { links: boolean; images: boolean }): Promise<{ url: string; truncated: boolean; pieces: Piece[] }>;
  /// Fill the declared tool form with host-validated fields, click its
  /// default submit button and wait for the resulting document; returns it
  /// with its structured data. Rejects with NavigationError.
  execute(tool: string, fields: ExecField[]): Promise<{ url: string; status: number; structured: string[]; structuredComplete: boolean }>;
  /// Click the element with this snapshot ref (or, when the ref went
  /// stale, the one element matching the approved target) and wait for the
  /// resulting navigation to load; rejects with NavigationError.
  activate(ref: string, target?: ApprovedTarget): Promise<{ url: string; status: number }>;
  /// Click the element with this snapshot ref (or the one matching the
  /// approved target), expect a download, and save it to `path` (which must
  /// not exist); rejects with NavigationError.
  download(ref: string, path: string, target?: ApprovedTarget): Promise<{ url: string; name: string; media: string; bytes: number }>;
  /// BR-07: read-only probes of the primary page, one result per probe.
  verify(probes: VerifyProbe[]): Promise<{ url: string; results: VerifyResult[] }>;
  /// Called once if the engine goes away without `close`.
  onUnexpectedExit(listener: () => void): void;
}

export interface Launcher {
  launch(spec: LaunchSpec, policy: RoutePolicy): Promise<EngineSession>;
}

export type WorkerState = "awaiting_hello" | "ready" | "launched" | "closed";

export class Worker {
  private state: WorkerState = "awaiting_hello";
  /// The last extraction's remaining pieces, until the host has read them.
  private extraction: { extId: number; url: string; truncated: boolean; pieces: Piece[] } | null = null;
  private session: EngineSession | null = null;
  private launchedOnce = false;
  private queue: Promise<void> = Promise.resolve();
  private navigating = false;
  private nextRequestId = 0;
  private readonly pending = new Map<number, { resolve: (allow: boolean) => void; timer: NodeJS.Timeout }>();
  private readonly policy: RoutePolicy = { decide: (query) => this.ask(query) };

  constructor(
    private readonly launcher: Launcher,
    private readonly send: (frame: WorkerFrame) => void,
    private readonly finish: (exitCode: number) => void
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
      const detail = query.detail ?? { method: "GET", contentType: "", body: "", bodyBytes: 0 };
      this.send({
        frame: "route_request",
        request_id: requestId,
        kind: query.kind,
        url: query.url,
        origin: query.origin,
        method: detail.method,
        content_type: detail.contentType,
        body: detail.body,
        body_bytes: detail.bodyBytes
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
          const { url, truncated, tools } = await this.session.discover(frame.disc_id);
          this.send({ frame: "discovered", disc_id: frame.disc_id, url, truncated, tools });
        } catch {
          this.send({ frame: "discovery_failed", disc_id: frame.disc_id });
        }
        return;
      }
      case "extract": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        this.extraction = null;
        try {
          const { url, truncated, pieces } = await this.session.extract({ links: frame.links, images: frame.images });
          if (pieces.length === 0 || pieces.length > MAX_EXTRACT_PIECES) throw new Error("piece count out of range");
          // A page can give itself a long URL (pushState); the pieces are
          // sized for one of at most MAX_URL_BYTES.
          if (Buffer.byteLength(url) > MAX_URL_BYTES) throw new Error("the page URL is too long");
          const first = pieces[0] ?? { chunk: 0, content: "" };
          this.send({ frame: "extracted", ext_id: frame.ext_id, url, truncated, piece: 0, total: pieces.length, chunk: first.chunk, content: first.content });
          // Kept only until the host has read every piece.
          if (pieces.length > 1) this.extraction = { extId: frame.ext_id, url, truncated, pieces };
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
          url: kept.url,
          truncated: kept.truncated,
          piece: frame.piece,
          total: kept.pieces.length,
          chunk: piece.chunk,
          content: piece.content
        });
        return;
      }
      case "verify": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        try {
          const { url, results } = await this.session.verify(frame.probes);
          if (results.length !== frame.probes.length) throw new Error("one result per probe");
          this.send({ frame: "verified", ver_id: frame.ver_id, url, results });
        } catch {
          this.send({ frame: "verification_failed", ver_id: frame.ver_id });
        }
        return;
      }
      case "observe": {
        if (this.state !== "launched" || !this.session) return this.fail("not_ready");
        try {
          const { url, snapshot } = await this.session.observe();
          this.send({ frame: "observed", obs_id: frame.obs_id, url, truncated: snapshot.truncated, nodes: snapshot.nodes });
        } catch {
          this.send({ frame: "observation_failed", obs_id: frame.obs_id });
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
        } catch {
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
      outcome = { frame: "navigated", nav_id: navId, url: result.url, status: result.status };
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
      outcome = { frame: "activated", act_id: actId, url: result.url, status: result.status };
    } catch (error) {
      const reason: NavigationFailure = error instanceof NavigationError ? error.reason : "failed";
      outcome = { frame: "activation_failed", act_id: actId, reason };
    }
    this.navigating = false;
    if (this.state === "launched" && this.session === session) this.settle(outcome, { frame: "activation_failed", act_id: actId, reason: "failed" });
  }

  private async runExecution(session: EngineSession, execId: number, tool: string, fields: ExecField[]): Promise<void> {
    let outcome: WorkerFrame;
    try {
      const result = await session.execute(tool, fields);
      outcome = {
        frame: "executed",
        exec_id: execId,
        url: result.url,
        status: result.status,
        structured: result.structured,
        structured_complete: result.structuredComplete
      };
    } catch (error) {
      const reason: NavigationFailure = error instanceof NavigationError ? error.reason : "failed";
      outcome = { frame: "execution_failed", exec_id: execId, reason };
    }
    this.navigating = false;
    if (this.state === "launched" && this.session === session) this.settle(outcome, { frame: "execution_failed", exec_id: execId, reason: "failed" });
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
