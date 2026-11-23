// SG-000135 OB-03: a bounded PNG of the active tab's page, with every
// secret field masked before capture (WPB-01 capture contract).
//
// The capture is Playwright's `page.screenshot` of the session's own page
// over the existing pipe: never another session's page, another app or the
// desktop (Orcel's desktop window capture is SG-000080's, and is never used
// here). Orcel runs no script of its own in the page; the masks are
// Playwright's overlay, which Playwright inserts into the page's DOM for the
// capture and removes afterwards, so the page can see it while it exists.
//
// Residual limits of the mask (docs/orcel/implementation-readiness/prep/
// OB01_E2E.md): fields inside closed shadow roots, secret text drawn on a
// canvas or shown as ordinary text, and a page script that removes or hides
// the overlay during the capture are not masked. Fields in open shadow roots
// and in every frame present right before the capture are; a capture during
// which the set of frames or of secret fields changed is refused.
//
// Donor provenance (docs/orcel/agent_browser_provenance.json and
// docs/orcel/browseros_provenance.json):
// - `fullPageClip` ports `full_page_clip_size` from vercel-labs/agent-browser
//   cli/src/native/screenshot.rs (blob
//   22bce7de24c3104bac86e162611128b6cd6d654a at
//   b06e2533ba9b3823b8a96c859d455cb55f4d7893; Apache-2.0, notice
//   docs/orcel/notices/agent-browser-Apache-2.0.txt). Orcel's changes: the
//   clip is bounded to MAX_SCREENSHOT_WIDTH x MAX_SCREENSHOT_HEIGHT CSS
//   pixels and says when it cut the page; a missing or non-finite size falls
//   back to the viewport-sized default, never to an unbounded one.
// - `runExclusive` adapts `runExclusiveScreenshotCapture` from
//   browseros-ai/BrowserOS packages/browseros-agent/packages/browser-core/
//   src/core/screenshot-queue.ts (blob cf9e8d3da9ba7d03fc0317db056380b79e3a4d3d
//   at bd725831273884c4b1aee8425975afa122f720f2;
//   AGPL-3.0-or-later upstream, notice docs/orcel/notices/browseros-AGPL-3.0.txt,
//   owner-asserted authorization). Orcel's changes: keyed by any object (the
//   page), not a CDP session; no annotation overlay.

import { existingSecretMemory, type SecretMemory } from "./secret-memory.js";

/// The largest PNG one screenshot may be, in bytes (mirrors the host).
export const MAX_SCREENSHOT_BYTES = 2 * 1024 * 1024;
/// The largest screenshot, in CSS pixels at scale 1 (mirrors the host).
export const MAX_SCREENSHOT_WIDTH = 2048;
export const MAX_SCREENSHOT_HEIGHT = 4096;
/// One piece's base64 text on the wire, a multiple of 4 so every piece
/// decodes on its own (mirrors the host).
export const MAX_SCREENSHOT_PIECE_CHARS = 48 * 1024;
/// The most pieces one screenshot is sent in (mirrors the host).
export const MAX_SCREENSHOT_PIECES = 64;
/// The longest Playwright's own capture may take.
export const SCREENSHOT_TIMEOUT_MS = 10_000;
/// The whole screenshot: waiting for the page's turn, the layout metrics, the
/// census, the capture and the census again. The host ends the worker's
/// lifetime when no reply came in its `WORKER_SCREENSHOT_TIMEOUT` (20 s,
/// worker_launch.rs), so this stays well under it. A capture that takes its
/// full 10 s leaves 5 s for everything else.
export const SCREENSHOT_BUDGET_MS = 15_000;
/// What the capture leaves of the budget for the census after it: a picture
/// that cannot be checked is never returned.
export const CENSUS_RESERVE_MS = 1_000;
/// What a masked field is painted with: opaque black.
export const MASK_COLOR = "#000000";

/// Every field whose content is a secret: password inputs, the secret
/// `autocomplete` tokens (passwords, one-time codes, card number, security
/// code and expiry), and inputs or textareas whose name or id suggests a
/// secret. It mirrors (and widens) the refusal of secret fields for form
/// actions (`actions/form.ts`): a field Orcel never types into is never shown.
export const SECRET_FIELD_SELECTOR = [
  'input[type="password" i]',
  // A text field drawn as dots by a style (inline only: a stylesheet rule
  // is not visible to a selector).
  '[style*="text-security" i]',
  // Rich editors can hold anything: every editable region is masked.
  '[contenteditable]:not([contenteditable="false" i])',
  ...["current-password", "new-password", "one-time-code", "cc-number", "cc-csc", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-name", "cc-type"].map(
    (token) => `[autocomplete~="${token}" i]`
  ),
  ...["pass", "pwd", "otp", "cvc", "cvv", "csc", "cc-", "cc_", "ccnum", "secret", "token", "card", "pin", "ssn", "iban", "security"].flatMap((part) => [
    `input[name*="${part}" i]`,
    `input[id*="${part}" i]`,
    `textarea[name*="${part}" i]`,
    `textarea[id*="${part}" i]`
  ]),
  // SG-000135 OB-07b: an accessible label or placeholder naming a password
  // or code (a password field a page shows in clear keeps its label).
  ...["password", "passcode", "passphrase", "one-time", "pin"].flatMap((part) => [`input[aria-label*="${part}" i]`, `input[placeholder*="${part}" i]`])
].join(", ");

/// SG-000135 OB-07b: the mask for a page that remembers password fields
/// (`secret-memory.ts`): the fixed selector plus every remembered name and
/// id, so a password field the page now shows in clear stays masked.
export function maskSelector(memory?: SecretMemory): string {
  if (memory === undefined || memory.names.size === 0) return SECRET_FIELD_SELECTOR;
  const quote = (value: string) => `"${value.replace(/["\\]/g, "\\$&").replace(/[\u0000-\u001f\u007f]/g, " ")}"`;
  const remembered = [...memory.names].flatMap((entry) => {
    const at = entry.indexOf(":");
    const attr = entry.slice(0, at);
    const value = entry.slice(at + 1);
    return attr === "name" || attr === "id" ? [`input[${attr}=${quote(value)} i]`] : [];
  });
  return [SECRET_FIELD_SELECTOR, ...remembered].join(", ");
}

/// Why a screenshot failed, on the wire.
export type ScreenshotFailure = "busy" | "failed" | "oversized";

export class ScreenshotError extends Error {
  constructor(readonly reason: ScreenshotFailure) {
    super(reason);
  }
}

/// Where a screenshot was when it failed.
export type ScreenshotStage = "queue" | "metrics" | "census_before" | "capture" | "census_after";

const ERROR_CODES: ReadonlySet<string> = new Set(["TimeoutError", "TargetClosedError", "AbortError", "ProtocolError", "Error"]);

/// An error's class as one of a closed set. The name can come from another
/// process and the message can carry page content or a URL, so anything else
/// is "other".
export function errorCode(error: unknown): string {
  const name = error instanceof Error ? error.name : "";
  return ERROR_CODES.has(name) ? name : "other";
}

/// One line on stderr, like the worker's other diagnostics: closed names only.
function reportToStderr(stage: ScreenshotStage, code: string): void {
  process.stderr.write(`orcel-browser-worker: screenshot failed at ${stage}: ${code}\n`);
}

/// The one budget every step of a screenshot spends.
///
/// Not every step can be given a timeout: counting elements, an element's
/// own box and a CDP command have none, and a stalled renderer answers none
/// of them. So `within` answers the caller on time whatever the work does,
/// and the work, which is not cancelled, finds the budget over at its next
/// step and stops there. Its late result is dropped.
export class ScreenshotBudget {
  private stage: ScreenshotStage = "queue";
  private over = false;
  private reported = false;
  private readonly deadline: number;

  constructor(
    ms: number = SCREENSHOT_BUDGET_MS,
    private readonly report: (stage: ScreenshotStage, code: string) => void = reportToStderr,
    private readonly clock: () => number = () => performance.now()
  ) {
    this.deadline = clock() + ms;
  }

  /// The whole milliseconds left, at least 1 (Playwright takes 0 as "no
  /// timeout"), less what is kept back for later. With none left, the
  /// screenshot has failed.
  remaining(reserve = 0): number {
    const left = Math.floor(this.deadline - this.clock()) - reserve;
    if (this.over || left < 1) throw this.failure("budget");
    return left;
  }

  /// Start a step, unless the budget is over.
  enter(stage: ScreenshotStage): void {
    this.remaining();
    this.stage = stage;
  }

  /// The typed failure for this screenshot. Its reason is reported once, the
  /// first time: work that fails after the budget ended adds nothing.
  failure(code: string): ScreenshotError {
    if (!this.reported) {
      this.reported = true;
      this.report(this.stage, code);
    }
    return new ScreenshotError("failed");
  }

  /// What `work` gives within the budget, else a typed failure.
  async within<T>(work: Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        this.over = true;
        reject(this.failure("budget"));
      }, Math.max(0, this.deadline - this.clock()));
    });
    try {
      const done = await Promise.race([work, deadline]);
      // Work that ended late, in a process too busy to run the timer.
      this.remaining();
      return done;
    } finally {
      clearTimeout(timer);
    }
  }
}

/// A full-page clip: the page's CSS content size, bounded, and whether the
/// bound cut it. `metrics` is CDP `Page.getLayoutMetrics`'s result.
export function fullPageClip(metrics: unknown): { clip: { x: number; y: number; width: number; height: number }; truncated: boolean } {
  const size = pick(metrics, "cssContentSize") ?? pick(metrics, "contentSize");
  const dimension = (name: string, fallback: number): number => {
    const value = size !== undefined ? (size as Record<string, unknown>)[name] : undefined;
    return typeof value === "number" && Number.isFinite(value) && value >= 1 ? Math.ceil(value) : fallback;
  };
  const width = dimension("width", 1280);
  const height = dimension("height", 720);
  return {
    clip: { x: 0, y: 0, width: Math.min(width, MAX_SCREENSHOT_WIDTH), height: Math.min(height, MAX_SCREENSHOT_HEIGHT) },
    truncated: width > MAX_SCREENSHOT_WIDTH || height > MAX_SCREENSHOT_HEIGHT
  };
}

function pick(value: unknown, key: string): unknown {
  if (typeof value !== "object" || value === null) return undefined;
  const found = (value as Record<string, unknown>)[key];
  return typeof found === "object" && found !== null ? found : undefined;
}

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/// A PNG's width and height from its IHDR chunk, or null when the bytes are
/// not a PNG that starts with one.
export function pngSize(png: Buffer): { width: number; height: number } | null {
  if (png.length < 24 || !png.subarray(0, 8).equals(PNG_SIGNATURE)) return null;
  if (png.readUInt32BE(8) !== 13 || png.toString("latin1", 12, 16) !== "IHDR") return null;
  return { width: png.readUInt32BE(16), height: png.readUInt32BE(20) };
}

/// Check a captured PNG against the bounds; returns its size or throws a
/// typed failure.
export function checkCapture(png: Buffer): { width: number; height: number } {
  const size = pngSize(png);
  if (size === null || size.width < 1 || size.height < 1) throw new ScreenshotError("failed");
  if (png.length > MAX_SCREENSHOT_BYTES || size.width > MAX_SCREENSHOT_WIDTH || size.height > MAX_SCREENSHOT_HEIGHT) {
    throw new ScreenshotError("oversized");
  }
  return size;
}

/// Split a PNG into base64 pieces of at most MAX_SCREENSHOT_PIECE_CHARS,
/// each the encoding of its own slice of bytes.
export function toBase64Pieces(png: Buffer): string[] {
  const raw = (MAX_SCREENSHOT_PIECE_CHARS / 4) * 3;
  const pieces: string[] = [];
  for (let start = 0; start < png.length; start += raw) pieces.push(png.subarray(start, start + raw).toString("base64"));
  if (pieces.length === 0 || pieces.length > MAX_SCREENSHOT_PIECES) throw new ScreenshotError("oversized");
  return pieces;
}

const queues = new WeakMap<object, Promise<void>>();

/// Run captures of one page one at a time.
export async function runExclusive<T>(key: object, task: () => Promise<T>): Promise<T> {
  const previous = queues.get(key) ?? Promise.resolve();
  let release = () => {};
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  const tail = previous.catch(() => {}).then(() => current);
  queues.set(key, tail);
  await previous.catch(() => {});
  try {
    return await task();
  } finally {
    release();
    if (queues.get(key) === tail) queues.delete(key);
  }
}

/// Run `task` alone on `key`, answering within `budget`. The answer is on time
/// even when the task is stuck, but the key stays held until the task itself
/// ends: nothing else captures the page while a late capture may still be
/// running or removing its masks. A task whose turn comes too late does nothing.
export function runBounded<T>(key: object, budget: ScreenshotBudget, task: () => Promise<T>): Promise<T> {
  return budget.within(
    runExclusive(key, async () => {
      budget.remaining();
      return task();
    })
  );
}

/// The page surface a screenshot uses (a Playwright `Page`, or a test stub).
export interface ShotBox {
  x: number;
  y: number;
  width: number;
  height: number;
}
export interface ShotElement {
  boundingBox(options: { timeout: number }): Promise<ShotBox | null>;
}
export interface ShotLocator {
  all(): Promise<ShotElement[]>;
}

/// The most secret fields per frame whose places are compared before and
/// after a capture; a frame with more is refused.
export const MAX_CENSUS_FIELDS = 256;

/// Where each secret field of one frame is (rounded CSS pixels; "none" for
/// one not rendered), in document order.
async function placesOf(locator: ShotLocator, budget: ScreenshotBudget): Promise<string[]> {
  const elements = await locator.all();
  if (elements.length > MAX_CENSUS_FIELDS) throw new ScreenshotError("failed");
  const places: string[] = [];
  for (const element of elements) {
    // The timeout covers only finding the element; `within` covers its box.
    const box = await element.boundingBox({ timeout: budget.remaining() });
    places.push(box === null ? "none" : [box.x, box.y, box.width, box.height].map((value) => Math.round(value)).join(","));
  }
  return places;
}
export interface ShotFrame {
  locator(selector: string): ShotLocator;
}
export interface ShotPage {
  frames(): ShotFrame[];
  screenshot(options: Record<string, unknown>): Promise<Buffer>;
}

/// Capture `page`: the viewport, or with `clip` (a bounded full-page
/// clip) the page from its top; every secret field in every frame masked.
/// A failed capture (masking included) is a typed failure, never an
/// unmasked picture. The census, the capture and the second census share
/// `budget`, and no picture is returned unless both were read and equal.
/// The caller holds the page and answers on time (`runBounded`).
export async function capturePng(
  page: ShotPage,
  clip: { x: number; y: number; width: number; height: number } | undefined,
  budget: ScreenshotBudget
): Promise<{ png: Buffer; width: number; height: number }> {
  // The frames and where each secret field in each is, right before the
  // capture (Playwright resolves the mask locators inside the capture
  // itself). Places, not counts: a field added and another removed during
  // the capture still differ.
  const frames = page.frames();
  const selector = maskSelector(existingSecretMemory(page));
  const mask = frames.map((frame) => frame.locator(selector));
  const census = async (): Promise<string> => {
    try {
      return JSON.stringify(await Promise.all(mask.map((locator) => placesOf(locator, budget))));
    } catch (error) {
      throw budget.failure(errorCode(error));
    }
  };
  budget.enter("census_before");
  const before = await census();
  budget.enter("capture");
  const timeout = Math.min(SCREENSHOT_TIMEOUT_MS, budget.remaining(CENSUS_RESERVE_MS));
  let png: Buffer;
  try {
    png = await page.screenshot({
      type: "png",
      ...(clip ? { fullPage: true, clip } : {}),
      mask,
      maskColor: MASK_COLOR,
      animations: "disabled",
      caret: "hide",
      scale: "css",
      timeout
    });
  } catch (error) {
    throw budget.failure(errorCode(error));
  }
  budget.enter("census_after");
  // A frame attached or detached, or a secret field added or removed,
  // while the capture ran: it may hold an unmasked field. Refused.
  const after = page.frames();
  const sameFrames = after.length === frames.length && after.every((frame, index) => frame === frames[index]);
  if (!sameFrames || (await census()) !== before) {
    throw new ScreenshotError("busy");
  }
  return { png, ...checkCapture(png) };
}
