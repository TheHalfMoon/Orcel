// SG-000135 OB-03: a bounded PNG of the active tab's page, with every
// secret field masked before capture (WPB-01 capture contract).
//
// The capture is Playwright's `page.screenshot` of the session's own page
// over the existing pipe: never another session's page, another app or the
// desktop (Orcel's desktop window capture is SG-000080's, and is never used
// here). No page script runs: the masks are Playwright's own overlay in its
// utility world, as its locators and accessibility snapshots are.
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
/// The worker's own budget for one capture, under the host's deadline.
export const SCREENSHOT_TIMEOUT_MS = 10_000;
/// What a masked field is painted with: opaque black.
export const MASK_COLOR = "#000000";

/// Every field whose content is a secret: password inputs, the secret
/// `autocomplete` tokens (passwords, one-time codes, card number, security
/// code and expiry), and inputs or textareas whose name or id suggests a
/// secret. It mirrors (and widens) the refusal of secret fields for form
/// actions (`actions/form.ts`): a field Orcel never types into is never shown.
export const SECRET_FIELD_SELECTOR = [
  'input[type="password" i]',
  ...["current-password", "new-password", "one-time-code", "cc-number", "cc-csc", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-name", "cc-type"].map(
    (token) => `[autocomplete~="${token}" i]`
  ),
  ...["pass", "pwd", "otp", "cvc", "cvv", "csc", "secret", "token", "card"].flatMap((part) => [
    `input[name*="${part}" i]`,
    `input[id*="${part}" i]`,
    `textarea[name*="${part}" i]`,
    `textarea[id*="${part}" i]`
  ])
].join(", ");

/// Why a screenshot failed, on the wire.
export type ScreenshotFailure = "busy" | "failed" | "oversized";

export class ScreenshotError extends Error {
  constructor(readonly reason: ScreenshotFailure) {
    super(reason);
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

/// The page surface a screenshot uses (a Playwright `Page`, or a test stub).
export interface ShotFrame {
  locator(selector: string): unknown;
}
export interface ShotPage {
  frames(): ShotFrame[];
  screenshot(options: Record<string, unknown>): Promise<Buffer>;
}

/// Capture `page`: the viewport, or with `clip` (a bounded full-page
/// clip) the page from its top; every secret field in every frame masked.
/// A failed capture (masking included) is a typed failure, never an
/// unmasked picture.
export async function capturePng(page: ShotPage, clip?: { x: number; y: number; width: number; height: number }): Promise<{ png: Buffer; width: number; height: number }> {
  const mask = page.frames().map((frame) => frame.locator(SECRET_FIELD_SELECTOR));
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
      timeout: SCREENSHOT_TIMEOUT_MS
    });
  } catch {
    throw new ScreenshotError("failed");
  }
  return { png, ...checkCapture(png) };
}
