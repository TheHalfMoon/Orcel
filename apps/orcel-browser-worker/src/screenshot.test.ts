import assert from "node:assert/strict";
import { test } from "node:test";
import {
  capturePng,
  checkCapture,
  fullPageClip,
  MASK_COLOR,
  MAX_SCREENSHOT_BYTES,
  MAX_SCREENSHOT_HEIGHT,
  MAX_SCREENSHOT_PIECE_CHARS,
  MAX_SCREENSHOT_PIECES,
  MAX_SCREENSHOT_WIDTH,
  pngSize,
  runExclusive,
  ScreenshotError,
  SECRET_FIELD_SELECTOR,
  toBase64Pieces,
  type ShotPage
} from "./screenshot.js";

/// A PNG header (signature and IHDR) of the given size, padded.
function png(width: number, height: number, padding = 0): Buffer {
  const head = Buffer.alloc(33 + padding);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(head, 0);
  head.writeUInt32BE(13, 8);
  head.write("IHDR", 12, "latin1");
  head.writeUInt32BE(width, 16);
  head.writeUInt32BE(height, 20);
  return head;
}

test("OB-03: the mask covers every secret field kind the form actions refuse", () => {
  for (const part of [
    'input[type="password" i]',
    '[autocomplete~="current-password" i]',
    '[autocomplete~="new-password" i]',
    '[autocomplete~="one-time-code" i]',
    '[autocomplete~="cc-number" i]',
    '[autocomplete~="cc-csc" i]',
    '[autocomplete~="cc-exp" i]',
    '[autocomplete~="cc-exp-month" i]',
    '[autocomplete~="cc-exp-year" i]',
    'input[name*="pass" i]',
    'input[id*="pwd" i]',
    'input[name*="otp" i]',
    'input[name*="cvv" i]',
    'input[name*="cvc" i]',
    'input[name*="csc" i]',
    'input[name*="secret" i]',
    'input[name*="token" i]',
    'input[name*="card" i]',
    'textarea[name*="secret" i]'
  ]) {
    assert.ok(SECRET_FIELD_SELECTOR.split(", ").includes(part), part);
  }
  // One selector list: no part can swallow the rest.
  assert.ok(!SECRET_FIELD_SELECTOR.includes("\n") && !SECRET_FIELD_SELECTOR.includes(";"));
});

test("OB-03: a full-page clip is the page's CSS size, bounded, and says when it cut", () => {
  assert.deepEqual(fullPageClip({ cssContentSize: { width: 1280, height: 3000.2 } }), { clip: { x: 0, y: 0, width: 1280, height: 3001 }, truncated: false });
  assert.deepEqual(fullPageClip({ cssContentSize: { width: 5000, height: 99_999 } }), {
    clip: { x: 0, y: 0, width: MAX_SCREENSHOT_WIDTH, height: MAX_SCREENSHOT_HEIGHT },
    truncated: true
  });
  // The physical size only when the CSS one is missing.
  assert.deepEqual(fullPageClip({ contentSize: { width: 800, height: 600 } }).clip, { x: 0, y: 0, width: 800, height: 600 });
  // Missing, non-finite or nonsense sizes fall back to the viewport default.
  for (const metrics of [null, {}, { cssContentSize: { width: Number.NaN, height: -4 } }, { cssContentSize: "big" }, { cssContentSize: { width: Infinity, height: 0 } }]) {
    assert.deepEqual(fullPageClip(metrics), { clip: { x: 0, y: 0, width: 1280, height: 720 }, truncated: false }, JSON.stringify(metrics));
  }
});

test("OB-03: a capture is a PNG within the byte and pixel bounds, or a typed failure", () => {
  assert.deepEqual(pngSize(png(1280, 720)), { width: 1280, height: 720 });
  assert.equal(pngSize(Buffer.from("not a png at all, no signature")), null);
  const wrongChunk = png(1, 1);
  wrongChunk.write("IDAT", 12, "latin1");
  assert.equal(pngSize(wrongChunk), null);
  assert.deepEqual(checkCapture(png(MAX_SCREENSHOT_WIDTH, MAX_SCREENSHOT_HEIGHT)), { width: MAX_SCREENSHOT_WIDTH, height: MAX_SCREENSHOT_HEIGHT });
  const reason = (buffer: Buffer) => {
    try {
      checkCapture(buffer);
      return "ok";
    } catch (error) {
      assert.ok(error instanceof ScreenshotError);
      return error.reason;
    }
  };
  assert.equal(reason(png(MAX_SCREENSHOT_WIDTH + 1, 10)), "oversized");
  assert.equal(reason(png(10, MAX_SCREENSHOT_HEIGHT + 1)), "oversized");
  assert.equal(reason(png(10, 10, MAX_SCREENSHOT_BYTES)), "oversized");
  assert.equal(reason(png(0, 10)), "failed");
  assert.equal(reason(Buffer.alloc(40)), "failed");
});

test("OB-03: pieces are whole base64 slices that join to the PNG, within the piece bounds", () => {
  const bytes = Buffer.from(Array.from({ length: 200_000 }, (_, i) => i % 251));
  const pieces = toBase64Pieces(bytes);
  assert.equal(pieces.length, Math.ceil(200_000 / ((MAX_SCREENSHOT_PIECE_CHARS / 4) * 3)));
  for (const piece of pieces) assert.ok(piece.length <= MAX_SCREENSHOT_PIECE_CHARS);
  assert.ok(Buffer.concat(pieces.map((piece) => Buffer.from(piece, "base64"))).equals(bytes));
  assert.ok(MAX_SCREENSHOT_PIECES * (MAX_SCREENSHOT_PIECE_CHARS / 4) * 3 >= MAX_SCREENSHOT_BYTES);
  assert.throws(() => toBase64Pieces(Buffer.alloc(0)), ScreenshotError);
  assert.throws(() => toBase64Pieces(Buffer.alloc(MAX_SCREENSHOT_PIECES * (MAX_SCREENSHOT_PIECE_CHARS / 4) * 3 + 1)), ScreenshotError);
});

test("OB-03: captures of one page run one at a time", async () => {
  const key = {};
  const order: string[] = [];
  let release: () => void = () => {};
  const first = runExclusive(key, async () => {
    order.push("first start");
    await new Promise<void>((resolve) => (release = resolve));
    order.push("first end");
    return 1;
  });
  const second = runExclusive(key, async () => {
    order.push("second");
    return 2;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(order, ["first start"]);
  release();
  assert.deepEqual(await Promise.all([first, second]), [1, 2]);
  assert.deepEqual(order, ["first start", "first end", "second"]);
  // A failed capture does not hold the next one.
  await assert.rejects(runExclusive(key, async () => Promise.reject(new Error("x"))));
  assert.equal(await runExclusive(key, async () => 3), 3);
});

test("OB-03: every frame's secret fields are masked, and a failed capture is never an unmasked one", async () => {
  const calls: Array<Record<string, unknown>> = [];
  const located: string[] = [];
  const locators = [0, 1, 2].map((index) => ({ frame: index, count: async () => 1 }));
  const framesOf = [0, 1, 2].map((index) => ({ locator: (selector: string) => (located.push(`${index}:${selector}`), locators[index] as (typeof locators)[number]) }));
  const page = (fail: boolean): ShotPage => ({
    frames: () => framesOf,
    screenshot: async (options) => {
      calls.push(options);
      if (fail) throw new Error("mask could not be applied");
      return png(1280, 720);
    }
  });
  const shot = await capturePng(page(false));
  assert.deepEqual([shot.width, shot.height], [1280, 720]);
  const options = calls[0] as Record<string, unknown>;
  assert.equal(options.type, "png");
  assert.equal(options.maskColor, MASK_COLOR);
  assert.equal(options.scale, "css");
  assert.equal(options.fullPage, undefined);
  assert.deepEqual(options.mask, locators);
  assert.deepEqual(located, [0, 1, 2].map((index) => `${index}:${SECRET_FIELD_SELECTOR}`));
  const clip = { x: 0, y: 0, width: 1280, height: 4096 };
  await capturePng(page(false), clip);
  assert.equal(calls[1]?.fullPage, true);
  assert.deepEqual(calls[1]?.clip, clip);
  await assert.rejects(capturePng(page(true)), (error: unknown) => error instanceof ScreenshotError && error.reason === "failed");
});

test("OB-03: a capture during which a frame or a secret field appeared is refused", async () => {
  const reason = async (page: ShotPage) => {
    try {
      await capturePng(page);
      return "ok";
    } catch (error) {
      assert.ok(error instanceof ScreenshotError);
      return error.reason;
    }
  };
  // A frame attached while the capture ran.
  const frames: Array<{ locator: () => { count: () => Promise<number> } }> = [{ locator: () => ({ count: async () => 0 }) }];
  assert.equal(
    await reason({
      frames: () => [...frames],
      screenshot: async () => {
        frames.push({ locator: () => ({ count: async () => 1 }) });
        return png(10, 10);
      }
    }),
    "busy"
  );
  // A secret field added in a frame while the capture ran.
  let fields = 0;
  assert.equal(
    await reason({
      frames: () => [{ locator: () => ({ count: async () => fields }) }],
      screenshot: async () => {
        fields += 1;
        return png(10, 10);
      }
    }),
    "busy"
  );
  // A frame that cannot be counted fails closed before any capture.
  let captured = false;
  assert.equal(
    await reason({
      frames: () => [{ locator: () => ({ count: async () => Promise.reject(new Error("detached")) }) }],
      screenshot: async () => {
        captured = true;
        return png(10, 10);
      }
    }),
    "failed"
  );
  assert.equal(captured, false);
  // The widened selector names the new kinds.
  for (const part of ['[style*="text-security" i]', '[contenteditable]:not([contenteditable="false" i])', 'input[name*="pin" i]', 'input[name*="ssn" i]', 'input[name*="cc-" i]', 'input[id*="iban" i]']) {
    assert.ok(SECRET_FIELD_SELECTOR.split(", ").includes(part), part);
  }
});
