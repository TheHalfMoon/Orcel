import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  capturePng as capture,
  CENSUS_RESERVE_MS,
  checkCapture,
  errorCode,
  fullPageClip,
  MASK_COLOR,
  MAX_SCREENSHOT_BYTES,
  MAX_SCREENSHOT_HEIGHT,
  MAX_SCREENSHOT_PIECE_CHARS,
  MAX_SCREENSHOT_PIECES,
  MAX_SCREENSHOT_WIDTH,
  pngSize,
  runBounded,
  runExclusive,
  SCREENSHOT_BUDGET_MS,
  SCREENSHOT_TIMEOUT_MS,
  ScreenshotBudget,
  ScreenshotError,
  SECRET_FIELD_SELECTOR,
  takeScreenshot,
  toBase64Pieces,
  type ShotFrame,
  type ShotPage,
  type ShotSubject
} from "./screenshot.js";

const capturePng = (page: ShotPage, clip?: Parameters<typeof capture>[1]) => capture(page, clip, new ScreenshotBudget(SCREENSHOT_BUDGET_MS, () => {}));

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
  const box = (y: number) => ({ boundingBox: async () => ({ x: 0, y, width: 10, height: 10 }) });
  const locators = [0, 1, 2].map((index) => ({ frame: index, all: async () => [box(index)] }));
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
  const at = (y: number) => ({ boundingBox: async () => ({ x: 40, y, width: 320, height: 48 }) });
  const frameWith = (fields: () => Array<{ boundingBox: () => Promise<{ x: number; y: number; width: number; height: number } | null> }>) => ({
    locator: () => ({ all: async () => fields() })
  });
  // A frame attached while the capture ran.
  const frames = [frameWith(() => [])];
  assert.equal(
    await reason({
      frames: () => [...frames],
      screenshot: async () => {
        frames.push(frameWith(() => [at(0)]));
        return png(10, 10);
      }
    }),
    "busy"
  );
  // A secret field added in a frame while the capture ran.
  let fields = [at(100)];
  // One frame object throughout: only the fields differ.
  const frame = frameWith(() => fields);
  assert.equal(
    await reason({
      frames: () => [frame],
      screenshot: async () => {
        fields = [at(100), at(180)];
        return png(10, 10);
      }
    }),
    "busy"
  );
  // One added and another removed: the same count, other places. Refused.
  fields = [at(100), at(180)];
  assert.equal(
    await reason({
      frames: () => [frame],
      screenshot: async () => {
        fields = [at(100), at(260)];
        return png(10, 10);
      }
    }),
    "busy"
  );
  // Unchanged places: the capture stands.
  fields = [at(100), at(180)];
  assert.equal(await reason({ frames: () => [frame], screenshot: async () => png(10, 10) }), "ok");
  // A frame that cannot be read, or one with too many fields, fails closed
  // before any capture.
  let captured = false;
  for (const broken of [
    { locator: () => ({ all: async () => Promise.reject(new Error("detached")) }) },
    frameWith(() => Array.from({ length: 257 }, (_, index) => at(index)))
  ]) {
    assert.equal(
      await reason({
        frames: () => [broken],
        screenshot: async () => {
          captured = true;
          return png(10, 10);
        }
      }),
      "failed"
    );
  }
  assert.equal(captured, false);
  // The widened selector names the new kinds.
  for (const part of ['[style*="text-security" i]', '[contenteditable]:not([contenteditable="false" i])', 'input[name*="pin" i]', 'input[name*="ssn" i]', 'input[name*="cc-" i]', 'input[id*="iban" i]']) {
    assert.ok(SECRET_FIELD_SELECTOR.split(", ").includes(part), part);
  }
});

/// A promise settled by hand, as a renderer that answers late (or never) does.
function held<T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (error: Error) => void } {
  let resolve: (value: T) => void = () => {};
  let reject: (error: Error) => void = () => {};
  const promise = new Promise<T>((ok, fail) => {
    resolve = ok;
    reject = fail;
  });
  return { promise, resolve, reject };
}

const BOX = { x: 0, y: 0, width: 10, height: 10 };
const still: ShotFrame = { locator: () => ({ all: async () => [{ boundingBox: async () => BOX }] }) };

/// Run one screenshot as the worker does: alone on its page, within `ms`.
async function shoot(page: ShotPage, ms: number): Promise<{ outcome: string; elapsed: number; reports: string[] }> {
  const reports: string[] = [];
  const began = performance.now();
  const budget = new ScreenshotBudget(ms, (stage, code) => reports.push(`${stage}: ${code}`));
  const outcome = await runBounded(page, budget, () => capture(page, undefined, budget)).then(
    () => "picture",
    (error: unknown) => {
      assert.ok(error instanceof ScreenshotError, String(error));
      return error.reason;
    }
  );
  return { outcome, elapsed: performance.now() - began, reports };
}

const turns = () => new Promise((resolve) => setTimeout(resolve, 20));

test("#438: the whole screenshot's budget is above the capture and well under the host's deadline", () => {
  const host = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../../../crates/orcel-browser-host/src/worker_launch.rs"), "utf8");
  const deadline = /pub const WORKER_SCREENSHOT_TIMEOUT: Duration = Duration::from_secs\((\d+)\);/.exec(host);
  assert.ok(deadline, "WORKER_SCREENSHOT_TIMEOUT");
  assert.ok(SCREENSHOT_BUDGET_MS + 4_000 <= Number(deadline[1]) * 1_000, `${SCREENSHOT_BUDGET_MS} ms vs ${deadline[1]} s`);
  assert.ok(SCREENSHOT_BUDGET_MS >= SCREENSHOT_TIMEOUT_MS + CENSUS_RESERVE_MS);
});

test("#438: a field whose box never comes fails the screenshot on time, and the page stays held until it ends", async () => {
  const box = held<typeof BOX>();
  const timeouts: number[] = [];
  let hang = true;
  let captures = 0;
  const field = { boundingBox: ({ timeout }: { timeout: number }) => (timeouts.push(timeout), hang ? box.promise : Promise.resolve(BOX)) };
  const page: ShotPage = {
    frames: () => [frame],
    screenshot: async () => {
      captures += 1;
      return png(10, 10);
    }
  };
  const frame: ShotFrame = { locator: () => ({ all: async () => [field] }) };
  const first = await shoot(page, 500);
  assert.equal(first.outcome, "failed");
  assert.ok(first.elapsed < 5_000, `${first.elapsed} ms`);
  assert.deepEqual(first.reports, ["census_before: budget"]);
  // Finding the element is bounded by what is left of the budget.
  assert.equal(timeouts.length, 1);
  assert.ok((timeouts[0] as number) >= 1 && (timeouts[0] as number) <= 500, `${timeouts[0]}`);
  // The stuck work still holds the page: the next one is not let in beside
  // it, and is answered on time too.
  hang = false;
  const second = await shoot(page, 150);
  assert.equal(second.outcome, "failed");
  assert.deepEqual(second.reports, ["queue: budget"]);
  assert.equal(timeouts.length, 1, "the queued screenshot touched nothing");
  // The late answer is dropped: no capture follows it, nothing is reported
  // again, and the page is free.
  box.resolve(BOX);
  await turns();
  assert.equal(captures, 0);
  assert.equal(first.reports.length, 1);
  const third = await shoot(page, 5_000);
  assert.equal(third.outcome, "picture");
  assert.equal(captures, 1);
});

test("#438: no picture is returned when the fields cannot be read again after the capture", async () => {
  const run = async (late: "resolve" | "reject") => {
    const box = held<typeof BOX>();
    let reads = 0;
    const page: ShotPage = { frames: () => [frame], screenshot: async () => png(10, 10) };
    const frame: ShotFrame = { locator: () => ({ all: async () => [{ boundingBox: () => (++reads === 1 ? Promise.resolve(BOX) : box.promise) }] }) };
    const shot = await shoot(page, CENSUS_RESERVE_MS + 1_500);
    assert.equal(shot.outcome, "failed");
    assert.deepEqual(shot.reports, ["census_after: budget"]);
    // Equal places, too late: the answer was already given.
    if (late === "resolve") box.resolve(BOX);
    else box.reject(new Error("closed"));
    await turns();
    assert.equal(shot.reports.length, 1);
  };
  await Promise.all([run("resolve"), run("reject")]);
});

test("#438: counting the fields has no timeout of its own, and is bounded too", async () => {
  const page: ShotPage = {
    frames: () => [{ locator: () => ({ all: () => new Promise(() => {}) }) }],
    screenshot: async () => png(10, 10)
  };
  const shot = await shoot(page, 150);
  assert.equal(shot.outcome, "failed");
  assert.ok(shot.elapsed < 5_000, `${shot.elapsed} ms`);
});

test("#438: a capture that outlives the budget is dropped, and holds the page until it ends", async () => {
  const picture = held<Buffer>();
  const options: Array<Record<string, unknown>> = [];
  let running = 0;
  let most = 0;
  let hang = true;
  let counted = 0;
  const frame: ShotFrame = { locator: () => ({ all: async () => ((counted += 1), []) }) };
  const page: ShotPage = {
    frames: () => [frame],
    screenshot: async (asked) => {
      options.push(asked);
      running += 1;
      most = Math.max(most, running);
      try {
        return hang ? await picture.promise : png(10, 10);
      } finally {
        running -= 1;
      }
    }
  };
  const first = await shoot(page, CENSUS_RESERVE_MS + 1_500);
  assert.equal(first.outcome, "failed");
  assert.deepEqual(first.reports, ["capture: budget"]);
  // Playwright is told to end first, with time left to check its picture.
  const timeout = options[0]?.timeout as number;
  assert.ok(timeout >= 1 && timeout <= 1_500, `${timeout}`);
  hang = false;
  const second = shoot(page, 5_000);
  await turns();
  assert.equal(options.length, 1, "the second capture waits for the first to end");
  picture.resolve(png(10, 10));
  assert.equal((await second).outcome, "picture");
  assert.equal(most, 1);
  assert.equal(counted, 3, "the late capture was followed by no census");
});

test("#438: a screenshot whose turn comes after its budget does nothing, and lets the next one in", async () => {
  const key = {};
  const first = held<void>();
  const running = runExclusive(key, () => first.promise);
  let ran = false;
  const budget = new ScreenshotBudget(100, () => {});
  await assert.rejects(
    runBounded(key, budget, async () => {
      ran = true;
    }),
    ScreenshotError
  );
  first.resolve();
  await running;
  await turns();
  assert.equal(ran, false);
  assert.equal(await runBounded(key, new ScreenshotBudget(5_000, () => {}), async () => "free"), "free");
});

/// Let everything that can run now run, with timers mocked.
const settle = async () => {
  for (let n = 0; n < 3; n++) await new Promise((resolve) => setImmediate(resolve));
};

test("#438: the answer comes at the budget's end, to the millisecond", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const budget = new ScreenshotBudget(1_000, () => {}, () => 0);
  let outcome = "pending";
  budget.within(new Promise(() => {})).catch((error: ScreenshotError) => (outcome = error.reason));
  t.mock.timers.tick(999);
  await settle();
  assert.equal(outcome, "pending");
  t.mock.timers.tick(1);
  await settle();
  assert.equal(outcome, "failed");
  // From then on the budget is over whatever a clock says (this one stands still).
  assert.throws(() => budget.remaining(), ScreenshotError);
  assert.throws(() => budget.enter("capture"), ScreenshotError);
});

test("#438: a screenshot that ended in time leaves no timer behind to report it failed", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const reports: string[] = [];
  const budget = new ScreenshotBudget(1_000, (stage) => reports.push(stage), () => 0);
  assert.equal(await budget.within(Promise.resolve("picture")), "picture");
  t.mock.timers.tick(5_000);
  await settle();
  assert.deepEqual(reports, []);
  assert.equal(budget.remaining(), 1_000);
});

/// The worker's active tab, as `takeScreenshot` sees it; every part can be replaced.
function subject(parts: { [K in keyof ShotSubject]?: ShotSubject[K] } = {}, onPage: Partial<ShotSubject["page"]> = {}): ShotSubject {
  return {
    page: { frames: () => [still], screenshot: async () => png(10, 10), url: () => "https://example.test/", isClosed: () => false, ...onPage },
    loading: () => false,
    active: () => true,
    metrics: () => Promise.reject(new Error("not asked for")),
    ...parts
  };
}

/// What one screenshot gives, and what it reported.
async function taken(of: ShotSubject, fullPage = false): Promise<[string, ...string[]]> {
  const reports: string[] = [];
  const budget = new ScreenshotBudget(5_000, (stage, code) => reports.push(`${stage}: ${code}`));
  const outcome = await takeScreenshot(of, fullPage, budget).then(
    (shot) => `picture ${shot.url} ${shot.truncated}`,
    (error: unknown) => {
      assert.ok(error instanceof ScreenshotError, String(error));
      return error.reason as string;
    }
  );
  return [outcome, ...reports];
}

test("#438: a full page's metrics are a step of the screenshot: staged, typed, and their session let go of", async () => {
  const seen: string[] = [];
  const asking = (answer: () => Promise<unknown>) =>
    subject(
      {
        metrics: async () => ({
          send: (method) => (seen.push(method), answer()),
          detach: async () => void seen.push("detach")
        })
      },
      {
        screenshot: async (options) => {
          seen.push(`clip ${JSON.stringify(options.clip)}`);
          return png(10, 10);
        }
      }
    );
  assert.deepEqual(await taken(asking(async () => ({ cssContentSize: { width: 800, height: 9_000 } })), true), ["picture https://example.test/ true"]);
  assert.deepEqual(seen.splice(0), ["Page.getLayoutMetrics", "detach", `clip {"x":0,"y":0,"width":800,"height":${MAX_SCREENSHOT_HEIGHT}}`]);
  // The command fails, or the session never opens: typed, one line, no capture.
  assert.deepEqual(await taken(asking(() => Promise.reject(new Error("https://example.test/?q=secret"))), true), ["failed", "metrics: Error"]);
  assert.deepEqual(seen.splice(0), ["Page.getLayoutMetrics", "detach"]);
  assert.deepEqual(await taken(subject({ metrics: () => Promise.reject(new Error("closed")) }), true), ["failed", "metrics: Error"]);
  // A viewport screenshot asks for none.
  assert.deepEqual(await taken(asking(async () => ({}))), ["picture https://example.test/ false"]);
  assert.deepEqual(seen.splice(0), ["clip undefined"]);
});

test("#438: the worker's screenshot takes the whole budget by default, its metrics included", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const write = t.mock.method(process.stderr, "write", () => true);
  let outcome = "pending";
  takeScreenshot(subject({ metrics: () => new Promise(() => {}) }), true).catch((error: ScreenshotError) => (outcome = error.reason));
  t.mock.timers.tick(SCREENSHOT_BUDGET_MS - 100);
  await settle();
  assert.equal(outcome, "pending");
  t.mock.timers.tick(200);
  await settle();
  write.mock.restore();
  assert.equal(outcome, "failed");
  assert.deepEqual(
    write.mock.calls.map((call) => call.arguments[0] as unknown).filter((text) => String(text).startsWith("orcel-browser-worker:")),
    ["orcel-browser-worker: screenshot failed at metrics: budget\n"]
  );
});

test("#438: what the metrics took is gone from the capture's time", async () => {
  let now = 0;
  const asked: unknown[] = [];
  const of = subject(
    {
      metrics: async () => {
        now += 8_000;
        return { send: async () => ({}), detach: async () => {} };
      }
    },
    { screenshot: async (options) => (asked.push(options.timeout), png(10, 10)) }
  );
  await takeScreenshot(of, true, new ScreenshotBudget(SCREENSHOT_BUDGET_MS, () => {}, () => now));
  assert.deepEqual(asked, [6_000]);
});

test("OB-03: a screenshot that raced a navigation, a close or a tab change is refused", async () => {
  assert.deepEqual(await taken(subject()), ["picture https://example.test/ false"]);
  // Before anything is captured.
  let captures = 0;
  const counting = { screenshot: async () => ((captures += 1), png(10, 10)) };
  assert.deepEqual(await taken(subject({}, { ...counting, isClosed: () => true })), ["failed"]);
  assert.deepEqual(await taken(subject({ loading: () => true }, counting)), ["busy"]);
  assert.equal(captures, 0);
  // Each true only once the capture has run.
  const racing = (what: "loading" | "closed" | "url" | "tab") => {
    let captured = false;
    const now = (kind: string) => captured && what === kind;
    return subject(
      { loading: () => now("loading"), active: () => !now("tab") },
      {
        isClosed: () => now("closed"),
        url: () => (now("url") ? "https://example.test/other" : "https://example.test/"),
        screenshot: async () => {
          captured = true;
          return png(10, 10);
        }
      }
    );
  };
  for (const what of ["loading", "closed", "url", "tab"] as const) assert.deepEqual(await taken(racing(what)), ["busy"], what);
});

test("#438: a slow census is taken from the capture's time, which never becomes 0 (no timeout)", async () => {
  let now = 0;
  const run = async (censusMs: number) => {
    now = 0;
    const asked: unknown[] = [];
    const budget = new ScreenshotBudget(SCREENSHOT_BUDGET_MS, () => {}, () => now);
    const frame: ShotFrame = {
      locator: () => ({
        all: async () => {
          if (asked.length === 0) now += censusMs;
          return [];
        }
      })
    };
    const page: ShotPage = {
      frames: () => [frame],
      screenshot: async (options) => {
        asked.push(options.timeout);
        return png(10, 10);
      }
    };
    const outcome = await capture(page, undefined, budget).then(
      () => "picture",
      (error: ScreenshotError) => error.reason
    );
    return [outcome, ...asked];
  };
  assert.deepEqual(await run(0), ["picture", SCREENSHOT_TIMEOUT_MS]);
  assert.deepEqual(await run(8_000), ["picture", 6_000]);
  assert.deepEqual(await run(SCREENSHOT_BUDGET_MS - CENSUS_RESERVE_MS - 1), ["picture", 1]);
  assert.deepEqual(await run(SCREENSHOT_BUDGET_MS - CENSUS_RESERVE_MS), ["failed"]);
  assert.deepEqual(await run(SCREENSHOT_BUDGET_MS), ["failed"]);
});

test("#438: work that ends after the deadline gives no picture even when the timer has not run", async () => {
  let now = 0;
  const budget = new ScreenshotBudget(1_000, () => {}, () => now);
  const work = Promise.resolve("picture").then((value) => {
    now = 1_000;
    return value;
  });
  await assert.rejects(budget.within(work), (error: unknown) => error instanceof ScreenshotError && error.reason === "failed");
});

test("#438: a failed screenshot reports one closed code, never the error's message", async () => {
  class TimeoutError extends Error {
    override name = "TimeoutError";
  }
  const secret = "https://example.test/?q=secret";
  const written: string[] = [];
  const write = process.stderr.write;
  process.stderr.write = ((text: string) => (written.push(text), true)) as typeof process.stderr.write;
  try {
    const failing = async (page: ShotPage) => {
      const budget = new ScreenshotBudget();
      await assert.rejects(runBounded(page, budget, () => capture(page, undefined, budget)), ScreenshotError);
    };
    const throwing = (error: unknown): ShotPage => ({ frames: () => [still], screenshot: () => Promise.reject(error) });
    await failing(throwing(new TimeoutError(secret)));
    await failing(throwing(Object.assign(new Error(secret), { name: secret })));
    await failing(throwing(secret));
    await failing({ frames: () => [{ locator: () => ({ all: () => Promise.reject(new Error(secret)) }) }], screenshot: async () => png(10, 10) });
  } finally {
    process.stderr.write = write;
  }
  assert.deepEqual(written, [
    "orcel-browser-worker: screenshot failed at capture: TimeoutError\n",
    "orcel-browser-worker: screenshot failed at capture: other\n",
    "orcel-browser-worker: screenshot failed at capture: other\n",
    "orcel-browser-worker: screenshot failed at census_before: Error\n"
  ]);
  assert.equal(errorCode(null), "other");
});
