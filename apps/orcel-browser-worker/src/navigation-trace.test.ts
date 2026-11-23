import assert from "node:assert/strict";
import { test } from "node:test";
import { cpuBusyPercent, netErrorCode, PROBE_METHODS, probeBrowser, traceLine, traceMark, traceStart, traceWatchEventLoop } from "./navigation-trace.js";

test("the timeline names stages with elapsed milliseconds and restarts", () => {
  traceStart(1_000);
  traceMark("goto", 1_005);
  traceMark("route_entered", 1_020);
  assert.equal(traceLine(), "navigation timeline: goto+5ms route_entered+20ms");
  traceStart(2_000);
  assert.equal(traceLine(), "navigation timeline: ");
});

test("the timeline is bounded, keeps the newest stages and says how many it dropped", () => {
  traceStart(0);
  for (let n = 0; n < 500; n++) traceMark("request", n);
  traceMark("last", 500);
  const line = traceLine();
  assert.ok(line.startsWith("navigation timeline: (453 earlier) "), line);
  assert.ok(line.endsWith(" last+500ms"), line);
  assert.equal(line.split("+").length - 1, 48);
});

test("the event loop watch reports the largest time the loop did not run", async () => {
  traceStart();
  const stop = traceWatchEventLoop(20);
  const until = Date.now() + 200;
  while (Date.now() < until) {
    // Holds the event loop, as a starved worker would.
  }
  await new Promise((resolve) => setTimeout(resolve, 40));
  stop();
  const gap = /largest_event_loop_gap_(\d+)ms/.exec(traceLine());
  assert.ok(gap, traceLine());
  assert.ok(Number(gap[1]) >= 100, traceLine());
});

test("a stall still open when the watch stops is counted", () => {
  let now = 1_000;
  traceStart(now);
  const stop = traceWatchEventLoop(1_000_000, () => now);
  now = 1_001_500;
  stop();
  assert.match(traceLine(), /largest_event_loop_gap_500ms/);
});

test("an idle event loop reports no gap", () => {
  let now = 1_000;
  traceStart(now);
  const stop = traceWatchEventLoop(1_000_000, () => now);
  now = 1_100;
  stop();
  assert.match(traceLine(), /largest_event_loop_gap_0ms\+100ms/);
});

test("the watch reports how busy the machine was", () => {
  traceStart();
  const stop = traceWatchEventLoop();
  const until = Date.now() + 100;
  while (Date.now() < until) {
    // Spends CPU, so the reading has something to count.
  }
  stop();
  const busy = /system_cpu_busy_(\d+)pct/.exec(traceLine());
  if (busy) assert.ok(Number(busy[1]) <= 100, traceLine());
});

const cpu = (user: number, idle: number) => ({
  model: "m",
  speed: 1,
  times: { user, nice: 0, sys: 0, idle, irq: 0 }
});

test("busy share is across all cores and refuses readings it can't compare", () => {
  assert.equal(cpuBusyPercent([cpu(0, 0), cpu(0, 0)], [cpu(100, 0), cpu(0, 100)]), 50);
  assert.equal(cpuBusyPercent([cpu(0, 0)], [cpu(0, 0)]), null);
  assert.equal(cpuBusyPercent([], []), null);
  assert.equal(cpuBusyPercent([cpu(0, 0)], [cpu(1, 1), cpu(1, 1)]), null);
});

test("#584: a failed navigation keeps only the engine's network error code", () => {
  assert.equal(
    netErrorCode("page.goto: net::ERR_PROXY_CONNECTION_FAILED at https://fixture.test/site/dl?q=secret"),
    "net::ERR_PROXY_CONNECTION_FAILED"
  );
  assert.equal(netErrorCode("net::ERR_NAME_NOT_RESOLVED"), "net::ERR_NAME_NOT_RESOLVED");
  assert.equal(netErrorCode("Target page, context or browser has been closed"), "unknown");
});

/// A CDP session that answers each method as told.
function session(answer: (method: string) => Promise<unknown>) {
  const seen: string[] = [];
  return {
    seen,
    send(method: string) {
      seen.push(method);
      return answer(method);
    },
    async detach() {
      seen.push("detach");
    }
  };
}

const never = () => new Promise<never>(() => {});

test("#584: the probe sends two reads of the browser process, keeps no answer, and lets its session go", async () => {
  const answering = session(() => Promise.resolve({ entries: [{ url: "https://example.test/?q=secret" }] }));
  assert.deepEqual(await probeBrowser(async () => answering), ["browser_attach_answered", "browser_history_answered", "browser_version_answered"]);
  assert.deepEqual(answering.seen, ["Page.getNavigationHistory", "Browser.getVersion", "detach"]);
  assert.deepEqual([...PROBE_METHODS], ["Page.getNavigationHistory", "Browser.getVersion"]);
});

test("#584: no answer and a refusal are told apart from an answer, each on its own", async () => {
  const half = session((method) => (method === "Browser.getVersion" ? Promise.resolve({}) : never()));
  const began = performance.now();
  assert.deepEqual(await probeBrowser(async () => half, 50), ["browser_attach_answered", "browser_history_no_answer", "browser_version_answered"]);
  const refusing = session(() => Promise.reject(new Error("closed")));
  assert.deepEqual(await probeBrowser(async () => refusing, 50), ["browser_attach_answered", "browser_history_error", "browser_version_error"]);
  assert.deepEqual(await probeBrowser(() => Promise.reject(new Error("closed")), 50), ["browser_attach_error", "browser_history_not_sent", "browser_version_not_sent"]);
  assert.ok(performance.now() - began < 1_000);
});

test("#584: one deadline for the whole probe; a session that attaches late is let go of and sent nothing", async () => {
  const late = session(() => Promise.resolve({}));
  let attach: () => void = () => {};
  const attaching = new Promise<typeof late>((resolve) => (attach = () => resolve(late)));
  assert.deepEqual(await probeBrowser(() => attaching, 20), ["browser_attach_no_answer", "browser_history_not_sent", "browser_version_not_sent"]);
  attach();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(late.seen, ["detach"]);
  // A detach that never ends holds nothing up.
  const stuck = { ...session(() => Promise.resolve({})), detach: never };
  assert.equal((await probeBrowser(async () => stuck, 1_000)).length, 3);
});

test("#584: every step of the probe ends at the one deadline", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const settle = async () => {
    for (let n = 0; n < 3; n++) await new Promise((resolve) => setImmediate(resolve));
  };
  const stuck = session(never);
  let attach: () => void = () => {};
  const attaching = new Promise<typeof stuck>((resolve) => (attach = () => resolve(stuck)));
  let marks: string[] = [];
  void probeBrowser(() => attaching, 2_000).then((found) => (marks = found));
  // Attaching takes most of it; the reads get the rest, not 2 s of their own.
  t.mock.timers.tick(1_500);
  attach();
  await settle();
  assert.deepEqual(stuck.seen, ["Page.getNavigationHistory", "Browser.getVersion"]);
  t.mock.timers.tick(499);
  await settle();
  assert.deepEqual(marks, []);
  t.mock.timers.tick(1);
  await settle();
  assert.deepEqual(marks, ["browser_attach_answered", "browser_history_no_answer", "browser_version_no_answer"]);
});

test("#584: attaching that throws at once is an error, and the probe's timer is cleared", async (t) => {
  const cleared = t.mock.method(globalThis, "clearTimeout");
  const throwing = (): never => {
    throw new Error("closed");
  };
  assert.deepEqual(await probeBrowser(throwing, 50), ["browser_attach_error", "browser_history_not_sent", "browser_version_not_sent"]);
  assert.equal(cleared.mock.callCount(), 1);
  assert.deepEqual(await probeBrowser(async () => ({ send: throwing, detach: async () => {} }), 50), ["browser_attach_answered", "browser_history_error", "browser_version_error"]);
});
