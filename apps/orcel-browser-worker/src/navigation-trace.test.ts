import assert from "node:assert/strict";
import { test } from "node:test";
import { cpuBusyPercent, netErrorCode, rendererAnswers, traceLine, traceMark, traceStart, traceWatchEventLoop } from "./navigation-trace.js";

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

test("#584: a renderer that answers, even with an error, is told apart from one that doesn't", async () => {
  assert.equal(await rendererAnswers(() => Promise.resolve(1), 1_000), "answered");
  assert.equal(await rendererAnswers(() => Promise.reject(new Error("closed")), 1_000), "answered");
  assert.equal(await rendererAnswers(() => new Promise(() => {}), 20), "no answer");
});
