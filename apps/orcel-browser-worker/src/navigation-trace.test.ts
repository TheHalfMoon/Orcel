import assert from "node:assert/strict";
import { test } from "node:test";
import { traceLine, traceMark, traceStart, traceWatchEventLoop } from "./navigation-trace.js";

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

test("an idle event loop reports a small gap", async () => {
  let now = 1_000;
  traceStart(now);
  const stop = traceWatchEventLoop(1_000_000, () => now);
  now = 1_100;
  stop();
  assert.match(traceLine(), /largest_event_loop_gap_0ms\+100ms/);
});
