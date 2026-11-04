import assert from "node:assert/strict";
import { test } from "node:test";
import { traceLine, traceMark, traceStart } from "./navigation-trace.js";

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
