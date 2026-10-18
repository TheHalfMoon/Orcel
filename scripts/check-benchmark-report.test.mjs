import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { checkTargets, findReports, loadSchema, samplesDir, validateReport } from "./check-benchmark-report.mjs";

const script = fileURLToPath(new URL("./check-benchmark-report.mjs", import.meta.url));
const schema = loadSchema();
const sample = JSON.parse(readFileSync(join(samplesDir, "native-conformance.sample.report.json"), "utf8"));
const copy = () => structuredClone(sample);

const run = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });

const withTempDir = (fn) => {
  const dir = mkdtempSync(join(tmpdir(), "orcel-bm01-"));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};

test("bundled sample validates", () => {
  assert.deepEqual(validateReport(sample, schema), []);
  assert.ok(findReports(samplesDir).length >= 1);
});

test("CLI with no arguments checks the bundled samples and passes", () => {
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /passed: [1-9]\d* report/);
});

const invalidCases = [
  ["missing machine.os", (r) => delete r.machine.os, /missing required property os/],
  ["missing orcel_commit", (r) => delete r.orcel_commit, /missing required property orcel_commit/],
  ["short commit", (r) => (r.orcel_commit = "40fc9f0"), /orcel_commit: does not match/],
  ["uppercase commit", (r) => (r.orcel_commit = r.orcel_commit.toUpperCase()), /orcel_commit: does not match/],
  ["wrong schema id", (r) => (r.schema = "orcel-benchmark-report/2"), /schema: must equal/],
  ["unknown suite", (r) => (r.suite = "speed"), /suite: "speed" is not one of/],
  ["unknown os", (r) => (r.machine.os = "freebsd"), /machine\/os: "freebsd" is not one of/],
  ["unknown planner kind", (r) => (r.planner.kind = "human"), /planner\/kind/],
  ["empty rows", (r) => (r.rows = []), /rows: fewer than 1 items/],
  ["row missing observed", (r) => delete r.rows[0].observed, /rows\/0: missing required property observed/],
  ["unknown status", (r) => (r.rows[0].status = "flaky"), /rows\/0\/status/],
  ["extra top-level property", (r) => (r.notes = "fast"), /unexpected property notes/],
  ["page text in a row", (r) => (r.rows[0].page_text = "Welcome back"), /unexpected property page_text/],
  [
    "prose in observed",
    (r) => (r.rows[0].observed = "Clicked the Sign in button on the page"),
    /rows\/0\/observed: does not match/
  ],
  ["prose in evidence", (r) => (r.rows[0].evidence = "see the screenshot I took"), /rows\/0\/evidence: does not match/],
  ["negative latency", (r) => (r.rows[0].latency_ms.p95 = -1), /latency_ms\/p95: below minimum 0/],
  ["latency missing p95", (r) => delete r.rows[0].latency_ms.p95, /latency_ms: missing required property p95/],
  ["fractional steps", (r) => (r.rows[0].steps = 1.5), /rows\/0\/steps: expected integer/],
  ["string tokens", (r) => (r.rows[0].tokens_in = "12"), /rows\/0\/tokens_in: expected integer/],
  ["machine as array", (r) => (r.machine = []), /machine: expected object/]
];

for (const [name, mutate, expected] of invalidCases) {
  test(`invalid: ${name}`, () => {
    const report = copy();
    mutate(report);
    const errors = validateReport(report, schema);
    assert.ok(errors.length > 0, "expected at least one error");
    assert.ok(
      errors.some((e) => expected.test(e)),
      `no error matched ${expected}: ${errors.join("; ")}`
    );
  });
}

test("CLI walks a directory, ignores non-report files, and fails with messages", () => {
  withTempDir((dir) => {
    mkdirSync(join(dir, "nested"));
    writeFileSync(join(dir, "ok.report.json"), JSON.stringify(sample));
    const bad = copy();
    delete bad.machine.os;
    writeFileSync(join(dir, "nested", "bad.report.json"), JSON.stringify(bad));
    writeFileSync(join(dir, "nested", "broken.report.json"), "{ not json");
    writeFileSync(join(dir, "ignored.json"), "{}");

    const { checked, failures } = checkTargets([dir], schema);
    assert.equal(checked, 3);
    assert.equal(failures.length, 2);

    const result = run(dir);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /bad\.report\.json: \/machine: missing required property os/);
    assert.match(result.stderr, /broken\.report\.json: invalid JSON/);
    assert.match(result.stderr, /2 problem\(s\) in 3 report\(s\)/);
  });
});

test("CLI passes on a directory of valid reports", () => {
  withTempDir((dir) => {
    writeFileSync(join(dir, "a.report.json"), JSON.stringify(sample));
    const result = run(dir);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /passed: 1 report/);
  });
});

test("CLI fails on a missing path", () => {
  const result = run(join(tmpdir(), "orcel-bm01-does-not-exist"));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /no such file or directory/);
});

test("checker refuses a schema with keywords it does not implement", () => {
  withTempDir((dir) => {
    const path = join(dir, "schema.json");
    writeFileSync(path, JSON.stringify({ type: "object", properties: { a: { type: "string", format: "date" } } }));
    assert.throws(() => loadSchema(path), /keyword format .* not supported/);
  });
});
