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
  ["machine as array", (r) => (r.machine = []), /machine: expected object/],
  [
    "prose in machine.cpu",
    (r) => (r.machine.cpu = "Clicked the Sign in button on the page"),
    /machine\/cpu: does not match/
  ],
  ["machine.cpu too long", (r) => (r.machine.cpu = "A".repeat(65)), /machine\/cpu: longer than 64/],
  ["URL in evidence", (r) => (r.rows[0].evidence = "https://example.com/leak/x"), /rows\/0\/evidence: does not match/],
  ["absolute path in evidence", (r) => (r.rows[0].evidence = "/etc/passwd"), /rows\/0\/evidence: does not match/],
  ["dot segment in evidence", (r) => (r.rows[0].evidence = "runs/../secrets"), /rows\/0\/evidence: does not match/]
];

// Credential-shaped values are assembled from parts so this file itself never
// contains a secret-shaped literal.
const credentialShapes = [
  ["sk-" + "ant-api03-abcdef", "anthropic"],
  ["sk_" + "live_abcdef", "stripe"],
  ["gh" + "p_abcdef123456", "github classic"],
  ["github" + "_pat_abcdef", "github fine-grained"],
  ["xo" + "xb-123456-abcdef", "slack"],
  ["AK" + "IAABCDEFGHIJKLMNOP", "aws"]
];

for (const [value, kind] of credentialShapes) {
  test(`invalid: ${kind} credential shape in planner.model, observed and evidence`, () => {
    for (const [field, set] of [
      [/planner\/model: does not match/, (r) => (r.planner.model = value)],
      [/planner\/name: does not match/, (r) => (r.planner.name = value)],
      [/rows\/0\/observed: does not match/, (r) => (r.rows[0].observed = value)],
      [/rows\/0\/evidence: does not match/, (r) => (r.rows[0].evidence = `${value}/run.json`)]
    ]) {
      const report = copy();
      set(report);
      const errors = validateReport(report, schema);
      assert.ok(
        errors.some((e) => field.test(e)),
        `${kind} value not rejected (${field}): ${errors.join("; ")}`
      );
    }
  });
}

test("valid: realistic short cpu names, numeric run id and plain model ids", () => {
  for (const cpu of ["Apple M2", "AMD Ryzen 9 7950X", "Intel i7-1185G7", "Snapdragon X Elite"]) {
    const report = copy();
    report.machine.cpu = cpu;
    assert.deepEqual(validateReport(report, schema), [], cpu);
  }
  const report = copy();
  report.rows[0].evidence = "18273645123";
  report.planner = { kind: "mcp-client", name: "claude-code", version: "2.1.0", model: "claude-opus-5-5" };
  assert.deepEqual(validateReport(report, schema), []);
});

test("regression: api_key, password and secret properties are rejected at every level", () => {
  for (const name of ["api_key", "password", "secret"]) {
    for (const [where, target] of [
      ["(root)", (r) => r],
      ["/machine", (r) => r.machine],
      ["/planner", (r) => r.planner],
      ["/rows/0", (r) => r.rows[0]],
      ["/rows/0/latency_ms", (r) => r.rows[0].latency_ms]
    ]) {
      const report = copy();
      target(report)[name] = "value";
      const errors = validateReport(report, schema);
      assert.ok(
        errors.includes(`${where}: unexpected property ${name}`),
        `${name} at ${where} not rejected: ${errors.join("; ")}`
      );
    }
  }
});

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
