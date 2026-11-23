// The founder decision effective 2026-11-23
// (docs/governance/2026-11-23-jev-retirement.md): Jev is no longer a review
// gate, the Alibaba OCR gate and its fork refusal stay, and past Jev evidence
// stays as recorded.
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const read = (path: string): string => readFileSync(join(repo, path), "utf8").replace(/\r\n/g, "\n");

interface Spec {
  id: string;
  state: string;
  scope?: unknown;
  acceptance: unknown;
  done_when?: unknown;
  review?: Record<string, unknown>;
  canonical_evidence?: Record<string, unknown>;
}
const specs = readdirSync(join(repo, ".specgrain", "specs"))
  .filter((name) => name.endsWith(".json"))
  .map((name) => JSON.parse(read(`.specgrain/specs/${name}`)) as Spec);

test("the review gates workflow is the Alibaba OCR job alone, still refusing forks", () => {
  const text = read(".github/workflows/review-gates.yml");
  const jobs = text.slice(text.indexOf("\njobs:\n") + "\njobs:\n".length);
  assert.deepEqual(jobs.match(/^ {2}[\w-]+:$/gm), ["  ocr-delegation:"]);
  assert.match(jobs, /^ {4}name: Alibaba OCR Delegation$/m);
  assert.match(jobs, /- name: Refuse a pull request from a fork\n/);
  assert.match(jobs, /if \[ "\$HEAD_REPO" != "\$THIS_REPO" \]; then\n.*::error::.*\n\s+exit 1\n/);
  // A skipped or tolerated job would pass the required check.
  assert.equal(/^ {4}if:/m.test(jobs), false, "job-level if");
  assert.equal(text.includes("continue-on-error"), false);
  // Read-only, and no credential: the Jev job's secret went with it.
  assert.deepEqual(text.match(/^permissions:\n(?: {2}.*\n)+/gm), ["permissions:\n  contents: read\n"]);
  assert.equal(/^ +permissions:/m.test(text), false, "a job-level permissions block");
  assert.equal(text.includes("secrets."), false);
  assert.equal(/jev|typesafe/i.test(text), false);
  assert.equal(existsSync(join(repo, ".github", "scripts", "jev-exact-diff.mjs")), false);
});

test("the whitespace check over a pull request's range stays a required Governance step", () => {
  const ci = read(".github/workflows/ci.yml");
  const governance = ci.slice(ci.indexOf("\n  governance:\n"));
  assert.match(governance, /git diff --check "\$BASE_SHA" "\$HEAD_SHA"\n/);
});

test("no open grain requires Jev, and each requires independent code review", () => {
  const open = specs.filter((spec) => spec.state !== "CLOSED");
  assert.ok(open.length > 0);
  for (const spec of open) {
    const review = spec.review ?? {};
    assert.equal(/jev/i.test(JSON.stringify(review)), false, spec.id);
    assert.equal(/jev/i.test(JSON.stringify([spec.scope, spec.acceptance, spec.done_when])), false, spec.id);
    assert.match(String(review.independent_code_review), /^required on each exact head, /, spec.id);
    assert.match(String(review.independent_code_review), /not a GitHub check$/, spec.id);
    assert.equal(review.exact_head_ci, true, spec.id);
    assert.ok(review.alibaba_open_code_review, spec.id);
    assert.ok(review.security_review, spec.id);
    assert.ok(review.adversarial_tests, spec.id);
  }
});

test("Jev evidence of grains closed before the decision stays as recorded", () => {
  const byId = new Map(specs.map((spec) => [spec.id, spec]));
  for (const [id, jev] of [
    ["SG-000009", "PASSED: 20/20 hunks, zero findings, zero blocking findings"],
    ["SG-000010", "PASSED: 46/46 hunks, zero findings, zero blocking findings"]
  ] as const) {
    assert.equal(byId.get(id)?.state, "CLOSED", id);
    assert.equal(byId.get(id)?.canonical_evidence?.jev, jev, id);
  }
  // The 104 grains that had closed with a Jev requirement keep it.
  const required = specs.filter((spec) => spec.review?.jev_semantic_review === true);
  assert.equal(required.length, 104);
  assert.ok(required.every((spec) => spec.state === "CLOSED"));
});

test("the normative review rule names what enforces it, and D1 authorizes nothing", () => {
  const rule = read("docs/governance/DIFFCIPLINE.md");
  assert.match(rule, /Independent code review is a process rule\. No GitHub check enforces it/);
  assert.match(rule, /Who records it: whoever merges the pull request, before merging/);
  assert.match(rule, /It can never authorize a merge, clear a gate,\nstand in for a review above, or authorize a privileged operation\./);
});
