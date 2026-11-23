// The founder decision effective 2026-11-23
// (docs/governance/2026-11-23-jev-retirement.md): Jev is no longer a review
// gate, the Alibaba OCR gate and its fork refusal stay and gain the range check
// (review-range.test.ts), and past Jev evidence stays as recorded.
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

const gates = read(".github/workflows/review-gates.yml");

const stripComments = (text: string): string => text.split("\n").filter((line) => !/^\s*#/.test(line)).join("\n");

/** The job's steps, as text without comment lines. */
function stepsOf(workflow: string): string[] {
  const start = workflow.indexOf("\n    steps:\n") + "\n    steps:\n".length;
  return stripComments(workflow.slice(start)).split(/^ {6}(?=- )/m).filter((step) => step.trim() !== "");
}

test("the review gates workflow is the Alibaba OCR job alone, read-only and with no credential", () => {
  // Every top-level key, every key at job depth and every key of the job,
  // however it is quoted or commented: one job, no job-level condition,
  // permissions or tolerance.
  const lines = gates.split("\n");
  const top = lines.filter((line) => /^[^\s#]/.test(line));
  assert.deepEqual(top, ["name: Review Gates", "on:", "permissions:", "concurrency:", "jobs:"]);
  const jobs = lines.slice(lines.indexOf("jobs:") + 1);
  assert.deepEqual(jobs.filter((line) => /^ {1,3}\S/.test(line)), ["  ocr-delegation:"]);
  assert.deepEqual(
    jobs.filter((line) => /^ {4}[^\s#]/.test(line)).map((line) => line.trim()),
    ["name: Alibaba OCR Delegation", "runs-on: ubuntu-latest", "timeout-minutes: 10", "env:", "steps:"]
  );
  assert.ok(
    stripComments(gates).startsWith(
      "name: Review Gates\n\non:\n  pull_request_target:\n    branches: [main]\n    types: [opened, synchronize, reopened, edited]\n\npermissions:\n  contents: read\n\nconcurrency:\n"
    )
  );
  // The job's own environment: nothing there steers node, git or bash.
  assert.ok(stripComments(gates).includes([
    "    env:",
    "      OCR_BIN: /tmp/orcel-ocr",
    "      OCR_OUT: /tmp/orcel-ocr-output",
    "      OCR_URL: https://github.com/alibaba/open-code-review/releases/download/v1.12.9/opencodereview-linux-amd64",
    "      OCR_SHA256: 9105c7081b8362a1cb0167f1ddfd1437e147a0e3c9a5af89c03c8859a5b0f0e8",
    "    steps:",
    ""
  ].join("\n")));
  assert.match(gates, /\npermissions:\n {2}contents: read\n\n/);
  assert.equal(gates.match(/permissions/g)?.length, 1);
  // secrets.X, secrets['X'], toJSON(secrets), github.token, github['token'].
  assert.equal(/secrets|github\s*\.\s*token|github\s*\[|toJSON|GITHUB_TOKEN|GH_TOKEN|id-token/i.test(gates), false);
  assert.equal(/continue-on-error|\|\|\s*(true|:)|set \+e|exit 0/.test(gates), false);
  assert.equal(/jev|typesafe/i.test(gates), false);
  assert.equal(existsSync(join(repo, ".github", "scripts", "jev-exact-diff.mjs")), false);
});

test("the Alibaba OCR job's steps keep their order, conditions and pins", () => {
  const steps = stepsOf(gates);
  assert.deepEqual(
    steps.map((step) => /^- name: (.*)$/m.exec(step)?.[1] ?? /^- uses: ([^@]+)@/m.exec(step)?.[1]),
    [
      "Refuse a pull request from a fork",
      "actions/setup-node",
      "actions/checkout",
      "Refuse a diff that cannot be reviewed as text",
      "Install checksum-pinned OpenCodeReview before candidate checkout",
      "actions/checkout",
      "Generate deterministic delegation spec",
      "actions/upload-artifact"
    ]
  );
  const step = (index: number): string => steps[index] ?? "";
  const [fork, baseCheckout, range, install, headCheckout, spec, upload] = [0, 2, 3, 4, 5, 6, 7].map(step) as [
    string, string, string, string, string, string, string
  ];

  // One condition in the whole file, however its key is written: the evidence
  // is uploaded whatever happened. `if: false` on any step fails here.
  assert.deepEqual(gates.match(/^[\s-]*["']?if["']?\s*:.*$/gm), ["        if: always()"]);
  assert.ok(upload.includes("if: always()"));

  const uses = gates.match(/^.*\buses["']?\s*:.*$/gm) ?? [];
  assert.equal(uses.length, 4);
  for (const line of uses) assert.match(line, /uses: [\w./-]+@[0-9a-f]{40} # v\d+$/);

  // Whole steps, so no key, environment entry or command can be added unseen:
  // the fork refusal, and the range check from the base with the head as data.
  const whole = (...lines: string[]): string => `- ${lines.join("\n        ")}\n`;
  assert.equal(fork, whole(
    "name: Refuse a pull request from a fork",
    "env:",
    "  HEAD_REPO: ${{ github.event.pull_request.head.repo.full_name }}",
    "  THIS_REPO: ${{ github.repository }}",
    "shell: bash",
    "run: |",
    "  set -euo pipefail",
    '  if [ "$HEAD_REPO" != "$THIS_REPO" ]; then',
    `    echo "::error::OCR delegation doesn't run for a pull request from a fork; it stays unqualified."`,
    "    exit 1",
    "  fi"
  ));
  assert.equal(step(1), whole("uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4", "with:", '  node-version: "24"'));
  const checkout = "uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4";
  assert.equal(baseCheckout, whole(
    checkout,
    "with:",
    "  fetch-depth: 0",
    "  persist-credentials: false",
    "  ref: ${{ github.event.pull_request.base.sha }}",
    "  path: review-range-base"
  ));
  assert.equal(range, whole(
    "name: Refuse a diff that cannot be reviewed as text",
    "working-directory: review-range-base",
    "env:",
    "  BASE_SHA: ${{ github.event.pull_request.base.sha }}",
    "  HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
    "  PR_NUMBER: ${{ github.event.pull_request.number }}",
    "shell: bash",
    "run: |",
    "  set -euo pipefail",
    '  test "$(git rev-parse HEAD)" = "$BASE_SHA"',
    '  git fetch --no-tags origin "refs/pull/$PR_NUMBER/head"',
    '  test "$(git rev-parse FETCH_HEAD)" = "$HEAD_SHA"',
    '  node .github/scripts/check-review-range.mjs "$BASE_SHA" "$HEAD_SHA" .'
  ));
  assert.equal(headCheckout, whole(
    checkout,
    "with:",
    "  fetch-depth: 0",
    "  persist-credentials: false",
    "  ref: ${{ github.event.pull_request.head.sha }}"
  ));
  // Nothing later changes what an earlier step runs.
  assert.equal(/GITHUB_(ENV|PATH|OUTPUT)/.test(gates), false);
  assert.match(spec, /^- name: Generate deterministic delegation spec\n {8}env:\n {10}BASE_SHA: .*\n {10}HEAD_SHA: .*\n {8}shell: bash\n {8}run: \|\n {10}set -euo pipefail\n/);

  // OCR's checksum, checked before the binary is made executable or run.
  assert.equal(gates.match(/OCR_SHA256/g)?.length, 2);
  assert.match(
    install,
    /set -euo pipefail\n.*"\$OCR_URL" --output "\$OCR_BIN"\n +echo "\$OCR_SHA256 {2}\$OCR_BIN" \| sha256sum --check --status\n +chmod 700 "\$OCR_BIN"\n/
  );
  assert.match(spec, /test "\$\(git merge-base "\$BASE_SHA" "\$HEAD_SHA"\)" = "\$BASE_SHA"\n/);
  assert.match(spec, /git diff --quiet "\$BASE_SHA" "\$HEAD_SHA" -- \.opencodereview/);
});

test("no open grain requires Jev, and each requires the retained items", () => {
  const open = specs.filter((spec) => spec.state !== "CLOSED");
  assert.ok(open.length > 0);
  for (const spec of open) {
    const review = spec.review ?? {};
    assert.equal(/jev/i.test(JSON.stringify(review)), false, spec.id);
    assert.equal(/jev/i.test(JSON.stringify([spec.scope, spec.acceptance, spec.done_when])), false, spec.id);
    assert.match(String(review.independent_code_review), /^required on each exact head, .*not a GitHub check$/, spec.id);
    assert.equal(review.exact_head_ci, true, spec.id);
    assert.equal(review.rust_and_platform_tests, true, spec.id);
    assert.match(String(review.alibaba_open_code_review), /manual (review of excluded files|exclusions)/, spec.id);
    assert.ok(review.security_review, spec.id);
    assert.match(String(review.adversarial_tests), /^negative and adversarial regression tests/, spec.id);
    assert.equal(review.zero_unresolved_blocking_findings, true, spec.id);
    assert.equal(review.post_merge_verification, true, spec.id);
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

test("the normative review rule says what nothing enforces, and D1 authorizes nothing", () => {
  const rule = read("docs/governance/DIFFCIPLINE.md").replace(/\s+/g, " ");
  for (const text of [
    "Independent code review is a process rule. No GitHub check enforces it",
    "two separate reviews, each with its own record",
    "The required status checks carry no `integration_id`",
    "Who records them: whoever merges the pull request, before merging",
    "It can never authorize a merge, clear a gate, stand in for a review above, or authorize a privileged operation."
  ]) assert.ok(rule.includes(text), text);
  const unenforced = rule.slice(rule.indexOf("**What nothing in the ruleset enforces**"), rule.indexOf("**D1 is optional"));
  for (const text of [
    "independent code review", "targeted security review", "negative and adversarial regression tests",
    "manual review of the files Open Code Review excludes", "zero unresolved blocking findings",
    "resolved review threads", "post-merge verification", "platform jobs that are not required checks",
    "authority service artifact", "that a required check was posted by its own workflow"
  ]) assert.ok(unenforced.includes(text), text);
});
