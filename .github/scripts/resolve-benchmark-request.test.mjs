import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  BENCHMARK_DATASETS,
  BENCHMARK_HARNESSES,
  DEFAULT_DATASET,
  DEFAULT_HARNESSES,
  resolveBenchmarkRequest,
} from "./resolve-benchmark-request.mjs";

const sweLean = { dataset: "swe-lean", reasoning: "low", attempts: "5" };
const deepsweLean = { dataset: "deepswe-lean", reasoning: "high", attempts: "3" };
const defaults = { harness: "orcel-code,opencode,pi", slug: "orcel-code+opencode+pi", ...sweLean };

const sha = "a".repeat(40);
const pull = {
  number: 42,
  state: "open",
  head: { sha, repo: { full_name: "vercel/orcel", fork: false } },
  base: { repo: { full_name: "vercel/orcel" } },
};

function fixture({
  eventName = "issue_comment",
  body = "/benchmark",
  permission = "write",
  pr = pull,
} = {}) {
  const calls = [];
  const context = {
    eventName,
    repo: { owner: "vercel", repo: "orcel" },
    sha: "b".repeat(40),
    payload:
      eventName === "issue_comment"
        ? {
            action: "created",
            issue: { number: 42, pull_request: {} },
            comment: { body, user: { login: "alice", type: "User" } },
          }
        : eventName === "pull_request"
          ? { pull_request: pull }
          : { inputs: {} },
  };
  const github = {
    rest: {
      repos: {
        async getCollaboratorPermissionLevel(input) {
          calls.push(["permission", input]);
          return { data: { permission } };
        },
      },
      pulls: {
        async get(input) {
          calls.push(["pull", input]);
          return { data: pr };
        },
      },
    },
  };
  return { context, github, calls };
}

const resolve = (input) => resolveBenchmarkRequest(input);

test("automatic PR runs compare orcel-code with opencode and pi at the exact current PR head", async () => {
  assert.deepEqual(DEFAULT_HARNESSES, ["orcel-code", "opencode", "pi"]);
  const input = fixture({ eventName: "pull_request" });
  assert.deepEqual(await resolve(input), { ...defaults, sha, pr: "42" });
  assert.deepEqual(input.calls, [["pull", { owner: "vercel", repo: "orcel", pull_number: 42 }]]);
});

test("bare comment command reruns the default harnesses at the PR head, not default-branch github.sha", async () => {
  const input = fixture();
  assert.deepEqual(await resolve(input), { ...defaults, sha, pr: "42" });
  assert.deepEqual(input.calls[0], [
    "permission",
    { owner: "vercel", repo: "orcel", username: "alice" },
  ]);
});

for (const harness of BENCHMARK_HARNESSES) {
  test(`a comment can select ${harness} independently`, async () => {
    assert.deepEqual(await resolve(fixture({ body: `/benchmark ${harness}` })), {
      harness,
      slug: harness,
      ...sweLean,
      sha,
      pr: "42",
    });
  });
}

test("a comment can select several harnesses, comma- or space-separated, deduplicated in order", async () => {
  for (const body of [
    "/benchmark pi,orcel-code",
    "/benchmark pi orcel-code",
    "/benchmark pi, orcel-code,pi",
  ]) {
    const result = await resolve(fixture({ body }));
    assert.equal(result.harness, "pi,orcel-code");
    assert.equal(result.slug, "pi+orcel-code");
  }
});

test("manual dispatch offers exactly the datasets the resolver accepts", async () => {
  const workflow = await readFile(
    new URL("../workflows/orcel-code-benchmark.yml", import.meta.url),
    "utf8",
  );
  const input = /\n {6}dataset:\n(?: {8}.*\n)+/u.exec(workflow)?.[0] ?? "";
  const options = /^ {8}options: \[(.*)\]$/mu.exec(input)?.[1].split(/, */u);
  assert.deepEqual(options, Object.keys(BENCHMARK_DATASETS));
  assert.equal(/^ {8}default: (\S+)$/mu.exec(input)?.[1], DEFAULT_DATASET);
});

test("a comment can select a dataset, with the default harnesses or its own list", async () => {
  assert.deepEqual(await resolve(fixture({ body: "/benchmark deepswe-lean" })), {
    ...defaults,
    ...deepsweLean,
    sha,
    pr: "42",
  });
  for (const body of [
    "/benchmark deepswe-lean orcel-code,pi",
    "/benchmark orcel-code pi deepswe-lean",
    "/benchmark orcel-code, deepswe-lean, pi",
  ]) {
    const result = await resolve(fixture({ body }));
    assert.deepEqual(
      [result.dataset, result.reasoning, result.attempts, result.harness, result.slug],
      ["deepswe-lean", "high", "3", "orcel-code,pi", "orcel-code+pi"],
    );
  }
  assert.equal((await resolve(fixture({ body: "/benchmark swe-lean pi" }))).dataset, "swe-lean");
});

test("a comment cannot name two datasets", async () => {
  await assert.rejects(
    resolve(fixture({ body: "/benchmark swe-lean deepswe-lean" })),
    /at most one benchmark dataset/u,
  );
});

for (const permission of ["read", "triage", "none"]) {
  test(`${permission} permission cannot launch a benchmark`, async () => {
    const input = fixture({ permission });
    assert.equal(await resolve(input), null);
    assert.equal(input.calls.length, 1);
  });
}

for (const permission of ["write", "maintain", "admin"]) {
  test(`${permission} permission can request a benchmark`, async () => {
    assert.equal((await resolve(fixture({ permission }))).harness, defaults.harness);
  });
}

test("permission lookup errors fail closed", async () => {
  const input = fixture();
  input.github.rest.repos.getCollaboratorPermissionLevel = async () => {
    throw new Error("permission unavailable");
  };
  await assert.rejects(resolve(input), /permission unavailable/u);
  assert.equal(input.calls.length, 0);
});

test("unrelated comments, bots, edited comments and ordinary issues are ignored", async () => {
  for (const change of [
    (payload) => {
      payload.comment.body = "Looks good";
    },
    (payload) => {
      payload.comment.user.type = "Bot";
    },
    (payload) => {
      payload.action = "edited";
    },
    (payload) => {
      delete payload.issue.pull_request;
    },
  ]) {
    const input = fixture();
    change(input.context.payload);
    assert.equal(await resolve(input), null);
    assert.deepEqual(input.calls, []);
  }
});

test("invalid or injected commands never become action inputs", async () => {
  for (const body of [
    "/benchmark missing",
    "/benchmark codex; echo nope",
    "/benchmark codex\necho nope",
    "/benchmark codex extra",
    "/benchmark codex,",
    "/benchmark codex;pi",
  ]) {
    await assert.rejects(
      resolve(fixture({ body })),
      /Use \/benchmark|Supported benchmark harnesses/u,
    );
  }
});

test("closed, forked and cross-repository PRs are not executed", async () => {
  for (const change of [
    (pr) => {
      pr.state = "closed";
    },
    (pr) => {
      pr.head.repo.fork = true;
    },
    (pr) => {
      pr.head.repo.full_name = "alice/orcel";
    },
    (pr) => {
      pr.head.repo = null;
    },
    (pr) => {
      pr.base.repo.full_name = "another/repository";
    },
  ]) {
    const pr = structuredClone(pull);
    change(pr);
    assert.equal(await resolve(fixture({ pr })), null);
  }
});

test("a superseded pull_request event cannot run or cancel the current benchmark", async () => {
  const input = fixture({ eventName: "pull_request" });
  input.context.payload = {
    pull_request: { ...pull, head: { ...pull.head, sha: "c".repeat(40) } },
  };
  assert.equal(await resolve(input), null);
});

test("manual dispatch defaults to the default harnesses and validates an explicit list", async () => {
  const input = fixture({ eventName: "workflow_dispatch" });
  assert.deepEqual(await resolve(input), { ...defaults, sha: input.context.sha, pr: "" });
  input.context.payload.inputs.harness = "codex";
  assert.equal((await resolve(input)).harness, "codex");
  input.context.payload.inputs.harness = "codex, pi";
  assert.equal((await resolve(input)).harness, "codex,pi");
  input.context.payload.inputs.harness = "missing";
  await assert.rejects(resolve(input), /Supported benchmark harnesses/u);
});

test("manual dispatch can publish a deepswe-lean result and rejects unknown datasets", async () => {
  const input = fixture({ eventName: "workflow_dispatch" });
  input.context.payload.inputs = { harness: "", dataset: "deepswe-lean" };
  assert.deepEqual(await resolve(input), {
    ...defaults,
    ...deepsweLean,
    sha: input.context.sha,
    pr: "",
  });
  input.context.payload.inputs.dataset = "terminal-bench";
  await assert.rejects(resolve(input), /Supported benchmark datasets: swe-lean, deepswe-lean/u);
});

test("pushes to main publish the default harnesses at the pushed commit", async () => {
  const input = fixture({ eventName: "push" });
  assert.deepEqual(await resolve(input), { ...defaults, sha: input.context.sha, pr: "" });
  assert.deepEqual(input.calls, []);
});

test("other events never run a benchmark", async () => {
  assert.equal(await resolve(fixture({ eventName: "schedule" })), null);
});

test("workflow names and concurrency preserve independent authorized harness runs", async () => {
  const workflow = await readFile(
    new URL("../workflows/orcel-code-benchmark.yml", import.meta.url),
    "utf8",
  );
  assert.match(workflow, /^name: orcel-code\n/u);
  assert.match(workflow, /name: Benchmark harness/u);
  assert.match(workflow, /issue_comment:\n\s+types: \[created\]/u);
  assert.match(
    workflow,
    /if: needs\.request\.outputs\.run == 'true' && github\.event_name == 'workflow_dispatch'/u,
  );
  // A deepswe-lean run never cancels or overwrites a swe-lean run of the same harnesses.
  assert.match(
    workflow,
    /group: orcel-code-.*needs\.request\.outputs\.pr.*needs\.request\.outputs\.dataset.*needs\.request\.outputs\.slug/u,
  );
  assert.match(
    workflow,
    /artifact-name: \$\{\{ needs\.request\.outputs\.dataset \}\}-\$\{\{ needs\.request\.outputs\.slug \}\}/u,
  );
  assert.match(workflow, /push:\n\s+branches: \[main\]/u);
  // Each dataset's attempts run in waves of the action's maximum of 16 sandboxes.
  assert.match(workflow, /attempts: \$\{\{ needs\.request\.outputs\.attempts \}\}/u);
  assert.match(workflow, /concurrency: "16"/u);
  assert.match(workflow, /agent-ref: \$\{\{ needs\.request\.outputs\.sha \}\}/u);
});

test("the consumer tracks eve-bench main and owns its model selection", async () => {
  const workflow = await readFile(
    new URL("../workflows/orcel-code-benchmark.yml", import.meta.url),
    "utf8",
  );
  assert.match(workflow, /repository: vercel-labs\/eve-bench\n\s+ref: main\n/u);
  assert.match(workflow, /uses: \.\/\.eve-bench-action/u);
  assert.match(
    workflow,
    /model: \$\{\{ vars\.ORCEL_CODE_BENCH_MODEL \|\| 'anthropic\/claude-sonnet-5\.5' \}\}/u,
  );
  assert.match(workflow, /reasoning: \$\{\{ needs\.request\.outputs\.reasoning \}\}\n/u);
  assert.doesNotMatch(workflow, /runner-revision:/u);
  assert.match(workflow, /blob-token: \$\{\{ secrets\.EVE_BENCH_BLOB_READ_WRITE_TOKEN \}\}/u);
  assert.doesNotMatch(workflow, /artifact-id/u);
  assert.match(workflow, /dataset: \$\{\{ needs\.request\.outputs\.dataset \}\}\n/u);
  assert.match(workflow, /contenders: eve-code@baseline,eve-code@head\n/u);
  assert.doesNotMatch(workflow, /^\s+task:/mu);
  assert.equal((workflow.match(/uses: \.\/\.eve-bench-action/gu) ?? []).length, 1);
});


test("external-cost E2E workflows stay manual-only on pull requests", async () => {
  const local = await readFile(new URL("../workflows/e2e-local.yml", import.meta.url), "utf8");
  assert.match(local, /name: model-e2e-policy/u);
  assert.match(local, /github\.event_name.*workflow_dispatch/u);
  assert.match(
    local,
    /if: needs\.changes\.outputs\.relevant == 'true' && needs\.model-e2e-policy\.outputs\.run == 'true'/u,
  );
  assert.match(local, /DISCOVERY_RESULT:/u);
  assert.match(local, /Real-model E2E intentionally skipped: \$POLICY_REASON/u);
  assert.match(local, /AI_GATEWAY_API_KEY is required for a manual real-model E2E run/u);

  const vercel = await readFile(new URL("../workflows/e2e-vercel.yml", import.meta.url), "utf8");
  assert.match(vercel, /name: vercel-e2e-policy/u);
  assert.match(vercel, /github\.event_name.*workflow_dispatch/u);
  assert.match(
    vercel,
    /if: needs\.changes\.outputs\.relevant == 'true' && needs\.vercel-e2e-policy\.outputs\.run == 'true'/u,
  );
  assert.match(vercel, /DISCOVERY_RESULT:/u);
  assert.match(vercel, /Vercel E2E intentionally skipped: \$POLICY_REASON/u);
  assert.match(vercel, /VERCEL_TOKEN and VERCEL_PROJECT_ID are required for a manual Vercel E2E run/u);
});
