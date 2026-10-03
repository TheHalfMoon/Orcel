import assert from "node:assert/strict";
import { test } from "node:test";

import { canarySubject, packageRevision } from "./source.mjs";

const revision = "1234567890abcdef1234567890abcdef12345678";
const packageSpec = `https://pkg.orcel.dev/${revision}/orcel.tgz`;

test("resolves a canary alias once to an immutable subject", () => {
  const calls = [];
  const subject = canarySubject("main", "current", (ref) => {
    calls.push(ref);
    return packageSpec;
  });

  assert.deepEqual(calls, ["main"]);
  assert.deepEqual(subject, {
    label: "current",
    revision,
    description: revision.slice(0, 12),
    packageSpec,
  });
});

test("rejects a non-immutable canary URL", () => {
  assert.throws(
    () => packageRevision("https://pkg.orcel.dev/main/orcel.tgz"),
    /did not resolve to an immutable revision/u,
  );
});

test("rejects a canary URL from another origin", () => {
  assert.throws(
    () => packageRevision(`https://example.com/${revision}/orcel.tgz`),
    /resolved outside/u,
  );
});
