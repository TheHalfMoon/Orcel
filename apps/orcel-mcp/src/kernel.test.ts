import assert from "node:assert/strict";
import test from "node:test";
import { buildDaemonEnv, buildRequest } from "./kernel.js";

test("daemon environment drops generic and Orcel secret variables", () => {
  const env = buildDaemonEnv({
    PATH: "safe-path",
    ORCEL_WORKSPACE_ROOT: "C:\\work",
    ORCEL_WORKSPACES_JSON: "[]",
    OPENAI_API_KEY: "must-not-leak",
    ORCEL_TUNNEL_TOKEN: "must-not-leak",
    ORCEL_API_KEY: "must-not-leak",
    RANDOM_SECRET: "must-not-leak"
  });

  assert.equal(env.PATH, "safe-path");
  assert.equal(env.ORCEL_WORKSPACE_ROOT, "C:\\work");
  assert.equal(env.ORCEL_WORKSPACES_JSON, "[]");
  assert.equal(env.OPENAI_API_KEY, undefined);
  assert.equal(env.ORCEL_TUNNEL_TOKEN, undefined);
  assert.equal(env.ORCEL_API_KEY, undefined);
  assert.equal(env.RANDOM_SECRET, undefined);
});

test("request builder preserves the declared bounded capability", () => {
  const request = buildRequest({
    sessionId: "session",
    workspaceId: "default",
    capability: "fs.read",
    operation: "read",
    target: "README.md",
    arguments: {}
  });

  assert.equal(request.version, 1);
  assert.equal(request.capability, "fs.read");
  assert.equal(request.operation, "read");
  assert.equal(request.target, "README.md");
  assert.equal(request.workspace_id, "default");
});

/**
 * SG-000120 RJ-03: when orceld dies, the session's next call starts a new
 * orceld under the same session id; the request in flight is rejected and
 * never sent again.
 */
test("rj03 a crashed orceld is replaced for the same session without re-sending", async () => {
  const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const { KernelClient } = await import("./kernel.js");
  const dir = mkdtempSync(join(tmpdir(), "orcel-rj03-kernel-"));
  const daemon = join(dir, "fake-orceld.mjs");
  writeFileSync(
    daemon,
    [
      'import { createInterface } from "node:readline";',
      "let seen = 0;",
      "createInterface({ input: process.stdin }).on('line', (line) => {",
      "  const request = JSON.parse(line);",
      "  seen += 1;",
      "  if (request.capability === 'crash') process.exit(3);",
      "  process.stdout.write(JSON.stringify({ ok: true, request_id: request.request_id, result: { pid: process.pid, seen, session: request.client_session_id } }) + '\\n');",
      "});"
    ].join("\n")
  );
  const client = new KernelClient(process.execPath, null, null, [daemon]);
  try {
    const first = (await client.call({ workspaceId: "default", capability: "system.status", operation: "get" })) as {
      result: { pid: number; session: string };
    };
    assert.equal(first.result.session, client.sessionId);
    await assert.rejects(
      client.call({ workspaceId: "default", capability: "crash", operation: "now", timeoutMs: 5000 }),
      /orceld exited/
    );
    const second = (await client.call({ workspaceId: "default", capability: "system.status", operation: "get" })) as {
      result: { pid: number; seen: number; session: string };
    };
    assert.notEqual(second.result.pid, first.result.pid, "a new orceld");
    assert.equal(second.result.session, client.sessionId, "the same session");
    assert.equal(second.result.seen, 1, "the crashed request was not sent again");
  } finally {
    client.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
