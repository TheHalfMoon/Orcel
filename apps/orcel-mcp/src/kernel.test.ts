import assert from "node:assert/strict";
import test from "node:test";
import { KernelClient, buildDaemonEnv, buildRequest, type RemoteDispatchContext } from "./kernel.js";

test("an isolated kernel keeps the session's remote context, profile, command and arguments", () => {
  const remote = { principal: "p", scopes: ["orcel.execute"] } as unknown as RemoteDispatchContext;
  // A daemon that exits at once: only what the copy was built with matters here.
  const session = new KernelClient(process.execPath, remote, "core", ["-e", ""]);
  const copy = session.isolated();
  try {
    assert.notEqual(copy, session);
    assert.deepEqual(copy.remote, session.remote);
    assert.equal(copy.profile, "core");
    const internals = (client: KernelClient) => client as unknown as { command: string; args: string[] };
    assert.equal(internals(copy).command, process.execPath);
    assert.deepEqual(internals(copy).args, ["-e", ""]);
  } finally {
    copy.close();
    session.close();
  }
});

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
 * SG-000120 RJ-03: a write that finds orceld's pipe broken, before any exit is
 * seen, fails that request and not the edge. The next call reaches a new orceld.
 */
test("rj03 a broken pipe to orceld rejects the request and is replaced", async () => {
  const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const { KernelClient } = await import("./kernel.js");
  const dir = mkdtempSync(join(tmpdir(), "orcel-rj03-pipe-"));
  const daemon = join(dir, "fake-orceld.mjs");
  writeFileSync(
    daemon,
    [
      'import { createInterface } from "node:readline";',
      "let seen = 0;",
      "createInterface({ input: process.stdin }).on('line', (line) => {",
      "  const request = JSON.parse(line);",
      "  seen += 1;",
      "  if (request.capability === 'hang') return;",
      "  process.stdout.write(JSON.stringify({ ok: true, request_id: request.request_id, result: { pid: process.pid, seen } }) + '\\n');",
      "});"
    ].join("\n")
  );
  const client = new KernelClient(process.execPath, null, null, [daemon]);
  try {
    const call = (capability: string) =>
      client.call({ workspaceId: "default", capability, operation: "get", timeoutMs: 5000 });
    const first = (await call("system.status")) as unknown as { result: { pid: number } };
    const broken = client.child;
    const gone = new Promise((resolve) => broken.once("exit", resolve));
    const inFlight = call("hang");
    // What a write to a dead orceld's pipe does, without racing its exit.
    broken.stdin.destroy(new Error("write EPIPE"));
    await assert.rejects(inFlight, /orceld stopped reading requests: write EPIPE/);
    await gone;
    const next = (await call("system.status")) as unknown as { result: { pid: number; seen: number } };
    assert.notEqual(next.result.pid, first.result.pid, "a new orceld");
    assert.equal(next.result.seen, 1, "the refused request was not sent again");
  } finally {
    client.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a session's hello is sent once, bounded, and again to a replacement orceld", async () => {
  const { mkdtempSync, writeFileSync, readFileSync, rmSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(join(tmpdir(), "orcel-hello-kernel-"));
  const daemon = join(dir, "fake-orceld.mjs");
  const log = join(dir, "requests.log");
  writeFileSync(
    daemon,
    [
      'import { createInterface } from "node:readline";',
      'import { appendFileSync } from "node:fs";',
      "createInterface({ input: process.stdin }).on('line', (line) => {",
      "  const request = JSON.parse(line);",
      "  appendFileSync(" + JSON.stringify(log) + ", line + '\\n');",
      "  if (request.capability === 'crash') process.exit(3);",
      "  process.stdout.write(JSON.stringify({ ok: true, request_id: request.request_id, result: {} }) + '\\n');",
      "});"
    ].join("\n")
  );
  const client = new KernelClient(process.execPath, null, null, [daemon]);
  try {
    client.hello("default", { name: "x".repeat(1000), version: 7 }, "stdio");
    client.hello("default", { name: "second" }, "stdio");
    await client.call({ workspaceId: "default", capability: "system.status", operation: "get" });
    await assert.rejects(
      client.call({ workspaceId: "default", capability: "crash", operation: "now", timeoutMs: 5000 }),
      /orceld exited/
    );
    await client.call({ workspaceId: "default", capability: "system.status", operation: "get" });
    const requests = readFileSync(log, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as { capability: string; arguments: Record<string, unknown> });
    const hellos = requests.filter((request) => request.capability === "session");
    assert.equal(hellos.length, 2, "once, and once more to the replacement");
    assert.equal(requests[requests.length - 2]?.capability, "session", "said before the next request");
    assert.equal((hellos[0]?.arguments.client_name as string).length, 256);
    assert.equal(hellos[0]?.arguments.client_version, null);
  } finally {
    client.close();
    rmSync(dir, { recursive: true, force: true });
  }

  const remote = { principal: "p", scopes: [] } as unknown as RemoteDispatchContext;
  const remoteClient = new KernelClient(process.execPath, remote, null, ["-e", ""]);
  try {
    remoteClient.hello("default", { name: "remote" }, "stdio");
    assert.equal((remoteClient as unknown as { helloRequest: unknown }).helloRequest, null);
  } finally {
    remoteClient.close();
  }
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
