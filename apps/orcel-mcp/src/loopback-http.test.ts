import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import test from "node:test";
import { profileTools } from "./tool_contract.js";
import {
  hostAllowed,
  originAllowed,
  startLoopbackTransport,
  validatePort,
  validateToken
} from "./transports/loopback_http.js";
import { CANONICAL_TOOL_NAMES } from "./server.js";

const TOKEN = "0123456789abcdef0123456789abcdef";

test("loopback credential and port fail closed", () => {
  assert.throws(() => validateToken(undefined));
  assert.throws(() => validateToken("short"));
  assert.equal(validateToken(TOKEN), TOKEN);
  assert.equal(validatePort(undefined), 0);
  assert.equal(validatePort(8080), 8080);
  assert.throws(() => validatePort(0));
  assert.throws(() => validatePort(70000));
  assert.throws(() => validatePort(1.5));
});

test("host validation admits only the bound loopback names", () => {
  assert.equal(hostAllowed("127.0.0.1:8080", 8080), true);
  assert.equal(hostAllowed("127.0.0.1", 8080), true);
  assert.equal(hostAllowed("localhost:8080", 8080), true);
  assert.equal(hostAllowed("localhost", 8080), true);
  assert.equal(hostAllowed("127.0.0.1:9999", 8080), false);
  assert.equal(hostAllowed("evil.example:8080", 8080), false);
  assert.equal(hostAllowed("evil.example", 8080), false);
  assert.equal(hostAllowed("127.0.0.1.evil.example:8080", 8080), false);
  assert.equal(hostAllowed("127.0.0.1.:8080", 8080), false);
  assert.equal(hostAllowed("[::1]:8080", 8080), false);
  assert.equal(hostAllowed(undefined, 8080), false);
});

test("origin validation admits only local origins and non-browser clients", () => {
  assert.equal(originAllowed(undefined, 8080), true);
  assert.equal(originAllowed("http://127.0.0.1:8080", 8080), true);
  assert.equal(originAllowed("http://localhost:8080", 8080), true);
  assert.equal(originAllowed("https://evil.example", 8080), false);
  assert.equal(originAllowed("http://evil.example:8080", 8080), false);
  assert.equal(originAllowed("http://127.0.0.1:9999", 8080), false);
  assert.equal(originAllowed("null", 8080), false);
});

test("loopback refuses to start without a credential", async () => {
  await assert.rejects(() => startLoopbackTransport({ token: "short" }));
});

async function post(
  url: string,
  body: unknown,
  headers: Record<string, string> = {}
): Promise<{ status: number; headers: Headers; text: string }> {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...headers
    },
    body: JSON.stringify(body)
  });
  return {
    status: response.status,
    headers: response.headers,
    text: await response.text()
  };
}

function authHeaders(token: string, extra: Record<string, string> = {}): Record<string, string> {
  return { authorization: `Bearer ${token}`, ...extra };
}

test("loopback serves the authoritative catalog over an authenticated session", async () => {
  const handle = await startLoopbackTransport({ token: TOKEN });
  try {
    assert.match(handle.url, /^http:\/\/127\.0\.0\.1:\d+\/mcp$/);

    const init = await post(
      handle.url,
      {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "loopback-test", version: "0" }
        }
      },
      authHeaders(TOKEN)
    );
    assert.equal(init.status, 200);
    const sessionId = init.headers.get("mcp-session-id");
    assert.ok(sessionId, "server assigns a session id");

    const initialized = await post(
      handle.url,
      { jsonrpc: "2.0", method: "notifications/initialized" },
      authHeaders(TOKEN, { "mcp-session-id": sessionId as string })
    );
    assert.equal(initialized.status, 202);

    const listed = await post(
      handle.url,
      { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
      authHeaders(TOKEN, { "mcp-session-id": sessionId as string })
    );
    assert.equal(listed.status, 200);
    const payload = JSON.parse(listed.text) as {
      result: { tools: Array<{ name: string }> };
    };
    const names = payload.result.tools.map((tool) => tool.name).sort();
    // The default local profile: no live browser tool.
    assert.deepEqual(names, [...profileTools("desktop_structured")].sort());
  } finally {
    await handle.close();
  }
});

test("loopback denies unauthenticated, forged, oversized, and unknown traffic", async () => {
  const handle = await startLoopbackTransport({ token: TOKEN });
  try {
    const noAuth = await post(handle.url, { jsonrpc: "2.0", id: 1, method: "ping" });
    assert.equal(noAuth.status, 401);

    const wrongToken = await post(
      handle.url,
      { jsonrpc: "2.0", id: 1, method: "ping" },
      authHeaders("ffffffffffffffffffffffffffffffff")
    );
    assert.equal(wrongToken.status, 401);

    const evilOrigin = await post(
      handle.url,
      { jsonrpc: "2.0", id: 1, method: "ping" },
      { ...authHeaders(TOKEN), origin: "https://evil.example" }
    );
    assert.equal(evilOrigin.status, 403);

    const evilHostStatus = await new Promise<number>((resolve, reject) => {
      const target = new URL(handle.url);
      const probe = httpRequest(
        {
          host: "127.0.0.1",
          port: target.port,
          path: "/mcp",
          method: "POST",
          headers: {
            host: "evil.example",
            "content-type": "application/json",
            accept: "application/json, text/event-stream",
            authorization: `Bearer ${TOKEN}`,
            "content-length": Buffer.byteLength(
              JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" })
            )
          }
        },
        (response) => {
          response.resume();
          response.on("end", () => resolve(response.statusCode ?? 0));
          response.on("error", reject);
        }
      );
      probe.on("error", reject);
      probe.end(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }));
    });
    assert.equal(evilHostStatus, 403);

    const oversized = await fetch(handle.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${TOKEN}`
      },
      body: "x".repeat(5 * 1024 * 1024)
    });
    assert.equal(oversized.status, 413);
    await oversized.text();

    const unknownSession = await post(
      handle.url,
      { jsonrpc: "2.0", id: 9, method: "tools/list", params: {} },
      authHeaders(TOKEN, { "mcp-session-id": "00000000-0000-0000-0000-000000000000" })
    );
    assert.equal(unknownSession.status, 404);

    const wrongPath = await post(
      handle.url.replace("/mcp", "/admin"),
      { jsonrpc: "2.0", id: 1, method: "ping" },
      authHeaders(TOKEN)
    );
    assert.equal(wrongPath.status, 404);

    const wrongMethod = await fetch(handle.url, {
      method: "PUT",
      headers: authHeaders(TOKEN)
    });
    assert.equal(wrongMethod.status, 405);
    await wrongMethod.text();
  } finally {
    await handle.close();
  }
});

test("loopback preflight never emits a wildcard origin", async () => {
  const handle = await startLoopbackTransport({ token: TOKEN });
  try {
    const evil = await fetch(handle.url, {
      method: "OPTIONS",
      headers: { origin: "https://evil.example" }
    });
    assert.equal(evil.status, 403);
    await evil.text();

    const local = await fetch(handle.url, {
      method: "OPTIONS",
      headers: { origin: `http://127.0.0.1:${handle.port}` }
    });
    assert.equal(local.status, 204);
    assert.equal(local.headers.get("access-control-allow-origin"), `http://127.0.0.1:${handle.port}`);
    await local.text();
  } finally {
    await handle.close();
  }
});
