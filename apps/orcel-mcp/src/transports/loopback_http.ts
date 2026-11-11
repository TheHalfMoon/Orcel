import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/server";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/server";
import { KernelClient } from "../kernel.js";
import {
  buildOrcelServer,
  localTransportContext
} from "../server.js";

/**
 * Loopback Streamable HTTP transport for local MCP clients.
 *
 * Security properties, all fail closed:
 * - binds `127.0.0.1` only; any other bind target is refused before listen;
 * - every non-preflight request requires `Authorization: Bearer <token>`
 *   compared with a constant-time equality check;
 * - `Host` must be exactly `127.0.0.1` or `localhost` with the bound port;
 * - `Origin`, when present (browser clients), must exactly match the local
 *   origin; absent `Origin` (non-browser clients) is accepted;
 * - no wildcard CORS and no reflected arbitrary origins;
 * - only `POST`, `GET`, and `DELETE` on `/mcp`; everything else is `404`;
 * - request bodies are bounded before the SDK parses them;
 * - sessions are bounded in count, lifetime, and idle time;
 * - logs carry method, path, and status only, never tokens or payloads.
 *
 * Protocol framing itself stays inside the pinned MCP SDK transport.
 * This module owns the socket boundary around it.
 */

export const LOOPBACK_HOST = "127.0.0.1";
export const LOOPBACK_PATH = "/mcp";
export const LOOPBACK_TRANSPORT_RESERVED = "SG-000050";
export const MIN_TOKEN_CHARS = 32;
export const MAX_REQUEST_BODY_BYTES = 4 * 1024 * 1024;
export const MAX_RESPONSE_BODY_BYTES = 8 * 1024 * 1024;
export const MAX_SESSIONS = 4;
export const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
export const SESSION_IDLE_MS = 15 * 60 * 1000;
export const MAX_HEADER_COUNT = 100;

export interface LoopbackOptions {
  readonly port?: number | undefined;
  readonly token?: string | undefined;
  /** Each session's kernel; tests inject one. Local only: it gets no remote context. */
  readonly kernelFactory?: ((profile: string | null) => KernelClient) | undefined;
}

export interface LoopbackHandle {
  readonly url: string;
  readonly port: number;
  close(): Promise<void>;
}

interface SessionRecord {
  transport: WebStandardStreamableHTTPServerTransport;
  server: McpServer;
  kernel: KernelClient;
  createdAt: number;
  lastSeen: number;
}

export function validateToken(token: string | undefined): string {
  if (typeof token !== "string" || token.length < MIN_TOKEN_CHARS) {
    throw new Error(
      "TRANSPORT_UNAVAILABLE: a per-user loopback credential of at least 32 characters is required"
    );
  }
  return token;
}

export function validatePort(port: number | undefined): number {
  if (port === undefined) {
    return 0;
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("TRANSPORT_UNAVAILABLE: --port must be an integer from 1 to 65535");
  }
  return port;
}

function bearerMatches(header: string | undefined, token: Buffer): boolean {
  if (typeof header !== "string") {
    return false;
  }
  const prefix = "Bearer ";
  if (!header.startsWith(prefix)) {
    return false;
  }
  const presented = Buffer.from(header.slice(prefix.length));
  if (presented.length !== token.length) {
    return false;
  }
  return timingSafeEqual(presented, token);
}

export function hostAllowed(host: string | undefined, port: number): boolean {
  if (typeof host !== "string") {
    return false;
  }
  const lower = host.toLowerCase();
  return lower === `127.0.0.1:${port}` || lower === "127.0.0.1" || lower === `localhost:${port}` || lower === "localhost";
}

export function originAllowed(origin: string | undefined, port: number): boolean {
  if (origin === undefined) {
    return true;
  }
  const lower = origin.toLowerCase();
  return (
    lower === `http://127.0.0.1:${port}` ||
    lower === "http://127.0.0.1" ||
    lower === `http://localhost:${port}` ||
    lower === "http://localhost"
  );
}

function headerCount(headers: IncomingMessage["headers"]): number {
  return Object.keys(headers).length;
}

async function readBoundedBody(request: IncomingMessage, bound: number): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    request.on("data", (chunk: Buffer) => {
      if (settled) {
        return;
      }
      total += chunk.length;
      if (total > bound) {
        settled = true;
        reject(new Error("body too large"));
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (!settled) {
        settled = true;
        resolve(Buffer.concat(chunks));
      }
    });
    request.on("error", (error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
  });
}

async function forwardBounded(
  response: Response,
  out: ServerResponse,
  bound: number
): Promise<void> {
  out.statusCode = response.status;
  response.headers.forEach((value, key) => {
    const lower = key.toLowerCase();
    if (lower === "content-length" || lower === "transfer-encoding" || lower === "connection") {
      return;
    }
    out.setHeader(key, value);
  });
  if (response.body === null) {
    out.end();
    return;
  }
  const reader = response.body.getReader();
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.length;
      if (total > bound) {
        out.destroy();
        return;
      }
      if (!out.write(value)) {
        await new Promise<void>((resolve) => out.once("drain", resolve));
      }
    }
    out.end();
  } catch {
    out.destroy();
  } finally {
    reader.releaseLock();
  }
}

function logLine(method: string | undefined, path: string | undefined, status: number): void {
  process.stderr.write(`[orcel-mcp] loopback ${(method ?? "?").toUpperCase()} ${path ?? "?"} -> ${status}\n`);
}

function buildWebRequest(
  port: number,
  method: string,
  headers: Headers,
  body: Buffer | undefined
): Request {
  const init: RequestInit = { method, headers };
  if (body !== undefined && body.length > 0) {
    init.body = Uint8Array.from(body).buffer;
  }
  return new Request(`http://127.0.0.1:${port}${LOOPBACK_PATH}`, init);
}

/**
 * Starts the loopback MCP listener using the authoritative builder.
 * One `KernelClient` (one `orceld` child) is created per MCP session,
 * matching stdio per-connection semantics, and is closed with the session.
 */
export async function startLoopbackTransport(options: LoopbackOptions = {}): Promise<LoopbackHandle> {
  const tokenText = validateToken(options.token ?? process.env.ORCEL_LOOPBACK_TOKEN);
  const token = Buffer.from(tokenText);
  const requestedPort = validatePort(options.port);
  const defaultWorkspace = process.env.ORCEL_DEFAULT_WORKSPACE ?? "default";
  const context = { ...localTransportContext(), transportKind: "loopback_http" as const };
  const kernelFactory =
    options.kernelFactory ?? ((profile: string | null) => new KernelClient(undefined, null, profile));
  const sessions = new Map<string, SessionRecord>();

  function sweep(now: number): void {
    for (const [id, record] of sessions) {
      if (now - record.createdAt > SESSION_ABSOLUTE_MS || now - record.lastSeen > SESSION_IDLE_MS) {
        sessions.delete(id);
        try {
          record.kernel.close();
        } catch {
          // Fail closed on expiry.
        }
        try {
          void record.transport.close?.();
        } catch {
          // Transport already gone.
        }
      }
    }
  }
  const sweeper = setInterval(() => sweep(Date.now()), 60_000);
  sweeper.unref?.();

  const listener: Server = createServer(async (nodeRequest: IncomingMessage, nodeResponse: ServerResponse) => {
    try {
      const method = (nodeRequest.method ?? "").toUpperCase();
      const path = (nodeRequest.url ?? "").split("?")[0];

      if (!hostAllowed(nodeRequest.headers.host, boundPort)) {
        nodeResponse.statusCode = 403;
        nodeResponse.end();
        logLine(method, path, 403);
        return;
      }
      if (path !== LOOPBACK_PATH) {
        nodeResponse.statusCode = 404;
        nodeResponse.end();
        logLine(method, path, 404);
        return;
      }
      if (headerCount(nodeRequest.headers) > MAX_HEADER_COUNT) {
        nodeResponse.statusCode = 431;
        nodeResponse.end();
        logLine(method, path, 431);
        return;
      }
      if (method === "OPTIONS") {
        const origin = nodeRequest.headers.origin;
        if (!originAllowed(origin, boundPort)) {
          nodeResponse.statusCode = 403;
          nodeResponse.end();
          logLine(method, path, 403);
          return;
        }
        nodeResponse.statusCode = 204;
        if (origin !== undefined) {
          nodeResponse.setHeader("Access-Control-Allow-Origin", origin);
        }
        nodeResponse.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
        nodeResponse.setHeader(
          "Access-Control-Allow-Headers",
          "Content-Type, Authorization, Mcp-Session-Id, Mcp-Protocol-Version"
        );
        nodeResponse.setHeader("Access-Control-Max-Age", "600");
        nodeResponse.end();
        logLine(method, path, 204);
        return;
      }
      if (method !== "GET" && method !== "POST" && method !== "DELETE") {
        nodeResponse.statusCode = 405;
        nodeResponse.end();
        logLine(method, path, 405);
        return;
      }
      if (!bearerMatches(nodeRequest.headers.authorization, token)) {
        nodeResponse.statusCode = 401;
        nodeResponse.end();
        logLine(method, path, 401);
        return;
      }
      if (!originAllowed(nodeRequest.headers.origin, boundPort)) {
        nodeResponse.statusCode = 403;
        nodeResponse.end();
        logLine(method, path, 403);
        return;
      }

      const sessionId = nodeRequest.headers["mcp-session-id"];
      const sessionText = Array.isArray(sessionId) ? sessionId[0] : sessionId;
      const now = Date.now();
      sweep(now);

      let body: Buffer | undefined;
      if (method === "POST") {
        try {
          body = await readBoundedBody(nodeRequest, MAX_REQUEST_BODY_BYTES);
        } catch {
          nodeResponse.statusCode = 413;
          nodeResponse.end();
          logLine(method, path, 413);
          return;
        }
      }

      const forwardHeaders = new Headers();
      const passthrough = ["content-type", "mcp-session-id", "mcp-protocol-version", "accept"];
      for (const name of passthrough) {
        const value = nodeRequest.headers[name];
        if (typeof value === "string") {
          forwardHeaders.set(name, value);
        } else if (Array.isArray(value) && value[0] !== undefined) {
          forwardHeaders.set(name, value[0]);
        }
      }

      if (method === "POST" && sessionText === undefined) {
        if (sessions.size >= MAX_SESSIONS) {
          nodeResponse.statusCode = 503;
          nodeResponse.end();
          logLine(method, path, 503);
          return;
        }
        const kernel = kernelFactory(context.toolSurfaceProfile);
        const server = buildOrcelServer(kernel, defaultWorkspace, context);
        // Like a stdio session, this local session tells its orceld which client it serves,
        // for the desktop app's list of connected clients. Display only.
        const previousOnInitialized = server.server.oninitialized;
        server.server.oninitialized = () => {
          previousOnInitialized?.();
          kernel.hello(defaultWorkspace, server.server.getClientVersion() ?? {}, "loopback_http");
        };
        const transport = new WebStandardStreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          enableJsonResponse: true,
          maxRequestBodySize: MAX_REQUEST_BODY_BYTES,
          onsessioninitialized: (id: string) => {
            sessions.set(id, { transport, server, kernel, createdAt: Date.now(), lastSeen: Date.now() });
          },
          onsessionclosed: (id: string) => {
            const record = sessions.get(id);
            if (record !== undefined) {
              sessions.delete(id);
              try {
                record.kernel.close();
              } catch {
                // Already gone.
              }
            }
          }
        });
        await server.connect(transport);
        const webRequest = buildWebRequest(boundPort, method, forwardHeaders, body);
        const webResponse = await transport.handleRequest(webRequest);
        const created = sessions.get(transport.sessionId ?? "");
        if (created !== undefined) {
          created.lastSeen = Date.now();
        }
        await forwardBounded(webResponse, nodeResponse, MAX_RESPONSE_BODY_BYTES);
        logLine(method, path, webResponse.status);
        return;
      }

      if (sessionText === undefined) {
        nodeResponse.statusCode = 400;
        nodeResponse.end();
        logLine(method, path, 400);
        return;
      }
      const record = sessions.get(sessionText);
      if (record === undefined) {
        nodeResponse.statusCode = 404;
        nodeResponse.end();
        logLine(method, path, 404);
        return;
      }
      record.lastSeen = Date.now();
      const webRequest = buildWebRequest(
        boundPort,
        method,
        forwardHeaders,
        method === "POST" ? body : undefined
      );
      const webResponse = await record.transport.handleRequest(webRequest);
      await forwardBounded(webResponse, nodeResponse, MAX_RESPONSE_BODY_BYTES);
      logLine(method, path, webResponse.status);
    } catch {
      try {
        if (!nodeResponse.headersSent) {
          nodeResponse.statusCode = 500;
        }
        nodeResponse.end();
      } catch {
        // Socket already gone.
      }
      logLine(nodeRequest.method, nodeRequest.url, 500);
    }
  });

  listener.maxHeadersCount = MAX_HEADER_COUNT;
  listener.requestTimeout = 30_000;
  listener.headersTimeout = 10_000;
  listener.keepAliveTimeout = 5_000;

  await new Promise<void>((resolve, reject) => {
    listener.once("error", reject);
    listener.listen(requestedPort, LOOPBACK_HOST, () => {
      listener.off("error", reject);
      resolve();
    });
  });
  const address = listener.address();
  const boundPort =
    typeof address === "object" && address !== null ? address.port : requestedPort;
  if (typeof address !== "object" || address === null || address.address !== LOOPBACK_HOST) {
    listener.close();
    throw new Error("TRANSPORT_UNAVAILABLE: loopback listener did not bind 127.0.0.1");
  }

  process.stderr.write(`[orcel-mcp] serving Orcel tools over loopback http://127.0.0.1:${boundPort}/mcp\n`);

  return {
    url: `http://127.0.0.1:${boundPort}/mcp`,
    port: boundPort,
    async close(): Promise<void> {
      clearInterval(sweeper);
      for (const [, record] of sessions) {
        try {
          record.kernel.close();
        } catch {
          // Already gone.
        }
      }
      sessions.clear();
      await new Promise<void>((resolve) => listener.close(() => resolve()));
    }
  };
}
