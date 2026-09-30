import { spawn, type ChildProcess } from "node:child_process";
import { mkdir, open, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { resolvePackageRoot } from "#internal/application/package.js";
import { readDevelopmentRuntimeArtifactsRevision } from "#services/dev-client/runtime-artifacts.js";

import { normalizeOrigin } from "./routing.js";

export const KAF_BASE_URL_ENV = "KAF_BASE_URL";

const DEFAULT_SERVER_READY_TIMEOUT_MS = 30_000;
const DEV_SERVER_REGISTRY_TIMEOUT_MS = 30_000;
const DEV_SERVER_REGISTRY_POLL_MS = 100;
const DEV_SERVER_READINESS_TIMEOUT_MS = 1_000;
const DEV_SERVER_STALE_LOCK_MS = 30_000;
const KAF_CACHE_DIRECTORY_NAME = ".kaf";
const KAF_NUXT_DEV_SERVER_FILE_NAME = "nuxt-dev-server.json";
const KAF_NUXT_DEV_SERVER_LOCK_FILE_NAME = "nuxt-dev-server.lock";
const LOCAL_SERVER_URL_PATTERN = /https?:\/\/(?:\[[^\]\s]+\]|[^\s/:[\]]+)(?::\d+)?/;

interface KafProcessHandle {
  readonly origin: string;
  readonly process?: ChildProcess;
}

interface KafDevServerRegistry {
  readonly appRoot: string;
  readonly origin: string;
  readonly pid: number | null;
  readonly updatedAt: string;
}

function isNodeErrorWithCode(error: unknown, code: string): boolean {
  return error instanceof Error && "code" in error && error.code === code;
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function resolveKafCacheDirectory(appRoot: string): string {
  return join(appRoot, KAF_CACHE_DIRECTORY_NAME);
}

function resolveKafDevServerRegistryPath(appRoot: string): string {
  return join(resolveKafCacheDirectory(appRoot), KAF_NUXT_DEV_SERVER_FILE_NAME);
}

function resolveKafDevServerLockPath(appRoot: string): string {
  return join(resolveKafCacheDirectory(appRoot), KAF_NUXT_DEV_SERVER_LOCK_FILE_NAME);
}

/**
 * Parse and validate a persisted dev-server registry record. Returns
 * `undefined` for anything that is not a well-formed registry so callers fall
 * back to spawning a fresh server.
 */
export function normalizeDevServerRegistry(value: unknown): KafDevServerRegistry | undefined {
  if (!isRecord(value)) return undefined;
  if (
    typeof value.appRoot !== "string" ||
    typeof value.origin !== "string" ||
    typeof value.updatedAt !== "string"
  )
    return undefined;
  if (value.pid !== null && typeof value.pid !== "number") return undefined;
  try {
    return {
      appRoot: value.appRoot,
      origin: normalizeOrigin(value.origin),
      pid: value.pid,
      updatedAt: value.updatedAt,
    };
  } catch {
    return undefined;
  }
}

async function readUsableKafDevServerRegistry(appRoot: string): Promise<string | undefined> {
  try {
    const registry = normalizeDevServerRegistry(
      JSON.parse(await readFile(resolveKafDevServerRegistryPath(appRoot), "utf8")) as unknown,
    );
    if (registry === undefined || registry.appRoot !== appRoot) return undefined;
    if (
      (await readDevelopmentRuntimeArtifactsRevision({
        serverUrl: registry.origin,
        timeoutMs: DEV_SERVER_READINESS_TIMEOUT_MS,
      })) === undefined
    )
      return undefined;
    return registry.origin;
  } catch (error) {
    if (isNodeErrorWithCode(error, "ENOENT")) return undefined;
    throw error;
  }
}

async function writeKafDevServerRegistry(appRoot: string, handle: KafProcessHandle): Promise<void> {
  await mkdir(resolveKafCacheDirectory(appRoot), { recursive: true });
  await writeFile(
    resolveKafDevServerRegistryPath(appRoot),
    `${JSON.stringify(
      {
        appRoot,
        origin: handle.origin,
        pid: handle.process?.pid ?? null,
        updatedAt: new Date().toISOString(),
      } satisfies KafDevServerRegistry,
      null,
      2,
    )}\n`,
  );
}

async function removeStaleKafDevServerLock(lockPath: string): Promise<void> {
  try {
    const lockStat = await stat(lockPath);
    if (Date.now() - lockStat.mtimeMs > DEV_SERVER_STALE_LOCK_MS) {
      await rm(lockPath, { force: true });
    }
  } catch (error) {
    if (!isNodeErrorWithCode(error, "ENOENT")) throw error;
  }
}

async function acquireKafDevServerLock(appRoot: string): Promise<() => Promise<void>> {
  const cacheDirectory = resolveKafCacheDirectory(appRoot);
  const lockPath = resolveKafDevServerLockPath(appRoot);
  const deadline = Date.now() + DEV_SERVER_REGISTRY_TIMEOUT_MS;
  await mkdir(cacheDirectory, { recursive: true });

  while (true) {
    try {
      const lockFile = await open(lockPath, "wx");
      await lockFile.writeFile(`${String(process.pid)}\n`);
      await lockFile.close();
      return async () => {
        await rm(lockPath, { force: true });
      };
    } catch (error) {
      if (!isNodeErrorWithCode(error, "EEXIST")) throw error;
      const registeredOrigin = await readUsableKafDevServerRegistry(appRoot);
      if (registeredOrigin !== undefined) return async () => {};
      await removeStaleKafDevServerLock(lockPath);
      if (Date.now() > deadline) {
        throw new Error(
          `Timed out after ${DEV_SERVER_REGISTRY_TIMEOUT_MS}ms waiting for another Nuxt process to start kaf.`,
        );
      }
      await delay(DEV_SERVER_REGISTRY_POLL_MS);
    }
  }
}

function createKafBinaryPath(): string {
  return join(resolvePackageRoot(), "bin", "kaf.js");
}

function startServerProcess(input: {
  readonly args: readonly string[];
  readonly command: string;
  readonly cwd: string;
  readonly env?: Record<string, string>;
}): Promise<KafProcessHandle> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(input.command, input.args, {
      cwd: input.cwd,
      env: { ...process.env, ...input.env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const timeout = setTimeout(() => {
      child.kill();
      reject(
        new Error(
          `Timed out after ${DEFAULT_SERVER_READY_TIMEOUT_MS}ms waiting for kaf to print its server URL.`,
        ),
      );
    }, DEFAULT_SERVER_READY_TIMEOUT_MS);

    const cleanup = () => {
      clearTimeout(timeout);
      child.off("error", handleError);
      child.off("exit", handleEarlyExit);
    };
    const handleError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const handleEarlyExit = (code: number | null, signal: NodeJS.Signals | null) => {
      cleanup();
      reject(
        new Error(
          `kaf server process exited before printing its server URL (code ${String(code)}, signal ${String(signal)}).`,
        ),
      );
    };
    let resolved = false;
    const handleOutput = (chunk: Buffer) => {
      if (resolved) return;
      const match = LOCAL_SERVER_URL_PATTERN.exec(chunk.toString("utf8"));
      if (match === null) return;
      resolved = true;
      cleanup();
      resolvePromise({ origin: normalizeOrigin(match[0]), process: child });
    };

    child.once("error", handleError);
    child.once("exit", handleEarlyExit);
    child.stdout.on("data", (chunk: Buffer) => {
      process.stdout.write(chunk);
      handleOutput(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      process.stderr.write(chunk);
      handleOutput(chunk);
    });
  });
}

function installProcessShutdown(handle: KafProcessHandle): KafProcessHandle {
  const childProcess = handle.process;
  if (childProcess === undefined) return handle;
  const close = () => {
    process.off("beforeExit", close);
    process.off("exit", close);
    if (!childProcess.killed) childProcess.kill();
  };
  process.once("beforeExit", close);
  process.once("exit", close);
  return handle;
}

function startKafDevServer(appRoot: string): Promise<KafProcessHandle> {
  return startServerProcess({
    args: [createKafBinaryPath(), "dev", "--no-ui", "--port", "0"],
    command: process.execPath,
    cwd: appRoot,
  }).then((handle) => {
    process.env[KAF_BASE_URL_ENV] = handle.origin;
    return installProcessShutdown(handle);
  });
}

/**
 * Resolve a shared kaf dev server for {@link appRoot}, reusing a healthy
 * registered server when one exists and otherwise spawning a new one behind a
 * cross-process lock so concurrent Nuxt processes don't each boot kaf.
 */
export async function resolveSharedKafDevServer(appRoot: string): Promise<KafProcessHandle> {
  const registeredOrigin = await readUsableKafDevServerRegistry(appRoot);
  if (registeredOrigin !== undefined) {
    process.env[KAF_BASE_URL_ENV] = registeredOrigin;
    return { origin: registeredOrigin };
  }

  const releaseLock = await acquireKafDevServerLock(appRoot);
  try {
    const lockedRegisteredOrigin = await readUsableKafDevServerRegistry(appRoot);
    if (lockedRegisteredOrigin !== undefined) {
      process.env[KAF_BASE_URL_ENV] = lockedRegisteredOrigin;
      return { origin: lockedRegisteredOrigin };
    }
    const handle = await startKafDevServer(appRoot);
    await writeKafDevServerRegistry(appRoot, handle);
    return handle;
  } finally {
    await releaseLock();
  }
}
