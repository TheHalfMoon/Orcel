// Test support: runs the real orceld binary with its own app API instance,
// workspace, audit file and state root, so contract tests talk to the same
// endpoint code users get. Nothing here listens; orceld does.
//
// A daemon that does not open its endpoint fails the test at once, with
// orceld's own reason, and is killed: no test waits on it or leaks it.

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import { orceldTransport, type AppApiConnector } from "../agentkit/transport/orceld-transport.js";

const here = path.dirname(fileURLToPath(import.meta.url));
// dist/tests -> apps/orcel-control-room -> repository root
const repoRoot = path.resolve(here, "..", "..", "..", "..");

const START_TIMEOUT_MS = 30_000;
const STOP_TIMEOUT_MS = 10_000;

export function orceldBinary(): string | undefined {
  const explicit = process.env.ORCEL_ORCELD_BIN;
  if (explicit) return explicit;
  const exe = process.platform === "win32" ? "orceld.exe" : "orceld";
  for (const profile of ["debug", "release"]) {
    const candidate = path.join(repoRoot, "target", profile, exe);
    if (existsSync(candidate)) return candidate;
  }
  return undefined;
}

/**
 * The reason live tests skip, or undefined when they can run. With
 * ORCEL_REQUIRE_LIVE_ORCELD=1 (CI) a missing binary is a failure instead.
 */
export function liveSkipReason(): string | undefined {
  if (orceldBinary()) return undefined;
  if (process.env.ORCEL_REQUIRE_LIVE_ORCELD === "1") {
    throw new Error(
      "ORCEL_REQUIRE_LIVE_ORCELD=1 but no orceld binary: build it (cargo build -p orceld) or set ORCEL_ORCELD_BIN",
    );
  }
  return "no orceld binary; run cargo build -p orceld (CI sets ORCEL_REQUIRE_LIVE_ORCELD=1)";
}

/** A short instance name, so the Unix socket path stays under 100 bytes. */
export function uniqueInstance(label: string): string {
  const random = Math.random().toString(36).slice(2, 8);
  return `c2-${label.slice(0, 6)}-${random}`;
}

/**
 * The connector for tests. On Windows it opts in to the unverified pipe
 * connect that the default connector refuses (orceld-transport.ts header):
 * the test itself started the daemon that owns the pipe.
 */
export function testTransport(endpoint: string): Promise<AppApiConnector> {
  return orceldTransport({ endpoint, allowUnverifiedWindowsPipe: true });
}

export interface Sandbox {
  root: string;
  env: Record<string, string>;
  dispose(): Promise<void>;
}

/**
 * A private temporary state root and workspace for one or more daemons.
 * Unix roots live under /tmp, not os.tmpdir(): macOS's per-user temp
 * directory is about 50 bytes long, and with `Library/Application
 * Support/Orcel/run/app-api-<instance>.sock` below it the socket path would
 * pass the 100-byte limit orceld enforces. A long `home` makes the path as
 * long as a user's long real home would.
 */
export async function createSandbox(instance: string, home = "h"): Promise<Sandbox> {
  const base = process.platform === "win32" ? os.tmpdir() : "/tmp";
  const root = await mkdtemp(path.join(base, "oc-"));
  await chmod(root, 0o700);
  const workspace = path.join(root, "w");
  const audit = path.join(root, "a");
  await mkdir(workspace, { recursive: true, mode: 0o700 });
  await mkdir(audit, { recursive: true, mode: 0o700 });
  const env: Record<string, string> = {
    ORCEL_APP_API_INSTANCE: instance,
    ORCEL_WORKSPACE_ROOT: workspace,
    ORCEL_AUDIT_PATH: path.join(audit, "audit.jsonl"),
  };
  if (process.platform === "win32") {
    const local = path.join(root, "l");
    await mkdir(local, { recursive: true });
    env.LOCALAPPDATA = local;
  } else if (process.platform === "darwin") {
    const homeDir = path.join(root, home);
    await mkdir(homeDir, { recursive: true, mode: 0o700 });
    env.HOME = homeDir;
  } else {
    const state = path.join(root, home);
    await mkdir(state, { recursive: true, mode: 0o700 });
    env.XDG_STATE_HOME = state;
  }
  return {
    root,
    env,
    dispose: () => rm(root, { recursive: true, force: true, maxRetries: 5 }),
  };
}

export interface RunningOrceld {
  endpoint: string;
  child: ChildProcessWithoutNullStreams;
  stderr: string[];
  /** Sends `count` stdio requests; each publishes one request.completed. */
  publish(count: number): Promise<void>;
  /** Closes stdin, the daemon's clean exit, and waits for it (kills after 10 s). */
  stop(): Promise<void>;
}

/** Kills the daemon and waits for it to exit. */
async function kill(child: ChildProcessWithoutNullStreams, exited: Promise<void>): Promise<void> {
  child.stdin.destroy();
  if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  await exited;
}

/**
 * Starts orceld and resolves with its endpoint once it is listening.
 * Rejects (after killing it) when orceld reports the endpoint unavailable,
 * exits, or does not listen within 30 s.
 */
export async function startOrceld(sandbox: Sandbox): Promise<RunningOrceld> {
  const binary = orceldBinary();
  if (!binary) throw new Error("no orceld binary");
  const child = spawn(binary, [], {
    env: { ...process.env, ...sandbox.env },
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  const stderr: string[] = [];
  const responses: Array<() => void> = [];
  createInterface({ input: child.stdout }).on("line", () => responses.shift()?.());
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  let endpoint: string;
  try {
    endpoint = await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`orceld did not open its app API within ${START_TIMEOUT_MS} ms:\n${stderr.join("\n")}`)),
        START_TIMEOUT_MS,
      );
      createInterface({ input: child.stderr }).on("line", (line) => {
        stderr.push(line);
        const listening = /^orceld app api: listening on (.+)$/u.exec(line);
        if (listening?.[1]) {
          clearTimeout(timer);
          resolve(listening[1]);
        } else if (/^orceld app api: (unavailable|disabled)/u.test(line)) {
          clearTimeout(timer);
          reject(new Error(`orceld reported its app API unavailable: ${line}`));
        }
      });
      child.once("exit", (code) => {
        clearTimeout(timer);
        reject(new Error(`orceld exited (${code}) before listening:\n${stderr.join("\n")}`));
      });
      child.once("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
    });
  } catch (error) {
    await kill(child, exited);
    throw error;
  }
  return {
    endpoint,
    child,
    stderr,
    publish: async (count) => {
      const answered = Array.from(
        { length: count },
        () => new Promise<void>((resolve) => responses.push(resolve)),
      );
      child.stdin.write("{}\n".repeat(count));
      await Promise.all(answered);
    },
    stop: async () => {
      child.stdin.end();
      const timer = setTimeout(() => child.kill("SIGKILL"), STOP_TIMEOUT_MS);
      await exited;
      clearTimeout(timer);
    },
  };
}
