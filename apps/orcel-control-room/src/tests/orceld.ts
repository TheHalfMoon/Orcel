// Test support: runs the real orceld binary with its own app API instance,
// workspace, audit file and state root, so contract tests talk to the same
// endpoint code users get. Nothing here listens; orceld does.

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
// dist/tests -> apps/orcel-control-room -> repository root
const repoRoot = path.resolve(here, "..", "..", "..", "..");

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

export function uniqueInstance(label: string): string {
  const random = Math.random().toString(36).slice(2, 8);
  return `cr02-${label}-${process.pid.toString(36)}-${random}`.slice(0, 32);
}

export interface Sandbox {
  root: string;
  env: Record<string, string>;
  dispose(): Promise<void>;
}

/** A private temporary state root and workspace for one or more daemons. */
export async function createSandbox(instance: string): Promise<Sandbox> {
  const root = await mkdtemp(path.join(os.tmpdir(), "orcel-cr02-"));
  await chmod(root, 0o700);
  const workspace = path.join(root, "workspace");
  const audit = path.join(root, "audit");
  await mkdir(workspace, { recursive: true, mode: 0o700 });
  await mkdir(audit, { recursive: true, mode: 0o700 });
  const env: Record<string, string> = {
    ORCEL_APP_API_INSTANCE: instance,
    ORCEL_WORKSPACE_ROOT: workspace,
    ORCEL_AUDIT_PATH: path.join(audit, "audit.jsonl"),
  };
  if (process.platform === "win32") {
    const local = path.join(root, "local");
    await mkdir(local, { recursive: true });
    env.LOCALAPPDATA = local;
  } else if (process.platform === "darwin") {
    const home = path.join(root, "home");
    await mkdir(home, { recursive: true, mode: 0o700 });
    env.HOME = home;
  } else {
    const state = path.join(root, "state");
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
  /** Closes stdin, the daemon's clean exit, and waits for it. */
  stop(): Promise<void>;
}

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
  const endpoint = await new Promise<string>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`orceld did not open its app API:\n${stderr.join("\n")}`)),
      30_000,
    );
    createInterface({ input: child.stderr }).on("line", (line) => {
      stderr.push(line);
      const match = /^orceld app api: listening on (.+)$/u.exec(line);
      if (match?.[1]) {
        clearTimeout(timer);
        resolve(match[1]);
      }
    });
    child.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`orceld exited (${code}) before listening:\n${stderr.join("\n")}`));
    });
  });
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
      const timer = setTimeout(() => child.kill(), 10_000);
      await exited;
      clearTimeout(timer);
    },
  };
}
