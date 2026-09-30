import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { promisify } from "node:util";

const runFile = promisify(execFile);
const GIT_TIMEOUT_MS = 1_000;

export type KafCliTelemetryIdentity = {
  readonly installationId: string;
  readonly projectSalt: string;
};

export function createKafTelemetryIdentity(): KafCliTelemetryIdentity {
  return { installationId: randomUUID(), projectSalt: randomUUID() };
}

export function isEphemeralKafTelemetryEnvironment(): boolean {
  return Boolean(process.env.CI) || existsSync("/.dockerenv");
}

export function hashKafTelemetryProject(identity: KafCliTelemetryIdentity, value: string): string {
  return createHash("sha256").update(identity.projectSalt).update(value).digest("hex");
}

export async function resolveKafTelemetryProjectId(input: {
  readonly cwd?: string;
  readonly repositoryUrl?: string;
  readonly getGitRemote?: (cwd: string) => Promise<string | undefined>;
  readonly identity: KafCliTelemetryIdentity;
}): Promise<string> {
  const cwd = input.cwd ?? process.cwd();
  const gitRemote = await (input.getGitRemote ?? getGitRemote)(cwd);
  return hashKafTelemetryProject(
    input.identity,
    gitRemote ?? input.repositoryUrl ?? process.env.REPOSITORY_URL ?? cwd,
  );
}

async function getGitRemote(cwd: string): Promise<string | undefined> {
  try {
    const { stdout } = await runFile("git", ["config", "--local", "--get", "remote.origin.url"], {
      cwd,
      timeout: GIT_TIMEOUT_MS,
      windowsHide: true,
    });
    const value = stdout.trim();
    return value === "" ? undefined : value;
  } catch {
    return undefined;
  }
}
