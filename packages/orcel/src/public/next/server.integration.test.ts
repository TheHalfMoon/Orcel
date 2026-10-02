import { EventEmitter } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

const spawnMock = vi.hoisted(() => vi.fn());

vi.mock("node:child_process", () => ({
  spawn: spawnMock,
}));

import { resolveOrcelDestinationPrefix } from "./server.js";

const tempRoots: string[] = [];

interface MockChildProcess extends EventEmitter {
  stdout: EventEmitter;
  stderr: EventEmitter;
  killed: boolean;
  kill(): void;
  pid: number;
}

function createMockChildProcess(): MockChildProcess {
  const child = new EventEmitter() as MockChildProcess;
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.killed = false;
  child.pid = 12345;
  child.kill = () => {
    child.killed = true;
    child.emit("exit", null, "SIGTERM");
  };
  return child;
}

describe("resolveOrcelDestinationPrefix", () => {
  afterEach(async () => {
    spawnMock.mockReset();
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    await Promise.all(
      tempRoots.splice(0).map((root) =>
        rm(root, {
          force: true,
          recursive: true,
        }),
      ),
    );
  });

  it("reports a missing local production build instead of proxying to an unstarted port", async () => {
    vi.stubEnv("NODE_ENV", "production");
    const appRoot = await createTempAppRoot();

    await expect(
      resolveOrcelDestinationPrefix({
        appRoot,
        phase: "phase-production-server",
        productionDestinationPrefix: "http://127.0.0.1:4274",
        productionServerOrigin: "http://127.0.0.1:4274",
      }),
    ).rejects.toThrow(`Run orcel build from ${appRoot} before starting Next.js.`);
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("ignores non-server URLs in dev server output while waiting for the listening URL", async () => {
    vi.stubEnv("NODE_ENV", "development");
    const appRoot = await createTempAppRoot();
    const child = createMockChildProcess();
    const stderrWrites: string[] = [];
    const stdoutWrites: string[] = [];
    vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
      stderrWrites.push(String(chunk));
      return true;
    });
    vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
      stdoutWrites.push(String(chunk));
      return true;
    });
    spawnMock.mockReturnValue(child);

    const destination = resolveOrcelDestinationPrefix({
      appRoot,
      logLabel: "support",
      phase: "phase-development-server",
      productionDestinationPrefix: "/internal/orcel",
    });

    await vi.waitFor(() => {
      expect(spawnMock).toHaveBeenCalledTimes(1);
    });
    child.stdout.emit(
      "data",
      Buffer.from('dependency metadata: "homepage": "https://rolldown.rs/"\n'),
    );
    child.stdout.emit("data", Buffer.from("docs: open http://localhost for details\n"));
    child.stderr.emit("data", Buffer.from("dev server listening at http://127.0.0.1:33449\n"));

    await expect(destination).resolves.toBe("http://127.0.0.1:33449");
    await expect(readRegisteredOrigin(appRoot)).resolves.toBe("http://127.0.0.1:33449");
    expect(stdoutWrites).toContain(
      '[orcel:dev:support] dependency metadata: "homepage": "https://rolldown.rs/"\n',
    );
    expect(stderrWrites).toContain(
      "[orcel:dev:support] server listening at http://127.0.0.1:33449\n",
    );
  });

  it("selects a workspace agent when starting its dev server", async () => {
    vi.stubEnv("NODE_ENV", "development");
    const appRoot = await createTempAppRoot();
    const child = createMockChildProcess();
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    spawnMock.mockReturnValue(child);

    const destination = resolveOrcelDestinationPrefix({
      appRoot,
      logLabel: "support",
      phase: "phase-development-server",
      productionDestinationPrefix: "/internal/orcel",
      workspaceAgentName: "support",
    });

    await vi.waitFor(() => expect(spawnMock).toHaveBeenCalledTimes(1));
    expect(spawnMock).toHaveBeenCalledWith(
      process.execPath,
      expect.arrayContaining(["dev", "--no-ui", "--port", "0", "--agent", "support"]),
      expect.objectContaining({ cwd: appRoot }),
    );
    child.stdout.emit("data", Buffer.from("[dev] server listening at http://127.0.0.1:33451\n"));
    await expect(destination).resolves.toBe("http://127.0.0.1:33451");
  });

  it("suppresses low-signal orcel dev startup output", async () => {
    vi.stubEnv("NODE_ENV", "development");
    const appRoot = await createTempAppRoot();
    const child = createMockChildProcess();
    const stdoutWrites: string[] = [];
    vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
      stdoutWrites.push(String(chunk));
      return true;
    });
    spawnMock.mockReturnValue(child);

    const destination = resolveOrcelDestinationPrefix({
      appRoot,
      logLabel: "billing",
      phase: "phase-development-server",
      productionDestinationPrefix: "/internal/orcel",
    });

    await vi.waitFor(() => {
      expect(spawnMock).toHaveBeenCalledTimes(1);
    });
    child.stdout.emit(
      "data",
      Buffer.from(
        "☰orcel  v0.0.0\nCONFIGURATION_FIELD_CONFLICT\n\u001b[33m[CONFIGURATION_FIELD_CONFLICT] \u001b[0mnoisy\n[dev] server listening at http://127.0.0.1:33450\n",
      ),
    );

    await expect(destination).resolves.toBe("http://127.0.0.1:33450");
    expect(stdoutWrites).toEqual([
      "[orcel:dev:billing] server listening at http://127.0.0.1:33450\n",
    ]);
  });
});

async function createTempAppRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "orcel-next-server-"));
  tempRoots.push(root);
  return root;
}

async function readRegisteredOrigin(appRoot: string): Promise<string> {
  const registry = JSON.parse(
    await readFile(join(appRoot, ".orcel", "next-dev-server.json"), "utf8"),
  ) as { readonly origin?: unknown };
  if (typeof registry.origin !== "string") {
    throw new Error("orcel dev server registry did not record a string origin.");
  }
  return registry.origin;
}
