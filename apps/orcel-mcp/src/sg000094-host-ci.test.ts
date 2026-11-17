import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import test from "node:test";

const repo = resolve(import.meta.dirname, "..", "..", "..");
const hostDir = join(repo, "apps", "orcel-computer-host");

// Every host reply and the host's exit are awaited with a bound, so a host
// that stops answering or never exits fails this test in seconds instead of
// holding the Node / windows-latest job until its timeout.
const replyTimeoutMs = 20_000;
const exitTimeoutMs = 10_000;

function go(args: string[], cwd = hostDir) {
  return spawnSync("go", args, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, GOTOOLCHAIN: "go1.25.0" },
    timeout: 180_000,
  });
}

function hasExited(child: ChildProcessWithoutNullStreams): boolean {
  return child.exitCode !== null || child.signalCode !== null;
}

// Resolves true once the child has exited, or false after ms.
function waitForExit(child: ChildProcessWithoutNullStreams, ms: number): Promise<boolean> {
  if (hasExited(child)) {
    return Promise.resolve(true);
  }
  return new Promise((resolveExit) => {
    const timer = setTimeout(() => {
      child.off("exit", onExit);
      resolveExit(hasExited(child));
    }, ms);
    const onExit = () => {
      clearTimeout(timer);
      resolveExit(true);
    };
    child.once("exit", onExit);
  });
}

// Stops a host that a failed assertion left running: close stdin (the host
// exits on EOF), then kill the process tree, and return only once it is gone
// so the binary in the temporary directory is no longer locked.
async function stopHost(child: ChildProcessWithoutNullStreams): Promise<boolean> {
  if (hasExited(child)) {
    return true;
  }
  child.stdin.end();
  if (await waitForExit(child, exitTimeoutMs)) {
    return true;
  }
  if (child.pid !== undefined) {
    spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { timeout: 30_000 });
  }
  child.kill();
  return waitForExit(child, exitTimeoutMs);
}

// Reads the host's stdout one line at a time. Lines that arrive before they
// are asked for are queued; each read is bounded and fails fast when the
// host exits first.
function lineReader(child: ChildProcessWithoutNullStreams, stderr: string[]) {
  const queued: string[] = [];
  let waiting: ((line: string) => void) | undefined;
  let closed = false;
  let onClose: (() => void) | undefined;
  const lines = createInterface({ input: child.stdout });
  lines.on("line", (line) => {
    if (waiting !== undefined) {
      const deliver = waiting;
      waiting = undefined;
      deliver(line);
    } else {
      queued.push(line);
    }
  });
  lines.on("close", () => {
    closed = true;
    onClose?.();
  });
  return (what: string): Promise<string> => {
    const next = queued.shift();
    if (next !== undefined) {
      return Promise.resolve(next);
    }
    return new Promise((resolveLine, reject) => {
      const fail = (message: string) => {
        waiting = undefined;
        onClose = undefined;
        reject(new Error(`${message} waiting for ${what}; host stderr: ${stderr.join("")}`));
      };
      if (closed) {
        fail("host stdout closed");
        return;
      }
      const timer = setTimeout(() => fail(`timed out after ${replyTimeoutMs}ms`), replyTimeoutMs);
      onClose = () => {
        clearTimeout(timer);
        fail("host stdout closed");
      };
      waiting = (line) => {
        clearTimeout(timer);
        onClose = undefined;
        resolveLine(line);
      };
    });
  };
}

test("SG-000094 Windows host builds with pinned Go and speaks only private stdio protocol", { timeout: 240_000 }, async (t) => {
  if (process.platform !== "win32") {
    t.skip("native Windows host qualification runs only on Node / windows-latest");
    return;
  }

  const version = go(["version"]);
  if ((version.error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") {
    t.skip("local Go is unavailable; exact Go qualification runs in Node / windows-latest");
    return;
  }
  assert.equal(version.status, 0, version.stderr);
  assert.match(version.stdout, /go1\.25\.0\b/);

  const verify = go(["mod", "verify"]);
  assert.equal(verify.status, 0, verify.stderr);

  const unit = go(["test", "./..."]);
  assert.equal(unit.status, 0, unit.stdout + unit.stderr);

  const dir = mkdtempSync(join(tmpdir(), "orcel-sg94-"));
  const binary = join(dir, "orcel-computer-host.exe");
  let child: ChildProcessWithoutNullStreams | undefined;
  let passed = false;
  try {
    const build = go(["build", "-trimpath", "-o", binary, "."]);
    assert.equal(build.status, 0, build.stdout + build.stderr);

    const host = spawn(binary, [], {
      stdio: ["pipe", "pipe", "pipe"],
      env: Object.fromEntries(
        ["SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP", "PATH"]
          .map((key) => [key, process.env[key]])
          .filter((entry): entry is [string, string] => typeof entry[1] === "string"),
      ),
      windowsHide: true,
    });
    child = host;
    const stderr: string[] = [];
    host.stderr.setEncoding("utf8");
    host.stderr.on("data", (chunk: string) => stderr.push(chunk));
    const nextLine = lineReader(host, stderr);
    const reply = async (what: string) => JSON.parse(await nextLine(what));

    const request = (id: number, op: string) => {
      host.stdin.write(JSON.stringify({ id, protocol: "orcel-computer-host/1", op }) + "\n");
    };

    request(1, "hello");
    const hello = await reply("hello");
    assert.deepEqual(
      { ok: hello.ok, protocol: hello.protocol, host: hello.host },
      { ok: true, protocol: "orcel-computer-host/1", host: "orcel-windows-computer-host" },
    );

    request(2, "ping");
    const pong = await reply("ping");
    assert.equal(pong.ok, true);
    assert.equal(pong.pong, true);

    host.stdin.write(
      JSON.stringify({ id: 3, protocol: "orcel-computer-host/1", op: "click" }) + "\n",
    );
    const denied = await reply("click refusal");
    assert.equal(denied.ok, false);
    assert.equal(denied.error?.code, "capability_denied");

    // XP-04: the same live host also answers the orcel-computer-host/2 hello
    // that the Rust adapter offers first, with one capability per operation.
    host.stdin.write(
      JSON.stringify({ id: 5, protocol: "orcel-computer-host/2", op: "hello" }) + "\n",
    );
    const helloV2 = await reply("/2 hello");
    assert.deepEqual(
      {
        id: helloV2.id,
        ok: helloV2.ok,
        protocol: helloV2.protocol,
        host: helloV2.host,
        platform: helloV2.platform,
        backend: helloV2.backend,
      },
      {
        id: 5,
        ok: true,
        protocol: "orcel-computer-host/2",
        host: "orcel-windows-computer-host",
        platform: "windows",
        backend: "uia",
      },
    );
    assert.deepEqual(Object.keys(helloV2.capabilities).sort(), [
      "capture_window",
      "cursor_position",
      "hello",
      "input_click",
      "input_drag",
      "input_hotkey",
      "input_key",
      "input_move",
      "input_scroll",
      "input_type_text",
      "list_windows",
      "observe_window",
      "ping",
      "semantic_action",
      "semantic_batch",
      "shutdown",
      "window_action",
    ]);
    assert.equal(helloV2.capabilities.input_click.support, "foreground_only");
    // W2-01: batched semantic actions are named in the table but refused
    // until a grain amendment admits them.
    assert.deepEqual(helloV2.capabilities.semantic_batch, {
      support: "refused",
      reason: "grain_amendment_required",
    });

    host.stdin.write(
      JSON.stringify({ id: 6, protocol: "orcel-computer-host/2", op: "ping", extra: true }) + "\n",
    );
    const strictV2 = await reply("strict /2 refusal");
    assert.deepEqual(
      { id: strictV2.id, ok: strictV2.ok, protocol: strictV2.protocol, code: strictV2.error?.code },
      { id: 6, ok: false, protocol: "orcel-computer-host/2", code: "invalid_request" },
    );

    host.stdin.write(
      JSON.stringify({ id: 7, protocol: "orcel-computer-host/1", op: "ping", window: "x" }) + "\n",
    );
    assert.equal(
      await nextLine("/1 ping with window"),
      '{"id":7,"ok":true,"protocol":"orcel-computer-host/1","host":"orcel-windows-computer-host","pong":true}',
    );

    request(4, "shutdown");
    const shutdown = await reply("shutdown");
    assert.equal(shutdown.ok, true);
    assert.equal(await waitForExit(host, exitTimeoutMs), true, "host did not exit after shutdown");
    assert.equal(host.exitCode, 0, `host exit code; stderr: ${stderr.join("")}`);
    passed = true;
  } finally {
    const stopped = child === undefined || (await stopHost(child));
    // The image can stay locked briefly after the process is gone; retry.
    // A cleanup failure never masks the assertion that failed first.
    let cleanupError: unknown;
    try {
      rmSync(dir, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
    } catch (error) {
      cleanupError = error;
    }
    if (passed) {
      assert.equal(stopped, true, "host process could not be stopped");
      if (cleanupError !== undefined) {
        throw cleanupError;
      }
    } else if (!stopped || cleanupError !== undefined) {
      t.diagnostic(`cleanup after failure: stopped=${stopped} rm=${String(cleanupError)}`);
    }
  }
});

test("SG-000094 production host source contains no desktop mutation or public listener surface", () => {
  for (const forbidden of [
    "native_actions.go",
    "desktop_windows.go",
    "input_helpers.go",
    "desktop.go",
  ]) {
    assert.equal(existsSync(join(hostDir, forbidden)), false, `forbidden donor file imported: ${forbidden}`);
  }

  // This is historical SG-000094 evidence. SG-000095 lawfully adds three
  // separately-qualified mutation files; exclude only those successor files
  // while keeping every SG-000094 production file under this assertion.
  const sg95SuccessorFiles = new Set([
    "native_actions_windows.go",
    "native_input_windows.go",
    "native_window_actions_windows.go"
  ]);
  const production = readdirSync(hostDir)
    .filter(
      (name) =>
        name.endsWith(".go") &&
        !name.endsWith("_test.go") &&
        !sg95SuccessorFiles.has(name)
    )
    .map((name) => readFileSync(join(hostDir, name), "utf8"))
    .join("\n");

  for (const [name, pattern] of [
    ["SendInput", /NewProc\(["']SendInput["']\)/],
    ["PostMessage", /NewProc\(["']PostMessageW?["']\)/],
    ["foreground mutation", /NewProc\(["']SetForegroundWindow["']\)/],
    ["focus mutation", /NewProc\(["']SetFocus["']\)/],
    ["cursor mutation", /NewProc\(["']SetCursorPos["']\)/],
    ["legacy mouse input", /NewProc\(["']mouse_event["']\)/],
    ["legacy keyboard input", /NewProc\(["']keybd_event["']\)/],
    ["HTTP server", /ListenAndServe\s*\(/],
    ["network listener", /\bnet\.Listen\s*\(/],
    ["HTTP package", /["']net\/http["']/],
  ] as const) {
    assert.doesNotMatch(production, pattern, `forbidden SG-000094 surface: ${name}`);
  }

  assert.match(production, /context\.WithTimeout\(/);
  assert.match(production, /exec\.CommandContext\(ctx, os\.Args\[0\], "--worker"\)/);
  assert.match(production, /validateBoundWindow\(req\)/);
});

test("SG-000094 provenance and dependency notices are exact and release-deferred", () => {
  const importManifest = JSON.parse(
    readFileSync(join(repo, "docs", "p20", "sg000094_windows_host_import.json"), "utf8"),
  );
  const provenance = JSON.parse(
    readFileSync(join(repo, "docs", "p20", "sg000094_windows_host_provenance.json"), "utf8"),
  );

  assert.equal(importManifest.grain, "SG-000094");
  assert.equal(importManifest.donor.repository, "opensymph/open-computer-use");
  assert.equal(importManifest.donor.commit, "5b433b98019c18201a15d11e8c3cb0010879a3d8");
  assert.equal(importManifest.donor.license_blob_sha, "3b3840d939919f58113a626bb990a90f3b949aab");
  assert.equal(importManifest.packaging.included_in_release, false);

  const expectedSources = [
    "apps/OpenComputerUseWindows/native_capture.go",
    "apps/OpenComputerUseWindows/native_uia.go",
    "apps/OpenComputerUseWindows/native_win32.go",
    "apps/OpenComputerUseWindows/native_op_client.go",
    "apps/OpenComputerUseWindows/native_backend.go",
    "apps/OpenComputerUseWindows/main.go",
  ];
  assert.deepEqual(
    provenance.imports.map((entry: { source: string }) => entry.source),
    expectedSources,
  );
  for (const entry of provenance.imports) {
    assert.equal(typeof entry.source_blob_sha, "string");
    assert.ok(entry.source_blob_sha.length === 40);
    assert.equal(typeof entry.destination, "string");
    assert.equal(typeof entry.reuse, "string");
    assert.equal(typeof entry.modified, "boolean");
    assert.equal(typeof entry.modification_summary, "string");
    assert.equal(typeof entry.authority_delta, "string");
    assert.ok(Array.isArray(entry.qualification));
  }

  const xsys = provenance.dependencies.find(
    (entry: { module: string }) => entry.module === "golang.org/x/sys",
  );
  assert.equal(xsys.version, "v0.47.0");
  assert.equal(xsys.license, "BSD-3-Clause");
  assert.equal(xsys.license_blob_sha, "2a7cf70da6e498df9c11ab6a5eaa2ddd7af34da4");
  assert.equal(provenance.notice_impact.sg_000094_release_payload, false);

  const donorNotice = readFileSync(
    join(repo, "docs", "p20", "notices", "opensymph-open-computer-use-MIT.txt"),
    "utf8",
  );
  const xsysNotice = readFileSync(
    join(repo, "docs", "p20", "notices", "golang-x-sys-BSD-3-Clause.txt"),
    "utf8",
  );
  assert.match(donorNotice, /Copyright \(c\) 2026 opensymph/);
  assert.match(xsysNotice, /Copyright 2009 The Go Authors/);
});
