// Platform-neutral startup and command-line tests.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { splitWindowsCommandLine } from "./cmdline.js";
import { startupRefusal } from "./environment.js";
import { encodeFrame, FrameDecoder } from "./protocol.js";

const WORKER_MAIN = join(dirname(fileURLToPath(import.meta.url)), "main.js");

function cleanEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of ["SystemRoot", "SystemDrive", "PATH", "TEMP", "TMP", "HOME"]) {
    const value = process.env[key];
    if (value !== undefined) env[key] = value;
  }
  return env;
}

function run(flags: string[], input: Buffer | null): Promise<{ code: number | null; stdout: Buffer; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [...flags, WORKER_MAIN], { env: cleanEnv(), stdio: ["pipe", "pipe", "pipe"] });
    const out: Buffer[] = [];
    let err = "";
    child.stdout.on("data", (chunk: Buffer) => out.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => (err += chunk.toString()));
    child.on("exit", (code) => resolve({ code, stdout: Buffer.concat(out), stderr: err }));
    if (input) child.stdin.write(input);
    child.stdin.end();
  });
}

test("startupRefusal requires Node 22.15+ and --disable-sigusr1", () => {
  assert.equal(startupRefusal(["--disable-sigusr1"], "v22.15.0"), null);
  assert.equal(startupRefusal(["--disable-sigusr1"], "v24.19.0"), null);
  for (const version of ["v20.19.0", "v22.13.1", "v22.14.0", "v21.7.3", "garbage"]) {
    assert.equal(typeof startupRefusal(["--disable-sigusr1"], version), "string", version);
  }
  assert.equal(typeof startupRefusal([], "v24.19.0"), "string");
  for (const execArgv of [
    ["--disable-sigusr1=false"],
    ["--disable-sigusr1", "--no-disable-sigusr1"],
    ["--no-disable-sigusr1", "--disable-sigusr1"],
    ["--disable-sigusr1", "--inspect=127.0.0.1:0"],
    ["--disable-sigusr1", "--require", "evil.js"],
    ["--disable-sigusr1", "--import", "data:text/javascript,0"],
    ["--disable-sigusr1", "--disable-sigusr1"]
  ]) {
    assert.equal(typeof startupRefusal(execArgv, "v24.19.0"), "string", execArgv.join(" "));
  }
});

test("the worker refuses to start without --disable-sigusr1", async () => {
  const result = await run([], null);
  assert.equal(result.code, 2);
  assert.equal(result.stdout.length, 0);
  assert.match(result.stderr, /--disable-sigusr1/);
});

test("a negated or extra Node flag makes the worker refuse to start", async () => {
  for (const flags of [["--disable-sigusr1", "--no-disable-sigusr1"], ["--disable-sigusr1", "--inspect=127.0.0.1:0"]]) {
    const result = await run(flags, null);
    assert.equal(result.code, 2, flags.join(" "));
    assert.equal(result.stdout.length, 0);
  }
});

test("with --disable-sigusr1 the worker answers hello and ends cleanly at end of input", async () => {
  const result = await run(["--disable-sigusr1"], encodeFrame({ frame: "hello", generation: 11 }));
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(new FrameDecoder().push(result.stdout), [{ frame: "hello", generation: 11, worker: "orcel-browser-worker" }]);
});

test("Windows command lines split with CommandLineToArgvW rules", () => {
  assert.deepEqual(splitWindowsCommandLine('"C:\\Program Files\\x\\a.exe" --flag "two words" plain'), [
    "C:\\Program Files\\x\\a.exe",
    "--flag",
    "two words",
    "plain"
  ]);
  assert.deepEqual(splitWindowsCommandLine("C:\\a.exe   --x\t--y"), ["C:\\a.exe", "--x", "--y"]);
  // Backslashes are literal unless they precede a quote.
  assert.deepEqual(splitWindowsCommandLine('a.exe C:\\dir\\ "C:\\dir\\\\" "a\\"b"'), ["a.exe", "C:\\dir\\", "C:\\dir\\", 'a"b']);
  // Odd backslashes before a quote yield a literal quote; even ones toggle.
  assert.deepEqual(splitWindowsCommandLine('a.exe \\\\\\"x \\\\"y z"'), ["a.exe", '\\"x', "\\y z"]);
  assert.deepEqual(splitWindowsCommandLine('a.exe ""'), ["a.exe", ""]);
  // The real resolver-rules shape, quoted because it contains spaces.
  assert.deepEqual(splitWindowsCommandLine('"C:\\e\\msedge.exe" "--host-resolver-rules=MAP a.test 1.2.3.4:443, MAP * ~NOTFOUND" about:blank'), [
    "C:\\e\\msedge.exe",
    "--host-resolver-rules=MAP a.test 1.2.3.4:443, MAP * ~NOTFOUND",
    "about:blank"
  ]);
});
