// A build must say which .NET SDK compiled the Windows app, whose version floats with
// the runner image: without one, provenance fails clearly and writes nothing.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const script = join(resolve(dirname(fileURLToPath(import.meta.url))), "provenance.mjs");

function run(path) {
  const root = mkdtempSync(join(tmpdir(), "orcel-provenance-"));
  const release = join(root, "release");
  mkdirSync(release);
  writeFileSync(join(release, "manifest.json"), '{"version":"0.0.0"}');
  writeFileSync(join(root, "a.zip"), "zip");
  writeFileSync(join(root, "s.json"), "{}");
  const out = join(root, "p.json");
  const bin = join(root, "bin");
  mkdirSync(bin);
  const done = spawnSync(
    process.execPath,
    [script, "--release", release, "--artifact", join(root, "a.zip"), "--sbom", join(root, "s.json"), "--out", out],
    { encoding: "utf8", env: { PATH: path(bin) } }
  );
  const record = existsSync(out) ? JSON.parse(readFileSync(out, "utf8")) : null;
  rmSync(root, { recursive: true, force: true });
  return { status: done.status, stderr: done.stderr, record };
}

test("no .NET SDK fails clearly, and writes nothing", () => {
  const { status, stderr, record } = run((bin) => bin);
  assert.equal(status, 1);
  assert.match(stderr, /\.NET SDK version is unavailable/);
  assert.equal(record, null);
});

test("an SDK's version is recorded", { skip: process.platform === "win32" }, () => {
  const { status, record } = run((bin) => {
    writeFileSync(join(bin, "dotnet"), "#!/bin/sh\necho 9.9.9\n");
    chmodSync(join(bin, "dotnet"), 0o755);
    return bin;
  });
  assert.equal(status, 0);
  assert.equal(record.toolchain.dotnet_sdk, "9.9.9");
});
