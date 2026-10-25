import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { inspectRelease, LIMIT_BYTES } from "./release-size.mjs";

const cli = fileURLToPath(new URL("./release-size.mjs", import.meta.url));
function withFixture(body) {
  const dir = mkdtempSync(join(tmpdir(), "orcel-f4-size-"));
  const release = join(dir, "release");
  mkdirSync(join(release, "app/orcel-mcp"), { recursive: true });
  const files = [
    { path: "orcel.exe", size: 10 },
    { path: "app/orcel-mcp/package.json", size: 20 }
  ];
  for (const f of files) {
    writeFileSync(join(release, f.path), Buffer.alloc(f.size, 0x61));
  }
  const manifest = {
    schema: "orcel-release-manifest-v1",
    version: "0.2.0",
    config_schema: { min: 1, max: 1 },
    files
  };
  function saveManifest() { writeFileSync(join(release, "manifest.json"), JSON.stringify(manifest)); }
  saveManifest();
  try { return body({ dir, release, manifest, saveManifest }); }
  finally { rmSync(dir, { recursive: true, force: true }); }
}
function run(...args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
}

test("measures real files including manifest, with exact component breakdown", () => withFixture(({ release }) => {
  const report = inspectRelease(release);
  assert.equal(report.schema, "orcel-release-size/1");
  assert.equal(report.scope, "extracted-release-payload-only");
  assert.equal(report.payload_bytes, 30 + Buffer.byteLength(readFileSync(join(release, "manifest.json"))));
  assert.equal(report.breakdown_bytes.binaries, 10);
  assert.equal(report.breakdown_bytes.mcp_app, 20);
  assert.equal(report.breakdown_bytes.other, report.payload_bytes - 30);
  assert.equal(report.byte_budget, LIMIT_BYTES);
  assert.equal(report.budget_pass, true);
  assert.match(report.not_included_or_measured.join(" "), /Node.js/);
  assert.match(report.not_included_or_measured.join(" "), /browser/);
  assert.match(report.not_included_or_measured.join(" "), /not currently shipped/);
}));
test("CLI writes a machine-readable report outside the payload", () => withFixture(({ release, dir }) => {
  const output = join(dir, "size.json");
  const result = run("--release", release, "--out", output);
  assert.equal(result.status, 0, result.stderr);
  const written = JSON.parse(readFileSync(output));
  assert.deepEqual(written, JSON.parse(result.stdout));
}));
test("budget at exact boundary passes; one byte under fails closed", () => withFixture(({ release }) => {
  const n = inspectRelease(release).payload_bytes;
  assert.equal(run("--release", release, "--budget-bytes", String(n)).status, 0);
  const result = run("--release", release, "--budget-bytes", String(n - 1));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /exceeds/);
  assert.equal(JSON.parse(result.stdout).budget_pass, false);
}));
test("extra payload outside the signed manifest is rejected", () => withFixture(({ release }) => {
  writeFileSync(join(release, "unlisted.bin"), "x");
  assert.throws(() => inspectRelease(release), /unlisted release file/);
}));
test("missing, duplicated and incorrect manifest entries are rejected", () => withFixture(({ release, manifest, saveManifest }) => {
  manifest.files[0].size = 7;
  saveManifest();
  assert.throws(() => inspectRelease(release), /mismatched/);
  manifest.files[0].size = 10;
  manifest.files.push({ path: "orcel.exe", size: 10 });
  saveManifest();
  assert.throws(() => inspectRelease(release), /duplicate/);
  manifest.files.pop();
  manifest.files.splice(0, 1);
  saveManifest();
  assert.throws(() => inspectRelease(release), /unlisted/);
}));
test("symlink inside payload is always refused", { skip: process.platform === "win32" }, () => withFixture(({ release }) => {
  symlinkSync(join(release, "orcel.exe"), join(release, "linked.exe"));
  assert.throws(() => inspectRelease(release), /symbolic links/);
}));
test("output inside the measured release is refused", () => withFixture(({ release }) => {
  const r = run("--release", release, "--out", join(release, "report.json"));
  assert.equal(r.status, 1);
  assert.match(r.stderr, /outside the release/);
}));
test("invalid bounds and unknown arguments are refused", () => withFixture(({ release }) => {
  for (const budget of ["0", "-1", "5.4", "Infinity", "9007199254740992"]) {
    assert.equal(run("--release", release, "--budget-bytes", budget).status, 1, budget);
  }
  assert.equal(run("--release", release, "--unknown", "x").status, 1);
  assert.equal(run("--release", release, "--release", release).status, 1);
}));
