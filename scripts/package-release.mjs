#!/usr/bin/env node
// Assembles a Orcel Windows release directory and its manifest.json.
//
// Usage:
//   node scripts/package-release.mjs --out <empty-or-new-dir> [--target-dir target/release]
//     [--contain-target-dir apps/orcel-contain/target/release]
//
// Prerequisites: `cargo build --release -p orceld -p orcel-lifecycle` on
// Windows, `cargo build --release --locked --bin orcel-contain` in
// apps/orcel-contain (its own workspace, XP-13b), and `npm run build` for the
// MCP app. The helper ships beside orceld.exe with its pin,
// orcel-contain.sha256, which orceld reads to pin it (both are manifest
// files, so the installer verifies them too). The script copies only runtime
// payload (no tests, type declarations, or source maps), installs the MCP
// app's production dependencies, and writes a manifest whose paths satisfy
// the same rules the installer enforces.

import { stageMcpPayload } from "./mcp-payload.mjs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST_SCHEMA = "orcel-release-manifest-v1";
const CONFIG_SCHEMA = { min: 1, max: 1 };
const BINARIES = ["orcel.exe", "orcel-mcp-host.exe", "orceld.exe"];

function fail(message) {
  console.error(`package-release: ${message}`);
  process.exit(1);
}

function arg(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index === -1) return fallback;
  const value = process.argv[index + 1];
  if (!value || value.startsWith("--")) fail(`${name} requires a value`);
  return value;
}

function workspaceVersion() {
  const cargo = readFileSync(join(repo, "Cargo.toml"), "utf8");
  const match = cargo.match(/\[workspace\.package\][^[]*?\nversion\s*=\s*"([^"]+)"/);
  if (!match) fail("workspace version not found in Cargo.toml");
  const app = JSON.parse(readFileSync(join(repo, "apps/orcel-mcp/package.json"), "utf8"));
  if (app.version !== match[1]) {
    fail(`Cargo workspace version ${match[1]} does not match @orcel/mcp ${app.version}`);
  }
  return match[1];
}

// Mirrors orcel_lifecycle::manifest::validate_relative_path.
function validateRelativePath(path) {
  if (path.length === 0 || path.length > 200) return "length out of range";
  if (path.startsWith("/")) return "absolute path";
  for (const segment of path.split("/")) {
    if (segment === "" || segment === "." || segment === "..") return "empty or relative segment";
    if (segment.endsWith(".") || segment.endsWith(" ")) return "trailing dot or space";
    if (!/^[\x20-\x7e]+$/.test(segment) || /[<>:"\\|?*]/.test(segment)) return "forbidden character";
    const stem = segment.split(".")[0].toUpperCase();
    if (["CON", "PRN", "AUX", "NUL"].includes(stem) || /^(COM|LPT)[0-9]$/.test(stem)) {
      return "reserved device name";
    }
  }
  return null;
}

function walk(dir, out) {
  for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name);
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) fail(`release payload must not contain links: ${path}`);
    if (stat.isDirectory()) walk(path, out);
    else if (stat.isFile()) out.push(path);
    else fail(`unsupported payload entry: ${path}`);
  }
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

const out = resolve(arg("--out", ""));
if (!process.argv.includes("--out")) fail("--out <dir> is required");
const targetDir = resolve(repo, arg("--target-dir", "target/release"));
const containTargetDir = resolve(repo, arg("--contain-target-dir", "apps/orcel-contain/target/release"));
const version = workspaceVersion();

if (existsSync(out) && readdirSync(out).length > 0) fail(`${out} must be empty or absent`);
mkdirSync(out, { recursive: true });

for (const binary of BINARIES) {
  const from = join(targetDir, binary);
  if (!existsSync(from)) fail(`missing ${from}; run cargo build --release on Windows first`);
  copyFileSync(from, join(out, binary));
}
// XP-13b: the contained-tier helper and its pin. orceld resolves both only
// beside its own executable.
const containHelper = join(containTargetDir, "orcel-contain.exe");
if (!existsSync(containHelper)) {
  fail(`missing ${containHelper}; run cargo build --release --locked --bin orcel-contain in apps/orcel-contain first`);
}
copyFileSync(containHelper, join(out, "orcel-contain.exe"));
writeFileSync(join(out, "orcel-contain.sha256"), `${sha256(join(out, "orcel-contain.exe"))}\n`);
// SG-000127: the Windows app, built deterministically by build.ps1. It only starts
// `orcel` from the install and reads the local app API.
const appBuild = join(targetDir, "windows-app");
execFileSync(
  "powershell.exe",
  [
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    join(repo, "apps", "orcel-desktop-preview", "build.ps1"),
    "-OutputDirectory",
    appBuild,
    "-Deterministic"
  ],
  { stdio: "inherit" }
);
copyFileSync(join(appBuild, "Orcel.Desktop.exe"), join(out, "Orcel.Desktop.exe"));
copyFileSync(join(repo, "LICENSE"), join(out, "LICENSE"));

stageMcpPayload(repo, out, fail);

// Third-party notices are generated from the actual shipped dependency graph
// and this payload's node_modules, and become part of the verified payload.
execFileSync(
  process.execPath,
  [join(repo, "scripts", "third-party-notices.mjs"), "--release", out, "--out", join(out, "THIRD_PARTY_NOTICES.txt")],
  { cwd: repo, stdio: "inherit" }
);

const files = [];
walk(out, files);
const entries = files
  .map((path) => relative(out, path).split(sep).join("/"))
  .filter((path) => path !== "manifest.json")
  .sort()
  .map((path) => {
    const problem = validateRelativePath(path);
    if (problem) fail(`payload path ${JSON.stringify(path)} is not installable: ${problem}`);
    const full = join(out, ...path.split("/"));
    return { path, size: lstatSync(full).size, sha256: sha256(full) };
  });

const manifest = { schema: MANIFEST_SCHEMA, version, config_schema: CONFIG_SCHEMA, files: entries };
writeFileSync(join(out, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`package-release: Orcel ${version} with ${entries.length} files in ${out}`);
