#!/usr/bin/env node
// F4 preparatory guard: counts every byte in the extracted release payload.
// This is NOT a full installed-app measurement: Node.js, the installed browser,
// disk allocation and user state are separately declared unmeasured.
import { existsSync, lstatSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const LIMIT_BYTES = 400_000_000;
const RELEASE_SCHEMA = "orcel-release-manifest-v1";

function requireDir(path) {
  if (!existsSync(path) || !lstatSync(path).isDirectory() || lstatSync(path).isSymbolicLink()) {
    throw new Error("release root must be an existing plain directory");
  }
}
function enumerate(dir, root, rows = []) {
  for (const name of readdirSync(dir).sort()) {
    const abs = join(dir, name);
    const stat = lstatSync(abs);
    if (stat.isSymbolicLink()) throw new Error("release cannot contain symbolic links: " + abs);
    if (stat.isDirectory()) enumerate(abs, root, rows);
    else if (stat.isFile()) rows.push({ path: relative(root, abs).split(sep).join("/"), bytes: stat.size });
    else throw new Error("unsupported release entry: " + abs);
  }
  return rows;
}
function integerBudget(input) {
  const n = Number(input);
  if (!/^[1-9][0-9]*$/.test(String(input)) || !Number.isSafeInteger(n)) {
    throw new Error("budget must be a positive safe integer in bytes");
  }
  return n;
}

export function inspectRelease(root, budget = LIMIT_BYTES) {
  const dir = resolve(root);
  requireDir(dir);
  const maxBytes = integerBudget(budget);
  const manifestPath = join(dir, "manifest.json");
  if (!existsSync(manifestPath) || lstatSync(manifestPath).isSymbolicLink()) {
    throw new Error("release must include a plain manifest.json");
  }
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  if (manifest.schema !== RELEASE_SCHEMA || !Array.isArray(manifest.files)) {
    throw new Error("unexpected release manifest schema or files");
  }
  const rows = enumerate(dir, dir);
  const actual = new Map(rows.map((row) => [row.path, row.bytes]));
  const listed = new Set();
  for (const entry of manifest.files) {
    if (!entry || typeof entry.path !== "string" || !Number.isSafeInteger(entry.size) || entry.size < 0) {
      throw new Error("invalid release manifest entry");
    }
    if (listed.has(entry.path)) throw new Error("duplicate manifest entry: " + entry.path);
    listed.add(entry.path);
    if (actual.get(entry.path) !== entry.size) throw new Error("missing/mismatched manifest entry: " + entry.path);
  }
  for (const row of rows) {
    if (row.path !== "manifest.json" && !listed.has(row.path)) {
      throw new Error("unlisted release file: " + row.path);
    }
  }
  const bytes = rows.reduce((total, row) => total + row.bytes, 0);
  if (!Number.isSafeInteger(bytes)) throw new Error("release bytes exceed safe integer range");
  const sum = (filter) => rows.filter(filter).reduce((total, row) => total + row.bytes, 0);
  return {
    schema: "orcel-release-size/1",
    scope: "extracted-release-payload-only",
    release_version: manifest.version,
    byte_budget: maxBytes,
    payload_bytes: bytes,
    file_count: rows.length,
    budget_pass: bytes <= maxBytes,
    breakdown_bytes: {
      binaries: sum((row) => /^[^/]+\.exe$/i.test(row.path)),
      mcp_app: sum((row) => row.path.startsWith("app/orcel-mcp/")),
      other: sum((row) => !/^[^/]+\.exe$/i.test(row.path) && !row.path.startsWith("app/orcel-mcp/"))
    },
    not_included_or_measured: [
      "Node.js prerequisite (not bundled)",
      "installed Edge or Chrome browser (not bundled)",
      "installer-created state, version history and logs",
      "Windows per-file allocated disk space and filesystem overhead",
      "native desktop UI (not currently shipped in this archive)",
      "code signing / installed-artifact qualification"
    ]
  };
}
export function run(args) {
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!["--release", "--out", "--budget-bytes"].includes(args[i]) || !args[i + 1] || options[args[i]]) {
      throw new Error("usage: --release <dir> [--out <json-outside-release>] [--budget-bytes <positive-integer>]");
    }
    options[args[i]] = args[i + 1];
  }
  if (!options["--release"]) throw new Error("--release is required");
  const dir = resolve(options["--release"]);
  const output = options["--out"] ? resolve(options["--out"]) : null;
  if (output && (output === dir || output.startsWith(dir + sep))) {
    throw new Error("--out must be outside the release being measured");
  }
  const result = inspectRelease(dir, options["--budget-bytes"] ?? LIMIT_BYTES);
  if (output) writeFileSync(output, JSON.stringify(result, null, 2) + "\n");
  process.stdout.write(JSON.stringify(result) + "\n");
  if (!result.budget_pass) throw new Error("release payload exceeds " + result.byte_budget + " bytes");
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    run(process.argv.slice(2));
  } catch (error) {
    console.error("release-size: " + error.message);
    process.exitCode = 1;
  }
}
