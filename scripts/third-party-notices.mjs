#!/usr/bin/env node
// Writes THIRD_PARTY_NOTICES.txt for a Orcel release: for every third-party
// crate linked into the shipped binaries (x86_64-pc-windows-msvc unless
// --target names another triple, normal dependency edges only) and every npm package in the release's
// app/orcel-mcp/node_modules, the declared license expression and the full
// text of each license or notice file the package ships.
//
// Usage:
//   node scripts/third-party-notices.mjs --release <release-dir> --out <file> [--target <triple>]

import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const targetIndex = process.argv.indexOf("--target");
// XP-17: the Linux packages pass --target x86_64-unknown-linux-gnu.
const TARGET = targetIndex === -1 ? "x86_64-pc-windows-msvc" : process.argv[targetIndex + 1];
if (!TARGET || TARGET.startsWith("--")) fail("--target <triple> needs a value");
// Each Cargo workspace that ships a binary, with its shipped root packages.
// XP-13b: the orcel-contain helper is its own workspace (AD-16).
// #369/#373: the XP-10 approval helper (GTK 4) ships in the Linux packages
// only.
const WORKSPACES = [
  { dir: ".", roots: ["orceld", "orcel-lifecycle"] },
  { dir: "apps/orcel-contain", roots: ["orcel-contain"] },
  { dir: "apps/orcel-approval-helper-linux", roots: ["orcel-approval-helper-linux"], linuxOnly: true }
].filter((workspace) => !workspace.linuxOnly || TARGET.includes("-linux-"));
const NOTICE_FILE = /^(licen[cs]e|copying|notice|unlicense)([-_.].*)?$/i;
// Source vendored into this repository rather than resolved from a registry.
// Its notice is maintained in-repo, and the upstream copyright line must
// appear in it verbatim.
const VENDORED_NOTICES = [
  {
    name: "Cua Driver (trycua/cua@a802eaf26ca97616a6bf0de6a29729a9346fbb1f, vendored source)",
    license: "MIT",
    file: "docs/orcel/notices/cua-MIT.txt",
    copyright: "Copyright (c) 2025 Cua AI, Inc."
  },
  {
    name: "Playwright (microsoft/playwright@1b025d7e20a026371cd5f98ba0cdce48892737c8, adapted verifier source)",
    license: "Apache-2.0",
    file: "docs/orcel/notices/playwright-Apache-2.0.txt",
    copyright: "Copyright (c) Microsoft Corporation"
  }
];

function fail(message) {
  console.error(`third-party-notices: ${message}`);
  process.exit(1);
}

function arg(name) {
  const index = process.argv.indexOf(name);
  if (index === -1 || !process.argv[index + 1]) fail(`${name} <value> is required`);
  return resolve(process.argv[index + 1]);
}

/**
 * License and notice files a package ships: matching files anywhere in the
 * package (excluding nested dependencies and VCS folders) plus a declared
 * license file, each listed by its path relative to the package root.
 */
function noticeFiles(dir, declared) {
  const found = new Map();
  const visit = (current, prefix, depth) => {
    for (const name of readdirSync(current).sort()) {
      if (name === "node_modules" || name === ".git" || name === "target") continue;
      const path = join(current, name);
      // lstat: links are never followed, so only files inside the package are read.
      const stat = lstatSync(path);
      const rel = prefix ? `${prefix}/${name}` : name;
      if (stat.isDirectory()) {
        if (depth < 3) visit(path, rel, depth + 1);
      } else if (stat.isFile() && (NOTICE_FILE.test(name) || /^licen[cs]es?$/i.test(prefix.split("/").pop() ?? ""))) {
        found.set(rel, path);
      }
    }
  };
  visit(dir, "", 0);
  if (declared) {
    // A declared license file must stay inside the package directory.
    const path = resolve(dir, declared);
    const rel = relative(resolve(dir), path);
    const inside = rel !== "" && rel !== ".." && !rel.startsWith(`..${sep}`) && !/^[A-Za-z]:|^[\\/]/.test(rel);
    if (!inside) fail(`${dir} declares a license file outside the package: ${declared}`);
    if (existsSync(path) && lstatSync(path).isFile()) found.set(rel.split(sep).join("/"), path);
  }
  return [...found.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([name, path]) => ({ name, text: readFileSync(path, "utf8").replace(/\r\n/g, "\n").trimEnd() }));
}

function crates() {
  return WORKSPACES.flatMap((workspace) => workspaceCrates(workspace));
}

function workspaceCrates({ dir, roots }) {
  const metadata = JSON.parse(
    execFileSync("cargo", ["metadata", "--locked", "--format-version", "1", "--filter-platform", TARGET], {
      cwd: join(repo, dir),
      maxBuffer: 256 * 1024 * 1024
    }).toString()
  );
  const packages = new Map(metadata.packages.map((p) => [p.id, p]));
  const nodes = new Map(metadata.resolve.nodes.map((n) => [n.id, n]));
  const reached = new Set();
  const stack = metadata.packages.filter((p) => roots.includes(p.name) && !p.source).map((p) => p.id);
  if (stack.length !== roots.length) fail(`root packages ${roots.join(", ")} not found in ${dir}`);
  while (stack.length) {
    const id = stack.pop();
    if (reached.has(id)) continue;
    reached.add(id);
    for (const dep of nodes.get(id)?.deps ?? []) {
      if (dep.dep_kinds.some((kind) => kind.kind === null)) stack.push(dep.pkg);
    }
  }
  return [...reached]
    .map((id) => packages.get(id))
    .filter((p) => p.source)
    .map((p) => ({
      kind: "crate",
      name: p.name,
      version: p.version,
      license: p.license,
      licenseFile: p.license_file,
      dir: dirname(p.manifest_path)
    }));
}

function npmPackages(release) {
  const found = [];
  const visit = (dir) => {
    if (!existsSync(dir)) return;
    for (const name of readdirSync(dir).sort()) {
      if (name.startsWith(".")) continue;
      const path = join(dir, name);
      if (name.startsWith("@")) {
        visit(path);
        continue;
      }
      if (existsSync(join(path, "package.json"))) {
        const pkg = JSON.parse(readFileSync(join(path, "package.json"), "utf8"));
        const declared = typeof pkg.license === "string" && /^SEE LICEN[CS]E IN /i.test(pkg.license)
          ? pkg.license.replace(/^SEE LICEN[CS]E IN /i, "")
          : null;
        found.push({ kind: "npm", name: pkg.name, version: pkg.version, license: pkg.license, licenseFile: declared, dir: path });
        visit(join(path, "node_modules"));
      }
    }
  };
  visit(join(release, "app", "orcel-mcp", "node_modules"));
  return found;
}

const release = arg("--release");
const out = arg("--out");
// One entry per kind:name@version (a package installed at several nesting
// levels ships the same text), in a strict total order.
const byKey = new Map();
for (const entry of [...crates(), ...npmPackages(release)]) {
  const key = `${entry.kind}:${entry.name}@${entry.version}`;
  if (!byKey.has(key)) byKey.set(key, entry);
}
const entries = [...byKey.entries()]
  .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  .map(([, entry]) => entry);
const missing = [];
let text =
  "Orcel third-party notices\n\n" +
  "Orcel is licensed under the Apache License 2.0 (see LICENSE). This release\n" +
  "includes the following third-party components, each under its own license.\n";
for (const entry of entries) {
  const files = noticeFiles(entry.dir, entry.licenseFile);
  if (!entry.license || files.length === 0) missing.push(`${entry.kind} ${entry.name}@${entry.version}`);
  text += `\n${"=".repeat(78)}\n${entry.name} ${entry.version} (${entry.kind})\nLicense: ${entry.license ?? "UNDECLARED"}\n`;
  for (const file of files) {
    text += `\n--- ${file.name} ---\n${file.text}\n`;
  }
}
for (const vendored of VENDORED_NOTICES) {
  const notice = readFileSync(join(repo, vendored.file), "utf8").replace(/\r\n/g, "\n").trimEnd();
  if (!notice.includes(vendored.copyright)) fail(`${vendored.file} lacks "${vendored.copyright}"`);
  text += `\n${"=".repeat(78)}\n${vendored.name}\nLicense: ${vendored.license}\n\n--- ${vendored.file} ---\n${notice}\n`;
}
if (missing.length) {
  text += `\n${"=".repeat(78)}\nComponents without a declared license or shipped license file:\n${missing.join("\n")}\n`;
}
writeFileSync(out, text);
console.log(`third-party-notices: ${entries.length} components; ${missing.length} without a shipped license file -> ${out}`);
