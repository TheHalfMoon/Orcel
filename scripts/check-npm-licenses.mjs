#!/usr/bin/env node
// WP1-01 npm lockfile gate.
//
// Founder decision of 2026-11-17 (docs/orcel/grants/2026-11-17-founder-
// attestation.md, owner-asserted): a licence type blocks nothing. This gate
// therefore no longer refuses any licence; it reports the licences of every
// locked npm package and enforces how packages are locked:
// - every package-lock.json in the repository is read (lockfileVersion 2
//   or 3);
// - every installed package is pinned: a version, a resolved URL and an
//   integrity hash (workspace links and workspace members excepted);
// - another lockfile kind (npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock,
//   bun.lock, bun.lockb) fails, and so does a package.json that declares
//   dependencies with no package-lock.json beside it (a root npm workspace
//   member is locked by the root lockfile).
//
// Usage: node scripts/check-npm-licenses.mjs [--root <repository>] [--report]
//   --report prints the licence of every locked package.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { listFiles, rootFromArgs } from "./licence-gate-lib.mjs";

const OTHER_LOCKS = /(^|\/)(npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?)$/;
const DEPENDENCY_KEYS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];

/** True when `dir` matches an npm workspace pattern (a literal path, or one with single-segment `*`). */
export function inWorkspace(dir, patterns) {
  return patterns.some((pattern) => {
    const clean = pattern.replace(/^\.\//, "").replace(/\/$/, "");
    if (clean.includes("**")) return false;
    const regex = new RegExp(`^${clean.split("*").map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join("[^/]+")}$`);
    return regex.test(dir);
  });
}

function packageName(key) {
  const marker = "node_modules/";
  const at = key.lastIndexOf(marker);
  return at < 0 ? key : key.slice(at + marker.length);
}

export function lockfiles(root, files = listFiles(root)) {
  return files.filter((path) => path === "package-lock.json" || path.endsWith("/package-lock.json"));
}

/** Lockfiles of other kinds, and package.json files with dependencies but no lockfile. */
export function unlockedPackages(root) {
  const files = listFiles(root);
  const errors = files
    .filter((path) => OTHER_LOCKS.test(path))
    .map((path) => `${path}: only package-lock.json is read by the lockfile gate; use npm and commit package-lock.json`);
  const locks = new Set(lockfiles(root, files));
  let workspaces = [];
  if (existsSync(join(root, "package.json"))) {
    const top = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    workspaces = Array.isArray(top.workspaces) ? top.workspaces : top.workspaces?.packages ?? [];
  }
  for (const path of files.filter((p) => p === "package.json" || p.endsWith("/package.json"))) {
    const dir = posix.dirname(path);
    const manifest = JSON.parse(readFileSync(join(root, path), "utf8"));
    const declares = DEPENDENCY_KEYS.some((key) => manifest[key] && Object.keys(manifest[key]).length);
    if (!declares) continue;
    const lock = dir === "." ? "package-lock.json" : `${dir}/package-lock.json`;
    const member = inWorkspace(dir, workspaces) && locks.has("package-lock.json");
    if (!locks.has(lock) && !member) errors.push(`${path}: declares dependencies but has no package-lock.json`);
  }
  return errors;
}

export function checkNpmLockfiles(root) {
  const errors = [...unlockedPackages(root)];
  const report = [];
  const locks = lockfiles(root);
  for (const lockfile of locks) {
    const lock = JSON.parse(readFileSync(join(root, lockfile), "utf8"));
    if (!lock.packages || typeof lock.packages !== "object") {
      errors.push(`${lockfile}: no "packages" map (lockfileVersion 2 or 3 is required)`);
      continue;
    }
    const lockDir = posix.dirname(lockfile);
    for (const [key, entry] of Object.entries(lock.packages)) {
      if (key === "" || entry.link) continue;
      const workspace = !key.includes("node_modules/");
      let licence = entry.license;
      if (workspace && licence === undefined) {
        const manifest = join(root, lockDir === "." ? key : `${lockDir}/${key}`, "package.json");
        if (existsSync(manifest)) licence = JSON.parse(readFileSync(manifest, "utf8")).license;
      }
      const name = workspace ? key : packageName(key);
      report.push({ lockfile, name, version: entry.version ?? null, licence: typeof licence === "string" ? licence : null });
      if (workspace) continue;
      const missing = ["version", "resolved", "integrity"].filter((field) => typeof entry[field] !== "string" || !entry[field]);
      if (missing.length) errors.push(`${lockfile}: ${name} is not pinned (missing ${missing.join(", ")})`);
    }
  }
  return { errors, lockfiles: locks, report };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = rootFromArgs(process.argv, resolve(dirname(fileURLToPath(import.meta.url)), ".."), "check-npm-licenses");
  const { errors, lockfiles: locks, report } = checkNpmLockfiles(root);
  if (process.argv.includes("--report")) {
    for (const row of report) console.log(`${row.lockfile}\t${row.name}\t${row.version ?? ""}\t${row.licence ?? "(none declared)"}`);
  }
  const counts = new Map();
  for (const row of report) counts.set(row.licence ?? "(none declared)", (counts.get(row.licence ?? "(none declared)") ?? 0) + 1);
  const summary = [...counts].sort((a, b) => b[1] - a[1]).map(([licence, n]) => `${licence}: ${n}`).join("; ");
  if (errors.length) {
    for (const error of errors) console.error(`check-npm-licenses: ${error}`);
    process.exit(1);
  }
  console.log(`check-npm-licenses: ${report.length} locked packages in ${locks.length} lockfiles, all pinned. Licences (reported, not judged): ${summary}`);
}
