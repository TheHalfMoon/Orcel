#!/usr/bin/env node
// #399: lopdf is a path dependency of apps/orcel-doc-parser (the vendored,
// patched copy under third_party/lopdf), so `cargo audit` no longer matches
// it against RustSec. This is the replacement watch: it lists the RustSec
// advisories filed for the `lopdf` crate and requires each one to be either
// patched in (or unaffected at) the vendored version recorded in
// docs/orcel/lopdf_provenance.json, or named in that file's
// `reviewed_advisories` with the reason it does not apply.
//
// Usage: node scripts/check-lopdf-advisories.mjs
// Dependency-free. Reads the RustSec advisory database through the GitHub
// API (GITHUB_TOKEN or GH_TOKEN is used when set, to avoid rate limits).
// Exits 1 on an unreviewed advisory that affects the vendored version, and
// on any failure to read the database: the watch never passes by silence.
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PROVENANCE = join(ROOT, "docs", "orcel", "lopdf_provenance.json");
const API = "https://api.github.com/repos/rustsec/advisory-db/contents/crates/lopdf";

export function parseVersion(text) {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(text.trim());
  if (!match) throw new Error(`not a version: ${text}`);
  return match.slice(1).map(Number);
}

function compare(a, b) {
  for (let i = 0; i < 3; i += 1) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

// One requirement such as ">= 0.42.0", "< 0.3.0" or "^0.41.1".
function satisfies(version, requirement) {
  const match = /^(>=|<=|>|<|=|\^)?\s*(\d+\.\d+\.\d+)$/.exec(requirement.trim());
  if (!match) throw new Error(`unsupported version requirement: ${requirement}`);
  const bound = parseVersion(match[2]);
  const order = compare(version, bound);
  switch (match[1] ?? "^") {
    case ">=":
      return order >= 0;
    case "<=":
      return order <= 0;
    case ">":
      return order > 0;
    case "<":
      return order < 0;
    case "=":
      return order === 0;
    default:
      // Caret on a 0.x version pins the minor, as Cargo does.
      return order >= 0 && version[0] === bound[0] && (bound[0] !== 0 || version[1] === bound[1]);
  }
}

// An advisory's `[versions]` table lists requirements; a requirement set
// joined by commas must all hold, and any one set holding is enough.
export function isUnaffected(version, advisoryToml) {
  const sets = [];
  for (const key of ["patched", "unaffected"]) {
    const line = new RegExp(`^${key}${String.raw`\s*=\s*\[(.*)\]\s*$`}`, "m").exec(advisoryToml);
    if (!line) continue;
    for (const entry of line[1].matchAll(/"([^"]*)"/g)) sets.push(entry[1]);
  }
  return sets.some((set) => set.split(",").every((requirement) => satisfies(version, requirement)));
}

async function get(url) {
  const headers = { accept: "application/vnd.github+json", "user-agent": "orcel-lopdf-advisory-watch" };
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  if (token) headers.authorization = `Bearer ${token}`;
  const response = await fetch(url, { headers });
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  return response;
}

async function main() {
  const provenance = JSON.parse(readFileSync(PROVENANCE, "utf8"));
  const lopdf = provenance.crates.find((crate) => crate.name === "lopdf");
  const version = parseVersion(lopdf.version);
  const reviewed = new Set((provenance.reviewed_advisories ?? []).map((entry) => entry.id));
  const listing = await (await get(API)).json();
  const failures = [];
  for (const file of listing.filter((entry) => entry.name.endsWith(".md"))) {
    const id = file.name.replace(/\.md$/, "");
    const toml = /```toml\n([\s\S]*?)```/.exec(await (await get(file.download_url)).text());
    if (!toml) throw new Error(`${id}: no advisory table`);
    const verdict = isUnaffected(version, toml[1])
      ? "not affected"
      : reviewed.has(id)
        ? "affected, reviewed"
        : "AFFECTED, UNREVIEWED";
    console.log(`${id}: lopdf ${lopdf.version} ${verdict}`);
    if (verdict === "AFFECTED, UNREVIEWED") failures.push(id);
  }
  if (failures.length > 0) {
    console.error(
      `Unreviewed lopdf advisories: ${failures.join(", ")}. Rebase the vendored copy or add each to reviewed_advisories in docs/orcel/lopdf_provenance.json with the reason it does not apply.`,
    );
    process.exit(1);
  }
  console.log(`checked ${listing.length} RustSec file(s) for lopdf`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`lopdf advisory watch failed: ${error.message}`);
    process.exit(1);
  });
}
