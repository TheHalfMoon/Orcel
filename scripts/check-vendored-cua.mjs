#!/usr/bin/env node
// XP-05: proves the vendored Cua Driver crates under
// apps/orcel-native-host/third_party/cua-driver/ are byte-identical to the
// upstream trees at the pin recorded in docs/orcel/cua_driver_provenance.json,
// except for the files the reviewed patch queue (PATCHES.md) lists.
//
// For each crate the script takes the blobs git has for the committed files
// (the index, so it also works before a commit), puts the recorded upstream
// blob back for every listed patched file, rebuilds the git tree with
// `git mktree` and requires it to equal the upstream tree id. A changed,
// added, removed or re-moded file outside the list therefore fails, and so
// does a listed file that no longer differs from upstream.
//
// Usage: node scripts/check-vendored-cua.mjs
// Dependency-free; needs git on PATH. Exits 1 on any mismatch.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const provenancePath = join(repoRoot, "docs/orcel/cua_driver_provenance.json");
const vendorRoot = "apps/orcel-native-host/third_party/cua-driver";
const SHA = /^[0-9a-f]{40}$/;

function git(args, input) {
  return execFileSync("git", args, {
    cwd: repoRoot,
    input,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
}

/** Index entries under `prefix` as path -> { mode, sha }. */
function indexEntries(prefix) {
  const out = new Map();
  for (const record of git(["ls-files", "-s", "-z", "--", prefix]).split("\0")) {
    if (!record) continue;
    const tab = record.indexOf("\t");
    const [mode, sha, stage] = record.slice(0, tab).split(" ");
    const path = record.slice(tab + 1);
    if (stage !== "0") throw new Error(`${path}: unmerged index entry`);
    out.set(path, { mode, sha });
  }
  return out;
}

/** Builds the git tree for `files` (relative path -> { mode, sha }). */
function mktree(files) {
  const blobs = [];
  const dirs = new Map();
  for (const [path, entry] of files) {
    const slash = path.indexOf("/");
    if (slash < 0) {
      blobs.push(`${entry.mode} blob ${entry.sha}\t${path}`);
    } else {
      const dir = path.slice(0, slash);
      if (!dirs.has(dir)) dirs.set(dir, new Map());
      dirs.get(dir).set(path.slice(slash + 1), entry);
    }
  }
  const lines = [...blobs];
  for (const [dir, children] of dirs) {
    lines.push(`040000 tree ${mktree(children)}\t${dir}`);
  }
  return git(["mktree", "--missing", "-z"], lines.map((l) => `${l}\0`).join("")).trim();
}

export function check() {
  const provenance = JSON.parse(readFileSync(provenancePath, "utf8"));
  const patches = readFileSync(join(repoRoot, vendorRoot, "PATCHES.md"), "utf8");
  const errors = [];
  if (!SHA.test(provenance.donor?.commit ?? "")) errors.push("donor.commit is not a 40-hex id");

  const all = indexEntries(`${vendorRoot}/`);
  const claimed = new Set();
  for (const file of provenance.files ?? []) {
    claimed.add(file.destination);
    const entry = all.get(file.destination);
    if (!entry) errors.push(`${file.destination}: missing`);
    else if (entry.sha !== file.blob_sha) {
      errors.push(`${file.destination}: blob ${entry.sha} is not upstream ${file.blob_sha}`);
    }
  }
  claimed.add(`${vendorRoot}/PATCHES.md`);

  const summary = [];
  for (const crate of provenance.crates ?? []) {
    const prefix = `${crate.destination}/`;
    const files = new Map();
    for (const [path, entry] of all) {
      if (path.startsWith(prefix)) {
        files.set(path.slice(prefix.length), { ...entry });
        claimed.add(path);
      }
    }
    for (const patched of crate.patched_files ?? []) {
      const entry = files.get(patched.path);
      const full = `${prefix}${patched.path}`;
      if (!entry) {
        errors.push(`${full}: listed as patched but absent`);
        continue;
      }
      if (entry.sha === patched.upstream_blob_sha) {
        errors.push(`${full}: listed as patched but identical to upstream`);
      }
      if (!patches.includes(`${crate.name}/${patched.path}`)) {
        errors.push(`${full}: patched but not named in PATCHES.md`);
      }
      entry.sha = patched.upstream_blob_sha;
      entry.mode = patched.upstream_mode ?? entry.mode;
    }
    const tree = files.size ? mktree(files) : "(empty)";
    if (tree !== crate.tree_sha) {
      errors.push(`${crate.name}: rebuilt tree ${tree} is not upstream ${crate.tree_sha}`);
    }
    summary.push(
      `${crate.name}: ${files.size} files, ${(crate.patched_files ?? []).length} patched, tree ${tree}`,
    );
  }
  for (const path of all.keys()) {
    if (!claimed.has(path)) errors.push(`${path}: not part of any recorded upstream tree`);
  }
  return { errors, summary };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { errors, summary } = check();
  for (const line of summary) console.log(line);
  if (errors.length) {
    for (const e of errors) console.error(`error: ${e}`);
    process.exit(1);
  }
  console.log("vendored Cua Driver crates match the upstream pin outside PATCHES.md");
}
