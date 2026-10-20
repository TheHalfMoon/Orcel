#!/usr/bin/env node
// #391: proves the vendored lopdf crate under
// apps/orcel-doc-parser/third_party/lopdf/ is byte-identical to the crates.io
// release recorded in docs/orcel/lopdf_provenance.json, except for the files
// its reviewed patch queue (PATCHES.md) lists.
//
// The script takes the blobs git has for the committed files (the index, so
// it also works before a commit). It puts the recorded upstream blob back for
// every patched file, puts every removed file and directory back as its
// upstream blob or tree, and leaves out every added file. Then it rebuilds
// the git tree with `git mktree` and requires it to equal the recorded
// upstream tree id. A changed, added, removed or re-moded file outside the
// lists therefore fails, and so does a listed patch that no longer differs
// from upstream.
//
// With --upstream it also downloads the crate from crates.io, requires its
// SHA-256 to equal the recorded checksum (the one Cargo.lock carried before
// the patch), unpacks it and computes the upstream tree id itself, so the id
// recorded in this repository is not trusted on its own.
//
// It also checks the lockfile side of the patch: the parser's Cargo.lock
// resolves lopdf to the path copy at the recorded version (no registry
// source), pdf-inspector is still the version the patch was reviewed
// against, and orceld's lockfile has no lopdf at all.
//
// Every vendored file must also be reviewable by the exact-diff gate: text,
// with no line longer than MAX_REVIEWABLE_LINE and no line ending in
// whitespace (the gate runs `git diff --check`).
//
// Usage: node scripts/check-vendored-lopdf.mjs [--upstream]
// Dependency-free; needs git on PATH. Exits 1 on any mismatch.
import { Buffer, isUtf8 } from "node:buffer";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { MAX_REVIEWABLE_LINE } from "./check-vendored-cua.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const provenancePath = join(repoRoot, "docs/orcel/lopdf_provenance.json");
const SHA = /^[0-9a-f]{40}$/;

function git(args, input) {
  return execFileSync("git", args, {
    cwd: repoRoot,
    input,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
}

function gitHashObject(bytes) {
  return execFileSync("git", ["hash-object", "--stdin"], { cwd: repoRoot, input: bytes }).toString().trim();
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

/**
 * Builds the git tree for `files` (relative path -> { mode, sha }, or
 * { tree } for a whole subtree put back as its id).
 */
function mktree(files) {
  const lines = [];
  const dirs = new Map();
  for (const [path, entry] of files) {
    const slash = path.indexOf("/");
    if (slash < 0) {
      lines.push(entry.tree ? `040000 tree ${entry.tree}\t${path}` : `${entry.mode} blob ${entry.sha}\t${path}`);
    } else {
      const dir = path.slice(0, slash);
      if (!dirs.has(dir)) dirs.set(dir, new Map());
      dirs.get(dir).set(path.slice(slash + 1), entry);
    }
  }
  for (const [dir, children] of dirs) {
    lines.push(`040000 tree ${mktree(children)}\t${dir}`);
  }
  return git(["mktree", "--missing", "-z"], lines.map((l) => `${l}\0`).join("")).trim();
}

/** The regular files of a .tar (ustar, GNU long names, pax paths). */
export function untar(tar) {
  const files = new Map();
  let longName = null;
  for (let at = 0; at + 512 <= tar.length; ) {
    const header = tar.subarray(at, at + 512);
    if (header.every((b) => b === 0)) break;
    const field = (start, end) => header.subarray(start, end).toString("utf8").replace(/\0.*$/s, "");
    const size = Number.parseInt(field(124, 136).trim() || "0", 8);
    const type = String.fromCharCode(header[156] || 48);
    const body = tar.subarray(at + 512, at + 512 + size);
    at += 512 + Math.ceil(size / 512) * 512;
    if (type === "L") {
      longName = body.toString("utf8").replace(/\0.*$/s, "");
      continue;
    }
    if (type === "x") {
      const path = body.toString("utf8").match(/^\d+ path=(.*)$/m);
      if (path) longName = path[1];
      continue;
    }
    const prefix = field(345, 500);
    const name = longName ?? (prefix ? `${prefix}/${field(0, 100)}` : field(0, 100));
    longName = null;
    if (type === "0" || type === "\0") files.set(name, Buffer.from(body));
  }
  return files;
}

/** The git tree id of a crate's files (path under the crate root -> bytes). */
function treeOfFiles(files) {
  const entries = new Map();
  for (const [path, bytes] of files) entries.set(path, { mode: "100644", sha: gitHashObject(bytes) });
  return mktree(entries);
}

async function upstreamTree(krate) {
  const url = `https://static.crates.io/crates/${krate.name}/${krate.name}-${krate.version}.crate`;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  const archive = Buffer.from(await response.arrayBuffer());
  const checksum = createHash("sha256").update(archive).digest("hex");
  const root = `${krate.name}-${krate.version}/`;
  const files = new Map();
  for (const [path, bytes] of untar(gunzipSync(archive))) {
    if (path.startsWith(root)) files.set(path.slice(root.length), bytes);
  }
  return { checksum, tree: treeOfFiles(files), files };
}

/** `text` with the spaces and tabs at the end of every line removed. */
export function stripLineEnds(text) {
  return text.replace(/[ \t]+$/gm, "");
}

/** The `[[package]]` blocks of a Cargo.lock named `name`. */
function lockEntries(text, name) {
  return text
    .split(/\n(?=\[\[package\]\])/)
    .filter((block) => block.includes(`\nname = "${name}"\n`));
}

export async function check({ upstream = false } = {}) {
  const provenance = JSON.parse(readFileSync(provenancePath, "utf8"));
  if (provenance.crates?.length !== 1) throw new Error("lopdf provenance must list exactly one crate");
  const krate = provenance.crates[0];
  const prefix = `${krate.destination}/`;
  const patches = readFileSync(join(repoRoot, prefix, "PATCHES.md"), "utf8");
  const errors = [];
  if (!SHA.test(krate.tree_sha ?? "")) errors.push("crate.tree_sha is not a 40-hex id");

  const all = indexEntries(prefix);
  const files = new Map();
  for (const [path, entry] of all) files.set(path.slice(prefix.length), { ...entry });
  for (const own of krate.orcel_files ?? []) {
    if (!files.delete(own)) errors.push(`${prefix}${own}: Orcel-owned file is missing`);
  }
  for (const added of krate.added_files ?? []) {
    if (!files.delete(added.path)) errors.push(`${prefix}${added.path}: listed as added but absent`);
    if (!patches.includes(added.path)) errors.push(`${prefix}${added.path}: added but not named in PATCHES.md`);
  }
  for (const patched of krate.patched_files ?? []) {
    const entry = files.get(patched.path);
    const full = `${prefix}${patched.path}`;
    if (!entry) {
      errors.push(`${full}: listed as patched but absent`);
      continue;
    }
    if (entry.sha === patched.upstream_blob_sha) errors.push(`${full}: listed as patched but identical to upstream`);
    if (!patches.includes(patched.path)) errors.push(`${full}: patched but not named in PATCHES.md`);
    entry.sha = patched.upstream_blob_sha;
  }
  for (const removed of krate.removed_files ?? []) {
    const full = `${prefix}${removed.path}`;
    const id = removed.upstream_tree_sha ?? removed.upstream_blob_sha;
    if (!SHA.test(id ?? "")) errors.push(`${full}: removed entry needs its upstream id`);
    if ([...files.keys()].some((path) => path === removed.path || path.startsWith(`${removed.path}/`))) {
      errors.push(`${full}: listed as removed but present`);
    }
    if (!patches.includes(removed.path)) errors.push(`${full}: removed but not named in PATCHES.md`);
    files.set(
      removed.path,
      removed.upstream_tree_sha ? { tree: removed.upstream_tree_sha } : { mode: "100644", sha: removed.upstream_blob_sha },
    );
  }
  const rebuilt = mktree(files);
  if (rebuilt !== krate.tree_sha) errors.push(`${krate.name}: rebuilt tree ${rebuilt} is not upstream ${krate.tree_sha}`);

  const summary = [
    `${krate.name} ${krate.version}: ${all.size} files vendored, ${(krate.patched_files ?? []).length} patched, ` +
      `${(krate.added_files ?? []).length} added, ${(krate.removed_files ?? []).length} removed, tree ${rebuilt}`,
  ];
  if (upstream) {
    const fetched = await upstreamTree(krate);
    if (fetched.checksum !== krate.crate_sha256) {
      errors.push(`crates.io ${krate.name}-${krate.version}.crate has SHA-256 ${fetched.checksum}, not ${krate.crate_sha256}`);
    }
    if (fetched.tree !== krate.tree_sha) {
      errors.push(`crates.io ${krate.name}-${krate.version} unpacks to tree ${fetched.tree}, not ${krate.tree_sha}`);
    }
    // P-03: a whitespace-only patch must equal upstream's bytes with the
    // whitespace at each line's end removed, and nothing else.
    for (const patched of (krate.patched_files ?? []).filter((file) => file.whitespace_only)) {
      const original = fetched.files.get(patched.path);
      const vendored = readFileSync(join(repoRoot, prefix, patched.path), "utf8");
      if (!original || stripLineEnds(original.toString("utf8")) !== vendored) {
        errors.push(`${prefix}${patched.path}: not upstream's bytes with only line-end whitespace removed`);
      }
    }
    summary.push(`crates.io ${krate.name}-${krate.version}.crate: ${fetched.files.size} files, tree ${fetched.tree}`);
  }

  // Every vendored file must pass the exact-diff review gate as text.
  for (const path of all.keys()) {
    const bytes = readFileSync(join(repoRoot, path));
    if (bytes.subarray(0, 8192).includes(0) || !isUtf8(bytes)) {
      errors.push(`${path}: binary content cannot pass exact-diff review`);
      continue;
    }
    const text = bytes.toString("utf8");
    const longest = Math.max(...text.split("\n").map((line) => line.length));
    if (longest > MAX_REVIEWABLE_LINE) {
      errors.push(`${path}: a ${longest}-character line exceeds the ${MAX_REVIEWABLE_LINE}-character review limit`);
    }
    if (stripLineEnds(text) !== text) errors.push(`${path}: a line ends in whitespace, which git diff --check refuses`);
  }

  // The lockfile side of the patch.
  const lock = readFileSync(join(repoRoot, provenance.consumer.lockfile), "utf8");
  const entries = lockEntries(lock, krate.name);
  if (entries.length !== 1) errors.push(`${provenance.consumer.lockfile}: ${entries.length} ${krate.name} entries, not 1`);
  for (const entry of entries) {
    if (!entry.includes(`\nversion = "${krate.version}"\n`)) errors.push(`${provenance.consumer.lockfile}: ${krate.name} is not ${krate.version}`);
    if (entry.includes("\nsource = ")) errors.push(`${provenance.consumer.lockfile}: ${krate.name} resolves to a registry, not the vendored copy`);
  }
  for (const [name, version] of Object.entries(provenance.consumer.reviewed_against ?? {})) {
    const found = lockEntries(lock, name);
    if (found.length !== 1 || !found[0].includes(`\nversion = "${version}"\n`)) {
      errors.push(`${provenance.consumer.lockfile}: ${name} is not the reviewed ${version}`);
    }
  }
  if (lockEntries(readFileSync(join(repoRoot, "Cargo.lock"), "utf8"), krate.name).length) {
    errors.push(`Cargo.lock: ${krate.name} reached the root workspace`);
  }
  return { errors, summary };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const upstream = process.argv.includes("--upstream");
  const { errors, summary } = await check({ upstream });
  for (const line of summary) console.log(line);
  if (errors.length) {
    for (const e of errors) console.error(`error: ${e}`);
    process.exit(1);
  }
  console.log(
    "vendored lopdf matches its crates.io release outside its recorded patches" +
      (upstream ? " (tree id and checksum confirmed against crates.io)" : ""),
  );
}
