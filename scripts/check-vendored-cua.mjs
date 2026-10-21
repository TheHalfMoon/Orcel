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
// does a listed file that no longer differs from upstream. Files P-05 removes
// go back in as their recorded upstream blobs. A file P-05 adds must decode to
// the upstream blob it re-encodes.
//
// The upstream tree ids come from the provenance file, so the script also
// requires each one to equal the object of the same donor path in the
// transplant matrix. With --upstream it also asks the GitHub API for the
// pinned commit's tree and compares each crate's id with what trycua/cua
// actually has, which needs no file in this repository to be trusted. A token
// in GH_TOKEN or GITHUB_TOKEN raises the rate limit.
//
// XP-08: the native conformance fixtures under tests/native-fixtures/ are
// upstream's libs/cua-driver/tests/fixtures tree (the provenance file's
// `fixtures` entries) and get the same proof. Their Orcel-owned files are
// listed by path and left out of the rebuilt tree; files Orcel does not copy
// go back in as their upstream blobs and must be named in the tree's notes.
//
// Every vendored file must also be reviewable by the exact-diff gate: text,
// with no line longer than MAX_REVIEWABLE_LINE.
//
// #355: each patched file also records the blob it has now
// (`patched_blob_sha`), so a later edit to an already-patched file fails until
// its provenance record (and PATCHES.md entry) is updated with it. Without
// --upstream the matrix and registry in the working tree are not trusted on
// their own either: when origin/main is available (`--anchor <ref>` names
// another ref), each tree id must also equal that ref's transplant matrix row
// and donor registry pin, so matching edits to the provenance and the matrix
// fail locally. A re-pin is checked with --upstream, against GitHub.
//
// Usage: node scripts/check-vendored-cua.mjs [--upstream] [--anchor <ref>]
// Dependency-free; needs git on PATH. Exits 1 on any mismatch.
import { Buffer, isUtf8 } from "node:buffer";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const provenancePath = join(repoRoot, "docs/orcel/cua_driver_provenance.json");
const matrixRelative = "docs/orcel/implementation-readiness/transplant_matrix.json";
const registryRelative = "docs/orcel/implementation-readiness/donor_registry.json";
const matrixPath = join(repoRoot, matrixRelative);
const registryPath = join(repoRoot, registryRelative);
const vendorRoot = "apps/orcel-native-host/third_party/cua-driver";
const SHA = /^[0-9a-f]{40}$/;
// Jev's exact-diff review packs each slice into 10,000 characters, including
// the file and hunk headers (.github/scripts/jev-exact-diff.mjs); leave room
// for those.
export const MAX_REVIEWABLE_LINE = 9000;

/** The bytes of a `&[0x.., ...]` Rust byte-array literal, or null. */
export function decodeRustByteArray(text) {
  const body = text.replace(/\/\/[^\n]*/g, "").trim();
  const match = body.match(/^&\[([\s\S]*)\]$/);
  if (!match) return null;
  const tokens = match[1].split(",").map((t) => t.trim()).filter(Boolean);
  if (!tokens.every((t) => /^0x[0-9a-f]{2}$/.test(t))) return null;
  return Buffer.from(tokens.map((t) => Number.parseInt(t.slice(2), 16)));
}

function gitHashObject(bytes) {
  return execFileSync("git", ["hash-object", "--stdin"], { cwd: repoRoot, input: bytes }).toString().trim();
}

/** Tree ids of `paths` at `commit` in trycua/cua, read from the GitHub API. */
async function upstreamTreeIds(commit, paths) {
  const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
  const get = async (url) => {
    const response = await fetch(`https://api.github.com/repos/trycua/cua/${url}`, {
      headers: { accept: "application/vnd.github+json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    });
    if (!response.ok) throw new Error(`GitHub API ${url}: HTTP ${response.status}`);
    return response.json();
  };
  const cache = new Map();
  const children = async (tree) => {
    if (!cache.has(tree)) cache.set(tree, (await get(`git/trees/${tree}`)).tree);
    return cache.get(tree);
  };
  const root = (await get(`git/commits/${commit}`)).tree.sha;
  const out = new Map();
  for (const path of paths) {
    let sha = root;
    for (const part of path.split("/")) {
      const entry = (await children(sha)).find((e) => e.path === part && e.type === "tree");
      sha = entry?.sha;
      if (!sha) break;
    }
    out.set(path, sha ?? "(absent)");
  }
  return out;
}
// P-02: the cua-driver binary crate, its SDK/daemon and the telemetry client
// it uses (cua-telemetry over ureq, PostHog ingest) are not vendored, and no
// HTTP client may enter the host's graph. Cargo.lock lists every package for
// every target and feature, so absence there is absence from any build.
export const forbiddenPackages = [
  "cua-driver",
  "cua-driver-sdk",
  "cua-daemon",
  "cua-telemetry",
  "posthog-rs",
  "ureq",
  "reqwest",
  "hyper",
];

/** Package names in a Cargo.lock. */
export function lockPackages(text) {
  return [...text.matchAll(/^name = "([^"]+)"$/gm)].map((m) => m[1]);
}

/** `path` as committed at `ref`, parsed as JSON, or null when the ref is absent. */
function anchoredJson(ref, path) {
  try {
    git(["rev-parse", "--verify", "--quiet", `${ref}^{commit}`]);
  } catch {
    return null;
  }
  return JSON.parse(git(["show", `${ref}:${path}`]));
}

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

export async function check({ upstream = false, anchor = "origin/main" } = {}) {
  const provenance = JSON.parse(readFileSync(provenancePath, "utf8"));
  const patches = readFileSync(join(repoRoot, vendorRoot, "PATCHES.md"), "utf8");
  const matrix = new Map(JSON.parse(readFileSync(matrixPath, "utf8")).rows.map((row) => [row.id, row]));
  const registry = JSON.parse(readFileSync(registryPath, "utf8")).donors.find((d) => d.id === provenance.donor?.id);
  const upstreamTrees = upstream
    ? await upstreamTreeIds(
        provenance.donor.commit,
        [...(provenance.crates ?? []), ...(provenance.fixtures ?? [])].map((c) => c.source),
      )
    : null;
  const errors = [];
  const summaryHead = [];
  // The local anchor: the matrix and registry as the reviewed branch has them.
  let anchorMatrix = null;
  if (!upstream) {
    const anchoredRows = anchoredJson(anchor, matrixRelative);
    const anchoredRegistry = anchoredJson(anchor, registryRelative);
    if (anchoredRows && anchoredRegistry) {
      anchorMatrix = new Map(anchoredRows.rows.map((row) => [row.id, row]));
      const pinned = anchoredRegistry.donors.find((d) => d.id === provenance.donor?.id);
      if (pinned?.commit !== provenance.donor?.commit) {
        errors.push(`${anchor}'s donor_registry.json pins cua at ${pinned?.commit}, provenance at ${provenance.donor?.commit}`);
      }
      summaryHead.push(`anchor: matrix and registry also checked against ${anchor}`);
    } else {
      summaryHead.push(`anchor: ${anchor} is not available; the working-tree matrix is not cross-checked (run with --upstream)`);
    }
  }
  const anchored = (name, id, record) => {
    if (!anchorMatrix) return;
    const row = anchorMatrix.get(id);
    if (!row || row.object !== record.tree_sha || row.path !== record.source || row.dest !== record.destination) {
      errors.push(`${name}: provenance does not match ${anchor}'s matrix row ${id}`);
    }
  };
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

  const summary = summaryHead;
  for (const crate of provenance.crates ?? []) {
    const prefix = `${crate.destination}/`;
    const files = new Map();
    for (const [path, entry] of all) {
      if (path.startsWith(prefix)) {
        files.set(path.slice(prefix.length), { ...entry });
        claimed.add(path);
      }
    }
    // P-05: files upstream has but Orcel does not vendor go back into the
    // rebuilt tree as their upstream blobs; their absence is the patch.
    const removed = new Map((crate.removed_files ?? []).map((file) => [file.path, file]));
    for (const file of removed.values()) {
      const full = `${prefix}${file.path}`;
      if (files.has(file.path)) errors.push(`${full}: listed as removed but present`);
      if (!SHA.test(file.upstream_blob_sha ?? "")) errors.push(`${full}: removed file needs its upstream blob id`);
      if (!patches.includes(`${crate.name}/${file.path}`)) {
        errors.push(`${full}: removed but not named in PATCHES.md`);
      }
      files.set(file.path, { mode: file.upstream_mode ?? "100644", sha: file.upstream_blob_sha });
    }
    // An added file must be an exact re-encoding of a removed upstream file.
    for (const added of crate.added_files ?? []) {
      const full = `${prefix}${added.path}`;
      const source = removed.get(added.encodes);
      if (!files.has(added.path) || removed.has(added.path)) {
        errors.push(`${full}: listed as added but absent`);
        continue;
      }
      files.delete(added.path);
      if (!source) {
        errors.push(`${full}: encodes ${added.encodes}, which is not a removed upstream file`);
        continue;
      }
      if (added.format !== "rust-byte-array") {
        errors.push(`${full}: unknown encoding ${added.format}`);
        continue;
      }
      const bytes = decodeRustByteArray(readFileSync(join(repoRoot, full), "utf8"));
      const blob = bytes && gitHashObject(bytes);
      if (blob !== source.upstream_blob_sha) {
        errors.push(`${full}: decodes to blob ${blob ?? "(unparsable)"}, not upstream ${source.upstream_blob_sha}`);
      }
      if (!patches.includes(`${crate.name}/${added.path}`)) {
        errors.push(`${full}: added but not named in PATCHES.md`);
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
      if (!SHA.test(patched.patched_blob_sha ?? "")) {
        errors.push(`${full}: patched file needs its patched_blob_sha`);
      } else if (entry.sha !== patched.patched_blob_sha) {
        errors.push(
          `${full}: blob ${entry.sha} is not the recorded patched blob ${patched.patched_blob_sha}; ` +
            "record the change in PATCHES.md and update patched_blob_sha",
        );
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
    // The recorded upstream id is only as good as its source: it must equal
    // the reviewed transplant-matrix row for the same donor path.
    const row = matrix.get(crate.matrix_id);
    if (!row) errors.push(`${crate.name}: matrix row ${crate.matrix_id} is missing`);
    else if (row.object !== crate.tree_sha || row.path !== crate.source || row.dest !== crate.destination) {
      errors.push(`${crate.name}: provenance does not match matrix row ${crate.matrix_id}`);
    }
    anchored(crate.name, crate.matrix_id, crate);
    if (upstreamTrees && upstreamTrees.get(crate.source) !== crate.tree_sha) {
      errors.push(
        `${crate.name}: trycua/cua@${provenance.donor.commit} has ${crate.source} as ${upstreamTrees.get(crate.source)}, not ${crate.tree_sha}`,
      );
    }
    summary.push(
      `${crate.name}: ${files.size} files, ${(crate.patched_files ?? []).length} patched, ` +
        `${removed.size} removed, ${(crate.added_files ?? []).length} added, tree ${tree}`,
    );
  }
  // XP-08: copied fixture trees. Orcel-owned files (the notes, the staging
  // script, the license copy) stay out of the rebuilt tree.
  const fixtureFiles = [];
  for (const tree of provenance.fixtures ?? []) {
    const prefix = `${tree.destination}/`;
    const entries = indexEntries(prefix);
    const own = new Set(tree.orcel_files ?? []);
    const files = new Map();
    for (const [path, entry] of entries) {
      fixtureFiles.push(path);
      const relative = path.slice(prefix.length);
      if (!own.has(relative)) files.set(relative, { ...entry });
    }
    for (const relative of own) {
      if (!entries.has(`${prefix}${relative}`)) errors.push(`${prefix}${relative}: Orcel-owned file is missing`);
    }
    if (!own.has(tree.notes)) errors.push(`${tree.name}: notes ${tree.notes} must be an Orcel-owned file`);
    const notes = entries.has(`${prefix}${tree.notes}`) ? readFileSync(join(repoRoot, prefix, tree.notes), "utf8") : "";
    for (const file of tree.removed_files ?? []) {
      const full = `${prefix}${file.path}`;
      if (files.has(file.path)) errors.push(`${full}: listed as removed but present`);
      if (!SHA.test(file.upstream_blob_sha ?? "")) errors.push(`${full}: removed file needs its upstream blob id`);
      if (!notes.includes(file.path)) errors.push(`${full}: removed but not named in ${tree.notes}`);
      files.set(file.path, { mode: file.upstream_mode ?? "100644", sha: file.upstream_blob_sha });
    }
    // The MIT notice travels with the copy: the license is upstream's blob.
    const license = entries.get(`${prefix}${tree.license}`);
    if (!own.has(tree.license) || license?.sha !== provenance.donor?.license_blob_sha) {
      errors.push(`${tree.name}: ${tree.license} is not the donor license blob ${provenance.donor?.license_blob_sha}`);
    }
    const rebuilt = files.size ? mktree(files) : "(empty)";
    if (rebuilt !== tree.tree_sha) {
      errors.push(`${tree.name}: rebuilt tree ${rebuilt} is not upstream ${tree.tree_sha}`);
    }
    const row = matrix.get(tree.matrix_id);
    if (!row) errors.push(`${tree.name}: matrix row ${tree.matrix_id} is missing`);
    else if (row.object !== tree.tree_sha || row.path !== tree.source || row.dest !== tree.destination) {
      errors.push(`${tree.name}: provenance does not match matrix row ${tree.matrix_id}`);
    }
    anchored(tree.name, tree.matrix_id, tree);
    if (upstreamTrees && upstreamTrees.get(tree.source) !== tree.tree_sha) {
      errors.push(
        `${tree.name}: trycua/cua@${provenance.donor.commit} has ${tree.source} as ${upstreamTrees.get(tree.source)}, not ${tree.tree_sha}`,
      );
    }
    summary.push(
      `${tree.name}: ${files.size - (tree.removed_files ?? []).length} upstream files, ` +
        `${(tree.removed_files ?? []).length} removed, ${own.size} Orcel-owned, tree ${rebuilt}`,
    );
  }
  if (registry?.commit !== provenance.donor?.commit) {
    errors.push(`donor_registry.json pins cua at ${registry?.commit}, provenance at ${provenance.donor?.commit}`);
  }
  // Every vendored file must pass the exact-diff review gate as text: no
  // binary content and no line longer than its per-slice budget allows.
  for (const path of [...all.keys(), ...fixtureFiles]) {
    const bytes = readFileSync(join(repoRoot, path));
    if (bytes.subarray(0, 8192).includes(0) || !isUtf8(bytes)) {
      errors.push(`${path}: binary content cannot pass exact-diff review`);
      continue;
    }
    const longest = Math.max(...bytes.toString("utf8").split("\n").map((line) => line.length));
    if (longest > MAX_REVIEWABLE_LINE) {
      errors.push(`${path}: a ${longest}-character line exceeds the ${MAX_REVIEWABLE_LINE}-character review limit`);
    }
  }
  for (const path of all.keys()) {
    if (!claimed.has(path)) errors.push(`${path}: not part of any recorded upstream tree`);
  }

  const hostLock = lockPackages(readFileSync(join(repoRoot, "apps/orcel-native-host/Cargo.lock"), "utf8"));
  for (const name of forbiddenPackages) {
    if (hostLock.includes(name)) errors.push(`apps/orcel-native-host/Cargo.lock: ${name} is in the graph`);
  }
  // orceld's lockfile must not reach any crate of the separate workspace.
  const rootLock = new Set(lockPackages(readFileSync(join(repoRoot, "Cargo.lock"), "utf8")));
  for (const crate of provenance.crates ?? []) {
    if (rootLock.has(crate.name)) errors.push(`Cargo.lock: ${crate.name} reached the root workspace`);
  }
  if (rootLock.has("orcel-native-host")) errors.push("Cargo.lock: orcel-native-host reached the root workspace");
  summary.push(`native-host lock: ${hostLock.length} packages, none forbidden`);
  return { errors, summary };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const upstream = process.argv.includes("--upstream");
  const at = process.argv.indexOf("--anchor");
  const anchor = at > 0 ? process.argv[at + 1] : "origin/main";
  if (!anchor || anchor.startsWith("-")) {
    console.error("error: --anchor needs a git ref");
    process.exit(1);
  }
  const { errors, summary } = await check({ upstream, anchor });
  for (const line of summary) console.log(line);
  if (errors.length) {
    for (const e of errors) console.error(`error: ${e}`);
    process.exit(1);
  }
  console.log(
    `vendored Cua Driver crates and native fixtures match the upstream pin outside their recorded patches` +
      (upstream ? " (tree ids confirmed against trycua/cua on GitHub)" : ""),
  );
}
