#!/usr/bin/env node
// Refuses a pull request whose exact diff cannot be reviewed as text. A step of
// the required "Alibaba OCR Delegation" job (.github/workflows/review-gates.yml)
// runs it from the base checkout, with the exact head present as Git data only:
// nothing here is read from or run for the candidate, and it needs no secret.
// Until 2026-11-23 the Jev adapter made these refusals
// (docs/governance/2026-11-23-jev-retirement.md, which also records what still
// counts as text).
//
// Refused: an empty diff; a path that is not valid UTF-8, or listed twice; a
// submodule link; a file with a NUL byte anywhere, or that Git calls binary; a
// changed file with no text hunk (a mode-only change, an empty file); a diff
// line that does not fit, with its file and hunk header, in 10,000 characters;
// what `git diff --check` refuses (trailing whitespace, CRLF, conflict
// markers); a base that is not the merge base; and any Git failure. A rename is
// read as a whole deletion and a whole addition, so its content has hunks on
// both sides.
//
// The hunks are read with no attributes at all. `git diff --check` uses the
// attributes of the checkout this runs in, which must be the base: fixtures
// kept byte for byte need their base's whitespace rule.
//
// Usage: node check-review-range.mjs <base sha> <head sha> <base checkout>
// Dependency-free; needs git 2.41 or later on PATH. Exits 0 only when every
// check ran and passed.
import { execFileSync } from "node:child_process";

const MAX_SLICE_CHARS = 10_000;
const MAX_OUTPUT_BYTES = 32 * 1024 * 1024;
const MAX_MESSAGE_CHARS = 4_000;
const EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
const NO_OBJECT = "0".repeat(40);
const SUBMODULE = "160000";
const SHA = /^[0-9a-f]{40}$/;
const RAW = /^:([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) ([AMDT])$/;
const [base, head, repository, ...extra] = process.argv.slice(2);

// No GIT_* variable and no system or user configuration reaches Git.
const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^GIT_/i.test(name)));
Object.assign(env, { GIT_ATTR_NOSYSTEM: "1", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "" });

/** Git's output as bytes. A non-zero exit, a signal, a missing git and an over-long output all throw. */
function git(...args) {
  return execFileSync("git", ["--literal-pathspecs", "--no-replace-objects", "-c", "core.attributesFile=", "-C", repository, ...args], {
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: MAX_OUTPUT_BYTES,
    env,
  });
}

/** A diff of the range that no attribute and no rename detection shapes. */
function diff(...args) {
  return git(`--attr-source=${EMPTY_TREE}`, "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames",
    "--ignore-submodules=none", "--no-abbrev", ...args);
}

/** UTF-8 text, keeping a leading byte order mark: two different byte strings never give the same text. */
function exactText(bytes, what) {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new Error(`${what} is not valid UTF-8: ${JSON.stringify(bytes.toString("latin1"))}`);
  }
}

/** The changed files of a raw, NUL-separated listing, each with its own record's bytes. */
function entries(raw) {
  const fields = [];
  for (let start = 0; start < raw.length;) {
    const end = raw.indexOf(0, start);
    if (end < 0) throw new Error("the file list does not end where it should");
    fields.push(raw.subarray(start, end));
    start = end + 1;
  }
  if (fields.length % 2 !== 0) throw new Error("the file list is not pairs of record and path");
  const list = [];
  for (let i = 0; i < fields.length; i += 2) {
    const match = RAW.exec(fields[i].toString("latin1"));
    if (!match) throw new Error(`a file list record is not understood: ${JSON.stringify(fields[i].toString("latin1"))}`);
    const [, oldMode, newMode, oldId, newId] = match;
    list.push({ record: Buffer.concat([fields[i], Buffer.from([0]), fields[i + 1], Buffer.from([0])]), path: exactText(fields[i + 1], "a path"), modes: [oldMode, newMode], ids: [oldId, newId] });
  }
  return list;
}

/** Throws unless every section of the patch has a hunk, and every hunk line fits with its headers. */
function checkHunks(name, patch) {
  // Every content line starts with a space, "+", "-" or a backslash, so a line that
  // opens with "diff --git " or "@@ " is a header, never a file's own text.
  const noHunk = `changed file has no text hunk (mode-only or empty): ${name}`;
  let header = 0;
  let prefix = 0; // 0 until this section's first hunk
  let sections = 0;
  for (const line of patch.split("\n")) {
    if (line.startsWith("diff --git ")) {
      if (sections > 0 && prefix === 0) throw new Error(noHunk);
      sections += 1;
      header = line.length + 1;
      prefix = 0;
    } else if (line.startsWith("@@ ")) {
      prefix = header + line.length + 1;
    } else if (prefix === 0) {
      header += line.length + 1;
    } else if (prefix + line.length + 1 > MAX_SLICE_CHARS) {
      throw new Error(`a diff line does not fit in ${MAX_SLICE_CHARS} characters with its headers: ${name}`);
    }
  }
  if (sections === 0 || prefix === 0) throw new Error(noHunk);
}

function checkFile({ record, path, modes, ids }) {
  const name = JSON.stringify(path);
  if (modes.includes(SUBMODULE)) throw new Error(`submodule link cannot be reviewed: ${name}`);
  for (const id of ids) {
    if (id !== NO_OBJECT && git("cat-file", "blob", id).includes(0)) throw new Error(`binary file cannot be reviewed: ${name}`);
  }
  // Naming the path must select this very record: the same modes, object ids and path bytes.
  if (!diff("--raw", "-z", base, head, "--", path).equals(record)) throw new Error(`literal path selection mismatch: ${name}`);
  if (diff("--numstat", base, head, "--", path).toString("utf8").split("\n").some((line) => line.startsWith("-\t-\t"))) {
    throw new Error(`binary file cannot be reviewed: ${name}`);
  }
  checkHunks(name, diff("--unified=3", base, head, "--", path).toString("utf8"));
}

function check() {
  if (extra.length > 0 || !SHA.test(base ?? "") || !SHA.test(head ?? "") || !repository) {
    throw new Error("usage: check-review-range.mjs <full base sha> <full head sha> <base checkout>");
  }
  if (git("rev-parse", "HEAD").toString("latin1").trim() !== base) throw new Error("the checkout is not the base");
  if (git("status", "--porcelain").length !== 0) throw new Error("the base checkout is not clean");
  git("cat-file", "-e", `${head}^{commit}`);
  if (git("merge-base", base, head).toString("latin1").trim() !== base) throw new Error("the base is not the merge base of the range");
  const files = entries(diff("--raw", "-z", base, head));
  if (files.length === 0) throw new Error("the exact diff contains no files");
  if (new Set(files.map((file) => file.path)).size !== files.length) throw new Error("the exact diff lists a path twice");
  for (const file of files) checkFile(file);
  // Rename detection stays on here, as it was: an unchanged line of a moved file is not a new line.
  git("diff", "--no-ext-diff", "--no-textconv", "--check", base, head);
  return files.length;
}

/**
 * Text from the diff as plain ASCII, bounded, with every later line marked, so
 * no name or line of the candidate reads as a workflow command or hides text.
 */
function safe(text) {
  const plain = text.replace(/[^\x20-\x7e\n]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`).replaceAll("##[", "# #[");
  const cut = plain.length > MAX_MESSAGE_CHARS ? `${plain.slice(0, MAX_MESSAGE_CHARS)} [cut]` : plain;
  return cut.trimEnd().replaceAll("\n", "\n| ");
}

try {
  console.log(`review range: ${check()} changed files, all reviewable as text`);
} catch (error) {
  const detail = error?.stdout?.length ? `\n${error.stdout.toString("utf8")}` : "";
  console.error(safe(`review range refused: ${error instanceof Error ? error.message : error}${detail}`));
  process.exitCode = 1;
}
