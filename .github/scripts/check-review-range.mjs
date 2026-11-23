#!/usr/bin/env node
// Refuses a pull request whose exact diff cannot be reviewed as text. A step of
// the required "Alibaba OCR Delegation" job (.github/workflows/review-gates.yml)
// runs it from the base checkout, with the exact head present as Git data only:
// nothing here is read from or run for the candidate, and it needs no secret.
// Until 2026-11-23 the Jev adapter made these refusals
// (docs/governance/2026-11-23-jev-retirement.md).
//
// Refused: an empty diff; a binary file; a changed file with no text hunk (a
// mode-only change, an empty file); a diff line that does not fit, with its
// file and hunk header, in 10,000 characters; what `git diff --check` refuses
// (trailing whitespace, CRLF, conflict markers); a base that is not the merge
// base; and any Git failure. A rename is read as a whole deletion and a whole
// addition, so its content has hunks on both sides.
//
// Attributes come from the checkout this runs in, which must be the base.
//
// Usage: node check-review-range.mjs <base sha> <head sha> <base checkout>
// Dependency-free; needs git on PATH. Exits 0 only when every check ran and passed.
import { execFileSync } from "node:child_process";

const MAX_SLICE_CHARS = 10_000;
const MAX_PATCH_BYTES = 32 * 1024 * 1024;
const SHA = /^[0-9a-f]{40}$/;
const [base, head, repository, ...extra] = process.argv.slice(2);

function git(...args) {
  // A non-zero exit, a signal, a missing git and an over-long output all throw.
  return execFileSync("git", ["--literal-pathspecs", "--no-replace-objects", "-C", repository, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: MAX_PATCH_BYTES,
    env: { ...process.env, GIT_ATTR_NOSYSTEM: "1" },
  });
}

function diff(...args) {
  return git("-c", "core.attributesFile=", "diff", "--no-ext-diff", "--no-textconv", "--no-color",
    "--no-renames", "--ignore-submodules=none", ...args);
}

/** Throws unless every section of the patch has a hunk, and every hunk line fits with its headers. */
function checkHunks(path, patch) {
  // Every content line starts with a space, "+", "-" or a backslash, so a line that
  // opens with "diff --git " or "@@ " is a header, never a file's own text.
  const noHunk = `changed file has no text hunk (mode-only or empty): ${path}`;
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
      throw new Error(`a diff line does not fit in ${MAX_SLICE_CHARS} characters with its headers: ${path}`);
    }
  }
  if (sections === 0 || prefix === 0) throw new Error(noHunk);
}

function check() {
  if (extra.length > 0 || !SHA.test(base ?? "") || !SHA.test(head ?? "") || !repository) {
    throw new Error("usage: check-review-range.mjs <full base sha> <full head sha> <base checkout>");
  }
  if (git("rev-parse", "HEAD").trim() !== base) throw new Error("the checkout is not the base");
  if (git("status", "--porcelain").trim() !== "") throw new Error("the base checkout is not clean");
  git("cat-file", "-e", `${head}^{commit}`);
  if (git("merge-base", base, head).trim() !== base) throw new Error("the base is not the merge base of the range");
  const names = diff("--name-only", "-z", base, head).split("\0").filter(Boolean);
  if (names.length === 0) throw new Error("the exact diff contains no files");
  for (const path of names) {
    const selected = diff("--name-only", "-z", base, head, "--", path).split("\0").filter(Boolean);
    if (selected.length !== 1 || selected[0] !== path) throw new Error(`literal path selection mismatch: ${path}`);
    if (diff("--numstat", base, head, "--", path).split("\n").some((line) => line.startsWith("-\t-\t"))) {
      throw new Error(`binary file cannot be reviewed: ${path}`);
    }
    checkHunks(path, diff("--unified=3", base, head, "--", path));
  }
  // Rename detection stays on here, as it was: an unchanged line of a moved file is not a new line.
  git("-c", "core.attributesFile=", "diff", "--no-ext-diff", "--no-textconv", "--check", base, head);
  return names.length;
}

try {
  console.log(`review range: ${check()} changed files, all reviewable as text`);
} catch (error) {
  const detail = error?.stdout ? `\n${error.stdout}` : "";
  console.error(`review range refused: ${error instanceof Error ? error.message : error}${detail}`);
  process.exitCode = 1;
}
