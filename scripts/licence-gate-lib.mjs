// Shared pieces of the WP1-01 licence gates (check-npm-licenses.mjs,
// check-agpl-markers.mjs, check-donor-provenance.mjs): the policy files,
// the repository file list, SPDX expression evaluation and the restricted
// licence families. See docs/orcel/notices/licence-policy.json.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

export const POLICY_PATH = "docs/orcel/notices/licence-policy.json";
export const PROVENANCE_PATH = "docs/orcel/notices/donor-provenance.json";

const SKIP_DIRS = new Set([".git", "node_modules", "target", "dist", ".next", ".venv", "__pycache__"]);

export function readJson(root, path) {
  return JSON.parse(readFileSync(join(root, path), "utf8"));
}

export function readPolicy(root) {
  return readJson(root, POLICY_PATH);
}

/** Paths listed one per line; blank lines and '#' comments are ignored. */
export function readList(root, path) {
  return readFileSync(join(root, path), "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
}

function walk(root, dir, out) {
  for (const entry of readdirSync(join(root, dir), { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walk(root, dir ? `${dir}/${entry.name}` : entry.name, out);
    } else if (entry.isFile()) {
      out.push(dir ? `${dir}/${entry.name}` : entry.name);
    }
  }
}

/**
 * Every file of the repository at `root` (tracked plus untracked files that
 * are not ignored, when `root` is a git checkout; otherwise a directory walk
 * that skips build and dependency directories), repository-relative with
 * forward slashes, sorted.
 */
export function listFiles(root) {
  let files;
  try {
    const top = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd: root,
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString()
      .trim();
    if (relative(top, root) !== "") throw new Error("not the repository root");
    files = execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], {
      cwd: root,
      stdio: ["ignore", "pipe", "ignore"],
      maxBuffer: 256 * 1024 * 1024,
    })
      .toString()
      .split("\0")
      .filter(Boolean)
      .filter((path) => existsSync(join(root, path)));
  } catch {
    files = [];
    walk(root, "", files);
  }
  return [...new Set(files.map((path) => path.split(sep).join("/")))].sort();
}

export function underAny(path, prefixes) {
  return prefixes.some((prefix) => path.startsWith(prefix));
}

export const MAX_TEXT_BYTES = 4 * 1024 * 1024;
const ARCHIVE = /\.(jar|war|whl|egg|tgz|tar|gz|bz2|xz|zst|zip|7z|rar|nupkg|crate|gem|deb|rpm|apk|aar)$/i;

/**
 * Reads a file for scanning. Returns {text} for text (UTF-8, or UTF-16 with a
 * byte-order mark), or {unreadable} naming why the scan cannot read it: an
 * archive, an oversized file, or binary content. The gates never skip an
 * unreadable file silently; they require provenance or an exception for it.
 */
export function readScan(root, path) {
  if (ARCHIVE.test(path)) return { unreadable: "archive" };
  const full = join(root, path);
  if (statSync(full).size > MAX_TEXT_BYTES) return { unreadable: "larger than 4 MiB" };
  const bytes = readFileSync(full);
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return { text: bytes.subarray(2).toString("utf16le") };
  if (bytes[0] === 0xfe && bytes[1] === 0xff) {
    const swapped = Buffer.from(bytes.subarray(2));
    swapped.swap16();
    return { text: swapped.toString("utf16le") };
  }
  if (bytes.includes(0)) return { unreadable: "binary" };
  const text = bytes.toString("utf8");
  return { text: text.charCodeAt(0) === 0xfeff ? text.slice(1) : text };
}

/** The file's text, or null when readScan cannot read it. */
export function readText(root, path) {
  return readScan(root, path).text ?? null;
}

/** SHA-256 of the file with CRLF folded to LF, so a pin holds on every OS checkout. */
export function contentSha256(root, path) {
  const text = readFileSync(join(root, path)).toString("latin1").replace(/\r\n/g, "\n");
  return createHash("sha256").update(Buffer.from(text, "latin1")).digest("hex");
}

/**
 * A pinned allowlist: one "<sha256>  <path>" per line (sha256sum format,
 * LF-normalized content); blank lines and '#' comments are ignored.
 */
export function readPinnedList(root, path) {
  return readList(root, path).map((line) => {
    const match = /^([0-9a-f]{64})\s+(\S+)$/.exec(line);
    return match ? { sha256: match[1], path: match[2] } : { sha256: null, path: line };
  });
}

// Text a donor's licence file or notice must contain for its declared
// licence, so a manifest cannot name one licence while the copied notice
// carries another.
const LICENCE_TEXT = {
  MIT: /Permission is hereby granted, free of charge/i,
  "Apache-2.0": /Apache License,?\s+Version 2\.0/i,
  "BSD-2-Clause": /Redistribution and use in source and binary forms/i,
  "BSD-3-Clause": /Redistribution and use in source and binary forms/i,
  ISC: /Permission to use, copy, modify, and\/or distribute this software/i,
  "AGPL-3.0": /GNU Affero General Public License/i,
  "AGPL-3.0-only": /GNU Affero General Public License/i,
  "AGPL-3.0-or-later": /GNU Affero General Public License/i,
  "FSL-1.1-MIT": /Functional Source License, Version 1\.1/i,
};

/** Null when `text` carries the licence text of `licence`, else why not. */
export function licenceTextProblem(licence, text) {
  const pattern = LICENCE_TEXT[licence];
  if (!pattern) return `no licence-text check is defined for ${licence}`;
  return pattern.test(text) ? null : `does not contain the ${licence} licence text`;
}

/** A path segment that marks vendored or copied upstream code. */
export const DONOR_SEGMENT = /(^|\/)(upstream|vendor|vendored|third_party)\//;

// ---------------------------------------------------------------- SPDX

function tokenize(expression) {
  return expression
    .replace(/\(/g, " ( ")
    .replace(/\)/g, " ) ")
    .replace(/\//g, " OR ")
    .trim()
    .split(/\s+/)
    .filter(Boolean);
}

/**
 * Parses an SPDX licence expression into a tree of
 * {or: [...]}, {and: [...]}, {id, exception}. Throws on malformed input.
 */
export function parseSpdx(expression) {
  if (typeof expression !== "string" || !expression.trim()) throw new Error("empty licence expression");
  const tokens = tokenize(expression);
  let index = 0;
  const peek = () => tokens[index];
  const take = () => tokens[index++];
  const isOperator = (token) => ["AND", "OR", "WITH", "(", ")"].includes(token?.toUpperCase?.() ?? token);
  function primary() {
    const token = take();
    if (token === undefined) throw new Error(`incomplete licence expression: ${expression}`);
    if (token === "(") {
      const inner = or();
      if (take() !== ")") throw new Error(`unbalanced licence expression: ${expression}`);
      return inner;
    }
    if (isOperator(token)) throw new Error(`unexpected ${token} in licence expression: ${expression}`);
    let node = { id: token };
    if (peek()?.toUpperCase() === "WITH") {
      take();
      const exception = take();
      if (exception === undefined || isOperator(exception)) throw new Error(`bad WITH in: ${expression}`);
      node = { id: token, exception };
    }
    return node;
  }
  function and() {
    const items = [primary()];
    while (peek()?.toUpperCase() === "AND") {
      take();
      items.push(primary());
    }
    return items.length === 1 ? items[0] : { and: items };
  }
  function or() {
    const items = [and()];
    while (peek()?.toUpperCase() === "OR") {
      take();
      items.push(and());
    }
    return items.length === 1 ? items[0] : { or: items };
  }
  const tree = or();
  if (index !== tokens.length) throw new Error(`trailing tokens in licence expression: ${expression}`);
  return tree;
}

/** True when the expression is satisfiable from `allowed` (a Set of ids). */
export function spdxAllowed(expression, allowed) {
  let tree;
  try {
    tree = parseSpdx(expression);
  } catch {
    return false;
  }
  const evaluate = (node) => {
    if (node.or) return node.or.some(evaluate);
    if (node.and) return node.and.every(evaluate);
    if (node.exception) return allowed.has(`${node.id} WITH ${node.exception}`);
    return allowed.has(node.id);
  };
  return evaluate(tree);
}

export function spdxIds(expression) {
  try {
    const ids = [];
    const visit = (node) => {
      if (node.or) node.or.forEach(visit);
      else if (node.and) node.and.forEach(visit);
      else ids.push(node.id);
    };
    visit(parseSpdx(expression));
    return ids;
  } catch {
    return [];
  }
}

// ------------------------------------------------- restricted families

/** The licence family of one SPDX id, or null when it is not restricted. */
export function familyOfId(id) {
  const upper = id.toUpperCase();
  if (upper.startsWith("AGPL")) return "AGPL";
  if (upper.startsWith("LGPL")) return "LGPL";
  if (upper.startsWith("GPL")) return "GPL";
  if (upper.startsWith("MPL")) return "MPL";
  if (upper.startsWith("SSPL")) return "SSPL";
  if (upper.startsWith("BUSL")) return "BUSL";
  if (upper.startsWith("FSL")) return "FSL";
  if (upper.startsWith("LICENSEREF") || upper.startsWith("COMMERCIAL") || upper.startsWith("PROPRIETARY")) {
    return "COMMERCIAL";
  }
  return null;
}

/** Restricted families named by a licence expression ("OTHER" if it names only unknown ids). */
export function familiesOfExpression(expression, allowed) {
  if (spdxAllowed(expression, allowed)) return [];
  const families = new Set(spdxIds(expression).map(familyOfId).filter(Boolean));
  return families.size ? [...families].sort() : ["OTHER"];
}

// Text markers of restricted licences. "SPDX-License-Identifier:" lines are
// judged by their expression instead (see markerFamilies).
const TEXT_MARKERS = [
  ["AGPL", /GNU\s+AFFERO|Affero\s+General\s+Public|\bAGPL/i],
  ["LGPL", /GNU\s+(?:LESSER|LIBRARY)\s+GENERAL\s+PUBLIC|\bLGPL/i],
  ["GPL", /GNU\s+GENERAL\s+PUBLIC\s+LICEN[CS]E|\bGPL(?:v?\d|-\d|\b)/i],
  ["MPL", /Mozilla\s+Public\s+License|\bMPL-?\d/i],
  ["SSPL", /Server\s+Side\s+Public\s+License|\bSSPL\b/i],
  ["BUSL", /Business\s+Source\s+License|\bBUSL\b/i],
  ["FSL", /Functional\s+Source\s+License|\bFSL-\d/i],
];

export const FAMILIES = ["AGPL", "LGPL", "GPL", "MPL", "SSPL", "BUSL", "FSL", "COMMERCIAL", "OTHER"];

/** Restricted licence families a line of text names. */
export function markerFamilies(line, allowed) {
  const found = new Set();
  const spdx = /SPDX-License-Identifier:\s*(.*)$/i.exec(line);
  if (spdx) {
    // The expression runs while the characters are SPDX ones; a comment
    // close, quote or escape (a header inside a string literal) ends it.
    const expression = /^[A-Za-z0-9.+\-()\s]*/.exec(spdx[1])[0].trim();
    if (expression) for (const family of familiesOfExpression(expression, allowed)) found.add(family);
  }
  for (const [family, pattern] of TEXT_MARKERS) {
    if (pattern.test(line)) found.add(family);
  }
  return [...found].sort();
}
