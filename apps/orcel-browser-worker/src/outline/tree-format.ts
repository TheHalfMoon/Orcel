// W2-03: text helpers for the accessibility outline: the cleaning of page
// text before it crosses to the host.
//
// Copied from browserbase/stagehand at commit
// 82827a219512f0399cb159720a63f7d271d21480,
// `packages/extension/understudy/a11y/snapshot/treeFormatUtils.ts` (blob
// 4928894ca32684f7cc854578c3ddaee9d6305a1a: `cleanText`, `normaliseSpaces`).
// MIT License, Copyright (c) 2024 Browserbase Inc.; notice in
// docs/orcel/notices/stagehand-MIT.txt; provenance in
// docs/orcel/stagehand_provenance.json. Modifications for Orcel: the text
// outline helpers (`formatTreeLine`, `injectSubtrees`, `indentBlock`,
// `diffCombinedTrees`) are not copied, as the outline crosses as bounded
// nodes; `untrustedText` (new) is the one sanitiser every page string passes
// before it crosses to the host, and it applies the well-formed repair
// Stagehand's `capture.ts` applies to whole outlines (blob
// 6706bef9c7bd654bfd161129ae8be8cb78dffaba, `toWellFormed`).

/**
 * Remove whitespace noise and invisible code points before rendering names.
 */
export function cleanText(input: string): string {
  const PUA_START = 0xe000;
  const PUA_END = 0xf8ff;
  const NBSP = new Set<number>([0x00a0, 0x202f, 0x2007, 0xfeff]);

  let out = "";
  let prevSpace = false;
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (code >= PUA_START && code <= PUA_END) continue;
    if (NBSP.has(code)) {
      if (!prevSpace) {
        out += " ";
        prevSpace = true;
      }
      continue;
    }
    out += input[i];
    prevSpace = input[i] === " ";
  }
  return out.trim();
}

/**
 * Collapse all whitespace runs in a string to a single space without trimming.
 * Exported for pruning routines that need the same normalization.
 */
export function normaliseSpaces(s: string): string {
  let out = "";
  let inWs = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    const isWs = /\s/.test(ch);
    if (isWs) {
      if (!inWs) {
        out += " ";
        inWs = true;
      }
    } else {
      out += ch;
      inWs = false;
    }
  }
  return out;
}

// String.prototype.toWellFormed exists at runtime (Node 20+), but not in the
// ES2022 lib this package compiles against.
type StringWithToWellFormed = string & { toWellFormed(): string };

/// Orcel: lone surrogates, C0/C1 controls, bidirectional overrides and
/// isolates, zero-width and other format characters are removed (or, for
/// whitespace, folded into one space); the rest is cleaned like a name
/// (`cleanText`), and the result is cut on a character boundary to at most
/// `maxBytes` UTF-8 bytes. Page text stays untrusted after this: it is
/// bounded and printable, not true.
export function untrustedText(input: string, maxBytes: number): string {
  const wellFormed = (input as StringWithToWellFormed).toWellFormed();
  const stripped = wellFormed
    .replace(/[\u0000-\u0008\u000e-\u001f\u007f-\u009f]/g, "")
    .replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u2069\u00ad\u061c\u180e\ufff9-\ufffb]/g, "")
    .replace(/[\t\n\v\f\r\u2028\u2029]/g, " ");
  const clean = normaliseSpaces(cleanText(stripped)).trim();
  if (Buffer.byteLength(clean, "utf8") <= maxBytes) return clean;
  let out = "";
  let bytes = 0;
  for (const ch of clean) {
    const size = Buffer.byteLength(ch, "utf8");
    if (bytes + size > maxBytes) break;
    out += ch;
    bytes += size;
  }
  return out;
}
