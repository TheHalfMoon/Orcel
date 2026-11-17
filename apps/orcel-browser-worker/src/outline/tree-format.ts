// W2-03: text helpers for the accessibility outline: an indented text form
// of the tree, the cleaning of page text before it is shown, and the
// line diff of two outlines.
//
// Copied from browserbase/stagehand at commit
// 82827a219512f0399cb159720a63f7d271d21480,
// `packages/extension/understudy/a11y/snapshot/treeFormatUtils.ts` (blob
// 4928894ca32684f7cc854578c3ddaee9d6305a1a: `formatTreeLine`,
// `injectSubtrees`, `indentBlock`, `diffCombinedTrees`, `cleanText`,
// `normaliseSpaces`). MIT License, Copyright (c) 2024 Browserbase Inc.;
// notice in docs/orcel/notices/stagehand-MIT.txt; provenance in
// docs/orcel/stagehand_provenance.json. Modifications for Orcel: the node
// type is the outline's own `OutlineNode`; `formatTreeLine` labels a node
// with its outline id and shows no state but checked/selected;
// `untrustedText` (new) is the one sanitiser every page string passes
// before it crosses to the host, and it applies the well-formed repair
// Stagehand's `capture.ts` applies to whole outlines (blob
// 6706bef9c7bd654bfd161129ae8be8cb78dffaba, `toWellFormed`).

/// The node shape the text form renders (see `outline/a11y-tree.ts`).
export interface FormattableNode {
  id: string;
  role: string;
  name: string;
  checked?: boolean;
  selected?: boolean;
  children: FormattableNode[];
}

/**
 * Render a formatted outline (with encoded ids) for the accessibility tree.
 * Keeps indentation logic shared between modules so unit tests can cover these
 * pure formatting helpers without a full snapshot pipeline.
 */
export function formatTreeLine(node: FormattableNode, level = 0): string {
  const indent = "  ".repeat(level);
  const stateFlags = formatStateFlags(node);
  const label = `[${node.id}] ${node.role}${node.name ? `: ${cleanText(node.name)}` : ""}${stateFlags}`;
  const kids = node.children.map((c) => formatTreeLine(c, level + 1)).join("\n");
  return kids ? `${indent}${label}\n${kids}` : `${indent}${label}`;
}

function formatStateFlags(node: FormattableNode): string {
  let flags = "";
  if (node.selected) flags += " [selected]";
  if (node.checked) flags += " [checked]";
  return flags;
}

/**
 * Inject each child frame outline under the parent's iframe node line.
 * Keys in `idToTree` are the parent's iframe encoded ids.
 */
export function injectSubtrees(rootOutline: string, idToTree: Map<string, string>): string {
  type Frame = { lines: string[]; i: number };
  const out: string[] = [];
  const visited = new Set<string>();
  const stack: Frame[] = [{ lines: rootOutline.split("\n"), i: 0 }];

  while (stack.length) {
    const top = stack[stack.length - 1]!;
    if (top.i >= top.lines.length) {
      stack.pop();
      continue;
    }

    const raw = top.lines[top.i++]!;
    out.push(raw);

    const indent = raw.match(/^(\s*)/)?.[1] ?? "";
    const content = raw.slice(indent.length);

    const m = content.match(/^\[([^\]]+)]/);
    if (!m) continue;

    const encId = m[1]!;
    const childOutline = idToTree.get(encId);
    if (!childOutline || visited.has(encId)) continue;

    visited.add(encId);

    const fullyInjectedChild = injectSubtrees(childOutline, idToTree);
    out.push(indentBlock(fullyInjectedChild.trimEnd(), indent + "  "));
  }

  return out.join("\n");
}

export function indentBlock(block: string, indent: string): string {
  if (!block) return "";
  return block
    .split("\n")
    .map((line) => indent + line)
    .join("\n");
}

/**
 * Return the lines that appear in `nextTree` but not in `prevTree`.
 * Comparison is done line-by-line, ignoring leading whitespace in both trees.
 * The returned block is re-indented so the minimal indent becomes column 0.
 */
export function diffCombinedTrees(prevTree: string, nextTree: string): string {
  const prevSet = new Set(
    (prevTree || "")
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 0)
  );

  const nextLines = (nextTree || "").split("\n");
  const added: string[] = [];
  for (const line of nextLines) {
    const core = line.trim();
    if (!core) continue;
    if (!prevSet.has(core)) added.push(line);
  }

  if (added.length === 0) return "";

  let minIndent = Infinity;
  for (const l of added) {
    if (!l.trim()) continue;
    const m = l.match(/^\s*/);
    const indentLen = m ? m[0]!.length : 0;
    if (indentLen < minIndent) minIndent = indentLen;
  }
  if (!isFinite(minIndent)) minIndent = 0;

  const out = added.map((l) => (l.length >= minIndent ? l.slice(minIndent) : l));
  return out.join("\n");
}

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
