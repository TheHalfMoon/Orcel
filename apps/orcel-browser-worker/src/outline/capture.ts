// W2-03: the bounded accessibility outline of the primary page's main
// document (the `outline` frame): Stagehand's hybrid DOM + accessibility
// snapshot, cut down to what the worker may send.
//
// Adapted from browserbase/stagehand at commit
// 82827a219512f0399cb159720a63f7d271d21480,
// `packages/extension/understudy/a11y/snapshot/capture.ts` (blob
// 6706bef9c7bd654bfd161129ae8be8cb78dffaba: `captureHybridSnapshot`,
// `collectPerFrameMaps`, `mergeFramesIntoSnapshot`) and `a11yTree.ts` (blob
// 2d3a626f9645f29b817a7a30a7cfbc3343da9c5e: `a11yForFrame`). MIT License,
// Copyright (c) 2024 Browserbase Inc.; notice in
// docs/orcel/notices/stagehand-MIT.txt; provenance in
// docs/orcel/stagehand_provenance.json.
//
// Modifications for Orcel: one CDP session on the primary page, wrapped in
// `readOnlyCdp`, which refuses every method but the five read methods the
// outline needs (no `Runtime.*`, no `Input.*`, nothing that runs page
// script or changes the page); the main document only (an iframe is a leaf;
// Stagehand stitches child frames with `injectSubtrees` and per-frame
// sessions); no focus or ignore locators; the result is a tree of bounded
// nodes (`OutlineNode`) rather than Stagehand's text outline plus id maps,
// with names withheld as `withholdNames` says, page text cleaned by
// `untrustedText`, link URLs kept only when absolute http(s), no field value,
// description or checked/selected state, and node, depth and byte ceilings
// (`truncated`). The host stays the authority: it decides whether an outline
// is taken at all (denied by default), keeps the raw names, and marks every
// string untrusted.

import { buildHierarchicalTree, decorateRoles, extractUrlFromAXNode, withholdNames, type A11yNode, type AxNode } from "./a11y-tree.js";
import { buildSessionDomIndex, relativizeXPath, type CdpReader } from "./dom-tree.js";
import { untrustedText } from "./tree-format.js";
import { boundXPath, trimTrailingTextNode } from "./xpath.js";

export const MAX_OUTLINE_NODES = 512;
export const MAX_OUTLINE_DEPTH = 32;
export const MAX_OUTLINE_NAME_BYTES = 512;
export const MAX_OUTLINE_URL_BYTES = 2048;
/// Leaves room under the 64 KiB frame bound for the frame envelope.
export const MAX_OUTLINE_JSON_BYTES = 56 * 1024;
/// The whole capture's budget (under the host's observation bound).
export const OUTLINE_BUDGET_MS = 4_000;
/// The deepest accessibility level asked of the engine, and the most AX
/// nodes read (past either, the outline withholds every name but plain text).
export const MAX_AX_DEPTH = 128;
export const MAX_AX_NODES = 100_000;

/// The only CDP methods an outline may send.
export const OUTLINE_METHODS: ReadonlySet<string> = new Set([
  "DOM.enable",
  "DOM.getDocument",
  "DOM.describeNode",
  "Accessibility.enable",
  "Accessibility.getFullAXTree"
]);

/// One outline node on the wire. `id` is `0-<backend node id>` (main frame
/// ordinal 0, Stagehand's encoding); `xpath` is built from element names and
/// positions only; `name` is cleaned page text, or empty when withheld.
export interface OutlineNode {
  id: string;
  role: string;
  name: string;
  xpath: string;
  url?: string;
  children: OutlineNode[];
}

export interface BoundedOutline {
  nodes: OutlineNode[];
  truncated: boolean;
}

export class OutlineRefused extends Error {}

/// Wrap a CDP session so only the outline's read methods can be sent.
export function readOnlyCdp(session: { send(method: never, params?: never): Promise<unknown> }): CdpReader {
  const send = session.send.bind(session) as (method: string, params?: Record<string, unknown>) => Promise<unknown>;
  return {
    send(method: string, params?: Record<string, unknown>): Promise<unknown> {
      if (!OUTLINE_METHODS.has(method)) return Promise.reject(new OutlineRefused(`CDP method ${method} is not an outline read`));
      return send(method, params);
    }
  };
}

const ID = /^0-\d{1,12}$/;
const ROLE = /^[A-Za-z][A-Za-z0-9 ,-]{0,47}$/;

function safeUrl(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined;
  const text = untrustedText(raw, MAX_OUTLINE_URL_BYTES);
  if (text.length === 0 || /\s/.test(text)) return undefined;
  try {
    const url = new URL(text);
    if (url.protocol !== "http:" && url.protocol !== "https:") return undefined;
    if (url.username !== "" || url.password !== "") return undefined;
    return Buffer.byteLength(url.href, "utf8") <= MAX_OUTLINE_URL_BYTES ? url.href : undefined;
  } catch {
    return undefined;
  }
}

/// Bound a built tree into wire nodes (pure; exported for tests).
export function boundOutline(tree: A11yNode[], xpathMap: Record<string, string>, urlMap: Record<string, string>): BoundedOutline {
  let count = 0;
  // The top-level array's brackets.
  let bytes = 2;
  let truncated = false;
  const visit = (node: A11yNode, depth: number): OutlineNode | null => {
    if (depth > MAX_OUTLINE_DEPTH || count >= MAX_OUTLINE_NODES) {
      truncated = true;
      return null;
    }
    const id = node.encodedId ?? "";
    const role = ROLE.test(node.role) ? node.role : "generic";
    const out: OutlineNode = {
      id: ID.test(id) ? id : "",
      role,
      name: untrustedText(node.name ?? "", MAX_OUTLINE_NAME_BYTES),
      xpath: boundXPath(trimTrailingTextNode(xpathMap[id]) ?? ""),
      children: []
    };
    const url = safeUrl(urlMap[id]);
    if (url !== undefined) out.url = url;
    // One separator per node keeps the sum an upper bound of the tree JSON.
    const size = Buffer.byteLength(JSON.stringify(out), "utf8") + 1;
    if (bytes + size > MAX_OUTLINE_JSON_BYTES) {
      truncated = true;
      return null;
    }
    bytes += size;
    count += 1;
    for (const child of node.children ?? []) {
      if (count >= MAX_OUTLINE_NODES || bytes >= MAX_OUTLINE_JSON_BYTES) {
        truncated = true;
        break;
      }
      const kept = visit(child, depth + 1);
      if (kept) out.children.push(kept);
    }
    return out;
  };
  const nodes: OutlineNode[] = [];
  for (const root of tree) {
    const kept = visit(root, 0);
    if (kept) nodes.push(kept);
    if (truncated) break;
  }
  return { nodes, truncated };
}

/// Take the outline through a read-only CDP session on the primary page.
export async function captureOutline(cdp: CdpReader, budgetMs = OUTLINE_BUDGET_MS): Promise<BoundedOutline> {
  const deadline = Date.now() + budgetMs;
  const index = await buildSessionDomIndex(cdp, true, deadline);
  const docRoot = index.rootBackend;
  const baseAbs = index.absByBe.get(docRoot) ?? "/";
  const encode = (be: number) => `0-${be}`;
  const tagNameMap: Record<string, string> = {};
  const xpathMap: Record<string, string> = {};
  const scrollableMap: Record<string, boolean> = {};
  for (const [be, nodeAbs] of index.absByBe.entries()) {
    if (index.docRootOf.get(be) !== docRoot) continue;
    const key = encode(be);
    xpathMap[key] = relativizeXPath(baseAbs, nodeAbs);
    const tag = index.tagByBe.get(be);
    if (tag) tagNameMap[key] = tag;
    if (index.scrollByBe.get(be)) scrollableMap[key] = true;
  }
  // A node of another document (an iframe's) or one past the DOM bound is
  // not in the outline.
  const isIgnoredBackendNode = (be: number) => index.docRootOf.get(be) !== docRoot;

  await cdp.send("Accessibility.enable").catch(() => {});
  if (Date.now() > deadline) throw new Error("the outline timed out");
  // The engine stops at MAX_AX_DEPTH; a cut shows as children the list
  // names but does not hold, which withholdNames treats as incomplete.
  const { nodes: all } = (await cdp.send("Accessibility.getFullAXTree", { depth: MAX_AX_DEPTH })) as { nodes: AxNode[] };
  if (!Array.isArray(all)) throw new Error("the accessibility tree is malformed");
  if (Date.now() > deadline) throw new Error("the outline timed out");
  const nodes = all.length > MAX_AX_NODES ? all.slice(0, MAX_AX_NODES) : all;

  const opts = { tagNameMap, scrollableMap, encode, isIgnoredBackendNode };
  // Names are withheld on the whole list, before anything is filtered or
  // pruned; a cut DOM index or AX list withholds every name but plain text.
  const decorated = decorateRoles(nodes, opts);
  withholdNames(decorated, index.truncated || all.length > MAX_AX_NODES);
  const filtered = decorated.filter((n) => {
    const be = n.backendDOMNodeId;
    // Ignored nodes stay: their children hang off them, and structural
    // pruning removes them (as in Stagehand).
    return typeof be !== "number" || !isIgnoredBackendNode(be);
  });
  const urlMap: Record<string, string> = {};
  for (const n of nodes) {
    const be = n.backendDOMNodeId;
    if (typeof be !== "number" || isIgnoredBackendNode(be)) continue;
    const url = extractUrlFromAXNode(n);
    if (url) urlMap[encode(be)] = url;
  }
  const { tree } = buildHierarchicalTree(filtered, opts);
  const bounded = boundOutline(tree, xpathMap, urlMap);
  return { nodes: bounded.nodes, truncated: bounded.truncated || index.truncated || all.length > MAX_AX_NODES };
}
