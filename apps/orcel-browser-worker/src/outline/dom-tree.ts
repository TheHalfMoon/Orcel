// W2-03: the main document's DOM index for the accessibility outline: per
// backend node, its absolute XPath, its tag (with an input's type) and
// whether the engine reports it scrollable. Read with CDP `DOM.getDocument`
// (and `DOM.describeNode` to fill in branches a shallow read left out): the
// engine serialises its own DOM, and no page script runs.
//
// Copied from browserbase/stagehand at commit
// 82827a219512f0399cb159720a63f7d271d21480,
// `packages/extension/understudy/a11y/snapshot/domTree.ts` (blob
// 02c589d7f9799ba9c66894cd7ba9a4ae99d6aabf: `shouldExpandNode`,
// `mergeDomNodes`, `collectDomTraversalTargets`, `hydrateDomTree`,
// `getDomTreeWithFallback`, `buildSessionDomIndex`, `relativizeXPath`,
// `enrichedTagName`, `findNodeByBackendId`). MIT License, Copyright (c) 2024
// Browserbase Inc.; notice in docs/orcel/notices/stagehand-MIT.txt;
// provenance in docs/orcel/stagehand_provenance.json. Modifications for
// Orcel: the session is the worker's read-only `CdpReader` (an allowlist of
// read methods, `outline/capture.ts`); Stagehand's `Progress` is replaced by
// an absolute deadline; the index stops at MAX_DOM_NODES (and says so);
// `domMapsForSession` (per-frame owner lookup) is not copied, as the outline
// covers the main document only.

import { buildChildXPathSegments, joinXPath, normalizeXPath, type CdpDomNode } from "./xpath.js";

/// The read-only CDP surface the outline uses (see `outline/capture.ts`).
export interface CdpReader {
  send(method: string, params?: Record<string, unknown>): Promise<unknown>;
}

/// Upper bound on DOM nodes indexed for one outline.
export const MAX_DOM_NODES = 50_000;

// starting from infinite depth (-1), exponentially shrink down to 1
const DOM_DEPTH_ATTEMPTS = [-1, 256, 128, 64, 32, 16, 8, 4, 2, 1];
const DESCRIBE_DEPTH_ATTEMPTS = [-1, 64, 32, 16, 8, 4, 2, 1];

/// Orcel: thrown when the outline's deadline passes.
export class OutlineTimeout extends Error {}

function checkDeadline(deadline: number | undefined): void {
  if (deadline !== undefined && Date.now() > deadline) throw new OutlineTimeout("the outline timed out");
}

/** Identify CDP failures caused by deep DOM trees blowing the CBOR encoder stack. */
function isCborStackError(message: string): boolean {
  return message.includes("CBOR: stack limit exceeded");
}

/**
 * Determine if CDP truncated a node's children when streaming the DOM tree.
 * childNodeCount stays accurate even when `children` are omitted; we use this to
 * decide whether DOM.describeNode must be re-run for that node.
 */
export function shouldExpandNode(node: CdpDomNode): boolean {
  const declaredChildren = node.childNodeCount ?? 0;
  const realizedChildren = node.children?.length ?? 0;
  return declaredChildren > realizedChildren;
}

/** Merge an expanded DescribeNode payload back into the original shallow node. */
export function mergeDomNodes(target: CdpDomNode, source: CdpDomNode): void {
  target.childNodeCount = source.childNodeCount ?? target.childNodeCount;
  target.children = source.children ?? target.children;
  target.shadowRoots = source.shadowRoots ?? target.shadowRoots;
  target.contentDocument = source.contentDocument ?? target.contentDocument;
}

/** Helper that returns every nested collection we recurse through uniformly. */
export function collectDomTraversalTargets(node: CdpDomNode): CdpDomNode[] {
  const targets: CdpDomNode[] = [];
  if (node.children) targets.push(...node.children);
  if (node.shadowRoots) targets.push(...node.shadowRoots);
  if (node.contentDocument) targets.push(node.contentDocument);
  return targets;
}

/**
 * Rehydrate a truncated DOM tree by repeatedly calling DOM.describeNode with
 * decreasing depths. Any non-CBOR failure is surfaced directly.
 */
export async function hydrateDomTree(session: CdpReader, root: CdpDomNode, pierce: boolean, deadline?: number): Promise<void> {
  const stack: CdpDomNode[] = [root];
  const expandedNodeIds = new Set<number>();
  const expandedBackendIds = new Set<number>();
  let visited = 0;

  while (stack.length) {
    checkDeadline(deadline);
    // Orcel: a hydration never walks more nodes than the index keeps.
    if (++visited > MAX_DOM_NODES) return;
    const node = stack.pop()!;
    const nodeId = typeof node.nodeId === "number" && node.nodeId > 0 ? node.nodeId : undefined;
    const backendId = typeof node.backendNodeId === "number" && node.backendNodeId > 0 ? node.backendNodeId : undefined;

    const seenByNode = nodeId ? expandedNodeIds.has(nodeId) : false;
    const seenByBackend = !nodeId && backendId ? expandedBackendIds.has(backendId) : false;
    if (seenByNode || seenByBackend) continue;
    if (nodeId) expandedNodeIds.add(nodeId);
    else if (backendId) expandedBackendIds.add(backendId);

    const needsExpansion = shouldExpandNode(node);
    if (needsExpansion && (nodeId || backendId)) {
      const describeParamsBase = nodeId ? { nodeId } : { backendNodeId: backendId! };
      let expanded = false;
      let lastRetryError: unknown;
      for (const depth of DESCRIBE_DEPTH_ATTEMPTS) {
        checkDeadline(deadline);
        try {
          const described = (await session.send("DOM.describeNode", { ...describeParamsBase, depth, pierce })) as { node: CdpDomNode };
          mergeDomNodes(node, described.node);
          if (!nodeId && described.node.nodeId && described.node.nodeId > 0) {
            node.nodeId = described.node.nodeId;
            expandedNodeIds.add(described.node.nodeId);
          }
          expanded = true;
          break;
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          if (isCborStackError(message)) {
            lastRetryError = err;
            continue;
          }
          throw err;
        }
      }
      if (!expanded) {
        if (lastRetryError !== undefined) throw lastRetryError;
        throw new Error("Unable to expand DOM node after describeNode depth retries");
      }
    }

    for (const child of collectDomTraversalTargets(node)) {
      stack.push(child);
    }
  }
}

/**
 * Attempt DOM.getDocument with progressively shallower depths until CBOR stops
 * complaining. When a shallower snapshot is returned we hydrate the missing
 * branches so downstream DOM traversals see the full tree shape.
 */
export async function getDomTreeWithFallback(session: CdpReader, pierce: boolean, deadline?: number): Promise<CdpDomNode> {
  let lastRetryError: unknown;

  for (const depth of DOM_DEPTH_ATTEMPTS) {
    checkDeadline(deadline);
    try {
      const { root } = (await session.send("DOM.getDocument", { depth, pierce })) as { root: CdpDomNode };

      if (depth !== -1) {
        await hydrateDomTree(session, root, pierce, deadline);
      }

      return root;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (isCborStackError(message)) {
        lastRetryError = err;
        continue;
      }
      throw err;
    }
  }

  if (lastRetryError !== undefined) throw lastRetryError;
  throw new Error("CDP DOM.getDocument failed after adaptive depth retries");
}

/// The DOM index of one CDP session's documents.
export interface SessionDomIndex {
  rootBackend: number;
  absByBe: Map<number, string>;
  tagByBe: Map<number, string>;
  scrollByBe: Map<number, boolean>;
  docRootOf: Map<number, number>;
  contentDocRootByIframe: Map<number, number>;
  enterByBe: Map<number, number>;
  exitByBe: Map<number, number>;
  /// Orcel: the walk stopped at MAX_DOM_NODES.
  truncated: boolean;
}

/**
 * Build an index of absolute XPath/tag metadata for an entire CDP session.
 * Once the index is cached, per-frame slices are derived without extra DOM
 * calls, which keeps snapshot capture linear in the number of frames.
 */
export async function buildSessionDomIndex(session: CdpReader, pierce: boolean, deadline?: number): Promise<SessionDomIndex> {
  await session.send("DOM.enable").catch(() => {});
  // CDP uses one piercing flag for both shadow roots and iframe documents.
  // Fetch both, then independently omit shadow roots while building the index.
  const root = await getDomTreeWithFallback(session, true, deadline);

  const absByBe = new Map<number, string>();
  const tagByBe = new Map<number, string>();
  const scrollByBe = new Map<number, boolean>();
  const docRootOf = new Map<number, number>();
  const contentDocRootByIframe = new Map<number, number>();
  const enterByBe = new Map<number, number>();
  const exitByBe = new Map<number, number>();
  let truncated = false;

  type Entry = {
    node: CdpDomNode;
    xp: string;
    docRootBe: number;
    phase: "enter" | "exit";
  };
  const rootBe = root.backendNodeId!;
  const stack: Entry[] = [{ node: root, xp: "/", docRootBe: rootBe, phase: "enter" }];
  let dfsIndex = 0;

  while (stack.length) {
    checkDeadline(deadline);
    const { node, xp, docRootBe, phase } = stack.pop()!;
    if (phase === "exit") {
      if (node.backendNodeId) {
        exitByBe.set(node.backendNodeId, dfsIndex++);
      }
      continue;
    }

    // Orcel: bounded; what is left out is simply not in the outline.
    if (absByBe.size >= MAX_DOM_NODES) {
      truncated = true;
      continue;
    }

    if (node.backendNodeId) {
      enterByBe.set(node.backendNodeId, dfsIndex++);
      absByBe.set(node.backendNodeId, xp || "/");
      tagByBe.set(node.backendNodeId, enrichedTagName(node));
      if (node?.isScrollable === true) scrollByBe.set(node.backendNodeId, true);
      docRootOf.set(node.backendNodeId, docRootBe);
    }

    stack.push({ node, xp, docRootBe, phase: "exit" });

    const kids = node.children ?? [];
    if (kids.length) {
      const segs = buildChildXPathSegments(kids);
      for (let i = kids.length - 1; i >= 0; i--) {
        const child = kids[i]!;
        const step = segs[i]!;
        stack.push({
          node: child,
          xp: joinXPath(xp, step),
          docRootBe,
          phase: "enter"
        });
      }
    }

    for (const sr of pierce ? (node.shadowRoots ?? []) : []) {
      stack.push({
        node: sr,
        xp: joinXPath(xp, "//"),
        docRootBe,
        phase: "enter"
      });
    }

    const cd = node.contentDocument;
    if (cd && typeof cd.backendNodeId === "number") {
      contentDocRootByIframe.set(node.backendNodeId!, cd.backendNodeId);
      stack.push({
        node: cd,
        xp,
        docRootBe: cd.backendNodeId,
        phase: "enter"
      });
    }
  }

  return {
    rootBackend: rootBe,
    absByBe,
    tagByBe,
    scrollByBe,
    docRootOf,
    contentDocRootByIframe,
    enterByBe,
    exitByBe,
    truncated
  };
}

/**
 * Relativize an absolute XPath against a document root's absolute path.
 * When the node lives outside the document we return the absolute path as-is.
 */
export function relativizeXPath(baseAbs: string, nodeAbs: string): string {
  const base = normalizeXPath(baseAbs);
  const abs = normalizeXPath(nodeAbs);
  if (abs === base) return "/";
  if (abs.startsWith(base)) {
    const tail = abs.slice(base.length);
    if (!tail) return "/";
    return tail.startsWith("/") || tail.startsWith("//") ? tail : `/${tail}`;
  }
  if (base === "/") return abs;
  return abs;
}

/**
 * Extract an attribute value from a CDP DOM node's flat attributes array.
 * Attributes are stored as [name1, value1, name2, value2, ...].
 */
function getAttr(attrs: string[] | undefined, name: string): string | undefined {
  if (!attrs) return undefined;
  for (let i = 0; i < attrs.length; i += 2) {
    if (attrs[i] === name) return attrs[i + 1];
  }
  return undefined;
}

/// Orcel: the input types an enriched tag may name (anything else is
/// "input, text", the HTML default for an unknown type).
const INPUT_TYPES = new Set([
  "button", "checkbox", "color", "date", "datetime-local", "email", "file", "hidden", "image", "month", "number",
  "password", "radio", "range", "reset", "search", "submit", "tel", "text", "time", "url", "week"
]);

/** Build an enriched tag name that includes the type attribute for inputs. */
export function enrichedTagName(node: CdpDomNode): string {
  const tag = String(node.nodeName).toLowerCase();
  if (tag === "input") {
    const type = getAttr(node.attributes, "type");
    // Orcel: a page-chosen type string never crosses; only a known type.
    if (type) return `input, ${INPUT_TYPES.has(type.toLowerCase()) ? type.toLowerCase() : "text"}`;
  }
  return tag;
}

/** Find a node by backendNodeId inside a DOM.getDocument tree. */
export function findNodeByBackendId(root: CdpDomNode, backendNodeId: number): CdpDomNode | undefined {
  const stack: CdpDomNode[] = [root];
  while (stack.length) {
    const n = stack.pop()!;
    if (n.backendNodeId === backendNodeId) return n;
    if (n.children) for (const c of n.children) stack.push(c);
    if (n.shadowRoots) for (const s of n.shadowRoots) stack.push(s);
  }
  return undefined;
}
