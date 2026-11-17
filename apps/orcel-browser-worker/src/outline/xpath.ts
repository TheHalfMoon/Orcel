// W2-03: XPath helpers for the accessibility outline (`outline/capture.ts`).
//
// Copied from browserbase/stagehand at commit
// 82827a219512f0399cb159720a63f7d271d21480,
// `packages/extension/understudy/a11y/snapshot/xpathUtils.ts` (blob
// a5b8d34230e4e33a2e3829a64919e4bac3c8ef61: `prefixXPath`, `normalizeXPath`,
// `buildChildXPathSegments`, `joinXPath`) and `packages/extension/utils.ts`
// (blob ade45fa134cb6f19773376ff4be48d6ff603c8af: `trimTrailingTextNode`).
// MIT License, Copyright (c) 2024 Browserbase Inc.; notice in
// docs/orcel/notices/stagehand-MIT.txt; provenance in
// docs/orcel/stagehand_provenance.json. Modifications for Orcel: the DOM node
// type is the worker's own minimal `CdpDomNode` (no devtools-protocol
// dependency); `buildAbsoluteXPathFromChain` and
// `absoluteXPathForBackendNode` are not copied (they run a function in the
// page with `Runtime.callFunctionOn`, and the worker never runs page script);
// `boundXPath` is new.

/// The fields of a CDP `DOM.Node` the outline reads.
export interface CdpDomNode {
  nodeId?: number | undefined;
  backendNodeId?: number | undefined;
  nodeType?: number | undefined;
  nodeName?: string | undefined;
  attributes?: string[] | undefined;
  childNodeCount?: number | undefined;
  children?: CdpDomNode[] | undefined;
  shadowRoots?: CdpDomNode[] | undefined;
  contentDocument?: CdpDomNode | undefined;
  isScrollable?: boolean | undefined;
}

/// The longest XPath the outline carries for one node.
export const MAX_XPATH_BYTES = 1024;

/**
 * Prefix `child` XPath with an absolute iframe path `parentAbs`.
 * Handles root slashes and shadow hops ("//") cleanly.
 */
export function prefixXPath(parentAbs: string, child: string): string {
  const p = parentAbs === "/" ? "" : parentAbs.replace(/\/$/, "");
  if (!child || child === "/") return p || "/";
  if (child.startsWith("//")) return p ? `${p}//${child.slice(2)}` : `//${child.slice(2)}`;
  const c = child.replace(/^\//, "");
  return p ? `${p}/${c}` : `/${c}`;
}

/** Normalize an XPath: strip `xpath=`, ensure leading '/', remove trailing '/'. */
export function normalizeXPath(x?: string): string {
  if (!x) return "";
  let s = x.trim().replace(/^xpath=/i, "");
  if (!s.startsWith("/")) s = "/" + s;
  if (s.length > 1 && s.endsWith("/")) s = s.slice(0, -1);
  return s;
}

/** Build per-sibling XPath steps for DOM traversal. */
export function buildChildXPathSegments(kids: CdpDomNode[]): string[] {
  const segs: string[] = [];
  const ctr: Record<string, number> = {};
  for (const child of kids) {
    const tag = String(child.nodeName).toLowerCase();
    const key = `${child.nodeType}:${tag}`;
    const idx = (ctr[key] = (ctr[key] ?? 0) + 1);
    if (child.nodeType === 3) {
      segs.push(`text()[${idx}]`);
    } else if (child.nodeType === 8) {
      segs.push(`comment()[${idx}]`);
    } else {
      segs.push(tag.includes(":") ? `*[name()='${tag}'][${idx}]` : `${tag}[${idx}]`);
    }
  }
  return segs;
}

/** Join two XPath fragments while preserving special shadow-root hops. */
export function joinXPath(base: string, step: string): string {
  if (step === "//") {
    if (!base || base === "/") return "//";
    return base.endsWith("/") ? `${base}/` : `${base}//`;
  }
  if (!base || base === "/") return step ? `/${step}` : "/";
  if (base.endsWith("//")) return `${base}${step}`;
  if (!step) return base;
  return `${base}/${step}`;
}

/** Drop a trailing `/text()[n]` step so the path names the element. */
export function trimTrailingTextNode(path: string | undefined): string | undefined {
  return path?.replace(/\/text\(\)(\[\d+\])?$/iu, "");
}

/// Orcel: an XPath the outline may carry: built only from element names,
/// positions and shadow hops (never from page attribute values), and at most
/// MAX_XPATH_BYTES. Anything else is dropped (empty string).
export function boundXPath(path: string): string {
  if (path.length === 0 || Buffer.byteLength(path, "utf8") > MAX_XPATH_BYTES) return "";
  return /^[A-Za-z0-9_\-/\[\]():.*=' ]+$/.test(path) ? path : "";
}
