// Test support for the OB-07 challenge detector: turns fixture HTML into
// the parts of an engine DOM snapshot the detector reads, the way the
// engine would lay it out for the cases the fixtures use. It is a small
// tag reader for well-formed fixture markup only, never page input.
//
// Layout: an element is laid out unless it is a non-rendered element
// (head, title, script, style, meta, link, template, noscript), a hidden
// input, carries the `hidden` attribute or `display:none` in its inline
// style, or sits under such an element. `visibility:hidden` (inline)
// is inherited, as the engine computes it. Text is laid out with its
// parent. `<iframe>` documents are given as extra documents by the caller.

import type { ChallengeSnapshot } from "./challenge.js";

const VOID = new Set(["input", "br", "img", "meta", "link", "hr", "source", "area", "base", "col", "embed", "param", "track", "wbr"]);
const RAW = new Set(["script", "style", "title", "textarea"]);
const UNRENDERED = new Set(["head", "title", "script", "style", "meta", "link", "template", "noscript"]);

interface Built {
  types: number[];
  names: number[];
  values: number[];
  parents: number[];
  attributes: number[][];
  layout: number[];
  styles: number[][];
  backends: Map<number, number>;
}

/// Build one document from `html`, interning strings into `strings`.
function buildDocument(html: string, strings: string[]): { built: Built; title: number } {
  const intern = (value: string): number => {
    const at = strings.indexOf(value);
    if (at >= 0) return at;
    strings.push(value);
    return strings.length - 1;
  };
  const built: Built = { types: [], names: [], values: [], parents: [], attributes: [], layout: [], styles: [], backends: new Map() };
  // The document node.
  built.types.push(9);
  built.names.push(intern("#document"));
  built.values.push(-1);
  built.parents.push(-1);
  built.attributes.push([]);
  // Each open element: its node, whether it is laid out, and whether it is
  // visibility-hidden.
  const stack: Array<{ node: number; tag: string; shown: boolean; hidden: boolean }> = [{ node: 0, tag: "#document", shown: true, hidden: false }];
  let title = -1;
  const top = () => stack[stack.length - 1] ?? { node: 0, tag: "#document", shown: true, hidden: false };
  const lay = (node: number, hidden: boolean) => {
    built.layout.push(node);
    built.styles.push([intern("block"), intern(hidden ? "hidden" : "visible")]);
  };
  const addText = (text: string) => {
    if (text.length === 0) return;
    const parent = top();
    const node = built.types.length;
    built.types.push(3);
    built.names.push(intern("#text"));
    built.values.push(intern(text));
    built.parents.push(parent.node);
    built.attributes.push([]);
    if (parent.shown && !UNRENDERED.has(parent.tag)) lay(node, parent.hidden);
    if (parent.tag === "title") title = intern(text);
  };
  let at = 0;
  while (at < html.length) {
    if (html.startsWith("<!--", at)) {
      const end = html.indexOf("-->", at);
      at = end < 0 ? html.length : end + 3;
      continue;
    }
    if (html.startsWith("<!", at)) {
      const end = html.indexOf(">", at);
      at = end < 0 ? html.length : end + 1;
      continue;
    }
    if (html.startsWith("</", at)) {
      const end = html.indexOf(">", at);
      const tag = html.slice(at + 2, end < 0 ? html.length : end).trim().toLowerCase();
      for (let k = stack.length - 1; k > 0; k--) {
        if (stack[k]?.tag === tag) {
          stack.length = k;
          break;
        }
      }
      at = end < 0 ? html.length : end + 1;
      continue;
    }
    if (html[at] === "<" && /[a-zA-Z]/.test(html[at + 1] ?? "")) {
      const end = html.indexOf(">", at);
      const inner = html.slice(at + 1, end < 0 ? html.length : end);
      at = end < 0 ? html.length : end + 1;
      const selfClosing = inner.endsWith("/");
      const body = selfClosing ? inner.slice(0, -1) : inner;
      const tag = (/^[a-zA-Z][a-zA-Z0-9-]*/.exec(body)?.[0] ?? "").toLowerCase();
      const attrs: Array<[string, string]> = [];
      const pattern = /([^\s=/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
      const rest = body.slice(tag.length);
      for (const match of rest.matchAll(pattern)) {
        attrs.push([(match[1] ?? "").toLowerCase(), match[2] ?? match[3] ?? match[4] ?? ""]);
      }
      const parent = top();
      const node = built.types.length;
      built.types.push(1);
      built.names.push(intern(tag.toUpperCase()));
      built.values.push(-1);
      built.parents.push(parent.node);
      built.attributes.push(attrs.flatMap(([name, value]) => [intern(name), intern(value)]));
      const attr = (name: string) => attrs.find(([key]) => key === name)?.[1];
      // A fixture names an element's engine identity with data-backend, so
      // two snapshots can show "the same" element (OB-07b).
      const backend = Number(attr("data-backend"));
      if (Number.isSafeInteger(backend) && backend > 0) built.backends.set(node, backend);
      const style = (attr("style") ?? "").replace(/\s+/g, "").toLowerCase();
      const shown =
        parent.shown &&
        !UNRENDERED.has(tag) &&
        !UNRENDERED.has(parent.tag) &&
        attr("hidden") === undefined &&
        !style.includes("display:none") &&
        !(tag === "input" && (attr("type") ?? "").toLowerCase() === "hidden");
      const hidden = style.includes("visibility:hidden") ? true : style.includes("visibility:visible") ? false : parent.hidden;
      if (shown) lay(node, hidden);
      if (VOID.has(tag) || selfClosing) continue;
      if (RAW.has(tag)) {
        const close = html.toLowerCase().indexOf(`</${tag}`, at);
        stack.push({ node, tag, shown, hidden });
        addText(html.slice(at, close < 0 ? html.length : close));
        stack.pop();
        const after = close < 0 ? html.length : html.indexOf(">", close);
        at = after < 0 ? html.length : after + 1;
        continue;
      }
      stack.push({ node, tag, shown, hidden });
      continue;
    }
    const next = html.indexOf("<", at + 1);
    const chunk = html.slice(at, next < 0 ? html.length : next);
    at = next < 0 ? html.length : next;
    addText(chunk.replace(/&amp;/g, "&").replace(/&#39;|&apos;/g, "'").replace(/&quot;/g, '"'));
  }
  return { built, title };
}

/// An engine-like snapshot of `html` and, as further documents, `frames`.
export function snapshotOf(html: string, ...frames: string[]): ChallengeSnapshot {
  const strings: string[] = [];
  const documents = [html, ...frames].map((source, index) => {
    const { built, title } = buildDocument(source, strings);
    strings.push(index === 0 ? "https://fixture.test/page" : `https://fixture.test/frame-${index}`);
    return {
      documentURL: strings.length - 1,
      title,
      nodes: {
        parentIndex: built.parents,
        nodeType: built.types,
        nodeName: built.names,
        nodeValue: built.values,
        attributes: built.attributes,
        backendNodeId: built.types.map((_, node) => built.backends.get(node) ?? 1_000_000 * (index + 1) + node)
      },
      layout: { nodeIndex: built.layout, styles: built.styles }
    };
  });
  return { documents, strings };
}
