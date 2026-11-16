// SG-000119 slice A4: the only code that writes to the page. A view is
// described as a tree of plain objects (`Node`) and materialised here with
// createElement, setAttribute and textContent only: no HTML parsing sink and
// no code evaluation exist in the view (build.test.ts checks the built
// files for each by name). Tags and attributes
// are closed unions: no link, button, input, form, image, frame or script can
// be described, and no href, src, style or event handler attribute exists, so
// nothing the view draws can navigate, open a path or act.

export type Tag =
  | "section"
  | "div"
  | "p"
  | "span"
  | "strong"
  | "h3"
  | "h4"
  | "dl"
  | "dt"
  | "dd"
  | "ul"
  | "ol"
  | "li"
  | "table"
  | "caption"
  | "thead"
  | "tbody"
  | "tr"
  | "th"
  | "td"
  | "details"
  | "summary"
  | "code";

export type Attribute = "class" | "role" | "aria-label" | "scope" | "data-task" | "open";

export const TAGS: readonly Tag[] = [
  "section", "div", "p", "span", "strong", "h3", "h4", "dl", "dt", "dd", "ul", "ol", "li",
  "table", "caption", "thead", "tbody", "tr", "th", "td", "details", "summary", "code",
];
export const ATTRIBUTES: readonly Attribute[] = ["class", "role", "aria-label", "scope", "data-task", "open"];

export interface Node {
  tag: Tag;
  attrs?: Partial<Record<Attribute, string>>;
  /** Plain text, set with textContent; a node has text or children, not both. */
  text?: string;
  children?: Node[];
}

export function h(tag: Tag, attrs: Node["attrs"] | null, content?: string | Node[]): Node {
  const node: Node = { tag };
  if (attrs) node.attrs = attrs;
  if (typeof content === "string") node.text = content;
  else if (content) node.children = content;
  return node;
}

/** The part of the DOM this module uses (the tests supply their own). */
export interface ElementLike {
  setAttribute(name: string, value: string): void;
  append(...children: ElementLike[]): void;
  replaceChildren(...children: ElementLike[]): void;
  textContent: string | null;
}

export interface DocumentLike {
  createElement(tag: string): ElementLike;
}

/** Builds the elements for `node`. Unknown tags and attributes are refused. */
export function materialise(doc: DocumentLike, node: Node): ElementLike {
  if (!TAGS.includes(node.tag)) throw new Error("a tag outside the view's set");
  const element = doc.createElement(node.tag);
  for (const [name, value] of Object.entries(node.attrs ?? {})) {
    if (!(ATTRIBUTES as readonly string[]).includes(name)) throw new Error("an attribute outside the view's set");
    if (typeof value === "string") element.setAttribute(name, value);
  }
  if (node.text !== undefined) {
    element.textContent = node.text;
  } else if (node.children) {
    element.append(...node.children.map((child) => materialise(doc, child)));
  }
  return element;
}

/** Replaces `container`'s content with `nodes`. */
export function show(doc: DocumentLike, container: ElementLike, nodes: Node[]): void {
  container.replaceChildren(...nodes.map((node) => materialise(doc, node)));
}
