// W2-03: the accessibility tree of the main document, decorated with DOM
// facts (tag, input type, scrollable) and pruned of structural noise, from
// CDP `Accessibility.getFullAXTree` (the engine's own accessibility
// computation; no page script runs).
//
// Copied from browserbase/stagehand at commit
// 82827a219512f0399cb159720a63f7d271d21480,
// `packages/extension/understudy/a11y/snapshot/a11yTree.ts` (blob
// 2d3a626f9645f29b817a7a30a7cfbc3343da9c5e: `decorateRoles`,
// `buildHierarchicalTree`, `isStructural`, `extractUrlFromAXNode`,
// `toBooleanValue`, `extractBooleanProperty`) and
// `treeFormatUtils.ts` (blob 4928894ca32684f7cc854578c3ddaee9d6305a1a:
// `removeRedundantStaticTextChildren`). MIT License, Copyright (c) 2024
// Browserbase Inc.; notice in docs/orcel/notices/stagehand-MIT.txt;
// provenance in docs/orcel/stagehand_provenance.json.
//
// Modifications for Orcel:
// - No field value and no description is ever kept (Stagehand's `value` and
//   `description`): a value can be a password, and a description is
//   referenced page text the host has no use for.
// - Names are withheld (`withholdNames`, new) wherever the engine's name
//   computation can pull in what a user typed or chose: the name of every
//   form control or editable node, of every node inside one, of every node
//   that holds one, and of every node named through another element
//   (aria-labelledby, a label, a legend or a caption: `relatedElement`). A
//   name whose source the engine does not report is withheld too, except a
//   text node's own text.
// - A generic node takes its tag as its role only for a plain HTML tag name
//   (never a custom element's page-chosen name).
// - The tree build is synchronous; focus-locator scoping (`a11yForFrame`'s
//   CSS/XPath focus, which resolves selectors in the page) is not copied.

import { normaliseSpaces } from "./tree-format.js";

/// The fields of a CDP `Accessibility.AXNode` the outline reads.
export interface AxValue {
  value?: unknown;
  sources?: Array<{ type?: string; attribute?: string; value?: unknown; superseded?: boolean }>;
}
export interface AxNode {
  nodeId: string;
  ignored?: boolean;
  role?: AxValue;
  name?: AxValue;
  properties?: Array<{ name: string; value?: AxValue }>;
  parentId?: string;
  childIds?: string[];
  backendDOMNodeId?: number;
}

/// A decorated node while the tree is built.
export interface A11yNode {
  role: string;
  name?: string | undefined;
  selected?: boolean | undefined;
  checked?: boolean | undefined;
  nodeId: string;
  backendDOMNodeId?: number | undefined;
  parentId?: string | undefined;
  childIds?: string[] | undefined;
  children?: A11yNode[] | undefined;
  encodedId?: string | undefined;
  /// Orcel: a form control or an editable node (see `isControl`).
  control?: boolean | undefined;
  /// Orcel: the engine computed this name from another element, or did not
  /// say how it computed it.
  borrowedName?: boolean | undefined;
}

export interface A11yOptions {
  tagNameMap: Record<string, string>;
  scrollableMap: Record<string, boolean>;
  encode: (backendNodeId: number) => string;
  isIgnoredBackendNode?: (backendNodeId: number) => boolean;
}

/// Orcel: the roles whose name can carry a value a user typed or chose.
export const CONTROL_ROLES: ReadonlySet<string> = new Set([
  "textbox", "searchbox", "combobox", "listbox", "spinbutton", "slider", "checkbox", "radio", "switch",
  "menuitemcheckbox", "menuitemradio", "option", "textField", "TextField", "ComboBoxGrouping", "ComboBoxMenuButton",
  "ListBox", "ListBoxOption", "SpinButton", "Slider", "CheckBox", "RadioButton", "Switch", "MenuListPopup", "MenuListOption"
]);

/// Orcel: a plain HTML tag a generic node may show as its role.
const PLAIN_TAG = /^[a-z][a-z0-9]{0,15}$/;

export function decorateRoles(nodes: AxNode[], opts: A11yOptions): A11yNode[] {
  const asRole = (n: AxNode) => String(n.role?.value ?? "");

  return nodes.map((n) => {
    let encodedId: string | undefined;
    if (typeof n.backendDOMNodeId === "number") {
      try {
        encodedId = opts.encode(n.backendDOMNodeId);
      } catch {
        //
      }
    }

    let role = asRole(n);
    const control = isControl(n, role, encodedId ? opts.tagNameMap[encodedId] : undefined);

    const domIsScrollable = encodedId ? opts.scrollableMap[encodedId] === true : false;
    const tag = encodedId ? opts.tagNameMap[encodedId] : undefined;
    const isHtmlElement = tag === "html";
    if ((domIsScrollable || isHtmlElement) && tag !== "#document") {
      const tagLabel = tag && tag.startsWith("#") ? tag.slice(1) : tag;
      role = tagLabel ? `scrollable, ${tagLabel}` : `scrollable${role ? `, ${role}` : ""}`;
    }

    // File inputs typically get role "button" from Chrome's AX tree;
    // override so they appear as "input, file" in the outline.
    if (tag === "input, file") {
      role = tag;
    }

    const name = typeof n.name?.value === "string" ? n.name.value : undefined;
    return {
      role,
      name,
      selected: extractBooleanProperty(n, "selected"),
      checked: extractBooleanProperty(n, "checked"),
      nodeId: n.nodeId,
      backendDOMNodeId: n.backendDOMNodeId,
      parentId: n.parentId,
      childIds: n.childIds,
      encodedId,
      control,
      borrowedName: name !== undefined && name.length > 0 && nameIsBorrowed(n, role)
    };
  });
}

/// Orcel: whether a node is a form control or editable (a value a user can
/// type or choose lives in it).
export function isControl(n: AxNode, role: string, tag: string | undefined): boolean {
  if (CONTROL_ROLES.has(role)) return true;
  if (tag !== undefined && (tag === "select" || tag === "textarea" || tag.startsWith("input"))) return true;
  for (const p of n.properties ?? []) {
    if (p.name === "editable" && typeof p.value?.value === "string" && p.value.value !== "") return true;
    if (p.name === "editable" && p.value?.value === true) return true;
  }
  return false;
}

/// Orcel: the engine's winning name source is another element, or unknown.
export function nameIsBorrowed(n: AxNode, role: string): boolean {
  const sources = n.name?.sources;
  if (!Array.isArray(sources) || sources.length === 0) return role !== "StaticText" && role !== "text";
  const winner = sources.find((s) => s.value !== undefined && s.superseded !== true);
  if (winner === undefined) return true;
  return winner.type === "relatedElement" || winner.attribute === "aria-labelledby";
}

export function buildHierarchicalTree(nodes: A11yNode[], opts: A11yOptions): { tree: A11yNode[] } {
  const nodeMap = new Map<string, A11yNode>();

  for (const n of nodes) {
    const keep = !!(n.name && n.name.trim()) || !!(n.childIds && n.childIds.length) || !isStructural(n.role);
    if (!keep) continue;
    nodeMap.set(n.nodeId, { ...n });
  }

  for (const n of nodes) {
    if (!n.parentId) continue;
    const parent = nodeMap.get(n.parentId);
    const cur = nodeMap.get(n.nodeId);
    if (parent && cur) (parent.children ??= []).push(cur);
  }

  const roots = nodes.filter((n) => !n.parentId && nodeMap.has(n.nodeId)).map((n) => nodeMap.get(n.nodeId)!);

  const cleaned = roots.map(pruneStructuralSafe).filter(Boolean) as A11yNode[];

  return { tree: cleaned };

  function pruneStructuralSafe(node: A11yNode): A11yNode | null {
    if (+node.nodeId < 0) return null;

    const children = node.children ?? [];
    if (!children.length) {
      return isStructural(node.role) ? null : node;
    }

    const cleanedKids = children.map(pruneStructuralSafe).filter(Boolean) as A11yNode[];

    const prunedStatic = removeRedundantStaticTextChildren(node, cleanedKids);

    if (isStructural(node.role)) {
      if (prunedStatic.length === 1) return prunedStatic[0]!;
      if (prunedStatic.length === 0) return null;
    }

    let newRole = node.role;
    if ((newRole === "generic" || newRole === "none") && node.encodedId) {
      const tagName = opts.tagNameMap[node.encodedId];
      if (tagName && PLAIN_TAG.test(tagName)) newRole = tagName;
    }

    if (newRole === "combobox" && node.encodedId) {
      const tagName = opts.tagNameMap[node.encodedId];
      if (tagName === "select") newRole = "select";
    }

    return { ...node, role: newRole, children: prunedStatic };
  }
}

/// Orcel: clears every name that could carry what a user typed or chose
/// (see the module comment). Returns how many names were withheld.
export function withholdNames(tree: A11yNode[]): number {
  let withheld = 0;
  // Post-order: whether the subtree holds a control.
  const holds = (node: A11yNode, inside: boolean): boolean => {
    let below = false;
    const nowInside = inside || node.control === true;
    for (const child of node.children ?? []) {
      if (holds(child, nowInside)) below = true;
    }
    if (node.name && (nowInside || below || node.borrowedName === true)) {
      node.name = "";
      withheld += 1;
    }
    return below || node.control === true;
  };
  for (const root of tree) holds(root, false);
  return withheld;
}

export function isStructural(role: string): boolean {
  const r = role?.toLowerCase();
  return r === "generic" || r === "none" || r === "inlinetextbox";
}

export function extractUrlFromAXNode(ax: AxNode): string | undefined {
  const props = ax.properties ?? [];
  const urlProp = props.find((p) => p.name === "url");
  const value = urlProp?.value?.value;
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function toBooleanValue(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (value === 1) return true;
    if (value === 0) return false;
  }
  if (typeof value === "string") {
    const normalized = value.toLowerCase();
    if (normalized === "true") return true;
    if (normalized === "false") return false;
  }
  return undefined;
}

export function extractBooleanProperty(node: AxNode, propertyName: string): boolean | undefined {
  const value = node.properties?.find((p) => p.name === propertyName)?.value?.value;
  return toBooleanValue(value);
}

export function removeRedundantStaticTextChildren(parent: A11yNode, children: A11yNode[]): A11yNode[] {
  if (!parent.name) return children;
  const parentNorm = normaliseSpaces(parent.name).trim();
  let combined = "";
  for (const c of children) {
    if (c.role === "StaticText" && c.name) {
      combined += normaliseSpaces(c.name).trim();
    }
  }
  if (combined === parentNorm) {
    return children.filter((c) => c.role !== "StaticText");
  }
  return children;
}
