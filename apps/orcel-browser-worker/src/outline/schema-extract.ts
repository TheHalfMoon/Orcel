// W2-03: deterministic, schema-driven extraction from the accessibility
// outline (the `extract_schema` frame), with no model.
//
// Stagehand's `extract` (browserbase/stagehand at commit
// 82827a219512f0399cb159720a63f7d271d21480,
// `packages/extension/services/extractService.ts`, blob
// 3193fbe656b1af3bca0a0a4c0d3e076e9d1cc731) captures the hybrid snapshot and
// asks a language model to fill a JSON schema, then maps the model's numeric
// element ids back to URLs through the snapshot's URL map
// (`transformUrlStringsToNumericIds`, `injectUrls`). This module keeps the
// deterministic half of that design under the MIT License, Copyright (c)
// 2024 Browserbase Inc. (notice in docs/orcel/notices/stagehand-MIT.txt;
// provenance in docs/orcel/stagehand_provenance.json): the same snapshot,
// the same id-to-URL resolution, and a schema of named fields; the
// inference is replaced by exact matching. Each field names its target by
// role (and optionally the exact accessible name) or by an outline XPath,
// and takes the target's text, the texts of every match (role) or of the
// target's children (XPath), or a link's URL. Every value is outline text:
// already cleaned, bounded, and withheld where the outline withholds a name,
// so an extraction can never return a field value. Any model step
// (Stagehand's `inference.extract`) belongs to orceld with the user's own
// key, never to the worker.

import { normaliseSpaces, untrustedText } from "./tree-format.js";
import { normalizeXPath } from "./xpath.js";
import type { OutlineNode } from "./capture.js";

export type SchemaTake = "text" | "texts" | "url";
export const SCHEMA_TAKES: readonly SchemaTake[] = ["text", "texts", "url"];

/// One field of a schema extraction (host-validated; see protocol.ts).
export interface SchemaField {
  key: string;
  take: SchemaTake;
  role?: string;
  name?: string;
  xpath?: string;
}

export interface SchemaValue {
  key: string;
  found: boolean;
  text?: string;
  texts?: string[];
  url?: string;
}

export const MAX_SCHEMA_FIELDS = 32;
export const MAX_SCHEMA_TEXT_BYTES = 2048;
export const MAX_SCHEMA_LIST_ITEMS = 32;
export const MAX_SCHEMA_ITEM_BYTES = 512;
/// Leaves room under the 64 KiB frame bound for the frame envelope.
export const MAX_SCHEMA_JSON_BYTES = 56 * 1024;

/// A node's text: its name, or (when it has none) the names of the text
/// nodes under it, in order.
export function nodeText(node: OutlineNode, maxBytes: number): string {
  if (node.name.length > 0) return untrustedText(node.name, maxBytes);
  const parts: string[] = [];
  let bytes = 0;
  const visit = (n: OutlineNode): void => {
    if (bytes > maxBytes) return;
    if (n.name.length > 0 && (n.role === "StaticText" || n.children.length === 0)) {
      parts.push(n.name);
      bytes += Buffer.byteLength(n.name, "utf8") + 1;
      return;
    }
    for (const child of n.children) visit(child);
  };
  for (const child of node.children) visit(child);
  return untrustedText(parts.join(" "), maxBytes);
}

function walk(nodes: OutlineNode[], visit: (node: OutlineNode) => boolean): void {
  const stack = [...nodes].reverse();
  while (stack.length) {
    const node = stack.pop()!;
    if (visit(node)) return;
    for (let i = node.children.length - 1; i >= 0; i--) stack.push(node.children[i]!);
  }
}

function matches(field: SchemaField, node: OutlineNode): boolean {
  if (field.xpath !== undefined) return node.xpath.length > 0 && normalizeXPath(node.xpath) === normalizeXPath(field.xpath);
  if (field.role === undefined || node.role !== field.role) return false;
  if (field.name === undefined) return true;
  return normaliseSpaces(node.name).trim() === normaliseSpaces(field.name).trim();
}

/// Extract one value per field, in field order, within the byte bound.
export function extractBySchema(nodes: OutlineNode[], fields: SchemaField[]): { values: SchemaValue[]; truncated: boolean } {
  const values: SchemaValue[] = [];
  let bytes = 0;
  let truncated = false;
  for (const field of fields.slice(0, MAX_SCHEMA_FIELDS)) {
    const value: SchemaValue = { key: field.key, found: false };
    if (field.take === "texts") {
      const texts: string[] = [];
      walk(nodes, (node) => {
        if (!matches(field, node)) return false;
        // An XPath names one container: its children are the list.
        const items = field.xpath !== undefined ? node.children : [node];
        for (const item of items) {
          if (texts.length >= MAX_SCHEMA_LIST_ITEMS) {
            truncated = true;
            return true;
          }
          const text = nodeText(item, MAX_SCHEMA_ITEM_BYTES);
          if (text.length > 0) texts.push(text);
        }
        return field.xpath !== undefined;
      });
      if (texts.length > 0) {
        value.found = true;
        value.texts = texts;
      }
    } else {
      walk(nodes, (node) => {
        if (!matches(field, node)) return false;
        if (field.take === "url") {
          if (node.url === undefined) return false;
          value.found = true;
          value.url = node.url;
          return true;
        }
        const text = nodeText(node, MAX_SCHEMA_TEXT_BYTES);
        if (text.length === 0) return false;
        value.found = true;
        value.text = text;
        return true;
      });
    }
    const size = Buffer.byteLength(JSON.stringify(value), "utf8");
    if (bytes + size > MAX_SCHEMA_JSON_BYTES) {
      truncated = true;
      values.push({ key: field.key, found: false });
      continue;
    }
    bytes += size;
    values.push(value);
  }
  return { values, truncated };
}
